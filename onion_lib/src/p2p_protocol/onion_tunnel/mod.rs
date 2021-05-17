mod message_codec;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{net::UdpSocket, time::timeout};

use crate::p2p_protocol::messages::p2p_messages;
use crate::p2p_protocol::P2pError;

/// Tunnel state machine
///
/// ```text
///            Connecting
///                |
///                |
///                | - send connection request
///                | - receive response
///                |
///                V
///            Connected ------------+
///                |   ^             |
///                |   |             | handle packets
///                |   |             |
///                |   +-------------+
/// end connection |
///                |
///                V
///             Closing
///                |
///                |
///  receive resp. |
///                |
///                V
///            Terminate
/// ```

pub(crate) struct OnionTunnel {
    event_tx: Sender<IoEvent>,
}

#[derive(Debug)]
pub(crate) struct TunnelStateContext {
    event_rx: Receiver<IoEvent>,
    message_codec: Box<dyn message_codec::P2pCodec + Send + 'static>,
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub(crate) enum TunnelState {
    Connecting,
    Connected,
    Closing,
}

type TunnelError = P2pError;
pub enum Transit<Out>
where
    Out: Sized + Copy,
{
    /// Enter the next state
    To(Out),
    /// Final state
    Terminate,
}
type TunnelTransit = Transit<TunnelState>;

#[derive(Debug, Clone, PartialEq)]
enum IoEvent {
    ReceiveData(Vec<u8>),
}

async fn wait_for_event(event_rx: &mut Receiver<IoEvent>) -> Result<IoEvent, P2pError> {
    let event_future = event_rx.recv();
    let event = timeout(Duration::from_secs(30), event_future).await;

    if event.is_err() {
        return Err(TunnelError::SocketResponseTimeout(0));
    }
    let event = event.unwrap(); // Safe
    if event.is_none() {
        return Err(TunnelError::EventQueueClosed);
    }
    let event = event.unwrap(); // Safe
    Ok(event)
}

async fn tunnel_connect(
    comp: &mut TunnelStateContext,
) -> Result<TunnelTransit, TunnelError> {
    let hello_msg = p2p_messages::TunnelHello::new();
    comp.message_codec.write_socket(&hello_msg.into()).await?;

    let event = wait_for_event(&mut comp.event_rx).await?;

    match event {
        IoEvent::ReceiveData(data) => {
            let _connect_response = comp.message_codec.from_raw(&data).await?;
            // TODO

            Ok(Transit::To(TunnelState::Connected))
        }
        _ => Err(TunnelError::InvalidTunnelEvent),
    }
}

async fn receive_packet(comp: &mut TunnelStateContext) -> Result<TunnelTransit, TunnelError> {
    let event = wait_for_event(&mut comp.event_rx).await?;
    match event {
        IoEvent::ReceiveData(_) => Ok(Transit::To(TunnelState::Connected)),
        _ => Err(TunnelError::InvalidTunnelEvent),
    }
}

async fn close_tunnel(
    comp: &mut TunnelStateContext,
) -> Result<TunnelTransit, TunnelError> {
    let msg = p2p_messages::TunnelClose::new();
    comp.message_codec.write_socket(&msg.into()).await?;
    Ok(Transit::Terminate)
}

impl OnionTunnel {
    pub fn unsubscribe(&mut self, _connection_id: u64) {}

    pub async fn new(socket: Arc<UdpSocket>, target: SocketAddr, _host_key: Vec<u8>) -> Self {
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);
        let mut app = TunnelStateContext {
            event_rx,
            message_codec: Box::new(message_codec::PlainProtobuf {
                socket: socket,
                target: target,
            }),
        };
        let tunnel = OnionTunnel { event_tx };

        tokio::spawn(async move {
            // Start in Connecting state
            let mut trans = Transit::To(TunnelState::Connecting);

            loop {
                trans = match trans {
                    Transit::To(out) => {
                        let res = match out {
                            TunnelState::Connecting => tunnel_connect(&mut app).await,
                            TunnelState::Connected => receive_packet(&mut app).await,
                            TunnelState::Closing => close_tunnel(&mut app).await,
                        };
                        match res {
                            Ok(t) => t,
                            Err(e) => return Err(e),
                        }
                    }
                    Transit::Terminate => return Ok(()),
                }
            }
        });
        tunnel
    }
}
