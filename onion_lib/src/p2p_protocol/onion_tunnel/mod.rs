mod message_codec;

use std::{
    collections::{HashMap, LinkedList},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};
use tokio::{net::UdpSocket, time::timeout};

use crate::p2p_protocol::messages::p2p_messages;
use crate::p2p_protocol::P2pError;

use super::{PacketId, TunnelId};

/// The initial sending tunnel endpoint behaves the same as an intermediate hop.
///
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
pub(crate) struct TunnelStateMachine {
    event_rx: Receiver<IoEvent>,
    message_codec_in: Box<dyn message_codec::P2pCodec + Send + 'static>,
    message_codec_out: Box<dyn message_codec::P2pCodec + Send + 'static>,
    is_endpoint: bool,
    packet_ids: Arc<Mutex<HashMap<PacketId, TunnelId>>>,
    incoming_next_packet_ids: LinkedList<PacketId>,
    outgoing_next_packet_ids: LinkedList<PacketId>,
    tunnel_id: TunnelId,
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

impl TunnelStateMachine {
    /// For now only ReceiveData events are supported, do not use this function.
    /// Use wait_for_frame_event instead.
    async fn wait_for_event(&mut self) -> Result<IoEvent, P2pError> {
        let event_future = self.event_rx.recv();
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

    async fn wait_for_frame_event(
        &mut self,
    ) -> Result<p2p_messages::TunnelFrame_oneof_message, P2pError> {
        let event = self.wait_for_event().await?;

        match event {
            IoEvent::ReceiveData(data) => {
                let connect_request = self.message_codec_in.from_raw(&data).await?;
                let message = connect_request
                    .message
                    .ok_or(P2pError::FrameError("TunnelFrame is unset".to_string()))?;
                Ok(message)
            }
        }
    }

    fn outgoing_packet_id(&mut self) -> (Vec<PacketId>, PacketId) {
        let current_packet_id = self
            .outgoing_next_packet_ids
            .pop_front()
            .expect("Out of packet ids");
        self.outgoing_next_packet_ids.push_back(rand::random());
        let mut next_packet_ids = vec![];
        next_packet_ids.extend(self.outgoing_next_packet_ids.iter());

        (next_packet_ids, current_packet_id)
    }

    async fn incoming_packet_id(&mut self, next_packet_ids: &[PacketId]) {
        for next_packet_id in next_packet_ids {
            if ! self.incoming_next_packet_ids.contains(&next_packet_id) {
                self.incoming_next_packet_ids.push_back(next_packet_id.to_owned());
                let mut packet_ids = self.packet_ids.lock().await;

                // The key should not be present
                debug_assert!(packet_ids.insert(next_packet_id.to_owned(), self.tunnel_id).is_none());
            }
        }
        // Move acceptance window forward if packets got lost
        while self.incoming_next_packet_ids.len() > 20 {
            let timeout_packet_id = self.incoming_next_packet_ids.pop_front().unwrap(); // safe unwrap
            let mut packet_ids = self.packet_ids.lock().await;
            debug_assert!(packet_ids.remove(&timeout_packet_id).is_some());
        }
    }

    pub(crate) async fn tunnel_connect(&mut self) -> Result<TunnelTransit, TunnelError> {
        let frame = self.wait_for_frame_event().await?;

        match frame {
            p2p_messages::TunnelFrame_oneof_message::tunnelHello(message) => {
                self.incoming_packet_id(message.get_next_packet_ids()).await;

                let target = if message.target == "" {
                    // Final host in the hop chain
                    None
                } else {
                    Some(SocketAddr::from_str(message.target.as_str()).map_err(|e| {
                        P2pError::FrameError(format!(
                            "Target is invalid socket address: {:#?}, error: {:#?}",
                            message.target, e
                        ))
                    })?)
                };
                self.message_codec_out.set_target(target);

                return Ok(Transit::To(TunnelState::Connected));
            }
            _ => {
                return Err(P2pError::FrameError(format!(
                    "Expected TunnelHello, got: {:#?}",
                    frame
                )))
            }
        }
    }

    pub(crate) async fn receive_packet(&mut self) -> Result<TunnelTransit, TunnelError> {
        let frame = self.wait_for_frame_event().await?;

        match frame {
            p2p_messages::TunnelFrame_oneof_message::tunnelData(message) => {
                self.incoming_packet_id(message.get_next_packet_ids()).await;

                if self.message_codec_out.is_endpoint() {
                    // TODO: send data to API
                    log::debug!("Received {} bytes at final endpoint", message.data.len());
                } else {
                    let mut msg = p2p_messages::TunnelData::new();
                    msg.set_data(message.data);

                    let (next_packet_ids, current_packet_id) = self.outgoing_packet_id();
                    msg.set_next_packet_ids(next_packet_ids);

                    self.message_codec_out
                        .write_socket(current_packet_id, &msg.into())
                        .await?;
                }

                return Ok(Transit::To(TunnelState::Connected));
            }
            p2p_messages::TunnelFrame_oneof_message::tunnelClose(_message) => {
                let msg = p2p_messages::TunnelClose::new();

                let (_next_packet_ids, current_packet_id) = self.outgoing_packet_id();

                self.message_codec_out
                    .write_socket(current_packet_id, &msg.into())
                    .await?;

                return Ok(Transit::To(TunnelState::Closing));
            }
            _ => {
                return Err(P2pError::FrameError(format!(
                    "Expected TunnelData or TunnelClose, got: {:#?}",
                    frame
                )))
            }
        }
    }

    pub(crate) async fn close_tunnel(&mut self) -> Result<TunnelTransit, TunnelError> {
        Ok(Transit::Terminate)
    }
}

impl OnionTunnel {
    pub fn unsubscribe(&mut self, _connection_id: u64) {}

    pub async fn new(
        packet_ids: Arc<Mutex<HashMap<PacketId, TunnelId>>>,
        tunnel_id: TunnelId,
        socket: Arc<UdpSocket>,
        source: Option<SocketAddr>,
        target: Option<SocketAddr>,
        _host_key: Vec<u8>,
        start_endpoint: bool,
    ) -> Self {
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);
        let mut app = TunnelStateMachine {
            event_rx,
            message_codec_in: Box::new(message_codec::PlainProtobuf {
                socket: socket.clone(),
                target: source,
            }),
            message_codec_out: Box::new(message_codec::PlainProtobuf {
                socket,
                target: None,
            }),
            is_endpoint: false,
            packet_ids,
            incoming_next_packet_ids: LinkedList::new(),
            outgoing_next_packet_ids: LinkedList::new(),
            tunnel_id,
        };
        let tunnel = OnionTunnel { event_tx };

        tokio::spawn(async move {
            // Start in Connecting state
            let mut trans = Transit::To(TunnelState::Connecting);

            loop {
                trans = match trans {
                    Transit::To(out) => {
                        let res = match out {
                            TunnelState::Connecting => app.tunnel_connect().await,
                            TunnelState::Connected => app.receive_packet().await,
                            TunnelState::Closing => app.close_tunnel().await,
                        };
                        match res {
                            Ok(t) => t,
                            Err(e) => {
                                log::warn!("{:?}", e);
                                return Err(e);
                            }
                        }
                    }
                    Transit::Terminate => return Ok(()),
                }
            }
        });

        if start_endpoint {
            let mut hello_msg = p2p_messages::TunnelHello::new();
            hello_msg.set_target(
                target
                    .expect("target must be set when start_endpoint is true")
                    .to_string(),
            );
            let msg = message_codec::start_endpoint_into_raw(&hello_msg.into()).unwrap();
            // Ignore error
            tunnel.event_tx.send(IoEvent::ReceiveData(msg)).await.ok();
        }

        tunnel
    }

    pub(crate) async fn forward_packet(&self, data: Vec<u8>) -> Result<(), TunnelError> {
        let res = self.event_tx.send(IoEvent::ReceiveData(data)).await;
        if res.is_err() {
            Err(TunnelError::TunnelClosed)
        } else {
            Ok(())
        }
    }
}
