mod messages;
mod onion_tunnel;

use crate::api_protocol::ApiInterface;
use crate::config_parser::OnionConfiguration;
use crate::p2p_protocol::messages::p2p_messages::{TunnelFrame, TunnelFrame_oneof_message};
use crate::p2p_protocol::onion_tunnel::fsm::{FsmEvent, ProtocolError};
use crate::p2p_protocol::onion_tunnel::{OnionTunnel, TunnelResult};
use protobuf::Message;
use std::sync::{Arc, Weak};
use std::{collections::HashMap, net::SocketAddr};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::sync::Mutex;

// hard coded packet size should not be configurable and equal for all modules
pub(crate) const PACKET_SIZE: usize = 1024;

pub type TunnelId = u32;
type FrameId = u64;
pub type ConnectionId = u64;

#[derive(Debug)]
pub enum Direction {
    Forward,
    Backward,
}

impl ToOwned for Direction {
    type Owned = Direction;

    fn to_owned(&self) -> Self::Owned {
        match self {
            Direction::Forward => Direction::Forward,
            Direction::Backward => Direction::Backward,
        }
    }
}

pub(crate) struct P2pInterface {
    // TODO is there a way for a more well-distributed key?
    // TODO maybe rw lock for better performance?
    onion_tunnels: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    socket: Arc<UdpSocket>,
    config: OnionConfiguration,
    api_interface: Weak<ApiInterface>,
}

impl P2pInterface {
    pub(crate) async fn new(
        config: OnionConfiguration,
        api_interface: Weak<ApiInterface>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            onion_tunnels: Arc::new(Mutex::new(HashMap::new())),
            frame_ids: Arc::new(Mutex::new(HashMap::new())),
            socket: Arc::new(
                UdpSocket::bind(format!("{}:{:?}", config.p2p_hostname, config.p2p_port)).await?,
            ),
            config,
            api_interface,
        })
    }

    pub(crate) async fn listen(&self) -> Result<(), P2pError> {
        // Allow to receive more than expected to detect messages exceeding the fixed size.
        // Otherwise recv_from would silently discards exceeding bytes.
        let mut buf = [0u8; PACKET_SIZE + 1];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, addr)) => {
                    if size == PACKET_SIZE {
                        log::debug!("Received UDP packet with valid length from {:?}", addr);

                        // parse tunnel frame
                        match TunnelFrame::parse_from_bytes(&buf[0..PACKET_SIZE]) {
                            Ok(frame) => {
                                // check if data available, which should always be the case
                                let frame_message = match frame.message {
                                    None => {
                                        log::warn!("Received empty frame");
                                        continue;
                                    }
                                    Some(message) => message,
                                };

                                let (tunnel_id, direction) = if frame.frameId == 1 {
                                    // frame id one is the initial handshake message (client_hello)

                                    // build a new target tunnel
                                    let tunnel_id = OnionTunnel::new_target_tunnel(
                                        self.frame_ids.clone(),
                                        self.socket.clone(),
                                        addr,
                                        self.onion_tunnels.clone(),
                                        self.api_interface.clone(),
                                    )
                                    .await;

                                    (tunnel_id, Direction::Forward)
                                } else {
                                    // not a new tunnel request, get corresponding tunnel id from frame id
                                    let frame_ids = self.frame_ids.lock().await;
                                    match frame_ids.get(&frame.frameId) {
                                        None => {
                                            // no tunnel available for the given frame
                                            log::warn!(
                                                "Received unexpected frame id, drop the frame"
                                            );
                                            continue;
                                        }
                                        Some((tunnel_id, d)) => (*tunnel_id, d.to_owned()),
                                    }
                                };

                                let event = match frame_message {
                                    TunnelFrame_oneof_message::data(data) => {
                                        FsmEvent::IncomingFrame((data, direction))
                                    }
                                    TunnelFrame_oneof_message::close(_) => FsmEvent::RecvClose,
                                };

                                let mut tunnels = self.onion_tunnels.lock().await;
                                match tunnels.get(&tunnel_id) {
                                    None => {
                                        log::warn!(
                                            "Received frame for not available tunnel with id {:?}",
                                            tunnel_id
                                        );
                                    }
                                    Some(tunnel) => {
                                        // forward message to tunnel
                                        if tunnel.forward_event(event).await.is_err() {
                                            // tunnel has been closed, remove tunnel from registry
                                            let _ = tunnels.remove(&tunnel_id);
                                        }
                                    }
                                };
                            }
                            Err(_) => {
                                log::warn!(
                                    "Cannot parse UDP packet from {:?} to tunnel frame.",
                                    addr
                                );
                            }
                        };
                    } else {
                        log::warn!(
                            "Dropping received UDP packet from {:?} because of packet size",
                            addr
                        );
                    }
                }
                Err(e) => {
                    log::error!("Cannot read from UDP socket {}", e);
                    return Err(P2pError::IOError(e));
                }
            };
        }
    }

    /**
     *  Unsubscribe connection from all tunnels due to connection closure
     */
    pub(crate) async fn unsubscribe(&self, connection_id: ConnectionId) {
        // call unsubscribe on all tunnels
        let mut onion_tunnels = self.onion_tunnels.lock().await;
        for (_, tunnel) in onion_tunnels.iter_mut() {
            tunnel.unsubscribe(connection_id).await;
        }
    }

    /**
     *  Build a new onion tunnel (initiator) triggered from the api protocol
     *
     *  Return the tunnel_id and the target peer public key (DER)
     */
    pub(crate) async fn build_tunnel(
        &self,
        target: SocketAddr,
        host_key: Vec<u8>,
        listener: ConnectionId,
    ) -> Result<(TunnelId, Vec<u8>), P2pError> {
        let (tx, rx) = oneshot::channel::<TunnelResult>();

        let tunnel_id = OnionTunnel::new_initiator_tunnel(
            listener,
            self.frame_ids.clone(),
            self.socket.clone(),
            target,
            host_key.clone(),
            self.onion_tunnels.clone(),
            self.config.hop_count,
            self.config.rps_api_address,
            tx,
            self.api_interface.clone(),
        )
        .await;

        // wait until connected or failure
        match rx.await {
            Ok(res) => match res {
                TunnelResult::Connected => Ok((tunnel_id, host_key)),
                TunnelResult::Failure(e) => Err(P2pError::HandshakeFailure(e)),
            },
            Err(_) => Err(P2pError::TunnelClosed),
        }
    }

    /*
     *  Unsubscribe connection from specific tunnel
     */
    pub(crate) async fn destroy_tunnel_ref(
        &self,
        tunnel_id: TunnelId,
        connection_id: ConnectionId,
    ) -> Result<(), P2pError> {
        // call unsubscribe on specific tunnel
        let onion_tunnels = self.onion_tunnels.lock().await;
        match onion_tunnels.get(&tunnel_id) {
            None => Err(P2pError::InvalidTunnelId(tunnel_id)),
            Some(tunnel) => {
                tunnel.unsubscribe(connection_id).await;
                Ok(())
            }
        }
    }

    /*
     *  Send data via specific tunnel
     */
    pub(crate) async fn send_data(
        &self,
        tunnel_id: TunnelId,
        data: Vec<u8>,
    ) -> Result<(), P2pError> {
        let tunnels = self.onion_tunnels.lock().await;
        let tunnel = tunnels.get(&tunnel_id);

        match tunnel {
            Some(tunnel) => tunnel.send(data).await,
            None => Err(P2pError::InvalidTunnelId(tunnel_id)),
        }
    }

    /// Send cover traffic via new random tunnel
    /// API protocol
    pub(crate) async fn send_cover_traffic(&self, _cover_size: u16) -> Result<(), P2pError> {
        // TODO implement logic
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum P2pError {
    #[error("Onion tunnel with ID '{0}' is not existent")]
    InvalidTunnelId(u32),
    #[error("Onion tunnel closed")]
    TunnelClosed,
    #[error("Handshake failed: {0}")]
    HandshakeFailure(ProtocolError),
    #[error("IO Error: {0}")]
    IOError(std::io::Error),
}

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> Self {
        Self::IOError(e)
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    #[test]
    fn unit_test() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:2000").await.unwrap();
            let client = UdpSocket::bind("127.0.0.1:2001").await.unwrap();

            client.connect("127.0.0.1:2000").await.unwrap();
            client.send("Data".as_bytes()).await.unwrap();

            let mut buf = [0u8; 3];
            let (size, _addr) = socket.recv_from(&mut buf).await.unwrap();
            println!("{:?}", size);
        });
    }
}
