mod messages;
pub mod onion_tunnel;
pub mod rps_api;

use crate::api_protocol::ApiInterface;
use crate::config_parser::OnionConfiguration;
use crate::p2p_protocol::messages::p2p_messages::TunnelFrame;
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
use crate::p2p_protocol::onion_tunnel::fsm::{FsmEvent, ProtocolError};
use crate::p2p_protocol::onion_tunnel::{OnionTunnel, TunnelResult};
use protobuf::Message;
use std::sync::{Arc, Weak};
use std::{collections::HashMap, net::SocketAddr};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::{oneshot, RwLock};

// hard coded packet size should not be configurable and equal for all modules
// TODO select correct
pub(crate) const MAX_PACKET_SIZE: usize = 2048;

pub type TunnelId = u32;
type FrameId = u64;
pub type ConnectionId = u64;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Direction {
    Forward,
    Backward,
}

pub(crate) struct P2pInterface {
    onion_tunnels: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
    frame_id_manager: Arc<RwLock<FrameIdManager>>,
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
            frame_id_manager: Arc::new(RwLock::new(FrameIdManager::new())),
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
        let mut buf = [0u8; MAX_PACKET_SIZE + 1];
        let my_addr = format!("{}:{:?}", self.config.p2p_hostname, self.config.p2p_port);
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, addr)) => {
                    if size <= MAX_PACKET_SIZE {
                        log::debug!("Received UDP packet from {:?} at {}", addr, my_addr);

                        // parse tunnel frame
                        match TunnelFrame::parse_from_bytes(&buf[0..size]) {
                            Ok(frame) => {
                                // check if data available, which should always be the case
                                log::trace!("UDP packet successfully parsed to TunnelFrame");

                                let (tunnel_id, direction) = if frame.frame_id == 1 {
                                    // frame id one is the initial handshake message (client_hello)
                                    log::debug!(
                                        "Frame is a new tunnel request. Create a new target tunnel"
                                    );
                                    // build a new target tunnel
                                    let tunnel_id = OnionTunnel::new_target_tunnel(
                                        self.frame_id_manager.clone(),
                                        self.socket.clone(),
                                        addr,
                                        self.onion_tunnels.clone(),
                                        self.api_interface.clone(),
                                        self.config.crypto_config.clone(),
                                        self.config.handshake_message_timeout,
                                        self.config.timeout,
                                    )
                                    .await;
                                    log::trace!("New target tunnel has tunnel ID {:?}", tunnel_id);
                                    (tunnel_id, Direction::Forward)
                                } else {
                                    // not a new tunnel request, get corresponding tunnel id from frame id
                                    let frame_id_manager = self.frame_id_manager.read().await;
                                    match frame_id_manager.get_tunnel_id(&frame.frame_id) {
                                        None => {
                                            // no tunnel available for the given frame
                                            log::warn!(
                                                "Received unexpected frame id, drop the frame"
                                            );
                                            continue;
                                        }
                                        Some((tunnel_id, d)) => {
                                            log::debug!("Incoming frame (direction={:?}) belongs to tunnel with ID {:?} ", d, tunnel_id);
                                            (tunnel_id, d)
                                        }
                                    }
                                };

                                let event =
                                    FsmEvent::IncomingFrame((frame.data, direction, frame.iv));

                                let tunnels = self.onion_tunnels.lock().await;
                                match tunnels.get(&tunnel_id) {
                                    None => {
                                        // should never happen, means outdated frame_ids
                                        log::warn!(
                                            "Received frame for not available tunnel with id {:?}",
                                            tunnel_id
                                        );
                                    }
                                    Some(tunnel) => {
                                        // forward message to tunnel
                                        log::trace!(
                                            "Forward the parsed frame to the tunnel (ID {:?})",
                                            tunnel_id
                                        );
                                        if tunnel.forward_event(event).await.is_err() {
                                            // it seems that the tunnel is currently closing
                                            log::warn!("Cannot forward the parsed frame since the tunnel (ID {:?}) has been closed", tunnel_id);
                                        }
                                    }
                                };
                            }
                            Err(_) => {
                                log::warn!(
                                    "Cannot parse UDP packet from {:?} at {:?} to tunnel frame.",
                                    addr,
                                    my_addr
                                );
                            }
                        };
                    } else {
                        log::warn!(
                            "Dropping received UDP packet from {:?} at {:?} because of packet size",
                            addr,
                            my_addr
                        );
                    }
                }
                Err(e) => {
                    log::error!("Cannot read from UDP socket at {:?}: {}", my_addr, e);
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
        log::debug!(
            "Unsubscribe connection {:?} from all tunnels",
            connection_id
        );
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

        log::debug!("Received build_tunnel request from connection {:?} to {:?}. Build initiator tunnel and wait for handshake result", listener, target);
        let tunnel_id = match OnionTunnel::new_initiator_tunnel(
            listener,
            self.frame_id_manager.clone(),
            self.socket.clone(),
            target,
            host_key.clone(),
            self.onion_tunnels.clone(),
            self.config.hop_count,
            self.config.rps_api_address,
            tx,
            self.api_interface.clone(),
            self.config.crypto_config.clone(),
            self.config.handshake_message_timeout,
            self.config.timeout,
        )
        .await
        {
            Ok(id) => id,
            Err(e) => return Err(P2pError::HandshakeFailure(e)),
        };

        // wait until connected or failure
        match rx.await {
            Ok(res) => match res {
                TunnelResult::Connected => {
                    log::debug!("Tunnel with ID={:?} established", tunnel_id);
                    Ok((tunnel_id, host_key))
                }
                TunnelResult::Failure(e) => {
                    log::warn!("Request build_tunnel failed: Handshake failure {:?}", e);
                    Err(P2pError::HandshakeFailure(e))
                }
            },
            Err(_) => {
                log::warn!(
                    "Request build_tunnel failed: Tunnel (ID={:?}) has closed",
                    tunnel_id
                );
                Err(P2pError::TunnelClosed)
            }
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
        log::debug!(
            "Destroy tunnel reference connection={:?}, tunnel={:?}",
            connection_id,
            tunnel_id
        );
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
            Some(tunnel) => {
                log::debug!("Tunnel={:?}: Send data", tunnel_id);
                tunnel.send(data).await
            }
            None => {
                log::warn!("Cannot send data due to unknown tunnel ID={:?}", tunnel_id);
                Err(P2pError::InvalidTunnelId(tunnel_id))
            }
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
