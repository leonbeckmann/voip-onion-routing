mod messages;
pub mod onion_tunnel;
pub mod rps_api;

use crate::api_protocol::ApiInterface;
use crate::config_parser::OnionConfiguration;
use crate::p2p_protocol::messages::p2p_messages::TunnelFrame;
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
use crate::p2p_protocol::onion_tunnel::fsm::{FsmEvent, ProtocolError};
use crate::p2p_protocol::onion_tunnel::tunnel_manager::TunnelManager;
use crate::p2p_protocol::onion_tunnel::{
    OnionTunnel, TunnelResult, TunnelStatus, TunnelType, UpdateInformation,
};
use protobuf::Message;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, RwLock};

// hard coded packet size should not be configurable and equal for all modules
// TODO select correct
pub(crate) const MAX_PACKET_SIZE: usize = 2048;
const CLIENT_HELLO_FORWARD_ID: FrameId = 1;

pub type TunnelId = u32;
type FrameId = u64;
pub type ConnectionId = u64;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Direction {
    Forward,
    Backward,
}

pub(crate) struct P2pInterface {
    tunnel_manager: Arc<RwLock<TunnelManager>>,
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
            tunnel_manager: Arc::new(RwLock::new(TunnelManager::new())),
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

                                let (tunnel_id, direction) = if frame.frame_id
                                    == CLIENT_HELLO_FORWARD_ID
                                {
                                    // frame id one is the initial handshake message (client_hello)
                                    log::debug!(
                                        "Frame is a new tunnel request. Create a new target tunnel"
                                    );
                                    // build a new target tunnel
                                    let tunnel_id = OnionTunnel::new_target_tunnel(
                                        self.frame_id_manager.clone(),
                                        self.socket.clone(),
                                        addr,
                                        self.tunnel_manager.clone(),
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

                                let tunnel_manager = self.tunnel_manager.read().await;
                                match tunnel_manager.get_tunnel(&tunnel_id) {
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
        self.tunnel_manager
            .write()
            .await
            .unsubscribe(connection_id)
            .await;
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
            self.tunnel_manager.clone(),
            self.config.hop_count,
            self.config.rps_api_address,
            tx,
            self.api_interface.clone(),
            self.config.crypto_config.clone(),
            self.config.handshake_message_timeout,
            self.config.timeout,
            None,
            UpdateInformation::new(listener, (target, host_key.clone())),
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
                    self.tunnel_manager.write().await.set_connected(&tunnel_id);
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
        let tunnel_manager = self.tunnel_manager.read().await;
        let redirected_tunnel_id = tunnel_manager.resolve_tunnel_id(tunnel_id);
        log::debug!(
            "Destroy tunnel reference connection={:?}, tunnel={:?}, redirected_tunnel_id={:?}",
            connection_id,
            tunnel_id,
            redirected_tunnel_id
        );
        match tunnel_manager.get_tunnel(&redirected_tunnel_id) {
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
        let tunnel_manager = self.tunnel_manager.read().await;
        let redirected_tunnel_id = tunnel_manager.resolve_tunnel_id(tunnel_id);
        let tunnel = tunnel_manager.get_tunnel(&redirected_tunnel_id);
        match tunnel {
            Some(tunnel) => {
                log::debug!(
                    "Tunnel={:?} (redirected_tunnel_id={:?}): Send data",
                    tunnel_id,
                    redirected_tunnel_id
                );
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

    async fn update_tunnel(&mut self, tunnel_id: TunnelId) {
        log::debug!("Tunnel={:?}: Start updating", tunnel_id);
        // get tunnel update reference
        let frame_id = match self
            .frame_id_manager
            .read()
            .await
            .get_tunnel_reference(&tunnel_id)
        {
            None => {
                log::warn!(
                    "Tunnel={:?}: Cannot update tunnel, reference id not available.",
                    tunnel_id
                );
                return;
            }
            Some(id) => *id,
        };

        // only update connected tunnels where we are the initiator
        let update_info = match self.tunnel_manager.read().await.get_tunnel(&tunnel_id) {
            None => {
                log::warn!(
                    "Tunnel with id={:?} not found in registry. Update failed.",
                    tunnel_id
                );
                return;
            }
            Some(tunnel) => match tunnel.status {
                TunnelStatus::Connected => match &tunnel.tunnel_type {
                    TunnelType::Initiator(update_info) => {
                        UpdateInformation::new(update_info.listener, update_info.target.clone())
                    }
                    TunnelType::Target => {
                        log::warn!("Tunnel={:?}: Cannot update target tunnel.", tunnel_id);
                        return;
                    }
                },
                TunnelStatus::Connecting => {
                    log::warn!(
                        "Tunnel={:?}: Cannot update non-connected tunnel.",
                        tunnel_id
                    );
                    return;
                }
            },
        };

        // create a new tunnel from Initiator to target and reference the old tunnel
        let (tx, rx) = oneshot::channel::<TunnelResult>();
        let new_tunnel_id = match OnionTunnel::new_initiator_tunnel(
            update_info.listener,
            self.frame_id_manager.clone(),
            self.socket.clone(),
            update_info.target.0,
            update_info.target.1.clone(),
            self.tunnel_manager.clone(),
            self.config.hop_count,
            self.config.rps_api_address,
            tx,
            self.api_interface.clone(),
            self.config.crypto_config.clone(),
            self.config.handshake_message_timeout,
            self.config.timeout,
            Some(frame_id),
            update_info,
        )
        .await
        {
            Ok(id) => id,
            Err(e) => {
                log::warn!("Tunnel={:?}: Cannot update tunnel: {:?}", tunnel_id, e);
                return;
            }
        };

        // wait until connected or failure
        match rx.await {
            Ok(res) => match res {
                TunnelResult::Connected => {
                    self.tunnel_manager.write().await.set_connected(&tunnel_id);
                    log::debug!("Tunnel with ID={:?} established", tunnel_id);
                }
                TunnelResult::Failure(e) => {
                    log::warn!("Tunnel={:?}: Cannot update tunnel: {:?}", tunnel_id, e);
                    return;
                }
            },
            Err(e) => {
                log::warn!("Tunnel={:?}: Cannot update tunnel: {:?}", tunnel_id, e);
                return;
            }
        }

        // redirect the tunnel id
        self.tunnel_manager
            .write()
            .await
            .add_redirection_link(tunnel_id, new_tunnel_id);

        // destroy the old tunnel
        let tunnel_manager_guard = self.tunnel_manager.read().await;
        match tunnel_manager_guard.get_tunnel(&tunnel_id) {
            None => {
                // the old tunnel has been closed during the tunnel update, close the new one
                log::debug!("Tunnel={:?}: Tunnel with id={:?} has been closed during updating, close new tunnel", new_tunnel_id, tunnel_id);
                if let Some(tunnel) = tunnel_manager_guard.get_tunnel(&new_tunnel_id) {
                    tunnel.close_tunnel().await;
                }
            }
            Some(tunnel) => {
                tunnel.shutdown_tunnel().await;
            }
        }
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
