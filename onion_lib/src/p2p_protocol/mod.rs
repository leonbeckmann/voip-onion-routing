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
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, Notify, RwLock};
use tokio::time::sleep;

// hard coded packet size should not be configurable and equal for all modules
// TODO select correct
pub(crate) const MAX_PACKET_SIZE: usize = 2048;
const CLIENT_HELLO_FORWARD_ID: FrameId = 1;

pub type TunnelId = u32;
type FrameId = u64;
pub type ConnectionId = u64;
type Registration = Arc<(Mutex<NotifyState>, Notify)>;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Direction {
    Forward,
    Backward,
}

#[derive(PartialEq)]
enum NotifyState {
    Inactive,
    Processing,
    Processed,
    Permitted,
    Cancelled,
}

struct RoundSynchronizer {
    update_notify: Arc<(Mutex<NotifyState>, Notify, Notify)>,
    new_notify: Arc<Mutex<VecDeque<Registration>>>,
    cover_notify: Arc<(Mutex<NotifyState>, Notify, Notify)>,
    round_time: Duration,
    registration_window: Duration,
    tunnel_registration_counter: Arc<Mutex<u8>>,
    round_cover_tunnel: Arc<Mutex<Option<TunnelId>>>,
    local_addr: String,
}

impl RoundSynchronizer {
    fn new(round_time: Duration, host: &str, port: u16) -> RoundSynchronizer {
        RoundSynchronizer {
            update_notify: Arc::new((
                Mutex::new(NotifyState::Inactive),
                Notify::new(),
                Notify::new(),
            )),
            new_notify: Arc::new(Mutex::new(VecDeque::new())),
            cover_notify: Arc::new((
                Mutex::new(NotifyState::Inactive),
                Notify::new(),
                Notify::new(),
            )),
            round_time,
            registration_window: round_time.saturating_sub(Duration::from_secs(1)), // TODO configurable
            tunnel_registration_counter: Arc::new(Mutex::new(0)),
            round_cover_tunnel: Arc::new(Mutex::new(None)),
            local_addr: format!("{}:{:?}", host, port),
        }
    }

    async fn process_tunnels(notify: Arc<(Mutex<NotifyState>, Notify, Notify)>) {
        let (lock, notifier_a, notifier_b) = &*notify;
        let mut status = lock.lock().await;
        *status = NotifyState::Processing;
        notifier_a.notify_one();

        // wait for result
        while *status != NotifyState::Processed {
            drop(status);
            notifier_b.notified().await;
            status = lock.lock().await;
        }
        *status = NotifyState::Inactive;
        drop(status);
    }

    async fn run(&self, tunnel_manager: Arc<RwLock<TunnelManager>>) {
        let update_notify = self.update_notify.clone();
        let new_notify = self.new_notify.clone();
        let cover_notify = self.cover_notify.clone();
        let round_time = self.round_time;
        let registration_window = self.registration_window;
        let build_window = round_time.saturating_sub(registration_window);
        let registration_counter = self.tunnel_registration_counter.clone();
        let addr = self.local_addr.clone();
        tokio::spawn(async move {
            loop {
                log::debug!(
                    "New round has started at {}. Duration={:?}",
                    addr,
                    round_time
                );
                // sleep until registration_window is closed
                sleep(registration_window).await;
                let update_notify = update_notify.clone();
                let new_notify = new_notify.clone();
                let cover_notify = cover_notify.clone();
                let registration_counter = registration_counter.clone();
                let addr2 = addr.clone();
                tokio::spawn(async move {
                    // first rebuild existent tunnels preprocessing
                    log::trace!("Process tunnel updates at {} for new round", addr2);
                    RoundSynchronizer::process_tunnels(update_notify).await;

                    // secondly new tunnels
                    let mut registrations = new_notify.lock().await;
                    log::trace!(
                        "Process {:?} new tunnel requests at {} for new round",
                        registrations.len(),
                        addr2
                    );
                    let mut registration_counter2 = registration_counter.lock().await;
                    while !registrations.is_empty() {
                        let entry = registrations.pop_front().unwrap();
                        let (lock, notifier) = &*entry;
                        let mut status = lock.lock().await;
                        // currently only allow one registration
                        if *registration_counter2 < 1 {
                            *status = NotifyState::Permitted;
                            *registration_counter2 += 1;
                        } else {
                            *status = NotifyState::Cancelled;
                        }
                        notifier.notify_one();
                    }
                    assert!(registrations.is_empty());
                    drop(registration_counter2);
                    drop(registrations);

                    // build cover tunnel
                    log::trace!("Process cover tunnels at {} for new round", addr2);
                    RoundSynchronizer::process_tunnels(cover_notify).await;
                    // clear registration_counter again for next registration window
                    *(registration_counter.lock().await) = 0;
                });
                // sleep for the rest of the round
                log::trace!("At {} sleep for the rest of the round", addr);
                sleep(build_window).await;
                log::trace!("At {} round is over, cleanup tunnels", addr);
                let tunnel_manager = tunnel_manager.clone();
                tokio::spawn(async move {
                    // shutdown old tunnels
                    tunnel_manager.write().await.round_cleanup().await;
                });
            }
        });
    }

    async fn run_update_task(&self, p2p_interface: Arc<P2pInterface>) {
        let notify = self.update_notify.clone();
        let registration_counter = self.tunnel_registration_counter.clone();
        let addr = self.local_addr.clone();
        tokio::spawn(async move {
            loop {
                // wait for round change
                let (lock, notifier_a, notifier_b) = &*notify;
                let mut status = lock.lock().await;
                while *status != NotifyState::Processing {
                    drop(status);
                    notifier_a.notified().await;
                    status = lock.lock().await;
                }

                // get connected initiator tunnels and register them all
                let ids = p2p_interface
                    .tunnel_manager
                    .read()
                    .await
                    .get_connected_initiator_tunnel_ids();
                assert!(ids.len() <= 1);
                let mut registration_counter = registration_counter.lock().await;
                *registration_counter = ids.len() as u8;
                drop(registration_counter);

                // update status and notify synchronizer
                *status = NotifyState::Processed;
                drop(status);
                notifier_b.notify_one();

                // update tunnel if available
                log::debug!(
                    "Registration_window is over, update initiator tunnel at {} if available",
                    addr
                );
                if let Some(id) = ids.first() {
                    p2p_interface.update_tunnel(*id).await;
                }
            }
        });
    }

    async fn run_cover_task(&self, p2p_interface: Arc<P2pInterface>) {
        let notify = self.cover_notify.clone();
        let registration_counter = self.tunnel_registration_counter.clone();
        let addr = self.local_addr.clone();
        tokio::spawn(async move {
            loop {
                // wait for round change
                let (lock, notifier_a, notifier_b) = &*notify;
                let mut status = lock.lock().await;
                while *status != NotifyState::Processing {
                    drop(status);
                    notifier_a.notified().await;
                    status = lock.lock().await;
                }

                // check if cover tunnel is required
                let registration_counter = registration_counter.lock().await;
                let required = *registration_counter < 1;
                drop(registration_counter);

                // update status and notify synchronizer
                *status = NotifyState::Processed;
                drop(status);
                notifier_b.notify_one();

                // build cover tunnel if required
                log::debug!(
                    "Registration_window is over, build cover tunnel at {} if required",
                    addr
                );
                if required {
                    match rps_api::rps_get_peer(p2p_interface.config.rps_api_address).await {
                        Ok((target, key)) => {
                            log::debug!("Build cover tunnel at {}", addr);
                            if let Err(e) =
                                p2p_interface.inner_build_tunnel(None, target, key).await
                            {
                                log::warn!("Cannot build cover tunnel at {}: {:?}", addr, e);
                            }
                        }
                        Err(e) => {
                            log::warn!("Cannot request random target peer from rps: {:?}", e);
                        }
                    }
                }
            }
        });
    }

    async fn wait(&self) -> Result<(), P2pError> {
        // create new waiter
        let notify = Arc::new((Mutex::new(NotifyState::Processing), Notify::new()));
        let notify2 = notify.clone();

        // register at synchronizer
        let (lock, notifier) = &*notify;
        let mut status = lock.lock().await;
        let mut guard = self.new_notify.lock().await;
        guard.push_back(notify2);
        drop(guard);

        // wait until result
        while *status == NotifyState::Processing {
            drop(status);
            notifier.notified().await;
            status = lock.lock().await;
        }

        // return result
        if *status == NotifyState::Permitted {
            Ok(())
        } else {
            Err(P2pError::OnionModuleEngaged)
        }
    }
}

pub(crate) struct P2pInterface {
    tunnel_manager: Arc<RwLock<TunnelManager>>,
    frame_id_manager: Arc<RwLock<FrameIdManager>>,
    socket: Arc<UdpSocket>,
    config: OnionConfiguration,
    api_interface: Weak<ApiInterface>,
    round_sync: RoundSynchronizer,
}

impl P2pInterface {
    pub(crate) async fn new(
        config: OnionConfiguration,
        api_interface: Weak<ApiInterface>,
    ) -> anyhow::Result<Self> {
        let round_sync =
            RoundSynchronizer::new(config.round_time, &config.p2p_hostname, config.p2p_port);
        Ok(Self {
            tunnel_manager: Arc::new(RwLock::new(TunnelManager::new())),
            frame_id_manager: Arc::new(RwLock::new(FrameIdManager::new())),
            socket: Arc::new(
                UdpSocket::bind(format!("{}:{:?}", config.p2p_hostname, config.p2p_port)).await?,
            ),
            config,
            api_interface,
            round_sync,
        })
    }

    pub(crate) async fn listen(&self, self_ref: Arc<P2pInterface>) -> Result<(), P2pError> {
        // run the tunnel update task
        self.round_sync.run_update_task(self_ref.clone()).await;
        // run the cover tunnel task
        self.round_sync.run_cover_task(self_ref.clone()).await;
        // run the round synchronizer
        self.round_sync.run(self_ref.tunnel_manager.clone()).await;
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
                                log::trace!(
                                    "UDP packet successfully parsed to TunnelFrame at {}",
                                    my_addr
                                );

                                let (tunnel_id, direction) = if frame.frame_id
                                    == CLIENT_HELLO_FORWARD_ID
                                {
                                    // frame id one is the initial handshake message (client_hello)
                                    log::debug!(
                                        "Frame is a new tunnel request. Create a new target tunnel at {}", my_addr
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
                                    log::trace!(
                                        "New target tunnel at {} has tunnel ID {:?}",
                                        my_addr,
                                        tunnel_id
                                    );
                                    (tunnel_id, Direction::Forward)
                                } else {
                                    // not a new tunnel request, get corresponding tunnel id from frame id
                                    let frame_id_manager = self.frame_id_manager.read().await;
                                    match frame_id_manager.get_tunnel_id(&frame.frame_id) {
                                        None => {
                                            // no tunnel available for the given frame
                                            log::warn!(
                                                "Received unexpected frame id at {}, drop the frame", my_addr
                                            );
                                            continue;
                                        }
                                        Some((tunnel_id, d)) => {
                                            log::debug!("Incoming frame (direction={:?}) at {} belongs to tunnel with ID {:?} ", d, my_addr, tunnel_id);
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
                                            "Received frame for not available tunnel with id {:?} at {}",
                                            tunnel_id, my_addr
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
        // wait for new round
        log::debug!("Received build_tunnel request from connection {:?} to {:?}. Wait for new round,build initiator tunnel and wait for handshake result", listener, target);
        self.round_sync.wait().await?;
        self.inner_build_tunnel(Some(listener), target, host_key)
            .await
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
        let mut tunnel_manager = self.tunnel_manager.write().await;
        let redirected_tunnel_id = tunnel_manager.resolve_tunnel_id(tunnel_id);
        log::debug!(
            "Destroy tunnel reference connection={:?}, tunnel={:?}, redirected_tunnel_id={:?}",
            connection_id,
            tunnel_id,
            redirected_tunnel_id
        );
        let res = match tunnel_manager.get_tunnel(&redirected_tunnel_id) {
            None => {
                return Err(P2pError::InvalidTunnelId(tunnel_id));
            }
            Some(tunnel) => tunnel.unsubscribe(connection_id).await,
        };
        if res {
            tunnel_manager.downgrade_tunnel(&redirected_tunnel_id);
        }
        Ok(())
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
    pub(crate) async fn send_cover_traffic(&self, cover_size: u16) -> Result<(), P2pError> {
        match *self.round_sync.round_cover_tunnel.lock().await {
            None => Err(P2pError::CoverFailure),
            Some(id) => {
                let tunnel_manager = self.tunnel_manager.read().await;
                let redirected_tunnel_id = tunnel_manager.resolve_tunnel_id(id);
                let tunnel = tunnel_manager.get_tunnel(&redirected_tunnel_id);
                match tunnel {
                    Some(tunnel) => {
                        log::trace!(
                            "Tunnel={:?} (redirected_tunnel_id={:?}): Send cover traffic",
                            id,
                            redirected_tunnel_id
                        );
                        let data = (0..cover_size).map(|_| rand::random::<u8>()).collect();
                        tunnel.send_cover(data).await
                    }
                    None => Err(P2pError::CoverFailure),
                }
            }
        }
    }

    async fn inner_build_tunnel(
        &self,
        listener: Option<ConnectionId>,
        target: SocketAddr,
        host_key: Vec<u8>,
    ) -> Result<(TunnelId, Vec<u8>), P2pError> {
        let (tx, rx) = oneshot::channel::<TunnelResult>();
        let update_info = listener
            .map(|listener_id| UpdateInformation::new(listener_id, (target, host_key.clone())));
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
            update_info,
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
                    self.tunnel_manager
                        .write()
                        .await
                        .set_connected(&tunnel_id, listener.is_none());
                    *self.round_sync.round_cover_tunnel.lock().await = Some(tunnel_id);
                    log::debug!("Tunnel with ID={:?} established", tunnel_id);
                    Ok((tunnel_id, host_key))
                }
                TunnelResult::Failure(e) => {
                    log::warn!("Building tunnel failed: Handshake failure {:?}", e);
                    Err(P2pError::HandshakeFailure(e))
                }
            },
            Err(_) => {
                log::warn!(
                    "Building tunnel failed: Tunnel (ID={:?}) has closed",
                    tunnel_id
                );
                Err(P2pError::TunnelClosed)
            }
        }
    }

    async fn update_tunnel(&self, tunnel_id: TunnelId) {
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
        log::trace!(
            "Tunnel={:?}: Tunnel update reference for target is {:?}",
            tunnel_id,
            frame_id
        );

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
                    _ => {
                        log::warn!("Tunnel={:?}: Cannot update target/cover tunnel.", tunnel_id);
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
                TunnelStatus::Downgraded => {
                    log::warn!("Tunnel={:?}: Cannot update downgraded tunnel.", tunnel_id);
                    return;
                }
            },
        };

        // create a new tunnel from Initiator to target and reference the old tunnel
        log::trace!("Tunnel={:?}: Start creating new tunnel", tunnel_id);
        let (tx, rx) = oneshot::channel::<TunnelResult>();
        let new_tunnel_id = match OnionTunnel::new_initiator_tunnel(
            Some(update_info.listener),
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
            Some(update_info),
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
                    let mut tunnel_manager_guard = self.tunnel_manager.write().await;
                    tunnel_manager_guard.set_connected(&new_tunnel_id, false);
                    log::debug!(
                        "Tunnel={:?}: New tunnel with ID={:?} established",
                        tunnel_id,
                        new_tunnel_id
                    );

                    // redirect the tunnel id
                    tunnel_manager_guard.add_redirection_link(tunnel_id, new_tunnel_id);

                    // destroy the old tunnel
                    match tunnel_manager_guard.get_tunnel(&tunnel_id) {
                        None => {
                            // the old tunnel has been closed during the tunnel update, close the new one
                            log::debug!("Tunnel={:?}: Tunnel with id={:?} has been closed during updating, close new tunnel", new_tunnel_id, tunnel_id);
                            tunnel_manager_guard.downgrade_tunnel(&new_tunnel_id);
                            if let Some(tunnel) = tunnel_manager_guard.get_tunnel(&new_tunnel_id) {
                                tunnel.close_tunnel().await;
                            }
                        }
                        Some(tunnel) => {
                            // FIXME this should be done at the end of the round
                            tunnel.shutdown_tunnel().await;
                        }
                    }
                }
                TunnelResult::Failure(e) => {
                    log::warn!("Tunnel={:?}: Cannot update tunnel: {:?}", tunnel_id, e);
                }
            },
            Err(e) => {
                log::warn!("Tunnel={:?}: Cannot update tunnel: {:?}", tunnel_id, e);
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
    #[error("Cannot create onion tunnel since module is already in use by too many callers")]
    OnionModuleEngaged,
    #[error("Cannot rebuild the onion tunnel")]
    TunnelRebuildFailure,
    #[error("Cannot send cover traffic since no cover tunnel is available")]
    CoverFailure,
    #[error("Action not supported for cover-only tunnel")]
    CoverOnlyTunnel,
}
