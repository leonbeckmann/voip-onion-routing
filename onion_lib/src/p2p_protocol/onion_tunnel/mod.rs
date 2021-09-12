use std::collections::HashSet;
use std::sync::Weak;
use std::{net::SocketAddr, sync::Arc};

use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot, Mutex, Notify, RwLock,
};

use openssl::sha;

use crate::api_protocol::ApiInterface;
use crate::p2p_protocol::onion_tunnel::fsm::{
    FiniteStateMachine, FsmEvent, InitiatorStateMachine, ProtocolError, TargetStateMachine,
};
use crate::p2p_protocol::{ConnectionId, FrameId, P2pError};

use super::dtls_connections::{Blocklist, DtlsSocketLayer};
use super::TunnelId;
use crate::p2p_protocol::onion_tunnel::crypto::HandshakeCryptoConfig;
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
use crate::p2p_protocol::onion_tunnel::tunnel_manager::TunnelManager;
use crate::p2p_protocol::rps_api::rps_get_peer_filtered;
use std::time::Duration;

pub mod crypto;
pub(crate) mod frame_id_manager;
pub(crate) mod fsm;
pub(crate) mod message_codec;
pub(crate) mod tunnel_manager;

pub enum TunnelResult {
    Connected,
    Failure(ProtocolError),
}

#[derive(PartialEq)]
pub enum FsmLockState {
    HandshakeDone,
    Processing,
    WaitForEvent,
}

/*
 *  An enum send by the FSM to the tunnel via an mpsc channel. IncomingData will be passed to the
 *  user. IncomingTunnelCompletion signals the tunnel mgmt layer that the tunnel is connected and
 *  the API should be notified now via the IncomingTunnel message.
 */
enum IncomingEventMessage {
    TunnelCompletion,
    CoverTunnelCompletion,
    TunnelUpdate(FrameId),
    Data(Vec<u8>),
    Downgraded,
}

pub(crate) type Peer = (SocketAddr, Vec<u8>);
type Listeners = Arc<Mutex<HashSet<ConnectionId>>>;

#[derive(PartialEq)]
pub(crate) struct UpdateInformation {
    pub listener: ConnectionId,
    pub target: Peer,
}

impl UpdateInformation {
    pub fn new(listener: ConnectionId, target: Peer) -> UpdateInformation {
        UpdateInformation { listener, target }
    }
}

#[derive(PartialEq)]
pub(crate) enum TunnelType {
    Initiator(UpdateInformation),
    NonInitiator,
}

#[derive(Debug, PartialEq)]
pub(crate) enum TunnelStatus {
    Connecting,
    Connected,
    Downgraded,
}

// TODO: Add Test for assertion: Downgraded Tunnels must not have any listeners anymore
// TODO: Add Test for assertion: TunnelStatus == Downgrade <=> FSM.state == Downgraded
pub(crate) struct OnionTunnel {
    listeners: Arc<(Mutex<bool>, Listeners, Notify)>, // all the api connection listeners
    tunnel_id: TunnelId,                              // unique tunnel id
    lifo_event_sender: Sender<FsmEvent>,
    pub tunnel_type: TunnelType,
    pub status: TunnelStatus,
}

impl OnionTunnel {
    pub fn is_connected(&self) -> bool {
        matches!(self.status, TunnelStatus::Connected)
    }

    pub fn is_initiator(&self) -> bool {
        matches!(self.tunnel_type, TunnelType::Initiator(_))
    }

    pub fn is_downgraded(&self) -> bool {
        matches!(self.status, TunnelStatus::Downgraded)
    }

    pub fn set_connected(&mut self) {
        // set status
        self.status = TunnelStatus::Connected;
    }

    pub async fn downgrade(&mut self) {
        // set status
        self.status = TunnelStatus::Downgraded;
        // clear listeners
        self.clear_listeners().await;
    }

    async fn get_listeners(listeners: Arc<(Mutex<bool>, Listeners, Notify)>) -> Listeners {
        // wait until available and then return listeners
        let (lock, listeners, notify) = &*listeners;
        let mut status = lock.lock().await;
        while !*status {
            drop(status);
            notify.notified().await;
            status = lock.lock().await;
        }
        assert!(*status);
        listeners.clone()
    }

    pub async fn set_listeners(&mut self, listeners: HashSet<ConnectionId>, force: bool) {
        let (lock, listeners_ref, notify) = &*self.listeners;
        let mut status = lock.lock().await;
        // do not override
        if !*status || force {
            let mut listener_guard = listeners_ref.lock().await;
            log::trace!(
                "Tunnel={:?}: Set listeners to {:?}",
                self.tunnel_id,
                listeners
            );
            *listener_guard = listeners;
            *status = true;
        } else {
            log::warn!("Tunnel={:?}: Cannot override listeners", self.tunnel_id);
        }
        notify.notify_waiters();
    }

    async fn clear_listeners(&mut self) {
        log::trace!("Tunnel={:?}: Clear listeners", self.tunnel_id);
        self.set_listeners(HashSet::new(), true).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_tunnel(
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        listeners: Arc<(Mutex<bool>, Listeners, Notify)>,
        tunnel_manager: Arc<RwLock<TunnelManager>>,
        event_tx: Sender<FsmEvent>,
        tunnel_id: TunnelId,
        mut mgmt_rx: Receiver<IncomingEventMessage>,
        api_interface: Weak<ApiInterface>,
        fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
        tunnel_type: TunnelType,
    ) {
        // clone the sender for init
        let event_tx_clone = event_tx.clone();

        let (lifo_event_sender, mut lifo_event_receiver) = tokio::sync::mpsc::channel(32);

        // create tunnel
        let tunnel = OnionTunnel {
            listeners: listeners.clone(),
            tunnel_id,
            lifo_event_sender,
            tunnel_type,
            status: TunnelStatus::Connecting,
        };

        // register tunnel at registry
        {
            tunnel_manager
                .write()
                .await
                .insert_tunnel(tunnel_id, tunnel);
        }

        // start management task that manages tunnel cleanup and listener notification
        tokio::spawn(async move {
            log::trace!("Tunnel={:?}: Run the async management task", tunnel_id);
            loop {
                match mgmt_rx.recv().await {
                    None => {
                        // here the FSM has been dropped.
                        log::debug!(
                            "Tunnel={:?}: Received a closure from the FSM. Unregister the tunnel and shutdown the management layer",
                            tunnel_id
                        );
                        let mut tunnel_manager_guard = tunnel_manager.write().await;
                        tunnel_manager_guard.remove_tunnel(&tunnel_id);
                        frame_id_manager.write().await.tunnel_closure(tunnel_id);
                        return;
                    }

                    // communicate with api interface
                    Some(m) => {
                        if let Some(iface) = api_interface.upgrade() {
                            match m {
                                IncomingEventMessage::TunnelCompletion => {
                                    log::debug!(
                                        "Tunnel={:?}: Received TunnelCompletion, delegate to API",
                                        tunnel_id
                                    );

                                    // get listeners
                                    let connections = iface.connections.lock().await;
                                    let raw_listeners = connections
                                        .keys()
                                        .cloned()
                                        .collect::<HashSet<ConnectionId>>();
                                    drop(connections);
                                    log::debug!(
                                        "Tunnel={:?}: Listeners={:?}",
                                        tunnel_id,
                                        raw_listeners
                                    );

                                    let mut tunnel_manager_guard = tunnel_manager.write().await;
                                    // check if listeners are empty, then we want to downgrade the tunnel
                                    if raw_listeners.is_empty() {
                                        tunnel_manager_guard
                                            .downgrade_tunnel(&tunnel_id, true)
                                            .await;
                                        continue;
                                    }
                                    tunnel_manager_guard.set_connected(&tunnel_id);
                                    tunnel_manager_guard
                                        .register_listeners(&tunnel_id, raw_listeners)
                                        .await;
                                    let listeners =
                                        OnionTunnel::get_listeners(listeners.clone()).await;
                                    drop(tunnel_manager_guard);
                                    iface.incoming_tunnel(tunnel_id, listeners).await;
                                }
                                IncomingEventMessage::CoverTunnelCompletion => {
                                    log::debug!(
                                        "Tunnel={:?}: Received CoverTunnelCompletion",
                                        tunnel_id
                                    );
                                    tunnel_manager
                                        .write()
                                        .await
                                        .downgrade_tunnel(&tunnel_id, false)
                                        .await;
                                }
                                IncomingEventMessage::TunnelUpdate(tunnel_update_ref) => {
                                    // this target tunnel is an update for an old one
                                    log::debug!("Tunnel={:?}: Received TunnelUpdate", tunnel_id);
                                    // redirect tunnel id
                                    let old_tunnel_id = match frame_id_manager
                                        .read()
                                        .await
                                        .get_tunnel_id(&tunnel_update_ref)
                                    {
                                        None => {
                                            // failure, downgrade new tunnel to cover tunnel
                                            log::debug!("Tunnel={:?}: Cannot find tunnel_update_reference. Close new tunnel", tunnel_id);
                                            tunnel_manager
                                                .write()
                                                .await
                                                .downgrade_tunnel(&tunnel_id, true)
                                                .await;
                                            continue;
                                        }
                                        Some((tunnel_id, _)) => tunnel_id,
                                    };

                                    let mut tunnel_manager_guard = tunnel_manager.write().await;
                                    // redirect the tunnel id such that the old tunnel is not used anymore for outgoing traffic
                                    tunnel_manager_guard
                                        .add_redirection_link(old_tunnel_id, tunnel_id);
                                    let downgrade = match tunnel_manager_guard
                                        .get_tunnel(&old_tunnel_id)
                                    {
                                        None => true,
                                        Some(tunnel) => {
                                            if tunnel.status == TunnelStatus::Downgraded {
                                                true
                                            } else {
                                                // take listeners from old tunnel and set it in new tunnel
                                                let raw_listeners = OnionTunnel::get_listeners(
                                                    tunnel.listeners.clone(),
                                                )
                                                .await
                                                .lock()
                                                .await
                                                .clone();
                                                tunnel_manager_guard
                                                    .register_listeners(&tunnel_id, raw_listeners)
                                                    .await;
                                                // set connected
                                                tunnel_manager_guard.set_connected(&tunnel_id);
                                                false
                                            }
                                        }
                                    };
                                    if downgrade {
                                        // the old tunnel has been closed during the tunnel update, downgrade the new one
                                        log::debug!("Tunnel={:?}: Tunnel with id={:?} has been closed during updating, downgrade new tunnel", tunnel_id, old_tunnel_id);
                                        tunnel_manager_guard
                                            .downgrade_tunnel(&tunnel_id, true)
                                            .await;
                                    }
                                }
                                IncomingEventMessage::Downgraded => {
                                    log::debug!("Tunnel={:?}: Received downgrade.", tunnel_id,);
                                    let mut tunnel_manager_guard = tunnel_manager.write().await;
                                    tunnel_manager_guard
                                        .downgrade_tunnel(&tunnel_id, false)
                                        .await;
                                    // check for tunnel_update, then we would have downgrade also the new tunnel
                                    let new_tunnel_id = tunnel_manager_guard.resolve_tunnel_id(
                                        tunnel_manager_guard.resolve_reverse_tunnel_id(tunnel_id),
                                    );
                                    if new_tunnel_id != tunnel_id {
                                        tunnel_manager_guard
                                            .downgrade_tunnel(&new_tunnel_id, false)
                                            .await;
                                    }
                                }
                                IncomingEventMessage::Data(data) => {
                                    let redirected_tunnel_id = tunnel_manager
                                        .read()
                                        .await
                                        .resolve_reverse_tunnel_id(tunnel_id);
                                    log::debug!(
                                        "Tunnel={:?} (redirected to id={:?}): Received incoming data, delegate to API",
                                        tunnel_id,
                                        redirected_tunnel_id
                                    );
                                    iface
                                        .incoming_data(
                                            data,
                                            redirected_tunnel_id,
                                            OnionTunnel::get_listeners(listeners.clone()).await,
                                        )
                                        .await;
                                }
                            }
                        } else {
                            // this will always lead to a shutdown of the main thread
                            log::error!("API interface not available anymore");
                            return;
                        }
                    }
                }
            }
        });

        // start fsm
        let _ = event_tx_clone.send(FsmEvent::Init).await;

        // run tunnel_event_listener
        tokio::spawn(async move {
            loop {
                // recv the next incoming event from udp stream or onion api
                let event = match lifo_event_receiver.recv().await {
                    None => {
                        log::trace!("Tunnel={:?}: Event listener received closure", tunnel_id);
                        return;
                    }
                    Some(e) => {
                        log::trace!(
                            "Tunnel={:?}: Event listener received incoming event for FSM",
                            tunnel_id
                        );
                        e
                    }
                };

                // we have to ensure that we do not send messages to the fsm until the previous message has been processed
                // otherwise there would be a race condition when the ClientHello of the next hop is available
                // before the handshake_result has been sent to the FSM
                // once the fsm_lock_state is HandshakeDone, there is no race condition anymore
                log::trace!("Tunnel={:?}: Event listener will wait until the fsm is waiting for a new event", tunnel_id);
                let (lock, notifier) = &*fsm_lock;
                let mut state = lock.lock().await;
                while *state == FsmLockState::Processing {
                    // this is allowed since if notify is called before notified().await, the permit is stored
                    drop(state);
                    notifier.notified().await;
                    state = lock.lock().await;
                }
                // now we are either in HandshakeDone or WaitForEvent
                assert!(*state != FsmLockState::Processing);
                if *state == FsmLockState::WaitForEvent {
                    *state = FsmLockState::Processing;
                }
                drop(state);

                // send the event to the FSM
                log::trace!(
                    "Tunnel={:?}: Event listener forwards the event to the FSM",
                    tunnel_id
                );
                if event_tx.send(event).await.is_err() {
                    // this only happens when FSM has been terminated
                    log::warn!("Tunnel={:?}: Cannot forward event to fsm", tunnel_id);
                    return;
                }
            }
        });
    }

    /*
     * Create a tunnel for an initiating peer
     */
    #[allow(clippy::too_many_arguments)]
    pub async fn new_initiator_tunnel(
        listener: Option<ConnectionId>,
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        socket: Arc<DtlsSocketLayer>,
        target: SocketAddr,
        target_host_key: Vec<u8>,
        tunnel_manager: Arc<RwLock<TunnelManager>>,
        hop_count: u8,
        rps_api_address: SocketAddr,
        tunnel_result_tx: oneshot::Sender<TunnelResult>,
        api_interface: Weak<ApiInterface>,
        local_crypto_context: Arc<HandshakeCryptoConfig>,
        handshake_timeout: Duration,
        timeout: Duration,
        tunnel_update_ref: Option<FrameId>,
        update_information: Option<UpdateInformation>,
        blocklist: Arc<RwLock<Blocklist>>,
    ) -> Result<TunnelId, ProtocolError> {
        // select intermediate hops via rps module and hop count
        // TODO Future Work: robustness isAlive checks during tunnel establishment, maybe add some more backup peers
        let mut hops: Vec<Peer> = vec![];
        for i in 0..hop_count {
            let peer = match rps_get_peer_filtered(rps_api_address, blocklist.clone()).await {
                Ok(peer) => {
                    log::debug!(
                        "{:?}. intermediate peer: (addr={:?}, identity={:?})",
                        i + 1,
                        peer.0,
                        sha::sha256(peer.1.as_ref())
                    );
                    peer
                }
                Err(_) => return Err(ProtocolError::RpsFailure),
            };
            hops.push(peer);
        }

        // add target as last hop
        hops.push((target, target_host_key));

        // create a channel for handing events to the fsm
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // create a channel for handing events (data, tunnel completion, closure) to the tunnel
        let (mgmt_tx, mgmt_rx) = tokio::sync::mpsc::channel(32);

        // create new tunnel id
        let tunnel_id = TunnelManager::get_id();
        log::debug!("Create new initiator tunnel with new ID={:?}", tunnel_id);

        // create initiator FSM
        let fsm_lock = Arc::new((Mutex::new(FsmLockState::WaitForEvent), Notify::new()));
        let mut fsm = InitiatorStateMachine::new(
            hops,
            tunnel_result_tx,
            frame_id_manager.clone(),
            socket,
            tunnel_id,
            mgmt_tx,
            event_tx.clone(),
            fsm_lock.clone(),
            local_crypto_context,
            handshake_timeout,
            tunnel_update_ref,
            listener.is_none(),
        );

        // run the fsm
        tokio::spawn(async move {
            fsm.handle_events(event_rx, timeout).await;
        });

        // create the tunnel
        let listeners = if let Some(listener) = listener {
            vec![listener]
        } else {
            vec![]
        };
        let empty = listeners.is_empty();
        let listeners = Arc::new(Mutex::new(
            listeners.into_iter().collect::<HashSet<ConnectionId>>(),
        ));

        let tunnel_type = if let Some(update_info) = update_information {
            TunnelType::Initiator(update_info)
        } else {
            TunnelType::NonInitiator
        };

        Self::new_tunnel(
            frame_id_manager,
            Arc::new((Mutex::new(!empty), listeners, Notify::new())),
            tunnel_manager,
            event_tx,
            tunnel_id,
            mgmt_rx,
            api_interface,
            fsm_lock,
            tunnel_type,
        )
        .await;
        Ok(tunnel_id)
    }

    /*
     *  Create a tunnel for a non-initiating peer (intermediate hop and target peer)
     */
    #[allow(clippy::too_many_arguments)]
    pub async fn new_target_tunnel(
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        socket: Arc<DtlsSocketLayer>,
        source: SocketAddr,
        tunnel_manager: Arc<RwLock<TunnelManager>>,
        api_interface: Weak<ApiInterface>,
        local_crypto_context: Arc<HandshakeCryptoConfig>,
        handshake_timeout: Duration,
        timeout: Duration,
    ) -> TunnelId {
        // create a channel for handing events to the fsm
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // create a channel for handing events (data, tunnel completion, closure) to the tunnel
        let (mgmt_tx, mgmt_rx) = tokio::sync::mpsc::channel(32);

        // create new tunnel id
        let tunnel_id = TunnelManager::get_id();
        log::debug!("Create new target tunnel with new ID={:?}", tunnel_id);

        // create target FSM
        let fsm_lock = Arc::new((Mutex::new(FsmLockState::WaitForEvent), Notify::new()));
        let mut fsm = TargetStateMachine::new(
            frame_id_manager.clone(),
            socket,
            source,
            tunnel_id,
            mgmt_tx,
            event_tx.clone(),
            fsm_lock.clone(),
            local_crypto_context,
            handshake_timeout,
        );

        // run the fsm
        tokio::spawn(async move {
            fsm.handle_events(event_rx, timeout).await;
        });

        Self::new_tunnel(
            frame_id_manager,
            Arc::new((
                Mutex::new(false),
                Arc::new(Mutex::new(HashSet::new())),
                Notify::new(),
            )),
            tunnel_manager,
            event_tx,
            tunnel_id,
            mgmt_rx,
            api_interface,
            fsm_lock,
            TunnelType::NonInitiator,
        )
        .await;
        tunnel_id
    }

    pub(crate) async fn send(&self, data: Vec<u8>) -> Result<(), P2pError> {
        if self.is_connected() {
            self.forward_event(FsmEvent::Send(data)).await
        } else {
            Err(P2pError::CoverOnlyTunnel)
        }
    }

    pub(crate) async fn send_cover(&self, data: Vec<u8>) -> Result<(), P2pError> {
        // specification requires that cover traffic must only be sent via cover-traffic-only tunnels
        if self.is_downgraded() {
            self.forward_event(FsmEvent::Cover(data)).await
        } else {
            Err(P2pError::CoverFailure)
        }
    }

    pub(crate) async fn forward_event(&self, e: FsmEvent) -> Result<(), P2pError> {
        log::trace!(
            "Tunnel={:?}: Forward event=({:?}) to tunnel",
            self.tunnel_id,
            e
        );
        if self.lifo_event_sender.send(e).await.is_err() {
            // if this fails, the FSM handle_events() method has terminated
            log::warn!(
                "Tunnel={:?}: Cannot forward event to tunnel",
                self.tunnel_id
            );
            Err(P2pError::TunnelClosed)
        } else {
            Ok(())
        }
    }

    pub async fn close_tunnel(&self) {
        if self.status != TunnelStatus::Downgraded {
            // send close event
            log::trace!("Tunnel={:?}: Send close event to FSM", self.tunnel_id);
            let _ = self.forward_event(FsmEvent::Close).await;
        }
    }

    pub async fn shutdown_tunnel(&self) {
        // send shutdown event
        log::trace!("Tunnel={:?}: Send shutdown event to FSM", self.tunnel_id);
        let _ = self.forward_event(FsmEvent::Shutdown).await;
    }

    pub async fn unsubscribe(&self, connection_id: ConnectionId) -> bool {
        if self.status != TunnelStatus::Downgraded {
            let listeners = OnionTunnel::get_listeners(self.listeners.clone()).await;
            let mut connections = listeners.lock().await;
            log::trace!(
                "Tunnel={:?}: Remove connection={:?}",
                self.tunnel_id,
                connection_id
            );
            let _ = connections.remove(&connection_id);
            if connections.is_empty() {
                // no more listeners exist
                log::debug!("Tunnel={:?}: No more listeners exist.", self.tunnel_id);
                // signal the calling function that this tunnel must be downgraded
                return true;
            }
        }
        false
    }
}
