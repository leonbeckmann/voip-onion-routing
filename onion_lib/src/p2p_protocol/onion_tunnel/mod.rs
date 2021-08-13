use std::collections::HashSet;
use std::sync::Weak;
use std::{net::SocketAddr, sync::Arc};

use tokio::net::UdpSocket;
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

use super::TunnelId;
use crate::p2p_protocol::onion_tunnel::crypto::HandshakeCryptoConfig;
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
use crate::p2p_protocol::onion_tunnel::tunnel_manager::TunnelManager;
use crate::p2p_protocol::rps_api::rps_get_peer;
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
    TunnelUpdate(FrameId),
    Data(Vec<u8>),
}

pub(crate) type Peer = (SocketAddr, Vec<u8>);

pub(crate) struct UpdateInformation {
    pub listener: ConnectionId,
    pub target: Peer,
}

impl UpdateInformation {
    pub fn new(listener: ConnectionId, target: Peer) -> UpdateInformation {
        UpdateInformation { listener, target }
    }
}

pub(crate) enum TunnelType {
    Initiator(UpdateInformation),
    Target,
}

pub(crate) enum TunnelStatus {
    Connected,
    Connecting,
}

pub(crate) struct OnionTunnel {
    listeners: Arc<Mutex<HashSet<ConnectionId>>>, // all the api connection listeners
    listeners_available: Arc<Mutex<bool>>,        // are the listeners set, important for managing
    tunnel_id: TunnelId,                          // unique tunnel id
    lifo_event_sender: Sender<FsmEvent>,
    pub tunnel_type: TunnelType,
    pub status: TunnelStatus,
}

impl OnionTunnel {
    pub fn is_connected(&self) -> bool {
        match self.status {
            TunnelStatus::Connected => true,
            TunnelStatus::Connecting => false,
        }
    }

    pub fn is_initiator(&self) -> bool {
        match self.tunnel_type {
            TunnelType::Initiator(_) => true,
            TunnelType::Target => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_tunnel(
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        listeners: Arc<Mutex<HashSet<ConnectionId>>>,
        listeners_available: Arc<Mutex<bool>>,
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
            listeners_available: listeners_available.clone(),
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
                        tunnel_manager_guard.remove_redirection_link(&tunnel_id);
                        frame_id_manager.write().await.tunnel_closure(tunnel_id);
                        return;
                    }

                    // communicate with api interface
                    Some(m) => {
                        if let Some(iface) = api_interface.upgrade() {
                            match m {
                                IncomingEventMessage::TunnelCompletion => {
                                    log::debug!(
                                        "Tunnel={:?}: Received IncomingTunnelCompletion, delegate to API",
                                        tunnel_id
                                    );
                                    tunnel_manager.write().await.set_connected(&tunnel_id);

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

                                    // check if listeners are empty, then we want to terminate the tunnel
                                    if raw_listeners.is_empty() {
                                        tunnel_manager
                                            .read()
                                            .await
                                            .get_tunnel(&tunnel_id)
                                            .unwrap()
                                            .close_tunnel()
                                            .await;
                                        continue;
                                    }

                                    // store listeners in tunnel reference
                                    let mut listeners_guard = listeners.lock().await;
                                    let mut listeners_available_guard =
                                        listeners_available.lock().await;
                                    *listeners_guard = raw_listeners;
                                    *listeners_available_guard = true;
                                    drop(listeners_guard);

                                    iface.incoming_tunnel(tunnel_id, listeners.clone()).await;
                                }

                                IncomingEventMessage::TunnelUpdate(tunnel_update_ref) => {
                                    tunnel_manager.write().await.set_connected(&tunnel_id);
                                    // this target tunnel is an update for an old one

                                    // redirect tunnel id
                                    let old_tunnel_id = match frame_id_manager
                                        .read()
                                        .await
                                        .get_tunnel_id(&tunnel_update_ref)
                                    {
                                        None => {
                                            // failure, close tunnel, cleanup
                                            let mut tunnel_manager_guard =
                                                tunnel_manager.write().await;
                                            log::debug!("Tunnel={:?}: Cannot find tunnel_update_reference. Close tunnel again", tunnel_id);
                                            if let Some(tunnel) =
                                                tunnel_manager_guard.get_tunnel(&tunnel_id)
                                            {
                                                tunnel.close_tunnel().await;
                                            }
                                            tunnel_manager_guard.remove_tunnel(&tunnel_id);
                                            tunnel_manager_guard
                                                .remove_redirection_link(&tunnel_id);
                                            frame_id_manager
                                                .write()
                                                .await
                                                .tunnel_closure(tunnel_id);
                                            return;
                                        }
                                        Some((tunnel_id, _)) => tunnel_id,
                                    };

                                    // redirect tunnel ids
                                    tunnel_manager
                                        .write()
                                        .await
                                        .add_redirection_link(old_tunnel_id, tunnel_id);

                                    // destroy the old tunnel
                                    let mut tunnel_manager_guard = tunnel_manager.write().await;
                                    match tunnel_manager_guard.get_tunnel(&old_tunnel_id) {
                                        None => {
                                            // the old tunnel has been closed during the tunnel update, close the new one
                                            log::debug!("Tunnel={:?}: Tunnel with id={:?} has been closed during updating, close new tunnel", tunnel_id, old_tunnel_id);
                                            if let Some(tunnel) =
                                                tunnel_manager_guard.get_tunnel(&tunnel_id)
                                            {
                                                tunnel.close_tunnel().await;
                                            }
                                            tunnel_manager_guard.remove_tunnel(&tunnel_id);
                                            tunnel_manager_guard
                                                .remove_redirection_link(&tunnel_id);
                                            frame_id_manager
                                                .write()
                                                .await
                                                .tunnel_closure(tunnel_id);
                                        }
                                        Some(tunnel) => {
                                            // take listeners from old tunnel
                                            let raw_listeners =
                                                tunnel.listeners.lock().await.clone();
                                            let mut listeners_guard = listeners.lock().await;
                                            let mut listeners_available_guard =
                                                listeners_available.lock().await;
                                            *listeners_guard = raw_listeners;
                                            *listeners_available_guard = true;
                                            drop(listeners_guard);
                                            tunnel.shutdown_tunnel().await;
                                        }
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
                                            listeners.clone(),
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
        listener: ConnectionId,
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        socket: Arc<UdpSocket>,
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
        update_information: UpdateInformation,
    ) -> Result<TunnelId, ProtocolError> {
        // select intermediate hops via rps module and hop count
        // TODO robustness isAlive checks during tunnel establishment, maybe add some more backup peers
        let mut hops: Vec<Peer> = vec![];
        for i in 0..hop_count {
            let peer = match rps_get_peer(rps_api_address).await {
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
        );

        // run the fsm
        tokio::spawn(async move {
            fsm.handle_events(event_rx, timeout).await;
        });

        // create the tunnel
        let listeners = Arc::new(Mutex::new(
            vec![listener]
                .into_iter()
                .collect::<HashSet<ConnectionId>>(),
        ));

        Self::new_tunnel(
            frame_id_manager,
            listeners,
            Arc::new(Mutex::new(true)),
            tunnel_manager,
            event_tx,
            tunnel_id,
            mgmt_rx,
            api_interface,
            fsm_lock,
            TunnelType::Initiator(update_information),
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
        socket: Arc<UdpSocket>,
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
            Arc::new(Mutex::new(HashSet::new())),
            Arc::new(Mutex::new(false)),
            tunnel_manager,
            event_tx,
            tunnel_id,
            mgmt_rx,
            api_interface,
            fsm_lock,
            TunnelType::Target,
        )
        .await;
        tunnel_id
    }

    pub(crate) async fn send(&self, data: Vec<u8>) -> Result<(), P2pError> {
        self.forward_event(FsmEvent::Send(data)).await
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
        // send close event
        log::trace!("Tunnel={:?}: Send close event to FSM", self.tunnel_id);
        let _ = self.forward_event(FsmEvent::Close).await;
    }

    pub async fn shutdown_tunnel(&self) {
        // send shutdown event
        log::trace!("Tunnel={:?}: Send shutdown event to FSM", self.tunnel_id);
        let _ = self.forward_event(FsmEvent::Shutdown).await;
    }

    pub async fn unsubscribe(&self, connection_id: u64) {
        let available_guard = self.listeners_available.lock().await;
        if *available_guard {
            let mut connections = self.listeners.lock().await;
            log::trace!(
                "Tunnel={:?}: Remove connection={:?}",
                self.tunnel_id,
                connection_id
            );
            let _ = connections.remove(&connection_id);
            if connections.is_empty() {
                // no more listeners exist, terminate tunnel
                log::debug!(
                    "Tunnel={:?}: No more listeners exist. Close the tunnel",
                    self.tunnel_id
                );
                self.close_tunnel().await;
            }
        }
    }
}
