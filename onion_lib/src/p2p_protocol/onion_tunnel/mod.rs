use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Weak;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::net::UdpSocket;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot, Mutex, Notify,
};

use openssl::sha;

use crate::api_protocol::ApiInterface;
use crate::p2p_protocol::onion_tunnel::fsm::{
    FiniteStateMachine, FsmEvent, InitiatorStateMachine, ProtocolError, TargetStateMachine,
};
use crate::p2p_protocol::{ConnectionId, Direction, P2pError};

use super::{FrameId, TunnelId};
use crate::p2p_protocol::onion_tunnel::crypto::HandshakeCryptoConfig;
use crate::p2p_protocol::rps_api::rps_get_peer;
use std::time::Duration;

pub mod crypto;
pub(crate) mod fsm;
pub(crate) mod message_codec;

static ID_COUNTER: AtomicU32 = AtomicU32::new(1);
fn get_id() -> u32 {
    ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

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
    IncomingTunnelCompletion,
    IncomingData(Vec<u8>),
}

pub(crate) type Peer = (SocketAddr, Vec<u8>);

pub(crate) struct OnionTunnel {
    listeners: Arc<Mutex<HashSet<ConnectionId>>>, // all the api connection listeners
    listeners_available: Arc<Mutex<bool>>,        // are the listeners set, important for managing
    tunnel_id: TunnelId,                          // unique tunnel id
    tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>, // tunnel registry for tunnel mgmt
    lifo_event_sender: Sender<FsmEvent>,
}

impl OnionTunnel {
    #[allow(clippy::too_many_arguments)]
    async fn new_tunnel(
        listeners: Arc<Mutex<HashSet<ConnectionId>>>,
        listeners_available: Arc<Mutex<bool>>,
        tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
        event_tx: Sender<FsmEvent>,
        tunnel_id: TunnelId,
        mut mgmt_rx: Receiver<IncomingEventMessage>,
        api_interface: Weak<ApiInterface>,
        fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
    ) {
        // clone the sender for init
        let event_tx_clone = event_tx.clone();

        let (lifo_event_sender, mut lifo_event_receiver) = tokio::sync::mpsc::channel(32);

        let tunnel = OnionTunnel {
            listeners: listeners.clone(),
            listeners_available: listeners_available.clone(),
            tunnel_id,
            tunnel_registry: tunnel_registry.clone(),
            lifo_event_sender,
        };

        // start management task that manages tunnel cleanup and listener notification
        let id_clone = tunnel_id;
        let registry_clone = tunnel_registry.clone();
        tokio::spawn(async move {
            log::trace!("Tunnel={:?}: Run the async management task", id_clone);
            loop {
                match mgmt_rx.recv().await {
                    None => {
                        log::debug!(
                            "Tunnel={:?}: Received a closure from the FSM. Unregister the tunnel and shutdown the management layer",
                            id_clone
                        );
                        let mut registry = registry_clone.lock().await;
                        let _ = registry.remove(&id_clone);
                        return;
                    }

                    // communicate with api interface
                    Some(m) => {
                        if let Some(iface) = api_interface.upgrade() {
                            match m {
                                IncomingEventMessage::IncomingTunnelCompletion => {
                                    log::debug!(
                                        "Tunnel={:?}: Received IncomingTunnelCompletion, delegate to API",
                                        id_clone
                                    );

                                    // get listeners
                                    let connections = iface.connections.lock().await;
                                    let raw_listeners = connections.keys().cloned().collect();
                                    drop(connections);
                                    log::debug!(
                                        "Tunnel={:?}: Listeners={:?}",
                                        id_clone,
                                        raw_listeners
                                    );

                                    // TODO check if listeners are empty, then we want to terminate the tunnel

                                    // store listeners in tunnel reference
                                    let mut listeners_guard = listeners.lock().await;
                                    let mut listeners_available_guard =
                                        listeners_available.lock().await;
                                    *listeners_guard = raw_listeners;
                                    *listeners_available_guard = true;
                                    drop(listeners_guard);

                                    iface.incoming_tunnel(id_clone, listeners.clone()).await;
                                }

                                IncomingEventMessage::IncomingData(data) => {
                                    log::debug!(
                                        "Tunnel={:?}: Received incoming data, delegate to API",
                                        id_clone
                                    );
                                    iface.incoming_data(data, id_clone, listeners.clone()).await;
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
        if let Err(_e) = event_tx_clone.send(FsmEvent::Init).await {
            // TODO handle error
        }

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
                    log::warn!("Tunnel={:?}: Cannot forward event to fsm", tunnel_id);
                    return;
                }
            }
        });

        // register tunnel at registry
        let mut tunnels = tunnel_registry.lock().await;
        let _ = tunnels.insert(tunnel_id, tunnel);
    }

    /*
     * Create a tunnel for an initiating peer
     */
    #[allow(clippy::too_many_arguments)]
    pub async fn new_initiator_tunnel(
        listener: ConnectionId,
        frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
        socket: Arc<UdpSocket>,
        target: SocketAddr,
        target_host_key: Vec<u8>,
        tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
        hop_count: u8,
        rps_api_address: SocketAddr,
        tunnel_result_tx: oneshot::Sender<TunnelResult>,
        api_interface: Weak<ApiInterface>,
        local_crypto_context: Arc<HandshakeCryptoConfig>,
        handshake_timeout: Duration,
    ) -> TunnelId {
        // select intermediate hops via rps module and hop count
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
                Err(_) => {
                    // TODO handle error
                    panic!("Error occurred");
                }
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
        let tunnel_id = get_id();
        log::debug!("Create new initiator tunnel with new ID={:?}", tunnel_id);

        // create initiator FSM
        let fsm_lock = Arc::new((Mutex::new(FsmLockState::WaitForEvent), Notify::new()));
        let mut fsm = InitiatorStateMachine::new(
            hops,
            tunnel_result_tx,
            frame_ids,
            socket,
            tunnel_id,
            mgmt_tx,
            event_tx.clone(),
            fsm_lock.clone(),
            local_crypto_context,
            handshake_timeout,
        );

        // run the fsm
        tokio::spawn(async move {
            fsm.handle_events(event_rx).await;
        });

        // create the tunnel
        let listeners = Arc::new(Mutex::new(
            vec![listener]
                .into_iter()
                .collect::<HashSet<ConnectionId>>(),
        ));

        Self::new_tunnel(
            listeners,
            Arc::new(Mutex::new(true)),
            tunnel_registry,
            event_tx,
            tunnel_id,
            mgmt_rx,
            api_interface,
            fsm_lock,
        )
        .await;
        tunnel_id
    }

    /*
     *  Create a tunnel for a non-initiating peer (intermediate hop and target peer)
     */
    pub async fn new_target_tunnel(
        frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
        socket: Arc<UdpSocket>,
        source: SocketAddr,
        tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
        api_interface: Weak<ApiInterface>,
        local_crypto_context: Arc<HandshakeCryptoConfig>,
        handshake_timeout: Duration,
    ) -> TunnelId {
        // create a channel for handing events to the fsm
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // create a channel for handing events (data, tunnel completion, closure) to the tunnel
        let (mgmt_tx, mgmt_rx) = tokio::sync::mpsc::channel(32);

        // create new tunnel id
        let tunnel_id = get_id();
        log::debug!("Create new target tunnel with new ID={:?}", tunnel_id);

        // create target FSM
        let fsm_lock = Arc::new((Mutex::new(FsmLockState::WaitForEvent), Notify::new()));
        let mut fsm = TargetStateMachine::new(
            frame_ids,
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
            fsm.handle_events(event_rx).await;
        });

        Self::new_tunnel(
            Arc::new(Mutex::new(HashSet::new())),
            Arc::new(Mutex::new(false)),
            tunnel_registry,
            event_tx,
            tunnel_id,
            mgmt_rx,
            api_interface,
            fsm_lock,
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
            log::warn!(
                "Tunnel={:?}: Cannot forward event to tunnel",
                self.tunnel_id
            );
            Err(P2pError::TunnelClosed)
        } else {
            Ok(())
        }
    }

    async fn close_tunnel(&self) {
        // send close event
        log::trace!("Tunnel={:?}: Send close event to FSM", self.tunnel_id);
        let _ = self.forward_event(FsmEvent::Close).await;

        // remove from tunnels list
        log::trace!(
            "Tunnel={:?}: Remove tunnel from tunnel registry",
            self.tunnel_id
        );
        let mut tunnel_registry = self.tunnel_registry.lock().await;
        let _ = tunnel_registry.remove(&self.tunnel_id);
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
