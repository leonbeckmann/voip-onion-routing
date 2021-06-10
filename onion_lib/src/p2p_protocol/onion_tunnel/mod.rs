pub mod fsm;

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use std::sync::atomic::{AtomicU32, Ordering};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc::{Receiver, Sender}, oneshot, Mutex};

use crate::p2p_protocol::{ConnectionId, P2pError, Direction};

use super::{FrameId, TunnelId};
use crate::api_protocol::ApiInterface;
use crate::p2p_protocol::onion_tunnel::fsm::{
    FiniteStateMachine, FsmEvent, InitiatorStateMachine, ProtocolError, TargetStateMachine,
};
use std::collections::HashSet;
use std::sync::Weak;

pub(crate) const _RPS_QUERY: u16 = 540;
pub(crate) const _RPS_PEER: u16 = 541;

static ID_COUNTER: AtomicU32 = AtomicU32::new(1);
fn get_id() -> u32 {
    ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub enum TunnelResult {
    Connected,
    Failure(ProtocolError),
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

type IntermediateHop = (SocketAddr, Vec<u8>);

pub(crate) struct OnionTunnel {
    listeners: Arc<Mutex<HashSet<ConnectionId>>>, // all the api connection listeners
    listeners_available: Arc<Mutex<bool>>,        // are the listeners set, important for managing
    event_tx: Sender<FsmEvent>,                   // sending events to the fsm
    tunnel_id: TunnelId,                          // unique tunnel id
    tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>, // tunnel registry for tunnel mgmt
}

// TODO private keys
impl OnionTunnel {
    async fn new_tunnel(
        listeners: Arc<Mutex<HashSet<ConnectionId>>>,
        listeners_available: Arc<Mutex<bool>>,
        tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
        event_tx: Sender<FsmEvent>,
        tunnel_id: TunnelId,
        mut mgmt_rx: Receiver<IncomingEventMessage>,
        api_interface: Weak<ApiInterface>,
    ) {
        // clone the sender for init
        let event_tx_clone = event_tx.clone();

        let tunnel = OnionTunnel {
            listeners: listeners.clone(),
            listeners_available: listeners_available.clone(),
            event_tx,
            tunnel_id,
            tunnel_registry: tunnel_registry.clone(),
        };

        // start management task that manages tunnel cleanup and listener notification
        let id_clone = tunnel_id;
        let registry_clone = tunnel_registry.clone();
        tokio::spawn(async move {
            loop {
                match mgmt_rx.recv().await {
                    None => {
                        log::debug!(
                            "Tunnel with id {:?} has received a closure from the FSM.",
                            id_clone
                        );
                        log::debug!("Unregister tunnel and shutdown management layer");
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
                                        "Received IncomingTunnelCompletion at tunnel {:?}",
                                        id_clone
                                    );

                                    // get listeners
                                    let connections = iface.connections.lock().await;
                                    let raw_listeners = connections.keys().cloned().collect();

                                    // TODO check if listeners are empty, then we want to terminate the tunnel

                                    // store listeners in tunnel reference
                                    let mut listeners_guard = listeners.lock().await;
                                    let mut listeners_available_guard = listeners_available.lock().await;
                                    *listeners_guard = raw_listeners;
                                    *listeners_available_guard = true;
                                    drop(listeners_guard);

                                    iface.incoming_tunnel(id_clone, listeners.clone()).await;
                                }

                                IncomingEventMessage::IncomingData(data) => {
                                    log::debug!("Received IncomingData at {:?}", id_clone);
                                    iface.incoming_data(data, id_clone, listeners.clone()).await;
                                }
                            }
                        } else {
                            // this will always lead to a shutdown of the main thread
                            log::error!(
                                "API interface not available anymore. Shutdown tunnel mgmt"
                            );
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
        _hop_count: u8,
        _rps_api_address: SocketAddr,
        tunnel_result_tx: oneshot::Sender<TunnelResult>,
        api_interface: Weak<ApiInterface>,
    ) -> TunnelId {
        // TODO select intermediate hops via rps module and hop count
        let hops: Vec<IntermediateHop> = vec![];

        // create a channel for handing events to the fsm
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // create a channel for handing events (data, tunnel completion, closure) to the tunnel
        let (mgmt_tx, mgmt_rx) = tokio::sync::mpsc::channel(32);

        // create new tunnel id
        let tunnel_id = get_id();

        // create initiator FSM
        let mut fsm = InitiatorStateMachine::new(
            hops,
            tunnel_result_tx,
            frame_ids,
            socket,
            target,
            target_host_key,
            tunnel_id,
            mgmt_tx,
            event_tx.clone(),
        );

        // run the fsm
        tokio::spawn(async move {
            fsm.handle_events(event_rx).await;
        });

        // create the tunnel
        let listeners =
            Arc::new(Mutex::new(vec![listener].into_iter().collect::<HashSet<ConnectionId>>()));

        Self::new_tunnel(
            listeners,
            Arc::new(Mutex::new(true)),
            tunnel_registry,
            event_tx,
            tunnel_id,
            mgmt_rx,
            api_interface,
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
    ) -> TunnelId {
        // create a channel for handing events to the fsm
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // create a channel for handing events (data, tunnel completion, closure) to the tunnel
        let (mgmt_tx, mgmt_rx) = tokio::sync::mpsc::channel(32);

        // create new tunnel id
        let tunnel_id = get_id();

        // create target FSM
        let mut fsm = TargetStateMachine::new(
            frame_ids,
            socket,
            source,
            tunnel_id,
            mgmt_tx,
            event_tx.clone(),
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
        )
        .await;
        tunnel_id
    }

    pub(crate) async fn send(&self, data: Vec<u8>) -> Result<(), P2pError> {
        self.forward_event(FsmEvent::Send(data)).await
    }

    pub(crate) async fn forward_event(&self, e: FsmEvent) -> Result<(), P2pError> {
        if self.event_tx.send(e).await.is_err() {
            Err(P2pError::TunnelClosed)
        } else {
            Ok(())
        }
    }

    async fn close_tunnel(&self) {
        // send close event
        let _ = self.forward_event(FsmEvent::Close).await;

        // remove from tunnels list
        log::debug!(
            "Remove tunnel with id {:?} from tunnel registry",
            self.tunnel_id
        );
        let mut tunnel_registry = self.tunnel_registry.lock().await;
        let _ = tunnel_registry.remove(&self.tunnel_id);
    }

    pub async fn unsubscribe(&self, connection_id: u64) {
        let available_guard = self.listeners_available.lock().await;
        if *available_guard {
            let mut connections = self.listeners.lock().await;
            let _ = connections.remove(&connection_id);
            if connections.is_empty() {
                // no more listeners exist, terminate tunnel
                log::debug!(
                    "No more listeners exist for tunnel with id {:?}. Close tunnel",
                    self.tunnel_id
                );
                self.close_tunnel().await;
            }
        }
    }
}
