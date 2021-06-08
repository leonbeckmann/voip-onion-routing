pub mod fsm;

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use std::sync::atomic::{AtomicU32, Ordering};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc::Sender, oneshot, Mutex};

use crate::p2p_protocol::{ConnectionId, P2pError};

use super::{FrameId, TunnelId};
use crate::p2p_protocol::onion_tunnel::fsm::{
    FiniteStateMachine, FsmEvent, InitiatorStateMachine, ProtocolError, TargetStateMachine,
};
use std::collections::HashSet;

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

type IntermediateHop = (SocketAddr, Vec<u8>);

pub(crate) struct OnionTunnel {
    listeners: Mutex<HashSet<ConnectionId>>, // all the api connection listeners
    event_tx: Sender<FsmEvent>,              // sending events to the fsm
    tunnel_id: TunnelId,                     // unique tunnel id
    tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>, // tunnel registry for managing tunnel
}

// TODO private keys
impl OnionTunnel {
    async fn new_tunnel(
        listeners: HashSet<ConnectionId>,
        tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
        event_tx: Sender<FsmEvent>,
        tunnel_id: TunnelId,
    ) {
        // clone the sender for init
        let event_tx_clone = event_tx.clone();

        let tunnel = OnionTunnel {
            listeners: Mutex::new(listeners),
            event_tx,
            tunnel_id,
            tunnel_registry: tunnel_registry.clone(),
        };

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
        frame_ids: Arc<Mutex<HashMap<FrameId, TunnelId>>>,
        socket: Arc<UdpSocket>,
        target: SocketAddr,
        target_host_key: Vec<u8>,
        tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
        _hop_count: u8,
        _rps_api_address: SocketAddr,
        tunnel_result_tx: oneshot::Sender<TunnelResult>,
    ) -> TunnelId {
        // TODO select intermediate hops via rps module and hop count
        let hops: Vec<IntermediateHop> = vec![];

        // create a channel for handing events to the fsm
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

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
        );

        // run the fsm
        tokio::spawn(async move {
            fsm.handle_events(event_rx).await;
        });

        // create the tunnel
        let mut listeners = HashSet::new();
        listeners.insert(listener);

        Self::new_tunnel(listeners, tunnel_registry, event_tx, tunnel_id).await;
        tunnel_id
    }

    /*
     *  Create a tunnel for a non-initiating peer (intermediate hop and target peer)
     */
    pub async fn new_target_tunnel(
        listeners: HashSet<ConnectionId>,
        frame_ids: Arc<Mutex<HashMap<FrameId, TunnelId>>>,
        socket: Arc<UdpSocket>,
        source: SocketAddr,
        tunnel_registry: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
    ) -> TunnelId {
        // create a channel for handing events to the fsm
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // create new tunnel id
        let tunnel_id = get_id();

        // create target FSM
        let mut fsm = TargetStateMachine::new(frame_ids, socket, source, tunnel_id);

        // run the fsm
        tokio::spawn(async move {
            fsm.handle_events(event_rx).await;
        });

        Self::new_tunnel(listeners, tunnel_registry, event_tx, tunnel_id).await;
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
