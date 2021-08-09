mod handshake_fsm;

use crate::p2p_protocol::messages::p2p_messages::HandshakeData_oneof_message;
use crate::p2p_protocol::onion_tunnel::crypto::HandshakeCryptoConfig;
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
use crate::p2p_protocol::onion_tunnel::fsm::handshake_fsm::{
    Client, HandshakeEvent, HandshakeStateMachine, Server,
};
use crate::p2p_protocol::onion_tunnel::message_codec::DataType::AppData;
use crate::p2p_protocol::onion_tunnel::message_codec::{
    InitiatorEndpoint, P2pCodec, ProcessedData, TargetEndpoint,
};
use crate::p2p_protocol::onion_tunnel::{FsmLockState, IncomingEventMessage, Peer, TunnelResult};
use crate::p2p_protocol::{Direction, TunnelId};
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::ops::{Add, Sub};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{oneshot, Mutex, Notify, RwLock};
use tokio::time::timeout;

type IV = Bytes;

pub(super) struct InitiatorStateMachine {
    tunnel_result_tx: Option<oneshot::Sender<TunnelResult>>, // signal the listener completion
    event_tx: Sender<FsmEvent>, // only for cloning purpose to pass the sender to the handshake fsm
    endpoint_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
    listener_tx: Sender<IncomingEventMessage>,
    tunnel_id: TunnelId,
    hops: Vec<Peer>,
    fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
    local_crypto_config: Arc<HandshakeCryptoConfig>,
    handshake_timeout: Duration,
}

impl InitiatorStateMachine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hops: Vec<Peer>,
        tunnel_result_tx: oneshot::Sender<TunnelResult>,
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        socket: Arc<UdpSocket>,
        tunnel_id: TunnelId,
        listener_tx: Sender<IncomingEventMessage>,
        event_tx: Sender<FsmEvent>,
        fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
        local_crypto_config: Arc<HandshakeCryptoConfig>,
        handshake_timeout: Duration,
    ) -> Self {
        assert!(!hops.is_empty());
        let (next_hop, _) = hops.first().unwrap();
        InitiatorStateMachine {
            tunnel_result_tx: Some(tunnel_result_tx),
            event_tx,
            endpoint_codec: Arc::new(Mutex::new(Box::new(InitiatorEndpoint::new(
                socket,
                *next_hop,
                frame_id_manager,
                tunnel_id,
            )))),
            listener_tx,
            tunnel_id,
            hops,
            fsm_lock,
            local_crypto_config,
            handshake_timeout,
        }
    }
}

pub(super) struct TargetStateMachine {
    listener_tx: Sender<IncomingEventMessage>,
    event_tx: Sender<FsmEvent>, // only for cloning purpose to pass the sender to the handshake fsm
    codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
    tunnel_id: TunnelId,
    fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
    local_crypto_config: Arc<HandshakeCryptoConfig>,
    handshake_timeout: Duration,
}

impl TargetStateMachine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        socket: Arc<UdpSocket>,
        source: SocketAddr,
        tunnel_id: TunnelId,
        listener_tx: Sender<IncomingEventMessage>,
        event_tx: Sender<FsmEvent>,
        fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
        local_crypto_config: Arc<HandshakeCryptoConfig>,
        handshake_timeout: Duration,
    ) -> Self {
        TargetStateMachine {
            listener_tx,
            event_tx,
            codec: Arc::new(Mutex::new(Box::new(TargetEndpoint::new(
                socket,
                source,
                frame_id_manager,
                tunnel_id,
            )))),
            tunnel_id,
            fsm_lock,
            local_crypto_config,
            handshake_timeout,
        }
    }
}

async fn free_fsm_lock(fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>) {
    let (lock, notifier) = &*fsm_lock;
    let mut state = lock.lock().await;
    *state = FsmLockState::HandshakeDone;
    notifier.notify_one();
}

#[async_trait]
pub(super) trait FiniteStateMachine {
    fn tunnel_id(&self) -> TunnelId;

    async fn action_init(&mut self) -> Result<State, ProtocolError>;

    async fn action_handshake_data(
        &mut self,
        tx: SenderWrapper,
        data: Bytes,
        iv: IV,
    ) -> Result<State, ProtocolError> {
        // parse handshake data
        log::trace!(
            "Tunnel={:?}: Try to parse incoming data into handshake data using message codec",
            self.tunnel_id()
        );
        let event = match self
            .get_codec()
            .lock()
            .await
            .process_data(Direction::Forward, data, iv)
            .await?
        {
            ProcessedData::ReceivedClose => {
                log::trace!("Tunnel={:?}: Received close", self.tunnel_id());
                return Ok(State::Terminated);
            }
            ProcessedData::TransferredToNextHop => {
                return Err(ProtocolError::UnexpectedMessageType);
            }
            ProcessedData::HandshakeData(data) => {
                if data.message.is_none() {
                    return Err(ProtocolError::EmptyMessage);
                }
                match data.message.unwrap() {
                    HandshakeData_oneof_message::client_hello(data) => {
                        log::trace!(
                            "Tunnel={:?}: Successfully parsed to ClientHello",
                            self.tunnel_id()
                        );
                        HandshakeEvent::ClientHello(data)
                    }
                    HandshakeData_oneof_message::server_hello(data) => {
                        log::trace!(
                            "Tunnel={:?}: Successfully parsed to ServerHello",
                            self.tunnel_id()
                        );
                        HandshakeEvent::ServerHello(data)
                    }
                    HandshakeData_oneof_message::routing(data) => {
                        log::trace!(
                            "Tunnel={:?}: Successfully parsed to RoutingInformation",
                            self.tunnel_id()
                        );
                        HandshakeEvent::RoutingInformation(data)
                    }
                }
            }
            ProcessedData::IncomingData(_) => {
                log::warn!(
                    "Tunnel={:?}: Not expecting incoming application data in connecting state",
                    self.tunnel_id()
                );
                return Err(ProtocolError::UnexpectedMessageType);
            }
        };

        log::trace!(
            "Tunnel={:?}: Transfer handshake event={:?} to handshake FSM",
            self.tunnel_id(),
            event
        );
        match tx.event_tx.send(event).await {
            Ok(_) => {
                // stay in connecting
                Ok(State::Connecting(tx))
            }
            Err(_) => {
                // error occurred, handshake protocol not available anymore
                Err(ProtocolError::HandshakeSendFailure)
            }
        }
    }

    async fn action_app_data(
        &mut self,
        data: Bytes,
        direction: Direction,
        iv: IV,
    ) -> Result<State, ProtocolError> {
        // send data to the target via the tunnel
        log::trace!(
            "Tunnel={:?}: Handle incoming data (direction={:?}) via codec",
            self.tunnel_id(),
            direction
        );
        match self
            .get_codec()
            .lock()
            .await
            .process_data(direction, data, iv)
            .await?
        {
            ProcessedData::ReceivedClose => {
                log::trace!("Tunnel={:?}: Received close", self.tunnel_id());
                return Ok(State::Terminated);
            }
            ProcessedData::TransferredToNextHop => {
                log::trace!(
                    "Tunnel={:?}: Data have been transferred to next hop",
                    self.tunnel_id()
                );
            }
            ProcessedData::IncomingData(data) => {
                log::trace!(
                    "Tunnel={:?}: Send incoming application data to the upper layer",
                    self.tunnel_id()
                );
                // we can ignore an error here since this will only fail when the tunnel has been closed
                let _ = self
                    .get_listener()
                    .send(IncomingEventMessage::IncomingData(data))
                    .await;
            }
            ProcessedData::HandshakeData(_) => {
                log::trace!(
                    "Tunnel={:?}: Not expecting handshake message in connected state",
                    self.tunnel_id()
                );
                return Err(ProtocolError::UnexpectedMessageType);
            }
        };

        // stay in state connected
        Ok(State::Connected)
    }

    async fn action_close(&mut self) -> Result<State, ProtocolError> {
        // all connection listeners have left
        log::debug!(
            "Tunnel={:?}: Received close event, notify tunnel peers and shutdown tunnel",
            self.tunnel_id()
        );
        self.get_codec().lock().await.close(false).await;
        Ok(State::Terminated)
    }

    async fn action_send(&mut self, data: Vec<u8>) -> Result<State, ProtocolError> {
        // send data to the target via the tunnel
        self.get_codec().lock().await.write(AppData(data)).await?;
        Ok(State::Connected)
    }

    async fn action_handshake_result(
        &mut self,
        res: Result<IsTargetEndpoint, ProtocolError>,
    ) -> Result<State, ProtocolError>;

    const INIT_STATE: State = State::Closed;

    fn get_listener(&mut self) -> Sender<IncomingEventMessage>;
    fn get_codec(&mut self) -> Arc<Mutex<Box<dyn P2pCodec + Send>>>;

    #[allow(unused_assignments)]
    async fn handle_events(&mut self, mut event_rx: Receiver<FsmEvent>, fsm_timeout: Duration) {
        let mut current_state = Self::INIT_STATE;
        let mut inactive_ctr = Duration::from_secs(0);

        loop {
            // read event from queue
            let now = Instant::now();
            let event_future = event_rx.recv();
            let event = match timeout(fsm_timeout.sub(inactive_ctr), event_future).await {
                Ok(res) => match res {
                    None => {
                        log::warn!(
                            "Tunnel={:?}: Event queue closed by the tunnel, terminate FSM",
                            self.tunnel_id()
                        );
                        current_state = State::Terminated;
                        return;
                    }
                    Some(e) => e,
                },
                Err(_) => {
                    // timeout occurred
                    log::warn!(
                        "Tunnel={:?}: FSM timeout occurred. Tunnel has not received any incoming payload too long. Terminate FSM.",
                        self.tunnel_id()
                    );
                    current_state = State::Terminated;
                    return;
                }
            };

            // reset timeout for incoming frame, update inactive_ctr for other event
            match event {
                FsmEvent::IncomingFrame(_) => {
                    log::trace!(
                        "Tunnel={:?}: Reset FSM timeout counter after receiving data.",
                        self.tunnel_id()
                    );
                    inactive_ctr = Duration::from_secs(0);
                }
                _ => {
                    inactive_ctr = inactive_ctr.add(now.elapsed());
                }
            }

            log::trace!(
                "Tunnel={:?}: Received event={:?} in state={:?}",
                self.tunnel_id(),
                event,
                current_state
            );

            // handle event which returns a result with an error or the next state
            let res = match current_state {
                State::Closed => match event {
                    FsmEvent::Init => self.action_init().await,
                    _ => {
                        log::warn!(
                            "Tunnel={:?}: Received message for uninitialized FSM.",
                            self.tunnel_id()
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                State::Connecting(tx) => match event {
                    FsmEvent::Init => {
                        log::warn!(
                            "Tunnel={:?}: Received init event for initialized FSM.",
                            self.tunnel_id()
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::Close => self.action_close().await,
                    FsmEvent::Send(_) => {
                        log::warn!(
                            "Tunnel={:?}: Received send event for non-connected FSM.",
                            self.tunnel_id()
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::IncomingFrame((data, _, iv)) => {
                        // we expect handshake data
                        self.action_handshake_data(tx, data, iv).await
                    }
                    FsmEvent::HandshakeResult(res) => self.action_handshake_result(res).await,
                },

                State::Connected => match event {
                    FsmEvent::Init => {
                        log::warn!(
                            "Tunnel={:?}: Received init event for initialized FSM.",
                            self.tunnel_id()
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::Close => self.action_close().await,
                    FsmEvent::Send(data) => self.action_send(data).await,
                    FsmEvent::IncomingFrame((data, dir, iv)) => {
                        // we expect encrypted application data
                        self.action_app_data(data, dir, iv).await
                    }
                    FsmEvent::HandshakeResult(_) => {
                        log::warn!(
                            "Tunnel={:?}: Received handshake result for connected FSM.",
                            self.tunnel_id()
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                State::Terminated => {
                    log::warn!(
                        "Tunnel={:?}: Received event in state 'Terminated'. Ignore event",
                        self.tunnel_id()
                    );
                    Ok(State::Terminated)
                }
            };

            // handle result
            match res {
                Ok(new_state) => {
                    log::trace!(
                        "Tunnel={:?}: Switch to state {:?}",
                        self.tunnel_id(),
                        new_state
                    );
                    current_state = new_state;
                }
                Err(e) => {
                    log::warn!("Tunnel={:?}: FSM failure: {:?}", self.tunnel_id(), e);
                    current_state = State::Terminated;
                }
            }

            if current_state == State::Terminated {
                log::debug!("Tunnel={:?}: Terminate FSM", self.tunnel_id());
                return;
            }
        }
    }
}

// used for moving FsmEvent and HandshakeEvent to one channel for initiator action_init
enum InitiatorEvent {
    Result(FsmEvent),
    Data(HandshakeEvent),
    FsmClosure,
    HandshakeFsmClosure,
}

#[async_trait]
impl FiniteStateMachine for InitiatorStateMachine {
    fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    #[allow(clippy::single_match)]
    async fn action_init(&mut self) -> Result<State, ProtocolError> {
        // start the handshake fsm in state 'start'
        log::debug!(
            "Tunnel={:?}: Initialize the handshake protocol as an initiator",
            self.tunnel_id
        );

        // prepare data for task
        let codec = self.endpoint_codec.clone();
        let tunnel_id = self.tunnel_id;
        let peers = self.hops.clone();
        let final_result_tx = self.event_tx.clone();
        let fsm_lock = self.fsm_lock.clone();
        let cc = self.local_crypto_config.clone();
        let handshake_timeout = self.handshake_timeout;

        // create a channel used by the main FSM to communicate with the handshake fsm
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(32);

        // create a channel used for receiving all kind of events on one channel
        let (writer, mut reader) = tokio::sync::mpsc::channel::<InitiatorEvent>(32);

        // a task for hooking handshake events from the FSM which are addressed to the handshake fsm
        let writer_clone = writer.clone();
        tokio::spawn(async move {
            log::trace!(
                "Tunnel={:?}: Run the task listening for handshake events from the FSM",
                tunnel_id
            );
            loop {
                match event_rx.recv().await {
                    None => {
                        log::trace!("Tunnel={:?}: Received closure from FSM, send event to reader and terminate the task listening for handshake events from the FSM", tunnel_id);
                        if writer_clone.send(InitiatorEvent::FsmClosure).await.is_err() {
                            log::trace!("Tunnel={:?}: Cannot send FsmClosure, reader has been closed already", tunnel_id);
                        }
                        return;
                    }
                    Some(e) => {
                        log::trace!("Tunnel={:?}: Received new handshake event from the FSM, transfer to reader", tunnel_id);
                        if writer_clone.send(InitiatorEvent::Data(e)).await.is_err() {
                            log::trace!("Tunnel={:?}: Cannot transfer handshake event, read has been closed already", tunnel_id);
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            // codec is already initialized with the first hop, we have to update the codec after
            // each handshake

            // iterate over all hops and target peer
            log::trace!(
                "Tunnel={:?}: Iterate over all peers and establish the tunnel",
                tunnel_id
            );
            for i in 0..peers.len() {
                let current_peer = peers.get(i).unwrap();
                let (target, next_hop) = match peers.get(i + 1) {
                    None => (true, None),
                    Some((addr, _)) => (false, Some(*addr)),
                };
                log::debug!(
                    "Tunnel={:?}: Initiate handshake to current_peer={:?} with next_hop={:?}",
                    tunnel_id,
                    (*current_peer).0,
                    next_hop
                );

                // create the handshake fsm for connecting to current_peer
                let mut handshake_fsm = HandshakeStateMachine::<Client>::new(
                    codec.clone(),
                    tunnel_id,
                    Some(current_peer.clone()),
                    next_hop,
                    fsm_lock.clone(),
                    cc.clone(),
                );

                // create a channel for hooking the handshake results
                let (hooked_result_tx, mut hooked_result_rx) = tokio::sync::mpsc::channel(32);

                // create a channel for communicating with the specific handshake protocol
                let (event_hooked_tx, event_hooked_rx) = tokio::sync::mpsc::channel(32);

                // a task for hooking handshake events from the FSM which are addressed to the handshake fsm
                let writer_clone = writer.clone();
                tokio::spawn(async move {
                    log::trace!(
                        "Tunnel={:?}: Run the task listening for handshake results",
                        tunnel_id
                    );
                    match hooked_result_rx.recv().await {
                        None => {
                            log::trace!("Tunnel={:?}: Received closure from handshake FSM, send event to reader and terminate the task listening for handshake result", tunnel_id);
                            if writer_clone
                                .send(InitiatorEvent::HandshakeFsmClosure)
                                .await
                                .is_err()
                            {
                                log::trace!("Tunnel={:?}: Cannot send HandshakeFsmClosure, reader has been closed already", tunnel_id)
                            }
                        }
                        Some(res) => {
                            log::trace!(
                                "Tunnel={:?}: Result listener has received handshake_result={:?}",
                                tunnel_id,
                                res
                            );
                            if writer_clone
                                .send(InitiatorEvent::Result(res))
                                .await
                                .is_err()
                            {
                                log::trace!("Tunnel={:?}: Terminate the task listening for handshake results due to sending error", tunnel_id);
                            }
                        }
                    }
                });

                // run the handshake fsm
                let handshake_timeout = handshake_timeout;
                tokio::spawn(async move {
                    handshake_fsm
                        .run(event_hooked_rx, hooked_result_tx.clone(), handshake_timeout)
                        .await
                });

                // send the init
                if event_hooked_tx.send(HandshakeEvent::Init).await.is_err() {
                    // cannot send data
                    log::warn!(
                        "Tunnel={:?}: Cannot start the handshake, send handshake failure to FSM",
                        tunnel_id
                    );
                    let _ = final_result_tx
                        .send(FsmEvent::HandshakeResult(Err(
                            ProtocolError::HandshakeSendFailure,
                        )))
                        .await;
                    return;
                }

                // wait for the result of the current handshake
                loop {
                    match reader.recv().await {
                        None => {
                            // here FSM and handshake FSM have failed, nothing more to do
                            log::trace!("Tunnel={:?}: Cannot read from the handshake reader, transfer to reader", tunnel_id);
                            return;
                        }
                        Some(e) => match e {
                            InitiatorEvent::Result(res) => match res {
                                FsmEvent::HandshakeResult(result) => match result {
                                    Ok(_) => {
                                        if target {
                                            log::debug!("Tunnel={:?}: Received handshake_result=ok for the target hop", tunnel_id);
                                            let _ = final_result_tx
                                                .send(FsmEvent::HandshakeResult(Ok(true)))
                                                .await;
                                            return;
                                        } else {
                                            log::debug!("Tunnel={:?}: Received handshake_result=ok for intermediate hop", tunnel_id);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("Tunnel={:?}: Received handshake_result=err, transfer to FSM", tunnel_id);
                                        let _ = final_result_tx
                                            .send(FsmEvent::HandshakeResult(Err(e)))
                                            .await;
                                        return;
                                    }
                                },
                                _ => {
                                    // never happening
                                }
                            },
                            InitiatorEvent::Data(event) => {
                                // delegate to handshake fsm
                                log::trace!("Tunnel={:?}: Transfer hooked handshake event to the handshake FSM", tunnel_id);
                                if event_hooked_tx.send(event).await.is_err() {
                                    let _ = final_result_tx
                                        .send(FsmEvent::HandshakeResult(Err(
                                            ProtocolError::HandshakeSendFailure,
                                        )))
                                        .await;
                                    return;
                                }
                            }
                            InitiatorEvent::FsmClosure => {
                                // FSM has been closed
                                log::warn!(
                                    "Tunnel={:?}: FSM closure, shutdown handshake",
                                    tunnel_id
                                );
                                return;
                            }
                            InitiatorEvent::HandshakeFsmClosure => {
                                // Handshake FSM failed without reply
                                log::warn!(
                                    "Tunnel={:?}: Handshake FSM closure, shutdown handshake",
                                    tunnel_id
                                );
                                return;
                            }
                        },
                    }
                }
            }
        });

        // return sender to the FSM, used for passing HandshakeEvents to the handshake FSM
        Ok(State::Connecting(SenderWrapper { event_tx }))
    }

    async fn action_handshake_result(
        &mut self,
        res: Result<IsTargetEndpoint, ProtocolError>,
    ) -> Result<State, ProtocolError> {
        let tunnel_result_tx = self.tunnel_result_tx.take().unwrap();
        let res = match res {
            Ok(_) => {
                log::debug!("Tunnel={:?}: Handshake was successful", self.tunnel_id);
                let _ = tunnel_result_tx.send(TunnelResult::Connected);
                Ok(State::Connected)
            }
            Err(e) => {
                log::warn!("Tunnel={:?}: Handshake failure: {:?}", self.tunnel_id, e);
                let _ = tunnel_result_tx.send(TunnelResult::Failure(e.clone()));
                Err(e)
            }
        };
        free_fsm_lock(self.fsm_lock.clone()).await;
        res
    }

    fn get_listener(&mut self) -> Sender<IncomingEventMessage> {
        self.listener_tx.clone()
    }

    fn get_codec(&mut self) -> Arc<Mutex<Box<dyn P2pCodec + Send>>> {
        self.endpoint_codec.clone()
    }
}

#[async_trait]
impl FiniteStateMachine for TargetStateMachine {
    fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    async fn action_init(&mut self) -> Result<State, ProtocolError> {
        // start the handshake fsm in state 'WaitForClientHello'
        log::debug!(
            "Tunnel={:?}: Initialize the handshake protocol as a non-initiator",
            self.tunnel_id
        );
        let mut handshake_fsm = HandshakeStateMachine::<Server>::new(
            self.codec.clone(),
            self.tunnel_id,
            None,
            None,
            self.fsm_lock.clone(),
            self.local_crypto_config.clone(),
        );

        // create a channel for communicating with the handshake protocol
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // run the handshake state machine async
        let fsm_event_tx = self.event_tx.clone();
        let handshake_timeout = self.handshake_timeout;
        tokio::spawn(async move {
            handshake_fsm
                .run(event_rx, fsm_event_tx, handshake_timeout)
                .await
        });

        Ok(State::Connecting(SenderWrapper { event_tx }))
    }

    async fn action_handshake_result(
        &mut self,
        res: Result<IsTargetEndpoint, ProtocolError>,
    ) -> Result<State, ProtocolError> {
        let res = match res {
            Ok(is_target_endpoint) => {
                log::debug!("Tunnel={:?}: Handshake was successful", self.tunnel_id);
                if is_target_endpoint {
                    let _ = self
                        .listener_tx
                        .send(IncomingEventMessage::IncomingTunnelCompletion)
                        .await;
                }
                Ok(State::Connected)
            }
            Err(e) => {
                log::warn!("Tunnel={:?}: Handshake failure: {:?}", self.tunnel_id, e);
                Err(e)
            }
        };
        free_fsm_lock(self.fsm_lock.clone()).await;
        res
    }

    fn get_listener(&mut self) -> Sender<IncomingEventMessage> {
        self.listener_tx.clone()
    }

    fn get_codec(&mut self) -> Arc<Mutex<Box<dyn P2pCodec + Send>>> {
        self.codec.clone()
    }
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ProtocolError {
    #[error("Received unexpected message type")]
    UnexpectedMessageType,
    #[error("Received empty message")]
    EmptyMessage,
    #[error("ECDH key exchange failed during handshake")]
    HandshakeECDHFailure,
    #[error("Cannot pass message to the handshake protocol")]
    HandshakeSendFailure,
    #[error("Handshake timeout occurred")]
    HandshakeTimeout,
    #[error("Encryption or decryption failed")]
    CryptoFailure,
    #[error("Error decoding protobuf message. Unexpected message format")]
    ProtobufError,
    #[error("Missing challenge response or invalid signature")]
    InvalidChallengeResponse,
    #[error("Cannot parse routing information of next hop into SockAddr")]
    InvalidRoutingInformation,
    #[error("Cannot update codec from TargetEndpoint to IntermediateHop")]
    CodecUpdateError,
    #[error("Codec impl received unsupported action")]
    CodecUnsupportedAction,
    #[error("IO Error occurred: {0}")]
    IOError(String),
    #[error("Received a packet with invalid payload length")]
    InvalidPacketLength,
    #[error("Received application data with a reused sequence number")]
    ReusedSequenceNumber,
    #[error("Received application data with an expired sequence number")]
    ExpiredSequenceNumber,
    #[error("Cannot sample random peers from RPS module")]
    RpsFailure,
}

#[derive(Debug)]
pub(super) struct SenderWrapper {
    pub event_tx: Sender<HandshakeEvent>,
}

impl PartialEq for SenderWrapper {
    fn eq(&self, _other: &Self) -> bool {
        // we only want to compare states, the sender is irrelevant
        true
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum State {
    Closed,
    Connecting(SenderWrapper),
    Connected,
    Terminated,
}

type IsTargetEndpoint = bool;

#[derive(Debug)]
pub enum FsmEvent {
    Init,                                                     // Start the FSM
    Close,                                                    // Close the Tunnel
    Send(Vec<u8>),                                            // Send Data via the Tunnel
    IncomingFrame((Bytes, Direction, IV)),                    // Received data frame
    HandshakeResult(Result<IsTargetEndpoint, ProtocolError>), // HandshakeResult from handshake fsm
}
