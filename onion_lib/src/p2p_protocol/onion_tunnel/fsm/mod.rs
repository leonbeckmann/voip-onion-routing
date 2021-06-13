mod handshake_fsm;

use crate::p2p_protocol::messages::message_codec::DataType::AppData;
use crate::p2p_protocol::messages::message_codec::{
    InitiatorEndpoint, P2pCodec, ProcessedData, TargetEndpoint,
};
use crate::p2p_protocol::messages::p2p_messages::HandshakeData_oneof_message;
use crate::p2p_protocol::onion_tunnel::fsm::handshake_fsm::{
    Client, HandshakeEvent, HandshakeStateMachine, Server,
};
use crate::p2p_protocol::onion_tunnel::{IncomingEventMessage, IntermediateHop, TunnelResult};
use crate::p2p_protocol::{Direction, FrameId, TunnelId};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{oneshot, Mutex};

type IV = Bytes;

pub(super) struct InitiatorStateMachine {
    tunnel_result_tx: Option<oneshot::Sender<TunnelResult>>, // signal the listener completion
    event_tx: Sender<FsmEvent>, // only for cloning purpose to pass the sender to the handshake fsm
    endpoint_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
    listener_tx: Sender<IncomingEventMessage>,
    tunnel_id: TunnelId,
}

// TODO fill fsm
impl InitiatorStateMachine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _hops: Vec<IntermediateHop>,
        tunnel_result_tx: oneshot::Sender<TunnelResult>,
        frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
        socket: Arc<UdpSocket>,
        target: SocketAddr,
        _target_host_key: Vec<u8>,
        tunnel_id: TunnelId,
        listener_tx: Sender<IncomingEventMessage>,
        event_tx: Sender<FsmEvent>,
    ) -> Self {
        InitiatorStateMachine {
            tunnel_result_tx: Some(tunnel_result_tx),
            event_tx,
            endpoint_codec: Arc::new(Mutex::new(Box::new(InitiatorEndpoint::new(
                socket, target, frame_ids, tunnel_id,
            )))),
            listener_tx,
            tunnel_id,
        }
    }
}

pub(super) struct TargetStateMachine {
    listener_tx: Sender<IncomingEventMessage>,
    event_tx: Sender<FsmEvent>, // only for cloning purpose to pass the sender to the handshake fsm
    codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
    tunnel_id: TunnelId,
}

impl TargetStateMachine {
    pub fn new(
        frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
        socket: Arc<UdpSocket>,
        source: SocketAddr,
        tunnel_id: TunnelId,
        listener_tx: Sender<IncomingEventMessage>,
        event_tx: Sender<FsmEvent>,
    ) -> Self {
        TargetStateMachine {
            listener_tx,
            event_tx,
            codec: Arc::new(Mutex::new(Box::new(TargetEndpoint::new(
                socket, source, frame_ids, tunnel_id,
            )))),
            tunnel_id,
        }
    }
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
            ProcessedData::TransferredToNextHop => {
                return Err(ProtocolError::UnexpectedMessageType);
            }
            ProcessedData::HandshakeData(data) => {
                if data.message.is_none() {
                    return Err(ProtocolError::EmptyMessage);
                }
                match data.message.unwrap() {
                    HandshakeData_oneof_message::clientHello(data) => {
                        HandshakeEvent::ClientHello(data)
                    }
                    HandshakeData_oneof_message::serverHello(data) => {
                        HandshakeEvent::ServerHello(data)
                    }
                    HandshakeData_oneof_message::routing(data) => {
                        HandshakeEvent::RoutingInformation(data)
                    }
                }
            }
            ProcessedData::IncomingData(_) => {
                log::warn!(
                    "Tunnel={:?}: Not expecting incooming application data in connecting state",
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
        log::trace!(
            "Tunnel={:?}: Received close event, notify tunnel peers and shutdown tunnel",
            self.tunnel_id()
        );
        self.get_codec()
            .lock()
            .await
            .close(Direction::Forward, true)
            .await;
        Ok(State::Terminated)
    }

    async fn action_recv_close(&mut self, d: Direction) -> Result<State, ProtocolError>;

    async fn action_send(&mut self, data: Vec<u8>) -> Result<State, ProtocolError> {
        // send data to the target via the tunnel
        self.get_codec().lock().await.write(AppData(data)).await?;
        Ok(State::Connected)
    }

    async fn action_handshake_result(
        &mut self,
        res: Result<(), ProtocolError>,
    ) -> Result<State, ProtocolError>;

    const INIT_STATE: State = State::Closed;

    fn get_listener(&mut self) -> Sender<IncomingEventMessage>;
    fn get_codec(&mut self) -> Arc<Mutex<Box<dyn P2pCodec + Send>>>;

    #[allow(unused_assignments)]
    async fn handle_events(&mut self, mut event_rx: Receiver<FsmEvent>) {
        let mut current_state = Self::INIT_STATE;

        loop {
            // read event from queue
            let event = match event_rx.recv().await {
                None => {
                    log::warn!(
                        "Tunnel={:?}: Event queue closed by the tunnel, terminate FSM",
                        self.tunnel_id()
                    );
                    current_state = State::Terminated;
                    return;
                }
                Some(e) => e,
            };
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
                    FsmEvent::RecvClose(direction) => self.action_recv_close(direction).await,
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
                    FsmEvent::RecvClose(direction) => self.action_recv_close(direction).await,
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
                        "Tunnel={:?}: Switch to new state {:?}",
                        self.tunnel_id(),
                        new_state
                    );
                    current_state = new_state;
                }
                Err(e) => {
                    log::warn!("Tunnel={:?}: FSM failure: {:?}", e, self.tunnel_id());
                    current_state = State::Terminated;
                }
            }

            if current_state == State::Terminated {
                log::trace!("Tunnel={:?}: Terminate FSM", self.tunnel_id());
                return;
            }
        }
    }
}

#[async_trait]
impl FiniteStateMachine for InitiatorStateMachine {
    fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    async fn action_init(&mut self) -> Result<State, ProtocolError> {
        // start the handshake fsm in state 'start'
        // TODO hops
        log::trace!(
            "Tunnel={:?}: Initialize the handshake protocol as an initiator",
            self.tunnel_id
        );
        let mut handshake_fsm =
            HandshakeStateMachine::<Client>::new(self.endpoint_codec.clone(), self.tunnel_id);

        // create a channel for communicating with the handshake protocol
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);
        let tx_clone = event_tx.clone();

        // run the handshake state machine async
        let fsm_event_tx = self.event_tx.clone();
        tokio::spawn(async move { handshake_fsm.run(event_rx, fsm_event_tx).await });

        // start via init
        if tx_clone.send(HandshakeEvent::Init).await.is_err() {
            Err(ProtocolError::HandshakeSendFailure)
        } else {
            Ok(State::Connecting(SenderWrapper { event_tx }))
        }
    }

    async fn action_recv_close(&mut self, d: Direction) -> Result<State, ProtocolError> {
        // target sends closure, notify hops
        log::trace!(
            "Tunnel={:?}: Received closure from target peer, notify hops amd close tunnel",
            self.tunnel_id
        );
        self.endpoint_codec.lock().await.close(d, false).await;
        Ok(State::Terminated)
    }

    async fn action_handshake_result(
        &mut self,
        res: Result<(), ProtocolError>,
    ) -> Result<State, ProtocolError> {
        let tunnel_result_tx = self.tunnel_result_tx.take().unwrap();
        match res {
            Ok(_) => {
                log::trace!("Tunnel={:?}: Handshake was successful", self.tunnel_id);
                let _ = tunnel_result_tx.send(TunnelResult::Connected);
                Ok(State::Connected)
            }
            Err(e) => {
                log::warn!("Tunnel={:?}: Handshake failure: {:?}", self.tunnel_id, e);
                let _ = tunnel_result_tx.send(TunnelResult::Failure(e.clone()));
                Err(e)
            }
        }
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
        log::trace!(
            "Tunnel={:?}: Initialize the handshake protocol as a non-initiator",
            self.tunnel_id
        );
        let mut handshake_fsm =
            HandshakeStateMachine::<Server>::new(self.codec.clone(), self.tunnel_id);

        // create a channel for communicating with the handshake protocol
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // run the handshake state machine async
        let fsm_event_tx = self.event_tx.clone();
        tokio::spawn(async move { handshake_fsm.run(event_rx, fsm_event_tx).await });

        Ok(State::Connecting(SenderWrapper { event_tx }))
    }

    async fn action_recv_close(&mut self, d: Direction) -> Result<State, ProtocolError> {
        // receives close from initiator peer
        log::trace!(
            "Tunnel={:?}: Received closure from initiator peer, close tunnel",
            self.tunnel_id
        );
        self.codec.lock().await.close(d, false).await;
        Ok(State::Terminated)
    }

    async fn action_handshake_result(
        &mut self,
        res: Result<(), ProtocolError>,
    ) -> Result<State, ProtocolError> {
        match res {
            Ok(_) => {
                log::trace!("Tunnel={:?}: Handshake was successful", self.tunnel_id);
                let _ = self
                    .listener_tx
                    .send(IncomingEventMessage::IncomingTunnelCompletion)
                    .await;
                Ok(State::Connected)
            }
            Err(e) => {
                log::warn!("Tunnel={:?}: Handshake failure: {:?}", self.tunnel_id, e);
                Err(e)
            }
        }
    }

    fn get_listener(&mut self) -> Sender<IncomingEventMessage> {
        self.listener_tx.clone()
    }

    fn get_codec(&mut self) -> Arc<Mutex<Box<dyn P2pCodec + Send>>> {
        self.codec.clone()
    }
}

#[derive(Error, Debug, Clone)]
pub enum ProtocolError {
    #[error("Received unexpected message type")]
    UnexpectedMessageType,
    #[error("Received empty message")]
    EmptyMessage,
    #[error("Cannot pass message to the handshake protocol")]
    HandshakeSendFailure,
    #[error("Handshake timeout occurred")]
    HandshakeTimeout,
    #[error("Error decoding protobuf message. Unexpected message format")]
    ProtobufError,
    #[error("Cannot parse routing information of next hop into SockAddr")]
    InvalidRoutingInformation,
    #[error("Cannot update codec from TargetEndpoint to IntermediateHop")]
    CodecUpdateError,
    #[error("Codec impl received unsupported action")]
    CodecUnsupportedAction,
    #[error("IO Error occurred: {0}")]
    IOError(String),
    #[error("Received a packet with invalid playload length")]
    InvalidPacketLength,
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

#[derive(Debug)]
pub enum FsmEvent {
    Init,  // Start the FSM
    Close, // Close the Tunnel
    RecvClose(Direction),
    Send(Vec<u8>),                              // Send Data via the Tunnel
    IncomingFrame((Bytes, Direction, IV)),      // Received data frame
    HandshakeResult(Result<(), ProtocolError>), // HandshakeResult from handshake fsm
}
