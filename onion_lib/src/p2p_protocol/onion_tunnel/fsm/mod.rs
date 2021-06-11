mod handshake_fsm;

use crate::p2p_protocol::messages::message_codec::DataType::AppData;
use crate::p2p_protocol::messages::message_codec::{
    InitiatorEndpoint, P2pCodec, ProcessedData, TargetEndpoint,
};
use crate::p2p_protocol::messages::p2p_messages::{
    HandshakeData, HandshakeData_oneof_message, PlainHandshakeData_oneof_message,
};
use crate::p2p_protocol::onion_tunnel::fsm::handshake_fsm::{
    Client, HandshakeEvent, HandshakeStateMachine, Server,
};
use crate::p2p_protocol::onion_tunnel::{IncomingEventMessage, IntermediateHop, TunnelResult};
use crate::p2p_protocol::{Direction, FrameId, TunnelId};
use async_trait::async_trait;
use bytes::Bytes;
use protobuf::Message;
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
        }
    }
}

pub(super) struct TargetStateMachine {
    listener_tx: Sender<IncomingEventMessage>,
    event_tx: Sender<FsmEvent>, // only for cloning purpose to pass the sender to the handshake fsm
    codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
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
        }
    }
}

#[async_trait]
pub(super) trait FiniteStateMachine {
    async fn action_init(&mut self) -> Result<State, ProtocolError>;

    async fn action_handshake_data(
        &mut self,
        tx: SenderWrapper,
        data: HandshakeData,
        iv: IV,
    ) -> Result<State, ProtocolError> {
        log::debug!("Delegate handshake data to the handshake protocol");

        // split up into more specific event
        if data.message.is_none() {
            return Err(ProtocolError::EmptyMessage);
        }
        let event = match data.message.unwrap() {
            HandshakeData_oneof_message::handshakeData(data) => {
                if data.message.is_none() {
                    return Err(ProtocolError::EmptyMessage);
                }
                match data.message.unwrap() {
                    PlainHandshakeData_oneof_message::clientHello(data) => {
                        HandshakeEvent::ClientHello(data)
                    }
                    PlainHandshakeData_oneof_message::serverHello(data) => {
                        HandshakeEvent::ServerHello(data)
                    }
                }
            }
            HandshakeData_oneof_message::encHandshakeData(data) => {
                HandshakeEvent::EncryptedHandshakeData(data, iv)
            }
        };

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
        match self
            .get_codec()
            .lock()
            .await
            .process_data(direction, data, iv)
            .await?
        {
            ProcessedData::TransferredToNextHop => {
                log::debug!("Data have been transferred to next hop");
            }
            ProcessedData::IncomingData(data) => {
                log::debug!("Send incoming data to upper layer");
                // we can ignore an error here since this will only fail when the tunnel has been closed
                let _ = self
                    .get_listener()
                    .send(IncomingEventMessage::IncomingData(data))
                    .await;
            }
        };

        // stay in state connected
        Ok(State::Connected)
    }

    async fn action_close(&mut self) -> Result<State, ProtocolError> {
        // all connection listeners have left
        log::debug!("Received close event, notify tunnel peers and shutdown tunnel");
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
                    log::warn!("Event queue closed by the tunnel, terminate FSM");
                    current_state = State::Terminated;
                    return;
                }
                Some(e) => e,
            };

            // handle event which returns a result with an error or the next state
            let res = match current_state {
                State::Closed => match event {
                    FsmEvent::Init => self.action_init().await,
                    _ => {
                        log::warn!("Received message for uninitialized FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                State::Connecting(tx) => match event {
                    FsmEvent::Init => {
                        log::warn!("Received init event for initialized FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::Close => self.action_close().await,
                    FsmEvent::Send(_) => {
                        log::warn!("Received send event for non-connected FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::IncomingFrame((data, _, iv)) => {
                        // we expect handshake data
                        match HandshakeData::parse_from_bytes(data.as_ref()) {
                            Ok(data) => self.action_handshake_data(tx, data, iv).await,
                            Err(_) => {
                                log::warn!("Cannot parse incoming frame to handshake data");
                                Err(ProtocolError::ProtobufError)
                            }
                        }
                    }
                    FsmEvent::HandshakeResult(res) => self.action_handshake_result(res).await,
                    FsmEvent::RecvClose(direction) => self.action_recv_close(direction).await,
                },

                State::Connected => match event {
                    FsmEvent::Init => {
                        log::warn!("Received init event for initialized FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::Close => self.action_close().await,
                    FsmEvent::Send(data) => self.action_send(data).await,
                    FsmEvent::IncomingFrame((data, dir, iv)) => {
                        // we expect encrypted application data
                        self.action_app_data(data, dir, iv).await
                    }
                    FsmEvent::HandshakeResult(_) => {
                        log::warn!("Received handshake result for connected FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::RecvClose(direction) => self.action_recv_close(direction).await,
                },

                State::Terminated => {
                    log::warn!("Received event in state 'Terminated'. Ignore event");
                    Ok(State::Terminated)
                }
            };

            // handle result
            match res {
                Ok(new_state) => {
                    log::trace!("Switch to new state {:?}", new_state);
                    current_state = new_state;
                }
                Err(e) => {
                    log::error!("FSM failure: {:?}", e);
                    current_state = State::Terminated;
                }
            }

            if current_state == State::Terminated {
                log::debug!("Terminate FSM");
                return;
            }
        }
    }
}

#[async_trait]
impl FiniteStateMachine for InitiatorStateMachine {
    async fn action_init(&mut self) -> Result<State, ProtocolError> {
        // start the handshake fsm in state 'start'
        log::debug!("Initialize the handshake protocol as an initiator");
        let mut handshake_fsm = HandshakeStateMachine::<Client>::new(self.endpoint_codec.clone());

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
        log::debug!("Received closure from target peer, notify hops and close tunnel");
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
                log::debug!("Handshake was successful");
                let _ = tunnel_result_tx.send(TunnelResult::Connected);
                Ok(State::Connected)
            }
            Err(e) => {
                log::warn!("Handshake failure");
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
    async fn action_init(&mut self) -> Result<State, ProtocolError> {
        // start the handshake fsm in state 'WaitForClientHello'
        log::debug!("Initialize the handshake protocol as a non-initiator");
        let mut handshake_fsm = HandshakeStateMachine::<Server>::new(self.codec.clone());

        // create a channel for communicating with the handshake protocol
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(32);

        // run the handshake state machine async
        let fsm_event_tx = self.event_tx.clone();
        tokio::spawn(async move { handshake_fsm.run(event_rx, fsm_event_tx).await });

        Ok(State::Connecting(SenderWrapper { event_tx }))
    }

    async fn action_recv_close(&mut self, d: Direction) -> Result<State, ProtocolError> {
        // receives close from initiator peer
        log::debug!("Received closure from initiator peer, close tunnel");
        self.codec.lock().await.close(d, false).await;
        Ok(State::Terminated)
    }

    async fn action_handshake_result(
        &mut self,
        res: Result<(), ProtocolError>,
    ) -> Result<State, ProtocolError> {
        match res {
            Ok(_) => {
                log::debug!("Handshake was successful");
                let _ = self
                    .listener_tx
                    .send(IncomingEventMessage::IncomingTunnelCompletion)
                    .await;
                Ok(State::Connected)
            }
            Err(e) => {
                log::warn!("Handshake failure");
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
    #[error("Cannot create packet of expected size")]
    CodecPaddingError,
    #[error("IO Error occurred: {0}")]
    IOError(String),
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

pub enum FsmEvent {
    Init,  // Start the FSM
    Close, // Close the Tunnel
    RecvClose(Direction),
    Send(Vec<u8>),                              // Send Data via the Tunnel
    IncomingFrame((Bytes, Direction, IV)),      // Received data frame
    HandshakeResult(Result<(), ProtocolError>), // HandshakeResult from handshake fsm
}

/*
#[derive(Debug)]
pub(crate) struct TunnelStateMachine {
    event_rx: Receiver<IoEvent>,
    message_codec_in: Box<dyn message_codec::P2pCodec + Send + 'static>,
    message_codec_out: Box<dyn message_codec::P2pCodec + Send + 'static>,
    is_endpoint: bool,
    packet_ids: Arc<Mutex<HashMap<PacketId, TunnelId>>>,
    incoming_next_packet_ids: LinkedList<PacketId>,
    outgoing_next_packet_ids: LinkedList<PacketId>,
    tunnel_id: TunnelId,
}

impl TunnelStateMachine {
    async fn wait_for_frame_event(
        &mut self,
    ) -> Result<p2p_messages::TunnelFrame_oneof_message, P2pError> {
        let event = self.wait_for_event().await?;

        match event {
            IoEvent::ReceiveData(data) => {
                let connect_request = self.message_codec_in.from_raw(&data).await?;
                let message = connect_request
                    .message
                    .ok_or(P2pError::FrameError("TunnelFrame is unset".to_string()))?;
                Ok(message)
            }
        }
    }

    fn outgoing_packet_id(&mut self) -> (Vec<PacketId>, PacketId) {
        let current_packet_id = self
            .outgoing_next_packet_ids
            .pop_front()
            .expect("Out of packet ids");
        self.outgoing_next_packet_ids.push_back(rand::random());
        let mut next_packet_ids = vec![];
        next_packet_ids.extend(self.outgoing_next_packet_ids.iter());

        (next_packet_ids, current_packet_id)
    }

    async fn incoming_packet_id(&mut self, next_packet_ids: &[PacketId]) {
        for next_packet_id in next_packet_ids {
            if !self.incoming_next_packet_ids.contains(&next_packet_id) {
                self.incoming_next_packet_ids
                    .push_back(next_packet_id.to_owned());
                let mut packet_ids = self.packet_ids.lock().await;

                // The key should not be present
                debug_assert!(packet_ids
                    .insert(next_packet_id.to_owned(), self.tunnel_id)
                    .is_none());
            }
        }
        // Move acceptance window forward if packets got lost
        while self.incoming_next_packet_ids.len() > 20 {
            let timeout_packet_id = self.incoming_next_packet_ids.pop_front().unwrap(); // safe unwrap
            let mut packet_ids = self.packet_ids.lock().await;
            debug_assert!(packet_ids.remove(&timeout_packet_id).is_some());
        }
    }

    pub(crate) async fn tunnel_connect(&mut self) -> Result<TunnelTransit, TunnelError> {
        let frame = self.wait_for_frame_event().await?;

        match frame {
            p2p_messages::TunnelFrame_oneof_message::tunnelHello(message) => {
                self.incoming_packet_id(message.get_next_packet_ids()).await;

                let target = if message.target == "" {
                    // Final host in the hop chain
                    None
                } else {
                    Some(SocketAddr::from_str(message.target.as_str()).map_err(|e| {
                        P2pError::FrameError(format!(
                            "Target is invalid socket address: {:#?}, error: {:#?}",
                            message.target, e
                        ))
                    })?)
                };
                self.message_codec_out.set_target(target);

                return Ok(Transit::To(TunnelState::Connected));
            }
            _ => {
                return Err(P2pError::FrameError(format!(
                    "Expected TunnelHello, got: {:#?}",
                    frame
                )))
            }
        }
    }

    pub(crate) async fn receive_packet(&mut self) -> Result<TunnelTransit, TunnelError> {
        let frame = self.wait_for_frame_event().await?;

        match frame {
            p2p_messages::TunnelFrame_oneof_message::tunnelData(message) => {
                self.incoming_packet_id(message.get_next_packet_ids()).await;

                if self.message_codec_out.is_endpoint() {
                    log::debug!("Received {} bytes at final endpoint", message.data.len());
                } else {
                    let mut msg = p2p_messages::TunnelData::new();
                    msg.set_data(message.data);

                    let (next_packet_ids, current_packet_id) = self.outgoing_packet_id();
                    msg.set_next_packet_ids(next_packet_ids);

                    self.message_codec_out
                        .write_socket(current_packet_id, &msg.into())
                        .await?;
                }

                return Ok(Transit::To(TunnelState::Connected));
            }
            p2p_messages::TunnelFrame_oneof_message::tunnelClose(_message) => {
                let msg = p2p_messages::TunnelClose::new();

                let (_next_packet_ids, current_packet_id) = self.outgoing_packet_id();

                self.message_codec_out
                    .write_socket(current_packet_id, &msg.into())
                    .await?;

                return Ok(Transit::To(TunnelState::Closing));
            }
            _ => {
                return Err(P2pError::FrameError(format!(
                    "Expected TunnelData or TunnelClose, got: {:#?}",
                    frame
                )))
            }
        }
    }
}
*/
