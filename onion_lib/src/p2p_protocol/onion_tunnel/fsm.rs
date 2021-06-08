use crate::p2p_protocol::messages::p2p_messages::{
    ApplicationData, EncryptedHandshakeData, HandshakeData,
};
use crate::p2p_protocol::onion_tunnel::{IntermediateHop, TunnelResult};
use crate::p2p_protocol::{FrameId, TunnelId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{oneshot, Mutex};

// TODO unregister the tunnel from the registry when receiving a closure

pub(super) struct InitiatorStateMachine {
    tunnel_result_tx: Option<oneshot::Sender<TunnelResult>>, // signal the listener completion
}

impl InitiatorStateMachine {
    pub fn new(
        _hops: Vec<IntermediateHop>,
        tunnel_result_tx: oneshot::Sender<TunnelResult>,
        _frame_ids: Arc<Mutex<HashMap<FrameId, TunnelId>>>,
        _socket: Arc<UdpSocket>,
        _target: SocketAddr,
        _target_host_key: Vec<u8>,
        _tunnel_id: TunnelId,
    ) -> Self {
        InitiatorStateMachine {
            tunnel_result_tx: Some(tunnel_result_tx),
        }
    }
}

pub(super) struct TargetStateMachine {}

impl TargetStateMachine {
    pub fn new(
        _frame_ids: Arc<Mutex<HashMap<FrameId, TunnelId>>>,
        _socket: Arc<UdpSocket>,
        _source: SocketAddr,
        _tunnel_id: TunnelId,
    ) -> Self {
        TargetStateMachine {}
    }
}

#[async_trait]
pub(super) trait FiniteStateMachine {
    async fn action_init(&mut self) -> Result<State, ProtocolError>;
    async fn action_handshake_data(&mut self, data: HandshakeData) -> Result<State, ProtocolError>;
    async fn action_enc_handshake_data(
        &mut self,
        data: EncryptedHandshakeData,
    ) -> Result<State, ProtocolError>;
    async fn action_app_data(&mut self, data: ApplicationData) -> Result<State, ProtocolError>;
    async fn action_close(&mut self) -> Result<State, ProtocolError>;
    async fn action_send(&mut self, data: Vec<u8>) -> Result<State, ProtocolError>;

    const INIT_STATE: State = State::Closed;

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

                State::Connecting => match event {
                    FsmEvent::Init => {
                        log::warn!("Received init event for initialized FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::Close => self.action_close().await,
                    FsmEvent::Send(_) => {
                        log::warn!("Received send event for non-connected FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::Handshake(data) => self.action_handshake_data(data).await,
                    FsmEvent::EncryptedHandshake(data) => {
                        self.action_enc_handshake_data(data).await
                    }
                    FsmEvent::ApplicationData(_) => {
                        log::warn!("Received application data for not-connected FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                State::Connected => match event {
                    FsmEvent::Init => {
                        log::warn!("Received init event for initialized FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::Close => self.action_close().await,
                    FsmEvent::Send(data) => self.action_send(data).await,
                    FsmEvent::Handshake(_) => {
                        log::warn!("Received handshake data for connected FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::EncryptedHandshake(_) => {
                        log::warn!("Received encrypted handshake data for connected FSM.");
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                    FsmEvent::ApplicationData(data) => self.action_app_data(data).await,
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
        // TODO implement
        let tunnel_result_tx = self.tunnel_result_tx.take().unwrap();
        let _ = tunnel_result_tx.send(TunnelResult::Connected);
        Ok(State::Connected)
    }

    async fn action_handshake_data(
        &mut self,
        _data: HandshakeData,
    ) -> Result<State, ProtocolError> {
        unimplemented!()
    }

    async fn action_enc_handshake_data(
        &mut self,
        _data: EncryptedHandshakeData,
    ) -> Result<State, ProtocolError> {
        unimplemented!()
    }

    async fn action_app_data(&mut self, _data: ApplicationData) -> Result<State, ProtocolError> {
        unimplemented!()
    }

    async fn action_close(&mut self) -> Result<State, ProtocolError> {
        // TODO implement
        Ok(State::Terminated)
    }

    async fn action_send(&mut self, _data: Vec<u8>) -> Result<State, ProtocolError> {
        unimplemented!()
    }
}

#[async_trait]
impl FiniteStateMachine for TargetStateMachine {
    async fn action_init(&mut self) -> Result<State, ProtocolError> {
        // TODO implement
        Ok(State::Connected)
    }

    async fn action_handshake_data(
        &mut self,
        _data: HandshakeData,
    ) -> Result<State, ProtocolError> {
        unimplemented!()
    }

    async fn action_enc_handshake_data(
        &mut self,
        _data: EncryptedHandshakeData,
    ) -> Result<State, ProtocolError> {
        unimplemented!()
    }

    async fn action_app_data(&mut self, _data: ApplicationData) -> Result<State, ProtocolError> {
        unimplemented!()
    }

    async fn action_close(&mut self) -> Result<State, ProtocolError> {
        // TODO implement
        Ok(State::Terminated)
    }

    async fn action_send(&mut self, _data: Vec<u8>) -> Result<State, ProtocolError> {
        unimplemented!()
    }
}

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Received unexpected message type")]
    UnexpectedMessageType,
}

#[derive(Debug, PartialEq)]
pub(super) enum State {
    Closed,
    Connecting,
    Connected,
    Terminated,
}

pub enum FsmEvent {
    Init,                                       // Start the FSM
    Close,                                      // Close the Tunnel
    Send(Vec<u8>),                              // Send Data via the Tunnel
    Handshake(HandshakeData),                   // Received handshake data
    EncryptedHandshake(EncryptedHandshakeData), // Received encrypted handshake data
    ApplicationData(ApplicationData),           // Received encrypted application data
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
    /// For now only ReceiveData events are supported, do not use this function.
    /// Use wait_for_frame_event instead.
    async fn wait_for_event(&mut self) -> Result<IoEvent, P2pError> {
        let event_future = self.event_rx.recv();
        let event = timeout(Duration::from_secs(30), event_future).await;

        if event.is_err() {
            return Err(TunnelError::SocketResponseTimeout(0));
        }
        let event = event.unwrap(); // Safe
        if event.is_none() {
            return Err(TunnelError::EventQueueClosed);
        }
        let event = event.unwrap(); // Safe
        Ok(event)
    }

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
                    // TODO: send data to API
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

    pub(crate) async fn close_tunnel(&mut self) -> Result<TunnelTransit, TunnelError> {
        Ok(Transit::Terminate)
    }
}
*/
