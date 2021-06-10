use crate::p2p_protocol::messages::p2p_messages::{
    ClientHello, EncryptedHandshakeData, ServerHello,
};
use crate::p2p_protocol::onion_tunnel::fsm::{FsmEvent, ProtocolError};
use std::marker::PhantomData;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::timeout;

pub(super) struct Client;
pub(super) struct Server;

pub trait PeerType {
    const INIT_STATE: HandshakeState;
}

impl PeerType for Client {
    const INIT_STATE: HandshakeState = HandshakeState::Start;
}

impl PeerType for Server {
    const INIT_STATE: HandshakeState = HandshakeState::WaitForClientHello;
}

// TODO we need a codec that uses the crypto context, pad the message and send the data
// TODO store the routing information within the codec
// TODO we need a crypto context that holds the key, manages the iv and encrypts / decrypts data
// TODO pass the crypto context and the codec to the main FSM on handshake success

#[derive(Debug, PartialEq)]
pub enum HandshakeState {
    Start,
    WaitForClientHello,
    WaitForServerHello,
    WaitForRoutingInformation,
}

#[derive(Debug)]
pub enum HandshakeEvent {
    Init,
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EncryptedHandshakeData(EncryptedHandshakeData),
}

pub struct HandshakeStateMachine<PT> {
    _phantom: PhantomData<PT>,
}

impl<PT: PeerType> HandshakeStateMachine<PT> {
    pub fn new() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }

    pub async fn action_init(&mut self) -> Result<HandshakeState, ProtocolError> {
        // TODO create client hello and give it to message codec
        Ok(HandshakeState::WaitForServerHello)
    }

    pub async fn action_recv_client_hello(
        &mut self,
        _data: ClientHello,
    ) -> Result<HandshakeState, ProtocolError> {
        // TODO create server hello and give it to message_codec
        Ok(HandshakeState::WaitForRoutingInformation)
    }

    pub async fn action_recv_server_hello(
        &mut self,
        _data: ServerHello,
    ) -> Result<(), ProtocolError> {
        // TODO create encrypted handshake message and give it to message_codec
        Ok(())
    }

    pub async fn action_recv_routing(
        &mut self,
        _data: EncryptedHandshakeData,
    ) -> Result<(), ProtocolError> {
        // TODO decrypt via crypto context
        // TODO check for routing information
        Ok(())
    }

    pub async fn run(
        &mut self,
        mut event_rx: Receiver<HandshakeEvent>,
        event_tx: Sender<FsmEvent>,
    ) {
        let mut current_state = PT::INIT_STATE;
        // TODO make timeout configurable
        let timeout_duration = Duration::from_millis(3000);

        loop {
            let event_future = event_rx.recv();
            let event = match timeout(timeout_duration, event_future).await {
                Ok(res) => match res {
                    None => {
                        // closed by fsm
                        log::warn!("Handshake fsm closed by the main FSM");
                        return;
                    }
                    Some(e) => e,
                },
                Err(_) => {
                    // timeout occurred
                    let _ = event_tx
                        .send(FsmEvent::HandshakeResult(Err(
                            ProtocolError::HandshakeTimeout,
                        )))
                        .await;
                    return;
                }
            };

            // handle event in current state
            let res = match current_state {
                HandshakeState::Start => match event {
                    HandshakeEvent::Init => self.action_init().await,

                    _ => {
                        log::warn!("Received unexpected event '{:?}' in Start", event);
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                HandshakeState::WaitForClientHello => match event {
                    HandshakeEvent::ClientHello(data) => {
                        self.action_recv_client_hello(data).await
                    }
                    _ => {
                        log::warn!(
                            "Received unexpected event '{:?}' in WaitForClientHello",
                            event
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                HandshakeState::WaitForServerHello => match event {
                    HandshakeEvent::ServerHello(data) => {
                        match self.action_recv_server_hello(data).await {
                            Ok(_) => {
                                // TODO return success
                                return;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => {
                        log::warn!(
                            "Received unexpected event '{:?}' in WaitForServerHello",
                            event
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                HandshakeState::WaitForRoutingInformation => match event {
                    HandshakeEvent::EncryptedHandshakeData(data) => {
                        match self.action_recv_routing(data).await {
                            Ok(_) => {
                                // TODO return success
                                return;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => {
                        log::warn!(
                            "Received unexpected event '{:?}' in WaitForRoutingInformation",
                            event
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },
            };

            // handle result
            match res {
                Ok(new_state) => {
                    log::trace!("Switch to handshake state {:?}", new_state);
                    current_state = new_state;
                }
                Err(e) => {
                    log::warn!("Handshake failure: {:?}", e.clone());
                    let _ = event_tx.send(FsmEvent::HandshakeResult(Err(e))).await;
                    return;
                }
            }
        }
    }
}
