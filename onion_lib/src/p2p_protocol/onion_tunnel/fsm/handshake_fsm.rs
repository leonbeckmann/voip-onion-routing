use crate::p2p_protocol::messages::p2p_messages::{DecryptedHandshakeData, HandshakeData};
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

#[derive(Debug, PartialEq)]
pub enum HandshakeState {
    Start,
    WaitForClientHello,
    WaitForServerHello,
    WaitForRoutingInformation,
    Final,
}

pub enum HandshakeEvent {
    Init,
    HandshakeData(HandshakeData),
    DecryptedHandshakeData(DecryptedHandshakeData),
    Shutdown,
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

    pub async fn run(&self, mut event_rx: Receiver<HandshakeEvent>, event_tx: Sender<FsmEvent>) {
        let _current_state = PT::INIT_STATE;
        // TODO make timeout configurable
        let timeout_duration = Duration::from_millis(3000);

        loop {
            let event_future = event_rx.recv();
            let _event = match timeout(timeout_duration, event_future).await {
                Ok(res) => match res {
                    None => {
                        // closed by fsm
                        log::warn!("Handshake fsm closed by the upper layer");
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

            // TODO handle event in current state
        }
    }
}
