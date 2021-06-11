use crate::p2p_protocol::messages::message_codec::{
    DataType, IntermediateHop, P2pCodec, TargetEndpoint,
};
use crate::p2p_protocol::messages::p2p_messages::{
    ClientHello, DecryptedHandshakeData, EncryptedHandshakeData, ServerHello,
};
use crate::p2p_protocol::onion_tunnel::fsm::{FsmEvent, ProtocolError, IV};
use protobuf::Message;
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
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

// TODO we need a crypto context that holds the key, manages the iv and encrypts / decrypts data

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
    EncryptedHandshakeData(EncryptedHandshakeData, IV),
}

pub struct HandshakeStateMachine<PT> {
    _phantom: PhantomData<PT>,
    message_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
}

impl<PT: PeerType> HandshakeStateMachine<PT> {
    pub fn new(message_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>) -> Self {
        Self {
            _phantom: Default::default(),
            message_codec,
        }
    }

    pub async fn action_init(&mut self) -> Result<HandshakeState, ProtocolError> {
        // create client hello and give it to message codec
        // TODO fill client hello
        let client_hello = ClientHello::new();

        let mut codec = self.message_codec.lock().await;
        if let Err(e) = codec.write(DataType::ClientHello(client_hello)).await {
            Err(e)
        } else {
            Ok(HandshakeState::WaitForServerHello)
        }
    }

    pub async fn action_recv_client_hello(
        &mut self,
        data: ClientHello,
    ) -> Result<HandshakeState, ProtocolError> {
        // set backward frame id on the target endpoint
        let mut codec = self.message_codec.lock().await;
        codec.set_backward_frame_id(data.backwardFrameId);

        // create server hello and give it to message_codec
        // TODO fill server_hello
        let server_hello = ServerHello::new();
        if let Err(e) = codec.write(DataType::ServerHello(server_hello)).await {
            Err(e)
        } else {
            Ok(HandshakeState::WaitForRoutingInformation)
        }
    }

    pub async fn action_recv_server_hello(
        &mut self,
        data: ServerHello,
    ) -> Result<(), ProtocolError> {
        let mut codec = self.message_codec.lock().await;
        codec.set_forward_frame_id(data.forwardFrameId);
        codec.set_backward_frame_id(data.backwardFrameId);

        // create decrypted handshake message and give it to message_codec
        // TODO fill
        let dec_data = DecryptedHandshakeData::new();
        if let Err(e) = codec.write(DataType::DecHandshakeData(dec_data)).await {
            Err(e)
        } else {
            Ok(())
        }
    }

    pub async fn action_recv_routing(
        &mut self,
        data: EncryptedHandshakeData,
        _iv: IV,
    ) -> Result<(), ProtocolError> {
        // TODO decrypt via crypto context using iv and key
        let decrypted_bytes = data.data;

        // check for decrypted handshake data
        let handshake_data =
            match DecryptedHandshakeData::parse_from_bytes(decrypted_bytes.as_ref()) {
                Ok(decrypted_frame) => decrypted_frame,
                Err(_) => {
                    log::warn!("Cannot parse incoming frame to decrypted handshake data");
                    return Err(ProtocolError::ProtobufError);
                }
            };

        // get target endpoint
        let mut codec_guard = self.message_codec.lock().await;
        let target_endpoint = match (*codec_guard).as_any().downcast_mut::<TargetEndpoint>() {
            None => return Err(ProtocolError::CodecUpdateError),
            Some(endpoint) => endpoint,
        };

        // check for routing
        if handshake_data.routing.is_none() {
            log::debug!("No routing information provided, peer is the target endpoint");
            target_endpoint.lock_as_target_endpoint().await;
            Ok(())
        } else {
            // parse socket addr
            let routing = handshake_data.routing.unwrap(); // safe
            let addr = match u16::try_from(routing.nextHopPort) {
                Ok(port) => match routing.nextHopAddr.len() {
                    4 => {
                        // ipv4
                        let slice: [u8; 4] = routing.nextHopAddr.as_ref()[0..4].try_into().unwrap();
                        let ipv4 = IpAddr::from(slice);
                        SocketAddr::new(ipv4, port)
                    }
                    16 => {
                        // ip6
                        let slice: [u8; 16] =
                            routing.nextHopAddr.as_ref()[0..16].try_into().unwrap();
                        let ipv6 = IpAddr::from(slice);
                        SocketAddr::new(ipv6, port)
                    }
                    _ => {
                        return Err(ProtocolError::InvalidRoutingInformation);
                    }
                },
                Err(_) => {
                    return Err(ProtocolError::InvalidRoutingInformation);
                }
            };

            // update codec
            let new_codec = Box::new(IntermediateHop::from(target_endpoint, addr));
            *codec_guard = new_codec;

            Ok(())
        }
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
                    HandshakeEvent::ClientHello(data) => self.action_recv_client_hello(data).await,
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
                                let _ = event_tx.send(FsmEvent::HandshakeResult(Ok(()))).await;
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
                    HandshakeEvent::EncryptedHandshakeData(data, iv) => {
                        match self.action_recv_routing(data, iv).await {
                            Ok(_) => {
                                let _ = event_tx.send(FsmEvent::HandshakeResult(Ok(()))).await;
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
