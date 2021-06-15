use crate::p2p_protocol::messages::p2p_messages::{ClientHello, RoutingInformation, ServerHello};
use crate::p2p_protocol::onion_tunnel::crypto::CryptoContext;
use crate::p2p_protocol::onion_tunnel::fsm::{FsmEvent, IsTargetEndpoint, ProtocolError};
use crate::p2p_protocol::onion_tunnel::message_codec::{
    DataType, IntermediateHopCodec, P2pCodec, TargetEndpoint,
};
use crate::p2p_protocol::onion_tunnel::FsmLockState;
use crate::p2p_protocol::TunnelId;
use bytes::Bytes;
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, Notify};
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
}

#[derive(Debug)]
pub enum HandshakeEvent {
    Init,
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    RoutingInformation(RoutingInformation),
}

pub struct HandshakeStateMachine<PT> {
    _phantom: PhantomData<PT>,
    message_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
    tunnel_id: TunnelId,
    next_hop: Option<SocketAddr>,
    fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
}

impl<PT: PeerType> HandshakeStateMachine<PT> {
    pub fn new(
        message_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
        tunnel_id: TunnelId,
        next_hop: Option<SocketAddr>,
        fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
    ) -> Self {
        Self {
            _phantom: Default::default(),
            message_codec,
            tunnel_id,
            next_hop,
            fsm_lock,
        }
    }

    pub async fn free_fsm_lock(&self) {
        let (lock, notifier) = &*self.fsm_lock;
        let mut state = lock.lock().await;
        if *state == FsmLockState::Processing {
            *state = FsmLockState::WaitForEvent;
        }
        notifier.notify_one();
    }

    pub async fn action_init(&mut self) -> Result<HandshakeState, ProtocolError> {
        // create client hello and give it to message codec
        let client_hello = ClientHello::new();
        // TODO fill client hello
        log::trace!(
            "Tunnel={:?}: Initialize handshake fsm: Send ClientHello=({:?}) via message codec",
            self.tunnel_id,
            client_hello
        );
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
        log::debug!(
            "Tunnel={:?}: Process incoming ClientHello=({:?})",
            self.tunnel_id,
            data
        );
        let mut codec = self.message_codec.lock().await;
        codec.set_backward_frame_id(data.backwardFrameId);

        // create server hello and give it to message_codec
        let server_hello = ServerHello::new();
        // TODO fill server_hello with information for secure key exchange

        // TODO crate cc with key and cipher
        let cc = CryptoContext::new();
        codec.add_crypto_context(cc);

        log::trace!(
            "Tunnel={:?}: Send ServerHello=({:?}) via message codec",
            self.tunnel_id,
            server_hello
        );
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
        log::debug!(
            "Tunnel={:?}: Process incoming ServerHello=({:?})",
            self.tunnel_id,
            data
        );

        // TODO create crypto context based on secure key exchange
        let cc = CryptoContext::new();

        codec.set_forward_frame_id(data.forwardFrameId);
        codec.set_backward_frame_id(data.backwardFrameId);
        codec.add_crypto_context(cc);

        // create routing information and give it to message_codec
        let mut data = RoutingInformation::new();
        match self.next_hop {
            None => {
                data.set_isEndpoint(true);
            }
            Some(addr) => {
                data.set_isEndpoint(false);
                data.set_nextHopPort(addr.port() as u32);
                match addr.ip() {
                    IpAddr::V4(ip) => {
                        data.set_nextHopAddr(Bytes::from(ip.octets().to_vec()));
                    }
                    IpAddr::V6(ip) => {
                        data.set_nextHopAddr(Bytes::from(ip.octets().to_vec()));
                    }
                };
            }
        }
        log::trace!(
            "Tunnel={:?}: Send RoutingInformation=({:?}) via message codec",
            self.tunnel_id,
            data
        );
        if let Err(e) = codec.write(DataType::RoutingInformation(data)).await {
            Err(e)
        } else {
            Ok(())
        }
    }

    pub async fn action_recv_routing(
        &mut self,
        routing: RoutingInformation,
    ) -> Result<IsTargetEndpoint, ProtocolError> {
        // get target endpoint
        log::debug!(
            "Tunnel={:?}: Process incoming RoutingInformation=({:?})",
            self.tunnel_id,
            routing
        );

        let mut codec_guard = self.message_codec.lock().await;
        let target_endpoint = match (*codec_guard).as_any().downcast_mut::<TargetEndpoint>() {
            None => {
                log::error!(
                    "Tunnel={:?}: Cannot parse message_codec to target endpoint",
                    self.tunnel_id
                );
                return Err(ProtocolError::CodecUpdateError);
            }
            Some(endpoint) => endpoint,
        };

        // check for routing
        if routing.isEndpoint {
            log::debug!(
                "Tunnel={:?}: No routing information provided, peer is the target endpoint",
                self.tunnel_id
            );
            target_endpoint.lock_as_target_endpoint().await;
            Ok(true)
        } else {
            // parse socket addr
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
            log::debug!(
                "Tunnel={:?}: Peer is intermediate hop, next_hop={:?}",
                self.tunnel_id,
                addr
            );
            let new_codec = Box::new(IntermediateHopCodec::from(target_endpoint, addr));
            *codec_guard = new_codec;

            Ok(false)
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

        log::trace!(
            "Tunnel={:?}: Run handshake FSM in INIT_STATE={:?}",
            self.tunnel_id,
            current_state
        );
        loop {
            let event_future = event_rx.recv();
            let event = match timeout(timeout_duration, event_future).await {
                Ok(res) => match res {
                    None => {
                        // closed by fsm
                        log::warn!(
                            "Tunnel={:?}: Handshake fsm closed by the main FSM",
                            self.tunnel_id
                        );
                        return;
                    }
                    Some(e) => e,
                },
                Err(_) => {
                    // timeout occurred
                    log::warn!(
                        "Tunnel={:?}: Send handshake_result=Err(timeout)",
                        self.tunnel_id
                    );
                    let _ = event_tx
                        .send(FsmEvent::HandshakeResult(Err(
                            ProtocolError::HandshakeTimeout,
                        )))
                        .await;
                    return;
                }
            };

            // handle event in current state
            log::trace!(
                "Tunnel={:?}: Received handshake_event={:?} in state={:?}",
                self.tunnel_id,
                event,
                current_state
            );
            let res = match current_state {
                HandshakeState::Start => match event {
                    HandshakeEvent::Init => self.action_init().await,

                    _ => {
                        log::warn!(
                            "Tunnel={:?}: Received unexpected event '{:?}' in Start state",
                            self.tunnel_id,
                            event
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                HandshakeState::WaitForClientHello => match event {
                    HandshakeEvent::ClientHello(data) => self.action_recv_client_hello(data).await,
                    _ => {
                        log::warn!(
                            "Tunnel={:?}: Received unexpected event '{:?}' in WaitForClientHello",
                            self.tunnel_id,
                            event
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                HandshakeState::WaitForServerHello => match event {
                    HandshakeEvent::ServerHello(data) => {
                        match self.action_recv_server_hello(data).await {
                            Ok(_) => {
                                log::trace!(
                                    "Tunnel={:?}: Send handshake_result=ok",
                                    self.tunnel_id
                                );
                                let _ = event_tx.send(FsmEvent::HandshakeResult(Ok(false))).await;
                                return;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => {
                        log::warn!(
                            "Tunnel={:?}: Received unexpected event '{:?}' in WaitForServerHello",
                            self.tunnel_id,
                            event
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },

                HandshakeState::WaitForRoutingInformation => match event {
                    HandshakeEvent::RoutingInformation(data) => {
                        match self.action_recv_routing(data).await {
                            Ok(is_target_endpoint) => {
                                log::trace!(
                                    "Tunnel={:?}: Send handshake_result=ok",
                                    self.tunnel_id
                                );
                                let _ = event_tx
                                    .send(FsmEvent::HandshakeResult(Ok(is_target_endpoint)))
                                    .await;
                                return;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => {
                        log::warn!(
                            "Tunnel={:?}: Received unexpected event '{:?}' in WaitForRoutingInformation",
                            self.tunnel_id,
                            event
                        );
                        Err(ProtocolError::UnexpectedMessageType)
                    }
                },
            };

            // handle result
            match res {
                Ok(new_state) => {
                    log::trace!(
                        "Tunnel={:?}: Switch to handshake state {:?}",
                        self.tunnel_id,
                        new_state
                    );
                    current_state = new_state;
                    self.free_fsm_lock().await;
                }
                Err(e) => {
                    log::warn!("Tunnel={:?}: Handshake failure: {:?}", self.tunnel_id, e);
                    let _ = event_tx.send(FsmEvent::HandshakeResult(Err(e))).await;
                    return;
                }
            }
        }
    }
}
