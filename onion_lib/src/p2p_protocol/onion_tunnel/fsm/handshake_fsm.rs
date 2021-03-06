use crate::p2p_protocol::messages::p2p_messages::{
    ClientHello, EncryptedServerHelloData, RoutingInformation,
    RoutingInformation_oneof_optional_challenge_response, ServerHello,
};
use crate::p2p_protocol::onion_tunnel::crypto::{
    CryptoContext, HandshakeCryptoConfig, HandshakeCryptoContext, AUTH_PLACEHOLDER, AUTH_SIZE,
};
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
use crate::p2p_protocol::onion_tunnel::fsm::{FsmEvent, IsTargetEndpoint, ProtocolError};
use crate::p2p_protocol::onion_tunnel::message_codec::{
    DataType, IntermediateHopCodec, P2pCodec, TargetEndpoint,
};
use crate::p2p_protocol::onion_tunnel::{FsmLockState, Peer};
use crate::p2p_protocol::{Direction, FrameId, TunnelId};
use bytes::Bytes;
use openssl::rsa::Rsa;
use protobuf::Message;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::time::timeout;

pub(super) struct Client {
    tunnel_update_ref: FrameId,
}
pub(super) struct Server;

pub trait PeerType {
    const INIT_STATE: HandshakeState;
    fn tunnel_update_reference(&self) -> FrameId;
}

impl PeerType for Client {
    const INIT_STATE: HandshakeState = HandshakeState::Start;

    fn tunnel_update_reference(&self) -> FrameId {
        self.tunnel_update_ref
    }
}

impl Client {
    pub fn new(tunnel_update_ref: FrameId) -> Client {
        Client { tunnel_update_ref }
    }
}

impl PeerType for Server {
    const INIT_STATE: HandshakeState = HandshakeState::WaitForClientHello;

    fn tunnel_update_reference(&self) -> FrameId {
        0
    }
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
    context: PT,
    message_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
    tunnel_id: TunnelId,
    current_hop: Option<Peer>,
    next_hop: Option<SocketAddr>,
    fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
    crypto_context: HandshakeCryptoContext,
    frame_id_manager: Arc<RwLock<FrameIdManager>>,
    cover_only: bool,
}

impl<PT: PeerType> HandshakeStateMachine<PT> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: PT,
        message_codec: Arc<Mutex<Box<dyn P2pCodec + Send>>>,
        tunnel_id: TunnelId,
        current_hop: Option<Peer>,
        next_hop: Option<SocketAddr>,
        fsm_lock: Arc<(Mutex<FsmLockState>, Notify)>,
        crypto_config: Arc<HandshakeCryptoConfig>,
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        cover_only: bool,
    ) -> Self {
        Self {
            context,
            message_codec,
            tunnel_id,
            current_hop,
            next_hop,
            fsm_lock,
            crypto_context: HandshakeCryptoContext::new(crypto_config),
            frame_id_manager,
            cover_only,
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
        // get public ECDHE parameter
        let initiator_pub_der = self.crypto_context.get_public_key();

        // create client hello and give it to message codec
        let mut client_hello = ClientHello::new();
        client_hello.set_ecdh_public_key(initiator_pub_der.into());

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
        log::debug!(
            "Tunnel={:?}: Process incoming ClientHello=({:?})",
            self.tunnel_id,
            data
        );

        // check if backward frame id valid
        FrameIdManager::verify_frame_id(data.backward_frame_id)?;

        // get public ECDHE parameter
        let receiver_pub_der = self.crypto_context.get_public_key();

        // calculate ECDHE shared secret
        let shared_secret = self.crypto_context.finish_ecdh(&data.ecdh_public_key)?;

        // Create crypto context based on secure key exchange
        let mut cc = CryptoContext::new(shared_secret, false);

        // calculate signature of handshake parameters
        let signature = self.crypto_context.hop_sign(&data.ecdh_public_key);

        // prepare secret server hello data
        let mut encrypted_data = EncryptedServerHelloData::new();
        encrypted_data.set_signature(signature.into());
        encrypted_data.set_forward_frame_id(
            self.frame_id_manager
                .write()
                .await
                .new_frame_id(self.tunnel_id, Direction::Forward),
        );
        encrypted_data.set_backward_frame_id(
            self.frame_id_manager
                .write()
                .await
                .new_frame_id(self.tunnel_id, Direction::Backward),
        );
        encrypted_data.set_challenge(self.crypto_context.get_challenge().to_owned().into());
        let mut raw_enc_data = vec![AUTH_PLACEHOLDER; AUTH_SIZE];
        raw_enc_data.append(&mut encrypted_data.write_to_bytes().unwrap());

        // encrypt signature for anonymity
        let (iv, enc_data) = cc.encrypt(None, &raw_enc_data, true)?;

        // store context at codec and set backward frame id on target endpoint
        let mut codec = self.message_codec.lock().await;
        codec.set_backward_frame_id(data.backward_frame_id);
        codec.add_crypto_context(cc);

        // create server hello and give it to message_codec
        let mut server_hello = ServerHello::new();
        server_hello.set_ecdh_public_key(receiver_pub_der.into());
        server_hello.set_iv(iv.into());
        server_hello.set_encrypted_data(enc_data.into());

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
        cover_only: bool,
    ) -> Result<(), ProtocolError> {
        log::debug!(
            "Tunnel={:?}: Process incoming ServerHello=({:?})",
            self.tunnel_id,
            data
        );

        // calculate ECDHE shared secret
        let shared_secret = self.crypto_context.finish_ecdh(&data.ecdh_public_key)?;

        // Create crypto context based on secure key exchange
        let mut cc = CryptoContext::new(shared_secret, true);

        // decrypt signature
        let (_, dec_data_raw) = cc.decrypt(&data.iv, &data.encrypted_data, true)?;
        let dec_data_raw = dec_data_raw[AUTH_SIZE..].to_vec();

        // parse dec_data into EncryptedServerHello
        let enc_server_hello_data = match EncryptedServerHelloData::parse_from_bytes(&dec_data_raw)
        {
            Ok(data) => {
                // valida frame ids
                FrameIdManager::verify_frame_id(data.backward_frame_id)?;
                FrameIdManager::verify_frame_id(data.forward_frame_id)?;
                // frame ids valid and available
                if self.next_hop.is_none() {
                    // frame ids for target, store the identifier for tunnel updates
                    self.frame_id_manager
                        .write()
                        .await
                        .add_tunnel_reference(self.tunnel_id, data.forward_frame_id);
                }
                data
            }
            Err(_) => {
                log::warn!(
                    "Tunnel={:?}: Cannot parse ServerHello encrypted data",
                    self.tunnel_id
                );
                return Err(ProtocolError::ProtobufError);
            }
        };

        // Get the public key of the hop. Safe unwrap, because initiator always has a current_hop
        let hop_public_key = Rsa::public_key_from_der(&self.current_hop.as_ref().unwrap().1)
            .map_err(|_| ProtocolError::HandshakeECDHFailure)?;

        // get the challenge from the encrypted_server_hello
        let challenge = enc_server_hello_data.challenge.to_vec();

        // verify the signature
        if !self.crypto_context.initiator_verify(
            hop_public_key,
            &enc_server_hello_data.signature,
            &data.ecdh_public_key,
            challenge.as_ref(),
        ) {
            // Invalid signature
            log::warn!(
                "Tunnel={:?}: Received invalid ECDH signature",
                self.tunnel_id
            );
            return Err(ProtocolError::HandshakeECDHFailure);
        }

        // update codec
        let mut codec = self.message_codec.lock().await;
        codec
            .process_forward_frame_id(enc_server_hello_data.forward_frame_id)
            .await?;
        codec.set_backward_frame_id(enc_server_hello_data.backward_frame_id);
        codec.add_crypto_context(cc);

        // create routing information and give it to message_codec
        let mut data = RoutingInformation::new();
        match self.next_hop {
            None => {
                data.set_is_endpoint(true);
                data.set_cover_only(cover_only);
                data.set_tunnel_update_reference(self.context.tunnel_update_reference());

                // Sign the challenge for the target peer
                let challenge_response = self.crypto_context.sign(&challenge);
                data.set_challenge_response(challenge_response.into());
            }
            Some(addr) => {
                data.set_is_endpoint(false);
                data.set_next_hop_port(addr.port() as u32);
                match addr.ip() {
                    IpAddr::V4(ip) => {
                        data.set_next_hop_addr(Bytes::from(ip.octets().to_vec()));
                    }
                    IpAddr::V6(ip) => {
                        data.set_next_hop_addr(Bytes::from(ip.octets().to_vec()));
                    }
                };
            }
        }
        log::trace!(
            "Tunnel={:?}: Send RoutingInformation=({:?}) via message codec",
            self.tunnel_id,
            data
        );
        codec.write(DataType::RoutingInformation(data)).await
    }

    pub async fn action_recv_routing(
        &mut self,
        routing: RoutingInformation,
    ) -> Result<(IsTargetEndpoint, bool, FrameId), ProtocolError> {
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
        if routing.is_endpoint {
            log::debug!(
                "Tunnel={:?}: No routing information provided, peer is the target endpoint",
                self.tunnel_id
            );

            if let Some(RoutingInformation_oneof_optional_challenge_response::challenge_response(
                _challenge_response,
            )) = routing.optional_challenge_response
            {
                // Future work: Authenticate initiator identity by transferring and verifying with PKI the initiator_public_rsa_key
                /*if !self.crypto_context.verify(
                    initiator_public_rsa_key,
                    &challenge_response,
                    self.crypto_context.get_challenge(),
                ) {
                    log::warn!(
                        "Tunnel={:?}: Invalid challenge response signature",
                        self.tunnel_id
                    );
                    return Err(ProtocolError::InvalidChallengeResponse);
                }*/
            } else {
                log::warn!(
                    "Tunnel={:?}: Missing challenge response for target endpoint",
                    self.tunnel_id
                );
                return Err(ProtocolError::InvalidChallengeResponse);
            }

            target_endpoint.lock_as_target_endpoint().await;
            Ok((true, routing.cover_only, routing.tunnel_update_reference))
        } else {
            // parse socket addr
            let addr = match u16::try_from(routing.next_hop_port) {
                Ok(port) => match routing.next_hop_addr.len() {
                    4 => {
                        // ipv4
                        let slice: [u8; 4] =
                            routing.next_hop_addr.as_ref()[0..4].try_into().unwrap();
                        let ipv4 = IpAddr::from(slice);
                        SocketAddr::new(ipv4, port)
                    }
                    16 => {
                        // ip6
                        let slice: [u8; 16] =
                            routing.next_hop_addr.as_ref()[0..16].try_into().unwrap();
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

            Ok((false, false, 0))
        }
    }

    pub async fn run(
        &mut self,
        mut event_rx: Receiver<HandshakeEvent>,
        event_tx: Sender<FsmEvent>,
        timeout_duration: Duration,
    ) {
        let mut current_state = PT::INIT_STATE;

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
                        match self.action_recv_server_hello(data, self.cover_only).await {
                            Ok(_) => {
                                log::trace!(
                                    "Tunnel={:?}: Send handshake_result=ok",
                                    self.tunnel_id
                                );
                                let _ = event_tx
                                    .send(FsmEvent::HandshakeResult(Ok((
                                        false,
                                        self.cover_only,
                                        None,
                                    ))))
                                    .await;
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
                            Ok((is_target_endpoint, is_cover_only, tunnel_update_ref)) => {
                                log::trace!(
                                    "Tunnel={:?}: Send handshake_result=ok",
                                    self.tunnel_id
                                );
                                let tunnel_update_ref = if tunnel_update_ref == 0 {
                                    None
                                } else {
                                    Some(tunnel_update_ref)
                                };
                                let _ = event_tx
                                    .send(FsmEvent::HandshakeResult(Ok((
                                        is_target_endpoint,
                                        is_cover_only,
                                        tunnel_update_ref,
                                    ))))
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
