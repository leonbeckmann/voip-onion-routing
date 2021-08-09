use std::{net::SocketAddr, sync::Arc};

use crate::p2p_protocol::messages::p2p_messages::{
    ApplicationData, ClientHello, HandshakeData, RoutingInformation, ServerHello, TunnelFrame,
};
use crate::p2p_protocol::onion_tunnel::crypto::{CryptoContext, AUTH_PLACEHOLDER, IV_SIZE};
use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
use crate::p2p_protocol::{Direction, FrameId, TunnelId};
use async_trait::async_trait;
use bytes::Bytes;
use protobuf::Message;
use std::any::Any;
use std::collections::HashSet;
use std::mem::size_of;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use super::crypto::AUTH_SIZE;
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;

const PADDING_LEN_SIZE: usize = size_of::<u16>();
const MSG_TYPE_SIZE: usize = size_of::<u8>();
const SEQ_NR_SIZE: usize = size_of::<u32>();

const CLOSE_MAGIC_NUMBER: &[u8] = "CLOSE_MAGIC_NUMBER".as_bytes();

const PAYLOAD_SIZE: usize = 1024;
const RAW_META_DATA_SIZE: usize = AUTH_SIZE + PADDING_LEN_SIZE + MSG_TYPE_SIZE;
const PROTOBUF_APP_META_LEN: usize = 17; // buffer for protobuf meta information
                                         // maximum of data within a single packet
const EFFECTIVE_PACKET_SIZE: usize =
    PAYLOAD_SIZE - RAW_META_DATA_SIZE - PROTOBUF_APP_META_LEN - SEQ_NR_SIZE;

pub enum ProcessedData {
    TransferredToNextHop,
    HandshakeData(HandshakeData),
    IncomingData(Vec<u8>),
    ReceivedClose,
}

pub enum DataType {
    Close(bool),
    AppData(Vec<u8>),
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    RoutingInformation(RoutingInformation),
}

struct RawData {
    padding_len: u16,
    message_type: u8,
    data: Vec<u8>,
    padding: Vec<u8>,
}

const APP_DATA: u8 = 1;
const HANDSHAKE_DATA: u8 = 2;
const CLOSE: u8 = 3;

impl RawData {
    fn new(len: u16, message_type: u8, data: Vec<u8>) -> Self {
        let data_len = (data.len() + RAW_META_DATA_SIZE) as u16;
        assert!(len >= data_len);
        let padding_len = len - data_len;
        Self {
            padding_len,
            message_type,
            data,
            padding: (0..padding_len).map(|_| rand::random::<u8>()).collect(),
        }
    }

    fn deserialize(raw: &[u8], tunnel_id: TunnelId) -> Result<Self, ProtocolError> {
        if raw.len() != PAYLOAD_SIZE {
            log::warn!(
                "Tunnel={:?}: Received packet with invalid payload size. Disconnect",
                tunnel_id
            );
            return Err(ProtocolError::InvalidPacketLength);
        }

        let (auth_tag, raw) = raw.split_at(AUTH_SIZE);
        if auth_tag != vec![AUTH_PLACEHOLDER; AUTH_SIZE] {
            return Ok(RawData {
                padding_len: 1,
                message_type: 2,
                data: vec![],
                padding: vec![],
            });
        }
        debug_assert_eq!(auth_tag, vec![AUTH_PLACEHOLDER; AUTH_SIZE]);
        // we have padding_size, so we are safe here
        let (padding_size_buf, remainder) = raw.split_at(size_of::<u16>());
        let (message_type_buf, data_buf) = remainder.split_at(size_of::<u8>());
        let mut padding_size = [0u8; size_of::<u16>()];
        padding_size.copy_from_slice(padding_size_buf);
        let padding_len = u16::from_le_bytes(padding_size);
        let message_type = message_type_buf[0];
        if message_type != APP_DATA && message_type != HANDSHAKE_DATA && message_type != CLOSE {
            log::warn!(
                "Tunnel={:?}: Invalid message type: {}",
                tunnel_id,
                message_type
            );
            return Err(ProtocolError::UnexpectedMessageType);
        }
        let data_len = (PAYLOAD_SIZE - RAW_META_DATA_SIZE) as u16 - padding_len;
        let (data, _padding) = data_buf.split_at(data_len as usize);
        Ok(RawData {
            padding_len,
            message_type,
            data: data.to_vec(),
            padding: vec![], // not required
        })
    }

    fn serialize(&mut self) -> Vec<u8> {
        let mut buf = vec![];
        let mut len = self.padding_len.to_le_bytes().to_vec();
        buf.append(&mut vec![AUTH_PLACEHOLDER; AUTH_SIZE]);
        buf.append(&mut len);
        buf.push(self.message_type);
        buf.append(&mut self.data);
        buf.append(&mut self.padding);
        assert_eq!(buf.len(), PAYLOAD_SIZE);
        buf
    }
}

type IV = Bytes;

#[derive(Debug, Clone)]
struct SequenceNumberContext {
    outgoing: u32,
    newest_received: u32,
    used_seq_nrs: HashSet<u32>,
}

impl SequenceNumberContext {
    fn new() -> Self {
        Self {
            outgoing: 0,
            newest_received: 0,
            used_seq_nrs: HashSet::new(),
        }
    }

    fn get_next_seq_nr(&mut self) -> u32 {
        self.outgoing += 1;
        self.outgoing
    }

    fn verify_incoming_seq_nr(&mut self, seq_nr: u32) -> Result<(), ProtocolError> {
        // reject packets that are too old, window is 20 sequence numbers in the past
        if self.newest_received >= 20 && self.newest_received - 20 > seq_nr {
            return Err(ProtocolError::ExpiredSequenceNumber);
        }

        // reject packets with reused sequence number
        if !self.used_seq_nrs.insert(seq_nr) {
            return Err(ProtocolError::ReusedSequenceNumber);
        }

        // update newest received
        if self.newest_received < seq_nr {
            self.newest_received = seq_nr;
        }

        Ok(())
    }
}

/**
 *  P2pCodec responsible for encryption, message padding and writing messages to the socket
 */

#[async_trait]
pub trait P2pCodec {
    /*
     *  Send data to the previous peer (for endpoints, previous == next)
     *  Used for sending handshake data to or back from hops or sending application data from endpoints
     */
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError>;

    /*
     *  Process incoming encrypted data.
     *
     *  If self is an intermediate hop, the data are processed and transferred to the next hop after
     * checked for magic close number.
     *  If self is an endpoint, the data are returned as IncomingData if no endpoint
     */
    async fn process_data(
        &mut self,
        d: Direction,
        data: Bytes,
        iv: IV,
    ) -> Result<ProcessedData, ProtocolError>;

    /*
     *  Tunnel close, send close messages
     */
    async fn close(&mut self, without_last_peer: bool);

    /*
     *  Get the implementation of the trait for updating codecs
     */
    fn as_any(&mut self) -> &mut dyn Any;

    /*
     *  Set the frame_id for forwarding packets
     */
    fn set_forward_frame_id(&mut self, _id: FrameId) {
        log::warn!("Setting forward frame_id not supported for this codec");
    }

    /*
     *  Set the frame_id for backward packets
     */
    fn set_backward_frame_id(&mut self, _id: FrameId) {
        log::warn!("Setting backward frame_id not supported for this codec");
    }

    /*
     *  This method adds a crypto_context to the codec. It is not supported for the intermediate
     *  hops impl, which inherits the context from the target_endpoint impl.
     *
     *  In case of the target_endpoint, only one crypto_context can be set, all others calls will be
     *  ignored. In case of the initiator_endpoint, a list of crypto_contexts is provided, one
     *  context per each hop inclusive the target.
     */
    fn add_crypto_context(&mut self, _cc: CryptoContext) {
        log::warn!("Adding crypto context not supported for this codec");
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InitiatorEndpoint {
    socket: Arc<UdpSocket>,
    next_hop: SocketAddr,
    frame_id_manager: Arc<RwLock<FrameIdManager>>,
    tunnel_id: TunnelId,
    forward_frame_id: FrameId, // frame id for forward packages
    next_hop_backward_frame_id: Option<FrameId>,
    crypto_contexts: Vec<CryptoContext>,
    seq_nr_context: SequenceNumberContext,
}

impl InitiatorEndpoint {
    pub fn new(
        socket: Arc<UdpSocket>,
        next_hop: SocketAddr,
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        tunnel_id: TunnelId,
    ) -> Self {
        Self {
            socket,
            next_hop,
            frame_id_manager,
            tunnel_id,
            forward_frame_id: 1,              // initialized for init client hello
            next_hop_backward_frame_id: None, // used for client hellos to next hops
            crypto_contexts: vec![],
            seq_nr_context: SequenceNumberContext::new(),
        }
    }

    /*
     * Used during initiator closing procedure to destruct tunnel
     */
    fn remove_crypto_context(&mut self) {
        if !self.crypto_contexts.is_empty() {
            let _ = self.crypto_contexts.remove(self.crypto_contexts.len() - 1);
        }
    }
}

pub(crate) struct TargetEndpoint {
    socket: Arc<UdpSocket>,
    prev_hop: SocketAddr,
    frame_id_manager: Arc<RwLock<FrameIdManager>>,
    tunnel_id: TunnelId,
    backward_frame_id: FrameId, // frame id for backward packages
    crypto_context: Option<CryptoContext>,
    seq_nr_context: SequenceNumberContext,
}

impl TargetEndpoint {
    pub fn new(
        socket: Arc<UdpSocket>,
        prev_hop: SocketAddr,
        frame_id_manager: Arc<RwLock<FrameIdManager>>,
        tunnel_id: TunnelId,
    ) -> Self {
        Self {
            socket,
            prev_hop,
            frame_id_manager,
            tunnel_id,
            backward_frame_id: 0,
            crypto_context: None,
            seq_nr_context: SequenceNumberContext::new(),
        }
    }

    pub async fn lock_as_target_endpoint(&mut self) {
        // this endpoint is the target and will not be transferred to an intermediate_hop
        log::trace!("Tunnel={:?}: Lock target hop", self.tunnel_id);
        // remove all backward frame ids, which are not used for target tunnels
        self.frame_id_manager
            .write()
            .await
            .remove_backward_frame_ids(self.tunnel_id);
    }
}

pub(crate) struct IntermediateHopCodec {
    socket: Arc<UdpSocket>,
    next_hop: SocketAddr,
    prev_hop: SocketAddr,
    _frame_id_manager: Arc<RwLock<FrameIdManager>>,
    tunnel_id: TunnelId,
    forward_frame_id: FrameId,  // frame id for forward packages
    backward_frame_id: FrameId, // frame id for backward packages
    crypto_context: CryptoContext,
}

// make target to intermediate
impl IntermediateHopCodec {
    pub fn from(target: &mut TargetEndpoint, next_hop: SocketAddr) -> Self {
        Self {
            socket: target.socket.clone(),
            next_hop,
            prev_hop: target.prev_hop,
            _frame_id_manager: target.frame_id_manager.clone(),
            tunnel_id: target.tunnel_id,
            forward_frame_id: 1,
            backward_frame_id: target.backward_frame_id,
            crypto_context: target.crypto_context.take().unwrap(),
        }
    }
}

#[async_trait]
impl P2pCodec for InitiatorEndpoint {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        let mut frame = TunnelFrame::new();
        frame.set_frame_id(self.forward_frame_id);

        let iv_data_chunks = match data {
            DataType::Close(to_endpoint) => {
                // send close similar as app_data without fragmentation and with magic number if hop
                let mut raw_data = if to_endpoint {
                    RawData::new(PAYLOAD_SIZE as u16, CLOSE, vec![]).serialize()
                } else {
                    let mut data = CLOSE_MAGIC_NUMBER.to_vec();
                    data.append(
                        &mut (0..(PAYLOAD_SIZE - CLOSE_MAGIC_NUMBER.len()))
                            .map(|_| rand::random::<u8>())
                            .collect(),
                    );
                    data
                };

                // layered encryption via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &raw_data, i == 0)?;
                    iv = Some(iv_);
                    raw_data = data_;
                }
                assert_eq!(raw_data.len(), PAYLOAD_SIZE);
                vec![(iv, raw_data)]
            }
            DataType::AppData(data) => {
                // fragmentation
                let mut chunks = vec![];
                for data_chunk in data.chunks(EFFECTIVE_PACKET_SIZE) {
                    let mut app_data = ApplicationData::new();
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_data(Bytes::copy_from_slice(data_chunk));
                    let raw_data = app_data.write_to_bytes().unwrap();
                    let mut raw_data =
                        RawData::new(PAYLOAD_SIZE as u16, APP_DATA, raw_data).serialize();

                    // Unencrypted data transfer is not allowed
                    assert!(!self.crypto_contexts.is_empty());

                    // layered encryption via iv and keys using the crypto contexts
                    let mut iv: Option<Vec<u8>> = None;
                    for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                        let (iv_, data_) = cc.encrypt(iv.as_deref(), &raw_data, i == 0)?;
                        iv = Some(iv_);
                        raw_data = data_;
                    }
                    assert_eq!(raw_data.len(), PAYLOAD_SIZE);
                    chunks.push((iv, raw_data));
                }

                log::debug!(
                    "Tunnel={:?}: Send encrypted application data ({:?} fragment(s)) to next hop {:?}.",
                    self.tunnel_id,
                    chunks.len(),
                    self.next_hop
                );

                chunks
            }
            DataType::ClientHello(mut client_hello) => {
                // calculate frame_id
                let id = match self.next_hop_backward_frame_id {
                    None => {
                        // this handshake is to the direct successor, we have to provide our own backward id
                        self.frame_id_manager
                            .write()
                            .await
                            .new_frame_id(self.tunnel_id, Direction::Backward)
                    }
                    Some(id) => {
                        // this handshake is not to the direct successor, provide backward id of other hop
                        id
                    }
                };
                client_hello.set_backward_frame_id(id);
                log::debug!(
                    "Tunnel={:?}: Send ClientHello={:?} to next hop {:?}",
                    self.tunnel_id,
                    client_hello,
                    self.next_hop
                );

                // prepare frame
                let mut handshake = HandshakeData::new();
                handshake.set_client_hello(client_hello);
                let data = handshake.write_to_bytes().unwrap();
                let mut data = RawData::new(PAYLOAD_SIZE as u16, HANDSHAKE_DATA, data).serialize();

                // encrypt via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &data, i == 0)?;
                    iv = Some(iv_);
                    data = data_;
                }
                assert_eq!(data.len(), PAYLOAD_SIZE);
                vec![(iv, data)]
            }
            DataType::RoutingInformation(data) => {
                log::debug!(
                    "Tunnel={:?}: Send RoutingInformation={:?} to next hop {:?}",
                    self.tunnel_id,
                    data,
                    self.next_hop
                );
                let mut handshake = HandshakeData::new();
                handshake.set_routing(data);
                let data = handshake.write_to_bytes().unwrap();
                let mut data = RawData::new(PAYLOAD_SIZE as u16, HANDSHAKE_DATA, data).serialize();

                // encrypt via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &data, i == 0)?;
                    iv = Some(iv_);
                    data = data_;
                }
                assert_eq!(data.len(), PAYLOAD_SIZE);
                vec![(iv, data)]
            }
            _ => {
                log::warn!(
                    "Tunnel={:?}: Invalid write action in initiator codec",
                    self.tunnel_id
                );
                return Err(ProtocolError::CodecUnsupportedAction);
            }
        };

        // write fragmented frames
        for (iv, data) in iv_data_chunks {
            // Lazily evaluated else only create vec when needed
            let iv = iv.unwrap_or_else(|| vec![0; IV_SIZE]);
            frame.set_iv(iv.into());
            frame.set_data(data.into());
            let data = frame.write_to_bytes().unwrap();

            // write to stream
            if let Err(e) = self.socket.send_to(data.as_ref(), self.next_hop).await {
                return Err(ProtocolError::IOError(format!(
                    "Cannot write frame via initiator codec: {:?}",
                    e
                )));
            }
        }

        Ok(())
    }

    async fn process_data(
        &mut self,
        _d: Direction,
        data: Bytes,
        iv: IV,
    ) -> Result<ProcessedData, ProtocolError> {
        // expected incoming data or incoming handshake, process and return
        let mut iv = iv.to_vec();

        log::trace!(
            "Tunnel={:?}: Process incoming data at initiator hop",
            self.tunnel_id
        );
        // decrypt from next hop to target using iv and cc
        let mut dec_data = data.to_vec();
        if !self.crypto_contexts.is_empty() {
            log::trace!("Tunnel={:?}: Decrypt incoming data", self.tunnel_id);
            for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate().rev() {
                let (iv_, data_) = cc.decrypt(&iv, &dec_data, i == 0)?;
                iv = iv_;
                dec_data = data_;
            }
        }

        // deserialize data
        let raw_data = RawData::deserialize(dec_data.as_ref(), self.tunnel_id)?;
        match raw_data.message_type {
            APP_DATA => match ApplicationData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => {
                    log::trace!(
                        "Tunnel={:?}: Initiator receives application data with sequence_number={:?}",
                        self.tunnel_id,
                        data.sequence_number
                    );
                    return match self
                        .seq_nr_context
                        .verify_incoming_seq_nr(data.sequence_number)
                    {
                        Ok(_) => Ok(ProcessedData::IncomingData(data.data.to_vec())),
                        Err(e) => Err(e),
                    };
                }
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            HANDSHAKE_DATA => match HandshakeData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => {
                    log::trace!(
                        "Tunnel={:?}: Initiator receives handshake data",
                        self.tunnel_id
                    );
                    Ok(ProcessedData::HandshakeData(data))
                }
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            CLOSE => {
                // initiator received close, deconstruct tunnel
                log::trace!("Tunnel={:?}: Initiator receives close", self.tunnel_id);
                self.close(true).await;
                Ok(ProcessedData::ReceivedClose)
            }
            _ => return Err(ProtocolError::UnexpectedMessageType),
        }
    }

    async fn close(&mut self, without_last_peer: bool) {
        // iteratively deconstruct tunnel, starting by the endpoint
        log::debug!("Tunnel={:?}: At initiator send close", self.tunnel_id,);

        if !without_last_peer {
            // send close to target endpoint
            let _ = self.write(DataType::Close(true)).await;
        }

        // remove last endpoint cc if available
        self.remove_crypto_context();
        let i = self.crypto_contexts.len();

        // send close to intermediate hops
        for _ in 0..i {
            // FIXME test terminates too early, this is not executed completely
            let _ = self.write(DataType::Close(false)).await;
            self.remove_crypto_context();
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn set_forward_frame_id(&mut self, id: FrameId) {
        // only update if this is still one, otherwise this client_hello is not from the
        // directly followed hop and the forward_frame_id has already been caught from the
        // correct intermediate hop
        if self.forward_frame_id == 1 {
            self.forward_frame_id = id;
        }
    }

    fn set_backward_frame_id(&mut self, id: FrameId) {
        self.next_hop_backward_frame_id = Some(id);
    }

    fn add_crypto_context(&mut self, cc: CryptoContext) {
        log::trace!(
            "Tunnel={:?}: Add crypto context to initiator codec",
            self.tunnel_id
        );
        self.crypto_contexts.push(cc)
    }
}

#[async_trait]
impl P2pCodec for TargetEndpoint {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        let mut frame = TunnelFrame::new();
        frame.set_frame_id(self.backward_frame_id);

        let iv_data_bytes = match data {
            DataType::Close(_) => {
                // send close to initiator endpoint similar to appData
                let raw_data = RawData::new(PAYLOAD_SIZE as u16, CLOSE, vec![]).serialize();
                // encrypt via iv and key
                assert!(self.crypto_context.is_some());
                let (iv, raw_data) = self
                    .crypto_context
                    .as_mut()
                    .unwrap()
                    .encrypt(None, &raw_data, true)?;
                assert_eq!(raw_data.len(), PAYLOAD_SIZE);
                log::debug!(
                    "Tunnel={:?}: Send encrypted close to prev hop {:?}",
                    self.tunnel_id,
                    self.prev_hop
                );
                vec![(iv, raw_data)]
            }
            DataType::AppData(data) => {
                // fragmentation
                let mut chunks = vec![];
                for data_chunk in data.chunks(EFFECTIVE_PACKET_SIZE) {
                    let mut app_data = ApplicationData::new();
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_data(Bytes::copy_from_slice(data_chunk));
                    let raw_data = app_data.write_to_bytes().unwrap();
                    let raw_data =
                        RawData::new(PAYLOAD_SIZE as u16, APP_DATA, raw_data).serialize();
                    // encrypt via iv and key
                    // Unecrypted data transfer is not allowed
                    assert!(self.crypto_context.is_some());
                    let (iv, raw_data) = self
                        .crypto_context
                        .as_mut()
                        .unwrap()
                        .encrypt(None, &raw_data, true)?;

                    assert_eq!(raw_data.len(), PAYLOAD_SIZE);
                    chunks.push((iv, raw_data));
                }
                log::debug!(
                    "Tunnel={:?}: Send encrypted application data ({:?} fragment(s)) to prev hop {:?}",
                    self.tunnel_id,
                    chunks.len(),
                    self.prev_hop
                );
                chunks
            }
            DataType::ServerHello(mut server_hello) => {
                // calculate frame_ids
                let new_forward_id = self
                    .frame_id_manager
                    .write()
                    .await
                    .new_frame_id(self.tunnel_id, Direction::Forward);
                let new_backward_id = self
                    .frame_id_manager
                    .write()
                    .await
                    .new_frame_id(self.tunnel_id, Direction::Backward);
                server_hello.set_forward_frame_id(new_forward_id);
                server_hello.set_backward_frame_id(new_backward_id);

                log::debug!(
                    "Tunnel={:?}: Send ServerHello=({:?}) to/via prev hop {:?}",
                    self.tunnel_id,
                    server_hello,
                    self.prev_hop
                );

                // prepare frame
                let mut iv = vec![0; IV_SIZE];
                openssl::rand::rand_bytes(&mut iv).expect("Failed to generated random IV");
                let mut handshake = HandshakeData::new();
                handshake.set_server_hello(server_hello);
                let data = handshake.write_to_bytes().unwrap();
                let raw_data = RawData::new(PAYLOAD_SIZE as u16, HANDSHAKE_DATA, data).serialize();
                assert_eq!(raw_data.len(), PAYLOAD_SIZE);
                vec![(iv, raw_data)]
            }
            _ => {
                log::warn!(
                    "Tunnel={:?}: Invalid write action in target codec",
                    self.tunnel_id
                );
                return Err(ProtocolError::CodecUnsupportedAction);
            }
        };

        for (iv, data) in iv_data_bytes {
            frame.set_iv(iv.into());
            frame.set_data(data.into());
            let data = frame.write_to_bytes().unwrap();

            // write to stream
            if let Err(e) = self.socket.send_to(data.as_ref(), self.prev_hop).await {
                return Err(ProtocolError::IOError(format!(
                    "Cannot write frame via target codec: {:?}",
                    e
                )));
            }
        }

        Ok(())
    }

    async fn process_data(
        &mut self,
        _d: Direction,
        data: Bytes,
        iv: IV,
    ) -> Result<ProcessedData, ProtocolError> {
        // expect incoming data, handshake or encrypted handshake, process and return
        log::trace!(
            "Tunnel={:?}: Process incoming data at target hop",
            self.tunnel_id
        );

        // if the crypto_context has already been set, we expect encrypted data
        let mut data = data.to_vec();
        if let Some(cc) = &mut self.crypto_context {
            // decrypt using keys and iv
            log::trace!("Tunnel={:?}: Decrypt incoming data", self.tunnel_id);
            let (_iv, data_) = cc.decrypt(&iv, &data, true)?;
            data = data_;
        }

        let raw_data = RawData::deserialize(data.as_ref(), self.tunnel_id)?;
        match raw_data.message_type {
            APP_DATA => match ApplicationData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => {
                    log::trace!(
                        "Tunnel={:?}: Target receives application data with sequence_number={:?}",
                        self.tunnel_id,
                        data.sequence_number
                    );
                    return match self
                        .seq_nr_context
                        .verify_incoming_seq_nr(data.sequence_number)
                    {
                        Ok(_) => Ok(ProcessedData::IncomingData(data.data.to_vec())),
                        Err(e) => Err(e),
                    };
                }
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            HANDSHAKE_DATA => match HandshakeData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => {
                    log::trace!(
                        "Tunnel={:?}: Target receives handshake data",
                        self.tunnel_id
                    );
                    Ok(ProcessedData::HandshakeData(data))
                }
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            CLOSE => {
                log::trace!("Tunnel={:?}: Target receives close", self.tunnel_id);
                Ok(ProcessedData::ReceivedClose)
            }
            _ => return Err(ProtocolError::UnexpectedMessageType),
        }
    }

    async fn close(&mut self, _: bool) {
        log::info!("Tunnel={:?}: Send close at target endpoint", self.tunnel_id,);
        let _ = self.write(DataType::Close(true)).await;
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn set_backward_frame_id(&mut self, id: FrameId) {
        self.backward_frame_id = id;
    }

    fn add_crypto_context(&mut self, cc: CryptoContext) {
        if self.crypto_context.is_none() {
            log::trace!(
                "Tunnel={:?}: Set the crypto context of this target codec",
                self.tunnel_id
            );
            self.crypto_context = Some(cc);
        } else {
            log::warn!(
                "Tunnel={:?}: Crypto context of this target codec already set",
                self.tunnel_id
            );
        }
    }
}

#[async_trait]
impl P2pCodec for IntermediateHopCodec {
    async fn write(&mut self, _data: DataType) -> Result<(), ProtocolError> {
        log::warn!("Write action not supported for intermediate hop codec");
        return Err(ProtocolError::CodecUnsupportedAction);
    }

    async fn process_data(
        &mut self,
        d: Direction,
        data: Bytes,
        iv: IV,
    ) -> Result<ProcessedData, ProtocolError> {
        let start_to_end = self.forward_frame_id == 1;

        log::trace!(
            "Tunnel={:?}: Process incoming data at intermediate hop",
            self.tunnel_id
        );
        if data.len() != PAYLOAD_SIZE {
            // disconnect immediately due to size error
            log::warn!(
                "Tunnel={:?}: Received packet with invalid payload size. Disconnect",
                self.tunnel_id
            );
            return Err(ProtocolError::InvalidPacketLength);
        }

        if d == Direction::Backward && self.forward_frame_id == 1 {
            // seems to be the unencrypted server_hello for the next hop, catch the forward id
            log::trace!("Tunnel={:?}: Received data containing the ServerHello from the next hop, extract forward ID", self.tunnel_id);
            let raw_data = RawData::deserialize(data.as_ref(), self.tunnel_id)?;
            if raw_data.message_type != HANDSHAKE_DATA {
                return Err(ProtocolError::UnexpectedMessageType);
            }
            match HandshakeData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => {
                    if !data.has_server_hello() {
                        return Err(ProtocolError::UnexpectedMessageType);
                    }
                    let id = data.get_server_hello().get_forward_frame_id();
                    self.forward_frame_id = id;
                }
                Err(_) => {
                    return Err(ProtocolError::ProtobufError);
                }
            }
        }

        // expect incoming data backward or forward, apply encryption or decryption and delegate to next hop
        let mut frame = TunnelFrame::new();
        let (frame, addr) = match d {
            Direction::Forward => {
                log::debug!("Tunnel={:?}: Hop receives a forward message, decrypt the payload and pass it to the next hop {:?}", self.tunnel_id, self.next_hop);
                // decrypt using iv and key
                let (iv, decrypted_data) = self.crypto_context.decrypt(&iv, &data, start_to_end)?;
                // check for magic number for closing a hop
                if &decrypted_data[0..CLOSE_MAGIC_NUMBER.len()] == CLOSE_MAGIC_NUMBER {
                    log::trace!(
                        "Tunnel={:?}: Hop found magic close number in packet",
                        self.tunnel_id
                    );
                    return Ok(ProcessedData::ReceivedClose);
                }
                frame.set_frame_id(self.forward_frame_id);
                frame.set_iv(iv.into());
                frame.set_data(decrypted_data.into());
                (frame, self.next_hop)
            }
            Direction::Backward => {
                // encrypt using iv and key
                log::debug!("Tunnel={:?}: Hop receives a backward message, encrypt the payload and pass it to the prev hop {:?}", self.tunnel_id, self.prev_hop);
                let (iv, encrypted_data) =
                    self.crypto_context
                        .encrypt(Some(&iv), &data, start_to_end)?;
                frame.set_frame_id(self.backward_frame_id);
                frame.set_iv(iv.into());
                frame.set_data(encrypted_data.into());
                (frame, self.prev_hop)
            }
        };

        let data = frame.write_to_bytes().unwrap();

        // write to stream
        if let Err(e) = self.socket.send_to(data.as_ref(), addr).await {
            return Err(ProtocolError::IOError(format!(
                "Cannot write frame via intermediate codec: {:?}",
                e
            )));
        }

        Ok(ProcessedData::TransferredToNextHop)
    }

    async fn close(&mut self, _: bool) {
        log::warn!("Close action not supported for intermediate hop codec");
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
    use crate::p2p_protocol::onion_tunnel::message_codec::SequenceNumberContext;

    #[test]
    fn unit_test_sequence_number() {
        let mut context = SequenceNumberContext::new();

        // outgoing
        assert_eq!(context.get_next_seq_nr(), 1);
        assert_eq!(context.get_next_seq_nr(), 2);
        assert_eq!(context.get_next_seq_nr(), 3);
        for _ in 0..10 {
            context.get_next_seq_nr();
        }
        assert_eq!(context.get_next_seq_nr(), 14);
        assert_eq!(context.get_next_seq_nr(), 15);
        assert_eq!(context.get_next_seq_nr(), 16);

        // incoming
        assert_eq!(context.verify_incoming_seq_nr(2), Ok(()));
        assert_eq!(
            context.verify_incoming_seq_nr(2),
            Err(ProtocolError::ReusedSequenceNumber)
        );
        assert_eq!(context.verify_incoming_seq_nr(1), Ok(()));
        assert_eq!(context.verify_incoming_seq_nr(7), Ok(()));
        assert_eq!(context.verify_incoming_seq_nr(20), Ok(()));
        assert_eq!(
            context.verify_incoming_seq_nr(20),
            Err(ProtocolError::ReusedSequenceNumber)
        );
        assert_eq!(context.verify_incoming_seq_nr(30), Ok(()));
        assert_eq!(
            context.verify_incoming_seq_nr(4),
            Err(ProtocolError::ExpiredSequenceNumber)
        );
        assert_eq!(context.verify_incoming_seq_nr(17), Ok(()));
    }
}
