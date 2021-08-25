use std::{net::SocketAddr, sync::Arc};

use crate::p2p_protocol::messages::p2p_messages::{
    ApplicationData, ApplicationData_oneof_message, ClientHello, CoverTraffic, HandshakeData,
    RoutingInformation, ServerHello, TunnelFrame,
};
use crate::p2p_protocol::onion_tunnel::crypto::{CryptoContext, AUTH_PLACEHOLDER, IV_SIZE};
use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
use crate::p2p_protocol::{Direction, FrameId, TunnelId, CLIENT_HELLO_FORWARD_ID};
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
const SEQ_NR_SIZE: usize = size_of::<SequenceNumber>();

const FORWARD_FRAME_IDS_MAGIC_NUMBER: &[u8] = "FORWARD_FRAME_IDS_MAGIC_NUMBER".as_bytes();

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
    IncomingCover(Vec<u8>, bool),
    ReceivedClose,
}

pub enum DataType {
    ForwardFrameIds(Vec<FrameId>),
    Close,
    AppData(Vec<u8>),
    Cover(Vec<u8>, bool),
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
type SequenceNumber = u32;

#[derive(Debug, Clone)]
struct SequenceNumberContext {
    outgoing: SequenceNumber,
    newest_received: SequenceNumber,
    used_seq_nrs: HashSet<SequenceNumber>,
}

impl SequenceNumberContext {
    fn new() -> Self {
        Self {
            outgoing: 0,
            newest_received: 0,
            used_seq_nrs: HashSet::new(),
        }
    }

    fn get_next_seq_nr(&mut self) -> SequenceNumber {
        self.outgoing += 1;
        self.outgoing
    }

    fn verify_incoming_seq_nr(&mut self, seq_nr: SequenceNumber) -> Result<(), ProtocolError> {
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
    async fn close(&mut self);

    /*
     *  Get the implementation of the trait for updating codecs
     */
    fn as_any(&mut self) -> &mut dyn Any;

    /*
     *  Set the secret frame_ids for forwarding packets
     */
    async fn process_forward_frame_ids(&mut self, _ids: Vec<FrameId>) -> Result<(), ProtocolError>;

    /*
     *  Set the frame_id for backward packets
     */
    fn set_backward_frame_id(&mut self, _id: FrameId) {
        log::warn!("Setting backward frame_id not supported for this codec");
    }

    /*
     *  Set the secret frame_ids for backward packets
     */
    fn set_backward_frame_ids(&mut self, _secret_ids: Vec<FrameId>) {
        log::warn!("Setting backward frame_ids not supported for this codec");
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
    forward_frame_ids: Vec<FrameId>,     // used for send to next hop
    next_hop_backward_frame_id: FrameId, // unencrypted for client_hello
    next_hop_backward_frame_ids: Vec<FrameId>, // encrypted secret via routing infos
    next_hop_backward_frame_ids_old: Vec<FrameId>, // used for storing last, otherwise would be overwritten too early
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
            forward_frame_ids: vec![],
            next_hop_backward_frame_id: 0,
            next_hop_backward_frame_ids: vec![],
            next_hop_backward_frame_ids_old: vec![],
            crypto_contexts: vec![],
            seq_nr_context: SequenceNumberContext::new(),
        }
    }
}

pub(crate) struct TargetEndpoint {
    socket: Arc<UdpSocket>,
    prev_hop: SocketAddr,
    frame_id_manager: Arc<RwLock<FrameIdManager>>,
    tunnel_id: TunnelId,
    backward_frame_ids: Vec<FrameId>,
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
            backward_frame_ids: vec![],
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
    tunnel_id: TunnelId,
    forward_frame_ids: Vec<FrameId>,
    backward_frame_ids: Vec<FrameId>,
    crypto_context: CryptoContext,
    server_hello_forwarded: bool,
}

// make target to intermediate
impl IntermediateHopCodec {
    pub fn from(target: &mut TargetEndpoint, next_hop: SocketAddr) -> Self {
        Self {
            socket: target.socket.clone(),
            next_hop,
            prev_hop: target.prev_hop,
            tunnel_id: target.tunnel_id,
            forward_frame_ids: vec![],
            backward_frame_ids: target.backward_frame_ids.drain(..).collect(),
            crypto_context: target.crypto_context.take().unwrap(),
            server_hello_forwarded: false,
        }
    }
}

#[async_trait]
impl P2pCodec for InitiatorEndpoint {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        let mut frame = TunnelFrame::new();
        if self.forward_frame_ids.is_empty() {
            // no forward_frame_ids available yet, use CLIENT_HELlO_FORWARD_ID
            frame.set_frame_id(CLIENT_HELLO_FORWARD_ID);
        } else {
            // choose a random
            let index = rand::random::<usize>() % self.forward_frame_ids.len();
            assert!(index < self.forward_frame_ids.len());
            frame.set_frame_id(*self.forward_frame_ids.get(index).unwrap());
        }

        let iv_data_chunks = match data {
            DataType::ForwardFrameIds(ids) => {
                let mut data = FORWARD_FRAME_IDS_MAGIC_NUMBER.to_vec();
                data.append(&mut (ids.len() as u16).to_le_bytes().into());
                for id in ids {
                    data.append(&mut id.to_le_bytes().into());
                }
                data.append(
                    &mut (0..(PAYLOAD_SIZE - data.len()))
                        .map(|_| rand::random::<u8>())
                        .collect(),
                );
                // layered encryption via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (_, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &data, false)?;
                    iv = Some(iv_);
                    data = data_;
                }
                assert_eq!(data.len(), PAYLOAD_SIZE);
                vec![(iv, data)]
            }
            DataType::Close => {
                // send close similar as app_data without fragmentation
                let mut raw_data = RawData::new(PAYLOAD_SIZE as u16, CLOSE, vec![]).serialize();

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
            DataType::Cover(data, _) => {
                // fragmentation
                let mut chunks = vec![];
                for data_chunk in data.chunks(EFFECTIVE_PACKET_SIZE) {
                    let mut app_data = ApplicationData::new();
                    let mut cover_packet = CoverTraffic::new();
                    cover_packet.set_data(Bytes::copy_from_slice(data_chunk));
                    cover_packet.set_mirrored(false);
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_cover_traffic(cover_packet);
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
                if self.next_hop_backward_frame_id == 0 {
                    self.next_hop_backward_frame_id = self
                        .frame_id_manager
                        .write()
                        .await
                        .new_frame_id(self.tunnel_id, Direction::Backward);
                }

                client_hello.set_backward_frame_id(self.next_hop_backward_frame_id);
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
            DataType::RoutingInformation(mut data) => {
                log::debug!(
                    "Tunnel={:?}: Send RoutingInformation={:?} to next hop {:?}",
                    self.tunnel_id,
                    data,
                    self.next_hop
                );

                // use the stored next_hop_backward_frame_ids to tell the next hop how he can address the previous one
                let bf_ids = self.next_hop_backward_frame_ids_old.drain(..).collect();
                data.set_backward_frame_ids(bf_ids);

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
                Ok(message) => {
                    log::trace!(
                        "Tunnel={:?}: Initiator receives application data with sequence_number={:?}",
                        self.tunnel_id,
                        message.sequence_number
                    );
                    if let Err(e) = self
                        .seq_nr_context
                        .verify_incoming_seq_nr(message.sequence_number)
                    {
                        return Err(e);
                    }
                    return match message.message {
                        None => Err(ProtocolError::EmptyMessage),
                        Some(data) => match data {
                            ApplicationData_oneof_message::data(data) => {
                                Ok(ProcessedData::IncomingData(data.to_vec()))
                            }
                            ApplicationData_oneof_message::cover_traffic(cover) => Ok(
                                ProcessedData::IncomingCover(cover.data.to_vec(), cover.mirrored),
                            ),
                        },
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
                Ok(ProcessedData::ReceivedClose)
            }
            _ => return Err(ProtocolError::UnexpectedMessageType),
        }
    }

    async fn close(&mut self) {
        log::debug!(
            "Tunnel={:?}: At initiator send close to target",
            self.tunnel_id,
        );
        let _ = self.write(DataType::Close).await;
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    async fn process_forward_frame_ids(&mut self, ids: Vec<FrameId>) -> Result<(), ProtocolError> {
        if self.forward_frame_ids.is_empty() {
            log::trace!(
                "Tunnel={:?}: Set secret forward frame ids = {:?}",
                self.tunnel_id,
                ids
            );
            self.forward_frame_ids = ids;
            Ok(())
        } else {
            log::trace!(
                "Tunnel={:?}: Initiator send forward_frame_ids={:?} to hop via magic number",
                self.tunnel_id,
                ids
            );
            self.write(DataType::ForwardFrameIds(ids)).await
        }
    }

    fn set_backward_frame_id(&mut self, id: FrameId) {
        log::trace!(
            "Tunnel={:?}: Initiator set_next_hop_bw_frame_id={:?}",
            self.tunnel_id,
            id
        );
        self.next_hop_backward_frame_id = id;
    }

    fn set_backward_frame_ids(&mut self, secret_ids: Vec<FrameId>) {
        log::trace!(
            "Tunnel={:?}: Initiator set_next_hop_bw_frame_ids={:?}",
            self.tunnel_id,
            secret_ids
        );
        self.next_hop_backward_frame_ids_old = self.next_hop_backward_frame_ids.drain(..).collect();
        self.next_hop_backward_frame_ids = secret_ids;
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

        if self.backward_frame_ids.is_empty() {
            return Err(ProtocolError::EmptyFrameIds);
        } else {
            let index = rand::random::<usize>() % self.backward_frame_ids.len();
            assert!(index < self.backward_frame_ids.len());
            frame.set_frame_id(*self.backward_frame_ids.get(index).unwrap());
        }

        let iv_data_bytes = match data {
            DataType::Close => {
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
            DataType::Cover(data, _) => {
                // mirror received cover data frame
                let mut chunks = vec![];
                for data_chunk in data.chunks(EFFECTIVE_PACKET_SIZE) {
                    let mut app_data = ApplicationData::new();
                    let mut cover_packet = CoverTraffic::new();
                    cover_packet.set_data(Bytes::copy_from_slice(data_chunk));
                    cover_packet.set_mirrored(true);
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_cover_traffic(cover_packet);
                    let raw_data = app_data.write_to_bytes().unwrap();
                    let raw_data =
                        RawData::new(PAYLOAD_SIZE as u16, APP_DATA, raw_data).serialize();

                    // Unencrypted data transfer is not allowed
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
            DataType::ServerHello(server_hello) => {
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
                Ok(message) => {
                    log::trace!(
                        "Tunnel={:?}: Target receives application data with sequence_number={:?}",
                        self.tunnel_id,
                        message.sequence_number
                    );
                    if let Err(e) = self
                        .seq_nr_context
                        .verify_incoming_seq_nr(message.sequence_number)
                    {
                        return Err(e);
                    }
                    return match message.message {
                        None => Err(ProtocolError::EmptyMessage),
                        Some(data) => match data {
                            ApplicationData_oneof_message::data(data) => {
                                Ok(ProcessedData::IncomingData(data.to_vec()))
                            }
                            ApplicationData_oneof_message::cover_traffic(cover) => Ok(
                                ProcessedData::IncomingCover(cover.data.to_vec(), cover.mirrored),
                            ),
                        },
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

    async fn close(&mut self) {
        log::debug!(
            "Tunnel={:?}: Send close at target endpoint to initiator",
            self.tunnel_id
        );
        let _ = self.write(DataType::Close).await;
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    async fn process_forward_frame_ids(&mut self, _ids: Vec<FrameId>) -> Result<(), ProtocolError> {
        log::warn!("Setting forward frame_ids not supported for this codec");
        Err(ProtocolError::UnsupportedAction)
    }

    fn set_backward_frame_id(&mut self, id: FrameId) {
        if self.backward_frame_ids.is_empty() {
            log::trace!(
                "Tunnel={:?}: Target set backward_frame_id={:?}",
                self.tunnel_id,
                id
            );
            self.backward_frame_ids.push(id);
        }
    }

    fn set_backward_frame_ids(&mut self, secret_ids: Vec<FrameId>) {
        log::trace!(
            "Tunnel={:?}: Set secret backward frame ids={:?}",
            self.tunnel_id,
            secret_ids
        );
        self.backward_frame_ids = secret_ids;
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

        // expect incoming data backward or forward, apply encryption or decryption and delegate to next hop
        let mut frame = TunnelFrame::new();
        let (frame, addr) = match d {
            Direction::Forward => {
                log::debug!("Tunnel={:?}: Hop receives a forward message, decrypt the payload and pass it to the next hop {:?}", self.tunnel_id, self.next_hop);
                // decrypt using iv and key
                let (iv, decrypted_data) =
                    self.crypto_context
                        .decrypt(&iv, &data, !self.server_hello_forwarded)?;

                // check for magic number forward frame ids
                if self.server_hello_forwarded && self.forward_frame_ids.is_empty() {
                    return if &decrypted_data[0..FORWARD_FRAME_IDS_MAGIC_NUMBER.len()]
                        == FORWARD_FRAME_IDS_MAGIC_NUMBER
                    {
                        log::trace!(
                            "Tunnel={:?}: Hop found magic number for secret forward frame ids",
                            self.tunnel_id
                        );
                        let mut ids: Vec<FrameId> = vec![];
                        let (_, remainder) =
                            decrypted_data.split_at(FORWARD_FRAME_IDS_MAGIC_NUMBER.len());
                        let (len_raw, remainder) = remainder.split_at(size_of::<u16>());
                        let mut len_buf = [0u8; size_of::<u16>()];
                        len_buf.copy_from_slice(len_raw);
                        let len = u16::from_le_bytes(len_buf) as usize;

                        for chunk in remainder.chunks(size_of::<FrameId>()) {
                            let mut current_id_buf = [0u8; size_of::<FrameId>()];
                            current_id_buf.copy_from_slice(chunk);
                            let id = FrameId::from_le_bytes(current_id_buf);
                            ids.push(id);
                            if ids.len() == len {
                                break;
                            }
                        }

                        log::trace!(
                            "Tunnel={:?}: New secret forwards ids: {:?}",
                            self.tunnel_id,
                            ids,
                        );

                        self.forward_frame_ids = ids;

                        Ok(ProcessedData::TransferredToNextHop)
                    } else {
                        log::warn!(
                            "Tunnel={:?}: Forward frame ids not available, cannot forward packet",
                            self.tunnel_id,
                        );
                        Err(ProtocolError::EmptyFrameIds)
                    };
                }

                // check if we should forward a client hello
                if !self.server_hello_forwarded {
                    frame.set_frame_id(CLIENT_HELLO_FORWARD_ID);
                } else {
                    // choose random forward id
                    let index = rand::random::<usize>() % self.forward_frame_ids.len();
                    assert!(index < self.forward_frame_ids.len());
                    frame.set_frame_id(*self.forward_frame_ids.get(index).unwrap());
                }
                frame.set_iv(iv.into());
                frame.set_data(decrypted_data.into());
                (frame, self.next_hop)
            }
            Direction::Backward => {
                // encrypt using iv and key
                log::debug!("Tunnel={:?}: Hop receives a backward message, encrypt the payload and pass it to the prev hop {:?}", self.tunnel_id, self.prev_hop);
                let (iv, encrypted_data) =
                    self.crypto_context
                        .encrypt(Some(&iv), &data, !self.server_hello_forwarded)?;
                self.server_hello_forwarded = true; // never set to false again
                                                    // choose random backward id
                let index = rand::random::<usize>() % self.backward_frame_ids.len();
                assert!(index < self.backward_frame_ids.len());
                frame.set_frame_id(*self.backward_frame_ids.get(index).unwrap());
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

    async fn close(&mut self) {
        log::warn!("Close action not supported for intermediate hop codec");
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    async fn process_forward_frame_ids(&mut self, _ids: Vec<FrameId>) -> Result<(), ProtocolError> {
        log::warn!("Setting forward frame_ids not supported for this codec");
        Err(ProtocolError::UnsupportedAction)
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
