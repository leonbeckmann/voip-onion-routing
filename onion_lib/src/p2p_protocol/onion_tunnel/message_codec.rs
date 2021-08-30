use std::{net::SocketAddr, sync::Arc};

use crate::p2p_protocol::messages::p2p_messages::{
    ApplicationData, ApplicationData_oneof_message, ClientHello, Close, CoverTraffic,
    ForwardFrameIds, FrameData, FrameDataType_oneof_message, HandshakeData, RoutingInformation,
    ServerHello, TunnelFrame,
};
use crate::p2p_protocol::onion_tunnel::crypto::{CryptoContext, AUTH_PLACEHOLDER, IV_SIZE};
use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
use crate::p2p_protocol::{Direction, FrameId, TunnelId, CLIENT_HELLO_FORWARD_ID};
use async_trait::async_trait;
use bytes::Bytes;
use std::any::Any;
use std::collections::HashSet;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use super::crypto::AUTH_SIZE;
use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
use protobuf::Message;

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

const FRAME_SIZE: usize = 1024;
const FRAME_DATA_SIZE: usize = 998;
const SERIALIZED_FRAME_DATA_SIZE: usize = 982;
const FRAME_DATA_CONTENT_SIZE_APP: usize = 972;
const FRAME_DATA_CONTENT_SIZE_OTHER: usize = 974;
const PAYLOAD_CHUNK_SIZE: usize = 964;
const COVER_CHUNK_SIZE: usize = 959;

fn serialize(message: FrameDataType_oneof_message) -> Vec<u8> {
    let mut buf = vec![AUTH_PLACEHOLDER; AUTH_SIZE];
    let mut frame_data = FrameData::new();
    let (mut data, content_size) = match message {
        FrameDataType_oneof_message::handshake_data(data) => {
            frame_data.set_app_data(false);
            (
                data.write_to_bytes().unwrap(),
                FRAME_DATA_CONTENT_SIZE_OTHER,
            )
        }
        FrameDataType_oneof_message::app_data(data) => {
            frame_data.set_app_data(true);
            (data.write_to_bytes().unwrap(), FRAME_DATA_CONTENT_SIZE_APP)
        }
        FrameDataType_oneof_message::forward_frame_ids(data) => {
            frame_data.set_app_data(false);
            (
                data.write_to_bytes().unwrap(),
                FRAME_DATA_CONTENT_SIZE_OTHER,
            )
        }
    };
    assert!(data.len() <= content_size);
    frame_data.set_data_size(data.len() as u32);
    let padding_size = content_size - data.len();
    let mut padding: Vec<_> = (0..padding_size).map(|_| rand::random::<u8>()).collect();
    data.append(&mut padding);
    assert_eq!(data.len(), content_size);
    frame_data.set_data(data.into());
    let mut frame_data_serialized = frame_data.write_to_bytes().unwrap();
    assert_eq!(frame_data_serialized.len(), SERIALIZED_FRAME_DATA_SIZE);
    buf.append(&mut frame_data_serialized);
    assert_eq!(buf.len(), FRAME_DATA_SIZE);
    buf
}

fn deserialize(
    raw: &[u8],
    frame_ids_expected: bool,
    tunnel_id: TunnelId,
) -> Result<FrameDataType_oneof_message, ProtocolError> {
    if raw.len() != FRAME_DATA_SIZE {
        log::warn!(
            "Tunnel={:?}: Received packet with invalid frame data size. Disconnect",
            tunnel_id
        );
        return Err(ProtocolError::InvalidPacketLength);
    }

    let (_auth_tag, raw) = raw.split_at(AUTH_SIZE);
    let frame_data = match FrameData::parse_from_bytes(raw) {
        Ok(data) => data,
        Err(_) => {
            log::warn!("Tunnel={:?}: Cannot parse frame data", tunnel_id);
            return Err(ProtocolError::ProtobufError);
        }
    };
    let raw_content = frame_data.data;
    let (data, _padding) = raw_content.split_at((frame_data.data_size) as usize);
    if frame_data.app_data {
        Ok(FrameDataType_oneof_message::app_data(
            match ApplicationData::parse_from_bytes(data) {
                Ok(data) => data,
                Err(_) => {
                    log::warn!("Tunnel={:?}: Cannot parse application data", tunnel_id);
                    return Err(ProtocolError::ProtobufError);
                }
            },
        ))
    } else if frame_ids_expected {
        Ok(FrameDataType_oneof_message::forward_frame_ids(
            match ForwardFrameIds::parse_from_bytes(data) {
                Ok(data) => data,
                Err(_) => {
                    log::warn!("Tunnel={:?}: Cannot parse forward_frame_ids", tunnel_id);
                    return Err(ProtocolError::ProtobufError);
                }
            },
        ))
    } else {
        Ok(FrameDataType_oneof_message::handshake_data(
            match HandshakeData::parse_from_bytes(data) {
                Ok(data) => data,
                Err(_) => {
                    log::warn!("Tunnel={:?}: Cannot parse handshake data", tunnel_id);
                    return Err(ProtocolError::ProtobufError);
                }
            },
        ))
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
                let mut data = ForwardFrameIds::new();
                data.set_forward_frame_ids(ids);
                let mut data = serialize(FrameDataType_oneof_message::forward_frame_ids(data));

                // Unencrypted frameID transfer is not allowed
                assert!(!self.crypto_contexts.is_empty());

                // layered encryption via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (_, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    // TODO makes this end-to-end AES-GCM for integrity protection
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &data, false)?;
                    iv = Some(iv_);
                    data = data_;
                }
                assert_eq!(data.len(), FRAME_DATA_SIZE);
                vec![(iv, data)]
            }
            DataType::Close => {
                // send close similar as app_data without fragmentation
                let mut app_data = ApplicationData::new();
                app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                app_data.set_close(Close::new());
                let mut raw_data = serialize(FrameDataType_oneof_message::app_data(app_data));

                // Unencrypted close is not allowed
                assert!(!self.crypto_contexts.is_empty());

                // layered encryption via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &raw_data, i == 0)?;
                    iv = Some(iv_);
                    raw_data = data_;
                }
                assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
                vec![(iv, raw_data)]
            }
            DataType::AppData(data) => {
                // fragmentation
                let mut chunks = vec![];
                for data_chunk in data.chunks(PAYLOAD_CHUNK_SIZE) {
                    let mut app_data = ApplicationData::new();
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_data(Bytes::copy_from_slice(data_chunk));
                    let mut raw_data = serialize(FrameDataType_oneof_message::app_data(app_data));

                    // Unencrypted data transfer is not allowed
                    assert!(!self.crypto_contexts.is_empty());

                    // layered encryption via iv and keys using the crypto contexts
                    let mut iv: Option<Vec<u8>> = None;
                    for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                        let (iv_, data_) = cc.encrypt(iv.as_deref(), &raw_data, i == 0)?;
                        iv = Some(iv_);
                        raw_data = data_;
                    }
                    assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
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
                for data_chunk in data.chunks(COVER_CHUNK_SIZE) {
                    let mut app_data = ApplicationData::new();
                    let mut cover_packet = CoverTraffic::new();
                    cover_packet.set_data(Bytes::copy_from_slice(data_chunk));
                    cover_packet.set_mirrored(false);
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_cover_traffic(cover_packet);
                    let mut raw_data = serialize(FrameDataType_oneof_message::app_data(app_data));

                    // Unencrypted data transfer is not allowed
                    assert!(!self.crypto_contexts.is_empty());

                    // layered encryption via iv and keys using the crypto contexts
                    let mut iv: Option<Vec<u8>> = None;
                    for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                        let (iv_, data_) = cc.encrypt(iv.as_deref(), &raw_data, i == 0)?;
                        iv = Some(iv_);
                        raw_data = data_;
                    }
                    assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
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
                let mut data = serialize(FrameDataType_oneof_message::handshake_data(handshake));

                // encrypt via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &data, i == 0)?;
                    iv = Some(iv_);
                    data = data_;
                }
                assert_eq!(data.len(), FRAME_DATA_SIZE);
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
                let mut data = serialize(FrameDataType_oneof_message::handshake_data(handshake));

                // Unencrypted routing transfer is not allowed
                assert!(!self.crypto_contexts.is_empty());

                // encrypt via iv and keys using the crypto contexts
                let mut iv: Option<Vec<u8>> = None;
                for (i, cc) in self.crypto_contexts.iter_mut().rev().enumerate() {
                    let (iv_, data_) = cc.encrypt(iv.as_deref(), &data, i == 0)?;
                    iv = Some(iv_);
                    data = data_;
                }
                assert_eq!(data.len(), FRAME_DATA_SIZE);
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
            let iv = iv.unwrap_or_else(|| {
                let mut iv = vec![0; IV_SIZE];
                openssl::rand::rand_bytes(&mut iv).expect("Failed to generated random IV");
                iv
            });
            assert_eq!(iv.len(), IV_SIZE);
            frame.set_iv(iv.into());
            frame.set_data(data.into());
            let data = frame.write_to_bytes().unwrap();
            assert_eq!(data.len(), FRAME_SIZE);
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
        match deserialize(dec_data.as_ref(), false, self.tunnel_id)? {
            FrameDataType_oneof_message::handshake_data(data) => {
                log::trace!(
                    "Tunnel={:?}: Initiator receives handshake data",
                    self.tunnel_id
                );
                Ok(ProcessedData::HandshakeData(data))
            }
            FrameDataType_oneof_message::app_data(message) => {
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
                        ApplicationData_oneof_message::close(_) => {
                            // initiator received close, deconstruct tunnel
                            log::trace!("Tunnel={:?}: Initiator receives close", self.tunnel_id);
                            Ok(ProcessedData::ReceivedClose)
                        }
                    },
                };
            }
            _ => Err(ProtocolError::UnexpectedMessageType),
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
                let mut app_data = ApplicationData::new();
                app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                app_data.set_close(Close::new());
                let raw_data = serialize(FrameDataType_oneof_message::app_data(app_data));

                // // Unencrypted close transfer is not allowed
                assert!(self.crypto_context.is_some());

                let (iv, raw_data) = self
                    .crypto_context
                    .as_mut()
                    .unwrap()
                    .encrypt(None, &raw_data, true)?;

                log::debug!(
                    "Tunnel={:?}: Send encrypted close to prev hop {:?}",
                    self.tunnel_id,
                    self.prev_hop
                );

                assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
                vec![(iv, raw_data)]
            }
            DataType::AppData(data) => {
                // fragmentation
                let mut chunks = vec![];
                for data_chunk in data.chunks(PAYLOAD_CHUNK_SIZE) {
                    let mut app_data = ApplicationData::new();
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_data(Bytes::copy_from_slice(data_chunk));
                    let raw_data = serialize(FrameDataType_oneof_message::app_data(app_data));

                    // Unencrypted data transfer is not allowed
                    assert!(self.crypto_context.is_some());

                    let (iv, raw_data) = self
                        .crypto_context
                        .as_mut()
                        .unwrap()
                        .encrypt(None, &raw_data, true)?;

                    assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
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
                for data_chunk in data.chunks(COVER_CHUNK_SIZE) {
                    let mut app_data = ApplicationData::new();
                    let mut cover_packet = CoverTraffic::new();
                    cover_packet.set_data(Bytes::copy_from_slice(data_chunk));
                    cover_packet.set_mirrored(true);
                    app_data.set_sequence_number(self.seq_nr_context.get_next_seq_nr());
                    app_data.set_cover_traffic(cover_packet);
                    let raw_data = serialize(FrameDataType_oneof_message::app_data(app_data));

                    // Unencrypted cover transfer is not allowed
                    assert!(self.crypto_context.is_some());

                    let (iv, raw_data) = self
                        .crypto_context
                        .as_mut()
                        .unwrap()
                        .encrypt(None, &raw_data, true)?;

                    assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
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
                let raw_data = serialize(FrameDataType_oneof_message::handshake_data(handshake));
                assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
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
            assert_eq!(iv.len(), IV_SIZE);
            frame.set_iv(iv.into());
            frame.set_data(data.into());
            let data = frame.write_to_bytes().unwrap();
            assert_eq!(data.len(), FRAME_SIZE);

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

        match deserialize(data.as_ref(), false, self.tunnel_id)? {
            FrameDataType_oneof_message::handshake_data(data) => {
                log::trace!(
                    "Tunnel={:?}: Target receives handshake data",
                    self.tunnel_id
                );
                Ok(ProcessedData::HandshakeData(data))
            }
            FrameDataType_oneof_message::app_data(message) => {
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
                        ApplicationData_oneof_message::close(_) => {
                            log::trace!("Tunnel={:?}: Target receives close", self.tunnel_id);
                            Ok(ProcessedData::ReceivedClose)
                        }
                    },
                };
            }
            _ => Err(ProtocolError::UnexpectedMessageType),
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
        if data.len() != FRAME_DATA_SIZE {
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
                // TODO intermediate hop should never use end-to-end, no integrity protection required
                let (iv, decrypted_data) =
                    self.crypto_context
                        .decrypt(&iv, &data, !self.server_hello_forwarded)?;

                if self.server_hello_forwarded && self.forward_frame_ids.is_empty() {
                    // expect frame ids
                    return match deserialize(&decrypted_data, true, self.tunnel_id) {
                        Ok(data) => match data {
                            FrameDataType_oneof_message::forward_frame_ids(ids) => {
                                log::trace!(
                                    "Tunnel={:?}: New secret forwards ids: {:?}",
                                    self.tunnel_id,
                                    ids.forward_frame_ids,
                                );
                                FrameIdManager::verify_frame_ids(ids.get_forward_frame_ids(), 10)?;
                                self.forward_frame_ids = ids.forward_frame_ids;
                                Ok(ProcessedData::TransferredToNextHop)
                            }
                            _ => {
                                log::warn!(
                                    "Tunnel={:?}: Cannot parse to forward_frame_ids",
                                    self.tunnel_id,
                                );
                                Err(ProtocolError::ProtobufError)
                            }
                        },
                        Err(_) => {
                            log::warn!(
                                "Tunnel={:?}: Forward frame ids not available, cannot forward packet",
                                self.tunnel_id,
                            );
                            Err(ProtocolError::EmptyFrameIds)
                        }
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
                // TODO intermediate hop should never use end-to-end, no integrity protection required
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
        assert_eq!(data.len(), FRAME_SIZE);

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
    use crate::p2p_protocol::messages::p2p_messages::{
        ApplicationData, ClientHello, Close, CoverTraffic, EncryptedServerHelloData,
        FrameDataType_oneof_message, HandshakeData, RoutingInformation, ServerHello, TunnelFrame,
    };
    use crate::p2p_protocol::onion_tunnel::crypto::{
        CryptoContext, HandshakeCryptoConfig, HandshakeCryptoContext,
    };
    use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
    use crate::p2p_protocol::onion_tunnel::message_codec::{
        deserialize, serialize, SequenceNumberContext, COVER_CHUNK_SIZE, FRAME_DATA_SIZE,
        FRAME_SIZE, PAYLOAD_CHUNK_SIZE,
    };
    use openssl::rsa::Rsa;
    use protobuf::Message;
    use std::sync::Arc;

    #[test]
    fn unit_frame_size() {
        let mut data_vec = vec![];
        let iv = vec![0; 16];
        let cover_chunk = vec![0; COVER_CHUNK_SIZE];
        let payload_chunk = vec![0; PAYLOAD_CHUNK_SIZE];
        let mut frame = TunnelFrame::new();
        frame.set_iv(iv.into());
        frame.set_frame_id(1);

        // test app data
        let mut app_data = ApplicationData::new();
        app_data.set_sequence_number(1);

        // close
        app_data.set_close(Close::new());
        let data = serialize(FrameDataType_oneof_message::app_data(app_data.clone()));
        match deserialize(&data, false, 1).unwrap() {
            FrameDataType_oneof_message::app_data(data) => assert!(data.has_close()),
            _ => panic!("Expected ApplicationData"),
        };
        data_vec.push(data);

        // cover not mirrored
        let mut cover = CoverTraffic::new();
        cover.set_data(cover_chunk.clone().into());
        cover.set_mirrored(true);
        app_data.set_cover_traffic(cover);
        let data = serialize(FrameDataType_oneof_message::app_data(app_data.clone()));
        match deserialize(&data, false, 1).unwrap() {
            FrameDataType_oneof_message::app_data(data) => assert!(data.has_cover_traffic()),
            _ => panic!("Expected ApplicationData"),
        };
        data_vec.push(data);

        // cover mirrored
        let mut cover = CoverTraffic::new();
        cover.set_data(cover_chunk.into());
        cover.set_mirrored(false);
        app_data.set_cover_traffic(cover);
        let data = serialize(FrameDataType_oneof_message::app_data(app_data.clone()));
        match deserialize(&data, false, 1).unwrap() {
            FrameDataType_oneof_message::app_data(data) => assert!(data.has_cover_traffic()),
            _ => panic!("Expected ApplicationData"),
        };
        data_vec.push(data);

        // data
        app_data.set_data(payload_chunk.into());
        let data = serialize(FrameDataType_oneof_message::app_data(app_data));
        match deserialize(&data, false, 1).unwrap() {
            FrameDataType_oneof_message::app_data(data) => assert!(data.has_data()),
            _ => panic!("Expected ApplicationData"),
        };
        data_vec.push(data);

        // test handshake data
        let key = Rsa::generate(4096).unwrap();
        let pub_key = Rsa::public_key_from_pem(key.public_key_to_pem().unwrap().as_ref()).unwrap();
        let priv_key =
            Rsa::private_key_from_pem(key.private_key_to_pem().unwrap().as_ref()).unwrap();

        let config = Arc::new(HandshakeCryptoConfig::new(pub_key, priv_key));
        let mut cc1 = HandshakeCryptoContext::new(config.clone());
        let mut cc2 = HandshakeCryptoContext::new(config);
        let shared_secret = cc1.finish_ecdh(cc2.get_public_key().as_ref()).unwrap();
        let _cc_a = CryptoContext::new(shared_secret.clone(), true);
        let mut cc_b = CryptoContext::new(shared_secret, false);
        let mut handshake = HandshakeData::new();

        // client hello
        let mut client_hello = ClientHello::new();
        client_hello.set_backward_frame_id(0xffffffff);
        client_hello.set_ecdh_public_key(cc1.get_public_key().into());
        handshake.set_client_hello(client_hello);
        let data = serialize(FrameDataType_oneof_message::handshake_data(
            handshake.clone(),
        ));
        match deserialize(&data, false, 1).unwrap() {
            FrameDataType_oneof_message::handshake_data(data) => assert!(data.has_client_hello()),
            _ => panic!("Expected ClientHello"),
        };
        data_vec.push(data);

        // server hello, test maximum size
        let mut server_hello = ServerHello::new();
        let signature = cc2.hop_sign(&cc1.get_public_key());
        let mut encrypted_data = EncryptedServerHelloData::new();
        encrypted_data.set_signature(signature.into());
        encrypted_data.set_backward_frame_id(0xffffffff);
        encrypted_data.set_backward_frame_ids(vec![0xffffffff; 10]);
        encrypted_data.set_forward_frame_ids(vec![0xffffffff; 10]);
        let raw_enc_data = encrypted_data.write_to_bytes().unwrap();
        let (iv, enc_data) = cc_b.encrypt(None, &raw_enc_data, false).unwrap();
        server_hello.set_ecdh_public_key(cc2.get_public_key().into());
        server_hello.set_challenge(cc2.get_challenge().to_owned().into());
        server_hello.set_iv(iv.into());
        server_hello.set_encrypted_data(enc_data.into());
        handshake.set_server_hello(server_hello);
        let data = serialize(FrameDataType_oneof_message::handshake_data(
            handshake.clone(),
        ));
        match deserialize(&data, false, 1).unwrap() {
            FrameDataType_oneof_message::handshake_data(data) => assert!(data.has_server_hello()),
            _ => panic!("Expected ServerHello"),
        };
        data_vec.push(data);

        // routing, test maximum size
        let mut routing = RoutingInformation::new();
        routing.set_cover_only(true);
        routing.set_tunnel_update_reference(0xffffffff);
        routing.set_is_endpoint(true);
        routing.set_backward_frame_ids(vec![0xffffffff; 10]);
        routing.set_next_hop_addr(vec![0; 16].into());
        routing.set_next_hop_port(0xffff_u32);
        let response = cc1.sign(cc2.get_challenge());
        routing.set_challenge_response(response.into());
        handshake.set_routing(routing);
        let data = serialize(FrameDataType_oneof_message::handshake_data(handshake));
        match deserialize(&data, false, 1).unwrap() {
            FrameDataType_oneof_message::handshake_data(data) => assert!(data.has_routing()),
            _ => panic!("Expected RoutingInformation"),
        };
        data_vec.push(data);

        for raw_data in data_vec.into_iter() {
            assert_eq!(raw_data.len(), FRAME_DATA_SIZE);
            frame.set_data(raw_data.into());
            let data = frame.write_to_bytes().unwrap();
            assert_eq!(data.len(), FRAME_SIZE);
        }
    }

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
