use std::{net::SocketAddr, sync::Arc};

use crate::p2p_protocol::messages::p2p_messages::{
    ApplicationData, ClientHello, Close, HandshakeData, RoutingInformation, ServerHello,
    TunnelFrame,
};
use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
use crate::p2p_protocol::{Direction, FrameId, TunnelId};
use async_trait::async_trait;
use bytes::Bytes;
use protobuf::Message;
use std::any::Any;
use std::collections::HashMap;
use std::mem::size_of;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub(crate) const PAYLOAD_SIZE: u16 = 1024;

pub enum ProcessedData {
    TransferredToNextHop,
    HandshakeData(HandshakeData),
    IncomingData(Vec<u8>),
}

pub enum DataType {
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

impl RawData {
    // TODO assert data small enough
    fn new(len: u16, message_type: u8, data: Vec<u8>) -> Self {
        let padding_len = len - (data.len() as u16) - 3;
        Self {
            padding_len,
            message_type,
            data,
            padding: (0..padding_len).map(|_| rand::random::<u8>()).collect(),
        }
    }

    fn deserialize(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() != (PAYLOAD_SIZE as usize) {
            // TODO do we want to terminate here?
            return Err(ProtocolError::InvalidPacketLength);
        }
        // we have padding_size, so we are safe here
        let (padding_size_buf, remainder) = raw.split_at(size_of::<u16>());
        let (message_type_buf, data_buf) = remainder.split_at(size_of::<u8>());
        let mut padding_size = [0u8; size_of::<u16>()];
        padding_size.copy_from_slice(&padding_size_buf);
        let padding_len = u16::from_le_bytes(padding_size);
        let message_type = message_type_buf[0];
        if message_type != APP_DATA && message_type != HANDSHAKE_DATA {
            return Err(ProtocolError::UnexpectedMessageType);
        }
        let data_len = PAYLOAD_SIZE - padding_len - (size_of::<u16>() + size_of::<u8>()) as u16;
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
        buf.append(&mut len);
        buf.push(self.message_type);
        buf.append(&mut self.data);
        buf.append(&mut self.padding);
        buf
    }
}

type IV = Bytes;
const DUMMY_IV: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
// TODO crypto context
// TODO make closing procedure safe

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
     *  If self is an intermediate hop, the data are processed and transferred to the next hop.
     *  If self is an endpoint, the data are returned ass IncomingData
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
    async fn close(&mut self, d: Direction, initiator: bool);

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
}

async fn new_frame_id(
    tunnel_id: TunnelId,
    direction: Direction,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
) -> FrameId {
    let mut frame_ids = frame_ids.lock().await;
    let mut new_id: u64 = rand::random();
    while new_id < 2 || frame_ids.contains_key(&new_id) {
        new_id = rand::random();
    }
    log::trace!(
        "Register new frame_id mapping: <{:?},{:?}>",
        new_id,
        (tunnel_id, direction)
    );
    let _ = frame_ids.insert(new_id, (tunnel_id, direction));
    new_id
}

fn cleanup_frames(
    _frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    _my_frames: &[(FrameId, Direction)],
) {
    // FIXME cannot run runtime within runtime
    /*let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut frame_ids = frame_ids.lock().await;
        for (id, _) in my_frames.iter() {
            let _ = frame_ids.remove(id);
        }
    });*/
}

async fn send_close(frame_id: FrameId, addr: SocketAddr, socket: Arc<UdpSocket>) {
    let mut frame = TunnelFrame::new();
    frame.set_frameId(frame_id);
    frame.set_close(Close::new());
    let data = frame.write_to_bytes().unwrap();
    let _ = socket.send_to(data.as_ref(), addr).await;
}

#[derive(Debug, Clone)]
pub(crate) struct InitiatorEndpoint {
    socket: Arc<UdpSocket>,
    next_hop: SocketAddr,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    tunnel_id: TunnelId,
    forward_frame_id: FrameId, // frame id for forward packages
    next_hop_backward_frame_id: FrameId,
    own_frame_ids: Vec<(FrameId, Direction)>,
}

impl InitiatorEndpoint {
    pub fn new(
        socket: Arc<UdpSocket>,
        next_hop: SocketAddr,
        frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
        tunnel_id: TunnelId,
    ) -> Self {
        Self {
            socket,
            next_hop,
            frame_ids,
            tunnel_id,
            forward_frame_id: 1,           // initialized for init client hello
            next_hop_backward_frame_id: 0, // TODO used for client hellos to next hops
            own_frame_ids: vec![],
        }
    }
}

impl Drop for InitiatorEndpoint {
    fn drop(&mut self) {
        cleanup_frames(self.frame_ids.clone(), &self.own_frame_ids);
    }
}

pub(crate) struct TargetEndpoint {
    socket: Arc<UdpSocket>,
    prev_hop: SocketAddr,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    tunnel_id: TunnelId,
    backward_frame_id: FrameId, // frame id for backward packages
    own_frame_ids: Vec<(FrameId, Direction)>,
}

impl TargetEndpoint {
    pub fn new(
        socket: Arc<UdpSocket>,
        prev_hop: SocketAddr,
        frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
        tunnel_id: TunnelId,
    ) -> Self {
        Self {
            socket,
            prev_hop,
            frame_ids,
            tunnel_id,
            backward_frame_id: 0,
            own_frame_ids: vec![],
        }
    }

    pub async fn lock_as_target_endpoint(&mut self) {
        // this endpoint is the target and will not be transferred to an intermediate_hop

        // remove unnecessary frame_ids from registry
        let mut frames = self.frame_ids.lock().await;
        self.own_frame_ids.retain(|(id, direction)| {
            if *direction == Direction::Backward {
                // remove all backward frame id's
                let _ = frames.remove(id);
                false
            } else {
                // keep all forward frame id's
                true
            }
        });
    }
}

impl Drop for TargetEndpoint {
    fn drop(&mut self) {
        cleanup_frames(self.frame_ids.clone(), &self.own_frame_ids);
    }
}

pub(crate) struct IntermediateHop {
    socket: Arc<UdpSocket>,
    next_hop: SocketAddr,
    prev_hop: SocketAddr,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    _tunnel_id: TunnelId,
    forward_frame_id: FrameId,  // frame id for forward packages
    backward_frame_id: FrameId, // frame id for backward packages
    own_frame_ids: Vec<(FrameId, Direction)>,
}

// make target to intermediate
impl IntermediateHop {
    pub fn from(target: &TargetEndpoint, next_hop: SocketAddr) -> Self {
        Self {
            socket: target.socket.clone(),
            next_hop,
            prev_hop: target.prev_hop,
            frame_ids: target.frame_ids.clone(),
            _tunnel_id: target.tunnel_id,
            forward_frame_id: 1,
            backward_frame_id: target.backward_frame_id,
            own_frame_ids: target.own_frame_ids.to_owned(),
        }
    }
}

impl Drop for IntermediateHop {
    fn drop(&mut self) {
        cleanup_frames(self.frame_ids.clone(), &self.own_frame_ids);
    }
}

#[async_trait]
impl P2pCodec for InitiatorEndpoint {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        let mut frame = TunnelFrame::new();
        frame.set_frameId(self.forward_frame_id);
        frame.set_iv(Bytes::from(DUMMY_IV.as_ref()));

        let ready_bytes = match data {
            DataType::AppData(data) => {
                let mut app_data = ApplicationData::new();
                app_data.set_data(Bytes::from(data));
                let data = app_data.write_to_bytes().unwrap();
                let raw_data = RawData::new(PAYLOAD_SIZE, APP_DATA, data).serialize();
                // TODO encrypt via iv and keys
                raw_data
            }
            DataType::ClientHello(mut client_hello) => {
                // calculate frame_id
                let new_id =
                    new_frame_id(self.tunnel_id, Direction::Backward, self.frame_ids.clone()).await;
                self.own_frame_ids.push((new_id, Direction::Backward));
                client_hello.set_backwardFrameId(new_id);

                // prepare frame
                let mut handshake = HandshakeData::new();
                handshake.set_clientHello(client_hello);
                let data = handshake.write_to_bytes().unwrap();
                let raw_data = RawData::new(PAYLOAD_SIZE, HANDSHAKE_DATA, data).serialize();
                // TODO encrypt via iv and keys
                raw_data
            }
            DataType::RoutingInformation(data) => {
                let mut handshake = HandshakeData::new();
                handshake.set_routing(data);
                let data = handshake.write_to_bytes().unwrap();
                let raw_data = RawData::new(PAYLOAD_SIZE, HANDSHAKE_DATA, data).serialize();
                // TODO encrypt via iv and keys
                raw_data
            }
            _ => {
                log::warn!("Invalid write action in initiator codec");
                return Err(ProtocolError::CodecUnsupportedAction);
            }
        };

        frame.set_data(Bytes::from(ready_bytes));
        let data = frame.write_to_bytes().unwrap();

        // write to stream
        if let Err(e) = self.socket.send_to(data.as_ref(), self.next_hop).await {
            return Err(ProtocolError::IOError(format!(
                "Cannot write frame via codec: {:?}",
                e
            )));
        }

        Ok(())
    }

    async fn process_data(
        &mut self,
        _d: Direction,
        data: Bytes,
        _iv: IV,
    ) -> Result<ProcessedData, ProtocolError> {
        // expected incoming data or incoming handshake, process and return
        // TODO decrypt using keys and iv
        let raw_data = RawData::deserialize(data.as_ref())?;
        match raw_data.message_type {
            APP_DATA => match ApplicationData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => Ok(ProcessedData::IncomingData(data.data.to_vec())),
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            HANDSHAKE_DATA => match HandshakeData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => Ok(ProcessedData::HandshakeData(data)),
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            _ => return Err(ProtocolError::UnexpectedMessageType),
        }
    }

    async fn close(&mut self, _: Direction, initiator: bool) {
        if initiator {
            send_close(self.forward_frame_id, self.next_hop, self.socket.clone()).await;
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
        self.next_hop_backward_frame_id = id;
    }
}

#[async_trait]
impl P2pCodec for TargetEndpoint {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        let mut frame = TunnelFrame::new();
        frame.set_frameId(self.backward_frame_id);
        frame.set_iv(Bytes::from(DUMMY_IV.as_ref()));

        let ready_bytes = match data {
            DataType::AppData(data) => {
                let mut app_data = ApplicationData::new();
                app_data.set_data(Bytes::from(data));
                let data = app_data.write_to_bytes().unwrap();
                let raw_data = RawData::new(PAYLOAD_SIZE, APP_DATA, data).serialize();
                // TODO encrypt via iv and keys
                raw_data
            }
            DataType::ServerHello(mut server_hello) => {
                // calculate frame_ids
                let new_forward_id =
                    new_frame_id(self.tunnel_id, Direction::Forward, self.frame_ids.clone()).await;
                let new_backward_id =
                    new_frame_id(self.tunnel_id, Direction::Backward, self.frame_ids.clone()).await;
                self.own_frame_ids
                    .push((new_backward_id, Direction::Backward));
                self.own_frame_ids
                    .push((new_forward_id, Direction::Forward));
                server_hello.set_forwardFrameId(new_forward_id);
                server_hello.set_backwardFrameId(new_backward_id);

                // prepare frame
                let mut handshake = HandshakeData::new();
                handshake.set_serverHello(server_hello);
                let data = handshake.write_to_bytes().unwrap();
                RawData::new(PAYLOAD_SIZE, HANDSHAKE_DATA, data).serialize()
            }
            _ => {
                log::warn!("Invalid write action in target codec");
                return Err(ProtocolError::CodecUnsupportedAction);
            }
        };

        frame.set_data(Bytes::from(ready_bytes));
        let data = frame.write_to_bytes().unwrap();

        // write to stream
        if let Err(e) = self.socket.send_to(data.as_ref(), self.prev_hop).await {
            return Err(ProtocolError::IOError(format!(
                "Cannot write frame via codec: {:?}",
                e
            )));
        }

        Ok(())
    }

    async fn process_data(
        &mut self,
        _d: Direction,
        data: Bytes,
        _iv: IV,
    ) -> Result<ProcessedData, ProtocolError> {
        // expect incoming data, handshake or encrypted handshake, process and return
        // TODO how to notice in an efficient way if we are expecting encrypted data? maybe from FSM?
        // TODO decrypt using keys and iv
        let raw_data = RawData::deserialize(data.as_ref())?;
        match raw_data.message_type {
            APP_DATA => match ApplicationData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => Ok(ProcessedData::IncomingData(data.data.to_vec())),
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            HANDSHAKE_DATA => match HandshakeData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => Ok(ProcessedData::HandshakeData(data)),
                Err(_) => Err(ProtocolError::ProtobufError),
            },
            _ => return Err(ProtocolError::UnexpectedMessageType),
        }
    }

    async fn close(&mut self, _: Direction, initiator: bool) {
        if initiator {
            send_close(self.backward_frame_id, self.prev_hop, self.socket.clone()).await;
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn set_backward_frame_id(&mut self, id: FrameId) {
        self.backward_frame_id = id;
    }
}

#[async_trait]
impl P2pCodec for IntermediateHop {
    async fn write(&mut self, _data: DataType) -> Result<(), ProtocolError> {
        log::warn!("Invalid write action in intermediate_hop codec");
        return Err(ProtocolError::CodecUnsupportedAction);
    }

    async fn process_data(
        &mut self,
        d: Direction,
        data: Bytes,
        iv: IV,
    ) -> Result<ProcessedData, ProtocolError> {
        if data.len() != (PAYLOAD_SIZE as usize) {
            // TODO do we want to terminate here?
            return Err(ProtocolError::InvalidPacketLength);
        }
        if d == Direction::Backward && self.forward_frame_id == 1 {
            // seems to be the unencrypted server_hello of the next hop, catch the forward id
            let raw_data = RawData::deserialize(data.as_ref())?;
            if raw_data.message_type != HANDSHAKE_DATA {
                return Err(ProtocolError::UnexpectedMessageType);
            }
            match HandshakeData::parse_from_bytes(raw_data.data.as_ref()) {
                Ok(data) => {
                    if !data.has_serverHello() {
                        return Err(ProtocolError::UnexpectedMessageType);
                    }
                    let id = data.get_serverHello().get_forwardFrameId();
                    self.forward_frame_id = id;
                }
                Err(_) => {
                    return Err(ProtocolError::ProtobufError);
                }
            }
        }

        // expect incoming data backward or forward, apply encryption or decryption and delegate to next hop
        let mut frame = TunnelFrame::new();
        frame.set_iv(iv);
        let (frame, addr) = match d {
            Direction::Forward => {
                // TODO decrypt using iv and key
                let decrypted_data = data;
                frame.set_frameId(self.forward_frame_id);
                frame.set_data(decrypted_data);
                (frame, self.next_hop)
            }
            Direction::Backward => {
                // TODO encrypt using iv and key
                let encrypted_data = data;
                frame.set_frameId(self.backward_frame_id);
                frame.set_data(encrypted_data);
                (frame, self.prev_hop)
            }
        };

        let data = frame.write_to_bytes().unwrap();

        // write to stream
        if let Err(e) = self.socket.send_to(data.as_ref(), addr).await {
            return Err(ProtocolError::IOError(format!(
                "Cannot write frame via codec: {:?}",
                e
            )));
        }

        Ok(ProcessedData::TransferredToNextHop)
    }

    async fn close(&mut self, d: Direction, initiator: bool) {
        // we should never be the initiator here
        assert!(!initiator);
        let (addr, frame_id) = match d {
            Direction::Forward => (self.next_hop, self.forward_frame_id),
            Direction::Backward => (self.prev_hop, self.backward_frame_id),
        };
        send_close(frame_id, addr, self.socket.clone()).await;
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
