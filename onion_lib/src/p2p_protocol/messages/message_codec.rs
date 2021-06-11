use std::{net::SocketAddr, sync::Arc};

use crate::p2p_protocol::messages::message_codec::ProcessedData::IncomingData;
use crate::p2p_protocol::messages::p2p_messages::{
    ApplicationData, ClientHello, Close, DecryptedHandshakeData, HandshakeData, PlainHandshakeData,
    ServerHello, TunnelFrame,
};
use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
use crate::p2p_protocol::{Direction, FrameId, TunnelId, PACKET_SIZE};
use async_trait::async_trait;
use bytes::Bytes;
use protobuf::Message;
use std::any::Any;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub enum ProcessedData {
    TransferredToNextHop,
    IncomingData(Vec<u8>),
}

pub enum DataType {
    AppData(Vec<u8>),
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    DecHandshakeData(DecryptedHandshakeData),
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
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    my_frames: &[(FrameId, Direction)],
) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut frame_ids = frame_ids.lock().await;
        for (id, _) in my_frames.iter() {
            let _ = frame_ids.remove(id);
        }
    });
}

async fn send_close(frame_id: FrameId, addr: SocketAddr, socket: Arc<UdpSocket>) {
    let mut frame = TunnelFrame::new();
    frame.set_frameId(frame_id);
    let close = Close::new();
    // TODO padding
    frame.set_close(close);
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

                // TODO padding

                let data = app_data.write_to_bytes().unwrap();

                // TODO encrypt via iv and keys
                data
            }
            DataType::ClientHello(mut client_hello) => {
                // calculate frame_id
                let new_id =
                    new_frame_id(self.tunnel_id, Direction::Backward, self.frame_ids.clone()).await;
                self.own_frame_ids.push((new_id, Direction::Backward));
                client_hello.set_backwardFrameId(new_id);

                // prepare frame
                let mut plain_handshake = PlainHandshakeData::new();
                plain_handshake.set_clientHello(client_hello);

                // TODO padding

                let mut handshake_data = HandshakeData::new();
                handshake_data.set_handshakeData(plain_handshake);
                let data = handshake_data.write_to_bytes().unwrap();

                // TODO encrypt via iv and keys
                data
            }
            DataType::DecHandshakeData(data) => {
                // TODO padding
                let data = data.write_to_bytes().unwrap();

                // TODO encrypt using iv and keys
                data
            }
            _ => {
                log::warn!("Invalid write action in initiator codec");
                return Err(ProtocolError::CodecUnsupportedAction);
            }
        };

        frame.set_data(Bytes::from(ready_bytes));
        let data = frame.write_to_bytes().unwrap();

        if data.len() != PACKET_SIZE {
            return Err(ProtocolError::CodecPaddingError);
        }

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
        // expected incoming data backwards, process and return
        // TODO decrypt using keys and iv

        match ApplicationData::parse_from_bytes(data.as_ref()) {
            Ok(data) => Ok(IncomingData(data.data.to_vec())),
            Err(_) => Err(ProtocolError::ProtobufError),
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

                // TODO padding

                let data = app_data.write_to_bytes().unwrap();

                // TODO encrypt via iv and key
                data
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
                let mut plain_handshake = PlainHandshakeData::new();
                plain_handshake.set_serverHello(server_hello);

                // TODO padding

                let mut handshake_data = HandshakeData::new();
                handshake_data.set_handshakeData(plain_handshake);
                handshake_data.write_to_bytes().unwrap()
            }
            _ => {
                log::warn!("Invalid write action in target codec");
                return Err(ProtocolError::CodecUnsupportedAction);
            }
        };

        frame.set_data(Bytes::from(ready_bytes));
        let data = frame.write_to_bytes().unwrap();

        if data.len() != PACKET_SIZE {
            return Err(ProtocolError::CodecPaddingError);
        }

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
        _data: Bytes,
        _iv: IV,
    ) -> Result<ProcessedData, ProtocolError> {
        // TODO expect incoming data forward, process and return
        unimplemented!()
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
        if d == Direction::Backward && self.forward_frame_id == 1 {
            // seems to be the unencrypted server_hello of the next hop, catch the forward id
            match PlainHandshakeData::parse_from_bytes(data.as_ref()) {
                Ok(plain) => {
                    if !plain.has_serverHello() {
                        return Err(ProtocolError::UnexpectedMessageType);
                    }
                    let id = plain.get_serverHello().get_forwardFrameId();
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

        if data.len() != PACKET_SIZE {
            return Err(ProtocolError::CodecPaddingError);
        }

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
