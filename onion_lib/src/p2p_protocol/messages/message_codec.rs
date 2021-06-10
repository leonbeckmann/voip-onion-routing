use std::{net::SocketAddr, sync::Arc};

use crate::p2p_protocol::messages::p2p_messages::{
    ApplicationData, DecryptedHandshakeData, PlainHandshakeData, TunnelFrame,
};
use crate::p2p_protocol::onion_tunnel::fsm::ProtocolError;
use crate::p2p_protocol::{Direction, FrameId, TunnelId};
use async_trait::async_trait;
use bytes::Bytes;
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
    PlainHandshakeData(PlainHandshakeData),
    DecHandshakeData(DecryptedHandshakeData),
}

// TODO crypto context

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
    ) -> Result<ProcessedData, ProtocolError>;

    /*
     *  Send close messages to
     */
    async fn close(&mut self);

    /*
     *  Get the implementation of the trait for updating codecs
     */
    fn as_any(&self) -> &dyn Any;
}

#[derive(Debug, Clone)]
pub(crate) struct InitiatorEndpoint {
    socket: Arc<UdpSocket>,
    next_hop: SocketAddr,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    tunnel_id: TunnelId,
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
        }
    }
}

pub(crate) struct TargetEndpoint {
    socket: Arc<UdpSocket>,
    prev_hop: SocketAddr,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    tunnel_id: TunnelId,
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
        }
    }
}

pub(crate) struct IntermediateHop {
    socket: Arc<UdpSocket>,
    next_hop: SocketAddr,
    prev_hop: SocketAddr,
    frame_ids: Arc<Mutex<HashMap<FrameId, (TunnelId, Direction)>>>,
    tunnel_id: TunnelId,
}

// make target to intermediate
impl IntermediateHop {
    pub fn from(target: &TargetEndpoint, next_hop: SocketAddr) -> Self {
        Self {
            socket: target.socket.clone(),
            next_hop,
            prev_hop: target.prev_hop,
            frame_ids: target.frame_ids.clone(),
            tunnel_id: target.tunnel_id,
        }
    }
}

#[async_trait]
impl P2pCodec for InitiatorEndpoint {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        unimplemented!()
    }

    async fn process_data(
        &mut self,
        d: Direction,
        data: Bytes,
    ) -> Result<ProcessedData, ProtocolError> {
        unimplemented!()
    }

    async fn close(&mut self) {
        unimplemented!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl P2pCodec for TargetEndpoint {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        unimplemented!()
    }

    async fn process_data(
        &mut self,
        d: Direction,
        data: Bytes,
    ) -> Result<ProcessedData, ProtocolError> {
        unimplemented!()
    }

    async fn close(&mut self) {
        unimplemented!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl P2pCodec for IntermediateHop {
    async fn write(&mut self, data: DataType) -> Result<(), ProtocolError> {
        unimplemented!()
    }

    async fn process_data(
        &mut self,
        d: Direction,
        data: Bytes,
    ) -> Result<ProcessedData, ProtocolError> {
        unimplemented!()
    }

    async fn close(&mut self) {
        unimplemented!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/*
#[async_trait]
impl P2pCodec for PlainProtobuf {
    async fn write_socket(
        &mut self,
        packet_id: PacketId,
        msg: &p2p_messages::TunnelFrame,
    ) -> Result<(), P2pError> {
        let mut buf = vec![];

        let mut packet_id_buf = packet_id.to_le_bytes().to_vec();
        let mut packet_size_buf = PacketSize::default().to_le_bytes().to_vec();
        let mut msg_buf = msg.write_to_bytes().unwrap();

        let packet_size = packet_id_buf.len() + msg_buf.len() + packet_size_buf.len();
        packet_size_buf = (packet_size as PacketSize).to_le_bytes().to_vec();

        buf.append(&mut packet_id_buf);
        buf.append(&mut packet_size_buf);
        buf.append(&mut msg_buf);

        // Add padding
        assert!(buf.len() <= crate::p2p_protocol::PACKET_SIZE);
        buf.resize(crate::p2p_protocol::PACKET_SIZE, 0);

        let bytes_written = self
            .socket
            .send_to(
                &buf,
                self.target
                    .expect("Internal state error: Tunnel target must not be None"),
            )
            .await?;
        assert_eq!(bytes_written, buf.len());
        Ok(())
    }

    async fn from_raw(&mut self, raw: &[u8]) -> Result<p2p_messages::TunnelFrame, P2pError> {
        let (buf_packet_id, buf_size_msg_padding) = raw.split_at(size_of::<PacketId>());
        let (buf_size, buf_msg_padding) = buf_size_msg_padding.split_at(size_of::<PacketSize>());

        let mut packet_size = [0u8; size_of::<PacketSize>()];
        packet_size.copy_from_slice(&buf_size);
        let packet_size = PacketSize::from_le_bytes(packet_size);

        let (buf_msg, _buf_padding) =
            buf_msg_padding.split_at(packet_size as usize - buf_packet_id.len() - buf_size.len());

        Ok(p2p_messages::TunnelFrame::parse_from_bytes(buf_msg)?)
    }

}
*/
