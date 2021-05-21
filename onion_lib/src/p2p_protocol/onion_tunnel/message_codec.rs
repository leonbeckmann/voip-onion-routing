use std::{mem::size_of, net::SocketAddr, sync::Arc};

use crate::p2p_protocol::{P2pError, PacketId, messages::p2p_messages};
use async_trait::async_trait;
use protobuf::Message;
use tokio::net::UdpSocket;

#[async_trait]
pub(crate) trait P2pCodec: std::fmt::Debug {
    async fn write_socket(&mut self, packet_id: PacketId, msg: &p2p_messages::TunnelFrame) -> Result<(), P2pError>;

    async fn from_raw(&mut self, raw: &[u8]) -> Result<p2p_messages::TunnelFrame, P2pError>;

    fn set_target(&mut self, source_target: Option<SocketAddr>);

    fn is_endpoint(&self) -> bool;
}

#[derive(Debug, Clone)]
pub(crate) struct PlainProtobuf {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) target: Option<SocketAddr>,
}

#[async_trait]
impl P2pCodec for PlainProtobuf {
    async fn write_socket(&mut self, packet_id: PacketId, msg: &p2p_messages::TunnelFrame) -> Result<(), P2pError> {
        let mut buf = packet_id.to_le_bytes().to_vec();
        buf.append(&mut msg.write_to_bytes().unwrap());
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
        let (_buf_packet_id, buf) = raw.split_at(size_of::<PacketId>());
        // let mut packet_id_buf_copy = [0u8; size_of::<PacketId>()];
        // packet_id_buf_copy.copy_from_slice(&buf[0..size_of::<PacketId>()]);
        // let packet_id = PacketId::from_le_bytes(packet_id_buf_copy);


        Ok(p2p_messages::TunnelFrame::parse_from_bytes(buf)?)
    }

    fn set_target(&mut self, target: Option<SocketAddr>) {
        self.target = target;
    }

    fn is_endpoint(&self) -> bool {
        self.target.is_none()
    }
}

pub(crate) fn start_endpoint_into_raw(
    msg: &p2p_messages::TunnelFrame,
) -> Result<Vec<u8>, P2pError> {
    let buf = msg.write_to_bytes().unwrap();
    Ok(buf)
}
