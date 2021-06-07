use std::{mem::size_of, net::SocketAddr, sync::Arc};

use crate::p2p_protocol::{messages::p2p_messages, P2pError, PacketId};
use async_trait::async_trait;
use protobuf::Message;
use tokio::net::UdpSocket;

type PacketSize = u32;

#[async_trait]
pub(crate) trait P2pCodec: std::fmt::Debug {
    async fn write_socket(
        &mut self,
        packet_id: PacketId,
        msg: &p2p_messages::TunnelFrame,
    ) -> Result<(), P2pError>;

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
