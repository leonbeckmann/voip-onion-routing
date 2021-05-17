use std::{net::SocketAddr, sync::Arc};

use protobuf::Message;
use tokio::net::UdpSocket;
use async_trait::async_trait;
use crate::p2p_protocol::{P2pError, messages::p2p_messages};

#[async_trait]
pub(crate) trait P2pCodec: std::fmt::Debug {
    async fn write_socket(&mut self, msg: &p2p_messages::TunnelFrame) -> Result<(), P2pError>;

    async fn from_raw(&mut self, raw: &[u8]) -> Result<p2p_messages::TunnelFrame, P2pError>;
}

#[derive(Debug, Clone)]
pub(crate) struct PlainProtobuf {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) target: SocketAddr,
}

#[async_trait]
impl P2pCodec for PlainProtobuf {
    async fn write_socket(&mut self, msg: &p2p_messages::TunnelFrame) -> Result<(), P2pError> {
        let buf = msg.write_to_bytes().unwrap();
        let bytes_written = self.socket.send_to(&buf, self.target).await?;
        assert_eq!(bytes_written, buf.len());
        Ok(())
    }

    async fn from_raw(&mut self, raw: &[u8]) -> Result<p2p_messages::TunnelFrame, P2pError> {
        Ok(p2p_messages::TunnelFrame::parse_from_bytes(raw)?)
    }
}
