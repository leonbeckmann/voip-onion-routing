use crate::api_protocol::event::{IncomingEvent, OutgoingEvent};
use crate::api_protocol::messages::OnionMessageHeader;
use std::convert::TryFrom;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Connection {
    stream: TcpStream,
}

impl Connection {
    pub(crate) fn new(stream: TcpStream) -> Connection {
        Connection { stream }
    }

    pub(crate) async fn read_event(&mut self) -> anyhow::Result<IncomingEvent> {
        // read message header
        let mut buf = [0u8; OnionMessageHeader::hdr_size()];
        self.stream.read_exact(&mut buf).await?;

        // parse buf the onion_msg_hdr
        let hdr = OnionMessageHeader::from(&buf);

        // read remaining message into buf without the hdr
        let mut buf = vec![0u8; hdr.size as usize - OnionMessageHeader::hdr_size()];
        self.stream.read_exact(&mut buf).await?;

        // parse to event via raw bytes from buf and onion header
        IncomingEvent::try_from((buf.to_vec(), hdr))
    }

    pub(crate) async fn write_event(&mut self, e: OutgoingEvent) -> anyhow::Result<()> {
        // parse event to raw
        let msg_type = match e {
            OutgoingEvent::TunnelReady(_) => super::ONION_TUNNEL_READY,
            OutgoingEvent::TunnelIncoming(_) => super::ONION_TUNNEL_INCOMING,
            OutgoingEvent::TunnelData(_) => super::ONION_TUNNEL_DATA,
            OutgoingEvent::Error(_) => super::ONION_ERROR,
        };
        let raw: Vec<u8> = e.into();
        let hdr = OnionMessageHeader::new(raw.len() as u16, msg_type).to_be_vec();

        self.stream.write_all(&hdr).await?;
        self.stream.write_all(&raw).await?;

        Ok(())
    }
}
