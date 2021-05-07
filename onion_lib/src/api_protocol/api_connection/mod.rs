use crate::api_protocol::event::IncomingEvent;
use crate::api_protocol::messages::OnionMessageHeader;
use std::convert::TryFrom;
use tokio::io::AsyncReadExt;
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
        let mut buf = vec![0u8; hdr.size() as usize - OnionMessageHeader::hdr_size()];
        self.stream.read_exact(&mut buf).await?;

        // parse to event via raw bytes from buf and onion header
        IncomingEvent::try_from((buf.to_vec(), hdr))
    }
}
