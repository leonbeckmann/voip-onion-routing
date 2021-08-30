use crate::api_protocol::event::{IncomingEvent, OutgoingEvent};
use crate::api_protocol::messages::OnionMessageHeader;
use crate::api_protocol::ConnectionId;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};

static ID_COUNTER: AtomicU64 = AtomicU64::new(1);
fn get_id() -> ConnectionId {
    ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub struct Connection {
    pub(super) internal_id: ConnectionId,
    write_tx: Sender<OutgoingEvent>,
}

async fn read_event(rx: &mut ReadHalf<TcpStream>) -> anyhow::Result<IncomingEvent> {
    // read message header
    let mut buf = [0u8; OnionMessageHeader::hdr_size()];
    rx.read_exact(&mut buf).await?;

    // parse buf the onion_msg_hdr
    let hdr = OnionMessageHeader::from(&buf);

    // Substraction overflow possible in line below this check:
    // hdr.size remote controlled, OnionMessageHeader::hdr_size() static
    if (hdr.size as usize) < OnionMessageHeader::hdr_size() {
        return Err(anyhow::Error::msg(
            "Given packet size in OnionMessageHeader less than sizeof OnionMessageHeader",
        ));
    }
    // read remaining message into buf without the hdr
    let mut buf = vec![0u8; hdr.size as usize - OnionMessageHeader::hdr_size()];
    rx.read_exact(&mut buf).await?;

    // parse to event via raw bytes from buf and onion header
    IncomingEvent::try_from((buf.to_vec(), hdr))
}

async fn write_event(tx: &mut WriteHalf<TcpStream>, e: OutgoingEvent) -> anyhow::Result<()> {
    // parse event to raw
    let msg_type = match e {
        OutgoingEvent::TunnelReady(_) => super::ONION_TUNNEL_READY,
        OutgoingEvent::TunnelIncoming(_) => super::ONION_TUNNEL_INCOMING,
        OutgoingEvent::TunnelData(_) => super::ONION_TUNNEL_DATA,
        OutgoingEvent::Error(_) => super::ONION_ERROR,
    };
    let raw: Vec<u8> = e.into();
    let hdr = OnionMessageHeader::new(
        (raw.len() + OnionMessageHeader::hdr_size()) as u16,
        msg_type,
    )
    .to_be_vec();

    tx.write_all(&hdr).await?;
    tx.write_all(&raw).await?;

    Ok(())
}

impl Connection {
    pub(crate) fn new(write_tx: Sender<OutgoingEvent>) -> Connection {
        Connection {
            internal_id: get_id(),
            write_tx,
        }
    }

    pub(crate) async fn write_event(&self, e: OutgoingEvent) -> anyhow::Result<()> {
        self.write_tx.send(e).await?;
        Ok(())
    }

    pub(crate) async fn start(
        &self,
        stream: TcpStream,
        read_tx: Sender<IncomingEvent>,
        mut write_rx: Receiver<OutgoingEvent>,
    ) {
        log::trace!(
            "Connection={:?}: Start the connection listeners",
            self.internal_id
        );
        let (mut rx, mut tx) = tokio::io::split(stream);
        let id = self.internal_id;

        // run sender component outgoing
        tokio::spawn(async move {
            loop {
                match write_rx.recv().await {
                    None => {
                        // sender side was closed by api_protocol
                        break;
                    }
                    Some(e) => {
                        if let Err(e) = write_event(&mut tx, e).await {
                            log::warn!(
                                "Connection={:?}: Cannot send outgoing event via TCP : {}",
                                id,
                                e
                            );
                            break;
                        }
                    }
                }
            }
            log::trace!("Connection={:?}: Close SenderHalf", id);
            let _ = tx.shutdown();
            write_rx.close();
        });

        // run receiver component incoming
        tokio::spawn(async move {
            loop {
                match read_event(&mut rx).await {
                    Ok(e) => {
                        if read_tx.send(e).await.is_err() {
                            // receiver side was closed by api protocol
                            break;
                        }
                    }
                    Err(e) => {
                        log::warn!("Connection={:?}: Cannot read event from TCP: {}", id, e);
                        break;
                    }
                }
            }
            log::trace!("Connection={:?}: Close ReaderHalf", id);
            drop(rx);
            drop(read_tx);
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::api_protocol::api_connection::get_id;

    #[test]
    fn unit_id_counter() {
        let v1 = get_id();
        let v2 = get_id();
        assert_ne!(v1, v2)
    }
}
