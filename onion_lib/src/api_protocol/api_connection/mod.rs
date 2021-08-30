use crate::api_protocol::event::{IncomingEvent, OutgoingEvent};
use crate::api_protocol::messages::OnionMessageHeader;
use crate::api_protocol::ConnectionId;
use ignore_result::Ignore;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::{Receiver, Sender};

static ID_COUNTER: AtomicU64 = AtomicU64::new(1);
fn get_id() -> ConnectionId {
    ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub struct Connection {
    pub(super) internal_id: ConnectionId,
    write_tx: Sender<OutgoingEvent>,
}

async fn read_event<T>(rx: &mut ReadHalf<T>) -> anyhow::Result<IncomingEvent>
where
    T: AsyncRead,
{
    // read message header
    let mut buf = [0u8; OnionMessageHeader::hdr_size()];
    rx.read_exact(&mut buf).await?;

    // parse buf the onion_msg_hdr
    let hdr = OnionMessageHeader::try_from(&buf)?;

    // read remaining message into buf without the hdr
    let mut buf = vec![0u8; hdr.size as usize - OnionMessageHeader::hdr_size()];
    rx.read_exact(&mut buf).await?;

    // parse to event via raw bytes from buf and onion header
    IncomingEvent::try_from((buf.to_vec(), hdr))
}

async fn write_event<T>(tx: &mut WriteHalf<T>, e: OutgoingEvent) -> anyhow::Result<()>
where
    T: AsyncWrite,
{
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

    pub(crate) async fn start<T>(
        &self,
        stream: T,
        read_tx: Sender<IncomingEvent>,
        mut write_rx: Receiver<OutgoingEvent>,
    ) where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
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
                        // This is unreachable, because `self` owns the sender half of write_rx and therefore the channel will never be closed.
                        #[cfg(not(tarpaulin_include))]
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
            tx.shutdown().await.ignore();
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
    use std::time::Duration;

    use tokio::{io::AsyncWriteExt, time::timeout};

    use crate::api_protocol::{
        self,
        api_connection::get_id,
        event::OutgoingEvent,
        messages::{OnionMessageHeader, OnionTunnelIncoming},
    };

    use super::Connection;

    #[test]
    fn unit_id_counter() {
        let v1 = get_id();
        let v2 = get_id();
        assert_ne!(v1, v2)
    }

    #[test]
    fn unit_api_connection() {
        // TODO: move test setup into single function for all tests
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            let (client, server) = tokio::io::duplex(64);
            let (tx_out, rx_out) = tokio::sync::mpsc::channel(16);
            let (tx_in, mut rx_in) = tokio::sync::mpsc::channel(16);

            let connection = Connection::new(tx_out.clone());
            connection.start(client, tx_in, rx_out).await;

            // In the following task 1 and 2 referes to the async tasks created in connection.start()

            // Assert boths tasks are running
            timeout(Duration::from_millis(50), tx_out.closed())
                .await
                .unwrap_err();
            timeout(Duration::from_millis(50), rx_in.recv())
                .await
                .unwrap_err();

            // Close API endpoint
            drop(server);
            // Check if the IncomingEvent sender closed to assert that task 2 exited
            assert!(timeout(Duration::from_secs(1), rx_in.recv())
                .await
                .unwrap()
                .is_none());
            // Check if the OutgoingEvent receiver is NOT closed to assert the task 1 is still running
            timeout(Duration::from_millis(50), tx_out.closed())
                .await
                .unwrap_err();
            // Send any event to task 1
            connection
                .write_event(OutgoingEvent::TunnelIncoming(OnionTunnelIncoming::new(2)))
                .await
                .unwrap();
            // The task 1 will forward the event to the closed API endpoint and exit due to this error
            // Check if the OutgoingEvent receiver closed to assert that task 1 exited
            timeout(Duration::from_secs(1), tx_out.closed())
                .await
                .unwrap();
        });
    }

    #[test]
    fn unit_api_connection2() {
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            let (client, mut server) = tokio::io::duplex(64);
            let (tx_out, rx_out) = tokio::sync::mpsc::channel(16);
            let (tx_in, mut rx_in) = tokio::sync::mpsc::channel(16);

            let connection = Connection::new(tx_out.clone());
            connection.start(client, tx_in, rx_out).await;

            // In the following task 1 and 2 referes to the async tasks created in connection.start()

            // Assert boths tasks are running
            timeout(Duration::from_millis(50), tx_out.closed())
                .await
                .unwrap_err();
            timeout(Duration::from_millis(50), rx_in.recv())
                .await
                .unwrap_err();

            // Close API receiver endpoint
            rx_in.close();
            // Send event to task 2
            let incoming_event: Vec<u8> = vec![0, 0, 4, 210, 127, 0, 0, 1, 107, 101, 121];
            let hdr = OnionMessageHeader::new(
                (incoming_event.len() + OnionMessageHeader::hdr_size()) as u16,
                api_protocol::ONION_TUNNEL_BUILD,
            )
            .to_be_vec();
            server.write_all(&hdr).await.unwrap();
            server.write_all(&incoming_event).await.unwrap();

            // Task 2 fails to forward the incoming event to the API and exits
            // Assert task 1 running, task 2 exited
            timeout(Duration::from_millis(50), tx_out.closed())
                .await
                .unwrap_err();
            assert!(timeout(Duration::from_secs(1), rx_in.recv())
                .await
                .unwrap()
                .is_none());
        });
    }

    #[test]
    fn unit_api_connection_invalid_onion_header() {
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            let (client, mut server) = tokio::io::duplex(64);
            let (tx_out, rx_out) = tokio::sync::mpsc::channel(16);
            let (tx_in, mut rx_in) = tokio::sync::mpsc::channel(16);

            let connection = Connection::new(tx_out.clone());
            connection.start(client, tx_in, rx_out).await;

            // In the following task 1 and 2 referes to the async tasks created in connection.start()

            // Assert boths tasks are running
            timeout(Duration::from_millis(50), tx_out.closed())
                .await
                .unwrap_err();
            timeout(Duration::from_millis(50), rx_in.recv())
                .await
                .unwrap_err();

            // Close API receiver endpoint
            rx_in.close();
            // Send event to task 2
            let incoming_event: Vec<u8> = vec![0, 0, 4, 210, 127, 0, 0, 1, 107, 101, 121];
            let mut hdr = OnionMessageHeader::new(
                (OnionMessageHeader::hdr_size()) as u16,
                api_protocol::ONION_TUNNEL_BUILD,
            )
            .to_be_vec();
            hdr[1] = 2;
            server.write_all(&hdr).await.unwrap();
            server.write_all(&incoming_event).await.unwrap();

            // Task 2 fails due to the substraction overflow and exits
            // Assert task 1 running, task 2 exited
            timeout(Duration::from_millis(50), tx_out.closed())
                .await
                .unwrap_err();
            assert!(timeout(Duration::from_secs(1), rx_in.recv())
                .await
                .unwrap()
                .is_none());
        });
    }
}
