mod messages;
mod onion_tunnel;

use crate::api_protocol::ApiInterface;
use crate::config_parser::OnionConfiguration;
use crate::p2p_protocol::onion_tunnel::OnionTunnel;
use std::sync::{Arc, Weak};
use std::{collections::HashMap, mem::size_of, net::SocketAddr};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

// TODO: Configuration option
pub(crate) const PACKET_SIZE: usize = 1024;

pub type TunnelId = u32;
pub type ConnectionId = u64;
type PacketId = u32;

pub(crate) struct P2pInterface {
    // TODO is there a way for a more well-distributed key?
    onion_tunnels: Mutex<HashMap<TunnelId, OnionTunnel>>,
    packet_ids: Arc<Mutex<HashMap<PacketId, TunnelId>>>,
    socket: Arc<UdpSocket>,
    _config: OnionConfiguration,
}

impl P2pInterface {
    pub(crate) async fn new(config: OnionConfiguration) -> anyhow::Result<Self> {
        Ok(Self {
            onion_tunnels: Mutex::new(HashMap::new()),
            packet_ids: Arc::new(Mutex::new(HashMap::new())),
            socket: Arc::new(
                UdpSocket::bind(format!("{}:{:?}", config.p2p_hostname, config.p2p_port)).await?,
            ),
            _config: config,
        })
    }

    pub(crate) async fn listen(&self, _api_interface: Weak<ApiInterface>) -> anyhow::Result<()> {
        // Allow to receive more than expected to detect messages exceeding the fixed size.
        // Otherwise recv_from would silently discards exceeding bytes.
        let mut buf = [0u8; PACKET_SIZE + 1];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, addr)) => {
                    if size == PACKET_SIZE {
                        log::debug!("Received UDP packet with valid length from {:?}", addr);

                        let mut packet_id_buf_copy = [0u8; size_of::<PacketId>()];
                        packet_id_buf_copy.copy_from_slice(&buf[0..size_of::<PacketId>()]);

                        let packet_id = PacketId::from_le_bytes(packet_id_buf_copy);

                        let mut packet_ids = self.packet_ids.lock().await;
                        let mut tunnel_id = packet_ids.remove(&packet_id);
                        drop(packet_ids); // unlock mutex

                        let mut tunnels = self.onion_tunnels.lock().await;
                        let onion_tunnel = match tunnel_id {
                            Some(tunnel_id) => tunnels.get(&tunnel_id).unwrap(),
                            None => {
                                // unlock mutex for build function, then lock it again
                                drop(tunnels);
                                let (new_tunnel_id, _) = self
                                    .build_tunnel_impl(Some(addr), None, vec![], false)
                                    .await?;
                                tunnels = self.onion_tunnels.lock().await;
                                tunnel_id = Some(new_tunnel_id);
                                tunnels.get(&new_tunnel_id).unwrap()
                            }
                        };

                        let res = onion_tunnel.forward_packet(buf.to_vec()).await;
                        if res.is_err() {
                            tunnels.remove(&tunnel_id.unwrap()); // Safe unwrap
                        }
                    } else {
                        // Drop packet with invalid size
                        log::warn!(
                            "Dropping received UDP packet from {:?} because of packet size",
                            addr
                        );
                    }
                }
                Err(e) => {
                    // TODO do we always want to quit here?
                    log::error!("Cannot read from UDP socket {}", e);
                    return Err(anyhow::Error::from(e));
                }
            };
        }
    }

    /// Unsubscribe connection from all tunnels due to connection closure
    pub(crate) async fn unsubscribe(&self, connection_id: ConnectionId) -> Result<(), P2pError> {
        // call unsubscribe on all tunnels
        let mut onion_tunnels = self.onion_tunnels.lock().await;
        for (_, b) in onion_tunnels.iter_mut() {
            b.unsubscribe(connection_id);
        }
        Ok(())
    }

    /// Build a new onion tunnel
    ///
    /// Return the new tunnel_id and the identity of the destination peer in DER format
    async fn build_tunnel_impl(
        &self,
        source: Option<SocketAddr>,
        target: Option<SocketAddr>,
        host_key: Vec<u8>,
        start_endpoint: bool,
    ) -> Result<(TunnelId, Vec<u8>), P2pError> {
        // TODO: return identity of the destination peer in DER format
        let mut onion_tunnels = self.onion_tunnels.lock().await;
        let mut tunnel_id: TunnelId = TunnelId::default();
        while onion_tunnels.contains_key(&tunnel_id) {
            tunnel_id += 1;
        }
        let tunnel = OnionTunnel::new(
            self.packet_ids.clone(),
            tunnel_id,
            self.socket.clone(),
            source,
            target,
            host_key,
            start_endpoint,
        )
        .await;
        onion_tunnels.insert(tunnel_id, tunnel);
        Ok((tunnel_id, vec![]))
    }

    pub(crate) async fn build_tunnel(
        &self,
        target: SocketAddr,
        host_key: Vec<u8>,
    ) -> Result<(TunnelId, Vec<u8>), P2pError> {
        self.build_tunnel_impl(None, Some(target), host_key, true)
            .await
    }

    /// Unsubscribe connection from specific tunnel
    pub(crate) async fn destroy_tunnel_ref(
        &self,
        tunnel_id: TunnelId,
        connection_id: ConnectionId,
    ) -> Result<(), P2pError> {
        // call unsubscribe on specific tunnel
        let mut onion_tunnels = self.onion_tunnels.lock().await;
        match onion_tunnels.get_mut(&tunnel_id) {
            None => Err(P2pError::InvalidTunnelId(tunnel_id)),
            Some(tunnel) => {
                tunnel.unsubscribe(connection_id);
                Ok(())
            }
        }
    }

    /// Send data via specific tunnel
    pub(crate) async fn send_data(
        &self,
        tunnel_id: TunnelId,
        data: Vec<u8>,
    ) -> Result<(), P2pError> {
        let tunnels = self.onion_tunnels.lock().await;
        let tunnel = tunnels.get(&tunnel_id);

        match tunnel {
            Some(tunnel) => tunnel.forward_packet(data).await,
            None => {
                log::error!(
                    "Trying to send data through invalid tunnel id: {}",
                    tunnel_id
                );
                Err(P2pError::InvalidTunnelId(tunnel_id))
            }
        }
    }

    /// Send cover traffic via new random tunnel
    pub(crate) async fn send_cover_traffic(&self, _cover_size: u16) -> Result<(), P2pError> {
        // TODO implement logic
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum P2pError {
    #[error("Onion tunnel with ID '{0}' is not existent")]
    InvalidTunnelId(u32),
    #[error("Onion tunnel event invalid")]
    _InvalidTunnelEvent,
    #[error("Onion tunnel with ID '{0}': Timeout waiting for packet")]
    SocketResponseTimeout(u32),
    // #[error("Onion tunnel with ID '{0}': Invalid state transition")]
    // InvalidStateTransition(u32),
    #[error("IO Error: {0}")]
    IOError(std::io::Error),
    #[error("Onion tunnel closed")]
    TunnelClosed,
    #[error("Error decoding protobuf message: {0}")]
    ProtobufError(protobuf::error::ProtobufError),
    #[error("Invalid protobuf frame content: {0}")]
    FrameError(String),
    #[error("Event queue closed unexpectely")]
    EventQueueClosed,
}

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> Self {
        Self::IOError(e)
    }
}

impl From<protobuf::error::ProtobufError> for P2pError {
    fn from(e: protobuf::error::ProtobufError) -> Self {
        Self::ProtobufError(e)
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    #[test]
    fn unit_test() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:2000").await.unwrap();
            let client = UdpSocket::bind("127.0.0.1:2001").await.unwrap();

            client.connect("127.0.0.1:2000").await.unwrap();
            client.send("Data".as_bytes()).await.unwrap();

            let mut buf = [0u8; 3];
            let (size, _addr) = socket.recv_from(&mut buf).await.unwrap();
            println!("{:?}", size);
        });
    }
}
