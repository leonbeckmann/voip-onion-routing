mod messages;
mod onion_tunnel;

use crate::api_protocol::ApiInterface;
use crate::config_parser::OnionConfiguration;
use crate::p2p_protocol::onion_tunnel::OnionTunnel;
use std::{collections::HashMap, net::SocketAddr};
use tokio::sync::Mutex;
use std::sync::{Arc, Weak};
use thiserror::Error;
use tokio::net::UdpSocket;

// TODO: Configuration option
const PACKET_SIZE: usize = 1024;

pub type TunnelId = u32;
pub type ConnectionId = u64;

pub(crate) struct P2pInterface {
    // TODO is there a way for a more well-distributed key?
    onion_tunnels: Arc<Mutex<HashMap<TunnelId, OnionTunnel>>>,
    socket: Arc<UdpSocket>,
    _config: OnionConfiguration,
}

impl P2pInterface {
    pub(crate) async fn new(config: OnionConfiguration) -> anyhow::Result<Self> {
        Ok(Self {
            onion_tunnels: Arc::new(Mutex::new(HashMap::new())),
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
                        let _socket = self.socket.clone();
                        // TODO handle packet
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
    pub(crate) async fn build_tunnel(
        &self,
        target: SocketAddr,
        host_key: Vec<u8>,
    ) -> Result<(TunnelId, Vec<u8>), P2pError> {
        // TODO: return identity of the destination peer in DER format
        let mut onion_tunnels = self.onion_tunnels.lock().await;
        let mut tunnel_id: TunnelId = TunnelId::default();
        while onion_tunnels.contains_key(&tunnel_id) {
            tunnel_id += 1;
        }
        let tunnel = OnionTunnel::new(self.socket.clone(), target, host_key).await;
        onion_tunnels.insert(tunnel_id, tunnel);
        Ok((tunnel_id, vec![]))
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
        _tunnel_id: TunnelId,
        _data: Vec<u8>,
    ) -> Result<(), P2pError> {
        // TODO implement logic
        Ok(())
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
    InvalidTunnelEvent,
    #[error("Onion tunnel with ID '{0}': Timeout waiting for packet")]
    SocketResponseTimeout(u32),
    // #[error("Onion tunnel with ID '{0}': Invalid state transition")]
    // InvalidStateTransition(u32),
    #[error("IO Error: {0}")]
    IOError(std::io::Error),
    #[error("Error decoding protobuf message: {0}")]
    ProtobufError(protobuf::error::ProtobufError),
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
