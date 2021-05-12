mod onion_tunnel;

use crate::api_protocol::ApiInterface;
use crate::config_parser::OnionConfiguration;
use crate::p2p_protocol::onion_tunnel::OnionTunnel;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::thread::sleep;
use std::time::Duration;
use thiserror::Error;

pub(crate) struct P2pInterface {
    // TODO is there a way for a more well-distributed key?
    onion_tunnels: Arc<Mutex<HashMap<u32, OnionTunnel>>>,
}

impl P2pInterface {
    pub(crate) fn new() -> Self {
        Self {
            onion_tunnels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn listen(
        &self,
        _config: OnionConfiguration,
        _api_interface: Weak<ApiInterface>,
    ) -> anyhow::Result<()> {
        // TODO implement logic
        Ok(())
    }

    /*
     * Unsubscribe connection from all tunnels due to connection closure
     */
    pub(crate) fn unsubscribe(&self, connection_id: u64) -> Result<(), P2pError> {
        // call unsubscribe on all tunnels
        match self.onion_tunnels.lock() {
            Ok(mut guard) => {
                for (_, b) in guard.iter_mut() {
                    b.unsubscribe(connection_id);
                }
                Ok(())
            }
            Err(_) => Err(P2pError::OnionTunnelLockFailed),
        }
    }

    /*
     * Build a new onion tunnel
     *
     * Return the new tunnel_id and the identity of the destination peer in DER format
     */
    pub(crate) async fn build_tunnel(
        &self,
        _ip: IpAddr,
        _port: u16,
        _host_key: Vec<u8>,
    ) -> Result<(u32, Vec<u8>), P2pError> {
        // TODO implement logic
        Ok((1, vec![]))
    }

    /*
     * Unsubscribe connection from specific tunnel
     */
    pub(crate) fn destroy_tunnel_ref(
        &self,
        tunnel_id: u32,
        connection_id: u64,
    ) -> Result<(), P2pError> {
        // call unsubscribe on specific tunnel
        match self.onion_tunnels.lock() {
            Ok(mut guard) => match guard.get_mut(&tunnel_id) {
                None => Err(P2pError::InvalidTunnelId(tunnel_id)),
                Some(tunnel) => {
                    tunnel.unsubscribe(connection_id);
                    Ok(())
                }
            },
            Err(_) => Err(P2pError::OnionTunnelLockFailed),
        }
    }

    /*
     * Send data via specific tunnel
     */
    pub(crate) async fn send_data(&self, _tunnel_ids: u32, _data: Vec<u8>) -> Result<(), P2pError> {
        // TODO implement logic
        Ok(())
    }

    /*
     * Send cover traffic via new random tunnel
     */
    pub(crate) async fn send_cover_traffic(&self, _cover_size: u16) -> Result<(), P2pError> {
        // TODO implement logic
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum P2pError {
    #[error("Cannot acquire lock for onion tunnels")]
    OnionTunnelLockFailed,
    #[error("Onion tunnel with ID '{0}' is not existent")]
    InvalidTunnelId(u32),
}
