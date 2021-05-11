use crate::api_protocol::ApiInterface;
use crate::config_parser::OnionConfiguration;
use std::net::IpAddr;
use std::sync::Weak;

pub(crate) struct P2pInterface {
    // TODO Onion tunnels
}

impl P2pInterface {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) async fn listen(
        &self,
        _config: OnionConfiguration,
        _api_interface: Weak<ApiInterface>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /*
     * Unsubscribe connection from all tunnels due to connection closure
     */
    pub(crate) fn unsubscribe(&self, _connection_id: u64) {
        //TODO call unsubscribe on all tunnels
    }

    /*
     * Build a new onion tunnel
     */
    pub(crate) async fn build_tunnel(&self, _ip: IpAddr, _port: u16, _host_key: Vec<u8>) {}

    /*
     * Unsubscribe connection from specific tunnel
     */
    pub(crate) fn destroy_tunnel_ref(&self, _tunnel_id: u32, _connection_id: u64) {
        // TODO call unsubscribe on specific tunnel
    }

    /*
     * Send data via specific tunnel
     */
    pub(crate) async fn send_data(&self, _tunnel_ids: u32, _data: Vec<u8>) {}

    /*
     * Send cover traffic via new random tunnel
     */
    pub(crate) async fn send_cover_traffic(&self, _cover_size: u16) {}
}
