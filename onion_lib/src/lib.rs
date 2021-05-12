extern crate anyhow;
extern crate tokio;

pub mod api_protocol;
mod config_parser;
mod p2p_protocol;

use std::path::Path;

use config_parser::OnionConfiguration;
use std::fmt::Debug;
use std::sync::Arc;

pub fn run_peer<P: AsRef<Path> + Debug>(config_file: P) {
    // parse config file
    log::debug!("Parse config file from {:?}", config_file);
    let config = match OnionConfiguration::parse_from_file(config_file) {
        Ok(config) => {
            log::debug!("Peer configuration: {:?}", config);
            config
        }
        Err(e) => {
            log::error!("Cannot parse config file: {}", e);
            return;
        }
    };

    // run async
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let api_interface = Arc::new(api_protocol::ApiInterface::new());
        let p2p_interface = Arc::new(p2p_protocol::P2pInterface::new());
        let api_interface_ref = Arc::downgrade(&api_interface);
        let p2p_interface_ref = Arc::downgrade(&p2p_interface);

        let api_address = config.onion_api_address;

        // run p2p listener
        tokio::spawn(async move {
            log::info!(
                "Run p2p listener ({}:{:?}) ...",
                config.p2p_hostname,
                config.p2p_port
            );
            if let Err(e) = p2p_interface.listen(config, api_interface_ref).await {
                log::error!("Cannot start P2P listener: {}", e);
                return;
            }
        });

        // run API connection listener
        log::info!("Run API listener ({:?}) ...", api_address);
        if let Err(e) = api_interface.listen(api_address, p2p_interface_ref).await {
            log::error!("Cannot start API connection listener: {}", e);
            return;
        }
    });
}

#[cfg(test)]
mod tests {}
