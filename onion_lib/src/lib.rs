pub mod api_protocol;
mod config_parser;
mod p2p_protocol;

use std::path::Path;

use config_parser::OnionConfiguration;
use std::fmt::Debug;
use std::sync::{Arc, Condvar, Mutex};

#[allow(clippy::mutex_atomic)]
pub fn run_peer<P: AsRef<Path> + Debug>(config_file: P) {
    // parse config file
    log::debug!("Parse config file from {:?}", config_file);
    let config = match OnionConfiguration::parse_from_file(config_file) {
        Ok(config) => {
            log::info!("Peer configuration: {:?}", config);
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
        let api_interface_ref = Arc::downgrade(&api_interface);

        let p2p_interface =
            match p2p_protocol::P2pInterface::new(config.clone(), api_interface_ref).await {
                Ok(iface) => Arc::new(iface),
                Err(e) => {
                    log::error!("Cannot start P2P interface: {}", e);
                    return;
                }
            };
        let p2p_interface_ref = Arc::downgrade(&p2p_interface);

        let api_address = config.onion_api_address;

        // we need a condvar to terminate the runtime when one of the protocols fails at any point
        let close_cond = Arc::new((Mutex::new(false), Condvar::new()));
        let close_cond_api = close_cond.clone();
        let close_cond_p2p = close_cond.clone();

        // run p2p listener
        tokio::spawn(async move {
            log::info!(
                "Run p2p listener ({}:{:?}) ...",
                config.p2p_hostname,
                config.p2p_port
            );
            if let Err(e) = p2p_interface.listen().await {
                log::error!("P2P listener has failed: {:?}", e);
            }

            // shutdown peer
            let (lock, c_var) = &*close_cond_p2p;
            let mut is_closed = lock.lock().unwrap();
            *is_closed = true;
            c_var.notify_one();
        });

        // run API connection listener
        tokio::spawn(async move {
            log::info!("Run API listener ({:?}) ...", api_address);
            if let Err(e) = api_interface.listen(api_address, p2p_interface_ref).await {
                log::error!("API connection listener has failed: {}", e);
            }

            // shutdown peer
            let (lock, c_var) = &*close_cond_api;
            let mut is_closed = lock.lock().unwrap();
            *is_closed = true;
            c_var.notify_one();
        });

        // block threat without using CPU time
        let (lock, c_var) = &*close_cond;
        let mut is_closed = lock.lock().unwrap();
        while !*is_closed {
            is_closed = c_var.wait(is_closed).unwrap();
        }
    });
}

#[cfg(test)]
mod tests {}
// TODO test running a peer with valid config, invalid config, shutdown api and p2p protocol
