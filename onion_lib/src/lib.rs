pub mod api_protocol;
mod config_parser;
pub mod p2p_protocol;

use std::path::Path;

use config_parser::OnionConfiguration;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::select;

pub fn run_peer<P: AsRef<Path> + Debug>(config_file: P) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(run_peer_async(config_file))
}

async fn run_peer_async<P: AsRef<Path> + Debug>(config_file: P) {
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
    let p2p_interface_strong_ref = p2p_interface.clone();

    let api_address = config.onion_api_address;

    // run p2p listener
    let p2p_listener = tokio::spawn(async move {
        log::info!(
            "Run p2p listener ({}:{:?}) ...",
            config.p2p_hostname,
            config.p2p_port
        );
        if let Err(e) = p2p_interface.listen(p2p_interface_strong_ref).await {
            log::error!("P2P listener has failed: {:?}", e);
        }

        // shutdown peer
        log::debug!("Shutdown P2P interface");
    });

    // run API connection listener
    let api_listener = tokio::spawn(async move {
        log::info!("Run API listener ({:?}) ...", api_address);
        if let Err(e) = api_interface.listen(api_address, p2p_interface_ref).await {
            log::error!("API connection listener has failed: {}", e);
        }

        // shutdown peer
        log::debug!("Shutdown API interface");
    });

    // To terminate the runtime when one of the protocols fails at any point, this
    // waits for both tasks concurrently. When the first task is completed, the other task will be cancelled.
    select! {
        _ = p2p_listener => (),
        _ = api_listener => (),
    };

    log::debug!("Shutdown peer");
}

        // block threat without using CPU time
        let (lock, c_var) = &*close_cond;
        let mut is_closed = lock.lock().unwrap();
        while !*is_closed {
            is_closed = c_var.wait(is_closed).unwrap();
        }
        log::debug!("Shutdown peer");
    });
}

#[cfg(test)]
mod tests {}
// TODO test running a peer with valid config, invalid config, shutdown api and p2p protocol
