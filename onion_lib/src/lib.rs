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

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use ini::Ini;
    use openssl::rsa::Rsa;
    use pin_utils::pin_mut;
    use tempdir::TempDir;

    use crate::{run_peer, run_peer_async};

    #[test]
    fn unit_invalid_config() {
        let dir = TempDir::new("onion-test").unwrap();
        let invalid_config_file = dir.path().join("invalid.ini");

        let mut config = Ini::new();
        // we have to add a dummy value within the general_section, otherwise the library function panics
        config.with_general_section().set("dummy", "dummy");
        config.write_to_file(&invalid_config_file).unwrap();

        run_peer(invalid_config_file);
    }

    async fn run_valid_peer(dir: &TempDir, p2p_port: &str, api_port: &str) -> tokio::task::JoinHandle<()> {
        let key_file = dir.path().join("peer.key");
        let priv_key_file = dir.path().join("peer_priv.key");
        // create RSA keys
        let key = Rsa::generate(4096).unwrap();
        let pub_pem = key.public_key_to_pem().unwrap();
        let priv_pem = key.private_key_to_pem().unwrap();

        let mut rsa_pem = File::create(&key_file).unwrap();
        rsa_pem.write_all(pub_pem.as_slice()).unwrap();
        rsa_pem.sync_all().unwrap();
        let mut rsa_priv_pem = File::create(&priv_key_file).unwrap();
        rsa_priv_pem.write_all(priv_pem.as_slice()).unwrap();
        rsa_priv_pem.sync_all().unwrap();

        let config_file = dir.path().join("config.ini");

        let mut config = Ini::new();
        config
            .with_general_section()
            .set("hostkey", key_file.to_str().unwrap());
        config
            .with_section(Some("onion"))
            .set("p2p_port", p2p_port)
            .set("p2p_hostname", "127.0.0.1")
            .set("hop_count", "2")
            .set("api_address", format!("127.0.0.1:{}", api_port).as_str())
            .set("round_time", "5")
            .set("private_hostkey", priv_key_file.to_str().unwrap())
            .set("handshake_timeout", "3000");
        config
            .with_section(Some("rps"))
            .set("api_address", "127.0.0.1:8000");
        config.write_to_file(&config_file).unwrap();

        // run peer
        tokio::task::spawn(run_peer_async(config_file))
    }

    #[test]
    fn unit_valid_config() {
        let dir = TempDir::new("onion-test").unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let peer = run_valid_peer(&dir, "2000", "3001");
            // This should timeout because it's valid
            // TODO: fix and use unwrap_err() here
            tokio::time::timeout(std::time::Duration::from_secs(1), peer)
                .await
                .unwrap();
        });
    }

    #[test]
    fn unit_multiple_with_same_p2p_port() {
        let dir = TempDir::new("onion-test").unwrap();
        let peer1 = run_valid_peer(&dir, "2000", "3000");
        let peer2 = run_valid_peer(&dir, "2000", "3001");
        // Pin that it can be passed by reference to timeout and is usable afterwards.
        pin_mut!(peer1);
        pin_mut!(peer2);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // This should timeout because it's valid
            // TODO: fix and use unwrap_err() here
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer1)
                .await
                .unwrap();
            // This should not timeout because port is already used
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer2)
                .await
                .unwrap();
        });
    }

    #[test]
    fn unit_multiple_with_same_api_port() {
        let dir = TempDir::new("onion-test").unwrap();
        let peer1 = run_valid_peer(&dir, "2000", "3000");
        let peer2 = run_valid_peer(&dir, "2001", "3000");
        // Pin that it can be passed by reference to timeout and is usable afterwards.
        pin_mut!(peer1);
        pin_mut!(peer2);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // This should timeout because it's valid
            // TODO: fix and use unwrap_err() here
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer1)
                .await
                .unwrap();
            // This should not timeout because port is already used
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer2)
                .await
                .unwrap();
        });
    }
}
// TODO test running a peer with valid config, shutdown api and p2p protocol
