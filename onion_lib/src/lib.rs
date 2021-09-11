pub mod api_protocol;
mod config_parser;
pub mod p2p_protocol;

use std::path::Path;

use config_parser::OnionConfiguration;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::select;

// Enable trace logging for all tests when coverage is enabled
#[cfg(all(test, coverage))]
#[ctor::ctor]
fn init() {
    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .parse_filters("trace")
        .try_init()
        .unwrap();
}

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
    use std::{fs::File, io::Write, time::Duration};

    use ini::Ini;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509Builder, X509Name},
    };
    use pin_utils::pin_mut;
    use tempdir::TempDir;

    use crate::{config_parser::create_config_file, run_peer, run_peer_async};

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

    fn run_valid_peer(
        dir: &TempDir,
        p2p_port: &str,
        api_port: &str,
    ) -> tokio::task::JoinHandle<()> {
        // create paths for host-key and config files
        let host_key_file = dir.path().join("hostkey");
        let invalid_host_key_file = dir.path().join("hostkey-der");
        let host_key_priv_file = dir.path().join("hostkey_priv");
        let invalid_host_key_priv_file = dir.path().join("hostkey_priv-der");
        let empty_host_key_priv_file = dir.path().join("hostkey_priv-empty");
        let cert_file = dir.path().join("cert-pem");

        let valid_config = dir.path().join("valid.config");

        // create RSA key
        let key = Rsa::generate(4096).unwrap();
        let pkey = PKey::from_rsa(key.clone()).unwrap();
        let pub_pem = key.public_key_to_pem().unwrap();
        let pub_der = key.public_key_to_der().unwrap();
        let priv_pem = key.private_key_to_pem().unwrap();
        let priv_der = key.private_key_to_der().unwrap();

        // create rsa files
        let mut rsa_pem = File::create(&host_key_file).unwrap();
        let mut rsa_der = File::create(&invalid_host_key_file).unwrap();
        let mut rsa_priv_pem = File::create(&host_key_priv_file).unwrap();
        let mut rsa_priv_der = File::create(&invalid_host_key_priv_file).unwrap();
        File::create(&empty_host_key_priv_file).unwrap();
        rsa_pem.write_all(pub_pem.as_slice()).unwrap();
        rsa_pem.sync_all().unwrap();
        rsa_der.write_all(pub_der.as_slice()).unwrap();
        rsa_der.sync_all().unwrap();
        rsa_priv_pem.write_all(priv_pem.as_slice()).unwrap();
        rsa_priv_pem.sync_all().unwrap();
        rsa_priv_der.write_all(priv_der.as_slice()).unwrap();
        rsa_priv_der.sync_all().unwrap();

        // create certificate files
        let mut cert = X509Builder::new().unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "test.com")
            .unwrap();
        let name = name.build();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        cert.set_pubkey(&pkey).unwrap();
        cert.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = cert.build();
        let cert_pem = cert.to_pem().unwrap();
        let mut cert_pem_file = File::create(&cert_file).unwrap();
        cert_pem_file.write_all(cert_pem.as_slice()).unwrap();
        cert_pem_file.sync_all().unwrap();

        create_config_file(
            true,
            true,
            Some(p2p_port),
            Some("127.0.0.1"),
            Some("2"),
            Some(format!("127.0.0.1:{}", api_port).as_str()),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &valid_config,
        );

        // run peer
        tokio::task::spawn(run_peer_async(valid_config))
    }

    #[test]
    fn unit_valid_config() {
        // create tmp dir that will be automatically dropped afterwards
        let dir = TempDir::new("onion-test").unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let peer = run_valid_peer(&dir, "2010", "3011");
            // This should timeout because it's valid
            tokio::time::timeout(Duration::from_secs(1), peer)
                .await
                .unwrap_err();
        });
    }

    #[test]
    fn unit_multiple_with_same_p2p_port() {
        let dir = TempDir::new("onion-test").unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let peer1 = run_valid_peer(&dir, "2020", "3020");
            tokio::time::sleep(Duration::from_millis(100)).await;
            let peer2 = run_valid_peer(&dir, "2020", "3021");
            // Pin that it can be passed by reference to timeout and is usable afterwards.
            // This prevents the abortion of the future which would unbind the port.
            pin_mut!(peer1);
            pin_mut!(peer2);

            // This should timeout because it's valid
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer1)
                .await
                .unwrap_err();
            // This should not timeout because port is already used
            // The port bind panics and therefore a JoinError is expected
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer2)
                .await
                .unwrap()
                .unwrap_err();
        });
    }

    #[test]
    fn unit_multiple_with_same_api_port() {
        let dir = TempDir::new("onion-test").unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let peer1 = run_valid_peer(&dir, "2030", "3030");
            tokio::time::sleep(Duration::from_millis(100)).await;
            let peer2 = run_valid_peer(&dir, "2031", "3030");
            // Pin that it can be passed by reference to timeout and is usable afterwards.
            // This prevents the abortion of the future which would unbind the port.
            pin_mut!(peer1);
            pin_mut!(peer2);

            // This should timeout because it's valid
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer1)
                .await
                .unwrap_err();
            // This should not timeout because port is already used
            // The port bind panics and therefore a JoinError is expected
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut peer2)
                .await
                .unwrap()
                .unwrap();
        });
    }
}
