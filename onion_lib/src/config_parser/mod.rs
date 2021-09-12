extern crate ini;

use crate::p2p_protocol::dtls_connections::DtlsConfig;
use crate::p2p_protocol::onion_tunnel::crypto::HandshakeCryptoConfig;
use ini::Ini;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use std::fmt::Formatter;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct OnionConfiguration {
    pub p2p_port: u16,
    pub p2p_hostname: String,
    pub crypto_config: Arc<HandshakeCryptoConfig>,
    pub hop_count: u8,
    pub onion_api_address: SocketAddr,
    pub rps_api_address: SocketAddr,
    pub round_time: Duration,
    pub build_window: Duration,
    pub handshake_message_timeout: Duration,
    pub dtls_config: Arc<DtlsConfig>,
    pub timeout: Duration,
}

impl OnionConfiguration {
    /**
     * Parse the config file to an OnionConfiguration
     */
    pub fn parse_from_file<P: AsRef<Path>>(path: P) -> Result<OnionConfiguration, ParsingError> {
        // parse config file
        let config = match Ini::load_from_file(path) {
            Ok(config) => config,
            Err(e) => return Err(ParsingError::from_string(e.to_string())),
        };

        // parse sections
        let onion_sec = match config.section(Some("onion")) {
            None => return Err(ParsingError::from_str("Missing section: 'onion'")),
            Some(section) => section,
        };

        let rps_sec = match config.section(Some("rps")) {
            None => return Err(ParsingError::from_str("Missing section: 'rps'")),
            Some(section) => section,
        };

        let global_sec = config.general_section();
        /* parse properties */

        // parse p2p_port
        let p2p_port = match onion_sec.get("p2p_port") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'p2p_port'"));
            }
            Some(port) => match port.parse() {
                Ok(port) => port,
                Err(_) => return Err(ParsingError::from_str("Cannot parse 'p2p_port' to u16")),
            },
        };

        // parse p2p_hostname
        let p2p_hostname = match onion_sec.get("p2p_hostname") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'p2p_hostname'"));
            }
            Some(hostname) => hostname.to_string(),
        };

        // parse host_key
        let host_key_pem = match global_sec.get("hostkey") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'hostkey'"));
            }
            Some(file) => match fs::read(file) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(ParsingError::from_string(format!(
                        "Cannot access hostkey file: {}",
                        e.to_string()
                    )));
                }
            },
        };

        let host_key = match Rsa::public_key_from_pem(host_key_pem.as_ref()) {
            Ok(rsa) => rsa,
            Err(e) => {
                return Err(ParsingError::from_string(format!(
                    "Cannot parse hostkey from pem: {}",
                    e.to_string()
                )))
            }
        };

        // parse private key
        let host_key_priv_pem = match onion_sec.get("private_hostkey") {
            None => {
                return Err(ParsingError::from_str(
                    "Missing component: 'private_hostkey'",
                ));
            }
            Some(file) => match fs::read(file) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(ParsingError::from_string(format!(
                        "Cannot access private_hostkey file: {}",
                        e.to_string()
                    )));
                }
            },
        };

        let private_host_key = match Rsa::private_key_from_pem(host_key_priv_pem.as_ref()) {
            Ok(rsa) => rsa,
            Err(e) => {
                return Err(ParsingError::from_string(format!(
                    "Cannot parse private_hostkey from pem: {}",
                    e.to_string()
                )))
            }
        };

        // parse peer identity certificate
        let peer_cert_pem = match onion_sec.get("hostkey_cert") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'hostkey_cert'"));
            }
            Some(file) => match fs::read(file) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(ParsingError::from_string(format!(
                        "Cannot access hostkey_cert file: {}",
                        e.to_string()
                    )));
                }
            },
        };

        // PKI future work: Use stack_from_pem to read certificate chains with more than two layers
        let peer_cert = match X509::from_pem(&peer_cert_pem) {
            Ok(cert) => cert,
            Err(e) => {
                return Err(ParsingError::from_string(format!(
                    "Cannot parse hostkey_cert to X509 certificate: {}",
                    e.to_string()
                )));
            }
        };

        // parse pki root certificate
        let pki_cert_pem = match onion_sec.get("pki_root_cert") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'pki_root_cert'"));
            }
            Some(file) => match fs::read(file) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(ParsingError::from_string(format!(
                        "Cannot access pki_root_cert file: {}",
                        e.to_string()
                    )));
                }
            },
        };

        let pki_cert = match X509::from_pem(&pki_cert_pem) {
            Ok(cert) => cert,
            Err(e) => {
                return Err(ParsingError::from_string(format!(
                    "Cannot parse pki_root_cert to X509 certificate: {}",
                    e.to_string()
                )));
            }
        };

        // parse hop_count
        let hop_count = match onion_sec.get("hop_count") {
            None => 2, // default
            Some(count) => match count.parse::<u8>() {
                Ok(count) => {
                    // must be at least two
                    if count < 2 {
                        return Err(ParsingError::from_str("hop_count must be at least 2"));
                    }
                    count
                }
                Err(_) => return Err(ParsingError::from_str("Cannot parse 'hop_count' to u8")),
            },
        };

        // parse onion's api_address
        let onion_api_address = match onion_sec.get("api_address") {
            None => {
                return Err(ParsingError::from_str(
                    "Missing component: onion's 'api_address'",
                ));
            }
            Some(address) => match address.to_socket_addrs() {
                Ok(mut iter) => match iter.next() {
                    None => {
                        #[rustfmt::skip]
                        return Err(
                            ParsingError::from_str("Cannot parse onion's api_address")
                        ); // coverage-unreachable
                    }
                    Some(addr) => addr,
                },
                Err(e) => {
                    return Err(ParsingError::from_string(format!(
                        "Cannot parse onion's api_address: {}",
                        e.to_string()
                    )))
                }
            },
        };

        // parse RPS's api_address
        let rps_api_address = match rps_sec.get("api_address") {
            None => {
                return Err(ParsingError::from_str(
                    "Missing component: rps's 'api_address'",
                ));
            }
            Some(address) => match address.to_socket_addrs() {
                Ok(mut iter) => match iter.next() {
                    None => {
                        #[rustfmt::skip]
                        return Err(
                            ParsingError::from_str("Cannot parse rps's api_address")
                        ); // coverage-unreachable
                    }
                    Some(addr) => addr,
                },
                Err(e) => {
                    return Err(ParsingError::from_string(format!(
                        "Cannot parse rps's api_address: {}",
                        e.to_string()
                    )))
                }
            },
        };

        // handshake message timeout (ms)
        let handshake_message_timeout = match onion_sec.get("handshake_timeout") {
            None => Duration::from_millis(1000), // default
            Some(timeout) => match timeout.parse::<u64>() {
                Ok(timeout) => Duration::from_millis(timeout),
                Err(_) => {
                    return Err(ParsingError::from_str(
                        "Cannot parse 'handshake_timeout' to u64",
                    ))
                }
            },
        };

        // message timeout (s)
        let timeout = match onion_sec.get("timeout") {
            None => Duration::from_secs(15), // default
            Some(timeout) => match timeout.parse::<u64>() {
                Ok(timeout) => Duration::from_secs(timeout),
                Err(_) => return Err(ParsingError::from_str("Cannot parse 'timeout' to u64")),
            },
        };

        // round time (seconds)
        let round_time = match onion_sec.get("round_time") {
            None => Duration::from_secs(600), // default
            Some(duration) => match duration.parse::<u64>() {
                Ok(duration) => Duration::from_secs(duration),
                Err(_) => return Err(ParsingError::from_str("Cannot parse 'round_time' to u64")),
            },
        };

        // round time (milli seconds)
        let build_window = match onion_sec.get("build_window") {
            None => Duration::from_secs(1), // default
            Some(duration) => match duration.parse::<u64>() {
                Ok(duration) => Duration::from_millis(duration),
                Err(_) => return Err(ParsingError::from_str("Cannot parse 'build_window' to u64")),
            },
        };

        // blocklist_time (seconds)
        let blocklist_time = match onion_sec.get("blocklist_time") {
            None => Duration::from_secs(3600), // default
            Some(duration) => match duration.parse::<u64>() {
                Ok(duration) => Duration::from_secs(duration),
                Err(_) => {
                    return Err(ParsingError::from_str(
                        "Cannot parse 'blocklist_time' to u64",
                    ))
                }
            },
        };

        // connect_timeout (milli seconds)
        let connect_timeout = match onion_sec.get("connect_timeout") {
            None => Duration::from_secs(10), // default
            Some(duration) => match duration.parse::<u64>() {
                Ok(duration) => Duration::from_millis(duration),
                Err(_) => {
                    return Err(ParsingError::from_str(
                        "Cannot parse 'connect_timeout' to u64",
                    ))
                }
            },
        };

        // send_message_timeout (milli seconds)
        let send_message_timeout = match onion_sec.get("send_message_timeout") {
            None => Duration::from_secs(10), // default
            Some(duration) => match duration.parse::<u64>() {
                Ok(duration) => Duration::from_millis(duration),
                Err(_) => {
                    return Err(ParsingError::from_str(
                        "Cannot parse 'send_message_timeout' to u64",
                    ))
                }
            },
        };

        Ok(OnionConfiguration {
            p2p_port,
            p2p_hostname,
            crypto_config: Arc::new(HandshakeCryptoConfig::new(
                host_key,
                private_host_key.clone(),
            )),
            hop_count,
            onion_api_address,
            rps_api_address,
            round_time,
            build_window,
            handshake_message_timeout,
            dtls_config: Arc::new(DtlsConfig::new(
                pki_cert,
                peer_cert,
                blocklist_time,
                private_host_key,
                connect_timeout,
                send_message_timeout,
                timeout,
            )),
            timeout,
        })
    }
}

#[derive(Debug)]
pub struct ParsingError {
    desc: String,
}

impl std::error::Error for ParsingError {}

impl ParsingError {
    fn from_string(desc: String) -> ParsingError {
        ParsingError { desc }
    }

    fn from_str(desc: &'static str) -> ParsingError {
        ParsingError {
            desc: desc.to_string(),
        }
    }
}

impl std::fmt::Display for ParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cannot parse configuration from windows ini: {}",
            self.desc
        )
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_config_file<P: AsRef<Path>>(
    onion: bool,
    rps: bool,
    p2p_port: Option<&str>,
    p2p_hostname: Option<&str>,
    hop_count: Option<&str>,
    onion_api_addr: Option<&str>,
    rps_api_addr: Option<&str>,
    hostkey: Option<&str>,
    priv_key: Option<&str>,
    round_time: Option<&str>,
    handshake_timeout: Option<&str>,
    timeout: Option<&str>,
    build_window: Option<&str>,
    pki_root_cert: Option<&str>,
    hostkey_cert: Option<&str>,
    blocklist_time: Option<&str>,
    connect_timeout: Option<&str>,
    send_message_timeout: Option<&str>,
    file_path: P,
) {
    let mut config = Ini::new();
    if let Some(key) = hostkey {
        config.with_general_section().set("hostkey", key);
    } else {
        // we have to add a dummy value within the general_section, otherwise the library function panics
        config.with_general_section().set("dummy", "dummy");
    }
    if onion {
        if let Some(port) = p2p_port {
            config.with_section(Some("onion")).set("p2p_port", port);
        }
        if let Some(hostname) = p2p_hostname {
            config
                .with_section(Some("onion"))
                .set("p2p_hostname", hostname);
        }
        if let Some(hop_count) = hop_count {
            config
                .with_section(Some("onion"))
                .set("hop_count", hop_count);
        }
        if let Some(api_addr) = onion_api_addr {
            config
                .with_section(Some("onion"))
                .set("api_address", api_addr);
        }
        if let Some(key) = priv_key {
            config
                .with_section(Some("onion"))
                .set("private_hostkey", key);
        }
        if let Some(timeout) = handshake_timeout {
            config
                .with_section(Some("onion"))
                .set("handshake_timeout", timeout);
        }
        if let Some(timeout) = timeout {
            config.with_section(Some("onion")).set("timeout", timeout);
        }
        if let Some(duration) = round_time {
            config
                .with_section(Some("onion"))
                .set("round_time", duration);
        }
        if let Some(duration) = build_window {
            config
                .with_section(Some("onion"))
                .set("build_window", duration);
        }
        if let Some(path) = pki_root_cert {
            config
                .with_section(Some("onion"))
                .set("pki_root_cert", path);
        }
        if let Some(path) = hostkey_cert {
            config.with_section(Some("onion")).set("hostkey_cert", path);
        }
        if let Some(duration) = blocklist_time {
            config
                .with_section(Some("onion"))
                .set("blocklist_time", duration);
        }
        if let Some(duration) = connect_timeout {
            config
                .with_section(Some("onion"))
                .set("connect_timeout", duration);
        }
        if let Some(duration) = send_message_timeout {
            config
                .with_section(Some("onion"))
                .set("send_message_timeout", duration);
        }
    }
    if rps {
        if let Some(api_addr) = rps_api_addr {
            config
                .with_section(Some("rps"))
                .set("api_address", api_addr);
        } else {
            config.with_section(Some("rps")).set("dummy", "dummy");
        }
    }

    config.write_to_file(file_path).unwrap();
}

#[cfg(test)]
mod tests {

    extern crate tempdir;
    use super::ParsingError;
    use crate::config_parser::{create_config_file, OnionConfiguration};
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509Name};
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    use tempdir::TempDir;

    #[test]
    fn unit_config_parser() {
        // create tmp dir that will be automatically dropped afterwards
        let dir = TempDir::new("onion-test").unwrap();

        // create paths for host-key and config files
        let host_key_file = dir.path().join("hostkey");
        let invalid_host_key_file = dir.path().join("hostkey-der");
        let invalid_path = dir.path().join("not-available");
        let host_key_priv_file = dir.path().join("hostkey_priv");
        let invalid_host_key_priv_file = dir.path().join("hostkey_priv-der");
        let empty_host_key_priv_file = dir.path().join("hostkey_priv-empty");
        let cert_file = dir.path().join("cert-pem");
        let invalid_cert_file = dir.path().join("cert-der");

        let valid_config = dir.path().join("valid.config");
        let config_missing_hostkey = dir.path().join("missing-hostkey.config");
        let config_der_hostkey = dir.path().join("der-hostkey.config");
        let config_invalid_hostkey_path = dir.path().join("invalid_hostkey.config");
        let config_missing_onion_section = dir.path().join("missing-onion-section.config");
        let config_missing_rps_section = dir.path().join("missing-rps-section.config");
        let config_missing_port = dir.path().join("missing-port.config");
        let config_invalid_port = dir.path().join("invalid-port.config");
        let config_missing_hostname = dir.path().join("missing-hostname.config");
        let config_too_high_hop_count = dir.path().join("too_high_hops.config");
        let config_too_low_hop_count = dir.path().join("too_low_hops.config");
        let config_missing_hop_count = dir.path().join("missing_hop_count.config");
        let config_missing_onion_api_address = dir.path().join("missing_o_api_address.config");
        let config_missing_rps_api_address = dir.path().join("missing_r_api_address.config");
        let config_invalid_api_address = dir.path().join("invalid_api_address.config");
        let config_invalid_rps_api_address = dir.path().join("invalid_rps_api_address.config");
        let config_api_address_v6 = dir.path().join("api_address_v6.config");
        let config_missing_round_time = dir.path().join("missing_round_time.config");
        let config_invalid_round_time = dir.path().join("invalid_round_time.config");
        let config_missing_handshake_timeout = dir.path().join("missing_handshake_timeout.config");
        let config_invalid_handshake_timeout = dir.path().join("invalid_handshake_timeout.config");
        let config_missing_timeout = dir.path().join("missing_timeout.config");
        let config_invalid_timeout = dir.path().join("invalid_timeout.config");
        let config_missing_private_key = dir.path().join("missing_private_key.config");
        let config_der_private_key = dir.path().join("der_private_key.config");
        let config_empty_private_key = dir.path().join("empty_private_key.config");
        let config_invalid_priv_key_path = dir.path().join("invalid_priv_key_path.config");
        let config_missing_build_window = dir.path().join("missing_build_window.config");
        let config_invalid_build_window = dir.path().join("invalid_build_window.config");
        let config_missing_blocklist_time = dir.path().join("missing_blocklist_time.config");
        let config_invalid_blocklist_time = dir.path().join("invalid_blocklist_time.config");
        let config_missing_connect_timeout = dir.path().join("missing_connect_timeout.config");
        let config_invalid_connect_timeout = dir.path().join("invalid_connect_timeout.config");
        let config_missing_send_message_timeout =
            dir.path().join("missing_send_message_timeout.config");
        let config_invalid_send_message_timeout =
            dir.path().join("invalid_send_message_timeout.config");
        let config_missing_cert = dir.path().join("missing-cert.config");
        let config_der_cert = dir.path().join("der-cert.config");
        let config_invalid_cert_path = dir.path().join("invalid_cert.config");
        let config_missing_pki_cert = dir.path().join("missing-pki-cert.config");
        let config_der_pki_cert = dir.path().join("der-pki-cert.config");
        let config_invalid_pki_cert_path = dir.path().join("invalid-pki-cert.config");

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
        let cert_der = cert.to_der().unwrap();
        let mut cert_pem_file = File::create(&cert_file).unwrap();
        let mut cert_der_file = File::create(&invalid_cert_file).unwrap();
        cert_pem_file.write_all(cert_pem.as_slice()).unwrap();
        cert_pem_file.sync_all().unwrap();
        cert_der_file.write_all(cert_der.as_slice()).unwrap();
        cert_der_file.sync_all().unwrap();

        // create config files
        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
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

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("localhost:1234"),
            Some("localhost:1235"),
            None,
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
            &config_missing_hostkey,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("localhost:1234"),
            Some("localhost:1235"),
            Some(invalid_host_key_file.to_str().unwrap()),
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
            &config_der_hostkey,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("localhost:1234"),
            Some("localhost:1235"),
            Some(invalid_path.to_str().unwrap()),
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
            &config_invalid_hostkey_path,
        );

        create_config_file(
            false,
            true,
            None,
            None,
            None,
            None,
            Some("localhost:1235"),
            Some(host_key_file.to_str().unwrap()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            &config_missing_onion_section,
        );

        create_config_file(
            true,
            false,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            None,
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
            &config_missing_rps_section,
        );

        create_config_file(
            true,
            true,
            None,
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
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
            &config_missing_port,
        );

        create_config_file(
            true,
            true,
            Some("2x"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
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
            &config_invalid_port,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            None,
            Some("2"),
            Some("127.0.0.1:1234"),
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
            &config_missing_hostname,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("256"),
            Some("127.0.0.1:1234"),
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
            &config_too_high_hop_count,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("1"),
            Some("127.0.0.1:1234"),
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
            &config_too_low_hop_count,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            None,
            Some("127.0.0.1:1234"),
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
            &config_missing_hop_count,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            None,
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
            &config_missing_onion_api_address,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            None,
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
            &config_missing_rps_api_address,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:12345678"),
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
            &config_invalid_api_address,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:12356789"),
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
            &config_invalid_rps_api_address,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("[::1]:1234"),
            Some("localhost:1235"),
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
            &config_api_address_v6,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            None,
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_missing_round_time,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100a"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_invalid_round_time,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            None,
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_missing_handshake_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000a"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_invalid_handshake_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            None,
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_missing_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1a"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_invalid_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            None,
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_missing_private_key,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(invalid_host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_der_private_key,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(empty_host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_empty_private_key,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("localhost"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(invalid_path.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_invalid_priv_key_path,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            None,
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_missing_build_window,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000a"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_invalid_build_window,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            None,
            Some("10000"),
            Some("10000"),
            &config_missing_blocklist_time,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600a"),
            Some("10000"),
            Some("10000"),
            &config_invalid_blocklist_time,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            None,
            Some("10000"),
            Some("10000"),
            &config_missing_blocklist_time,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600a"),
            Some("10000"),
            Some("10000"),
            &config_invalid_blocklist_time,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
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
            None,
            Some("10000"),
            &config_missing_connect_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
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
            Some("10000a"),
            Some("10000"),
            &config_invalid_connect_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
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
            None,
            &config_missing_send_message_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
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
            Some("10000a"),
            &config_invalid_send_message_timeout,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            None,
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_missing_cert,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(invalid_cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_der_cert,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(cert_file.to_str().unwrap()),
            Some(invalid_path.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_invalid_cert_path,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            None,
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_missing_pki_cert,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(invalid_cert_file.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_der_pki_cert,
        );

        create_config_file(
            true,
            true,
            Some("1234"),
            Some("127.0.0.1"),
            Some("2"),
            Some("127.0.0.1:1234"),
            Some("127.0.0.1:1235"),
            Some(host_key_file.to_str().unwrap()),
            Some(host_key_priv_file.to_str().unwrap()),
            Some("100"),
            Some("2000"),
            Some("1"),
            Some("1000"),
            Some(invalid_path.to_str().unwrap()),
            Some(cert_file.to_str().unwrap()),
            Some("3600"),
            Some("10000"),
            Some("10000"),
            &config_invalid_pki_cert_path,
        );

        // parse configurations
        let config = OnionConfiguration::parse_from_file(valid_config).unwrap();
        assert_eq!(config.p2p_port, 1234);
        assert_eq!(config.p2p_hostname, "127.0.0.1");
        assert_eq!(config.hop_count, 2);
        assert_eq!(config.onion_api_address.port(), 1234);
        assert_eq!(config.rps_api_address.port(), 1235);
        assert_eq!(config.round_time, Duration::from_secs(100));
        assert_eq!(
            config.handshake_message_timeout,
            Duration::from_millis(2000)
        );
        assert_eq!(config.timeout, Duration::from_secs(1));
        assert_eq!(config.build_window, Duration::from_millis(1000));

        assert!(OnionConfiguration::parse_from_file(config_missing_hostkey).is_err());
        assert!(OnionConfiguration::parse_from_file(config_der_hostkey).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_hostkey_path).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_onion_section).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_rps_section).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_port).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_port).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_hostname).is_err());
        assert!(OnionConfiguration::parse_from_file(config_too_high_hop_count).is_err());
        assert!(OnionConfiguration::parse_from_file(config_too_low_hop_count).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_hop_count).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_missing_onion_api_address).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_rps_api_address).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_api_address).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_rps_api_address).is_err());

        let config = OnionConfiguration::parse_from_file(config_api_address_v6).unwrap();
        assert_eq!(config.onion_api_address.port(), 1234);
        assert!(config.onion_api_address.is_ipv6());

        assert!(OnionConfiguration::parse_from_file(config_missing_round_time).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_invalid_round_time).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_handshake_timeout).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_invalid_handshake_timeout).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_timeout).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_invalid_timeout).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_private_key).is_err());
        assert!(OnionConfiguration::parse_from_file(config_der_private_key).is_err());
        assert!(OnionConfiguration::parse_from_file(config_empty_private_key).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_priv_key_path).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_build_window).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_invalid_build_window).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_blocklist_time).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_invalid_blocklist_time).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_connect_timeout).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_invalid_connect_timeout).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_send_message_timeout).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_invalid_send_message_timeout).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_cert).is_err());
        assert!(OnionConfiguration::parse_from_file(config_der_cert).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_cert_path).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_pki_cert).is_err());
        assert!(OnionConfiguration::parse_from_file(config_der_pki_cert).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_pki_cert_path).is_err());

        dir.close().unwrap();
    }

    #[test]
    fn unit_parser_error() {
        let e = ParsingError::from_str("abc");
        let s = format!("{}", e);
        assert_eq!("Cannot parse configuration from windows ini: abc", s);
    }
}
