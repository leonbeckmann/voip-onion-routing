
extern crate ini;

use std::fmt::Formatter;
use std::path::Path;
use ini::Ini;
use openssl::rsa::Rsa;
use std::fs;
use openssl::pkey::Public;
use std::net::{ToSocketAddrs, SocketAddr};

pub struct OnionConfiguration {
    p2p_port: u16,
    p2p_hostname: String,
    host_key: Rsa<Public>,
    hop_count: u8,
    onion_api_address: SocketAddr,
    rps_api_address: SocketAddr,
}

impl OnionConfiguration {
    pub fn parse_from_file<P: AsRef<Path>>(path: P) -> Result<OnionConfiguration, ParsingError> {

        // parse config file
        let config = match Ini::load_from_file(path) {
            Ok(config) => config,
            Err(e) => {
                return Err(ParsingError::from_string(e.to_string()))
            }
        };

        // parse sections
        let onion_sec = match config.section(Some("onion")) {
            None => {
                return Err(ParsingError::from_str("Missing section: 'onion'"))
            }
            Some(section) => section
        };

        let rps_sec = match config.section(Some("rps")) {
            None => {
                return Err(ParsingError::from_str("Missing section: 'rps'"))
            }
            Some(section) => section
        };

        /* parse properties */

        // parse p2p_port
        let p2p_port = match onion_sec.get("p2p_port") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'p2p_port'"));
            }
            Some(port) => match port.parse() {
                Ok(port) => port,
                Err(_) => {
                    return Err(ParsingError::from_str("Cannot parse 'p2p_port' to u16"))
                }
            }
        };

        // parse p2p_hostname
        let p2p_hostname = match onion_sec.get("p2p_hostname") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'p2p_hostname'"));
            }
            Some(hostname) => hostname.to_string()
        };

        // parse host_key
        let host_key_pem = match onion_sec.get("hostkey") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'hostkey'"));
            }
            Some(file) => match fs::read(file) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(ParsingError::from_string(
                        format!("Cannot access hostkey file: {}", e.to_string()))
                    );
                }
            }
        };

        let host_key = match Rsa::public_key_from_pem(host_key_pem.as_ref()) {
            Ok(rsa) => rsa,
            Err(e) => {
                return Err(ParsingError::from_string(
                    format!("Cannot parse hostkey from pem: {}", e.to_string()))
                )
            }
        };

        // parse hop_count
        let hop_count = match onion_sec.get("hop_count") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'hop_count'"));
            }
            Some(count) => match count.parse::<u8>() {
                Ok(count) => {
                    // must be at least two
                    if count < 2 {
                        return Err(ParsingError::from_str("hop_count must be at least 2"))
                    }
                    count
                }
                Err(_) => {
                    return Err(ParsingError::from_str("Cannot parse 'hop_count' to u8"))
                }
            }
        };

        // parse onion's api_address
        let onion_api_address = match onion_sec.get("api_address") {
            None => {
                return Err(ParsingError::from_str("Missing component: onion's 'api_address'"));
            }
            Some(address) => match address.to_socket_addrs() {
                Ok(mut iter) => match iter.next() {
                    None => {
                        return Err(ParsingError::from_str("Cannot parse onion's api_address"));
                    }
                    Some(addr) => addr
                }
                Err(e) => {
                    return Err(ParsingError::from_string(
                        format!("Cannot parse onion's api_address: {}", e.to_string()))
                    )
                }
            }
        };

        // parse RPS's api_address
        let rps_api_address = match rps_sec.get("api_address") {
            None => {
                return Err(ParsingError::from_str("Missing component: rps's 'api_address'"));
            }
            Some(address) => match address.to_socket_addrs() {
                Ok(mut iter) => match iter.next() {
                    None => {
                        return Err(ParsingError::from_str("Cannot parse rps's api_address"));
                    }
                    Some(addr) => addr
                }
                Err(e) => {
                    return Err(ParsingError::from_string(
                        format!("Cannot parse rps's api_address: {}", e.to_string()))
                    )
                }
            }
        };

        Ok(OnionConfiguration {
            p2p_port,
            p2p_hostname,
            host_key,
            hop_count,
            onion_api_address,
            rps_api_address,
        })
    }
}

#[derive(Debug)]
pub struct ParsingError {
    desc: String
}

impl std::error::Error for ParsingError {}

impl ParsingError {
    fn from_string(desc: String) -> ParsingError {
        ParsingError {
            desc
        }
    }

    fn from_str(desc: &'static str) -> ParsingError {
        ParsingError {
            desc: desc.to_string()
        }
    }
}

impl std::fmt::Display for ParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cannot parse configuration from windows ini: {}", self.desc)
    }
}

#[cfg(test)]
mod tests {

    extern crate tempdir;
    use super::ini::Ini;
    use openssl::rsa::Rsa;
    use tempdir::TempDir;
    use crate::config_parser::OnionConfiguration;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    fn create_config_file<P: AsRef<Path>>(
        onion: bool,
        rps: bool,
        p2p_port: Option<&str>,
        p2p_hostname: Option<&str>,
        hop_count: Option<&str>,
        onion_api_addr: Option<&str>,
        rps_api_addr: Option<&str>,
        hostkey: Option<&str>,
        file_path: P
    ) {
        let mut config = Ini::new();
        if onion {
            if let Some(port) = p2p_port {
                config.with_section(Some("onion")).set("p2p_port", port);
            }
            if let Some(hostname) = p2p_hostname {
                config.with_section(Some("onion")).set("p2p_hostname", hostname);
            }
            if let Some(hop_count) = hop_count {
                config.with_section(Some("onion")).set("hop_count", hop_count);
            }
            if let Some(key) = hostkey {
                config.with_section(Some("onion")).set("hostkey", key);
            }
            if let Some(api_addr) = onion_api_addr {
                config.with_section(Some("onion")).set("api_address", api_addr);
            }
        }
        if rps {
            if let Some(api_addr) = rps_api_addr {
                config.with_section(Some("rps")).set("api_address", api_addr);
            }
        }

        config.write_to_file(file_path).unwrap();
    }

    #[test]
    fn unit_config_parser() {

        // create tmp dir that will be automatically dropped afterwards
        let dir = TempDir::new("onion-test").unwrap();

        // create paths for host-key and config files
        let host_key_file = dir.path().join("hostkey");
        let invalid_host_key_file = dir.path().join("hostkey-der");
        let invalid_host_key_path = dir.path().join("not-available");
        let valid_config = dir.path().join("valid.config");
        let config_missing_port = dir.path().join("missing-port.config");
        let config_invalid_port = dir.path().join("invalid-port.config");
        let config_missing_hostname = dir.path().join("missing-hostname.config");
        let config_missing_section = dir.path().join("missing-section.config");
        let config_missing_hostkey = dir.path().join("missing-hostkey.config");
        let config_der_hostkey = dir.path().join("der-hostkey.config");
        let config_invalid_hostkey_path = dir.path().join("invalid_hostkey.config");
        let config_missing_hop_count = dir.path().join("missing_hops.config");
        let config_invalid_hop_count = dir.path().join("invalid_hops.config");
        let config_missing_onion_api_address = dir.path().join("missing_o_api_address.config");
        let config_missing_rps_api_address = dir.path().join("missing_r_api_address.config");
        let config_invalid_api_address = dir.path().join("invalid_api_address.config");
        let config_api_address_v6 = dir.path().join("api_address_v6.config");

        // create RSA key
        let key = Rsa::generate(4096).unwrap();
        let pub_pem = key.public_key_to_pem().unwrap();
        let pub_der = key.public_key_to_der().unwrap();

        // create rsa files
        let mut rsa_pem = File::create(&host_key_file).unwrap();
        let mut rsa_der = File::create(&invalid_host_key_file).unwrap();
        rsa_pem.write_all(pub_pem.as_slice()).unwrap();
        rsa_pem.sync_all().unwrap();
        rsa_der.write_all(pub_der.as_slice()).unwrap();
        rsa_der.sync_all().unwrap();

        // create config files
        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("127.0.0.1:1234"), Some("127.0.0.1:1235"),
                           Some(host_key_file.to_str().unwrap()), &valid_config);

        create_config_file(false, false, None, None, None,
                           None, None, None, &config_missing_section);

        create_config_file(true, true, None, Some("localhost"),
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_missing_port);

        create_config_file(true, true, Some("2x"), Some("localhost"),
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_invalid_port);

        create_config_file(true, true, Some("1234"), None,
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_missing_hostname);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           None, &config_missing_hostkey);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(invalid_host_key_file.to_str().unwrap()), &config_der_hostkey);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(invalid_host_key_path.to_str().unwrap()), &config_invalid_hostkey_path);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &valid_config);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           None, Some("localhost:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_missing_hop_count);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("1"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_invalid_hop_count);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("localhost:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &valid_config);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), None, Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_missing_onion_api_address);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("localhost:1234"), None,
                           Some(host_key_file.to_str().unwrap()), &config_missing_rps_api_address);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("127.0.0.1:123400"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_invalid_api_address);

        create_config_file(true, true, Some("1234"), Some("localhost"),
                           Some("2"), Some("[::1]:1234"), Some("localhost:1235"),
                           Some(host_key_file.to_str().unwrap()), &config_api_address_v6);

        // parse configurations
        let config = OnionConfiguration::parse_from_file(valid_config).unwrap();
        assert_eq!(config.p2p_port, 1234);
        assert_eq!(config.p2p_hostname, "localhost");
        assert_eq!(config.hop_count, 2);
        assert_eq!(config.onion_api_address.port(), 1234);
        assert_eq!(config.rps_api_address.port(), 1235);
        assert_eq!(config.host_key.public_key_to_pem().unwrap(), pub_pem);

        assert!(OnionConfiguration::parse_from_file(config_missing_section).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_port).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_port).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_hostname).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_hostkey_path).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_hostkey).is_err());
        assert!(OnionConfiguration::parse_from_file(config_der_hostkey).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_hop_count).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_hop_count).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_onion_api_address).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_rps_api_address).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_api_address).is_err());

        let config =
            OnionConfiguration::parse_from_file(config_api_address_v6).unwrap();
        assert_eq!(config.onion_api_address.port(), 1234);
        assert!(config.onion_api_address.is_ipv6());


        dir.close().unwrap();
    }
}