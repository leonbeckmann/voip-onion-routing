
extern crate ini;
extern crate regex;

use std::fmt::Formatter;
use std::path::Path;
use ini::Ini;
use openssl::rsa::Rsa;
use std::fs;
use openssl::pkey::Public;
use std::net::{SocketAddrV6, SocketAddrV4};
use crate::CustomSocketAddr;
use regex::Regex;

pub struct OnionConfiguration {
    p2p_port: u16,
    p2p_hostname: String,
    host_key: Rsa<Public>,
    hop_count: u8,
    api_address: CustomSocketAddr,
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
                Ok(count) => count,
                Err(_) => {
                    return Err(ParsingError::from_str("Cannot parse 'hop_count' to u8"))
                }
            }
        };

        // parse api_address
        let hostname_regex = Regex::new(r"^(\S+):(\b\d{1,5}\b)$").unwrap();
        let api_address = match onion_sec.get("api_address") {
            None => {
                return Err(ParsingError::from_str("Missing component: 'api_address'"));
            }
            Some(address) => {
                if let Ok(ipv6) = address.parse::<SocketAddrV6>() {
                    CustomSocketAddr::V6(ipv6)
                } else if let Ok(ipv4) = address.parse::<SocketAddrV4>() {
                    CustomSocketAddr::V4(ipv4)
                } else if let Some(cap) = hostname_regex.captures(address) {

                    let port = match cap.get(2).unwrap().as_str().parse::<u16>() {
                        Ok(port) => port,
                        Err(_) => {
                            return Err(ParsingError::from_str("Cannot parse api_address port to u16"));
                        }
                    };

                    CustomSocketAddr::Hostname(cap.get(1).unwrap().as_str().to_string(), port)

                } else {
                    return Err(ParsingError::from_str("Cannot match valid api_connection address format"));
                }
            }
        };

        Ok(OnionConfiguration {
            p2p_port,
            p2p_hostname,
            host_key,
            hop_count,
            api_address
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
        let config_additional_information = dir.path().join("add-info.config");
        let config_missing_section = dir.path().join("missing-section.config");
        let config_missing_hostkey = dir.path().join("missing-hostkey.config");
        let config_der_hostkey = dir.path().join("der-hostkey.config");
        let config_invalid_hostkey_path = dir.path().join("invalid_hostkey.config");
        let config_missing_hop_count = dir.path().join("missing_hops.config");
        let config_invalid_hop_count = dir.path().join("invalid_hops.config");
        let config_missing_api_address = dir.path().join("missing_api_address.config");
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
        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&valid_config).unwrap();

        let config = Ini::new();
        config.write_to_file(&config_missing_section).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_missing_port).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "invalid")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_invalid_port).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_missing_hostname).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345");
        config.write_to_file(&config_missing_hostkey).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", invalid_host_key_file.to_str().unwrap());
        config.write_to_file(&config_der_hostkey).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", invalid_host_key_path.to_str().unwrap());
        config.write_to_file(&config_invalid_hostkey_path).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:12345")
            .set("dummy_key", "some_value")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.with_section(Some("another_section"))
            .set("random_data", "value");
        config.write_to_file(&config_additional_information).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_missing_hop_count).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "256")
            .set("api_address", "127.0.0.1:12345")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_invalid_hop_count).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_missing_api_address).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "127.0.0.1:123456")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_invalid_api_address).unwrap();

        let mut config = Ini::new();
        config.with_section(Some("onion"))
            .set("p2p_port", "1234")
            .set("p2p_hostname", "localhost")
            .set("hop_count", "2")
            .set("api_address", "[::1]:12345")
            .set("hostkey", host_key_file.to_str().unwrap());
        config.write_to_file(&config_api_address_v6).unwrap();

        // parse configurations
        let config = OnionConfiguration::parse_from_file(valid_config).unwrap();
        assert_eq!(config.p2p_port, 1234);
        assert_eq!(config.p2p_hostname, "localhost");
        assert_eq!(config.hop_count, 2);
        assert_eq!(config.api_address.port(), 12345);
        assert!(config.api_address.is_ipv4());
        assert_eq!(config.host_key.public_key_to_pem().unwrap(), pub_pem);

        assert!(OnionConfiguration::parse_from_file(config_missing_section).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_port).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_port).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_hostname).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_hostkey_path).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_hostkey).is_err());
        assert!(OnionConfiguration::parse_from_file(config_der_hostkey).is_err());
        assert!(OnionConfiguration::parse_from_file(config_additional_information).is_ok());
        assert!(OnionConfiguration::parse_from_file(config_missing_hop_count).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_hop_count).is_err());
        assert!(OnionConfiguration::parse_from_file(config_missing_api_address).is_err());
        assert!(OnionConfiguration::parse_from_file(config_invalid_api_address).is_err());

        let config =
            OnionConfiguration::parse_from_file(config_api_address_v6).unwrap();
        assert_eq!(config.api_address.port(), 12345);
        assert!(config.api_address.is_ipv6());
        assert_eq!(config.host_key.public_key_to_pem().unwrap(), pub_pem);


        dir.close().unwrap();
    }
}