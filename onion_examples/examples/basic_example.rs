extern crate onion_lib;

use env_logger;
use ini::Ini;
use openssl::rsa::Rsa;
use std::fs::File;
use std::io::Write;
use tempdir::TempDir;

/*
 * This example runs a peer using a temporary hostkey and temporary config
 */
fn main() {
    // enable logging
    env_logger::init();

    let dir = TempDir::new("onion-example").unwrap();
    let config_file = dir.path().join("peer.config");
    let key_file = dir.path().join("hostkey.pem");

    // create RSA key
    let key = Rsa::generate(4096).unwrap();
    let pub_pem = key.public_key_to_pem().unwrap();

    // create rsa files
    let mut rsa_pem = File::create(&key_file).unwrap();
    rsa_pem.write_all(pub_pem.as_slice()).unwrap();
    rsa_pem.sync_all().unwrap();

    // write to config file
    let mut config = Ini::new();
    config
        .with_general_section()
        .set("hostkey", key_file.to_str().unwrap());
    config
        .with_section(Some("onion"))
        .set("p2p_port", "2222")
        .set("p2p_hostname", "localhost")
        .set("hop_count", "2")
        .set("api_address", "localhost:2223");
    config
        .with_section(Some("rps"))
        .set("api_address", "localhost:2224");
    config.write_to_file(&config_file).unwrap();

    // run peer
    onion_lib::run_peer(config_file)
}
