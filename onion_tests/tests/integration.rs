extern crate anyhow;
extern crate onion_lib;
use env_logger;
use ini::Ini;
use log;
use openssl::rsa::Rsa;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::thread::sleep;
use std::time::Duration;
use tempdir::TempDir;

use onion_lib::api_protocol::messages::{OnionMessageHeader, OnionTunnelBuild, OnionTunnelReady, OnionTunnelDestroy, OnionError};
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;

const ONION_TUNNEL_BUILD: u16 = 560; // incoming for tunnel build in next round
const ONION_TUNNEL_READY: u16 = 561; // outgoing response on build with new tunnel
const _ONION_TUNNEL_INCOMING: u16 = 562; // outgoing to all api connection listeners
const ONION_TUNNEL_DESTROY: u16 = 563; // incoming Destroy a tunnel for this api connection, destroy if no listeners available anymore
const _ONION_TUNNEL_DATA: u16 = 564; // incoming/outgoing send/recv data via a tunnel
const ONION_ERROR: u16 = 565; // by onion module on error to earlier request
const _ONION_COVER: u16 = 566; // send cover traffic to random peer

fn run_peer(
    p2p_port: &str,
    onion_api_addr: &str,
    rps_api_addr: &str,
    config_file: PathBuf,
    key_file: &PathBuf,
    pub_pem: Vec<u8>,
) {
    // create rsa files
    let mut rsa_pem = File::create(&key_file).unwrap();
    rsa_pem.write_all(pub_pem.as_slice()).unwrap();
    rsa_pem.sync_all().unwrap();

    // write to config file
    let mut config = Ini::new();
    config
        .with_section(Some("onion"))
        .set("p2p_port", p2p_port)
        .set("p2p_hostname", "127.0.0.1")
        .set("hop_count", "2")
        .set("hostkey", key_file.to_str().unwrap())
        .set("api_address", onion_api_addr);
    config
        .with_section(Some("rps"))
        .set("api_address", rps_api_addr);
    config.write_to_file(&config_file).unwrap();

    // run peer
    std::thread::spawn(move || {
        onion_lib::run_peer(config_file);
    });
}

fn connect(addr: &'static str) -> Option<TcpStream> {
    for _ in 1..6 {
        sleep(Duration::from_millis(500));
        if let Ok(s) = TcpStream::connect(addr) {
            return Some(s);
        }
    }
    None
}

fn read_msg(stream: &mut TcpStream) -> (OnionMessageHeader, Vec<u8>) {
    let mut buf = [0u8; OnionMessageHeader::hdr_size()];
    stream.read_exact(&mut buf).unwrap();

    // parse buf the onion_msg_hdr
    let hdr = OnionMessageHeader::from(&buf);

    // read remaining message into buf without the hdr
    let mut buf = vec![0u8; hdr.size as usize - OnionMessageHeader::hdr_size()];
    stream.read_exact(&mut buf).unwrap();

    (hdr, buf)
}

fn write_msg(msg_type: u16, data: Vec<u8>, stream: &mut TcpStream) {
    let hdr = OnionMessageHeader::new(
        (data.len() + OnionMessageHeader::hdr_size()) as u16,
        msg_type,
    )
    .to_be_vec();

    stream.write_all(hdr.as_slice()).unwrap();
    stream.write_all(data.as_slice()).unwrap();
}

#[test]
fn integration_test() {
    // enable logging
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    log::info!("Starting integration test");

    // run alice and bob
    let dir = TempDir::new("onion-test").unwrap();

    let config_file_alice = dir.path().join("alice.config");
    let key_file_alice = dir.path().join("alice.key");
    let config_file_bob = dir.path().join("bob.config");
    let key_file_bob = dir.path().join("bob.key");

    // create RSA keys
    let alice_key = Rsa::generate(4096).unwrap();
    let alice_pub_pem = alice_key.public_key_to_pem().unwrap();

    let bob_key = Rsa::generate(4096).unwrap();
    let bob_pub_pem = bob_key.public_key_to_pem().unwrap();

    log::info!("Starting peer alice ..");
    run_peer(
        "2001",
        "127.0.0.1:2002",
        "127.0.0.1:2003",
        config_file_alice,
        &key_file_alice,
        alice_pub_pem,
    );

    log::info!("Starting peer bob ..");
    run_peer(
        "3001",
        "127.0.0.1:3002",
        "127.0.0.1:3003",
        config_file_bob,
        &key_file_bob,
        bob_pub_pem,
    );

    // connect to alice from CM/CI
    let mut alice_api = match connect("localhost:2002") {
        None => {
            panic!("Cannot connect to Alice from CM/CI")
        }
        Some(s) => {
            log::info!("API connection established to Alice");
            s
        }
    };

    // connect to bob from CM/CI
    let _bob_api = match connect("localhost:3002") {
        None => {
            panic!("Cannot connect to Bob from CM/CI")
        }
        Some(s) => {
            log::info!("API connection established to Bob");
            s
        }
    };

    // get keys from Alice and Bob
    let _alice_host_key_der = alice_key.public_key_to_der().unwrap();
    let bob_host_key_der = bob_key.public_key_to_der().unwrap();

    // destroy non-existent tunnel id
    log::info!("Request TunnelDestroy for non-existent tunnel ID");
    let tunnel_destroy = OnionTunnelDestroy::new(20).to_be_vec();
    write_msg(ONION_TUNNEL_DESTROY, tunnel_destroy, &mut alice_api);
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_ERROR);
    let error = OnionError::try_from(data).unwrap();
    assert_eq!(error.tunnel_id, 20);
    assert_eq!(error.request_type, ONION_TUNNEL_DESTROY);

    // TODO build tunnel to non-existent peer

    // TODO send data via non-existent tunnel

    // request new tunnel from alice to bob
    let bob_hostname = IpAddr::from_str("127.0.0.1").unwrap();
    let bob_port = 3001;
    log::info!("Request TunnelBuild from Alice to Bob at 127.0.0.1:3001");
    let tunnel_build = OnionTunnelBuild::new(bob_hostname, bob_port, bob_host_key_der).to_be_vec();
    write_msg(ONION_TUNNEL_BUILD, tunnel_build, &mut alice_api);

    // expect TunnelReady response
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_TUNNEL_READY);
    let ready = Box::<OnionTunnelReady>::try_from(data).unwrap();
    let alice_to_bob_tunnel = ready.tunnel_id;
    log::info!(
        "Alice received TUNNEL_READY with tunnel ID {:?}",
        alice_to_bob_tunnel
    );

    // TODO expect Incoming message on Bob's API

    // TODO send data from Alice to Bob

    // TODO expect incoming data in Bob's API

    // TODO send data from Bob to Alice

    // TODO expect incoming data in Alice's API

    // TODO destroy the connection
}
