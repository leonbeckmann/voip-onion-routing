extern crate anyhow;
extern crate onion_lib;

use ini::Ini;
use openssl::rsa::Rsa;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::thread::sleep;
use std::time::Duration;
use tempfile::TempDir;

use onion_lib::api_protocol::messages::{
    OnionCover, OnionError, OnionMessageHeader, OnionTunnelBuild, OnionTunnelData,
    OnionTunnelDestroy, OnionTunnelIncoming, OnionTunnelReady,
};
use onion_lib::p2p_protocol::rps_api::{RpsPeer, ONION_PORT, RPS_PEER, RPS_QUERY};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const ONION_TUNNEL_BUILD: u16 = 560; // incoming for tunnel build in next round
const ONION_TUNNEL_READY: u16 = 561; // outgoing response on build with new tunnel
const ONION_TUNNEL_INCOMING: u16 = 562; // outgoing to all api connection listeners
const ONION_TUNNEL_DESTROY: u16 = 563; // incoming Destroy a tunnel for this api connection, destroy if no listeners available anymore
const ONION_TUNNEL_DATA: u16 = 564; // incoming/outgoing send/recv data via a tunnel
const ONION_ERROR: u16 = 565; // by onion module on error to earlier request
const ONION_COVER: u16 = 566; // send cover traffic to random peer

const PAYLOAD_CHUNK_SIZE: usize = 963;

#[allow(clippy::too_many_arguments)]
fn run_peer(
    p2p_port: &str,
    onion_api_addr: &str,
    rps_api_addr: &str,
    config_file: PathBuf,
    key_file: &Path,
    priv_key_file: &Path,
    cert_file: &Path,
    pki_cert_file: &Path,
    round_time: Duration,
) {
    // write to config file
    let mut config = Ini::new();
    config
        .with_general_section()
        .set("hostkey", key_file.to_str().unwrap());
    config
        .with_section(Some("onion"))
        .set("p2p_port", p2p_port)
        .set("p2p_hostname", "127.0.0.1")
        .set("hop_count", "2")
        .set("api_address", onion_api_addr)
        .set("round_time", format!("{:?}", round_time.as_secs()))
        .set("private_hostkey", priv_key_file.to_str().unwrap())
        .set("handshake_timeout", "1000")
        .set("pki_root_cert", pki_cert_file.to_str().unwrap())
        .set("hostkey_cert", cert_file.to_str().unwrap())
        .set("blocklist_time", "10");
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
    let hdr = OnionMessageHeader::try_from(&buf).unwrap();

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

fn run_rps_api(
    addr: SocketAddr,
    port_hop1: u16,
    port_hop2: u16,
    key_hop1: Vec<u8>,
    key_hop2: Vec<u8>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)?;

    let ip = IpAddr::from_str("127.0.0.1").unwrap();
    let port = 1234;
    let mut port_map_hop1 = HashMap::new();
    port_map_hop1.insert(ONION_PORT, port_hop1);
    let mut port_map_hop2 = HashMap::new();
    port_map_hop2.insert(ONION_PORT, port_hop2);

    let hop1 = RpsPeer::new(ip, port, port_map_hop1, key_hop1);
    let hop2 = RpsPeer::new(ip, port, port_map_hop2, key_hop2);

    let hops = vec![hop1, hop2];

    std::thread::spawn(move || {
        let mut next_peer = 0;
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buf = [0u8; OnionMessageHeader::hdr_size()];
                    stream.read_exact(&mut buf).unwrap();

                    // parse buf the onion_msg_hdr
                    let hdr = OnionMessageHeader::try_from(&buf).unwrap();

                    if hdr.msg_type != RPS_QUERY {
                        continue;
                    }

                    let peer_raw = hops.get(next_peer).unwrap().to_be_vec();
                    let hdr = OnionMessageHeader::new(
                        (peer_raw.len() + OnionMessageHeader::hdr_size()) as u16,
                        RPS_PEER,
                    )
                    .to_be_vec();

                    stream.write_all(hdr.as_ref()).unwrap();
                    stream.write_all(peer_raw.as_ref()).unwrap();

                    next_peer = (next_peer + 1) % 2;
                }
                Err(_) => {
                    return;
                }
            }
        }
    });

    Ok(())
}

#[test]
fn integration_test() {
    // enable logging
    env::set_var("RUST_LOG", "info");
    #[cfg(not(coverage))]
    env_logger::init();
    #[cfg(coverage)]
    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .parse_filters("trace")
        .try_init()
        .unwrap();

    log::info!("Starting integration test");

    // run alice and bob and hop1
    let dir = TempDir::new().unwrap();

    let config_file_alice = dir.path().join("alice.config");
    let config_file_bob = dir.path().join("bob.config");
    let config_file_hop1 = dir.path().join("hop1.config");
    let config_file_hop2 = dir.path().join("hop2.config");

    let key_file_alice = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "alice.key.pub"
    ));

    let priv_key_file_alice = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "alice.key"
    ));

    let cert_alice = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "alice.cert"
    ));

    let key_file_bob = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "bob.key.pub"
    ));

    let priv_key_file_bob = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "bob.key"
    ));

    let cert_bob = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "bob.cert"
    ));

    let key_file_hop1 = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "hop1.key.pub"
    ));

    let priv_key_file_hop1 = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "hop1.key"
    ));

    let cert_hop1 = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "hop1.cert"
    ));

    let key_file_hop2 = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "hop2.key.pub"
    ));

    let priv_key_file_hop2 = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "hop2.key"
    ));

    let cert_hop2 = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "hop2.cert"
    ));

    let cert_pki = PathBuf::from(format!(
        "{}/resources/openssl/{}",
        env!("CARGO_MANIFEST_DIR"),
        "pki.cert"
    ));

    log::info!("TEST: Starting peer alice ..");
    let round_time = Duration::from_secs(3);
    run_peer(
        "2001",
        "127.0.0.1:2002",
        "127.0.0.1:2003",
        config_file_alice,
        &key_file_alice,
        &priv_key_file_alice,
        &cert_alice,
        &cert_pki,
        round_time,
    );

    log::info!("TEST: Starting peer bob ..");
    run_peer(
        "3001",
        "127.0.0.1:3002",
        "127.0.0.1:3003",
        config_file_bob,
        &key_file_bob,
        &priv_key_file_bob,
        &cert_bob,
        &cert_pki,
        round_time,
    );

    log::info!("TEST: Starting peer hop1 ..");
    run_peer(
        "4001",
        "127.0.0.1:4002",
        "127.0.0.1:4003",
        config_file_hop1,
        &key_file_hop1,
        &priv_key_file_hop1,
        &cert_hop1,
        &cert_pki,
        round_time,
    );

    log::info!("TEST: Starting peer hop2 ..");
    run_peer(
        "5001",
        "127.0.0.1:5002",
        "127.0.0.1:5003",
        config_file_hop2,
        &key_file_hop2,
        &priv_key_file_hop2,
        &cert_hop2,
        &cert_pki,
        round_time,
    );

    // connect to alice from CM/CI
    let mut alice_api = match connect("localhost:2002") {
        None => {
            panic!("Cannot connect to Alice from CM/CI")
        }
        Some(s) => {
            log::info!("TEST: API connection established to Alice");
            s
        }
    };

    // connect to bob from CM/CI
    let mut bob_api = match connect("localhost:3002") {
        None => {
            panic!("Cannot connect to Bob from CM/CI")
        }
        Some(s) => {
            log::info!("TEST: API connection established to Bob");
            s
        }
    };

    // get keys from Alice and Bob and hops
    let _alice_host_key_der = Rsa::public_key_from_pem(fs::read(key_file_alice).unwrap().as_ref())
        .unwrap()
        .public_key_to_der()
        .unwrap();
    let bob_host_key_der = Rsa::public_key_from_pem(fs::read(key_file_bob).unwrap().as_ref())
        .unwrap()
        .public_key_to_der()
        .unwrap();
    let hop1_host_key_der = Rsa::public_key_from_pem(fs::read(key_file_hop1).unwrap().as_ref())
        .unwrap()
        .public_key_to_der()
        .unwrap();
    let hop2_host_key_der = Rsa::public_key_from_pem(fs::read(key_file_hop2).unwrap().as_ref())
        .unwrap()
        .public_key_to_der()
        .unwrap();

    // run rps api
    run_rps_api(
        SocketAddr::from_str("127.0.0.1:2003").unwrap(),
        4001,
        5001,
        hop1_host_key_der.clone(),
        hop2_host_key_der.clone(),
    )
    .unwrap();

    // run rps api
    run_rps_api(
        SocketAddr::from_str("127.0.0.1:3003").unwrap(),
        4001,
        5001,
        hop1_host_key_der.clone(),
        hop2_host_key_der.clone(),
    )
    .unwrap();

    // run rps api
    run_rps_api(
        SocketAddr::from_str("127.0.0.1:4003").unwrap(),
        4001,
        5001,
        hop1_host_key_der.clone(),
        hop2_host_key_der.clone(),
    )
    .unwrap();

    // run rps api
    run_rps_api(
        SocketAddr::from_str("127.0.0.1:5003").unwrap(),
        4001,
        5001,
        hop1_host_key_der,
        hop2_host_key_der,
    )
    .unwrap();

    // TEST: send cover traffic, should return an error because no cover tunnel is available in the beginning
    log::info!("TEST: Send cover traffic via cover tunnel and expect error");
    let tunnel_cover = OnionCover::new(300).to_be_vec();
    write_msg(ONION_COVER, tunnel_cover, &mut alice_api);
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_ERROR);
    let error = OnionError::try_from(data).unwrap();
    assert_eq!(error.tunnel_id, 0);
    assert_eq!(error.request_type, ONION_COVER);

    // TEST: destroy non-existent tunnel id
    log::info!("TEST: Request TunnelDestroy for non-existent tunnel ID");
    let tunnel_destroy = OnionTunnelDestroy::new(20).to_be_vec();
    write_msg(ONION_TUNNEL_DESTROY, tunnel_destroy, &mut alice_api);
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_ERROR);
    let error = OnionError::try_from(data).unwrap();
    assert_eq!(error.tunnel_id, 20);
    assert_eq!(error.request_type, ONION_TUNNEL_DESTROY);

    // TEST: build tunnel to non-existent peer
    log::info!("TEST: Request TunnelBuild from Alice to non-existent peer 127.0.0.1:10000");
    let unknown_peer = IpAddr::from_str("127.0.0.1").unwrap();
    let unknown_port = 10000;
    let tunnel_build = OnionTunnelBuild::new(unknown_peer, unknown_port, vec![]).to_be_vec();
    write_msg(ONION_TUNNEL_BUILD, tunnel_build, &mut alice_api);
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_ERROR);
    let error = OnionError::try_from(data).unwrap();
    assert_eq!(error.tunnel_id, 0);
    assert_eq!(error.request_type, ONION_TUNNEL_BUILD);

    // TEST: send data via non-existent tunnel
    log::info!("TEST: Request TunnelData via non-existent tunnel");
    let tunnel_data = OnionTunnelData::new(20, "hello".as_bytes().to_vec()).to_be_vec();
    write_msg(ONION_TUNNEL_DATA, tunnel_data, &mut alice_api);
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_ERROR);
    let error = OnionError::try_from(data).unwrap();
    assert_eq!(error.tunnel_id, 20);
    assert_eq!(error.request_type, ONION_TUNNEL_DATA);

    // TEST: cover tunnel at Bob
    sleep(Duration::from_millis(500)); // wait until cover tunnel available at Bob
    log::info!("TEST: Send cover traffic via cover tunnel");
    let tunnel_cover = OnionCover::new(300).to_be_vec();
    write_msg(ONION_COVER, tunnel_cover, &mut bob_api);

    // TEST: request new tunnel from alice to bob in next round
    log::info!("TEST: Request TunnelBuild from Alice to Bob at 127.0.0.1:3001");
    let bob_hostname = IpAddr::from_str("127.0.0.1").unwrap();
    let bob_port = 3001;
    let tunnel_build =
        OnionTunnelBuild::new(bob_hostname, bob_port, bob_host_key_der.clone()).to_be_vec();
    write_msg(ONION_TUNNEL_BUILD, tunnel_build, &mut alice_api);

    // expect TunnelReady response
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_TUNNEL_READY);
    let ready = Box::<OnionTunnelReady>::try_from(data).unwrap();
    let alice_to_bob_tunnel = ready.tunnel_id;
    log::info!(
        "TEST: Alice has received TUNNEL_READY with tunnel ID {:?}",
        alice_to_bob_tunnel
    );

    // expect Incoming message on Bob's API
    let (hdr, data) = read_msg(&mut bob_api);
    assert_eq!(hdr.msg_type, ONION_TUNNEL_INCOMING);
    let incoming = OnionTunnelIncoming::try_from(data).unwrap();
    let bob_from_alice_tunnel = incoming.tunnel_id;
    log::info!(
        "TEST: Bob has received TUNNEL_INCOMING with tunnel ID {:?}",
        bob_from_alice_tunnel
    );

    // TEST: send data from Alice to Bob
    log::info!("TEST: Request TunnelData='PING' from Alice to Bob");
    let message_ping = "PING".as_bytes();
    let tunnel_data = OnionTunnelData::new(alice_to_bob_tunnel, message_ping.to_vec()).to_be_vec();
    write_msg(ONION_TUNNEL_DATA, tunnel_data, &mut alice_api);

    // expect incoming data in Bob's API
    let (hdr, data) = read_msg(&mut bob_api);
    assert_eq!(hdr.msg_type, ONION_TUNNEL_DATA);
    let incoming = Box::<OnionTunnelData>::try_from(data).unwrap();
    assert_eq!(incoming.tunnel_id, bob_from_alice_tunnel);
    assert_eq!(incoming.data.as_slice(), message_ping);
    log::info!("TEST: Bob has received PING");

    // TEST: send data from Bob to Alice
    log::info!("TEST: Request TunnelData='PONG' from Bob to Alice");
    let message_pong = "PONG".as_bytes();
    let tunnel_data =
        OnionTunnelData::new(bob_from_alice_tunnel, message_pong.to_vec()).to_be_vec();
    write_msg(ONION_TUNNEL_DATA, tunnel_data, &mut bob_api);

    // expect incoming data in Alice's API
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_TUNNEL_DATA);
    let incoming = Box::<OnionTunnelData>::try_from(data).unwrap();
    assert_eq!(incoming.tunnel_id, alice_to_bob_tunnel);
    assert_eq!(incoming.data.as_slice(), message_pong);
    log::info!("TEST: Alice has received PONG");

    // wait for new round to test tunnel update
    log::info!("TEST: Wait for next round to check tunnel update");
    sleep(round_time);

    // send fragmented data from Alice to Bob
    log::info!("TEST: Send fragmented TunnelData from Alice to Bob via updated tunnel");
    let message = (0..PAYLOAD_CHUNK_SIZE + 1)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>();
    let tunnel_data = OnionTunnelData::new(alice_to_bob_tunnel, message.to_vec()).to_be_vec();
    write_msg(ONION_TUNNEL_DATA, tunnel_data, &mut alice_api);

    // expect incoming data in Bob's API
    let mut collected_incoming_data = vec![];
    for _ in 0..2 {
        let (hdr, data) = read_msg(&mut bob_api);
        assert_eq!(hdr.msg_type, ONION_TUNNEL_DATA);
        let mut incoming = Box::<OnionTunnelData>::try_from(data).unwrap();
        assert_eq!(incoming.tunnel_id, bob_from_alice_tunnel);
        collected_incoming_data.append(incoming.data.as_mut())
    }
    assert_eq!(collected_incoming_data, message);
    log::info!("TEST: Bob has received fragmented data");

    // wait for another round to test multiple tunnel updates
    log::info!("TEST: Wait for another round to check multiple tunnel updates");
    sleep(round_time);

    // send fragmented data from Bob to Alice
    log::info!("TEST: Send fragmented TunnelData from Bob to Alice");
    let message = (0..PAYLOAD_CHUNK_SIZE + 1)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>();
    let tunnel_data = OnionTunnelData::new(bob_from_alice_tunnel, message.to_vec()).to_be_vec();
    write_msg(ONION_TUNNEL_DATA, tunnel_data, &mut bob_api);

    // expect incoming data in Bob's API
    let mut collected_incoming_data = vec![];
    for _ in 0..2 {
        let (hdr, data) = read_msg(&mut alice_api);
        assert_eq!(hdr.msg_type, ONION_TUNNEL_DATA);
        let mut incoming = Box::<OnionTunnelData>::try_from(data).unwrap();
        assert_eq!(incoming.tunnel_id, alice_to_bob_tunnel);
        collected_incoming_data.append(incoming.data.as_mut())
    }
    assert_eq!(collected_incoming_data, message);
    log::info!("TEST: Alice has received fragmented data");

    // TEST: destroy the connection via alice
    log::info!("TEST: Request TunnelDestroy from Alice");
    let tunnel_destroy = OnionTunnelDestroy::new(alice_to_bob_tunnel).to_be_vec();
    write_msg(ONION_TUNNEL_DESTROY, tunnel_destroy, &mut alice_api);
    sleep(Duration::from_millis(500));

    // TEST: cannot send data from Alice to Bob anymore
    log::info!("TEST: Send data from Alice to Bob via old tunnel and expect failure");
    let tunnel_data = OnionTunnelData::new(alice_to_bob_tunnel, message_ping.to_vec()).to_be_vec();
    write_msg(ONION_TUNNEL_DATA, tunnel_data, &mut alice_api);
    let (hdr, data) = read_msg(&mut alice_api);
    assert_eq!(hdr.msg_type, ONION_ERROR);
    let error = OnionError::try_from(data).unwrap();
    assert_eq!(error.tunnel_id, alice_to_bob_tunnel);
    assert_eq!(error.request_type, ONION_TUNNEL_DATA);

    // TEST: cannot send data from Bob to Alice anymore
    log::info!("TEST: Send data from Bob to Alice via old tunnel and expect failure");
    let tunnel_data =
        OnionTunnelData::new(bob_from_alice_tunnel, "test".as_bytes().to_vec()).to_be_vec();
    write_msg(ONION_TUNNEL_DATA, tunnel_data, &mut bob_api);
    let (hdr, data) = read_msg(&mut bob_api);
    assert_eq!(hdr.msg_type, ONION_ERROR);
    let error = OnionError::try_from(data).unwrap();
    assert_eq!(error.tunnel_id, bob_from_alice_tunnel);
    assert_eq!(error.request_type, ONION_TUNNEL_DATA);

    // send cover traffic from Alice
    log::info!("TEST: Send cover traffic via downgraded cover tunnel");
    let tunnel_cover = OnionCover::new(300).to_be_vec();
    write_msg(ONION_COVER, tunnel_cover, &mut alice_api);

    // wait for another round with no new tunnel
    log::info!("TEST: Wait for another round without tunnel update");
    sleep(round_time);

    log::info!("TEST: Send cover traffic via cover tunnel");
    let tunnel_cover = OnionCover::new(300).to_be_vec();
    write_msg(ONION_COVER, tunnel_cover, &mut alice_api);

    // TEST: request multiple connections and expect error while one connection is established
    log::info!("TEST: Request multiple tunnel builds and expect error on second request");
    let bob_hostname = IpAddr::from_str("127.0.0.1").unwrap();
    let bob_port = 3001;
    let tunnel_build =
        OnionTunnelBuild::new(bob_hostname, bob_port, bob_host_key_der.clone()).to_be_vec();
    let tunnel_build2 = OnionTunnelBuild::new(bob_hostname, bob_port, bob_host_key_der).to_be_vec();
    write_msg(ONION_TUNNEL_BUILD, tunnel_build, &mut alice_api);
    write_msg(ONION_TUNNEL_BUILD, tunnel_build2, &mut alice_api);

    // expect TunnelReady response and error response
    let (hdr1, _) = read_msg(&mut alice_api);
    let (hdr2, _) = read_msg(&mut alice_api);
    assert!(
        hdr1.msg_type == ONION_TUNNEL_READY && hdr2.msg_type == ONION_ERROR
            || hdr2.msg_type == ONION_TUNNEL_READY && hdr1.msg_type == ONION_ERROR
    )
}
