mod api_connection;

use crate::api_protocol::api_connection::Connection;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

const RPS_QUERY: u16 = 540;
const RPS_PEER: u16 = 541;

const ONION_TUNNEL_BUILD: u16 = 560; // incoming for tunnel build in next round
const ONION_TUNNEL_READY: u16 = 561; // outgoing response on build with new tunnel
const ONION_TUNNEL_INCOMING: u16 = 562; // outgoing to all api connection listeners
const ONION_TUNNEL_DESTROY: u16 = 563; // incoming Destroy a tunnel for this api connection, destroy if no listeners available anymore
const ONION_TUNNEL_DATA: u16 = 564; // incoming/outgoing send/recv data via a tunnel
const ONION_ERROR: u16 = 565; // by onion module on error to earlier request
const ONION_COVER: u16 = 566; // send cover traffic to random peer

async fn process_client(stream: TcpStream) {
    // create a new API connection and register it to the API connection management layer
    let _connection = Connection::new(stream);
    log::debug!("New connection");
}

pub async fn listen(api_address: &SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(api_address).await?;

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    process_client(stream).await;
                });
            }
            Err(e) => {
                log::warn!("Error occurred during accepting new TCP client: {}", e);
            }
        };
    }
}
