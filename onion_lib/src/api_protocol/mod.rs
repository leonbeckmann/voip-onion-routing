mod api_connection;
mod event;
mod messages;

use api_connection::Connection;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub(crate) const RPS_QUERY: u16 = 540;
pub(crate) const RPS_PEER: u16 = 541;

pub(crate) const ONION_TUNNEL_BUILD: u16 = 560; // incoming for tunnel build in next round
pub(crate) const ONION_TUNNEL_READY: u16 = 561; // outgoing response on build with new tunnel
pub(crate) const ONION_TUNNEL_INCOMING: u16 = 562; // outgoing to all api connection listeners
pub(crate) const ONION_TUNNEL_DESTROY: u16 = 563; // incoming Destroy a tunnel for this api connection, destroy if no listeners available anymore
pub(crate) const ONION_TUNNEL_DATA: u16 = 564; // incoming/outgoing send/recv data via a tunnel
pub(crate) const ONION_ERROR: u16 = 565; // by onion module on error to earlier request
pub(crate) const ONION_COVER: u16 = 566; // send cover traffic to random peer

async fn handle_connection(mut connection: Connection) {
    // TODO register connection at some registry

    log::debug!("Handle new API connection");

    // read async events on this connection
    loop {
        match connection.read_event().await {
            Ok(_event) => {
                log::debug!("New event");
                // TODO handle event
            }
            Err(e) => {
                log::warn!("Cannot read from connection: {}", e);
                // TODO unregister from registry
                return;
            }
        };
    }
}

pub async fn listen(api_address: &SocketAddr) -> anyhow::Result<()> {
    // run a TCP listener async
    let listener = TcpListener::bind(api_address).await?;

    // loop over new api_connections
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    let connection = Connection::new(stream);
                    handle_connection(connection).await;
                });
            }
            Err(e) => {
                // TODO when is this error happening? Do we have to return here?
                log::warn!("Error occurred during accepting new TCP client: {}", e);
            }
        };
    }
}
