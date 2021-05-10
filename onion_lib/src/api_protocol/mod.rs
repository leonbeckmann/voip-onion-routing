mod api_connection;
mod event;
mod messages;

use crate::api_protocol::event::{IncomingEvent, OutgoingEvent};
use api_connection::Connection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{Receiver, Sender};

pub(crate) const RPS_QUERY: u16 = 540;
pub(crate) const RPS_PEER: u16 = 541;

pub(crate) const ONION_TUNNEL_BUILD: u16 = 560; // incoming for tunnel build in next round
pub(crate) const ONION_TUNNEL_READY: u16 = 561; // outgoing response on build with new tunnel
pub(crate) const ONION_TUNNEL_INCOMING: u16 = 562; // outgoing to all api connection listeners
pub(crate) const ONION_TUNNEL_DESTROY: u16 = 563; // incoming Destroy a tunnel for this api connection, destroy if no listeners available anymore
pub(crate) const ONION_TUNNEL_DATA: u16 = 564; // incoming/outgoing send/recv data via a tunnel
pub(crate) const ONION_ERROR: u16 = 565; // by onion module on error to earlier request
pub(crate) const ONION_COVER: u16 = 566; // send cover traffic to random peer

async fn handle_connection(
    connection: Connection,
    _write_tx: Sender<OutgoingEvent>,
    mut read_rx: Receiver<IncomingEvent>,
    connections: Arc<Mutex<HashMap<u64, Connection>>>,
) {
    let connection_id = connection.internal_id;
    log::debug!("Handle new API connection with id {:?}", connection_id);

    // register connection at registry
    match connections.lock() {
        Ok(mut connections) => {
            connections.insert(connection.internal_id, connection);
        }
        Err(e) => {
            log::error!("Cannot acquire connections lock: {}", e);
            return;
        }
    }

    // read async events on this connection
    loop {
        match read_rx.recv().await {
            Some(_event) => {
                log::debug!("New event");
                // TODO handle event
            }
            None => {
                // connection was closed
                match connections.lock() {
                    Ok(mut connections) => {
                        log::debug!(
                            "Unregister connection with id {:?} from connections",
                            connection_id
                        );
                        connections.remove(&connection_id);
                    }
                    Err(e) => {
                        log::error!("Cannot acquire connections lock: {}", e);
                        return;
                    }
                }
                return;
            }
        };
    }
}

pub async fn listen(api_address: &SocketAddr) -> anyhow::Result<()> {
    // run a TCP listener async
    let listener = TcpListener::bind(api_address).await?;
    // TODO is there a way for a well-distributed key?
    let connections = Arc::new(Mutex::new(HashMap::new()));

    // loop over new api_connections
    loop {
        // clone connections ref
        let connections = connections.clone();
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    // start a new mpsc channel for communicating with the connection
                    let (write_tx, write_rx) = tokio::sync::mpsc::channel(32);
                    let (read_tx, read_rx) = tokio::sync::mpsc::channel(32);

                    // create connection
                    let connection = Connection::new(write_tx.clone());
                    connection.start(stream, read_tx, write_rx).await;

                    // handle connection
                    handle_connection(connection, write_tx, read_rx, connections).await;
                });
            }
            Err(e) => {
                // TODO when is this error happening? Do we have to return here?
                log::warn!("Error occurred during accepting new TCP client: {}", e);
            }
        };
    }
}
