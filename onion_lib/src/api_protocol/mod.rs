mod api_connection;
mod event;
pub mod messages;

use crate::api_protocol::event::{IncomingEvent, OutgoingEvent};
use crate::api_protocol::messages::{OnionError, OnionTunnelReady};
use crate::p2p_protocol::P2pInterface;
use api_connection::Connection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

pub(crate) const ONION_TUNNEL_BUILD: u16 = 560; // incoming for tunnel build in next round
pub(crate) const ONION_TUNNEL_READY: u16 = 561; // outgoing response on build with new tunnel
pub(crate) const ONION_TUNNEL_INCOMING: u16 = 562; // outgoing to all api connection listeners
pub(crate) const ONION_TUNNEL_DESTROY: u16 = 563; // incoming Destroy a tunnel for this api connection, destroy if no listeners available anymore
pub(crate) const ONION_TUNNEL_DATA: u16 = 564; // incoming/outgoing send/recv data via a tunnel
pub(crate) const ONION_ERROR: u16 = 565; // by onion module on error to earlier request
pub(crate) const ONION_COVER: u16 = 566; // send cover traffic to random peer

async fn handle_incoming_event(
    e: IncomingEvent,
    p2p_interface: Weak<P2pInterface>,
    connection_id: u64,
) -> Option<OutgoingEvent> {
    // first we have to upgrade the p2p interface reference to communicate with p2p layer
    match p2p_interface.upgrade() {
        Some(interface) => match e {
            IncomingEvent::TunnelBuild(onion_build) => {
                log::debug!(
                    "TunnelBuild request from connection {:?}: {:?}",
                    connection_id,
                    onion_build
                );
                match interface
                    .build_tunnel(
                        (onion_build.ip, onion_build.onion_port).into(),
                        onion_build.host_key,
                        connection_id,
                    )
                    .await
                {
                    Ok((tunnel_id, host_key_der)) => {
                        log::debug!(
                            "New onion tunnel was established with tunnel id {:?}",
                            tunnel_id
                        );
                        Some(OutgoingEvent::TunnelReady(Box::new(OnionTunnelReady::new(
                            tunnel_id,
                            host_key_der,
                        ))))
                    }
                    Err(e) => {
                        log::warn!(
                            "Cannot build new onion tunnel from connection {:?}: {:?}",
                            connection_id,
                            e
                        );
                        // TODO is this how we should react when there is no tunnel id available yet?
                        Some(OutgoingEvent::Error(OnionError::new(ONION_TUNNEL_BUILD, 0)))
                    }
                }
            }

            IncomingEvent::TunnelDestroy(onion_destroy) => {
                log::debug!(
                    "TunnelDestroy request from connection {:?}: {:?}",
                    connection_id,
                    onion_destroy
                );
                match interface
                    .destroy_tunnel_ref(onion_destroy.tunnel_id, connection_id)
                    .await
                {
                    Ok(_) => None,
                    Err(e) => {
                        log::warn!(
                            "Cannot destroy tunnel {:?} from connection {:?}: {:?}",
                            onion_destroy.tunnel_id,
                            connection_id,
                            e
                        );
                        Some(OutgoingEvent::Error(OnionError::new(
                            ONION_TUNNEL_DESTROY,
                            onion_destroy.tunnel_id,
                        )))
                    }
                }
            }

            IncomingEvent::TunnelData(onion_data) => {
                log::debug!(
                    "TunnelData request from connection {:?}: {:?}",
                    connection_id,
                    onion_data
                );
                match interface
                    .send_data(onion_data.tunnel_id, onion_data.data)
                    .await
                {
                    Ok(_) => None,
                    Err(e) => {
                        log::warn!(
                            "Cannot send data to tunnel {:?} from connection {:?}: {:?}",
                            onion_data.tunnel_id,
                            connection_id,
                            e
                        );
                        Some(OutgoingEvent::Error(OnionError::new(
                            ONION_TUNNEL_DATA,
                            onion_data.tunnel_id,
                        )))
                    }
                }
            }

            IncomingEvent::Cover(onion_cover) => {
                log::debug!(
                    "OnionCover request from connection {:?}: {:?}",
                    connection_id,
                    onion_cover
                );
                match interface.send_cover_traffic(onion_cover.cover_size).await {
                    Ok(_) => None,
                    Err(e) => {
                        log::warn!(
                            "Cannot send cover traffic from connection {:?}: {:?}",
                            connection_id,
                            e
                        );
                        // TODO is this how we should react when there is no tunnel id available yet?
                        Some(OutgoingEvent::Error(OnionError::new(ONION_COVER, 0)))
                    }
                }
            }
        },
        None => {
            // interface not available, so the p2p listener has terminated
            // calling functions will ensure termination when this is happening
            log::error!("P2P interface is not available anymore");
            None
        }
    }
}

async fn handle_connection(
    connection: Connection,
    write_tx: Sender<OutgoingEvent>,
    mut read_rx: Receiver<IncomingEvent>,
    connections: Arc<Mutex<HashMap<u64, Connection>>>,
    p2p_interface: Weak<P2pInterface>,
) {
    let connection_id = connection.internal_id;
    log::debug!("Handle new API connection with id {:?}", connection_id);

    // register connection at registry
    let connections_clone = connections.clone();
    let mut connections_guard = connections_clone.lock().await;
    log::debug!(
        "Register connection {:?} in connections registry",
        connection_id
    );
    connections_guard.insert(connection.internal_id, connection);

    async fn unregister_connection(
        connections: Arc<Mutex<HashMap<u64, Connection>>>,
        connection_id: u64,
        p2p_interface: Weak<P2pInterface>,
    ) {
        if let Some(i_face) = p2p_interface.upgrade() {
            log::debug!(
                "Unsubscribe connection with id {:?} from all onion tunnels",
                connection_id
            );
            i_face.unsubscribe(connection_id).await;
        }
        let mut connections_guard = connections.lock().await;
        log::debug!(
            "Unregister connection with id {:?} from connections",
            connection_id
        );
        connections_guard.remove(&connection_id);
    }

    // read async events on this connection
    loop {
        let p2p_interface = p2p_interface.clone();
        match read_rx.recv().await {
            Some(event) => {
                if let Some(e) =
                    handle_incoming_event(event, p2p_interface.clone(), connection_id).await
                {
                    log::debug!(
                        "Send response {:?} to CM/CI via connection {:?}",
                        e,
                        connection_id
                    );
                    if write_tx.send(e).await.is_err() {
                        // connection has been closed
                        unregister_connection(connections, connection_id, p2p_interface.clone())
                            .await;
                        return;
                    }
                }
            }
            None => {
                // connection has been closed
                log::debug!("Connection with id {:?} has been closed", connection_id);
                unregister_connection(connections, connection_id, p2p_interface.clone()).await;
                return;
            }
        };
    }
}

pub(crate) struct ApiInterface {
    // TODO is there a way for a well-distributed key?
    pub connections: Arc<Mutex<HashMap<u64, Connection>>>,
}

impl ApiInterface {
    //TODO add api for p2p protocol

    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn listen(
        &self,
        api_address: SocketAddr,
        p2p_interface: Weak<P2pInterface>,
    ) -> anyhow::Result<()> {
        // run a TCP listener async
        let listener = TcpListener::bind(api_address).await?;

        // loop over new api_connections
        loop {
            // clone connections ref
            let p2p_interface = p2p_interface.clone();
            let connections = self.connections.clone();
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
                        handle_connection(
                            connection,
                            write_tx,
                            read_rx,
                            connections,
                            p2p_interface,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    // TODO when is this error happening? Do we always have to quit here?
                    log::error!("Error occurred during accepting new TCP client: {}", e);
                    return Err(anyhow::Error::from(e));
                }
            };
        }
    }
}
