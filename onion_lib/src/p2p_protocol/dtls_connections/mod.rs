use hex::ToHex;
use ignore_result::Ignore;
// TODO: check all used unwrap()
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sha::sha256;
use openssl::ssl::{
    ErrorCode, SslAcceptor, SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509VerifyResult, X509};
use std::collections::{BTreeMap, HashMap};
use std::io::{Error, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[derive(Clone, Debug)]
pub struct DtlsConfig {
    pki_root_cert: X509,
    local_peer_identity_cert: X509,
    private_host_key: Rsa<Private>,
    pub blocklist_time: Duration,
}

impl DtlsConfig {
    pub fn new(
        pki_root_cert: X509,
        local_peer_identity_cert: X509,
        blocklist_time: Duration,
        private_host_key: Rsa<Private>,
    ) -> Self {
        assert_eq!(
            pki_root_cert.issued(&local_peer_identity_cert),
            X509VerifyResult::OK,
            "Local certificate is not issued by PKI root cert"
        );

        let mut builder = X509StoreBuilder::new().unwrap();
        builder.add_cert(pki_root_cert.clone()).unwrap();
        let cert_store = builder.build();

        let mut cert_chain = openssl::stack::Stack::new().unwrap();
        cert_chain.push(pki_root_cert.clone()).unwrap();

        let mut x509_ctx = X509StoreContext::new().unwrap();
        assert!(x509_ctx
            .init(
                &cert_store,
                &local_peer_identity_cert,
                &cert_chain,
                |x509_ctx_callback| { Ok(x509_ctx_callback.verify_cert()) }
            )
            .unwrap()
            .unwrap(), "Certificate chain cannot be verified. Make sure the chain is ordered correctly and the CA extension flag is enabled (X509v3 only)");

        Self {
            pki_root_cert,
            local_peer_identity_cert,
            private_host_key,
            blocklist_time,
        }
    }

    pub fn rsa_cert_by_identity(&self, _id: &SocketAddr) -> Rsa<Public> {
        // TODO
        todo!();
    }
}

#[derive(Debug)]
pub struct Blocklist {
    block_duration: Duration,
    list: HashMap<SocketAddr, SystemTime>,
    unblock_queue: BTreeMap<SystemTime, Vec<SocketAddr>>,
}

impl Blocklist {
    pub fn new(block_duration: Duration) -> Blocklist {
        Blocklist {
            block_duration,
            list: HashMap::new(),
            unblock_queue: BTreeMap::new(),
        }
    }

    fn cleanup(&mut self) {
        let mut remove_times = vec![];
        let now = std::time::SystemTime::now();
        for (block_time, peers) in self.unblock_queue.iter() {
            if block_time.checked_add(self.block_duration).unwrap() < now {
                for peer in peers {
                    self.list.remove(peer);
                }
                remove_times.push(block_time.to_owned());
            } else {
                break;
            }
        }
        for block_time in remove_times {
            self.unblock_queue.remove(&block_time);
        }
    }

    pub fn is_blocked(&self, peer: &SocketAddr) -> bool {
        if let Some(block_time) = self.list.get(peer) {
            return block_time.checked_add(self.block_duration).unwrap()
                > std::time::SystemTime::now();
        }
        false
    }

    /// Block a peer
    pub fn block(&mut self, peer: SocketAddr) {
        self.cleanup();
        let now = std::time::SystemTime::now();
        self.list.insert(peer, now);
        if let Some(entry) = self.unblock_queue.get_mut(&now) {
            entry.push(peer);
        } else {
            self.unblock_queue.insert(now, vec![peer]);
        }
    }
}

/// Wrapper around UdpSocket used in openssl. This wrapper implements the multiplexing
/// of multiple UDP streams to a single UDP socket.

#[derive(Debug)]
struct UdpSocketWrapper {
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    incoming_message: std::sync::mpsc::Receiver<Vec<u8>>, // channel for incoming UDP frames
}

impl Read for UdpSocketWrapper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.incoming_message.try_recv() {
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                /*log::debug!(
                    "UdpSocketWrapper from {} to {}: incoming_message channel is disconnected",
                    self.socket.local_addr().unwrap(),
                    self.remote_addr
                );*/
                Err(ErrorKind::ConnectionReset.into())
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => Err(ErrorKind::WouldBlock.into()),
            Ok(data) => {
                log::trace!(
                    "DTLS: Received frame from {} at socket wrapper {} size {}",
                    self.remote_addr,
                    self.socket.local_addr().unwrap(),
                    data.len()
                );
                if data.len() > buf.len() {
                    return Ok(0);
                }
                buf.split_at_mut(data.len()).0.copy_from_slice(&data);
                Ok(data.len())
            }
        }
    }
}

impl Write for UdpSocketWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let r = self.socket.try_send_to(buf, self.remote_addr);
        if r.is_ok() {
            log::trace!(
                "DTLS: Send frame at socket wrapper {} to {} size {}",
                self.socket.local_addr().unwrap(),
                self.remote_addr,
                buf.len()
            );
        } else {
            log::warn!(
                "DTLS: Send frame at socket wrapper {} to {} size {}, result={:?}",
                self.socket.local_addr().unwrap(),
                self.remote_addr,
                buf.len(),
                r
            );
        }
        r
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct UdpChannel {
    raw_incoming: std::sync::mpsc::Sender<Vec<u8>>,
    ssl_stream: Option<SslStream<UdpSocketWrapper>>, // This is None during connection establishment
}

#[derive(Debug)]
pub struct DtlsSocketLayer {
    socket: Arc<UdpSocket>,
    dtls_config: Arc<DtlsConfig>,
    blocklist: Arc<RwLock<Blocklist>>,
    connection_sockets: Arc<Mutex<HashMap<SocketAddr, UdpChannel>>>,
    incoming_forwarding_worker: JoinHandle<()>,
    outgoing_forwarding_worker: JoinHandle<()>,
    outgoing_channel: Sender<(Instant, SocketAddr, Vec<u8>)>,
    loopback_channel: (Sender<Vec<u8>>, Mutex<Receiver<Vec<u8>>>),
}

impl DtlsSocketLayer {
    async fn accept_channel(
        connection_sockets_mutex: Arc<Mutex<HashMap<SocketAddr, UdpChannel>>>,
        socket: Arc<UdpSocket>,
        dtls_config: Arc<DtlsConfig>,
        remote_addr: SocketAddr,
        udp_socket_wrapper: UdpSocketWrapper,
    ) {
        // An acceptor can be cloned and reused in future connections. But because the remote_addr changes for each connection
        // the acceptor has to be recreated on each connection that we can use the openssl internal hostname verification.
        log::trace!("Creating new acceptor");

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls()).unwrap();

        // Replace trusted certificates with our PKI
        let mut builder = X509StoreBuilder::new().unwrap();
        builder.add_cert(dtls_config.pki_root_cert.clone()).unwrap();
        let cert_store = builder.build();
        acceptor_builder.set_cert_store(cert_store);

        // Enable server-side certificate verification
        acceptor_builder.set_verify(SslVerifyMode::PEER);
        // Setting hostname enables hostname verification
        let hostname = sha256(format!("{}::{}", remote_addr.ip(), remote_addr.port()).as_bytes())
            .encode_hex::<String>();
        acceptor_builder
            .verify_param_mut()
            .set_host(hostname.as_str())
            .unwrap();

        acceptor_builder
            .set_private_key(&PKey::from_rsa(dtls_config.private_host_key.clone()).unwrap())
            .unwrap();
        acceptor_builder
            .set_certificate(&dtls_config.local_peer_identity_cert)
            .unwrap();
        // TODO: Support multi layer certificate chains
        acceptor_builder
            .add_extra_chain_cert(dtls_config.pki_root_cert.clone())
            .unwrap();
        acceptor_builder.check_private_key().unwrap();
        acceptor_builder.set_options(SslOptions::NO_DTLSV1);

        let ssl_acceptor = acceptor_builder.build();

        let start_time = Instant::now();
        let mut ssl_stream = ssl_acceptor.accept(udp_socket_wrapper);
        let mut counter = 0;
        while let Err(openssl::ssl::HandshakeError::WouldBlock(s)) = ssl_stream {
            // TODO: configurable timeout
            if Instant::now() - start_time > Duration::from_secs(10) {
                ssl_stream = Err(openssl::ssl::HandshakeError::Failure(s));
                break;
            }
            // Make this blocking task asynchronous by yielding
            tokio::task::yield_now().await;
            // For low latency first do busy waiting and then reduce cpu usage by sleeping
            counter += 1;
            if counter > 10 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            ssl_stream = s.handshake();
        }

        match ssl_stream {
            Ok(ssl_stream) => {
                log::info!(
                    "Accepted DTLS channel from {} to {} successful",
                    &remote_addr,
                    socket.local_addr().unwrap(),
                );

                let mut connection_sockets = connection_sockets_mutex.lock().await;
                // Safe unwrap after insert
                let connection_socket = connection_sockets.get_mut(&remote_addr).unwrap();
                connection_socket.ssl_stream = Some(ssl_stream);
            }
            Err(e) => {
                log::info!(
                    "DTLS: Accept connection from {} to {} failed, error during Handshake: {}",
                    &remote_addr,
                    socket.local_addr().unwrap(),
                    e
                );
                let mut connection_sockets = connection_sockets_mutex.lock().await;
                assert!(connection_sockets.remove(&remote_addr).is_some());
            }
        }
    }

    /// There is a race condition when two peers try to connect with each other at the same time. Then both
    /// peers are connector, but none is in acceptor mode. In that case, the handshake fails with "unexpected message".
    /// This function returns true if it is likely that the connection failed due to this race condition.
    async fn connect_channel(
        connection_sockets_mutex: Arc<Mutex<HashMap<SocketAddr, UdpChannel>>>,
        socket: Arc<UdpSocket>,
        dtls_config: Arc<DtlsConfig>,
        remote_addr: SocketAddr,
        udp_socket_wrapper: UdpSocketWrapper,
    ) -> bool {
        log::trace!(
            "Connect DTLS channel from {} to {}...",
            socket.local_addr().unwrap(),
            remote_addr
        );

        let mut connector_builder = SslConnector::builder(SslMethod::dtls()).unwrap();

        // Replace trusted certificates with our PKI
        let mut builder = X509StoreBuilder::new().unwrap();
        builder.add_cert(dtls_config.pki_root_cert.clone()).unwrap();
        let cert_store = builder.build();
        connector_builder.set_cert_store(cert_store);

        let hostname = sha256(format!("{}::{}", remote_addr.ip(), remote_addr.port()).as_bytes())
            .encode_hex::<String>();
        connector_builder
            .verify_param_mut()
            .set_host(hostname.as_str())
            .unwrap();
        connector_builder.set_verify(SslVerifyMode::PEER);

        connector_builder
            .set_private_key(&PKey::from_rsa(dtls_config.private_host_key.clone()).unwrap())
            .unwrap();
        connector_builder
            .set_certificate(&dtls_config.local_peer_identity_cert)
            .unwrap();
        // TODO: Support multi layer certificate chains
        connector_builder
            .add_extra_chain_cert(dtls_config.pki_root_cert.clone())
            .unwrap();

        connector_builder.check_private_key().unwrap();
        connector_builder.set_options(SslOptions::NO_DTLSV1);

        let connector = connector_builder.build();

        let mut ssl_stream = connector.connect(hostname.as_str(), udp_socket_wrapper);
        let start_time = Instant::now();
        let mut counter = 0;
        while let Err(openssl::ssl::HandshakeError::WouldBlock(s)) = ssl_stream {
            // TODO: configurable timeout
            if Instant::now() - start_time > Duration::from_secs(10) {
                ssl_stream = Err(openssl::ssl::HandshakeError::Failure(s));
                break;
            }
            // Make this blocking task asynchronous by yielding
            tokio::task::yield_now().await;
            // For low latency first do busy waiting and then reduce cpu usage by sleeping
            counter += 1;
            if counter > 10 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            ssl_stream = s.handshake();
        }

        let unexpected_message_error = match ssl_stream {
            Ok(ssl_stream) => {
                log::info!(
                    "DTLS: Connected channel from {} to {} successful",
                    socket.local_addr().unwrap(),
                    &remote_addr
                );
                let mut connection_sockets = connection_sockets_mutex.lock().await;
                // Safe unwrap after insert
                let udp_channel = connection_sockets.get_mut(&remote_addr).unwrap();
                udp_channel.ssl_stream = Some(ssl_stream);
                false
            }
            Err(e) => {
                log::info!(
                    "DTLS: Connect connection from {} to {} failed, error during Handshake: {}",
                    socket.local_addr().unwrap(),
                    &remote_addr,
                    &e
                );
                let mut connection_sockets = connection_sockets_mutex.lock().await;
                assert!(connection_sockets.remove(&remote_addr).is_some());
                e.to_string().contains("unexpected message")
            }
        };

        unexpected_message_error
    }

    /// This is async to enforce running inside a tokio runtime. This is required due to tokio::spawn
    pub async fn new<A: ToSocketAddrs + Clone>(
        address: A,
        dtls_config: Arc<DtlsConfig>,
        blocklist: Arc<RwLock<Blocklist>>,
    ) -> DtlsSocketLayer {
        let socket = Arc::new(UdpSocket::bind(address.clone()).await.unwrap());
        let connection_sockets = Arc::new(Mutex::new(HashMap::new()));

        let socket_clone = socket.clone();
        let connection_sockets_clone = connection_sockets.clone();
        let dtls_config_clone = dtls_config.clone();
        let blocklist_clone = blocklist.clone();

        let incoming_forwarding_worker = tokio::spawn(async {
            DtlsSocketLayer::forward_incoming_frames(
                socket_clone,
                connection_sockets_clone,
                dtls_config_clone,
                blocklist_clone,
            )
            .await
        });

        let socket_clone = socket.clone();
        let connection_sockets_clone = connection_sockets.clone();
        let dtls_config_clone = dtls_config.clone();
        let blocklist_clone = blocklist.clone();

        let (outgoing_channel_tx, outgoing_channel_rx) = tokio::sync::mpsc::channel(1024);
        let outgoing_channel_tx_clone = outgoing_channel_tx.clone();

        let outgoing_forwarding_worker = tokio::spawn(async {
            DtlsSocketLayer::forward_outgoing_frames(
                socket_clone,
                outgoing_channel_tx_clone,
                outgoing_channel_rx,
                connection_sockets_clone,
                dtls_config_clone,
                blocklist_clone,
            )
            .await
        });

        let loopback_channel = tokio::sync::mpsc::channel(100);
        DtlsSocketLayer {
            socket,
            dtls_config,
            blocklist,
            connection_sockets,
            incoming_forwarding_worker,
            outgoing_forwarding_worker,
            outgoing_channel: outgoing_channel_tx,
            loopback_channel: (loopback_channel.0, Mutex::new(loopback_channel.1)),
        }
    }

    pub async fn block_peer(&mut self, peer: SocketAddr) {
        self.blocklist.write().await.block(peer);
    }

    async fn forward_incoming_frames(
        socket: Arc<UdpSocket>,
        connection_sockets_mutex: Arc<Mutex<HashMap<SocketAddr, UdpChannel>>>,
        dtls_config: Arc<DtlsConfig>,
        blocklist: Arc<RwLock<Blocklist>>,
    ) {
        log::trace!(
            "Started incoming socket forwarding worker at {}",
            socket.local_addr().unwrap()
        );
        // Use a large buffer, that every udp frame can be received completely
        let mut buf = [0; 16 * 1024];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((size, sender)) => {
                    if blocklist.read().await.is_blocked(&sender) {
                        log::warn!("DTLS: Dropping frame from blocked peer {}", &sender);
                        continue;
                    }

                    // Forward packet to the appropriate DTLS UDP wrapper
                    let mut connection_sockets = connection_sockets_mutex.lock().await;
                    if let Some(connection_socket) = connection_sockets.get_mut(&sender) {
                        // DTLS channel exists, forward it to the UDP wrapper
                        log::trace!(
                            "DTLS: Forwarding frame from {} to socket wrapper {} size {}",
                            &sender,
                            socket.local_addr().unwrap(),
                            &size
                        );
                        connection_socket
                            .raw_incoming
                            .send(buf[..size].to_vec())
                            .unwrap();
                    } else {
                        // DTLS channel does not exist, create it and then forward frame to the UDP wrapper
                        log::trace!(
                            "DTLS: Create socket wrapper at {} for frame from {} size {}",
                            socket.local_addr().unwrap(),
                            &sender,
                            &size
                        );

                        // The UdpChannel must be created and inserted into connection_sockets before unlocking that no
                        // other concurrent incoming or outgoing frame can trigger a UdpChannel creation for the same peer

                        let (raw_tx, raw_rx) = std::sync::mpsc::channel();
                        let udp_socket_wrapper = UdpSocketWrapper {
                            socket: socket.clone(),
                            remote_addr: sender,
                            incoming_message: raw_rx,
                        };

                        // Forward the received UDP frame that triggered this connection creation to the UdpSocketWrapper
                        raw_tx.send(buf[..size].to_vec()).unwrap();

                        let udp_channel = UdpChannel {
                            raw_incoming: raw_tx,
                            ssl_stream: None,
                        };

                        // Insert forwarding channel into the connection mapping for incoming frames (first handshake and then payload)
                        connection_sockets.insert(sender, udp_channel);
                        drop(connection_sockets);

                        // Connection establishment must be executed concurrently to the task, that is forwarding incoming frames
                        // on the UDP socket. Otherwise OpenSSL won't receive handshake responses.
                        let connection_sockets_mutex = connection_sockets_mutex.clone();
                        let socket = socket.clone();
                        let dtls_config = dtls_config.clone();
                        tokio::spawn(async move {
                            DtlsSocketLayer::accept_channel(
                                connection_sockets_mutex,
                                socket,
                                dtls_config,
                                sender,
                                udp_socket_wrapper,
                            )
                            .await;
                        });
                    }
                }
                Err(e) => {
                    // TODO: handle errors: disconnect, close, eof, timeout, ...
                    // Unreachable because we hold a reference to the UDP socket
                    log::trace!("DTLS: Failed to read from UDP socket: {:?}", e);
                    break;
                }
            }
        }
        log::info!(
            "Stopped incoming socket forwarding worker at {}",
            socket.local_addr().unwrap()
        );
    }

    async fn forward_outgoing_frames(
        socket: Arc<UdpSocket>,
        frame_channel_tx: Sender<(Instant, SocketAddr, Vec<u8>)>,
        mut frame_channel_rx: Receiver<(Instant, SocketAddr, Vec<u8>)>,
        connection_sockets_mutex: Arc<Mutex<HashMap<SocketAddr, UdpChannel>>>,
        dtls_config: Arc<DtlsConfig>,
        blocklist: Arc<RwLock<Blocklist>>,
    ) {
        log::trace!(
            "Started outgoing socket forwarding worker at {}",
            socket.local_addr().unwrap()
        );

        let no_connect = Arc::new(Mutex::new(HashMap::new()));

        while let Some((creation, remote_addr, frame)) = frame_channel_rx.recv().await {
            // Drop undeliverable frames after a timeout
            // TODO: configurable timeout
            if Instant::now() - creation > Duration::from_secs(10) {
                log::warn!(
                    "DTLS: Frame forwarding timeout at {} to {}",
                    socket.local_addr().unwrap(),
                    &remote_addr
                );
                continue;
            }
            if blocklist.read().await.is_blocked(&remote_addr) {
                log::warn!("DTLS: Not sending frame to blocked peer {}", &remote_addr);
                continue;
            }

            let mut connection_sockets = connection_sockets_mutex.lock().await;
            if let Some(udp_channel) = connection_sockets.get_mut(&remote_addr) {
                if let Some(s) = &mut udp_channel.ssl_stream {
                    // TODO: Consider to use write_all instead of write
                    let res = s.write(&frame);
                    if res.is_err() {
                        log::trace!(
                            "Remove erronous DTLS channel at {} to {}, error: {}",
                            socket.local_addr().unwrap(),
                            &remote_addr,
                            res.unwrap_err()
                        );
                        connection_sockets.remove(&remote_addr);
                        // Try to enque frame again. Must ignore full queue otherwise a deadlock
                        // can occur when another task inserts between recv() and send()
                        frame_channel_tx
                            .try_send((creation, remote_addr, frame))
                            .ignore();
                    }
                } else {
                    // Channel is currently connecting to peer in another task. Try to enque frame again.
                    // Must ignore full queue otherwise a deadlock can occur when another task inserts between recv() and send()
                    frame_channel_tx
                        .try_send((creation, remote_addr, frame))
                        .ignore();
                }
            } else {
                // Channel does not exist

                // Try to enque frame again. Must ignore full queue otherwise a deadlock
                // can occur when another task inserts between recv() and send()
                frame_channel_tx
                    .try_send((creation, remote_addr, frame))
                    .ignore();

                let mut no_connect_ = no_connect.lock().await;
                if let Some(blocked_until) = no_connect_.get(&remote_addr) {
                    if blocked_until < &Instant::now() {
                        no_connect_.remove(&remote_addr);
                    } else {
                        continue;
                    }
                }
                drop(no_connect_);

                // The UdpChannel must be created and inserted into connection_sockets before unlocking that no
                // other concurrent incoming or outgoing frame can trigger a UdpChannel creation for the same peer

                let (raw_tx, raw_rx) = std::sync::mpsc::channel();
                let udp_socket_wrapper = UdpSocketWrapper {
                    socket: socket.clone(),
                    remote_addr,
                    incoming_message: raw_rx,
                };

                let udp_channel = UdpChannel {
                    raw_incoming: raw_tx,
                    ssl_stream: None,
                };

                // Insert forwarding channel into the connection mapping for incoming frames (first handshake and then payload)
                connection_sockets.insert(remote_addr, udp_channel);
                drop(connection_sockets);

                let dtls_config = dtls_config.clone();
                let socket = socket.clone();
                let connection_sockets_mutex = connection_sockets_mutex.clone();
                let no_connect = no_connect.clone();
                tokio::spawn(async move {
                    let unexpected_message = DtlsSocketLayer::connect_channel(
                        connection_sockets_mutex,
                        socket.clone(),
                        dtls_config,
                        remote_addr,
                        udp_socket_wrapper,
                    )
                    .await;
                    // Mitigate the race condition by delaying the next connection attempt.
                    // The peer with lower SocketAddr waits 100ms, the one with higher waits 1s.
                    if unexpected_message {
                        if socket.local_addr().unwrap() < remote_addr {
                            no_connect
                                .lock()
                                .await
                                .insert(remote_addr, Instant::now() + Duration::from_millis(100));
                        } else {
                            no_connect
                                .lock()
                                .await
                                .insert(remote_addr, Instant::now() + Duration::from_secs(1));
                        }
                    }
                });
            }
        }
        // Closed
        log::trace!(
            "DTLS: Outgoing socket forwarding channel closed at {}",
            socket.local_addr().unwrap()
        );

        log::info!(
            "DTLS: Stopped outgoing socket forwarding worker at {}",
            socket.local_addr().unwrap()
        );
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut counter = 0;
        loop {
            // Receive non-blocking from loopback channel
            if let Ok(val) =
                timeout(Duration::ZERO, self.loopback_channel.1.lock().await.recv()).await
            {
                log::trace!(
                    "DTLS: Receive from loopback channel on {}",
                    self.socket.local_addr().unwrap()
                );
                // Safe unwrap, because sender and receiver are stored at the same location
                // and therefore sender cannot be closed as long as the receiver is available.
                let val = val.unwrap();
                buf.split_at_mut(val.len()).0.copy_from_slice(&val);
                return Ok((val.len(), self.socket.local_addr().unwrap()));
            }

            let mut connection_sockets = self.connection_sockets.lock().await;
            for (address, udp_channel) in connection_sockets.iter_mut() {
                if let Some(udp_channel) = udp_channel.ssl_stream.as_mut() {
                    match udp_channel.ssl_read(buf) {
                        Ok(n) => return Ok((n, address.to_owned())),
                        Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {
                            log::debug!("DTLS: recv_from: SSL session closed");
                            // return Ok((0, address.to_owned()))
                        }
                        Err(ref e) if e.code() == ErrorCode::SYSCALL && e.io_error().is_none() => {
                            log::debug!("DTLS: recv_from: Error: {:?}", e);
                            return Ok((0, address.to_owned()));
                        }
                        Err(ref e)
                            if e.code() == ErrorCode::WANT_READ
                                && (e.io_error().is_none()
                                    || e.io_error().unwrap().kind()
                                        == std::io::ErrorKind::WouldBlock) =>
                        {
                            // Do nothing
                        }
                        Err(e) => {
                            log::error!("DTLS: recv_from: Unknown error: {:?}", e);
                            return Err(e
                                .into_io_error()
                                .unwrap_or_else(|e| Error::new(ErrorKind::Other, e)));
                        }
                    }
                }
            }
            // Make this blocking task asynchronous by yielding
            tokio::task::yield_now().await;
            // For low latency first do busy waiting and then reduce cpu usage by sleeping
            counter += 1;
            if counter > 10 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    // TODO: make this non blocking in case a remote is not responding, that the caller worker is not blocked
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> std::io::Result<usize> {
        // lookup and use first result
        let remote_addr = tokio::net::lookup_host(addr)
            .await
            .map_err(|_| Error::from(ErrorKind::InvalidInput))?
            .next()
            .ok_or_else(|| Error::from(ErrorKind::NotFound))?;

        if remote_addr == self.socket.local_addr().unwrap() {
            log::trace!("DTLS: Sending to loopback channel on {}", &remote_addr);
            // Safe unwrap, because sender and receiver are stored at the same location
            // and therefore receiver cannot be closed as long as the sender is available.
            self.loopback_channel.0.send(buf.to_vec()).await.unwrap();
            return Ok(buf.len());
        }

        if self.blocklist.read().await.is_blocked(&remote_addr) {
            log::warn!("DTLS: Not sending frame to blocked peer {}", &remote_addr);
            return Err(Error::from(ErrorKind::ConnectionRefused));
        }

        self.outgoing_channel
            .send((Instant::now(), remote_addr, buf.to_vec()))
            .await
            .unwrap();

        Ok(buf.len())
    }
}

impl Drop for DtlsSocketLayer {
    fn drop(&mut self) {
        self.incoming_forwarding_worker.abort();
        self.outgoing_forwarding_worker.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

    use hex::ToHex;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, PKeyRef, Private},
        rsa::Rsa,
        sha::sha256,
        x509::{
            extension::BasicConstraints, X509Builder, X509Extension, X509Name, X509NameRef, X509,
        },
    };
    use rand::RngCore;
    use tokio::{sync::RwLock, time::timeout};

    use crate::p2p_protocol::dtls_connections::Blocklist;

    use super::{DtlsConfig, DtlsSocketLayer};

    fn peer_instance(
        peer_addr: &str,
        cert_pki: X509,
        pki_name: &X509NameRef,
        pkey_pki: &PKeyRef<Private>,
    ) -> Arc<DtlsConfig> {
        let socketaddr: SocketAddr = peer_addr.parse().unwrap();
        let hostname = sha256(format!("{}::{}", socketaddr.ip(), socketaddr.port()).as_bytes())
            .encode_hex::<String>();

        let key_local = Rsa::generate(4096).unwrap();
        let pkey_local = PKey::from_rsa(key_local.clone()).unwrap();
        let mut cert = X509Builder::new().unwrap();
        let mut local_name = X509Name::builder().unwrap();
        local_name
            .append_entry_by_nid(Nid::COMMONNAME, hostname.as_str())
            .unwrap();
        let name = local_name.build();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(pki_name).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        cert.set_pubkey(&pkey_local).unwrap();
        cert.sign(pkey_pki, MessageDigest::sha256()).unwrap();
        let cert = cert.build();

        let config = DtlsConfig::new(
            cert_pki,
            cert,
            Duration::from_secs(60 * 60 * 24 * 365),
            key_local,
        );
        Arc::new(config)
    }

    fn pki_instance() -> (X509, X509Name, PKey<Private>) {
        // Common name of the PKI and of peers must differ for openssl to work correctly
        let key_pki = Rsa::generate(4096).unwrap();
        let pkey_pki = PKey::from_rsa(key_pki).unwrap();
        let mut cert = X509Builder::new().unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "pki.example.com")
            .unwrap();
        let pki_name = name.build();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&pki_name).unwrap();

        cert.set_issuer_name(&pki_name).unwrap();
        let mut bc = BasicConstraints::new();
        let bc = bc.critical().ca();
        let extension: X509Extension = bc.build().unwrap();
        cert.append_extension(extension).unwrap();

        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        cert.set_pubkey(&pkey_pki).unwrap();
        cert.sign(&pkey_pki, MessageDigest::sha256()).unwrap();
        let cert_pki = cert.build();

        (cert_pki, pki_name, pkey_pki)
    }

    #[test]
    fn unit_dtls_single_connection() {
        let addr_1 = "127.0.0.1:8001";
        let addr_2 = "127.0.0.1:8002";

        let (cert_pki, pki_name, pkey_pki) = pki_instance();

        let config_1 = peer_instance(addr_1, cert_pki.clone(), &pki_name, &pkey_pki);
        let config_2 = peer_instance(addr_2, cert_pki, &pki_name, &pkey_pki);

        let mut buf = vec![0; 1400];
        rand::thread_rng().fill_bytes(&mut buf);

        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            let blocklist = Arc::new(RwLock::new(Blocklist::new(Duration::from_secs(60))));
            let socket_1 = DtlsSocketLayer::new(addr_1, config_1, blocklist.clone()).await;
            let socket_2 = DtlsSocketLayer::new(addr_2, config_2, blocklist).await;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Frames that must be received by the other endpoint
            let mut receive_frames_socket_1: BTreeSet<Vec<u8>> = BTreeSet::new();
            let mut receive_frames_socket_2: BTreeSet<Vec<u8>> = BTreeSet::new();

            for i in [844, 1, 1024, 12, 599, 1354, 144, 1368] {
                socket_1.send_to(&buf[..i], addr_2).await.unwrap();
                receive_frames_socket_2.insert(buf[..i].to_vec());

                // Send different frame
                let j = i + 32;
                socket_2.send_to(&buf[..j], addr_1).await.unwrap();
                receive_frames_socket_1.insert(buf[..j].to_vec());
            }

            let mut buf_in = vec![0; buf.len() + 1000];
            while !receive_frames_socket_2.is_empty() {
                let (size, addr) = socket_2.recv_from(&mut buf_in).await.unwrap();
                // This asserts size and content
                assert!(receive_frames_socket_2.remove(&buf_in[..size]));
                assert_eq!(addr, addr_1.parse().unwrap());
            }
            while !receive_frames_socket_1.is_empty() {
                let (size, addr) = socket_1.recv_from(&mut buf_in).await.unwrap();
                // This asserts size and content
                assert!(receive_frames_socket_1.remove(&buf_in[..size]));
                assert_eq!(addr, addr_2.parse().unwrap());
            }

            // Check there are no other frames in the pipeline
            timeout(Duration::from_millis(500), socket_2.recv_from(&mut buf_in))
                .await
                .unwrap_err();
            timeout(Duration::from_millis(500), socket_1.recv_from(&mut buf_in))
                .await
                .unwrap_err();
        });
    }

    #[test]
    fn unit_dtls_loopback() {
        let addr = "127.0.0.1:8005";

        let (cert_pki, pki_name, pkey_pki) = pki_instance();

        let config = peer_instance(addr, cert_pki, &pki_name, &pkey_pki);

        let mut buf = vec![0; 1400];
        rand::thread_rng().fill_bytes(&mut buf);

        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            let blocklist = Arc::new(RwLock::new(Blocklist::new(Duration::from_secs(60))));
            let socket = DtlsSocketLayer::new(addr, config, blocklist).await;

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Frames that must be received by the other endpoint
            let mut receive_frames_socket: BTreeSet<Vec<u8>> = BTreeSet::new();

            for i in [844, 1, 1024, 12, 599, 1354, 144, 1368] {
                socket.send_to(&buf[..i], addr).await.unwrap();
                receive_frames_socket.insert(buf[..i].to_vec());
            }

            let mut buf_in = vec![0; buf.len() + 1000];
            while !receive_frames_socket.is_empty() {
                let (size, remote_addr) = socket.recv_from(&mut buf_in).await.unwrap();
                // This asserts size and content
                assert!(receive_frames_socket.remove(&buf_in[..size]));
                assert_eq!(remote_addr, addr.parse().unwrap());
            }

            // Check there are no other frames in the pipeline
            timeout(Duration::from_millis(500), socket.recv_from(&mut buf_in))
                .await
                .unwrap_err();
        });
    }
}
