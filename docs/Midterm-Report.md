# Midterm Report for Onion Module of Team 10

## Changes to our assumptions in the initial report

## Module Architecture

![Logical Architecture](images/logical_structure.svg)

In the following, the architecture of the onion module is described. The module is implemented
as a fully asynchronous library using the tokio async runtime. The binary makes use of this library.

### Binary

The binary in *onion_bin/main.rs* handles the command-line argument parsing
and makes then use of the onion_lib to run a peer, using the given ini-config path.

### Library

The onion_lib/lib.rs provides a function to run a peer, given a ini config file path:

```rust
pub fn run_peer<P: AsRef<Path> + Debug>(config_file: P) {}
```

First, the function parses the config_file. Afterwards, it creates a tokio runtime, which is used
for starting a p2p_interface and an api_interface asynchronously. It is then blocked on a conditional variable
and waits until one of the interfaces terminate to shutdown the whole peer.

The two interfaces, which are owned by the run_peer function, are referenced to each other using weak references that do not imply
ownerships. These weak references can be upgraded at any time the peer is still active
and can then be used for communicating with each other. For example, API requests are parsed
in the api_protocol and are then passed to the p2p_protocol via the p2p_interface, while incoming tunnels
are handled in the p2p_protocol and passed to the API via the api_interface.

### Config Parser

The onion config parser parses the INI config file at the given path to
an OnionConfiguration struct using the rust-ini crate.

````rust
pub struct OnionConfiguration {
    pub p2p_port: u16,
    pub p2p_hostname: String,
    pub crypto_context: Arc<HandshakeCryptoContext>,    // contains local host-key pair
    pub hop_count: u8,
    pub onion_api_address: SocketAddr,
    pub rps_api_address: SocketAddr,
    pub round_time: Duration,
    pub handshake_message_timeout: Duration,    // configurable handshake timeout per message
}
````

### API Protocol

The api_protocol structure is as follows:
```rust
api_protocol
    |--> api_connection
    |--> event    // incoming and outgoing events, inclusive serialization and deserialization 
    |--> messages // contains all the API messages, as well as serialization and deserialization methods.
    |--> mod.rs   // the API_interface and all the handlers and main logic
```

The API protocol is started by the run_peer function from the lib.rs
asynchronously, by calling the listen function on the api_interface.

```rust
pub(crate) struct ApiInterface {
    pub connections: Arc<Mutex<HashMap<ConnectionId, Connection>>>,
}

impl ApiInterface {
    pub async fn listen(
    & self,
    api_address: SocketAddr,
    p2p_interface: Weak<P2pInterface>,  // weak reference to p2p interface
    ) -> anyhow::Result < () > {}
}
```

This method binds the TCP API listener to the api_address and then listens
for new connections from the CM/CI layer. For each new request, a new api_connection
is created and handled using a connection handler. This handler first registers the
new connection at the self.connections hashmap and then handles new
incoming events from the CM/CI. This event_handler might return an outgoing event, which must be send
back to the API via the api_connection and is the response on the request or an incoming tunnel.
When the connection has been closed, the handler unregisters the connection from the hashmap and returns.

Simply said, the connection abstracts the TCP stream to an api_connection that can be used
for reading incoming events and writing outgoing events. The api_connection is responsible for
serializing and deserializing the events into the specified message formats (as bytes).

An incoming event is one of the following, which is parsed from the raw bytes as specified in the project documentation.
```rust
pub(crate) enum IncomingEvent {
    TunnelBuild(Box<OnionTunnelBuild>),
    TunnelDestroy(OnionTunnelDestroy),
    TunnelData(Box<OnionTunnelData>),
    Cover(OnionCover),
}
```

An outgoing event is one of the following, which is then passed to raw bytes and send back to the CM/CI.
````rust
#[derive(Debug)]
pub(crate) enum OutgoingEvent {
    TunnelReady(Box<OnionTunnelReady>),
    TunnelIncoming(OnionTunnelIncoming),
    TunnelData(Box<OnionTunnelData>),
    Error(OnionError),
}
````

### P2P Protocol

The p2p_protocol structure is as follows:
```rust
p2p_protocol
    |--> messages   // contains the protobuf file
    |--> onion_tunnel
    |--> rps_api    // provides function for getting a random peer from rps
    |--> mod.rs     // P2P_interface
```

TODO

#### Peer-to-Peer Protocol Design

The p2p protocol is designed as a finite state machine (FSM), consisting of two components:
The Handshake FSM and the Main FSM. Using a FSM eliminates unexpected / unhandled cases, since for every state
it is clearly defined how to react on every event. The communication with the FSM, as well as the communication
between the Main and the Handshake FSM is done via mpsc_channels to ensure LIFO ordering and
synchronization. The FSMs run asynchronously via tokio.

#### Main FSM

![FSM](images/fsm.svg?raw=true)

The main FSM consists of four different states:
- **Closed** is the initial state on creation. It only expects an **INIT** event, which triggers
an init_action and then goes into the **Connecting** state on success. Each other event leads to termination.

- **Connecting** is the state where the handshake is active. When receiving the Handshake_Result_Success event, the
FSM goes into the state **Connected**. When receiving incoming frames that can be successfully parsed to handshake data, 
  this is passed to the handshake FSM and the FSM stays in **Connecting**. On close event, receiving closure, handshake errors, unexpected events and 
  parsing error, the FSM terminates. 
  
- **Connected** is the state, where the tunnel is established and communication (sending and receiving app data) is 
  allowed. On close, received_close, sending errors, incoming_frame parsing errors or unexpected events, the
  FSM terminates.
  
- **Terminated** is the final state, which has no outgoing transitions.

Since the initiator of the tunnel and the target (hop or real target) have completely different
init actions, the FSM is implemented as a trait with default implementations for the shared functionality, while the
peer-specific functions are implemented by the InitiatorFsm and the TargetFsm.
The main difference is the implementation of the *action_init* function. The target FSM simply creates
the HandshakeFsm, runs it, and builds the communication channel between Main FSM and Handshake FSM. In contrast, the
InitiatorFsm loops over all hops and the target peer and stays in the state **Connecting** until the whole tunnel
is established. For this, the handshake result for each handshake with a peer is hooked and caught and new
Handshake FSMs are created sequentially for each next hop. The underlying communication layer (MessageCodec)
is updated after each successful handshake to an intermediate hop, such that the data to the next hop are tunneled
through the partially established tunnels.

#### Handshake FSM

- message formats
- message explanation
- exception handling

## Future Work
- Rounds
- Cover traffic  
- Robustness
- Improving Test coverage (at the moment 80%)

## Workload Distribution

## Effort
