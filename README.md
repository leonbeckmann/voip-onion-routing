![Tests](https://github.com/leonbeckmann/voip-onion-routing/actions/workflows/ci.yml/badge.svg?branch=master)

# VoidPhone Project - Onion Module

The Onion Module of the VoidPhone Project at TUM is responsible for providing a layer for constructing anonymous onion tunnels within a peer-to-peer network.

Checkout the [TUM Project Specification](./docs/voidphone_spec.pdf) for more information on the project requirements and 
the [Project Documentation](./docs/Final_Report.pdf) for the architecture and a security analysis of the actual implementation.

Tested on Linux and macOS.

## Building

### Rust Toolchain
Install the latest stable release of the rust toolchain (e.g. via https://rustup.rs/).

### Protobuf Compiler
The OnionModule uses protobuf messages for communication between peer, which is why protobuf compiler must be installed.

On **Linux** it can be installed via get-apt:  `apt-get install protobuf-compiler`

On **MacOS** it can be installed via homebrew: `brew install protobuf`


### Project build

In the root directory run: `cargo build`

## How to Use

### Configuration

The module requires a Windows INI configuration file for configuring the Onion module
(see *template.config*). All the attributes are mandatory:

| Attribute         | Section | Value                                 | Description |
| :---------        | :-----: | :---:                                 | :---------- |
| hostkey           | global  | str                                   | Path to peer's public hostkey in PEM format |
| p2p_port          | onion   | u16                                   | P2P port of peer |
| p2p_hostname      | onion   | hostname, ipv4, ipv6                  | Peer's p2p address for onion layer |
| hop_count         | onion   | u8                                    | Number of intermediate hops per tunnel, >= 2 |
| api_address       | onion   | hostname:port, ipv4:port, [ipv6]:port | Peer's API address for Onion layer |
| round_time        | onion   | u64                                   | Round time in seconds (default=600s)| 
| build_window      | onion   | u64                                   | Build window in milliseconds (default=1000ms)|
| handshake_timeout | onion   | u64                                   | Handshake message timeout in ms (default=1000ms)| 
| timeout           | onion   | u64                                   | Timeout for recognize inactive tunnels (default=15s)|
| private_hostkey   | onion   | str                                   | Path to peer's private hostkey in PEM format |
| pki_root_cert     | onion   | str                                   | Path to the PKI's root certificate in PEM format |
| hostkey_cert      | onion   | str                                   | Path to the certificate for hostkey, signed by PKI |
| blocklist_time    | onion   | u64                                   | Seconds until peer is removed from the blocklist  (default=3600s)|
| api_address       | rps     | hostname:port, ipv4:port, [ipv6]:port | Peer's API address for RPS layer |

This could look like the following:
```
; An INI configuration file for configuring the Onion Module

hostkey = /etc/peer1.key.pub

[onion]
p2p_port = 2000
p2p_hostname = localhost
hop_count = 3           
api_address = localhost:2001
round_time = 100  
build_window = 2000  
private_hostkey = /etc/peer1.key
handshake_timeout = 1000
timeout = 20s
pki_root_cert = /etc/pki.cert
hostkey_cert = /etc/peer1.cert
blocklist_time = 3600

[rps]
api_address = localhost:2002
```

### Run the Application

In the root directory run:

```cargo run -- -c <CONFIG_FILE_PATH>```

For more information run:

```cargo run -- --help```

## Tests and Examples

Integration tests are located at *onion_tests*, examples are located at
*onion_examples*.

To run tests, run in the root directory:

```cargo test -- --nocapture```

To run an example, run in the root directory:

```cargo run --example <example_name>```

## Logging Output

The logging level can be set via the environment variable *RUST_LOG*:

`RUST_LOG=debug cargo run -- -c <CONFIG_FILE_PATH>`

## PKI

The PKI is the root of trust for the DTLS connections between peers. Designing a secure PKI
for the Onion Module goes beyond the scope of this project and is future work. Thus, we assume there is
a trusted PKI and the Onion Module expects the corresponding files via the configuration.

To create a self-signed certificate used by the trusted PKI server to sign new certificate request, first
create a password-protected private key for the trusted PKI server:

```openssl genrsa -aes256 -out pki.key 4096```

Afterwards, create the root certificate for the PKI server, using the private key:

```openssl req -x509 -new -nodes -extensions v3_ca -key pki.key -days 1024 -out pki.cert -sha512```

This PKI can then be used for signing new peer certificate. First create a private key for the peer:

```openssl genrsa -out peer.key 4096```

Then create a Certificate Signing Request (CSR), where the CommonName is set to sha256(<P2P_IP>::<P2P_Port>):

```openssl req -new -key peer.key -out peer.csr -sha512```

Ensure that the CSR does not contain any privacy-leaking information!
Finally, create the certificate and sign it by the PKI server:

```openssl x509 -req -in peer.csr -CA pki.cert -CAkey pki.key -CAcreateserial -out peer.cert -days 365 -sha512```

You can find certificates and keys for PKI (password: 1234), Alice (127.0.0.1::2001), Bob (127.0.0.1::3001), Hop1 (127.0.0.1::4001) and 
Hop2 (127.0.0.1::5001) in ./onion_tests/resources/.
