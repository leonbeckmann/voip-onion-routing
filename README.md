# VoidPhone Project - Onion Module

Onion Module of the VoidPhone Project is responsible for providing a layer for constructing anonymous onion tunnels within a peer-to-peer network.

Tested on Linux and MacOsX.

#### Master Branch Status

[![pipeline status](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/master/pipeline.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/master)

[![coverage report](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/master/coverage.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/master)

#### Develop Branch Status

[![pipeline status](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/develop/pipeline.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/develop)

[![coverage report](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/develop/coverage.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/develop)

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
| api_address       | rps     | hostname:port, ipv4:port, [ipv6]:port | Peer's API address for RPS layer |

This could look like the following:
```
; An INI configuration file for configuring the Onion Module

hostkey = /etc/peer1_pub_key.pem

[onion]
p2p_port = 2000
p2p_hostname = localhost
hop_count = 3           
api_address = localhost:2001
round_time = 100  
build_window = 2000  
private_hostkey = /etc/hostkey_priv.pem
handshake_timeout = 1000
timeout = 20s

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
