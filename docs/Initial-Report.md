# Initial Report for Onion Module of Team 10

## Team Information
* Team number 10
* Florian Freund and Leon Beckmann
* Project: Onion Module

## Programming Language and Operating System
**Rust on Linux and Mac OS X**

Our host systems run Linux andd MacOsX. To avoid development on virtual machines, our goal is to provide working solutions of the OnionModule for both, Linux and MacOsX. 

We have selected RUST as our programming language. Beside the fact that both of us are already familar with programming in RUST, there are further reasons why we think RUST is a good choice for programming network protocols:

* Rust is designed for concurrent **asynchronous programming** (we use the tokio library here)
* **Secure language model** (this is a big advantage in contrast to e.g. C)
  * Type safety
  * Memory safety
* **Fast run time**
  * Zero cost abstraction
  * Zero runtime overhead
  * Near C performance
* The standard library has support for many commonly used cryptographic functions (e.g. sha256, aes-encryption, ...)
* **Cross platform support**
* Many **built-in tools** (dependency management, building, testing, code formatting)


## Build System
* **Cargo**

## Quality Measures
* Code formatting: cargo clippy, rustfmt
* Rust test suite (for unit tests within the module and integration tests in an external crate)
* Test code coverage
* Gitlab CI
* Continuous integration
* GitLab hooks: Block invalid commits
* (Fuzzing)
* (LLVM address sanitizer) (only if we use external non-Rust code)

## Libraries
* **Openssl** for cryptography (Apache License 2.0)
* **Protobuf** for serializing/deserializing p2p protocol messages (MIT License)
* **Tokio** for asynchronous programming (MIT License)

#### Additional Libraries
* **log** and **env_logger** for logging, which can be configure via environment variables (Apache License 2.0 / MIT License)
* **anyhow** and **thiserror** for custom errors (Apache License 2.0 / MIT License)
* **rust-ini** for ini config-file parsing (MIT License)
* **clap** for commandline argument parsing (MIT License)
* **tpmdir** for creating temporary directories in /var for testing with dynamic config files (Apache License 2.0 / MIT License)

## License
For selecting the best fitting license for our software project, we first have to check the licences of our used libraries to avoid and licence issues with that: here all our libraries are either released via MIT License or Apache Licence 2.0.

...

Apache License 2.0

## Programming Experience

#### Leon
During the last two years, I was part of a team at the Fraunhofer AISEC for developing a
secure remote-attestation protocol in Java and Rust. I have mainly been responsible for
implementing the protocol and its drivers, document the protocol, writing
some test cases and I was also part of design choices and discussions on how to construct 
the finite state machine of the protocol. 

Further, my study program is/was mainly focused on IT-Security topics. Besides lectures like
NetSec or IT-Sec, I was enrolled in the Rootkit programming lab course, where we have developed
Linux LKM-based kernel rootkits and countermeasures. As a final project, we tried to recalculate
the TLS master secret by sniffing the TLS traffic and hooking the Linux's CSPRNG, such that 
Openssl will create predictable EC Diffie-Hellman parameters for ECDHE. (programming language C)

My Bachelor Thesis was about (quantum-secure) cryptography in the case of Proxy-ReEncryption schemes,
during which I learned a lot more about cryptography.

#### Florian
TODO

## Plannings and Planned Workload Distribution

The first goal of our project is the design and implementation of the API protocol in combination with a working setup:
* Setup project and environment for quality control
* Parsing the config file
* Running a peer from command line with thee config file path
* Running the API protocol (asynchronously):
  * Starting the TCP listener
  * Handle and store new API connections 
  * Parse incoming API messages into incoming events
  * Handle incoming connection events by checking its validity
  * Delegate requests to the p2p protocol via an p2p_interface
  * Handle responses to our requests from the p2p_interface and create API responses for the CM/CI layer regarding the spec.

The next goal is to implement the p2p_protocol environment (asynchronously), such that we have a fully working setup but without secure channels between the source and the destination peers:
* Run the p2p UDP listener
* Handle incoming p2p connections
* Handle incoming API requests such as OnionTunnelBuild or OnionTunnelData
* Communication with the API protocol interface
* Rounds
* (Cover traffic is skipped for now)
At the end of this step we have almost all the things from the project spec implemented, but the onion tunnel is just a udp stream
from source to dest without any intermediate peers.

The next step is to design the p2p protocol. We will split the p2p_protocol into two unique protocols: the main p2p_protocol is responsible for routing, sending messages and cover traffic, handling all the events from the API layer and incoming messages, ...
The other protocol is the security protocol, which is used for creating a secure channel between the source and the destination peer. So there is one state machine for the security protocol per connection and one overall p2p_protocol.
* Define message types using protobuf
* Define event handling for main p2p_protocol
* Specify the security protocol and its finite state machine
* Communication with RPS for random peer sampling
* Check common p2p attacks and implement countermeasures

During all the steps we will write test cases during the module developments. Last steps will be the Documentations in the Wiki and final improvements.

TODO workload

