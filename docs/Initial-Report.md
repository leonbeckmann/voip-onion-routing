# Initial Report for Onion Module of Team 10

## Team Information
* Team number 10
* Florian Freund and Leon Beckmann
* Project: Onion Module

## Programming Language and Operating System
Rust on Linux and Mac OS X

* Designed for concurrent asynchronous programming
* Secure language model
  * type safety
  * memory safety
* Fast run time
  * Zero cost abstraction
  * Zero runtime overhead
  * Near C performance
* The standard library has support for many commonly used cryptographic functions (e.g. sha256, aes-encryption, ...)
* Cross platform support
* Many built-in tools (dependeny management, building, testing, code formating)


## Build System
* **Cargo**

## Quality Measures
* Code formating: clippy, rustfmt
* Rust test suite
* Test code coverage
* LLVM address sanitizer (only if we use external non-Rust code)
* Continous integration
* GitLab hooks: Block invalid commits
* (Fuzzing)

## Libraries
* **openssl** for all cryptographic stuff
* Tonic
* Protobuf

## License
Apache-2.0

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

## Planned Workload Distribution

* Implement API protocol
* P2P protocol design und implementation
  * Single P2P
  * Multiple hops
* Encryption
