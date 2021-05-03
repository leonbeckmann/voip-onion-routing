# VoidPhone Project - Onion Module

## Building

Install the latest stable release of the rust toolchain (e.g. via https://rustup.rs/).

In the root directory run:

```cargo build```

## How to Use

In the root directory run:

```cargo run```

## Tests and Examples

Integration tests are located at *onion_tests*, examples are located at
*onion_examples*.

To run tests, run in the root directory:

```cargo test -- --nocapture```

To run an example, run in the root directory:

```cargo run --example <example_name>```

## Logging Output

The logging level can be set via the environment variable *RUST_LOG*:

`RUST_LOG=debug cargo run` 