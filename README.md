# VoidPhone Project - Onion Module

#### Master Branch Status

[![pipeline status](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/master/pipeline.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/master)

[![coverage report](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/master/coverage.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/master)

#### Develop Branch Status

[![pipeline status](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/develop/pipeline.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/develop)

[![coverage report](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/badges/develop/coverage.svg)](https://gitlab.lrz.de/netintum/teaching/p2psec_projects_2021/Onion-1/-/commits/develop)

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
