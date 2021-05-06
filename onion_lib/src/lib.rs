extern crate anyhow;
extern crate tokio;

mod api_protocol;
mod config_parser;
mod p2p_protocol;

use std::path::Path;

use config_parser::OnionConfiguration;

pub fn run_peer<P: AsRef<Path>>(config_file: P) {
    // parse config file
    let config = match OnionConfiguration::parse_from_file(config_file) {
        Ok(config) => config,
        Err(e) => {
            log::error!("Cannot parse config file: {}", e);
            return;
        }
    };

    // run async
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        // run API connection listener
        if let Err(e) = api_protocol::listen(&config.onion_api_address).await {
            log::error!("Cannot start API connection listener: {}", e);
            return;
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
