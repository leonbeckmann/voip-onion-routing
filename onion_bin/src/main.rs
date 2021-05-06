extern crate onion_lib;

#[macro_use]
extern crate clap;

fn main() {
    /*
     * Command line argument parser that requires a config file option
     * and handles --help requests and invalid program calls automatically
     */
    let matches = clap_app!(onion_app =>
        (name: "OnionModule")
        (version: crate_version!())
        //(authors: "Leon Beckmann <leon.beckmann@tum.de>, Florian Freund <florian.freund@tum.de>")
        (author: crate_authors!())
        (about: crate_description!())
        (@arg CONFIG: -c --config +takes_value +required "Sets a custom windows INI config file")
    )
    .get_matches();

    // unwrap is safe here, since config was required
    let config_path = matches.value_of("CONFIG").unwrap();

    // run the peer
    onion_lib::run_peer(config_path);
}
