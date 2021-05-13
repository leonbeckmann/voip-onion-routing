use protoc_rust::Customize;
use std::path::Path;

const PROTO_FILE_PATHS: &str = "src/p2p_protocol/messages/p2p_messages.proto";
const GEN_OUT_DIR: &str = "src/p2p_protocol/messages";

fn main() {
    // println!("cargo:rerun-if-changed=src/p2p_protocol/messages/p2p_messages.proto");
    std::fs::create_dir_all(GEN_OUT_DIR)
        .unwrap_or_else(|_| panic!("could not create or find directory {}", GEN_OUT_DIR));

    protoc_rust::Codegen::new()
        .out_dir(GEN_OUT_DIR)
        .input(Path::new(PROTO_FILE_PATHS))
        .customize(Customize {
            carllerche_bytes_for_bytes: Some(true),
            carllerche_bytes_for_string: Some(false),
            ..Default::default()
        })
        .run()
        .expect("protoc");
}
