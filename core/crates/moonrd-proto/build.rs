//! Compiles ../../../proto/moonrd.proto with protox (pure Rust), so building needs no
//! protoc installation.

use std::path::PathBuf;

fn main() {
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../proto");
    let file = proto_dir.join("moonrd.proto");
    println!("cargo:rerun-if-changed={}", file.display());
    let fds = protox::compile([&file], [&proto_dir]).expect("compile moonrd.proto");
    prost_build::Config::new()
        .compile_fds(fds)
        .expect("generate Rust code for moonrd.proto");
}
