//! Generate the client surface from `descriptors/heylogin.binpb`.
//!
//! `compile_fds` reads the committed `FileDescriptorSet` directly, so **no
//! `protoc` and no `buf` is needed on any build machine** and no `.proto` file
//! is ever read. That is what keeps the crates.io story simple: the descriptor
//! set is the only committed schema artifact (DESIGN.md §4).

use std::{env, fs, path::PathBuf};

use prost::Message as _;
use tonic_prost_build::FileDescriptorSet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../descriptors/heylogin.binpb")
        .canonicalize()?;
    println!("cargo:rerun-if-changed={}", descriptors.display());

    let fds = FileDescriptorSet::decode(&*fs::read(&descriptors)?)?;

    tonic_prost_build::configure()
        // `transport` pulls in a *server* and `axum`. We are a client speaking
        // gRPC-Web over our own hyper stack, so the generated code must not
        // assume it (found the hard way at M0 -- DESIGN.md §4).
        .build_transport(false)
        .build_server(false)
        .out_dir(env::var("OUT_DIR")?)
        .compile_fds(fds)?;

    Ok(())
}
