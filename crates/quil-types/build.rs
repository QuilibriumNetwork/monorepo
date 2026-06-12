use std::path::PathBuf;

// It's important to not to create files in this script,
// because that leads to unneccessary recompilations due
// to race conditions with mtime and build.rs last execution.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("protobufs");

    let protos = &[
        proto_dir.join("keys.proto"),
        proto_dir.join("channel.proto"),
        proto_dir.join("application.proto"),
        proto_dir.join("hypergraph.proto"),
        proto_dir.join("compute.proto"),
        proto_dir.join("token.proto"),
        proto_dir.join("node.proto"),
        proto_dir.join("proxy.proto"),
        proto_dir.join("ferret_proxy.proto"),
        proto_dir.join("global.proto"),
    ];

    // build_transport(false) suppresses the inherent `Client::connect(uri)`
    // channel constructor on every generated client. Two reasons:
    //   1. `OnionService.Connect` (in global.proto) would otherwise collide
    //      with that auto-generated `connect()` and break codegen.
    //   2. Nothing in the workspace calls `*Client::connect(...)` -- all
    //      14 client construction sites use `*Client::new(channel)` with
    //      an explicit `tonic::transport::Channel`. The constructor was
    //      dead code anyway.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(false)
        .emit_rerun_if_changed(true)
        .compile_protos(protos, &[proto_dir.clone()])?;

    Ok(())
}
