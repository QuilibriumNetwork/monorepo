fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");

    prost_build::compile_protos(&[proto_dir.join("rpc.proto")], &[proto_dir])?;

    println!("cargo:rerun-if-changed=proto/rpc.proto");
    Ok(())
}
