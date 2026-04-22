use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("protobufs");

    // Pass 1: All protos except global.proto — full client + server.
    let basic_protos = &[
        proto_dir.join("keys.proto"),
        proto_dir.join("channel.proto"),
        proto_dir.join("application.proto"),
        proto_dir.join("hypergraph.proto"),
        proto_dir.join("compute.proto"),
        proto_dir.join("token.proto"),
        proto_dir.join("node.proto"),
        proto_dir.join("proxy.proto"),
        proto_dir.join("ferret_proxy.proto"),
    ];

    let include_dirs = &[proto_dir.clone()];

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(basic_protos, include_dirs)?;

    // Pass 2: global.proto with OnionService stripped out so we get the
    // GlobalServiceClient. The OnionService.Connect RPC name collides with
    // tonic's generated `connect()` channel constructor, so we surgically
    // remove that service before handing the file to tonic_build.
    let global_proto_path = proto_dir.join("global.proto");
    let global_src = std::fs::read_to_string(&global_proto_path)?;
    let stripped = strip_service(&global_src, "OnionService");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let stripped_dir = out_dir.join("protos_stripped");
    std::fs::create_dir_all(&stripped_dir)?;
    let stripped_global = stripped_dir.join("global.proto");
    std::fs::write(&stripped_global, stripped)?;

    // Symlink/copy the other protos into the stripped dir so imports resolve.
    for p in basic_protos {
        let dst = stripped_dir.join(p.file_name().unwrap());
        let _ = std::fs::remove_file(&dst);
        std::fs::copy(p, &dst)?;
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[stripped_global], &[stripped_dir])?;

    for proto_file in basic_protos.iter().chain(std::iter::once(&global_proto_path)) {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    Ok(())
}

/// Remove a `service Name { ... }` block from a .proto source string. Brace
/// counting handles nested blocks (although gRPC services rarely contain them).
fn strip_service(src: &str, name: &str) -> String {
    let needle = format!("service {} {{", name);
    let Some(start) = src.find(&needle) else {
        return src.to_string();
    };
    let mut depth: i32 = 0;
    let mut end = start;
    for (i, ch) in src[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let mut out = String::with_capacity(src.len());
    out.push_str(&src[..start]);
    out.push_str(&src[end..]);
    out
}
