The `*.proto` files in this folder are the wire definitions. The Rust crates
generate their types from them at build time (for example
`crates/quil-types/build.rs`), so there are no generated sources to commit.

The `protoc` compiler must be installed; the project image and
`docker/Dockerfile.source` install protoc 25.1 from the upstream release page:
https://github.com/protocolbuffers/protobuf/releases/tag/v25.1

To pick up a change to a `*.proto` file, rebuild the workspace with `cargo`.
