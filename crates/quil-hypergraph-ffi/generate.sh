#!/bin/bash
set -euxo pipefail

# Script lives at crates/quil-hypergraph-ffi/generate.sh
# Resolve repo root: two dirname levels up from the script directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(dirname "$(dirname "$SCRIPT_DIR")")}"

RUST_PACKAGE="$ROOT_DIR/crates/quil-hypergraph-ffi"
BINDINGS_DIR="$ROOT_DIR/node/internal/ffi"

# Build the Rust hypergraph FFI package in release mode
cargo build -p quil-hypergraph-ffi --release

# Generate Go bindings into node/internal/ffi/ so they're importable
# from the node module without an extra go.mod.
pushd "$RUST_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"
