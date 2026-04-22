#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")")" >/dev/null 2>&1 && pwd )}"

RUST_KEYS_FFI_PACKAGE="$ROOT_DIR/crates/quil-keys-ffi"
BINDINGS_DIR="$ROOT_DIR/quil-keys-ffi"

# Build the Rust quil-keys-ffi package in release mode
cargo build -p quil-keys-ffi --release

# Generate Go bindings
pushd "$RUST_KEYS_FFI_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
