#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_DKLS23_PACKAGE="$ROOT_DIR/crates/dkls23_ffi"
BINDINGS_DIR="$ROOT_DIR/dkls23_ffi"

# Build the Rust DKLs23 FFI package in release mode
cargo build -p dkls23_ffi --release

# Generate Go bindings
pushd "$RUST_DKLS23_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
