#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_BULLETPROOFS_PACKAGE="$ROOT_DIR/crates/bulletproofs"
BINDINGS_DIR="$ROOT_DIR/bulletproofs"

# Build the Rust Bulletproofs package in release mode
cargo build -p ed448-bulletproofs --release

# Generate Go bindings
pushd "$RUST_BULLETPROOFS_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated