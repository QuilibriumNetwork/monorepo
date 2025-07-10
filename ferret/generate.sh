#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_FERRET_PACKAGE="$ROOT_DIR/crates/ferret"
BINDINGS_DIR="$ROOT_DIR/ferret"

# Build the Rust FERRET package in release mode
cargo build -p ferret --release

# Generate Go bindings
pushd "$RUST_FERRET_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
