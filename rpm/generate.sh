#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_RPM_PACKAGE="$ROOT_DIR/crates/rpm"
BINDINGS_DIR="$ROOT_DIR/rpm"

# Build the Rust RPM package in release mode
cargo build -p rpm --release

# Generate Go bindings
pushd "$RUST_RPM_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
