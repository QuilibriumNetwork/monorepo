#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "$(realpath "$(dirname "${BASH_SOURCE[0]}")")")" >/dev/null 2>&1 && pwd)}"
RUST_PACKAGE="$ROOT_DIR/crates/quil-tries-ffi"
BINDINGS_DIR="$ROOT_DIR/quil-tries-ffi"

cargo build -p quil-tries-ffi --release

pushd "$RUST_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
popd > /dev/null
