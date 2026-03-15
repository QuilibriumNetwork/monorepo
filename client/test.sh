#!/bin/bash
set -euxo pipefail

# Run tests for the client package. Takes care of linking the native FFI libs.
# Assumes that the libraries have been built by running the generate.sh script
# in the respective directories.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

CLIENT_DIR="$ROOT_DIR/client"
BINARIES_DIR="$ROOT_DIR/target/release"

# Link native libraries and execute tests
pushd "$CLIENT_DIR" > /dev/null
	CGO_LDFLAGS="-L$BINARIES_DIR -L/usr/local/lib/ -L/opt/homebrew/Cellar/openssl@3/3.6.1/lib -lbls48581 -lverenc -lbulletproofs -lvdf -lchannel -lferret -lrpm -lstdc++ -ldl -lm -lflint -lgmp -lmpfr -lcrypto -lssl" \
	CGO_ENABLED=1 \
  go test "$@"
