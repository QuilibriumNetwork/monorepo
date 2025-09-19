#!/bin/bash
set -euxo pipefail

# Run tests for the ferret package. Takes care of linking the native FERRET.
# Assumes that the FERRET library has been built by running the generate.sh script in the same directory.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

NODE_DIR="$ROOT_DIR/ferret"
BINARIES_DIR="$ROOT_DIR/target/release"

# Link the native FERRET and execute tests
pushd "$NODE_DIR" > /dev/null
	CGO_LDFLAGS="-L$BINARIES_DIR -L/usr/local/lib/ -L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lstdc++ -lferret -ldl -lm -lcrypto -lssl" \
	CGO_ENABLED=1 \
	GOEXPERIMENT=arenas \
  go test "$@"
