#!/bin/bash
set -euxo pipefail

# Run tests for the node package. Takes care of linking the native VDF. 
# Assumes that the VDF library has been built by running the generate.sh script in the `../vdf` directory.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

NODE_DIR="$ROOT_DIR/node"
BINARIES_DIR="$ROOT_DIR/target/release"

# Link the native VDF and execute tests
pushd "$NODE_DIR" > /dev/null
	CGO_LDFLAGS="-L$BINARIES_DIR -L/usr/local/lib/ -L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lbls48581 -lverenc -lbulletproofs -lvdf -lchannel -lferret -lrpm -lstdc++ -ldl -lm -lflint -lgmp -lmpfr -lcrypto -lssl" \
	CGO_ENABLED=1 \
  go test "$@"
