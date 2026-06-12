#!/bin/bash
set -euxo pipefail

# This script builds the Rust node binary (crates/quil-node) and
# places it alongside the historic Go build output so Docker images
# and packaging scripts find it without further changes.
#
# Output layout:
#   $ROOT_DIR/node/build/<platform>/node
#
# `<platform>` uses the same naming the Go releases used
# (amd64_linux, amd64_avx512_linux, arm64_linux, arm64_macos) so
# downstream artifact pipelines don't need to change.
#
# Environment overrides:
#   CARGO_PROFILE   — `release` (default) or `dev`.
#   CARGO_FEATURES  — passthrough features; e.g. `avx512`.
#   TARGET_TRIPLE   — override the detected Rust target triple.
#   QUIL_PLATFORM   — override the destination sub-directory
#                     (e.g. `amd64_avx512_linux`).

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"
NODE_DIR="$ROOT_DIR/node"
CRATE_NAME="quil-node"
BIN_NAME="${BIN_NAME:-quil-node}"

# Build profile. Release is the default — matches the Go build script
# which only produced optimized binaries. Override with CARGO_PROFILE=dev
# for debug builds.
CARGO_PROFILE="${CARGO_PROFILE:-release}"

# ---------------------------------------------------------------
# Detect platform + Rust target triple
# ---------------------------------------------------------------
detect_platform() {
    local os arch
    os="$(uname | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        linux)
            case "$arch" in
                x86_64)
                    if [[ -n "${AVX512:-}" || "${CARGO_FEATURES:-}" == *avx512* ]]; then
                        echo "amd64_avx512_linux"
                    else
                        echo "amd64_linux"
                    fi
                    ;;
                aarch64|arm64) echo "arm64_linux" ;;
                *) echo "unknown_linux_${arch}" ;;
            esac
            ;;
        darwin)
            case "$arch" in
                arm64) echo "arm64_macos" ;;
                x86_64) echo "amd64_macos" ;;
                *) echo "unknown_macos_${arch}" ;;
            esac
            ;;
        *) echo "unknown_${os}_${arch}" ;;
    esac
}

detect_target_triple() {
    local os arch
    os="$(uname | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$os" in
        linux)
            case "$arch" in
                x86_64) echo "x86_64-unknown-linux-gnu" ;;
                aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
                *) echo "" ;;
            esac
            ;;
        darwin)
            case "$arch" in
                arm64) echo "aarch64-apple-darwin" ;;
                x86_64) echo "x86_64-apple-darwin" ;;
                *) echo "" ;;
            esac
            ;;
        *) echo "" ;;
    esac
}

PLATFORM="${QUIL_PLATFORM:-$(detect_platform)}"
TARGET_TRIPLE="${TARGET_TRIPLE:-$(detect_target_triple)}"

# ---------------------------------------------------------------
# Resolve native library paths
# ---------------------------------------------------------------
# `crates/classgroup/build.rs` and `crates/ferret/build.rs` expect
# either env-var overrides (`FLINT_DIR`, `GMP_DIR`, `MPFR_DIR`,
# `OPENSSL_DIR`) or a working `brew --prefix <lib>` on macOS. Linux
# uses `/usr/local` (where the Dockerfile gmp/flint builder stages
# install) so no shell-level setup is required.
#
# Static-linking flint on macOS is special because Homebrew's flint
# package ships only the dynamic library. The Rust build.rs falls
# back to dynamic linking when `FLINT_DIR` is unset (binary then
# depends on `libflint.dylib` at runtime). For a self-contained
# binary, point `FLINT_DIR` at an install root containing
# `lib/libflint.a` or an in-tree source build (libflint.a at the
# root + headers under src/). We try `~/src/flint` automatically as
# a developer-convenience default.
os_name="$(uname | tr '[:upper:]' '[:lower:]')"
if [[ "$os_name" == "darwin" ]]; then
    if [[ -z "${FLINT_DIR:-}" ]]; then
        if [[ -f "$HOME/src/flint/libflint.a" ]]; then
            export FLINT_DIR="$HOME/src/flint"
            echo "node/build.sh: auto-detected FLINT_DIR=$FLINT_DIR (in-tree source build)"
        elif [[ -f "/opt/homebrew/lib/libflint.a" ]]; then
            export FLINT_DIR="/opt/homebrew"
        else
            cat <<EOF >&2
node/build.sh: FLINT_DIR is not set and no static libflint.a was found.
The macOS build will fall back to DYNAMIC libflint linkage, producing a
binary that needs \`libflint.dylib\` (from \`brew install flint\`) on every
host it runs on. For a self-contained binary, build flint from source:
    git clone https://github.com/flintlib/flint && cd flint
    ./bootstrap.sh
    ./configure --enable-static --disable-shared \\
        --with-gmp=\$(brew --prefix gmp) \\
        --with-mpfr=\$(brew --prefix mpfr)
    make -j\$(sysctl -n hw.ncpu)
then re-run with FLINT_DIR=\$PWD.
EOF
        fi
    fi
fi

# ---------------------------------------------------------------
# Build
# ---------------------------------------------------------------
pushd "$ROOT_DIR" > /dev/null

cargo_args=(build --bin "$BIN_NAME" -p "$CRATE_NAME")

case "$CARGO_PROFILE" in
    release) cargo_args+=(--release) ;;
    dev|debug) ;; # default profile
    *) cargo_args+=(--profile "$CARGO_PROFILE") ;;
esac

if [[ -n "${CARGO_FEATURES:-}" ]]; then
    cargo_args+=(--features "$CARGO_FEATURES")
fi

if [[ -n "$TARGET_TRIPLE" ]]; then
    cargo_args+=(--target "$TARGET_TRIPLE")
fi

cargo "${cargo_args[@]}"

# ---------------------------------------------------------------
# Locate the built binary
# ---------------------------------------------------------------
if [[ -n "$TARGET_TRIPLE" ]]; then
    BUILD_ROOT="$ROOT_DIR/target/$TARGET_TRIPLE"
else
    BUILD_ROOT="$ROOT_DIR/target"
fi

case "$CARGO_PROFILE" in
    release) PROFILE_DIR="release" ;;
    dev|debug) PROFILE_DIR="debug" ;;
    *) PROFILE_DIR="$CARGO_PROFILE" ;;
esac

BIN_SRC="$BUILD_ROOT/$PROFILE_DIR/$BIN_NAME"
if [[ ! -f "$BIN_SRC" ]]; then
    echo "error: built binary not found at $BIN_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------
# Publish to node/build/<platform>/node
# ---------------------------------------------------------------
OUT_DIR="$NODE_DIR/build/$PLATFORM"
mkdir -p "$OUT_DIR"
# Install as `node` so Docker/systemd scripts expecting the Go
# output path keep working unchanged.
cp "$BIN_SRC" "$OUT_DIR/node"
chmod +x "$OUT_DIR/node"

popd > /dev/null

echo "built $OUT_DIR/node ($(du -h "$OUT_DIR/node" | cut -f1))"
