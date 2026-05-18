#!/bin/bash
set -euxo pipefail

# This script builds the Go client binary and statically links the Rust
# crates (vdf, channel, ferret, verenc, bulletproofs, bls48581) as
# `.a` archives produced by `cargo build --release`. Assumes those
# archives already exist under `$ROOT_DIR/target/release/`.
#
# Native dependencies (gmp, mpfr, flint, openssl) must be reachable at
# link time. On macOS this script resolves their install prefixes via
# `brew --prefix <lib>` (matching the discovery the Rust
# `crates/classgroup/build.rs` and `crates/ferret/build.rs` do) and
# honors env-var overrides for non-Homebrew installs:
#
#   FLINT_DIR    — root containing `lib/libflint.a` (install layout)
#                  or a flint source tree with `libflint.a` at the
#                  root (in-tree build layout). When unset and no
#                  static archive is found, defaults to dynamic
#                  flint linkage via the brew prefix — binary then
#                  depends on `libflint.dylib` at runtime.
#   GMP_DIR      — install root containing `lib/libgmp.a`.
#   MPFR_DIR     — install root containing `lib/libmpfr.a`.
#   OPENSSL_DIR  — install root containing `lib/libssl.a`,
#                  `lib/libcrypto.a`.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

CLIENT_DIR="$ROOT_DIR/client"
BINARIES_DIR="$ROOT_DIR/target/release"

pushd "$CLIENT_DIR" > /dev/null

export CGO_ENABLED=1

# Resolve a library install prefix on macOS:
#   1. Honor the named env-var override (e.g. GMP_DIR) when set.
#   2. Otherwise call `brew --prefix <pkg>`.
# Exits the script with an actionable error when neither resolves.
resolve_lib_prefix() {
    local pkg="$1"
    local env_var="$2"
    local override="${!env_var:-}"
    if [[ -n "$override" ]]; then
        echo "$override"
        return 0
    fi
    if ! command -v brew >/dev/null 2>&1; then
        echo "client/build.sh: \`brew\` not found and $env_var is unset — cannot locate $pkg" >&2
        exit 1
    fi
    local prefix
    prefix="$(brew --prefix "$pkg" 2>/dev/null || true)"
    if [[ -z "$prefix" ]]; then
        echo "client/build.sh: \`brew --prefix $pkg\` returned empty; install with \`brew install $pkg\` or set $env_var" >&2
        exit 1
    fi
    echo "$prefix"
}

os_type="$(uname)"
case "$os_type" in
    "Darwin")
        # Check if the architecture is ARM
        if [[ "$(uname -m)" == "arm64" ]]; then
            # MacOS ld doesn't support -Bstatic and -Bdynamic, so it's
            # important that there is only a static version of the
            # library available at the resolved path. The hardcoded
            # `/usr/local/lib` + `Cellar/openssl@3/3.6.1` paths that
            # were here previously broke on every Homebrew minor-
            # version bump and were wrong for the Apple Silicon
            # `/opt/homebrew` layout — `brew --prefix` returns the
            # stable per-package symlink that survives upgrades.
            GMP_PREFIX="$(resolve_lib_prefix gmp GMP_DIR)"
            MPFR_PREFIX="$(resolve_lib_prefix mpfr MPFR_DIR)"
            OPENSSL_PREFIX="$(resolve_lib_prefix openssl@3 OPENSSL_DIR)"
            # Flint discovery mirrors crates/classgroup/build.rs.
            # When FLINT_DIR is set, accept either an install-prefix
            # layout (`<dir>/lib/libflint.a`) or an in-tree source
            # layout (`<dir>/libflint.a`). Otherwise fall back to
            # Homebrew's dynamic libflint.
            FLINT_LIB_DIR=""
            if [[ -n "${FLINT_DIR:-}" ]]; then
                if [[ -f "$FLINT_DIR/lib/libflint.a" ]]; then
                    FLINT_LIB_DIR="$FLINT_DIR/lib"
                elif [[ -f "$FLINT_DIR/libflint.a" ]]; then
                    FLINT_LIB_DIR="$FLINT_DIR"
                else
                    echo "client/build.sh: FLINT_DIR=$FLINT_DIR contains neither lib/libflint.a nor libflint.a" >&2
                    exit 1
                fi
            else
                FLINT_LIB_DIR="$(resolve_lib_prefix flint FLINT_DIR)/lib"
            fi
            go build -ldflags "-linkmode 'external' -extldflags '-L$BINARIES_DIR -L$FLINT_LIB_DIR -L$GMP_PREFIX/lib -L$MPFR_PREFIX/lib -L$OPENSSL_PREFIX/lib -lbls48581 -lvdf -lchannel -lferret -lverenc -lbulletproofs -ldl -lm -lflint -lgmp -lmpfr -lstdc++ -lcrypto -lssl'" "$@"
        else
            echo "Unsupported platform"
            exit 1
        fi
        ;;
    "Linux")
        # Linux build relies on /usr/local where the gmp/flint
        # Dockerfile builder stages install. Static linking
        # everything (including libgmp, libmpfr, libflint, libssl,
        # libcrypto) is what the `-static` flag at the end of
        # CGO_LDFLAGS is for. Don't swap `-lmpfr` for ordering
        # tweaks here -- that combination triggers
        # `__gmpz_export redeclared` because libmpfr.a bundles its
        # own GMP forwarders.
        export CGO_LDFLAGS="-L/usr/local/lib -lflint -lgmp -lmpfr -ldl -lm -L$BINARIES_DIR -lstdc++ -lvdf -lchannel -lferret -lverenc -lbulletproofs -lbls48581 -lcrypto -lssl -static"
        go build -ldflags "-linkmode 'external'" "$@"
        ;;
    *)
        echo "Unsupported platform"
        exit 1
        ;;
esac
