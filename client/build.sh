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
            # macOS `ld` has no `-Bstatic` / `-Bdynamic` toggles and,
            # given both forms in the same `-L` directory, prefers
            # `.dylib` over `.a`. That's how we ended up shipping a
            # qclient with a runtime dependency on `libchannel.dylib`
            # — the `channel` crate declares
            # `crate-type = ["lib", "staticlib", "cdylib"]`, so
            # `cargo build --release` produces both
            # `target/release/libchannel.a` AND
            # `.../libchannel.dylib`, and `-lchannel` quietly picked
            # the dynamic one. The hardcoded
            # `/opt/homebrew/Cellar/openssl@3/3.6.1` path had the
            # same hazard for the openssl libs — Homebrew ships
            # both .a and .dylib in `lib/`.
            #
            # To force static linkage we pass each archive as an
            # explicit absolute file path instead of `-l<name>`;
            # macOS ld treats positional `.a` paths as archives,
            # bypassing the dylib-preference rule entirely. Only
            # `-lstdc++`, `-ldl`, `-lm` remain as `-l` flags — those
            # are Apple system libraries that ship dylib-only and
            # are always present on any macOS install.
            GMP_PREFIX="$(resolve_lib_prefix gmp GMP_DIR)"
            MPFR_PREFIX="$(resolve_lib_prefix mpfr MPFR_DIR)"
            OPENSSL_PREFIX="$(resolve_lib_prefix openssl@3 OPENSSL_DIR)"
            # Flint discovery mirrors crates/classgroup/build.rs.
            # When FLINT_DIR is set, accept either an install-prefix
            # layout (`<dir>/lib/libflint.a`) or an in-tree source
            # layout (`<dir>/libflint.a`). Otherwise fall back to
            # Homebrew's dynamic libflint.
            FLINT_LIB_DIR=""
            FLINT_STATIC_OK=1
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
                if [[ ! -f "$FLINT_LIB_DIR/libflint.a" ]]; then
                    FLINT_STATIC_OK=0
                fi
            fi

            # Sanity-check: every Rust-side archive must exist at the
            # exact path we're about to pass to ld. Fail loudly if
            # cargo hasn't been run yet — better than a confusing
            # linker error.
            for name in vdf channel ferret verenc bulletproofs bls48581; do
                if [[ ! -f "$BINARIES_DIR/lib${name}.a" ]]; then
                    echo "client/build.sh: missing $BINARIES_DIR/lib${name}.a — run \`cargo build --release\` first" >&2
                    exit 1
                fi
            done

            # Same check for the native static archives. The libgmp
            # / libmpfr / libcrypto / libssl `.a` files all ship with
            # their respective Homebrew formulas (and with any
            # standard `make install --prefix=...` build).
            for path in \
                "$GMP_PREFIX/lib/libgmp.a" \
                "$MPFR_PREFIX/lib/libmpfr.a" \
                "$OPENSSL_PREFIX/lib/libcrypto.a" \
                "$OPENSSL_PREFIX/lib/libssl.a"
            do
                if [[ ! -f "$path" ]]; then
                    echo "client/build.sh: missing static archive $path" >&2
                    exit 1
                fi
            done

            # Build the explicit archive list. Order matters: callers
            # before callees (libbls48581 / libvdf / libchannel /
            # libferret / libverenc / libbulletproofs depend on
            # libflint / libgmp / libmpfr / libcrypto / libssl).
            archives=(
                "$BINARIES_DIR/libbls48581.a"
                "$BINARIES_DIR/libvdf.a"
                "$BINARIES_DIR/libchannel.a"
                "$BINARIES_DIR/libferret.a"
                "$BINARIES_DIR/libverenc.a"
                "$BINARIES_DIR/libbulletproofs.a"
            )
            if [[ "$FLINT_STATIC_OK" == "1" ]]; then
                archives+=("$FLINT_LIB_DIR/libflint.a")
            fi
            archives+=(
                "$GMP_PREFIX/lib/libgmp.a"
                "$MPFR_PREFIX/lib/libmpfr.a"
                "$OPENSSL_PREFIX/lib/libcrypto.a"
                "$OPENSSL_PREFIX/lib/libssl.a"
            )

            extldflags="${archives[*]} -ldl -lm -lstdc++"
            # Fallback flint linkage when no static archive is
            # available — emits a dylib dependency the binary
            # carries at runtime. Document the gap loudly.
            if [[ "$FLINT_STATIC_OK" != "1" ]]; then
                extldflags="-L$FLINT_LIB_DIR -lflint $extldflags"
                echo "client/build.sh: warning — linking libflint DYNAMICALLY (no libflint.a found at $FLINT_LIB_DIR); produced binary will need libflint.dylib at runtime" >&2
            fi

            go build -ldflags "-linkmode 'external' -extldflags '$extldflags'" "$@"
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
