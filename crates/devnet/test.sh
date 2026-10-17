#!/usr/bin/env bash
set -euo pipefail

# CI for the devnet harness.
#
# Runs formatting, lints, and unit tests for the `devnet` crate, then (unless
# -short is passed) a single end-to-end integration run against the compose
# stack. The integration run requires Docker and the proxy image.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SHORT=false
for arg in "$@"; do
    if [[ "$arg" == "-short" ]]; then
        SHORT=true
    fi
done

run() {
    echo ""
    echo ">>> $*"
    "$@"
}

# ── lint + unit tests ────────────────────────────────────────────────────────
# clippy is run with --no-deps: some transitive workspace crates set their own
# `#![deny(clippy::pedantic)]`, which fails under newer clippy and is out of
# scope here. We only gate on devnet's own lints.

run cargo fmt -p devnet -p devnet-proxy -- --check
run cargo clippy -p devnet -p devnet-proxy --no-deps --all-targets -- -D warnings
run cargo nextest run -p devnet -p devnet-proxy

# ── integration run ──────────────────────────────────────────────────────────

if [[ "$SHORT" == false ]]; then
    cd "$SCRIPT_DIR"
    run cargo run -p devnet -- single --verbose --stopframe=5 \
        --view-partitions='[{"view":2,"partition1":["archive-1","archive-2","archive-3"],"partition2":["archive-4"]}]'
fi
