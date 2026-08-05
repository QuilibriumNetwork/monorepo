#!/usr/bin/env bash
# Regenerate the real-frame fuzz seeds from the public explorer API.
#
# Fetches a spread of live GlobalFrames as protojson, converts each to canonical
# wire bytes via the `frames_to_corpus` example (which round-trip-checks that
# `decode_global_frame` accepts its own output), and writes them into
# fuzz/seeds/. Bundle seeds for the message decoders are emitted too.
#
#   FLINT_DIR=/path/to/flint crates/quil-engine/fuzz/fetch_seed_frames.sh
#
# Requires: curl, python3, and a working `cargo` (+ FLINT_DIR for the crypto deps).
set -euo pipefail

API="${EXPLORER_API:-https://explorer-api.quilibrium.com}"
FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$FUZZ_DIR/../../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

latest="$(curl -sS --max-time 20 "$API/frames/latest" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["header"]["frameNumber"])')"
echo "explorer latest frame = $latest"

# 8 recent consecutive (real request bundles) + a few historical representatives.
nums=("$latest")
for i in 1 2 3 4 5 6 7; do nums+=("$((latest - i))"); done
nums+=(675000 500000 250000 244300)

fetched=0
for n in "${nums[@]}"; do
  if curl -fsS --max-time 20 "$API/frames/$n" -o "$TMP/f_$n.json" 2>/dev/null; then
    fetched=$((fetched + 1))
  else
    echo "  (frame $n unavailable, skipping)"
  fi
done
echo "fetched $fetched frames"

mkdir -p "$FUZZ_DIR/seeds/decode_global_frame" "$FUZZ_DIR/seeds/decode_message_bundle"
BUNDLE_CORPUS="$FUZZ_DIR/seeds/decode_message_bundle" \
  cargo run --release -q -p quil-engine --example frames_to_corpus -- \
  "$FUZZ_DIR/seeds/decode_global_frame" "$TMP"/f_*.json

echo "seeds refreshed under $FUZZ_DIR/seeds/"
