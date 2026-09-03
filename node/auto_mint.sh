#!/usr/bin/env bash
# Automatically claims prover reward every 5 frames (~50s)

INTERVAL_SECONDS=${1:-50}

echo "Starting auto-mint daemon (every ${INTERVAL_SECONDS}s / ~5 frames)..."
echo "Press [CTRL+C] to stop."

while true; do
  output=$(./qclient token mint 2>&1)
  if echo "$output" | grep -q "Mint submitted"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $output"
  elif echo "$output" | grep -q "no claimable prover reward"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No new reward ready yet. Waiting..."
  else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $output"
  fi
  sleep "$INTERVAL_SECONDS"
done
