#!/usr/bin/env bash
#
# devnet-shard-info.sh — a regular node's shard info against the archives'.
#
# Only an archive materializes app shards. A regular node's master store
# holds no app data, so its GetShardInfo (`qclient node prover shardinfo`,
# the TUI, the planner of `token shield-all`) must take shard sizes from the
# archives; its own view stops at what its master store holds. A release
# that served that view showed regular nodes a few KB of world state, a
# fraction of the shards and none of their allocations (#1009).
#
# Starts ARCHIVES archives and REGULARS regular nodes with app-shard
# consensus through scripts/localnet.sh. Once archive0 materializes
# app-shard frames and reg1's prover holds a reward balance, reg1 mints its
# reward: `token mint`, then `token mint --claim` once GLOBAL finalized the
# authorization. The claim commits a coin into the QUIL shard, which the
# archives materialize and the regular nodes' master stores never receive.
# It asserts, each within its bound:
#   - reg1's reward mint is authorized and claimed (MINT_BOUND, CLAIM_BOUND);
#   - archive0's world state grows past its size before the mint, so the
#     archives hold app data reg1's master store lacks (DELIVERY_BOUND);
#   - reg1 and archive0 report the same shard filters and the same world
#     state in `node prover shardinfo`, in one of COMPARE_TRIES samples
#     COMPARE_GAP seconds apart. A regular node reporting fewer shards or a
#     smaller world serves its own partial view instead of the archives'.
# Exit status is non-zero, with both views and a summary of the failed
# checks, otherwise 0. About 30 min for a devnet given 4 CPUs.
#
# Environment:
#   TARGET_DIR   cargo target directory with <PROFILE>/quil-node,
#                <PROFILE>/quil-amount-proof-worker and <PROFILE>/qclient
#                (default <repo>/target)
#   PROFILE      cargo profile directory (default devnet)
#   QCLIENT      qclient binary (default <TARGET_DIR>/<PROFILE>/qclient)
#   NET_DIR      scratch directory of the devnet (default
#                <repo>/.devnet-shard-info); must not hold an earlier devnet
#   ARCHIVES, REGULARS, CORES   devnet size (default 3, 4, 1)
#   WARM_BOUND, MINT_BOUND, CLAIM_BOUND, DELIVERY_BOUND   seconds
#                (default 2400, 1800, 900, 900)
#   COMPARE_TRIES, COMPARE_GAP   (default 6, 10)
#   QUIL_EPOCH_LENGTH_FRAMES (default 30) and the other settings of
#                scripts/localnet.sh; APP_CW is always 1
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-$ROOT/target}"
PROFILE="${PROFILE:-devnet}"
QCLIENT="${QCLIENT:-$TARGET_DIR/$PROFILE/qclient}"
NET_DIR="${NET_DIR:-$ROOT/.devnet-shard-info}"
ARCHIVES="${ARCHIVES:-3}"
REGULARS="${REGULARS:-4}"
CORES="${CORES:-1}"
WARM_BOUND="${WARM_BOUND:-2400}"
MINT_BOUND="${MINT_BOUND:-1800}"
CLAIM_BOUND="${CLAIM_BOUND:-900}"
DELIVERY_BOUND="${DELIVERY_BOUND:-900}"
COMPARE_TRIES="${COMPARE_TRIES:-6}"
COMPARE_GAP="${COMPARE_GAP:-10}"
export APP_CW=1 QUIL_EPOCH_LENGTH_FRAMES="${QUIL_EPOCH_LENGTH_FRAMES:-30}"
OUT="$NET_DIR/results"
MATERIALIZED_RE='archive materialized shard frame'

[[ -x "$TARGET_DIR/$PROFILE/quil-node" && -x "$TARGET_DIR/$PROFILE/quil-amount-proof-worker" && -x "$QCLIENT" ]] \
  || { echo "build quil-node, quil-amount-proof-worker and qclient with profile $PROFILE into $TARGET_DIR first" >&2; exit 2; }
[[ ! -e "$NET_DIR" ]] || { echo "$NET_DIR exists; remove it or set NET_DIR" >&2; exit 2; }
mkdir -p "$OUT"

now() { date -u +%FT%TZ; }
log() { printf '[%s] %s\n' "$(now)" "$*" | tee -a "$OUT/run.log"; }
FAILS=()
fail() { FAILS+=("$1"); log "FAIL: $1"; }
elapsed() { echo $(( $(date +%s) - $1 )); }

# qclient for node $1. Prover commands read the node config from ./.config,
# so each node gets a directory whose .config is its own and a HOME without
# a default node config; token commands name it with --config as well.
qc() { # node args...
  local node=$1 d="$OUT/qclient-$1"; shift
  mkdir -p "$d/home"
  [[ -e "$d/.config" ]] || ln -s "$NET_DIR/$node" "$d/.config"
  ( cd "$d" && HOME="$d/home" QUILIBRIUM_NETWORK='' timeout 900 "$QCLIENT" "$@" ) 2>&1
}
# `node prover shardinfo` of node $1, saved as shardinfo.$1.$2.txt; prints
# "<shard count> <world state>", then the shard filters with their sizes.
shard_view() { # node tag
  local out
  out=$(qc "$1" node prover shardinfo)
  printf '%s\n' "$out" > "$OUT/shardinfo.$1.$2.txt"
  printf '%s %s\n' \
    "$(sed -n 's/^All Shards (\([0-9]*\) shards):$/\1/p' <<< "$out" | head -1)" \
    "$(sed -n 's/^World State: //p' <<< "$out" | head -1 | tr -d ' ')"
  awk '$1 == "Filter:" { print $2, $4 $5 }' <<< "$out" | sort
}

cleanup() {
  local i
  kill "${UPPID:-0}" 2>/dev/null
  pkill -f -- "--config $NET_DIR/" 2>/dev/null
  for (( i=0; i<60; i+=2 )); do
    pgrep -f -- "--config $NET_DIR/" > /dev/null || return 0
    sleep 2
  done
  pkill -9 -f -- "--config $NET_DIR/" 2>/dev/null
  sleep 2
}
trap cleanup EXIT

log "starting the devnet: $ARCHIVES archives + $REGULARS regular nodes ($CORES workers each), app-shard consensus, ${QUIL_EPOCH_LENGTH_FRAMES}-frame epochs, binary $TARGET_DIR/$PROFILE/quil-node"
NET_DIR="$NET_DIR" TARGET_DIR="$TARGET_DIR" PROFILE="$PROFILE" SKIP_BUILD=1 \
  ARCHIVES="$ARCHIVES" REGULARS="$REGULARS" CORES="$CORES" \
  bash "$ROOT/scripts/localnet.sh" up > "$OUT/up.log" 2>&1 &
UPPID=$!

# archive0 materializes app-shard frames: the regular nodes' workers formed
# the QUIL shard's committee and GLOBAL includes its frames.
t0=$(date +%s)
until (( $(cat "$NET_DIR/archive0/.log/master.log" 2>/dev/null | grep -ac "$MATERIALIZED_RE") >= 10 )); do
  (( $(elapsed "$t0") < WARM_BOUND )) \
    || { log "archive0 materialized no app-shard frames within ${WARM_BOUND}s; see $OUT/up.log"; exit 1; }
  sleep 10
done
wait "$UPPID" \
  || { log "scripts/localnet.sh up failed; the end of $OUT/up.log:"; tail -n 20 "$OUT/up.log" | tee -a "$OUT/run.log"; exit 1; }
log "archive0 materializes app-shard frames after $(elapsed "$t0")s"

{ read -r reg_n reg_world; read -r arc_n arc_world; } < <(shard_view reg1 before | head -1; shard_view archive0 before | head -1)
arc_world_before=$arc_world
log "before the mint: reg1 reports ${reg_n:-no} shards, world ${reg_world:-none}; archive0 reports ${arc_n:-no} shards, world ${arc_world:-none}"

# reg1's reward mint. The authorization fails until reg1's prover holds a
# credited reward ("no claimable prover reward found"); the claim fails until
# the QUIL shard anchors a GLOBAL frame that finalized the authorization.
t0=$(date +%s); auth=""
while [[ -z "$auth" ]] && (( $(elapsed "$t0") < MINT_BOUND )); do
  qc reg1 token mint --config "$NET_DIR/reg1" > "$OUT/mint.txt"
  auth=$(sed -n 's/.*`token mint --claim \([^`]*\)`.*/\1/p' "$OUT/mint.txt")
  [[ -n "$auth" ]] || sleep 30
done
if [[ -z "$auth" ]]; then
  fail "reg1's reward mint was not authorized within ${MINT_BOUND}s: $(tail -n 1 "$OUT/mint.txt")"
else
  log "reg1's reward mint authorized after $(elapsed "$t0")s: $(grep -a 'authorization submitted' "$OUT/mint.txt")"
  t0=$(date +%s); claimed=0
  while (( ! claimed && $(elapsed "$t0") < CLAIM_BOUND )); do
    sleep 30
    qc reg1 token mint --config "$NET_DIR/reg1" --claim "$auth" > "$OUT/claim.txt"
    grep -aq 'mint claim submitted' "$OUT/claim.txt" && claimed=1
  done
  if (( claimed )); then
    log "reg1's reward mint claimed after $(elapsed "$t0")s"
  else
    fail "reg1's reward mint was not claimed within ${CLAIM_BOUND}s: $(tail -n 1 "$OUT/claim.txt")"
  fi
fi

# The minted coin lands in the QUIL shard: archive0's world state grows.
t0=$(date +%s); grown=0
while (( ! grown && $(elapsed "$t0") < DELIVERY_BOUND )); do
  read -r arc_n arc_world < <(shard_view archive0 delivery)
  [[ -n "$arc_world" && "$arc_world" != "$arc_world_before" ]] && grown=1 || sleep 20
done
if (( grown )); then
  log "archive0's world state grew from $arc_world_before to $arc_world within $(elapsed "$t0")s of the claim"
else
  fail "archive0's world state stayed ${arc_world:-none} for ${DELIVERY_BOUND}s after the claim: no app data beyond the regular nodes' stores, so the comparison below cannot tell a partial view from the archives'"
fi

# reg1 against archive0: the same shards and the same world state.
same=0
for (( i=1; i<=COMPARE_TRIES; i++ )); do
  shard_view reg1 "try$i" > "$OUT/reg1.view"
  shard_view archive0 "try$i" > "$OUT/archive0.view"
  if [[ -n "$(head -c 1 "$OUT/archive0.view" | tr -d ' \n')" ]] && cmp -s "$OUT/reg1.view" "$OUT/archive0.view"; then
    same=1; break
  fi
  (( i < COMPARE_TRIES )) && sleep "$COMPARE_GAP"
done
read -r reg_n reg_world < "$OUT/reg1.view"
read -r arc_n arc_world < "$OUT/archive0.view"
log "shard info (sample $(( i > COMPARE_TRIES ? COMPARE_TRIES : i ))): reg1 reports ${reg_n:-no} shards, world ${reg_world:-none}; archive0 reports ${arc_n:-no} shards, world ${arc_world:-none}"
if (( ! same )); then
  fail "reg1's shard info differs from archive0's in all $COMPARE_TRIES samples: reg1 ${reg_n:-0} shards, world ${reg_world:-none}; archive0 ${arc_n:-0} shards, world ${arc_world:-none}. A regular node serving its own partial view instead of the archives' sizes"
  echo "--- reg1, last sample"; cat "$OUT/reg1.view"
  echo "--- archive0, last sample"; cat "$OUT/archive0.view"
fi
src=$(cat "$NET_DIR"/reg1/.log/master.log | grep -a 'shard info: serving' | tail -n 1 | cut -f1,4)
log "reg1's last shard-info source line: ${src:-none}"

echo
if (( ${#FAILS[@]} )); then
  echo "FAILED checks:"; printf '  - %s\n' "${FAILS[@]}"
  exit 1
fi
echo "PASS: reg1 reports archive0's shards and world state after its reward mint committed a coin into the QUIL shard"
