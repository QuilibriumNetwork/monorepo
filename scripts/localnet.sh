#!/usr/bin/env bash
#
# localnet.sh — stand up a local Quilibrium testnet of co-located nodes.
#
# Topology (default): ARCHIVES archive node(s) that form the global-consensus
# committee (commonware-simplex + Falcon) + N regular nodes that join and run
# app-shard workers. All on localhost with distinct ports and a private data dir
# per node under .localnet/.
#
#   scripts/localnet.sh up        # build + key-gen + launch
#   scripts/localnet.sh down      # stop all nodes
#   scripts/localnet.sh logs      # tail every node's log
#   scripts/localnet.sh clean     # down + wipe .localnet/
#
# Env overrides:
#   ARCHIVES=1        number of archive nodes = the global-consensus committee.
#                     N>1 exercises real multi-node simplex voting; quorum is
#                     floor(2N/3)+1 (N=1→1, N=2→2, N=3→3, N=4→3).
#   REGULARS=3        number of regular (non-archive) nodes
#   CORES=3           dataWorkerCount per regular node (worker threads)
#   PROFILE=release   cargo build profile (release|debug)
#   NETWORK=1         network id (1 = primary testnet; non-0, non-99)
#   HEAP_PROF=1       run regulars under MALLOC_CONF heap profiling
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET_DIR="$ROOT/.localnet"
ARCHIVES="${ARCHIVES:-1}"
REGULARS="${REGULARS:-3}"
CORES="${CORES:-3}"
PROFILE="${PROFILE:-release}"
NETWORK="${NETWORK:-1}"
HEAP_PROF="${HEAP_PROF:-0}"
# P3: drive app-shard consensus with commonware-simplex when APP_CW=1.
APP_CW_BOOL=$([[ "${APP_CW:-0}" == "1" || "${APP_CW:-0}" == "true" ]] && echo true || echo false)
# With app-CW on, shrink the epoch so a joined prover reaches Active (confirm in
# the epoch after join) in a handful of frames instead of ~60 — makes the
# app-shard lifecycle observable within a localnet run. Uniform across all nodes.
if [[ "$APP_CW_BOOL" == "true" ]]; then
  # Wide enough that the confirm (must materialize in the epoch AFTER join)
  # lands in-window despite include→finalize→materialize latency, yet small
  # enough to reach the epoch-1 boundary within a localnet run.
  export QUIL_EPOCH_LENGTH_FRAMES="${QUIL_EPOCH_LENGTH_FRAMES:-30}"
  # A joining prover only learns its own on-chain allocation via the incremental
  # prover-tree sync, and must see it in time to emit a ProverConfirm within the
  # one-epoch window. The production default (300s) is far longer than a
  # shortened localnet epoch (~seconds), so every joiner would miss its confirm
  # slot. Poll the prover tree every few seconds here to match the short epoch.
  export QUIL_PROVER_TREE_SYNC_SECS="${QUIL_PROVER_TREE_SYNC_SECS:-5}"
fi

# Per-node port base; node K gets base + K*10 for each service. Archives use
# indices 0..ARCHIVES-1; regulars continue from ARCHIVES.
P2P_BASE=8336    # /udp QUIC
STREAM_BASE=8340 # /tcp :8340 (peer mTLS + worker cluster + direct consensus)
GRPC_BASE=8337
REST_BASE=8338

if [[ "$PROFILE" == "release" ]]; then
  BIN="$ROOT/target/release/quil-node"
  CARGO_FLAGS="--release"
else
  BIN="$ROOT/target/debug/quil-node"
  CARGO_FLAGS=""
fi

# Common flags. Source builds aren't signed, so signature check is off.
COMMON_FLAGS=(--network "$NETWORK" --signature-check=false)
if [ -n "${LOGFILTER:-}" ]; then COMMON_FLAGS+=(--log-filter "$LOGFILTER"); fi

log() { printf '\033[1;34m[localnet]\033[0m %s\n' "$*"; }

node_dir()  { echo "$NET_DIR/$1"; }
node_p2p()  { echo $((P2P_BASE + $1 * 10)); }
node_strm() { echo $((STREAM_BASE + $1 * 10)); }
node_grpc() { echo $((GRPC_BASE + $1 * 10)); }
node_rest() { echo $((REST_BASE + $1 * 10)); }

# Extract the persisted Ed448 peer key hex from a node's config.yml.
read_peerkey() {
  sed -n 's/^[[:space:]]*peerPrivKey:[[:space:]]*"\{0,1\}\([0-9a-fA-F][0-9a-fA-F]*\).*/\1/p' \
    "$1/config.yml" | head -1
}

# Emit a YAML list (indented 4 spaces under an engine: key) from the remaining
# args, or `[]` if none. $1 = key name.
yaml_list() {
  local key="$1"; shift
  if [[ "$#" -eq 0 ]]; then
    printf '  %s: []\n' "$key"
    return
  fi
  printf '  %s:\n' "$key"
  local v
  for v in "$@"; do printf '    - "%s"\n' "$v"; done
}

# Write an ARCHIVE node config with committee + direct-consensus endpoints.
# $1=dir $2=idx $3=seed $4=peerkey $5=bootstrap(maybe empty)
# then: --committee <hex...> --peerids <b58...> --endpoints <maddr...>
# passed via the global arrays COMMITTEE_HEX, COMMITTEE_PID, ARCH_ENDPOINTS.
write_archive_config() {
  local dir="$1" idx="$2" seed="$3" peerkey="$4" bootstrap="$5"
  mkdir -p "$dir"
  local p2p strm grpc rest boot_block=""
  p2p=$(node_p2p "$idx"); strm=$(node_strm "$idx")
  grpc=$(node_grpc "$idx"); rest=$(node_rest "$idx")
  if [[ -n "$bootstrap" ]]; then boot_block=$'\n    - "'"$bootstrap"'"'; fi
  {
    cat <<YAML
key:
  keyStoreFile:
    path: "$dir/keys.yml"
p2p:
  network: $NETWORK
  peerPrivKey: "$peerkey"
  listenMultiaddr: "/ip4/0.0.0.0/udp/$p2p/quic-v1"
  announceListenMultiaddr: "/ip4/127.0.0.1/udp/$p2p/quic-v1"
  streamListenMultiaddr: "/ip4/0.0.0.0/tcp/$strm"
  announceStreamListenMultiaddr: "/ip4/127.0.0.1/tcp/$strm"
  minBootstrapPeers: $([[ -z "$bootstrap" ]] && echo 0 || echo 1)
  bootstrapPeers:$( [[ -n "$bootstrap" ]] && echo "$boot_block" || echo " []" )
  directPeers: []
engine:
  archiveMode: true
  genesisSeed: "$seed"
  dataWorkerCount: 0
YAML
    yaml_list "archiveEndpoints"           ${ARCH_ENDPOINTS[@]+"${ARCH_ENDPOINTS[@]}"}
    yaml_list "consensusCommittee"         ${COMMITTEE_HEX[@]+"${COMMITTEE_HEX[@]}"}
    yaml_list "consensusCommitteePeerIds"  ${COMMITTEE_PID[@]+"${COMMITTEE_PID[@]}"}
    cat <<YAML
db:
  path: "$dir/store"
listenGrpcMultiaddr: "/ip4/127.0.0.1/tcp/$grpc"
listenRESTMultiaddr: "/ip4/127.0.0.1/tcp/$rest"
YAML
  } > "$dir/config.yml"
}

# Write a REGULAR (non-archive) node config.
# $1=dir $2=idx $3=seed $4=bootstrap $5=workers $6=direct_peers_block(maybe empty)
write_regular_config() {
  local dir="$1" idx="$2" seed="$3" bootstrap="$4" workers="$5" direct_block="${6:-}"
  mkdir -p "$dir"
  local p2p strm grpc rest boot_block=""
  p2p=$(node_p2p "$idx"); strm=$(node_strm "$idx")
  grpc=$(node_grpc "$idx"); rest=$(node_rest "$idx")
  if [[ -n "$bootstrap" ]]; then boot_block=$'\n    - "'"$bootstrap"'"'; fi
  cat > "$dir/config.yml" <<YAML
key:
  keyStoreFile:
    path: "$dir/keys.yml"
p2p:
  network: $NETWORK
  listenMultiaddr: "/ip4/0.0.0.0/udp/$p2p/quic-v1"
  announceListenMultiaddr: "/ip4/127.0.0.1/udp/$p2p/quic-v1"
  streamListenMultiaddr: "/ip4/0.0.0.0/tcp/$strm"
  announceStreamListenMultiaddr: "/ip4/127.0.0.1/tcp/$strm"
  minBootstrapPeers: 1
  bootstrapPeers:$boot_block
  directPeers:$( [[ -n "$direct_block" ]] && echo "$direct_block" || echo " []" )
engine:
  archiveMode: false
  genesisSeed: "$seed"
  dataWorkerCount: $workers
  appConsensusCw: $APP_CW_BOOL
db:
  path: "$dir/store"
listenGrpcMultiaddr: "/ip4/127.0.0.1/tcp/$grpc"
listenRESTMultiaddr: "/ip4/127.0.0.1/tcp/$rest"
YAML
}

cmd_up() {
  log "building quil-node ($PROFILE)…"
  ( cd "$ROOT" && FLINT_DIR="${FLINT_DIR:-/Users/caheart/src/flint}" \
      QUILIBRIUM_SIGNATURE_CHECK=false cargo build $CARGO_FLAGS -p quil-node )
  [[ -x "$BIN" ]] || { echo "binary not found at $BIN"; exit 1; }

  mkdir -p "$NET_DIR"

  # --- Pass 1: generate every archive's identity (committee members). --------
  local -a A_DIR A_PEER A_BLS A_CONS A_PRIV
  local k
  for (( k=0; k<ARCHIVES; k++ )); do
    local adir; adir=$(node_dir "archive$k")
    A_DIR[$k]="$adir"
    log "preparing archive$k identity…"
    # Minimal placeholder config so --print-identity can persist the peer key.
    COMMITTEE_HEX=(); COMMITTEE_PID=(); ARCH_ENDPOINTS=()
    write_archive_config "$adir" "$k" "" "" ""
    local ident
    ident=$("$BIN" --config "$adir" "${COMMON_FLAGS[@]}" --print-identity)
    A_PEER[$k]=$(echo "$ident" | sed -n 's/^PEER_ID=//p')
    A_BLS[$k]=$(echo "$ident" | sed -n 's/^BLS_PUBKEY=//p')
    A_CONS[$k]=$(echo "$ident" | sed -n 's/^CONSENSUS_PUBKEY=//p')
    A_PRIV[$k]=$(read_peerkey "$adir")
    [[ -n "${A_PEER[$k]}" && -n "${A_BLS[$k]}" && -n "${A_CONS[$k]}" && -n "${A_PRIV[$k]}" ]] \
      || { echo "failed to read archive$k identity"; exit 1; }
    log "  archive$k peer: ${A_PEER[$k]}"
  done

  # --- Assemble committee + genesis prover set. ------------------------------
  # genesisSeed = concat of every archive's 897-byte prover pubkey (hex). A
  # single archive keeps an empty seed (self-elects as sole genesis prover),
  # matching the historical single-archive behaviour.
  local GENESIS_SEED=""
  if (( ARCHIVES > 1 )); then
    for (( k=0; k<ARCHIVES; k++ )); do GENESIS_SEED+="${A_BLS[$k]}"; done
  fi
  local ARCHIVE0_MADDR="/ip4/127.0.0.1/udp/$(node_p2p 0)/quic-v1/p2p/${A_PEER[0]}"

  # --- Pass 2: rewrite each archive with committee + peers, then launch. ------
  : > "$NET_DIR/pids"
  for (( k=0; k<ARCHIVES; k++ )); do
    # Committee arrays (identical order on every node → identical sorted Set).
    COMMITTEE_HEX=(${A_CONS[@]+"${A_CONS[@]}"})
    COMMITTEE_PID=(${A_PEER[@]+"${A_PEER[@]}"})
    # Direct-consensus endpoints = the OTHER archives' :8340 (never self).
    ARCH_ENDPOINTS=()
    local j
    for (( j=0; j<ARCHIVES; j++ )); do
      [[ "$j" == "$k" ]] && continue
      ARCH_ENDPOINTS+=("/ip4/127.0.0.1/tcp/$(node_strm "$j")")
    done
    local seed_k="$GENESIS_SEED"
    local boot_k=""
    [[ "$k" != "0" ]] && boot_k="$ARCHIVE0_MADDR"
    write_archive_config "${A_DIR[$k]}" "$k" "$seed_k" "${A_PRIV[$k]}" "$boot_k"
    log "launching archive${k}…"
    ( cd "$ROOT" && exec "$BIN" --config "${A_DIR[$k]}" "${COMMON_FLAGS[@]}" --archive ) \
      > "$NET_DIR/archive$k.log" 2>&1 &
    echo "$!" >> "$NET_DIR/pids"
    sleep 2
  done

  log "waiting for archive committee genesis…"
  sleep 8

  # --- Regular nodes: join the net, run $CORES worker threads. ---------------
  # Regulars need the same genesis prover set. With one archive that is its BLS
  # pubkey (self-elect equivalent); with a committee it is the concat seed.
  local REG_SEED="$GENESIS_SEED"
  [[ -z "$REG_SEED" ]] && REG_SEED="${A_BLS[0]}"
  local ridx
  # NB: BSD `seq 1 0` prints "1 0" (descending), not nothing — guard on count.
  #
  # Reg pass 1 — identities. App-shard CW members gossip votes among THEMSELVES
  # (shard_cw_bitmask topic); the archive isn't on the shard so it can't relay,
  # and there's no DHT/PeerInfo-dial that connects two regulars on localnet — so
  # each regular would sit at peers:1 (archive only) and every shard-CW publish
  # fails NoPeersSubscribedToTopic. Pre-generate each reg's Falcon network peer-id
  # (via --print-identity, exactly like the archive pass) so we can wire the
  # regulars to each other as explicit directPeers below.
  local -a R_DIR R_PEER R_MADDR
  for (( k=1; k<=REGULARS; k++ )); do
    ridx=$((ARCHIVES + k - 1))
    local rdir; rdir=$(node_dir "reg$k")
    R_DIR[$k]="$rdir"
    write_regular_config "$rdir" "$ridx" "$REG_SEED" "$ARCHIVE0_MADDR" "$CORES" ""
    local rident
    rident=$("$BIN" --config "$rdir" "${COMMON_FLAGS[@]}" --print-identity)
    R_PEER[$k]=$(echo "$rident" | sed -n 's/^PEER_ID=//p')
    R_MADDR[$k]="/ip4/127.0.0.1/udp/$(node_p2p "$ridx")/quic-v1/p2p/${R_PEER[$k]}"
    [[ -n "${R_PEER[$k]}" ]] || { echo "failed to read reg$k identity"; exit 1; }
    log "  reg$k peer: ${R_PEER[$k]}"
  done

  # Reg pass 2 — rewrite each reg with the OTHER regulars as directPeers, launch.
  for (( k=1; k<=REGULARS; k++ )); do
    ridx=$((ARCHIVES + k - 1))
    local rdir="${R_DIR[$k]}"
    local direct_block=""
    local j
    for (( j=1; j<=REGULARS; j++ )); do
      [[ "$j" == "$k" ]] && continue
      direct_block+=$'\n    - "'"${R_MADDR[$j]}"'"'
    done
    write_regular_config "$rdir" "$ridx" "$REG_SEED" "$ARCHIVE0_MADDR" "$CORES" "$direct_block"
    log "launching reg$k (cores=$CORES)…"
    if [[ "$HEAP_PROF" == "1" ]]; then
      ( cd "$ROOT" && exec env "MALLOC_CONF=prof:true,prof_prefix:$rdir/jeprof,lg_prof_interval:30" \
          "$BIN" --config "$rdir" "${COMMON_FLAGS[@]}" ) > "$NET_DIR/reg$k.log" 2>&1 &
    else
      ( cd "$ROOT" && exec "$BIN" --config "$rdir" "${COMMON_FLAGS[@]}" ) \
          > "$NET_DIR/reg$k.log" 2>&1 &
    fi
    echo "$!" >> "$NET_DIR/pids"
    sleep 2
  done

  log "localnet up: $ARCHIVES archive(s) + $REGULARS regular(s). Logs: $NET_DIR/*.log"
  log "  tail:    scripts/localnet.sh logs"
  log "  stop:    scripts/localnet.sh down"
  log "  rewards: scripts/localnet.sh rewards   # QUIL earned per worker (wait a few min first)"
  log "  consensus: grep -E 'simplex|finalized|activated frame' $NET_DIR/archive0.log"
}

cmd_down() {
  [[ -f "$NET_DIR/pids" ]] || { log "no pids file; nothing to stop"; return; }
  while read -r pid; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null && log "killed $pid" || true
  done < "$NET_DIR/pids"
  rm -f "$NET_DIR/pids"
}

# Phase-3 forest cutover: stop the running net, migrate every node's KZG DB into
# the JMT forest in place (--migrate-db), then relaunch from the SAME persisted
# configs — now forest-active (has_forest_data() → true). Flag-day: every node
# must migrate together (a mixed KZG/forest net would fork on state roots).
# Look for "Phase-3 JMT forest installed" in the relaunched logs to confirm.
cmd_migrate() {
  [[ -x "$BIN" ]] || { echo "binary not found at $BIN — run 'up' first"; exit 1; }
  # Snapshot pids BEFORE cmd_down wipes the file, so we can wait for a clean
  # exit — nodes shut down gracefully (up to a ~20s watchdog) and hold the
  # RocksDB LOCK until then; migrating too early fails with "lock file … busy".
  local -a OLD_PIDS=()
  if [[ -f "$NET_DIR/pids" ]]; then
    local _p
    while IFS= read -r _p; do [[ -n "$_p" ]] && OLD_PIDS+=("$_p"); done < "$NET_DIR/pids"
  fi
  cmd_down || true
  log "waiting for nodes to release RocksDB locks (graceful shutdown)…"
  local waited=0 alive
  while (( waited < 40 )); do
    alive=0
    local p
    for p in ${OLD_PIDS[@]+"${OLD_PIDS[@]}"}; do
      [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null && alive=1
    done
    (( alive == 0 )) && break
    sleep 2; waited=$(( waited + 2 ))
  done
  # Belt-and-suspenders: force-kill any survivors, then a final settle.
  for p in ${OLD_PIDS[@]+"${OLD_PIDS[@]}"}; do
    [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
  done
  sleep 2

  local d
  for d in "$NET_DIR"/archive* "$NET_DIR"/reg*; do
    [[ -d "$d" && -d "$d/store" ]] || continue
    log "migrating $(basename "$d") KZG → JMT forest (in place)…"
    if ! ( cd "$ROOT" && "$BIN" --config "$d" "${COMMON_FLAGS[@]}" --migrate-db "$d/store" ) \
        >> "$d.migrate.log" 2>&1; then
      echo "migration FAILED for $d — see $d.migrate.log"; exit 1
    fi
  done

  log "relaunching forest-active net from persisted configs…"
  : > "$NET_DIR/pids"
  for d in "$NET_DIR"/archive*; do
    [[ -d "$d" ]] || continue
    ( cd "$ROOT" && exec "$BIN" --config "$d" "${COMMON_FLAGS[@]}" --archive ) \
      >> "$d.log" 2>&1 &
    echo "$!" >> "$NET_DIR/pids"
    log "  relaunched $(basename "$d") (archive)"
    sleep 2
  done
  for d in "$NET_DIR"/reg*; do
    [[ -d "$d" ]] || continue
    ( cd "$ROOT" && exec "$BIN" --config "$d" "${COMMON_FLAGS[@]}" ) \
      >> "$d.log" 2>&1 &
    echo "$!" >> "$NET_DIR/pids"
    log "  relaunched $(basename "$d") (regular)"
    sleep 2
  done
  log "forest-active net up. Confirm: grep 'Phase-3 JMT forest installed' $NET_DIR/*.log"
}

cmd_logs() {
  tail -n +1 -F "$NET_DIR"/*.log
}

# Demonstrate that the data-worker provers are earning QUIL. Each regular node's
# prover accrues rewards on-chain as its app-shard produces finalized frames
# (coverage is published on GLOBAL_PROVER, the archive materializes the
# ProverShardUpdate → apply_reward, and the reg observes the credited balance via
# the incremental prover-tree sync, logging `reward balance updated by sync`).
# We report the PEAK balance each worker has seen: the synced balance can jitter
# down transiently (the versionless-blob sync race) and can legitimately reset to
# 0 on a reward mint, so the running max is the robust "amount earned" signal.
# QUIL_TOKEN_UNITS = 8_000_000_000 sub-units per QUIL.
cmd_rewards() {
  local units=8000000000
  log "worker QUIL rewards (peak on-chain reward balance per data-worker):"
  local earned_all=1 saw_any=0
  local f name peak quil updates
  for f in "$NET_DIR"/reg*.log; do
    [ -f "$f" ] || continue
    saw_any=1
    name=$(basename "$f" .log)
    peak=$(grep 'reward balance updated by sync' "$f" 2>/dev/null \
      | grep -oE '"new_balance":"[0-9]+"' | grep -oE '[0-9]+' | sort -n | tail -1)
    peak=${peak:-0}
    updates=$(grep -c 'reward balance updated by sync' "$f" 2>/dev/null || echo 0)
    quil=$(awk -v p="$peak" -v u="$units" 'BEGIN{ printf "%.4f", p/u }')
    if [ "$peak" -gt 0 ] 2>/dev/null; then
      log "  ✓ $name: $quil QUIL  ($peak sub-units, over $updates reward-sync events)"
    else
      log "  ✗ $name: 0 QUIL earned yet"
      earned_all=0
    fi
  done
  if [ "$saw_any" -eq 0 ]; then
    log "no regular-node logs in $NET_DIR — run 'scripts/localnet.sh up' first"
    exit 1
  fi
  if [ "$earned_all" -eq 1 ]; then
    log "✓ all workers are earning QUIL rewards"
  else
    log "⚠ not all workers have earned yet — the app-shard needs time to activate,"
    log "  finalize frames, and have coverage rewarded. Wait a few minutes and re-run:"
    log "    scripts/localnet.sh rewards"
    exit 1
  fi
}

cmd_clean() {
  cmd_down || true
  rm -rf "$NET_DIR"
  log "wiped $NET_DIR"
}

case "${1:-up}" in
  up)      cmd_up ;;
  down)    cmd_down ;;
  migrate) cmd_migrate ;;
  logs)    cmd_logs ;;
  rewards) cmd_rewards ;;
  clean)   cmd_clean ;;
  *) echo "usage: $0 {up|down|migrate|logs|rewards|clean}"; exit 1 ;;
esac
