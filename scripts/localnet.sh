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
#   scripts/localnet.sh run       # launch and keep this foreground session alive
#   scripts/localnet.sh resume    # run stopped nodes from their existing configs
#   scripts/localnet.sh runtime   # show the effective, non-secret runtime knobs
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
#   NET_DIR=path      isolated directory for this test network
#   SKIP_BUILD=1      use binaries already built from the intended source tree
#   NETWORK=1         network id (1 = primary testnet; non-0, non-99)
#   HEAP_PROF=1       run regulars under MALLOC_CONF heap profiling
#   SPLIT_MAX_PROVERS=N  DEV: induce shard splits — a shard with >N Active provers
#                     proposes a split (flips at epoch E+2). Pair with enough
#                     REGULARS, e.g. `REGULARS=6 SPLIT_MAX_PROVERS=3`.
#   SPLIT_ROOT_ONLY=1  DEV: propose one split of each whole app, then keep its children
#   CLUSTER_REGULARS=N the first N regulars run in cluster mode: their CORES
#                     workers are separate `--core` processes the master reaches
#                     through engine.dataWorkerStreamMultiaddrs (logs regK-wC.log)
#   PORT_OFFSET=0     added to every port `up` writes, so a second fixture can
#                     run beside one on the default ports
#   GEN0_MIGRATE=1    with `resume`: activate committee handoff on a legacy
#                     fixture (saved QUIL_COMMITTEE_HANDOFF_FRAME empty) at the
#                     QUIL_COMMITTEE_HANDOFF_FRAME given; its legacy shards
#                     migrate in place through generation zero
#   TARGET_DIR=path   cargo target directory holding the binaries (default
#                     <repo>/target), so a fixture can run a build other than
#                     the one another running fixture uses; pass it on `resume` too
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET_DIR="${NET_DIR:-$ROOT/.localnet}"
ARCHIVES="${ARCHIVES:-1}"
REGULARS="${REGULARS:-3}"
CORES="${CORES:-3}"
CLUSTER_REGULARS="${CLUSTER_REGULARS:-0}"
PORT_OFFSET="${PORT_OFFSET:-0}"
[[ "$PORT_OFFSET" =~ ^[0-9]+$ ]] || { echo "PORT_OFFSET must be a number" >&2; exit 1; }
# Worker stream port of cluster worker `core` (1-based) of node index `idx`.
cluster_worker_port() { echo $(( 33000 + PORT_OFFSET + $1 * 16 + $2 )); }
PROFILE="${PROFILE:-release}"
HEAP_PROF="${HEAP_PROF:-0}"

# Consensus-affecting test settings live in the launcher environment, not the
# node YAML. Save them with the fixture so a resume cannot silently switch
# epoch length or undo its unified-tree cutover. Only numeric, named settings
# are accepted; never source a file as shell code. Explicit caller overrides
# take precedence (e.g. MIN_PROVERS to exercise a merge).
RUNTIME_KEYS=(QUIL_EPOCH_LENGTH_FRAMES QUIL_PROVER_TREE_SYNC_SECS
  QUIL_COMMITTEE_HANDOFF_FRAME
  QUIL_SPLIT_MAX_PROVERS QUIL_SPLIT_ROOT_ONLY QUIL_MIN_PROVERS
  QUIL_UNIFIED_TREE_CUTOVER_FRAME QUIL_GRID_RESET_V2_FRAME
  QUIL_PROVER_RESET_V3_FRAME QUIL_PROVER_RESET_V4_FRAME QUIL_PROVER_RESET_V5_FRAME
  QUIL_ORPHAN_REPLACE_FRAME)
runtime_key_known() {
  [[ "$1" == NETWORK ]] && return 0
  local key
  for key in "${RUNTIME_KEYS[@]}"; do [[ "$1" == "$key" ]] && return 0; done
  return 1
}
load_runtime_settings() {
  local key value caller_value seen=" "
  while IFS='=' read -r key value; do
    runtime_key_known "$key" && [[ -z "$value" || "$value" =~ ^[0-9]+$ ]] \
      || { echo "invalid setting in $NET_DIR/runtime.env: $key" >&2; return 1; }
    [[ "$seen" != *" $key "* ]] \
      || { echo "duplicate runtime setting: $key" >&2; return 1; }
    seen+="$key "
    # A first session assumes empty genesis. Changing this setting on an
    # existing fixture cannot migrate its legacy history or consensus journals,
    # except the one audited migration: a legacy fixture (no activation saved)
    # activating with GEN0_MIGRATE=1, whose shards move through generation 0.
    if [[ "$key" == QUIL_COMMITTEE_HANDOFF_FRAME ]] \
      && caller_value=$(printenv "$key") && [[ "$caller_value" != "$value" ]]; then
      if [[ "${GEN0_MIGRATE:-0}" == 1 && -z "$value" && "$caller_value" =~ ^[0-9]+$ ]]; then
        echo "activating committee handoff at frame $caller_value: legacy shards migrate through generation zero" >&2
      else
        echo "committee handoff activation cannot change on an existing fixture; use a fresh network or GEN0_MIGRATE=1 on a legacy fixture" >&2
        return 1
      fi
    fi
    if [[ "$key" == NETWORK ]]; then
      [[ -n "$value" ]] || { echo "missing network in runtime.env" >&2; return 1; }
      NETWORK="${NETWORK:-$value}"
    elif ! printenv "$key" >/dev/null; then
      [[ -z "$value" ]] || export "$key=$value"
    fi
  done < "$NET_DIR/runtime.env"
  for key in NETWORK "${RUNTIME_KEYS[@]}"; do
    [[ "$seen" == *" $key "* ]] \
      || { echo "incomplete runtime.env: missing $key" >&2; return 1; }
  done
}
case "${1:-up}" in
  resume|migrate)
    [[ -f "$NET_DIR/runtime.env" ]] || {
      echo "no saved runtime.env; recover the fixture's original launch settings before resuming" >&2
      exit 1
    }
    load_runtime_settings ;;
  runtime) [[ ! -f "$NET_DIR/runtime.env" ]] || load_runtime_settings ;;
esac
NETWORK="${NETWORK:-1}"
# Proof verifier worker per node: on a single machine six nodes must share the
# cores, so default to one verification at a time with two native threads.
PROOF_MAX_CONCURRENT="${PROOF_MAX_CONCURRENT:-1}"
PROOF_NATIVE_THREADS="${PROOF_NATIVE_THREADS:-2}"
PROOF_VERIFY_BUDGET_SECS="${PROOF_VERIFY_BUDGET_SECS:-6}"
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

# DEV: induce shard splits for testing. Lowers the split-rebalance trigger's
# max-provers threshold (mainnet=32, never tripped by a handful of localnet
# provers) so any shard with MORE Active provers than this proposes a split
# (→ ShardSplitEligible → orchestrator op → PendingShardChange → epoch-aligned
# flip at E+2). Use enough REGULARS that post-split children stay above the halt
# floor — e.g. `REGULARS=6 SPLIT_MAX_PROVERS=3` splits the QUIL shard 2-way with
# ~3 provers per child. Only honored when set; mainnet is never affected.
if [[ -n "${SPLIT_MAX_PROVERS:-}" ]]; then
  export QUIL_SPLIT_MAX_PROVERS="$SPLIT_MAX_PROVERS"
fi
if [[ -n "${SPLIT_ROOT_ONLY:-}" ]]; then
  export QUIL_SPLIT_ROOT_ONLY="$SPLIT_ROOT_ONLY"
fi
# DEV: lower the MERGE trigger's min_provers. The mainnet default (6) is above
# any localnet's prover count, so a freshly split shard merges straight back —
# and a restart makes every shard look starved while allocations re-activate.
# `MIN_PROVERS=0` makes the merge trigger unreachable, which is what lets a
# localnet HOLD a split topology (pair with SPLIT_MAX_PROVERS above the prover
# count once the wanted depth exists).
if [[ -n "${MIN_PROVERS:-}" ]]; then
  export QUIL_MIN_PROVERS="$MIN_PROVERS"
fi

# NOTE: the old SPLIT_MAX_DATA / QUIL_SPLIT_MAX_DATA data-count trigger was
# removed — a shard splits on prover-count (SPLIT_MAX_PROVERS) AND divisibility.
# To force a localnet split, lower SPLIT_MAX_PROVERS below the covered count.

# DEV: unified-app-tree cutover frame. Localnet starts at frame 0, so mainnet's
# 695500 is never reached; set a LOW frame to exercise the state-commitment
# switch — split apps fold into their single app tree + the commitment forks
# (JMT root vs the legacy hash_pair rollup). Every node MUST use the SAME value
# (deterministic or fork). Only honored when set; mainnet never sets it.
if [[ -n "${UNIFIED_TREE_CUTOVER_FRAME:-}" ]]; then
  export QUIL_UNIFIED_TREE_CUTOVER_FRAME="$UNIFIED_TREE_CUTOVER_FRAME"
fi
# Second coordinated grid reset (grid-reset v2). Same discipline: every node MUST
# use the same value; mainnet defaults to 740_000 and never sets this.
if [[ -n "${GRID_RESET_V2_FRAME:-}" ]]; then
  export QUIL_GRID_RESET_V2_FRAME="$GRID_RESET_V2_FRAME"
fi
# Prover-tree RESET v3 (complete wipe+reseed + auto-worker filter reset, so
# re-join lands on the clean genesis grid). Same discipline: every node MUST use
# the same value; mainnet defaults to 747_000 and never sets this.
if [[ -n "${PROVER_RESET_V3_FRAME:-}" ]]; then
  export QUIL_PROVER_RESET_V3_FRAME="$PROVER_RESET_V3_FRAME"
fi
# Prover-tree RESET v4 (re-baseline after the boot grid-clobber removal). Same
# discipline; mainnet defaults to 755_000 and never sets this.
if [[ -n "${PROVER_RESET_V4_FRAME:-}" ]]; then
  export QUIL_PROVER_RESET_V4_FRAME="$PROVER_RESET_V4_FRAME"
fi

# Prover-tree RESET v5 (759_000 mainnet): clears the byte-suffix allocations the
# old-binary fleet re-joined with post-v4 + re-baselines to sentinel (all seeders
# are sentinel now). Same discipline; DEV: lower to exercise it.
if [[ -n "${PROVER_RESET_V5_FRAME:-}" ]]; then
  export QUIL_PROVER_RESET_V5_FRAME="$PROVER_RESET_V5_FRAME"
fi
# Re-placing coin outputs a split left without a block owner (consensus for
# GLOBAL and every shard's report). Off unless set; every node MUST use the
# same value. The mainnet frame is an owner decision.
if [[ -n "${ORPHAN_REPLACE_FRAME:-}" ]]; then
  export QUIL_ORPHAN_REPLACE_FRAME="$ORPHAN_REPLACE_FRAME"
fi

# Per-node port base; node K gets base + K*10 for each service. Archives use
# indices 0..ARCHIVES-1; regulars continue from ARCHIVES.
P2P_BASE=$((8336 + PORT_OFFSET))    # /udp QUIC
STREAM_BASE=$((8340 + PORT_OFFSET)) # /tcp :8340 (peer mTLS + worker cluster + direct consensus)
GRPC_BASE=$((8337 + PORT_OFFSET))
REST_BASE=$((8338 + PORT_OFFSET))

TARGET_DIR="${TARGET_DIR:-$ROOT/target}"
if [[ "$PROFILE" == "release" ]]; then
  BIN="$TARGET_DIR/release/quil-node"
  CARGO_FLAGS="--release"
else
  BIN="$TARGET_DIR/debug/quil-node"
  CARGO_FLAGS=""
fi

# Common flags. Source builds aren't signed, so signature check is off.
COMMON_FLAGS=(--network "$NETWORK" --signature-check=false)
if [ -n "${LOGFILTER:-}" ]; then COMMON_FLAGS+=(--log-filter "$LOGFILTER"); fi

log() { printf '\033[1;34m[localnet]\033[0m %s\n' "$*"; }

show_runtime_settings() {
  local key value
  printf 'NETWORK=%s\n' "$NETWORK"
  for key in "${RUNTIME_KEYS[@]}"; do
    value=$(printenv "$key") || value=""
    [[ -z "$value" || "$value" =~ ^[0-9]+$ ]] \
      || { echo "invalid numeric runtime setting: $key" >&2; return 1; }
    printf '%s=%s\n' "$key" "$value"
  done
}
save_runtime_settings() {
  local tmp="$NET_DIR/runtime.env.tmp.$$"
  show_runtime_settings > "$tmp"
  mv "$tmp" "$NET_DIR/runtime.env"
}

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
proofWorker:
  maxConcurrent: $PROOF_MAX_CONCURRENT
  nativeThreads: $PROOF_NATIVE_THREADS
  verifyBudgetSecs: $PROOF_VERIFY_BUDGET_SECS
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
  local p2p strm grpc rest boot_block="" peerkey=""
  # --print-identity persists this seed during pass 1. Retain it when adding
  # direct peers in pass 2 so cluster workers can start before the master.
  [[ ! -f "$dir/config.yml" ]] || peerkey=$(read_peerkey "$dir")
  p2p=$(node_p2p "$idx"); strm=$(node_strm "$idx")
  grpc=$(node_grpc "$idx"); rest=$(node_rest "$idx")
  if [[ -n "$bootstrap" ]]; then boot_block=$'\n    - "'"$bootstrap"'"'; fi
  # The archive pool is seeded ONLY from engine.archiveEndpoints (or mainnet's
  # hardcoded genesis IPs) — nothing populates it from PeerInfo gossip, despite
  # the comment in master_node/mod.rs saying so. Leaving it empty on a regular
  # makes every archive-pool consumer resolve an EMPTY endpoint and silently
  # no-op: the app-shard catch-up sync, a new split child's inherited-subtree
  # bootstrap, and delivery source-frame fetches all fail, so shards stall
  # after a split with `addr:""` in the syncer log.
  local archive_endpoints_yaml=""
  local ep
  for ep in ${ARCH_ENDPOINTS[@]+"${ARCH_ENDPOINTS[@]}"}; do
    archive_endpoints_yaml+=$'\n    - "'"$ep"'"'
  done
  [[ -z "$archive_endpoints_yaml" ]] && archive_endpoints_yaml=" []"
  # Cluster mode: one stream multiaddr per worker process.
  local cluster_yaml="" c
  if (( idx - ARCHIVES + 1 <= CLUSTER_REGULARS )); then
    for (( c=1; c<=workers; c++ )); do
      cluster_yaml+=$'\n    - "/ip4/127.0.0.1/tcp/'"$(cluster_worker_port "$idx" "$c")"'"'
    done
  fi
  [[ -z "$cluster_yaml" ]] && cluster_yaml=" []"
  # Mirror mainnet: a non-archive node knows the global committee (on mainnet it
  # loads the genesis archive_peers). Regulars need it to VERIFY the CW
  # finalization cert carried by GLOBAL_FRAME gossip frames — without it the
  # validator can't detect the cert, falls back to the legacy BLS path, and
  # rejects every gossiped frame as "BLS signature INVALID". COMMITTEE_HEX /
  # COMMITTEE_PID are set in the archive pass (identical on every node).
  local committee_yaml=" []" committee_pid_yaml=" []" _c
  if (( ${#COMMITTEE_HEX[@]:-0} > 0 )); then
    committee_yaml=""
    for _c in "${COMMITTEE_HEX[@]}"; do committee_yaml+=$'\n    - "'"$_c"'"'; done
  fi
  if (( ${#COMMITTEE_PID[@]:-0} > 0 )); then
    committee_pid_yaml=""
    for _c in "${COMMITTEE_PID[@]}"; do committee_pid_yaml+=$'\n    - "'"$_c"'"'; done
  fi
  cat > "$dir/config.yml" <<YAML
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
  minBootstrapPeers: 1
  bootstrapPeers:$boot_block
  directPeers:$( [[ -n "$direct_block" ]] && echo "$direct_block" || echo " []" )
engine:
  archiveMode: false
  genesisSeed: "$seed"
  dataWorkerCount: $workers
  dataWorkerStreamMultiaddrs:$cluster_yaml
  appConsensusCw: $APP_CW_BOOL
  archiveEndpoints:$archive_endpoints_yaml
  consensusCommittee:$committee_yaml
  consensusCommitteePeerIds:$committee_pid_yaml
proofWorker:
  maxConcurrent: $PROOF_MAX_CONCURRENT
  nativeThreads: $PROOF_NATIVE_THREADS
  verifyBudgetSecs: $PROOF_VERIFY_BUDGET_SECS
db:
  path: "$dir/store"
listenGrpcMultiaddr: "/ip4/127.0.0.1/tcp/$grpc"
listenRESTMultiaddr: "/ip4/127.0.0.1/tcp/$rest"
YAML
}

# Both the launcher's indented sequence and serde_yaml's indentless sequence
# represent the same list. The master persists the latter when saving config.
cluster_worker_count() {
  awk '/^[[:space:]]*dataWorkerStreamMultiaddrs:/{f=1;next} f&&/^[[:space:]]*-[[:space:]]/{n++;next} f{exit} END{print n+0}' "$1/config.yml"
}

# Nodes launched by this invocation. Its exit trap stops only these, so an
# earlier run's exit cannot stop (or unlist) a fixture resumed after it.
OWN_PIDS=()
record_pid() {
  OWN_PIDS+=("$1")
  echo "$1" >> "$NET_DIR/pids"
}

# Stop the given nodes and wait for them to exit: a node holds its RocksDB LOCK
# through graceful shutdown (up to its ~20s watchdog), so a resume started
# before then fails with "lock file … Resource temporarily unavailable".
stop_nodes() {
  local pid waited=0 alive
  for pid in "$@"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null && log "killed $pid" || true
  done
  while (( waited < 40 )); do
    alive=0
    for pid in "$@"; do
      [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && alive=1
    done
    (( alive == 0 )) && return
    sleep 2; waited=$(( waited + 2 ))
  done
  for pid in "$@"; do
    [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null && log "force-killed $pid" || true
  done
}

stop_own_nodes() {
  stop_nodes ${OWN_PIDS[@]+"${OWN_PIDS[@]}"}
  # Remove the pids file only while it is still this invocation's.
  local first=""
  [[ -f "$NET_DIR/pids" ]] && read -r first < "$NET_DIR/pids"
  local pid
  for pid in ${OWN_PIDS[@]+"${OWN_PIDS[@]}"}; do
    [[ "$pid" == "$first" ]] && { rm -f "$NET_DIR/pids"; return; }
  done
}

# Start the worker processes of a cluster-mode node (no-op otherwise).
launch_cluster_workers() {
  local dir="$1" name="$2" master_pid="$3" c count
  count=$(cluster_worker_count "$dir")
  for (( c=1; c<=count; c++ )); do
    log "launching $name worker $c (cluster mode)…"
    ( cd "$ROOT" && exec "$BIN" --config "$dir" "${COMMON_FLAGS[@]}" --core "$c" --parent-process "$master_pid" ) \
        >> "$NET_DIR/$name-w$c.log" 2>&1 &
    record_pid "$!"
  done
}

require_new_network() {
  if compgen -G "$NET_DIR/archive*/config.yml" >/dev/null || compgen -G "$NET_DIR/reg*/config.yml" >/dev/null; then
    echo "existing node configs in $NET_DIR; use 'resume' to preserve identities and state" >&2
    return 1
  fi
}

cmd_up() {
  require_new_network
  if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    log "building quil-node ($PROFILE)…"
    ( cd "$ROOT" && FLINT_DIR="${FLINT_DIR:-/Users/caheart/src/flint}" CARGO_TARGET_DIR="$TARGET_DIR" \
        QUILIBRIUM_SIGNATURE_CHECK=false cargo build --locked $CARGO_FLAGS -p quil-node )
    log "building quil-amount-proof-worker ($PROFILE)…"
    ( cd "$ROOT" && FLINT_DIR="${FLINT_DIR:-/Users/caheart/src/flint}" CARGO_TARGET_DIR="$TARGET_DIR" \
        cargo build --locked $CARGO_FLAGS -p quil-lattice-ct --features native-proof --bin quil-amount-proof-worker )
  fi
  [[ -x "$BIN" ]] || { echo "binary not found at $BIN"; exit 1; }
  # Token proof verifier worker: the node resolves it as the sibling of
  # its own executable, and cargo places both in the same target directory.
  [[ -x "$(dirname "$BIN")/quil-amount-proof-worker" ]] || { echo "worker not found beside $BIN"; exit 1; }

  mkdir -p "$NET_DIR"
  save_runtime_settings
  log "saved runtime settings (applies to every node):"
  show_runtime_settings

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
  # genesisSeed = concat of every archive's 897-byte prover pubkey (hex), for a
  # single archive too. An empty seed makes each node elect its OWN key as the
  # genesis prover: the boot cutover reset then rebuilds the prover tree from
  # an empty key (it fails, "empty message", and GLOBAL never leaves frame 0)
  # and regulars would disagree with the archive about the committee.
  local GENESIS_SEED=""
  for (( k=0; k<ARCHIVES; k++ )); do GENESIS_SEED+="${A_BLS[$k]}"; done
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
    record_pid "$!"
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
    elif [[ "$k" == "1" && -n "${REG1_DROP_FRAME:-}" ]]; then
      # DEV: force ONLY reg1 to drop a range of app-frames on receipt so it falls
      # behind while the majority keeps producing — exercises the step-4 catch-up
      # sync (AncestorSyncRequested) recovery path.
      ( cd "$ROOT" && exec env "QUIL_APP_SYNC_DROP_FRAME=$REG1_DROP_FRAME" \
          "$BIN" --config "$rdir" "${COMMON_FLAGS[@]}" ) > "$NET_DIR/reg$k.log" 2>&1 &
    else
      ( cd "$ROOT" && exec "$BIN" --config "$rdir" "${COMMON_FLAGS[@]}" ) \
          > "$NET_DIR/reg$k.log" 2>&1 &
    fi
    local master_pid=$!
    record_pid "$master_pid"
    launch_cluster_workers "$rdir" "reg$k" "$master_pid"
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
  local -a pids=()
  local pid
  while read -r pid; do [[ -n "$pid" ]] && pids+=("$pid"); done < "$NET_DIR/pids"
  stop_nodes ${pids[@]+"${pids[@]}"}
  rm -f "$NET_DIR/pids"
}

# Managed command runners may reap background descendants when the launching
# session ends. Keep their parent alive for the lifetime of the fixture.
cmd_run() {
  require_new_network || return 1
  trap 'stop_own_nodes' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  cmd_up
  wait
}

# Resume a stopped fixture without regenerating identities, changing configs,
# or truncating its logs. Supply the same consensus/cutover environment as the
# original launch; proposal-only split controls may be changed for a test.
cmd_resume() {
  [[ -x "$BIN" && -x "$(dirname "$BIN")/quil-amount-proof-worker" ]] \
    || { echo "node and proof worker binaries are required" >&2; return 1; }
  [[ -f "$NET_DIR/archive0/config.yml" ]] \
    || { echo "no existing archive config in $NET_DIR" >&2; return 1; }
  if [[ -f "$NET_DIR/pids" ]]; then
    local pid
    while read -r pid; do
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "node $pid is still running; stop the fixture and wait for it to exit before resuming" >&2
        return 1
      fi
    done < "$NET_DIR/pids"
  fi
  trap 'stop_own_nodes' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  save_runtime_settings
  : > "$NET_DIR/pids"
  local d
  for d in "$NET_DIR"/archive* "$NET_DIR"/reg*; do
    [[ -d "$d" && -f "$d/config.yml" ]] || continue
    local flags=()
    [[ "$(basename "$d")" == archive* ]] && flags+=(--archive)
    log "resuming $(basename "$d") from persisted config"
    ( cd "$ROOT" && exec "$BIN" --config "$d" "${COMMON_FLAGS[@]}" ${flags[@]+"${flags[@]}"} ) \
      >> "$d.log" 2>&1 &
    local master_pid=$!
    record_pid "$master_pid"
    launch_cluster_workers "$d" "$(basename "$d")" "$master_pid"
    sleep 2
  done
  wait
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
  run)     cmd_run ;;
  resume)  cmd_resume ;;
  runtime) show_runtime_settings ;;
  down)    cmd_down ;;
  migrate) cmd_migrate ;;
  logs)    cmd_logs ;;
  rewards) cmd_rewards ;;
  clean)   cmd_clean ;;
  *) echo "usage: $0 {up|run|resume|runtime|down|migrate|logs|rewards|clean}"; exit 1 ;;
esac
