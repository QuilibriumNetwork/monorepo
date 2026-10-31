#!/usr/bin/env bash
#
# devnet-smoke.sh — archive restart smoke test on a localhost devnet.
#
# Starts 4 archives (the GLOBAL committee) and 1 regular node with workers
# through scripts/localnet.sh, then restarts the archives the way an operator
# upgrade does and checks, per node, that the network comes back:
#
#   all          stop every archive (and the regular node), then start them
#   stagger      restart the archives one at a time, 20 s apart
#   <mode>+delay the same, with the first prover registry load of every
#                restarted node delayed by DELAY_MS (needs a node built with
#                `--features test-hooks`), to model a slow store
#
# After each round it asserts:
#   - every archive logs "global consensus activated" and none logs
#     "skipping global consensus activation";
#   - every archive proposes at least one GLOBAL frame in its leader turns
#     ("proposed GLOBAL frame as leader") within PROPOSAL_BOUND seconds;
#   - GLOBAL frames advance again within GLOBAL_BOUND seconds;
#   - the regular node is running and clears no orphaned worker filter
#     ("orphaned filter with no pending frame").
# At the end the regular node must have bound a worker to a shard filter at
# least once ("worker filter pinned" or "worker assigned to shard").
# Exit status is non-zero, with a summary of the failed checks, otherwise 0.
#
# Environment:
#   TARGET_DIR   cargo target directory with <PROFILE>/quil-node and
#                <PROFILE>/quil-amount-proof-worker (default <repo>/target)
#   PROFILE      cargo profile directory (default devnet)
#   NET_DIR      scratch directory of the devnet (default <repo>/.devnet-smoke);
#                must not hold an earlier devnet
#   ROUNDS       space separated rounds (default "all stagger all+delay stagger+delay")
#   DELAY_MS     registry load delay of the +delay rounds (default 15000)
#   GLOBAL_BOUND, PROPOSAL_BOUND, ACTIVATION_BOUND, SETTLE, STOP_GRACE   seconds
#   NETWORK, LOGFILTER, APP_CW, CLUSTER_REGULARS and the other settings of
#                scripts/localnet.sh: `localnet.sh up` reads them, and every
#                restart runs with the same ones
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-$ROOT/target}"
PROFILE="${PROFILE:-devnet}"
NET_DIR="${NET_DIR:-$ROOT/.devnet-smoke}"
ROUNDS="${ROUNDS:-all stagger all+delay stagger+delay}"
DELAY_MS="${DELAY_MS:-15000}"
GLOBAL_BOUND="${GLOBAL_BOUND:-240}"
PROPOSAL_BOUND="${PROPOSAL_BOUND:-240}"
ACTIVATION_BOUND="${ACTIVATION_BOUND:-$(( DELAY_MS / 1000 + 90 ))}"
SETTLE="${SETTLE:-30}"
# A node shuts down gracefully within its ~20 s watchdog; then kill -9.
STOP_GRACE="${STOP_GRACE:-60}"
CLUSTER_REGULARS="${CLUSTER_REGULARS:-0}"
ARCHIVES=4
BIN="$TARGET_DIR/$PROFILE/quil-node"
OUT="$NET_DIR/results"
GLOBAL_RE='GLOBAL frame published atomically'
FRAME_RE='"frame":[0-9]+'
LEADER_RE='proposed GLOBAL frame as leader'
ORPHAN_RE='orphaned filter with no pending frame'

[[ -x "$BIN" && -x "$TARGET_DIR/$PROFILE/quil-amount-proof-worker" ]] \
  || { echo "build quil-node and quil-amount-proof-worker with profile $PROFILE into $TARGET_DIR first" >&2; exit 2; }
[[ ! -e "$NET_DIR" ]] || { echo "$NET_DIR exists; remove it or set NET_DIR" >&2; exit 2; }
mkdir -p "$OUT"

now() { date -u +%FT%TZ; }
log() { printf '[%s] %s\n' "$(now)" "$*" | tee -a "$OUT/run.log"; }
alog() { echo "$NET_DIR/archive$1/.log/master.log"; }
FAILS=()
fail() { FAILS+=("$1"); log "FAIL: $1"; }

# Highest GLOBAL frame any archive published.
gmax() {
  cat "$NET_DIR"/archive*/.log/master.log 2>/dev/null | grep -a "$GLOBAL_RE" \
    | grep -aoE "$FRAME_RE" | grep -aoE '[0-9]+' | sort -n | tail -1
}
# Lines of archive $1's master log after offset $2 matching regex $3.
since() { tail -n +"$(( $2 + 1 ))" "$(alog "$1")" | grep -aE "$3"; }
lines() { wc -l < "$(alog "$1")"; }
regcount() { cat "$NET_DIR"/reg1/.log/*.log 2>/dev/null | grep -ac "$1"; }

# Restarts reuse the settings `localnet.sh up` saved in runtime.env (the
# network id and the consensus settings, including those APP_CW=1 exports),
# its log filter, and its cluster-mode worker processes.
COMMON=()
load_launch_settings() {
  local key value
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^(NETWORK|QUIL_[A-Z0-9_]+)$ && "$value" =~ ^[0-9]*$ ]] \
      || { echo "unexpected setting in $NET_DIR/runtime.env: $key" >&2; return 1; }
    if [[ "$key" == NETWORK ]]; then NETWORK=$value
    elif [[ -n "$value" ]]; then export "$key=$value"; fi
  done < "$NET_DIR/runtime.env"
  COMMON=(--network "$NETWORK" --signature-check=false)
  [[ -z "${LOGFILTER:-}" ]] || COMMON+=(--log-filter "$LOGFILTER")
}
# Worker processes of a cluster-mode node, counted as localnet.sh does.
cluster_workers() {
  awk '/^[[:space:]]*dataWorkerStreamMultiaddrs:/{f=1;next} f&&/^[[:space:]]*-[[:space:]]/{n++;next} f{exit} END{print n+0}' \
    "$NET_DIR/$1/config.yml"
}
start_node() { # dir-name [--archive] ; delay applies when DELAY_NOW is set
  local name=$1 master c workers; shift
  workers=$(cluster_workers "$name")
  ( cd "$ROOT" && exec env ${DELAY_NOW:+QUIL_TEST_REGISTRY_LOAD_DELAY_MS=$DELAY_NOW} \
      "$BIN" --config "$NET_DIR/$name" "${COMMON[@]}" "$@" ) >> "$NET_DIR/$name.log" 2>&1 &
  master=$!
  for (( c=1; c<=workers; c++ )); do
    ( cd "$ROOT" && exec "$BIN" --config "$NET_DIR/$name" "${COMMON[@]}" --core "$c" --parent-process "$master" ) \
      >> "$NET_DIR/$name-w$c.log" 2>&1 &
  done
}
# Every process of node $1: its master and any cluster workers.
node_pids() { pgrep -f -- "--config $NET_DIR/$1 "; }
STOPPED_PIDS=""
stop_node() {
  STOPPED_PIDS="$STOPPED_PIDS $(node_pids "$1" | tr '\n' ' ')"
  pkill -f -- "--config $NET_DIR/$1 " 2>/dev/null; return 0
}
# A stopped process holds its store's lock until it is gone or a zombie: the
# command line pgrep matches disappears earlier, while the kernel tears down
# its memory and its files are still open, and a node restarted then finds
# its store locked and stays down.
exiting() {
  local p s
  for p in $STOPPED_PIDS; do
    s=$(ps -o stat= -p "$p" 2>/dev/null)
    [[ -n "$s" && "$s" != Z* ]] && return 0
  done
  return 1
}
wait_gone() { # names...
  local n i alive
  for (( i=0; i<STOP_GRACE; i+=2 )); do
    alive=0; exiting && alive=1
    for n in "$@"; do [[ -n "$(node_pids "$n")" ]] && alive=1; done
    (( alive == 0 )) && { STOPPED_PIDS=""; return 0; }; sleep 2
  done
  for n in "$@"; do
    [[ -n "$(node_pids "$n")" ]] || continue
    log "$n did not stop within ${STOP_GRACE}s; killing it"
    pkill -9 -f -- "--config $NET_DIR/$n " 2>/dev/null
  done
  # shellcheck disable=SC2086 # one PID per word
  exiting && kill -9 $STOPPED_PIDS 2>/dev/null
  STOPPED_PIDS=""
  sleep 2
}

cleanup() {
  local i
  kill "${UPPID:-0}" 2>/dev/null
  pkill -f -- "--config $NET_DIR/" 2>/dev/null
  for (( i=0; i<STOP_GRACE; i+=2 )); do
    pgrep -f -- "--config $NET_DIR/" > /dev/null || return 0
    sleep 2
  done
  pkill -9 -f -- "--config $NET_DIR/" 2>/dev/null
  sleep 2
}
trap cleanup EXIT

log "starting the devnet: $ARCHIVES archives + 1 regular node (2 workers), binary $BIN"
NET_DIR="$NET_DIR" TARGET_DIR="$TARGET_DIR" PROFILE="$PROFILE" SKIP_BUILD=1 \
  ARCHIVES=$ARCHIVES REGULARS=1 CORES=2 CLUSTER_REGULARS="$CLUSTER_REGULARS" \
  bash "$ROOT/scripts/localnet.sh" up > "$OUT/up.log" 2>&1 &
UPPID=$!
# `up` launches the nodes and exits; stop at once if it fails.
up_rc=""
up_status() {
  wait "$UPPID"; up_rc=$?
  (( up_rc == 0 )) && return 0
  log "scripts/localnet.sh up failed (exit $up_rc); the end of $OUT/up.log:"
  tail -n 20 "$OUT/up.log" | tee -a "$OUT/run.log"
  exit 1
}
for (( i=0; i<600; i+=2 )); do
  [[ -z "$up_rc" ]] && ! kill -0 "$UPPID" 2>/dev/null && up_status
  [[ -n "$(gmax)" ]] && break; sleep 2
done
[[ -n "$(gmax)" ]] || { log "GLOBAL never produced a frame; see $OUT/up.log"; exit 1; }
[[ -n "$up_rc" ]] || up_status
load_launch_settings || exit 1
log "GLOBAL is producing frames (max frame $(gmax)); restarts use ${COMMON[*]}"
sleep 60

SUMMARY="$OUT/summary.tsv"
printf 'round\tglobal_resume_s\tactivated\tskipped\tproposals_per_archive\tregular_orphan_lines\n' > "$SUMMARY"

round() { # spec = all|stagger[+delay]
  local spec=$1 mode=${1%%+*} i k n t0 pre ok=0 resume=NA
  local -a off props
  DELAY_NOW=""; [[ "$spec" == *+delay ]] && DELAY_NOW=$DELAY_MS
  for k in $(seq 0 $((ARCHIVES-1))); do off[$k]=$(lines "$k"); done
  local rcount0; rcount0=$(regcount "$ORPHAN_RE")
  log "round $spec: restarting${DELAY_NOW:+ with a ${DELAY_NOW} ms registry load delay}"
  if [[ "$mode" == all ]]; then
    for k in $(seq 0 $((ARCHIVES-1))); do stop_node "archive$k"; done
    stop_node reg1
    wait_gone archive0 archive1 archive2 archive3 reg1
    pre=$(gmax)
    for k in $(seq 0 $((ARCHIVES-1))); do start_node "archive$k" --archive; done
    start_node reg1
  else
    for k in $(seq 0 $((ARCHIVES-1))); do
      stop_node "archive$k"; wait_gone "archive$k"; start_node "archive$k" --archive; sleep 20
    done
    pre=$(gmax)
  fi
  t0=$(date +%s)
  # GLOBAL resumes: a frame beyond the highest one seen when the restart ended.
  for (( i=0; i<GLOBAL_BOUND; i+=2 )); do
    n=$(gmax); if [[ -n "$n" && "$n" -gt "${pre:-0}" ]]; then ok=1; resume=$(( $(date +%s) - t0 )); break; fi
    sleep 2
  done
  [[ $ok == 1 ]] || fail "$spec: GLOBAL did not advance past frame ${pre:-?} within ${GLOBAL_BOUND}s of the last start"
  # Every archive activates, every archive leads at least one frame.
  local act=0 skip=0
  for k in $(seq 0 $((ARCHIVES-1))); do
    for (( i=0; i<ACTIVATION_BOUND; i+=2 )); do
      since "$k" "${off[$k]}" 'global consensus activated|skipping global consensus activation' | grep -aq . && break; sleep 2
    done
    if since "$k" "${off[$k]}" 'skipping global consensus activation' | grep -aq .; then
      skip=$((skip+1)); fail "$spec: archive$k logged \"skipping global consensus activation\""
    elif since "$k" "${off[$k]}" 'global consensus activated' | grep -aq .; then
      act=$((act+1))
    else
      fail "$spec: archive$k did not log its GLOBAL consensus activation within ${ACTIVATION_BOUND}s"
    fi
    if [[ -n "$DELAY_NOW" ]] && ! since "$k" "${off[$k]}" 'TEST HOOK: delaying' | grep -aq .; then
      fail "$spec: archive$k never logged the delay hook; build quil-node with --features test-hooks"
    fi
  done
  local deadline=$(( $(date +%s) + PROPOSAL_BOUND ))
  while :; do
    local missing=0
    for k in $(seq 0 $((ARCHIVES-1))); do
      props[$k]=$(since "$k" "${off[$k]}" "$LEADER_RE" | grep -ac .)
      (( props[k] > 0 )) || missing=1
    done
    (( missing == 0 )) && break; (( $(date +%s) >= deadline )) && break; sleep 3
  done
  for k in $(seq 0 $((ARCHIVES-1))); do
    (( props[k] > 0 )) || fail "$spec: archive$k proposed no GLOBAL frame within ${PROPOSAL_BOUND}s of its restart"
  done
  # Regular node: alive, no orphaned filters cleared by the restart.
  [[ -n "$(node_pids reg1)" ]] || fail "$spec: the regular node is not running"
  local orphans=$(( $(regcount "$ORPHAN_RE") - rcount0 ))
  (( orphans == 0 )) || fail "$spec: the regular node cleared $orphans orphaned worker filter(s)"
  printf '%s\t%s\t%s/%s\t%s\t%s\t%s\n' "$spec" "$resume" "$act" "$ARCHIVES" "$skip" \
    "${props[*]}" "$orphans" | tee -a "$SUMMARY" > /dev/null
  for k in $(seq 0 $((ARCHIVES-1))); do
    since "$k" "${off[$k]}" 'registry|global consensus|global prover|skipping|TEST HOOK|pthread' \
      | cut -c1-300 > "$OUT/$spec.archive$k.excerpt"
  done
  sleep "$SETTLE"
}

for spec in $ROUNDS; do round "$spec"; done

# Worker allocation of the regular node, over the whole run: a worker bound
# to a shard filter, before its allocation is Active (pinned) or after.
pinned=$(regcount 'worker filter pinned'); assigned=$(regcount 'worker assigned to shard')
log "regular node: $pinned worker filter pins, $assigned shard assignments, $(regcount 'submitting ProverConfirm') ProverConfirm submissions"
(( pinned + assigned > 0 )) || fail "the regular node bound no worker to a shard filter"
log "pthread aborts at shutdown: $(cat "$NET_DIR"/archive*.log | grep -ac 'pthread lock')"
log "devnet directory: $(du -sm "$NET_DIR" | cut -f1) MiB"

echo; echo "devnet-smoke summary (UTC $(now))"
awk -F'\t' '{printf "%-16s %-16s %-10s %-8s %-22s %s\n", $1, $2, $3, $4, $5, $6}' "$SUMMARY"
if (( ${#FAILS[@]} )); then
  echo; echo "FAILED checks:"; printf '  - %s\n' "${FAILS[@]}"
  exit 1
fi
echo; echo "PASS: every archive reactivated, led frames, and GLOBAL resumed in every round"
