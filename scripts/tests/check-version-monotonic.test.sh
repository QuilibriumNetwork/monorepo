#!/usr/bin/env bash
# Fixture tests for scripts/check-version-monotonic.sh, run in a
# throwaway repository. Usage: scripts/tests/check-version-monotonic.test.sh
set -uo pipefail
script=$(cd "$(dirname "$0")/.." && pwd)/check-version-monotonic.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp" && git init -q . &&
  git config user.email t@example.invalid && git config user.name t
mkdir -p crates/quil-config/src
fails=0

# commit PATCH SUBPATCH|none [VERSION_LINE] -> prints sha
commit() {
  local patch=$1 sub=$2 ver=${3:-'pub const VERSION: [u8; 3] = [0x02, 0x01, 0x00];'}
  {
    echo "$ver"
    echo "pub const PATCH_NUMBER: u8 = $patch;"
  } >crates/quil-config/src/version.rs
  if [ "$sub" = none ]; then rm -f subpatch; else echo "$sub" >subpatch; fi
  git add -A && git commit -q --allow-empty -m c && git rev-parse HEAD
}

expect() { # name want_status base head
  "$script" "$3" "$4" >out 2>&1
  local got=$?
  if [ "$got" -ne "$2" ]; then
    echo "FAIL $1: want $2 got $got: $(cat out)"; fails=$((fails + 1))
  else
    echo "ok   $1"
  fi
}

b25_122=$(commit 0x19 122)
b25_0=$(commit 0x19 0)
b25_123=$(commit 0x19 123)
b26_0=$(commit 0x1a 0)
b26_nosub=$(commit 0x1a none)
b25_nosub=$(commit 0x19 none)
bad=$(commit 0x19 5 'pub const VERSION: [u8; 3] = [0x02, 0x01];')
badnum=$(commit 0xzz 5)
b26_5=$(commit 0x1a 5)
bnewline=$(commit 0x01 0 'pub const VERSION: [u8; 3] = [0x02, 0x02, 0x00];')

expect "26 bump (122 -> 0, patch unchanged) fails" 1 "$b25_122" "$b25_0"
expect "new line (patch 25 -> 26, subpatch 0) passes" 0 "$b25_122" "$b26_0"
expect "subpatch +1 passes" 0 "$b25_122" "$b25_123"
expect "equal tuple passes" 0 "$b25_122" "$b25_122"
expect "missing subpatch on head after 122 fails" 1 "$b25_122" "$b25_nosub"
expect "missing subpatch on base reads empty" 0 "$b25_nosub" "$b25_0"
expect "missing on both passes" 0 "$b26_nosub" "$b26_nosub"
expect "patch down fails" 1 "$b26_5" "$b25_123"
expect "malformed version.rs on head errors" 2 "$b25_122" "$bad"
expect "malformed version.rs on base errors" 2 "$bad" "$b25_122"
expect "malformed patch number errors" 2 "$b25_122" "$badnum"
expect "unknown revision errors" 2 "$b25_122" 0000000000000000000000000000000000000000
expect "minor raised passes despite lower patch" 0 "$b26_5" "$bnewline"

if [ "$fails" -ne 0 ]; then echo "$fails failed"; exit 1; fi
echo "all passed"
