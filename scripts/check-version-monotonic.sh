#!/usr/bin/env bash
# Fails when the release version at HEAD_REV is lower than at BASE_REV.
# The version is the tuple (VERSION, PATCH_NUMBER, subpatch), read from
# crates/quil-config/src/version.rs and the `subpatch` file; nothing is
# built. A missing or non-numeric `subpatch` reads as 0, as build.rs
# embeds an empty value. A version.rs that cannot be parsed is an error.
# Usage: check-version-monotonic.sh BASE_REV [HEAD_REV]   (default HEAD)
set -euo pipefail

VERSION_FILE=crates/quil-config/src/version.rs
SUBPATCH_FILE=subpatch

die() { echo "check-version-monotonic: error: $*" >&2; exit 2; }

num() { # normalise a decimal or 0x literal to decimal, or fail
  [[ $1 =~ ^(0[xX][0-9a-fA-F]{1,4}|[0-9]{1,6})$ ]] || return 1
  local v=$1
  [[ $v =~ ^0[xX] ]] || v=$((10#$v))
  echo $((v))
}

# read_version REV -> "a b c patch subpatch" (decimal)
read_version() {
  local rev=$1 src ver patch sub a b c
  src=$(git show "$rev:$VERSION_FILE" 2>/dev/null) ||
    die "cannot read $VERSION_FILE at $rev"
  ver=$(sed -n -E 's/^pub const VERSION: \[u8; 3\] = \[([^],]+), *([^],]+), *([^],]+)\];.*/\1 \2 \3/p' <<<"$src")
  [ "$(wc -l <<<"$ver")" -eq 1 ] && [ -n "$ver" ] ||
    die "no single VERSION constant in $VERSION_FILE at $rev"
  patch=$(sed -n -E 's/^pub const PATCH_NUMBER: u8 = ([^;]+);.*/\1/p' <<<"$src")
  [ "$(wc -l <<<"$patch")" -eq 1 ] && [ -n "$patch" ] ||
    die "no single PATCH_NUMBER constant in $VERSION_FILE at $rev"
  read -r a b c <<<"$ver"
  if ! { a=$(num "$a") && b=$(num "$b") && c=$(num "$c") && patch=$(num "$patch"); }; then
    die "malformed version numbers in $VERSION_FILE at $rev"
  fi
  sub=$(git show "$rev:$SUBPATCH_FILE" 2>/dev/null | tr -d ' \t\r\n' || true)
  [[ $sub =~ ^[0-9]{1,9}$ ]] && sub=$((10#$sub)) || sub=0
  echo "$a $b $c $patch $sub"
}

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: $0 BASE_REV [HEAD_REV]"
base=$(read_version "$1")
head=$(read_version "${2:-HEAD}")

fmt() { read -r a b c p s <<<"$1"; echo "$a.$b.$c.$p.$s"; }
read -ra bt <<<"$base"
read -ra ht <<<"$head"
for i in 0 1 2 3 4; do
  if [ "${ht[$i]}" -gt "${bt[$i]}" ]; then
    echo "version ok: $(fmt "$base") -> $(fmt "$head")"
    exit 0
  elif [ "${ht[$i]}" -lt "${bt[$i]}" ]; then
    echo "version went backwards: head $(fmt "$head") is below base $(fmt "$base")" >&2
    exit 1
  fi
done
echo "version ok: unchanged $(fmt "$head")"
