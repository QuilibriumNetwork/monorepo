#!/usr/bin/env python3
"""Check native proof preprocessing guards without running a proof."""
import os
from pathlib import Path
import shlex
import subprocess
import sys

base = Path(__file__).resolve().parents[1]
compiler = shlex.split(os.environ.get("CC", "clang"))
command = compiler + ["-E", "-x", "c", "-std=gnu2x"]
for directory in ["adapter/shim", "adapter", "vendor/labrados", "vendor/simde"]:
    command += ["-I", str(base / directory)]


def check(source, flag=None, expected=None):
    args = command + ([flag] if flag else []) + [str(base / source)]
    result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0 and expected in result.stderr, result.stderr
    print(f"PASS {source} {flag or 'default configuration'}")


check("adapter/fixture_bridge.c")
check("vendor/labrados/lnp.c")
for flag in ["-DDEBUG=1", "-DNDEBUG=1"]:
    check("adapter/fixture_bridge.c", flag,
          "Native token proofs require assertions and prohibit internal debug dumps")
for flag in ["-DDEBUG=1"] + [f"-D{name}=1" for name in
        ["NOMASK", "NOREJ", "RANDZERO", "JLMATZERO", "UIZERO", "UIMAX", "YZERO"]]:
    check("vendor/labrados/lnp.c", flag,
          "Native token proofs prohibit debug dumps and disabled randomness, masking or rejection")

check("vendor/labrados/lnp.c", "-ffast-math",
      "Native sampling parameters require finite checks and strict floating arithmetic")

subprocess.run([sys.executable, str(base / "tools/check_sampling_params.py")], check=True)
