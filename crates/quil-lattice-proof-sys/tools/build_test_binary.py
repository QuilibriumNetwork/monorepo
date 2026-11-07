#!/usr/bin/env python3
"""Build and copy a lib-test executable out of a BuildKit cache mount.

The following Docker RUN can execute it without holding Cargo cache locks.
Cargo's structured artifact output selects the executable; no filename glob
may pick a stale test binary from an earlier feature set.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("package")
parser.add_argument("features")
parser.add_argument("output", type=Path)
parser.add_argument("--require-test", action="append", default=[],
                    help="Fail if the installed executable lacks this exact test (repeatable)")
args = parser.parse_args()
command = ["cargo", "test", "-p", args.package, "--features", args.features,
           "--lib", "--release", "--locked", "--no-run", "--message-format=json"]
result = subprocess.run(command, stdout=subprocess.PIPE, text=True)
executables = set()
for line in result.stdout.splitlines():
    message = json.loads(line)
    if message.get("reason") == "compiler-message":
        rendered = message.get("message", {}).get("rendered")
        if rendered:
            sys.stderr.write(rendered)
    if (message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == args.package.replace("-", "_")
            and "lib" in message.get("target", {}).get("kind", [])
            and message.get("profile", {}).get("test")
            and message.get("executable")):
        executables.add(Path(message["executable"]))
if result.returncode:
    raise SystemExit(result.returncode)
if len(executables) != 1:
    raise SystemExit(f"Expected one lib-test executable, found {len(executables)}")
source = executables.pop()
if not source.is_file():
    raise SystemExit("Cargo test executable is missing")
args.output.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(source, args.output)
for required_test in args.require_test:
    listing = subprocess.run([str(args.output), "--list", "--exact", required_test],
                             stdout=subprocess.PIPE, text=True, check=True)
    if f"{required_test}: test" not in listing.stdout.splitlines():
        raise SystemExit(f"Required test is missing: {required_test}")
print(f"Installed {args.package} test executable: {args.output}")
