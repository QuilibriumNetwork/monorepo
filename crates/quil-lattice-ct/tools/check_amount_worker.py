#!/usr/bin/env python3
"""Public saved-fixture diagnostic; does not test transaction admission."""
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("worker", type=pathlib.Path)
parser.add_argument("transaction", type=pathlib.Path)
parser.add_argument("network", help="independently specified expected network hex")
parser.add_argument("application", help="independently specified expected app hex")
args = parser.parse_args()
network, application = bytes.fromhex(args.network), bytes.fromhex(args.application)
if len(network) != 32 or len(application) != 32:
    raise SystemExit("expected 32-byte network and app")
with args.transaction.open("rb") as f:
    transaction = f.read(1 << 20)
if not 4 <= len(transaction) < (1 << 20):
    raise SystemExit("fixture exceeds worker request budget")

def envelope(net, budget):
    return (b"QCTW1\0\0\0" + net + application
            + struct.pack("<IIIQI", 2, 2, 32, budget, len(transaction))
            + transaction)

request = envelope(network, 1 << 30)
cases = [
    ("saved_native_proof", request, 80),
    ("wrong_network", envelope(bytes([network[0] ^ 1]) + network[1:], 1 << 30), 81),
    ("submission_budget_exhausted", envelope(network, 0), 82),
    ("truncated_local_request", request[:-1], 82),
]
results = []
for name, payload, expected in cases:
    result = subprocess.run([str(args.worker.resolve()), "--cpu-seconds", "600"], input=payload,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=600, check=False)
    if result.returncode != expected:
        raise SystemExit(f"{name}: exit {result.returncode}, expected {expected}")
    results.append({"case": name, "exit": result.returncode})
print(json.dumps({
    "scope": "public amount proof only; no source authorization, state or OS memory-cap test",
    "transaction_sha256": hashlib.sha256(transaction).hexdigest(),
    "worker_sha256": hashlib.sha256(args.worker.read_bytes()).hexdigest(),
    "transaction_bytes": len(transaction), "request_bytes": len(request),
    "results": results,
}, indent=2))
