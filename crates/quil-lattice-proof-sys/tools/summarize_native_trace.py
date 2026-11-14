#!/usr/bin/env python3
"""Summarize one process's native trace; nested intervals are not additive.

The trace has no process identifiers. Do not use this on interleaved worker
logs. Incomplete intervals are reported without inventing an end timestamp.
Process user CPU deltas include other threads; peak RSS is cumulative.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


def summarize(data):
    native = re.compile(
        r"quil_native_resource phase=(\S+) monotonic_seconds=([\d.]+) "
        r"peak_rss_bytes=(\d+) user_seconds=([\d.]+)"
    )
    starts, intervals, unmatched = {}, [], []
    peak = 0
    for match in native.finditer(data):
        phase, wall, rss, cpu = match.groups()
        wall, cpu = float(wall), float(cpu)
        peak = max(peak, int(rss))
        if phase.endswith("_begin"):
            starts.setdefault(phase[:-6], []).append((wall, cpu))
        elif phase.endswith("_end"):
            name = phase[:-4]
            if not starts.get(name):
                unmatched.append(phase)
                continue
            start_wall, start_cpu = starts[name].pop()
            intervals.append({
                "phase": name,
                "wall_seconds": round(wall - start_wall, 3),
                "process_user_seconds": round(cpu - start_cpu, 6),
            })
    return {
        "scope": "Single-process trace; nested intervals must not be summed.",
        "native_intervals": intervals,
        "incomplete_intervals": {k: len(v) for k, v in starts.items() if v},
        "unmatched_ends": unmatched,
        "process_peak_rss_bytes": peak if peak else None,
        "wallet_phases": [
            {"phase": phase, "wall_seconds": float(seconds)}
            for phase, seconds in re.findall(
                r"wallet_transfer_phase phase=(\S+) seconds=([\d.]+)", data
            )
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    raw = args.log.read_bytes()
    result = summarize(raw.decode(errors="replace"))
    result.update(log=str(args.log), log_sha256=hashlib.sha256(raw).hexdigest())
    print(json.dumps(result, indent=2))
