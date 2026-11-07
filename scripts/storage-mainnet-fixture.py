#!/usr/bin/env python3
"""Capture public explorer workloads for storage sizing (not canonical bytes)."""
import argparse
import concurrent.futures
import datetime
import json
import pathlib
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', default='https://explorer-api.quilibrium.com')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()

    def get(path):
        request = urllib.request.Request(args.endpoint.rstrip('/') + path,
                                         headers={'User-Agent': 'quilibrium-storage-sizing/1'})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    before = get('/stats')
    shards = get('/provers/shards')
    # /provers defaults to GLOBAL archives. Enumerate every application shard
    # instead, retaining each active (member, filter) allocation only once.
    loads = {}
    def members(shard):
        return shard, get('/provers/shards/' + shard['filter'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for shard, members_for_shard in pool.map(members, shards):
            for member in members_for_shard:
                if member['status'] != 'active':
                    continue
                if not any(a['confirmation_filter'] == shard['filter']
                           and a['status'] == 'active' for a in member['allocations']):
                    continue
                load = loads.setdefault(member['address'], {'filters': set(), 'live_bytes': 0, 'vertex_records': 0})
                if shard['filter'] in load['filters']:
                    continue
                load['filters'].add(shard['filter'])
                load['live_bytes'] += int(shard['size_bytes'])
                load['vertex_records'] += int(shard['data_shards'])
    after = get('/stats')
    fixture = {
        'source': args.endpoint, 'as_of_frame': before['current_frame'],
        'capture_finished_frame': after['current_frame'], 'capture_started_utc': started,
        'capture_finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'note': 'Reported live sizes and raw vertex-add counts, not exact canonical snapshot bytes. Shard active_seats are the effective summary census. Per-prover profiles retain raw active allocations on globally-active identities; REST rows omit epoch/eligibility and may include expired seats. Reads span the capture interval, not an atomic chain snapshot.',
        'shards': [{'filter': s['filter'], 'live_bytes': int(s['size_bytes']),
                    'vertex_records': int(s['data_shards']), 'active_seats': s['counts'].get('active', 0)} for s in shards],
        'provers': [{'seats': len(load['filters']), 'live_bytes': load['live_bytes'],
                     'vertex_records': load['vertex_records']} for _, load in sorted(loads.items())]
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fixture, indent=2) + '\n')
    print(f"Captured {len(shards)} shards, {len(loads)} active application provers to {args.output}")


if __name__ == '__main__':
    main()
