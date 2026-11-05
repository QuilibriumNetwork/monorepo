#!/usr/bin/env python3
"""Build and run storage regressions in isolated processes, including scale I/O."""
import argparse
import concurrent.futures
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGES = ['quil-types', 'quil-crypto', 'quil-store', 'quil-execution', 'quil-engine']
FILTERS = {
    'quil_types': ('consensus::',),
    'quil_crypto': ('storage_proof::', 'persistent_storage::', 'sdr::'),
    'quil_store': ('replica_store::',),
    'quil_execution': ('global_intrinsic::persistent_storage::', 'global_intrinsic::storage_binding::',
                       'global_intrinsic::intrinsic::tests::join_kick_parity::',
                       'global_intrinsic::leaf_root_registration::', 'global_intrinsic::storage_seat::',
                       'global_intrinsic::storage_snapshot::', 'global_schema::'),
    'quil_engine': ('storage_readiness::', 'storage_snapshot::', 'storage_labels::', 'storage_epoch_batch::', 'storage_jobs::'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--full-sector', action='store_true', help='also run the 512 MiB cold certification and update lifecycle')
    parser.add_argument('--results', type=pathlib.Path)
    args = parser.parse_args()
    command = ['cargo', '+' + os.environ.get('QUIL_STORAGE_TEST_TOOLCHAIN', '1.95.0'),
               'test', '--locked', '--config', 'profile.test.package.quil-crypto.opt-level=3',
               '--lib', '--no-run', '--message-format=json']
    if args.offline:
        command.append('--offline')
    for package in PACKAGES:
        command += ['-p', package]
    with tempfile.TemporaryDirectory(prefix='quil-storage-tests-') as directory:
        log = pathlib.Path(directory) / 'build.json'
        with log.open('w') as output:
            built = subprocess.run(command, cwd=ROOT, stdout=output)
        if built.returncode:
            for line in log.read_text().splitlines():
                message = json.loads(line)
                if message.get('reason') == 'compiler-message':
                    print(message['message'].get('rendered', ''), file=sys.stderr)
            return built.returncode
        binaries = {}
        for line in log.read_text().splitlines():
            message = json.loads(line)
            name = message.get('target', {}).get('name')
            if message.get('executable') and name in FILTERS:
                binaries[name] = message['executable']
        if set(binaries) != set(FILTERS):
            raise RuntimeError('missing test executables: ' + str(set(FILTERS) - set(binaries)))
        tasks, skipped = [], []
        for name, executable in sorted(binaries.items()):
            listing = subprocess.check_output([executable, '--list', '--format', 'terse'], text=True)
            for line in listing.splitlines():
                if not line.endswith(': test'):
                    continue
                test = line[:-6]
                if not test.startswith(FILTERS[name]):
                    continue
                if test.endswith('full_size_sector_lifecycle') and not args.full_sector:
                    skipped.append(test + ': opt in with --full-sector on a scale host')
                    continue
                if platform.system() != 'Linux' and test.endswith('a_converted_leaf_stops_being_read_by_lookups_beside_it'):
                    skipped.append(test + ': existing /proc/self/io test requires Linux')
                    continue
                tasks.append((name, executable, test))

        def run(task):
            package, executable, test = task
            # One exact test per process: existing engine tests configure
            # process-wide epochs, admission queues, installed stores and clocks.
            result = subprocess.run([executable, test, '--exact', '--include-ignored', '--nocapture'],
                                    capture_output=True, text=True, cwd=ROOT)
            return {'package': package, 'test': test, 'passed': result.returncode == 0,
                    'output': result.stdout + result.stderr}
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            for result in pool.map(run, tasks):
                results.append(result)
                if not result['passed']:
                    print('FAIL ' + result['test'] + '\n' + result['output'], file=sys.stderr)
                elif 'mainnet_' in result['test'] or result['test'].endswith('full_size_sector_lifecycle'):
                    print(result['output'])
        report = {'tests': results, 'skipped': skipped}
        if args.results:
            args.results.write_text(json.dumps(report, indent=2) + '\n')
        passed = sum(r['passed'] for r in results)
        print(f'{passed}/{len(results)} storage tests passed; {len(skipped)} platform skips')
        for skip in skipped:
            print('SKIP ' + skip)
        return int(passed != len(results))


if __name__ == '__main__':
    sys.exit(main())
