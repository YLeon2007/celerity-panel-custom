#!/usr/bin/env python3
"""Five focused checks over the ACTUAL unpacked package, no physical fixtures."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


# Required external-supervisor headroom; the application budget itself is read
# from the shipped entry point, never duplicated as a fixture constant.
STOP_TIMEOUT_MARGIN_SECONDS = 100


def check_stop_timeout(root):
    source = (root / 'app/index.js').read_text()
    budgets = re.findall(r'^const SHUTDOWN_DEADLINE_MS = ([^;\n]+);$', source, re.MULTILINE)
    if len(budgets) != 1 or not re.fullmatch(r'[1-9][0-9]*(?:\s*\*\s*[1-9][0-9]*)*', budgets[0]):
        raise RuntimeError('unrecognized shipped SHUTDOWN_DEADLINE_MS; review stop-timeout contract')
    # Deliberately finite literal-multiplication grammar, not eval or app import.
    budget_ms = math.prod(int(n.strip()) for n in budgets[0].split('*'))
    unit = (root / 'deployment/c3-test-native.service').read_text()
    services = re.findall(r'^\[Service\]\n(.*?)(?=^\[|\Z)', unit, re.MULTILINE | re.DOTALL)
    if len(services) != 1:
        raise RuntimeError('exactly one shipped Service section required')
    timeouts = re.findall(r'^TimeoutStopSec=(.*)$', services[0], re.MULTILINE)
    if len(timeouts) != 1:
        raise RuntimeError('exactly one shipped TimeoutStopSec required')
    timeout = timeouts[0]
    if not re.fullmatch(r'[1-9][0-9]*', timeout):
        raise RuntimeError('unrecognized shipped TimeoutStopSec; explicit integer seconds required')
    timeout_ms = int(timeout) * 1000
    margin_ms = timeout_ms - budget_ms
    if margin_ms <= 0 or margin_ms < STOP_TIMEOUT_MARGIN_SECONDS * 1000:
        raise RuntimeError(f'stop-timeout contract: supervisor={timeout_ms}ms, '
                           f'application={budget_ms}ms, margin={margin_ms}ms; '
                           f'require at least {STOP_TIMEOUT_MARGIN_SECONDS}s positive margin')
    return {'applicationBudgetMs': budget_ms, 'supervisorTimeoutMs': timeout_ms,
            'marginMs': margin_ms, 'requiredMarginSeconds': STOP_TIMEOUT_MARGIN_SECONDS}


def test_stop_timeout(root):
    contract = check_stop_timeout(root)
    # Test the same parser against the actual shipped source and private unit
    # copies. No timer waits, signal delivery, service startup or database I/O.
    with tempfile.TemporaryDirectory(prefix='stop-timeout-', dir=root.parent) as scratch:
        fixture = Path(scratch)
        (fixture / 'app').mkdir()
        (fixture / 'deployment').mkdir()
        shutil.copy2(root / 'app/index.js', fixture / 'app/index.js')
        target = fixture / 'deployment/c3-test-native.service'
        original = (root / 'deployment/c3-test-native.service').read_text()
        budget_seconds = contract['applicationBudgetMs'] // 1000
        for seconds in (60, budget_seconds, budget_seconds + STOP_TIMEOUT_MARGIN_SECONDS - 1):
            target.write_text(re.sub(r'^TimeoutStopSec=.*$', f'TimeoutStopSec={seconds}',
                                     original, flags=re.MULTILINE))
            try:
                check_stop_timeout(fixture)
            except RuntimeError as error:
                if 'stop-timeout contract:' not in str(error):
                    raise
            else:
                raise RuntimeError(f'unsafe stop-timeout {seconds}s was accepted')
        target.write_text(original)
        if check_stop_timeout(fixture) != contract:
            raise RuntimeError('stop-timeout positive control changed')
    print('PASS shipped supervisor exceeds shipped application drain with margin: '
          + json.dumps(contract, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', required=True)
    p.add_argument('--expected-input-sha256', required=True)
    a = p.parse_args()
    root = Path(a.root).resolve()
    checker = Path(__file__).with_name('package.py')

    def call(path, *extra):
        return subprocess.run([sys.executable, str(checker), 'check', '--root', str(path),
                               '--expected-input-sha256', a.expected_input_sha256, *extra],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)

    r = call(root)
    if r.returncode:
        raise RuntimeError(r.stdout)
    print('PASS actual fresh package/source/dependency/asset hashes: ' + r.stdout.strip())
    r = call(root, '--require-installation-ready')
    if r.returncode != 1 or 'INSTALLATION_NOT_READY' not in r.stdout:
        raise RuntimeError('acceptance refusal failed: ' + r.stdout)
    print('PASS unresolved installation acceptance refused: ' + r.stdout.strip())
    # Hard-link snapshot is bounded and private; BEFORE changing any file unlink
    # its snapshot path, so no sealed artifact bytes/inodes can be modified.
    with tempfile.TemporaryDirectory(prefix='package-negative-', dir=root.parent) as scratch:
        clone = Path(scratch) / 'snapshot'
        shutil.copytree(root, clone, symlinks=True, copy_function=os.link)
        manifest = clone / 'manifest.json'
        original = manifest.read_bytes()
        value = json.loads(original)
        value['sourceCommit'] = '0' * 40
        manifest.unlink()
        manifest.write_text(json.dumps(value))
        r = call(clone)
        if r.returncode != 1 or 'wrong artifact source pin' not in r.stdout:
            raise RuntimeError('wrong source refusal failed: ' + r.stdout)
        print('PASS wrong source pin refused: ' + r.stdout.strip())
        manifest.write_bytes(original)  # snapshot inode, never sealed inode
        asset = clone / 'app/public/js/network.min.js'
        changed = asset.read_bytes() + b'\n/* negative hash control */\n'
        asset.unlink()
        asset.write_bytes(changed)
        r = call(clone)
        if r.returncode != 1 or 'package file/hash/mode/symlink mismatch' not in r.stdout:
            raise RuntimeError('wrong asset hash refusal failed: ' + r.stdout)
        print('PASS wrong asset hash refused: ' + r.stdout.strip())
    r = call(root)
    if r.returncode:
        raise RuntimeError('sealed original changed: ' + r.stdout)
    print('PASS sealed original unchanged after controls; 4 existing focused cases passed')
    test_stop_timeout(root)
    print('PASS 5 focused cases passed')


if __name__ == '__main__':
    main()
