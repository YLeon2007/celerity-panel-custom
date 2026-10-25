#!/usr/bin/env python3
"""One serial hermes-heavy replay. Writes complete logs before hashes/summary.
No package install/network/Docker/root. C3_REAL_EVIDENCE must name caller evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ['C3_REAL_EVIDENCE'])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependencies():
    lock = json.loads((ROOT / 'package-lock.json').read_text())
    root = Path(os.environ['NODE_PATH'])
    checked, missing = [], []
    for name, pin in lock['packages'].items():
        if not name.startswith('node_modules/'):
            continue
        file = root.parent / name / 'package.json'
        if not file.is_file():
            # Only lock-marked optional foreign platform packages may be absent.
            foreign = (pin.get('os') and 'linux' not in pin['os']) or (pin.get('cpu') and 'x64' not in pin['cpu'])
            assert pin.get('optional') and foreign, 'missing current-platform dependency: ' + name
            missing.append(name)
            continue
        actual = json.loads(file.read_text())['version']
        assert actual == pin['version'], (name, pin['version'], actual)
        checked.append(dict(package=name, version=actual, packageJsonSha256=sha(file)))
    receipt = dict(root=str(root), lockSha256=sha(ROOT / 'package-lock.json'),
                   checkedCount=len(checked), checked=checked, foreignOptionalAbsent=missing,
                   claim='package versions checked against current lock; NOT whole-tree integrity/ABI equivalence')
    (OUT / 'dependencies.json').write_text(json.dumps(receipt, indent=2))


def run(name, args, expected=None, expected_subtests=0):
    if not re.fullmatch(r'[a-z0-9-]+', name):
        raise ValueError('SUITE_NAME_REFUSED')
    suite = OUT / name
    suite.mkdir(exist_ok=False)  # refuse rerun BEFORE opening log/launching process
    env = dict(os.environ, C3_REAL_EVIDENCE=str(suite))
    log = OUT / (name + '.log')
    ledger = OUT / (name + '-command.json')
    start = time.monotonic_ns()
    with ledger.open('x') as stream:
        json.dump(dict(name=name, command=args, cwd=str(ROOT), startedNs=start,
                       environment={k: env[k] for k in ['C3_REAL_EVIDENCE', 'C3_NODE', 'C3_MONGOD',
                                   'C3_REDIS_SERVER', 'NODE_PATH'] if k in env},
                       expectedTopLevel=expected, expectedSubtests=expected_subtests,
                       harnessOnly=expected is None), stream, indent=2)
    with log.open('xb') as stream:
        p = subprocess.run(args, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    finish = time.monotonic_ns()
    text = log.read_text(errors='replace')
    names = re.findall(r'^(test_[^\n]+?) \.\.\. ', text, re.M)
    report_path = suite / 'unittest-results.json'
    if report_path.exists():
        counts = json.loads(report_path.read_text())
        names = counts['successes']
        validated = (counts['passed'] and counts['started'] == counts['completed'] == expected
                     and len(names) == expected and len(set(names)) == expected
                     and len(counts['subtests']) == expected_subtests
                     and all(s['passed'] for s in counts['subtests'])
                     and counts['failures'] == counts['errors'] == counts['skipped'] == 0)
    else:
        def tap(field):
            match = re.search(r'^# ' + field + r' (\d+)$', text, re.M)
            return int(match.group(1)) if match else None
        names = re.findall(r'^ok \d+ - (.+)$', text, re.M)
        counts = dict(started=len(re.findall(r'^# Subtest: ', text, re.M)), completed=tap('tests'),
                      passed=tap('pass'), failures=tap('fail'), cancelled=tap('cancelled'),
                      skipped=tap('skipped'), subtests=[])
        validated = (counts['started'] == counts['completed'] == counts['passed'] == expected
                     and len(names) == expected and len(set(names)) == expected
                     and counts['failures'] == counts['cancelled'] == counts['skipped'] == 0)
    # Harness fixtures may omit test protocol; they are NEVER actual-app proof.
    passed = p.returncode == 0 and (validated if expected is not None else True)
    source = suite / 'executed-source-sha256.json'
    runner_source = OUT / 'runner-source.json'
    files = {str(f.relative_to(suite)): sha(f) for f in sorted(suite.rglob('*')) if f.is_file()}
    manifest = OUT / (name + '-evidence-sha256.json')
    with manifest.open('x') as stream:
        json.dump(dict(suite=str(suite), files=files), stream, indent=2)
    return dict(name=name, command=args, exit=p.returncode, passed=passed, harnessOnly=expected is None,
                startedNs=start, completedNs=finish, elapsedNs=finish-start,
                evidenceDirectory=str(suite), commandLedger=dict(path=str(ledger), sha256=sha(ledger)),
                log=str(log), logSha256=sha(log), counts=counts, topLevelNames=names,
                sourceManifest=dict(path=str(source), sha256=sha(source)) if source.exists() else None,
                inputSourceManifest=dict(path=str(runner_source), sha256=sha(runner_source)) if runner_source.exists() else None,
                evidenceManifest=dict(path=str(manifest), sha256=sha(manifest)))


def gateway():
    return subprocess.check_output(['systemctl', '--user', 'show', 'hermes-gateway.service',
                                   '-p', 'MainPID', '-p', 'NRestarts'], text=True).strip()


def main():
    OUT.mkdir(parents=True, exist_ok=False)  # existing output is immutable evidence
    git = lambda *args: subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()
    assert not git('status', '--porcelain=v1', '--untracked-files=all'), 'committed clean source required'
    source = dict(head=git('rev-parse', 'HEAD'), tree=git('rev-parse', 'HEAD^{tree}'),
                  files={n: sha(ROOT / n) for n in git('ls-files').splitlines() if (ROOT / n).is_file()})
    (OUT / 'runner-source.json').write_text(json.dumps(source, indent=2))
    before = gateway()
    (OUT / 'gateway-before.txt').write_text(before + '\n')
    dependencies()
    commands = [
        ('focused-final', [sys.executable, '-I', '-B', 'tests/lifecycleVnextSupervisor.test.py'], 13, 17),
        ('classic-settings', [os.environ['C3_NODE'], '--test', '--test-reporter=tap', 'tests/classicSettings.test.js'], 6, 0),
        ('actual-app', [sys.executable, '-I', '-B', 'tests/lifecycleVnextApplication.test.py'], 7, 2),
    ]
    records = []
    for name, args, expected, subtests in commands:
        record = run(name, args, expected, subtests)
        records.append(record)
        print(json.dumps(record), flush=True)
    if os.environ.get('C3_REDIS_SERVER'):
        records.append(run('classic-actual-regression', [os.environ['C3_NODE'], '--test', '--test-reporter=tap', 'tests/classicApplication.integration.test.js'], 1))
        print(json.dumps(records[-1]), flush=True)
    else:
        records.append(dict(name='classic-actual-regression', status='BLOCKED_NOT_RUN',
                            reason='real Redis binary unavailable; no fabricated/mock Redis'))
    after = gateway()
    (OUT / 'gateway-after.txt').write_text(after + '\n')
    summary = dict(commands=records, gatewayBefore=before, gatewayAfter=after,
                   gatewayUnchanged=before==after, realRedisAvailable=bool(os.environ.get('C3_REDIS_SERVER')),
                   sourceManifest=dict(path=str(OUT / 'runner-source.json'), sha256=sha(OUT / 'runner-source.json')),
                   head=source['head'], tree=source['tree'])
    (OUT / 'execution.json').write_text(json.dumps(summary, indent=2))
    return 0 if all(r.get('passed') is True for r in records) and before == after else 1


if __name__ == '__main__':
    sys.exit(main())
