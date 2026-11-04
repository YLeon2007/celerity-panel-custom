#!/usr/bin/env python3
"""Read recorded browser evidence; no service, write, credential or remote action."""
import hashlib
import json
import pathlib
import socket
import sys
from urllib.parse import urlsplit

root = pathlib.Path(__file__).resolve().parent.parent
run = root / (sys.argv[1] if len(sys.argv) > 1 else 'browser-assets-wave8/run-11')
x = json.loads((run / 'evidence.json').read_text())
names = [
    'actual-template-minified-bundle-browser-boot',
    'save-only-button-persists-pending-without-job-or-executor',
    'auto-buttons-accept-two-independent-jobs-and-poll-each-without-repost',
    'actual-worker-source-less-incomplete-keeps-pending-and-native-drawer-readiness-separate',
    'manual-selected-deploy-button-completes-route-no-full-sync',
    'native-graph-drag-wheel-and-refresh-preserve-positions-zoom',
    'actual-stale-revision-delete-error-keeps-arrow-and-creates-no-job',
    'lost-delete-http-responses-retain-arrow-and-one-idempotent-job',
    'real-delete-terminal-plus-list-absence-removes-only-arrow-and-recreate-same-port',
    'no-full-sync-or-extra-mutations-and-browser-served-hash',
]
if x.get('backendBlocker'):
    assert '--allow-known-blocker' in sys.argv, 'acceptance is RED; explicit evidence-only verification required'
    names[9:9] = [
        'rolled-back-reverse-delete-retains-arrow-and-failed-job',
        'independent-forward-delete-removes-only-arrow-and-recreates-same-port',
    ]
    assert x['success'] is False
    expected_fail = 'real-delete-terminal-plus-list-absence-removes-only-arrow-and-recreate-same-port'
    assert all(c['status'] == ('FAIL' if c['name'] == expected_fail else 'PASS') for c in x['cases'])
    assert x['backendBlocker']['status'] == 'rolled_back'
    assert x['backendBlocker']['routeState'] == 'no_bridge_exit'
    assert x['totals'] == {'cases': len(names), 'pass': len(names)-1, 'fail': 1}
else:
    assert x['success'] and all(c['status'] == 'PASS' for c in x['cases'])
    assert x['totals'] == {'cases': len(names), 'pass': len(names), 'fail': 0}
assert [c['name'] for c in x['cases']] == names
asset_sha = hashlib.sha256((root / 'public/js/network.min.js').read_bytes()).hexdigest()
assert x['asset']['httpStatus'] == 200
assert x['asset']['servedSha256'] == x['asset']['diskSha256'] == x['asset']['browserSha256'] == asset_sha
assert x['cases'][-1]['detail']['browserHash'] == asset_sha
for template in ['views/nodes.ejs', 'views/network.ejs']:
    assert 'network.min.js?v=' + asset_sha[:16] in (root / template).read_text()
lock_sha = hashlib.sha256((root / 'package-lock.json').read_bytes()).hexdigest()
deps = json.loads((root / 'browser-assets-wave8/dependency-evidence.json').read_text())
assert lock_sha == deps['lockSha256']
assert deps['packages'] == len(deps['rows']) == deps['integrityPresent']
assert all(r['matches'] and r['integrity'] for r in deps['rows'])
assert x['engine']['browserName'] == 'firefox' and x['engine']['moz:headless']
assert x['isolation']['memory.max'] == '2147483648'
assert x['isolation']['cpu.max'] == '100000 100000'
assert x['browserCleanup']['profileRemoved']
assert not pathlib.Path(x['engine']['moz:profile']).exists()
pid = x['browserCleanup']['pid']
assert not pathlib.Path(f'/proc/{pid}').exists(), f'owned Firefox PID still exists: {pid}'
assert not x['applicationCleanup']['listening']
u = urlsplit(x['applicationCleanup']['address'])
assert u.scheme == 'http' and u.hostname == '127.0.0.1'
s = socket.socket()
s.settimeout(1)
try:
    assert s.connect_ex((u.hostname, u.port)) != 0, 'owned listener remains open'
finally:
    s.close()
assert x['finalBackend']['errors'] == []
assert x['finalBackend']['locks'] == []
counts = {}
for r in x['requests']:
    key = f"{r['method']} {r['path']}"
    counts[key] = counts.get(key, 0) + 1
errors = [e['text'] for e in x['console'] if e['level'] == 'error']
print(json.dumps({'evidenceVerified': True, 'acceptancePassed': x['success'], 'backendBlocker': x.get('backendBlocker'), 'totals': x['totals'], 'engine': x['engine']['browserVersion'],
                  'assetSha256': asset_sha, 'lockSha256': lock_sha, 'installed': deps['packages'],
                  'knownConsoleErrors': sorted(set(errors)), 'obstructedCloseObservations': len(x.get('uiObstructions', [])),
                  'requestCounts': counts, 'cleanupReadback': {'firefoxPidAbsent': pid, 'profileAbsent': True,
                                                              'loopbackListenerClosed': u.port}}, indent=2))
