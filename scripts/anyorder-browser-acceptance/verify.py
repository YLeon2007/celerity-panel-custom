#!/usr/bin/env python3
"""Verify the new integration replay, not the historical failure harness."""
import hashlib
import json
from pathlib import Path
import re
import socket
import sys
from urllib.parse import urlparse

root = Path(__file__).resolve().parents[2]
evidence = json.loads(Path(sys.argv[1]).read_text())
expected = [
    'actual-template-minified-bundle-browser-boot',
    'save-only-button-persists-pending-without-job-or-executor',
    'auto-buttons-accept-two-independent-jobs-and-poll-each-without-repost',
    'actual-worker-source-less-incomplete-keeps-pending-and-native-drawer-readiness-separate',
    'manual-selected-deploy-button-completes-route-no-full-sync',
    'native-graph-drag-wheel-and-refresh-preserve-positions-zoom',
    'actual-stale-revision-delete-error-keeps-arrow-and-creates-no-job',
    'lost-delete-http-responses-retain-arrow-and-one-idempotent-job',
    'real-delete-terminal-plus-list-absence-removes-only-arrow-and-recreate-same-port',
    'independent-forward-delete-removes-only-arrow-and-recreates-same-port',
    'explicit-modeled-verify-failure-retains-arrow-job-and-neighbors',
    'no-full-sync-or-extra-mutations-and-browser-served-hash',
]
assert [c['name'] for c in evidence['cases']] == expected
assert all(c['status'] == 'PASS' for c in evidence['cases'])
assert evidence['success'] is True
assert evidence['totals'] == {'cases': len(expected), 'pass': len(expected), 'fail': 0}
asset_hash = hashlib.sha256((root / 'public/js/network.min.js').read_bytes()).hexdigest()
assert evidence['asset']['httpStatus'] == 200
assert all(evidence['asset'][key] == asset_hash for key in ['diskSha256', 'servedSha256', 'browserSha256'])
assert evidence['engine']['browserName'] == 'firefox'
assert '/hermes-heavy-' in evidence['isolation']['cgroup']
posts = [r for r in evidence['requests'] if r['method'] == 'POST' and r['path'] == '/api/cascade/links']
assert len(evidence['nativeFills']) == len(posts) * 4
assert {f['method'] for f in evidence['nativeFills']} == {'native-tab-home-arrows', 'native-pointer-control-a-keys'}
assert all(p['hit'] and 0 < p['x'] < p['width'] and 0 < p['y'] < p['height'] for p in evidence['edgeClicks'])
backend = evidence['finalBackend']
assert backend['locks'] == [] and backend['errors'] == []
assert not any(o.get('heldTopologyAdmission') for o in backend['operations'])
assert len([o for o in backend['operations'] if o['kind'] == 'link.delete' and o['status'] == 'succeeded']) == 2
assert len([o for o in backend['operations'] if o['kind'] == 'link.delete' and o['status'] == 'rolled_back']) == 1
fault = evidence['cases'][-2]['detail']
assert fault['faults'] > 0
assert next(o for o in backend['operations'] if o['id'] == fault['operationId'])['status'] == 'rolled_back'
assert next(j for j in backend['jobs'] if j['id'] == fault['jobId'])['status'] == 'failed'
assert any(j['id'] == fault['jobId'] and j['linkId'] in [l['id'] for l in backend['links']] for j in backend['jobs'])

cleanup = evidence['browserCleanup']
assert cleanup['profileRemoved'] and not Path(evidence['browserProfile']).exists()
assert not Path('/proc', str(cleanup['pid'])).exists()
assert evidence['applicationCleanup']['listening'] is False
listeners = [evidence['applicationCleanup']['address']]
listeners += re.findall(r'WebDriver BiDi listening on (ws://[^\s]+)', evidence['firefoxLog'])
assert len(listeners) == 2
for address in listeners:
    url = urlparse(address)
    assert url.hostname in {'127.0.0.1', 'localhost', '::1'}
    try:
        with socket.create_connection((url.hostname, url.port), timeout=0.5):
            raise AssertionError('owned listener still accepts connections: ' + address)
    except (ConnectionRefusedError, TimeoutError):
        pass
# These are disclosed UI-owner findings, not suppressed console acceptance.
console_errors = [x['text'] for x in evidence['console'] if x.get('level') == 'error']
assert all('memoize' in text and 'undefined' in text for text in console_errors), console_errors
print(json.dumps({'status': 'PASS', 'cases': len(expected), 'nativeFills': len(evidence['nativeFills']),
                  'assetSha256': asset_hash, 'cleanup': 'pid/profile/app-and-bidi-listeners-absent',
                  'uiObstructions': evidence.get('uiObstructions', []), 'consoleErrors': console_errors,
                  'scope': evidence['scope']}, indent=2))
