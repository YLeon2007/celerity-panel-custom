#!/usr/bin/env python3
"""Verify exact completed wave31 runs, including natural exit and disposal."""
import collections
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path('/home/leon/c3-anyorder-execution-20261104/forward-xray-wave31')


def verify(run):
    run = run.resolve()
    assert run.parent == ROOT
    load = lambda name: json.loads((run / name).read_text())
    rows = [json.loads(line) for line in (run / 'cases.jsonl').read_text().splitlines()]
    commands = [json.loads(line) for line in (run / 'ssh-exits.jsonl').read_text().splitlines()]
    result, matrix, pins, cleanup = map(load, ['result.json', 'matrix.json', 'pins.json', 'cleanup.json'])
    assert load('exit.json')['runnerExit'] == 0 and result['status'] == 'passed'
    assert not (run / 'failure.json').exists()
    assert cleanup['complete'] and cleanup['historicalUnchanged']
    assert load('historical-before.json') == load('historical-after.json')
    assert load('source-readback.json')['changed'] == []
    assert len(cleanup['containers']) == 3 and all(c['absent'] for c in cleanup['containers'])
    assert all(r['pidIdentityAbsent'] and r['cgroupAbsent'] for r in load('physical-cleanup-readback.json'))
    assert len(load('physical-cleanup-readback.json')) == 3
    assert len(load('physical-isolation.json')) == 3
    assert all(r['oomKilled'] is False for r in cleanup['resources'])
    assert not load('dependency-parity.json')['drift']
    assert all(hashlib.sha256((run / 'harness' / name).read_bytes()).hexdigest() == digest for name, digest in pins['harness'].items())
    assert hashlib.sha256((run / 'source-hashes.json').read_bytes()).hexdigest() == pins['sourceManifestSha256']
    assert all(hashlib.sha256((run / 'candidate' / name).read_bytes()).hexdigest() == digest for name, digest in load('source-hashes.json').items())
    plans = [r for r in rows if r['kind'] == 'plan']
    traffic = [r for r in rows if r['kind'] == 'traffic']
    controls = [r for r in rows if r['kind'] == 'no-reader-control']
    imports = [r for r in rows if r['kind'] == 'public-import']
    assert len(imports) == 1 and len(imports[0]['pins']) == 2
    assert {p['targetProfile'] for p in imports[0]['pins']} == {'xray-main'}
    assert {p['role'] for p in imports[0]['pins']} == {'portal', 'bridge'}
    assert len(controls) == 1 and controls[0]['dispatch'] == 0 and controls[0]['code'] == 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN'
    assert [r['label'] for r in plans] == matrix['planStages'] == ['apply', 'noop', 'delete', 'recreate']
    assert len({r['operationId'] for r in plans}) == len(plans) == result['planExecutions'] == 4
    assert len(traffic) == len(matrix['stages']) * matrix['probesPerStage'] == 25
    assert len({r['label'] for r in traffic}) == 25
    for stage in matrix['stages']:
        expected = [stage + ':selected'] + [stage + ':unrelated-main-' + n for n in ['p', 'b']] + [stage + ':sidecar-' + n for n in ['p', 'b']]
        assert [r['label'] for r in traffic if r['label'].startswith(stage + ':')] == expected
    blocked = []
    for probe in traffic:
        if probe['expected'] == 'blocked':
            assert probe['label'] == 'delete:selected' and probe['code'] != 0 and probe['response'] is None
            blocked.append(probe)
        else:
            assert probe['code'] == 0 and probe['response']['role'] == probe['expected']
            assert probe['response']['peer'] == '127.0.0.1' and probe['response']['nonce']
    assert len(blocked) == 1
    assert all(r['status'] == 'passed' for r in rows if r['kind'] != 'no-reader-control')
    terminals = [e['proof'] for p in plans for e in p['evidence']]
    assert len(terminals) == 8 and all(p['terminalOutcome'] == 'verified' and p['ownershipRetained'] and p['terminal'] for p in terminals)
    noops = [p for p in plans if p['noop']]
    assert len(noops) == 1 and all(e['before'] == e['after'] for p in noops for e in p['evidence'])
    assert all(e['profileTargetPin'] in imports[0]['pins'] for p in plans for e in p['evidence'])
    for node in ['p', 'b']:
        observations = [e for p in plans for e in p['evidence'] if e['node'] == node]
        assert len(observations) == 4
        assert len({e['sidecarSha256'] for e in observations}) == 1
        assert len({e['sidecarIdentity'] for e in observations}) == 1
    receipts = [r for r in commands if r.get('receipt')]
    counts = collections.Counter(r['action'] for r in receipts)
    assert counts == collections.Counter({name: 8 for name in ['prepare', 'commit', 'verify', 'close', 'status']})
    assert all(r['code'] == 0 and r['receipt']['ok'] for r in receipts)
    recreation = load('recreation.json')
    assert recreation['oldId'] != recreation['newId'] and recreation['oldPort'] != recreation['newPort']
    assert recreation['oldCredentialSha256'] != recreation['newCredentialSha256'] and recreation['importedPinsUnchanged']
    artifacts = {r['label']: r for r in rows if r['kind'] == 'artifacts'}
    assert set(artifacts) == {'baseline', 'apply', 'delete', 'recreate'}
    assert not artifacts['delete']['oldListenerPresent'] and artifacts['delete']['newArtifacts'] == 0
    assert not artifacts['recreate']['oldListenerPresent'] and artifacts['recreate']['newArtifacts'] == 2
    client = load('client-config.private.json')
    reality = [o for o in client['outbounds'] if o['tag'] == 'probe-10808'][0]
    assert reality['streamSettings']['security'] == 'reality'
    assert reality['settings']['vnext'][0]['users'][0]['flow'] == 'xtls-rprx-vision'
    scenario = [r for r in rows if r['kind'] == 'scenario']
    assert len(scenario) == 1 and scenario[0]['name'] == matrix['security']
    summary = {'run': str(run), 'security': matrix['security'], 'plans': len(plans), 'terminalProofs': len(terminals),
        'runnerCommands': dict(counts), 'trafficProbes': len(traffic), 'positiveProbes': len(traffic) - len(blocked),
        'blockedNoDirect': len(blocked), 'byteNoopNodes': sum(len(p['evidence']) for p in noops),
        'preservedMainProfiles': 2, 'preservedSidecars': 2, 'recreations': 1, 'publicProducedPins': len(imports[0]['pins']),
        'sourceCommit': pins['sourceCommit'], 'sourceTree': pins['sourceTree'], 'productBase': pins['productBaseCommit'],
        'authority': result['authorityAdapter'], 'cleanupVerified': True, 'notProved': result['notProved']}
    (run / 'verified-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


if __name__ == '__main__':
    summaries = [verify(Path(arg)) for arg in sys.argv[1:]]
    assert summaries
    aggregate: dict[str, object] = {'runs': summaries}
    if len(summaries) == 2:
        assert {s['security'] for s in summaries} == {'none', 'reality'}
        assert len({s['sourceCommit'] for s in summaries}) == 1
        aggregate['totals'] = {key: sum(s[key] for s in summaries) for key in ['plans', 'terminalProofs', 'trafficProbes', 'positiveProbes', 'blockedNoDirect', 'byteNoopNodes', 'preservedMainProfiles', 'preservedSidecars', 'recreations', 'publicProducedPins']}
        (ROOT / 'verified-summary.json').write_text(json.dumps(aggregate, indent=2) + '\n')
    print(json.dumps(aggregate, indent=2))
