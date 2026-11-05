#!/usr/bin/env python3
"""Verify exact completed wave35 runs, including natural exit and disposal."""
import collections
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path('/home/leon/c3-anyorder-execution-20261104/manual-tls-xray-wave35')


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
    assert {p['targetProfile'] for p in imports[0]['pins']} == {'xray-main', 'xray-bridge'}
    assert {p['role'] for p in imports[0]['pins']} == {'portal', 'bridge'}
    assert len(controls) == 1 and controls[0]['dispatch'] == 0 and controls[0]['code'] == 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN'
    assert [r['label'] for r in plans] == matrix['planStages'] == ['apply', 'noop', 'delete', 'recreate']
    assert len({r['operationId'] for r in plans}) == len(plans) == result['planExecutions'] == 4
    assert len(traffic) == len(matrix['stages']) * matrix['probesPerStage'] == (30 if matrix['variant'] == 'extra' else 25)
    assert len({r['label'] for r in traffic}) == (30 if matrix['variant'] == 'extra' else 25)
    for stage in matrix['stages']:
        expected = [stage + ':selected'] + ([stage + ':primary-none'] if matrix['variant'] == 'extra' else []) + [stage + ':selected-fragment-' + n for n in ['p', 'b']] + [stage + ':independent-' + n for n in ['p', 'b']]
        assert [r['label'] for r in traffic if r['label'].startswith(stage + ':')] == expected
    blocked = []
    for probe in traffic:
        if probe['expected'] == 'blocked':
            assert probe['label'] in ['delete:selected', 'delete:primary-none'] and probe['code'] != 0 and probe['response'] is None
            blocked.append(probe)
        else:
            assert probe['code'] == 0 and probe['response']['role'] == probe['expected']
            assert probe['response']['peer'] == '127.0.0.1' and probe['response']['nonce']
    assert len(blocked) == (2 if matrix['variant'] == 'extra' else 1)
    assert all(r['status'] == 'passed' for r in rows if r['kind'] != 'no-reader-control')
    terminals = [e['proof'] for p in plans for e in p['evidence']]
    assert len(terminals) == 8 and all(p['terminalOutcome'] == 'verified' and p['ownershipRetained'] and p['terminal'] for p in terminals)
    noops = [p for p in plans if p['noop']]
    assert len(noops) == 1 and all(e['before'] == e['after'] for p in noops for e in p['evidence'])
    assert all(e['profileTargetPin'] in imports[0]['pins'] for p in plans for e in p['evidence'])
    for node in ['p', 'b']:
        observations = [e for p in plans for e in p['evidence'] if e['node'] == node]
        assert len(observations) == 4
        assert len({e['otherSha256'] for e in observations}) == 1
        assert len({e['otherIdentity'] for e in observations}) == 1
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
    assert reality['streamSettings']['security'] == 'tls'
    tls = reality['streamSettings']['tlsSettings']
    assert tls['serverName'] == 'manual-tls-test-only.invalid' and tls['disableSystemRoot'] is True
    assert tls.get('allowInsecure', False) is False
    assert tls['certificates'][0]['usage'] == 'verify'
    cert = load('certificate-validation.json')
    assert cert['privateTrust'] and cert['hostnameCheck'] and cert['certificateRequired']
    assert all(row['rejected'] for row in cert['controls'].values())
    assert set(cert['controls']) == {'wrong-name', 'untrusted'}
    assert reality['settings']['vnext'][0]['users'][0]['flow'] == 'xtls-rprx-vision'
    digest = lambda data: hashlib.sha256(data).hexdigest()
    fixture = load('fixture.private.json')
    raw_http = [json.loads(line) for line in (run / 'http-results.jsonl').read_text().splitlines()]
    raw_runner = [json.loads(line) for line in (run / 'runner-responses.jsonl').read_text().splitlines()]
    assert len(raw_runner) == len(receipts) == 40
    assert len({p['nonce'] for p in traffic}) == len(traffic)
    for raw, command in zip(raw_runner, receipts):
        assert raw['sha256'] == command['stdoutSha256'] == digest(raw['raw'].encode())
        assert json.loads(raw['raw']) == command['receipt']
        assert (raw['node'], raw['action'], raw['label']) == (command['node'], command['action'], command['label'])
    for probe in traffic:
        matches = [r for r in raw_http if r['label'] == probe['label']]
        assert matches and matches[-1]['nonce'] == probe['nonce']
        raw = matches[-1]
        assert raw['sha256'] == probe['rawSha256'] == digest(raw['raw'].encode())
        assert raw['code'] == probe['code']
        if probe['expected'] != 'blocked':
            response = json.loads(raw['raw'])
            assert response == probe['response'] and response['nonce'] == probe['nonce']
            assert response['identity'] == fixture['nodes'][probe['expected']]['machineId']
    originals = load('originals.private.json')
    assert len(load('all-owners.private.json')) == 4
    for plan_number, plan_row in enumerate(plans, 1):
        candidate = load(f'plan-{plan_number}.private.json')
        for node in candidate['nodes']:
            short = next(k for k, v in fixture['nodes'].items() if v['nodeId'] == node['node'])
            selected_name = 'main' if short == 'p' else 'sidecar'
            assert node['targetProfile'] == ('xray-main' if short == 'p' else 'xray-bridge')
            raw_bytes = bytes(node['candidate']['bytes']['data']) if isinstance(node['candidate']['bytes'], dict) else bytes(node['candidate']['bytes'])
            assert digest(raw_bytes) == node['candidate']['sha256']
            current = json.loads(raw_bytes)
            original = json.loads(originals[short][selected_name]['config'])
            for tag in ['client-in', 'tls-extra', 'unrelated-in']:
                assert next((i for i in current['inbounds'] if i['tag'] == tag), None) == next((i for i in original['inbounds'] if i['tag'] == tag), None)
            assert current['policy'] == original['policy']
            assert [o for o in current['outbounds'] if o['tag'] == 'unrelated-out'] == [o for o in original['outbounds'] if o['tag'] == 'unrelated-out']
            assert [r for r in current['routing']['rules'] if r.get('outboundTag') == 'unrelated-out'] == [r for r in original['routing']['rules'] if r.get('outboundTag') == 'unrelated-out']
            evidence = next(e for e in plan_row['evidence'] if e['node'] == short)
            assert evidence['after']['config'] == node['candidate']['sha256']
    binaries = load('binary-pins-readback.json')
    assert binaries['node'] == 'v22.23.1'
    for version in binaries['versions'].values():
        assert '26.3.27' in version
        assert '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed' in version
        assert digest((run / 'candidate/src/modules/relay-l2tp/node-artifacts/topology/runner.sh').read_bytes()) in version
    witnesses = load('witnesses.json')
    for probe in traffic:
        seen = [w for node in witnesses.values() for w in node if w['nonce'] == probe['nonce']]
        if probe['expected'] == 'blocked':
            assert not seen, 'deleted request reached exit/direct canary'
        else:
            assert seen and all(w == probe['response'] for w in seen)
    certificates = [r for r in rows if r['kind'] == 'certificate']
    assert [r['label'] for r in certificates] == matrix['stages']
    assert len({r['peerCertificateSha256'] for r in certificates}) == 1
    assert all(r['privateTrust'] and r['hostnameCheck'] and all(c['rejected'] for c in r['controls'].values()) for r in certificates)
    scenario = [r for r in rows if r['kind'] == 'scenario']
    assert len(scenario) == 1 and scenario[0]['name'] == matrix['security']
    summary = {'run': str(run), 'security': matrix['security'], 'variant': matrix['variant'], 'plans': len(plans), 'terminalProofs': len(terminals),
        'runnerCommands': dict(counts), 'trafficProbes': len(traffic), 'positiveProbes': len(traffic) - len(blocked),
        'blockedNoDirect': len(blocked), 'byteNoopNodes': sum(len(p['evidence']) for p in noops),
        'preservedSelectedProfiles': 2, 'preservedIndependentProfiles': 2, 'recreations': 1, 'publicProducedPins': len(imports[0]['pins']),
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
        aggregate['totals'] = {key: sum(s[key] for s in summaries) for key in ['plans', 'terminalProofs', 'trafficProbes', 'positiveProbes', 'blockedNoDirect', 'byteNoopNodes', 'preservedSelectedProfiles', 'preservedIndependentProfiles', 'recreations', 'publicProducedPins']}
        (ROOT / 'verified-summary.json').write_text(json.dumps(aggregate, indent=2) + '\n')
    print(json.dumps(aggregate, indent=2))
