#!/usr/bin/env python3
"""Independent closed-packet checks; never accepts partial scenario coverage."""
import collections
import hashlib
import json
from pathlib import Path
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(run):
    def load(name):
        return json.loads((run / name).read_text())
    def lines(name):
        return [json.loads(line) for line in (run / name).read_text().splitlines()]
    result = load('result.json')
    assert result['status'] == 'passed' and load('exit.json')['runnerExit'] == 0
    scenario = result['scenario']
    stages = ['baseline', 'apply', 'noop', 'delete', 'recreate'] if scenario == 'delete-d' else ['baseline', 'delete', 'recreate']
    plan_stages = stages[1:]
    matrix = load('matrix.json')
    assert matrix['stages'] == stages and matrix['planStages'] == plan_stages and matrix['probesPerStage'] == 8
    rows = lines('cases.jsonl')
    assert all(r['status'] in ['passed', 'expected-refusal'] for r in rows)
    traffic = [r for r in rows if r['kind'] == 'traffic']
    expected_names = {f'{s}:{path}' for s in stages for path in ['portal', 'group-socks', 'selected-fragment-p', 'selected-fragment-r', 'selected-fragment-b', 'independent-p', 'independent-r', 'independent-b']}
    assert len(traffic) == len(expected_names) and {r['label'] for r in traffic} == expected_names
    assert len({r['nonce'] for r in traffic}) == len(traffic)
    cfg = load('fixture.private.json')
    witnesses = load('witnesses.json')
    http = lines('http-results.jsonl')
    for row in traffic:
        assert row['origin'] == ('r' if row['label'].endswith(':group-socks') else 'p')
        found = [(node, w) for node, values in witnesses.items() for w in values if w['nonce'] == row['nonce']]
        raw = [r for r in http if r['nonce'] == row['nonce']]
        assert raw and sha(raw[-1]['raw'].encode()) == row['rawSha256']
        if row['expected'] == 'blocked':
            assert row['code'] != 0 and not found
        else:
            assert row['code'] == 0 and len(found) == 1
            node, value = found[0]
            assert node == row['expected'] and value['identity'] == cfg['nodes'][node]['machineId']
            assert value['nonce'] == row['nonce'] and value['peer'] == '127.0.0.1'
            assert json.loads(raw[-1]['raw']) == row['response'] == value
    deleted = {r['label'].split(':')[1]: r['expected'] for r in traffic if r['label'].startswith('delete:')}
    assert deleted['portal'] == 'blocked'
    assert deleted['group-socks'] == ('blocked' if scenario == 'delete-d' else 'b')
    plans = [r for r in rows if r['kind'] == 'plan']
    assert [r['label'] for r in plans] == plan_stages and len(plans) == result['planExecutions']
    responses = lines('runner-responses.jsonl')
    exits = lines('ssh-exits.jsonl')
    commands = lines('ssh-commands.private.jsonl')
    assert len(commands) == len(exits)
    actions = collections.Counter(r['action'] for r in responses)
    assert actions == {a: len(plans) * 3 for a in ['prepare', 'commit', 'verify', 'close', 'status']}
    for response in responses:
        assert sha(response['raw'].encode()) == response['sha256']
        receipt = json.loads(response['raw'])
        assert receipt['ok'] and receipt['command'] == response['action']
        assert receipt['completion'] == 'completed'
        assert any(e['stdoutSha256'] == response['sha256'] and e['code'] == 0 for e in exits)
    terminals = []
    for plan in plans:
        assert len(plan['evidence']) == 3 and {e['node'] for e in plan['evidence']} == {'p', 'r', 'b'}
        stage = load(f"stage-{plan['label']}.json")
        for e in plan['evidence']:
            node = e['node']
            assert e['selectedProfile'] == ('xray-main' if node == 'p' else 'xray-bridge')
            actual = stage['profiles'][node]['selected']
            assert sha(actual['config'].encode()) == e['configSha256'] == e['after']['config']
            proof = e['proof']
            assert proof['terminal'] and proof['phase'] == 'closed' and proof['terminalOutcome'] == 'verified'
            assert proof['serviceState'] == 'active:running' and proof['targetProfile'] == e['selectedProfile']
            assert proof['candidateHash'] == 'sha256:' + e['configSha256']
            assert any(json.loads(r['raw']) == proof for r in responses if r['action'] == 'status')
            if plan['noop']:
                assert e['before'] == e['after']
            terminals.append((proof['nodeId'], proof['generation']))
    assert len(terminals) == len(set(terminals))
    baseline = load('stage-baseline.json')
    for name in stages:
        s = load(f'stage-{name}.json')
        assert s['independentProfilesUnchanged'] and s['modeledInventoryUnchanged']
        assert all(s['profiles'][n]['independent'] == baseline['profiles'][n]['independent'] for n in ['p', 'r', 'b'])
        assert s['group']['_id'] == baseline['group']['_id']
        assert s['group']['paths'][0]['cascadePathIngress'] == baseline['group']['paths'][0]['cascadePathIngress']
    # The independent relay MAIN must actually retain the real tproxy fragment.
    relay = json.loads(baseline['profiles']['r']['independent']['config'])
    group = baseline['group']
    tag = 'relay-l2tp-' + group['_id']
    inbound = next(i for i in relay['inbounds'] if i['tag'] == tag)
    assert inbound['protocol'] == 'dokodemo-door' and inbound['settings']['followRedirect']
    assert inbound['streamSettings']['sockopt']['tproxy'] == 'tproxy'
    socks = next(o for o in relay['outbounds'] if o['tag'] == group['paths'][0]['cascadePathIngress']['tag'])
    assert socks['protocol'] == 'socks' and socks['settings']['servers'][0]['address'] == '127.0.0.1'
    assert socks['settings']['servers'][0]['port'] == group['paths'][0]['cascadePathIngress']['port']
    assert any(r.get('inboundTag') == [tag] and r.get('ip') == ['geoip:private'] and r['outboundTag'] == 'block' for r in relay['routing']['rules'])
    assert all('MainPID=' in baseline['profiles'][n]['independent']['identity'] for n in ['p', 'r', 'b'])
    recreated = load('recreation.json')
    assert recreated['oldId'] != recreated['newId'] and recreated['oldPort'] != recreated['newPort']
    assert recreated['oldCredentialSha256'] != recreated['newCredentialSha256'] and recreated['importedPinsUnchanged']
    controls = [r for r in rows if r['kind'] == 'no-reader-control']
    assert len(controls) == 1 and controls[0]['dispatch'] == 0 and controls[0]['code'] == 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN'
    assert len(load('all-owners.private.json')) == 6 and len(load('public-import.private.json')) == 3
    assert not load('dependency-parity.json')['drift'] and load('dependency-parity.json')['actual']
    loaded = load('loaded-inputs.json')
    assert loaded
    for name, digest in loaded.items():
        file = run / 'candidate' / name.removeprefix('/candidate/') if name.startswith('/candidate/') else Path('/home/leon/celerity-l2tp-dev/node_modules') / name.removeprefix('/deps/')
        assert sha(file.read_bytes()) == digest
    cleanup = load('cleanup.json')
    assert cleanup['complete'] and cleanup['historicalUnchanged'] and all(r['absent'] and r['removeExit'] == 0 for r in cleanup['containers'])
    assert len(cleanup['containers']) == 4 and cleanup['network']['absent']
    assert all(r['pidIdentityAbsent'] and r['cgroupAbsent'] for r in load('physical-cleanup-readback.json'))
    assert all(r['oomKilled'] is False for r in cleanup['resources'])
    assert load('historical-before.json') == load('historical-after.json')
    assert not load('source-readback.json')['changed']
    pins = load('pins.json')
    for name, digest in load('source-hashes.json').items():
        assert sha((run / 'candidate' / name).read_bytes()) == digest
    for name, digest in pins['harness'].items():
        assert sha((run / 'harness' / name).read_bytes()) == digest
    return {'run': str(run), 'scenario': scenario, 'plans': len(plans), 'terminalProofs': len(terminals), 'runnerActions': dict(actions),
            'traffic': len(traffic), 'positive': sum(r['expected'] != 'blocked' for r in traffic), 'blocked': sum(r['expected'] == 'blocked' for r in traffic),
            'noopProfiles': sum(len(p['evidence']) for p in plans if p['noop']), 'adoptedSelected': 3, 'adoptedAll': 6,
            'preservedIndependentProfiles': 3, 'stageChecks': len(stages), 'sshCommands': len(commands), 'sourceCommit': pins['sourceCommit'], 'sourceManifestSha256': pins['sourceManifestSha256']}


def main():
    runs = [Path(p) for p in sys.argv[1:]]
    assert len(runs) == 2
    results = [verify(p) for p in runs]
    assert {r['scenario'] for r in results} == {'delete-d', 'delete-u'}
    keys = ['plans', 'terminalProofs', 'traffic', 'positive', 'blocked', 'noopProfiles', 'adoptedSelected', 'adoptedAll', 'preservedIndependentProfiles', 'stageChecks', 'sshCommands']
    print(json.dumps({'status': 'passed', 'runs': results, 'totals': {k: sum(r[k] for r in results) for k in keys}}, indent=2))


if __name__ == '__main__':
    main()
