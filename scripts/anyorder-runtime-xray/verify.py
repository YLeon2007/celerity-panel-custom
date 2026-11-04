#!/usr/bin/env python3
"""Read only the exact completed run; never count partial runs as acceptance."""
import argparse
import collections
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    assert run.parent == Path('/home/leon/c3-anyorder-execution-20261104/runtime-xray-wave8')
    load = lambda name: json.loads((run / name).read_text())
    rows = [json.loads(line) for line in (run / 'cases.jsonl').read_text().splitlines()]
    commands = [json.loads(line) for line in (run / 'ssh-exits.jsonl').read_text().splitlines()]
    matrix = load('matrix.json')
    result = load('result.json')
    cleanup = load('cleanup.json')
    assert load('exit.json')['runnerExit'] == 0
    assert result['status'] == 'passed' and cleanup['complete'] and cleanup['historicalUnchanged']
    assert load('historical-before.json') == load('historical-after.json')
    scenarios = [r for r in rows if r['kind'] == 'scenario']
    assert [r['name'] for r in scenarios] == [r[0] for r in matrix]
    assert all(r['status'] == 'passed' for r in rows if r['kind'] != 'native-authority-refusal')
    expected_plans = sum(3 * len(order) + 2 for _, order, _ in matrix)
    plans = [r for r in rows if r['kind'] == 'plan']
    traffic = [r for r in rows if r['kind'] == 'traffic']
    assert len(plans) == expected_plans == result['planExecutions']
    assert len({r['operationId'] for r in plans}) == len(plans)
    assert len(traffic) == 2 * len(plans)
    for probe in traffic:
        if probe['expected'] == 'blocked':
            assert probe['code'] != 0 and probe['response'] is None
        else:
            assert probe['code'] == 0 and probe['response']['role'] == probe['expected']
            assert probe['response']['peer'] == '127.0.0.1' and probe['response']['nonce']
    terminal = [e['proof'] for p in plans for e in p['evidence']]
    assert all(p['terminalOutcome'] == 'verified' and p['ownershipRetained'] and p['terminal'] for p in terminal)
    noops = [p for p in plans if p['noop']]
    assert len(noops) == len(matrix)
    assert all(e['before'] == e['after'] for p in noops for e in p['evidence'])
    receipts = [r for r in commands if r.get('receipt')]
    runner_counts = collections.Counter(r['action'] for r in receipts)
    assert runner_counts == collections.Counter({name: len(terminal) for name in ['prepare', 'commit', 'verify', 'close', 'status']})
    assert all(r['code'] == 0 and r['receipt']['ok'] for r in receipts)
    assert not load('dependency-parity.json')['drift']
    recreations = [r for r in rows if r['kind'] == 'recreation']
    assert len(recreations) == sum(len(order) for _, order, _ in matrix)
    assert all(r['oldId'] != r['newId'] and r['oldPort'] != r['newPort'] and r['oldCredentialSha256'] != r['newCredentialSha256']
               and r['oldListenerAbsent'] and r['newListenerPresent'] and r['oldIdentityAbsent'] for r in recreations)
    reality = load('reality-config-readback.json')
    client = load('client-config.private.json')
    assert reality['security'] == client['outbounds'][0]['streamSettings']['security'] == 'reality'
    assert reality['flow'] == client['outbounds'][0]['settings']['vnext'][0]['users'][0]['flow'] == 'xtls-rprx-vision'
    assert all(r['pidIdentityAbsent'] and r['cgroupAbsent'] for r in load('physical-cleanup-readback.json'))
    assert len(load('physical-cleanup-readback.json')) == 5
    assert len(load('physical-isolation.json')) == 5
    assert not (run / 'failure.json').exists()
    pins = load('pins.json')
    assert all(hashlib.sha256((run / 'harness' / name).read_bytes()).hexdigest() == value
               for name, value in pins['harness'].items())
    counts = {'scenarios': len(scenarios), 'planExecutions': len(plans), 'nodeTerminalProofs': len(terminal),
        'runnerCommands': dict(runner_counts), 'trafficProbes': len(traffic),
        'positiveExitProbes': sum(r['expected'] != 'blocked' for r in traffic),
        'blockedNoDirectProbes': sum(r['expected'] == 'blocked' for r in traffic),
        'byteNoopPlans': len(noops), 'byteNoopNodes': sum(len(p['evidence']) for p in noops),
        'scenarioNames': [r['name'] for r in scenarios], 'sourceCommit': pins['sourceCommit'],
        'sourceTree': pins['sourceTree'], 'cleanupVerified': True,
        'authority': result['authorityAdapter'], 'reality': True, 'newIDNewPortRecreations': len(recreations),
        'notProved': result['notProved']}
    (run / 'verified-summary.json').write_text(json.dumps(counts, indent=2) + '\n')
    print(json.dumps(counts, indent=2))


if __name__ == '__main__':
    main()
