'use strict';

const { after, test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { createRelayDirect } = require('../rebuildRelayDirect');

after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), backupId = 'c'.repeat(32);
const pin = 'd'.repeat(64);
const network = { clientCidr: '10.255.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 };
const input = { nodeId, backupId, network };
const unknown = { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true };
const frame = value => ({ code: 0, stderr: '', stdout: `${JSON.stringify(value)}\n` });

function fixture(response, { connectError = false, observed = machineId, request = input } = {}) {
    const counts = { connect: 0, attest: 0, dispatch: 0, disconnect: 0 };
    class SSH {
        constructor(_, options) { assert.equal(options.expectedHostKeySha256, pin); }
        async connectDirectOnce() {
            assert.equal(this.usePool, false);
            counts.connect++;
            if (connectError) throw Error('not reachable');
            return async (command, options, beforeStdin) => {
                if (!options.stdin) {
                    counts.attest++;
                    assert.equal(command, '/usr/bin/head -c 34 /etc/machine-id');
                    return { code: 0, stdout: `${observed}\n`, stderr: '' };
                }
                assert.equal(command.startsWith('/usr/bin/timeout '), true);
                assert.ok(Buffer.byteLength(command) + 1 <= 128 * 1024);
                await beforeStdin();
                counts.dispatch++;
                const wire = JSON.parse(options.stdin);
                assert.match(wire.challenge, /^[a-f0-9]{32}$/);
                assert.deepEqual(wire, { action: 'reconcile-install', machineId, ...request, challenge: wire.challenge });
                assert.ok(options.maxOutputBytes <= 256);
                return response({ nodeId, backupId, machineId, challenge: wire.challenge }, command, wire);
            };
        }
        disconnect() { counts.disconnect++; }
    }
    const node = { _id: nodeId, ip: '192.0.2.19', ssh: { username: 'root', port: 22 } };
    const binding = { host: node.ip, port: 22, username: 'root', machineId, sshHostKeySha256: pin };
    const fence = { merged: true, listMode: true, source: 'db', binding, check: async () => {} };
    return { remote: createRelayDirect({ node, fence, SSH, env: {} }), counts };
}

for (const result of ['absent', 'rolled_back']) {
    test(`one-shot pinned Install recovery returns only ${result}`, async () => {
        const { remote, counts } = fixture(proof => frame({ ...proof, result }));
        let guards = 0;
        assert.equal(await remote.reconcileInstall(input, async () => { guards++; }), result);
        assert.ok(guards >= 3);
        assert.deepEqual(counts, { connect: 1, attest: 1, dispatch: 1, disconnect: 1 });
        await assert.rejects(remote.reconcileInstall(input, async () => true), unknown);
        assert.equal(counts.dispatch, 1);
    });
}

test('errors, pending, inexact receipts and lock loss never confirm settlement', async () => {
    for (const reply of [
        proof => frame({ ...proof, result: 'pending' }),
        proof => frame({ ...proof, result: 'absent', backupId: pin.slice(0, 32) }),
        proof => frame({ ...proof, result: 'absent', challenge: pin.slice(0, 32) }),
        proof => frame({ ...proof, result: 'rolled_back', extra: true }),
        proof => ({ ...frame({ ...proof, result: 'rolled_back' }), stderr: 'unexpected' }),
        () => ({ code: 75, stdout: '', stderr: '' }),
        () => { throw Error('untrusted transport detail'); },
    ]) {
        const { remote, counts } = fixture(reply);
        await assert.rejects(remote.reconcileInstall(input, async () => true), unknown);
        assert.equal(counts.dispatch, 1);
    }
    for (const options of [{ connectError: true }, { observed: pin.slice(0, 32) }]) {
        const { remote, counts } = fixture(() => assert.fail('must not dispatch'), options);
        await assert.rejects(remote.reconcileInstall(input, async () => true), unknown);
        assert.equal(counts.dispatch, 0);
    }
    const { remote, counts } = fixture(proof => frame({ ...proof, result: 'absent' }));
    let checks = 0;
    await assert.rejects(remote.reconcileInstall(input, async () => ++checks < 3), unknown);
    assert.equal(counts.dispatch, 1);
});

const scenarios = {
    absent: ['ready', 'refused', 'ready-retained-bridge', 'ready-cold-retained-bridge', 'refused-cold'],
    rolled_back: ['rollback', 'rollback-applying', 'already-rolled-back', 'rollback-receipt-fsync'],
    unknown: ['missing', 'mismatch-token', 'mismatch-machine', 'mismatch-boot', 'mismatch-lock', 'mismatch-plan',
        'pending', 'preparing', 'empty-token-dir', 'symlink-receipt', 'trace-policy', 'trace-config', 'detached-vault-foreign-chap', 'trace-ppp',
        'trace-network', 'trace-listener', 'jobs', 'unavailable', 'concurrent', 'rollback-partial', 'rollback-policy-start',
        'rollback-postcondition', 'drift-rolled-back', 'manifest-lock', 'manifest-node', 'manifest-network', 'rollback-cold',
        'cold-nft-unavailable', 'cold-socket-unavailable', 'cold-partial-token', 'cold-bridge-drift', 'cold-network-drift',
        'cold-swan-drift', 'cold-nft-trace', 'cold-listener', 'cold-stray-ike', 'cold-ppp', 'warm-vpn'],
};
for (const [result, cases] of Object.entries(scenarios)) {
    for (const scenario of cases) test(`packed recovery: ${scenario} → ${result}`, async () => {
        // Default tests need no Git metadata. The immutable baseline replay
        // can additionally supply the exact old host source bytes via stdin below.
        const legacyRef = scenario !== 'rollback-policy-start' && process.env.C3_DIRECT_FIXTURE_LEGACY;
        const old = legacyRef && spawnSync('/usr/bin/git', ['--no-optional-locks', 'show',
            `${legacyRef}:src/services/rebuildRelayDirectHost.py`], { encoding: 'utf8', timeout: 3000, env: {} });
        if (old) assert.equal(old.status, 0, old.stderr);
        const request = scenario === 'missing' ? input : { ...input, packagePreparation: 'd'.repeat(64) };
        let fixtureError;
        const { remote, counts } = fixture((_, command, wire) => {
            const host = spawnSync('/usr/bin/python3', ['-I', '-B', join(__dirname, 'rebuildRelayDirectReconcileHost.py')], {
                input: JSON.stringify({ command, wire, scenario, old: old?.stdout }), encoding: 'utf8', timeout: 5000, env: {},
            });
            fixtureError = host.stderr || host.error?.message || '';
            if (host.status !== 0) throw Error('local host fixture failed');
            return JSON.parse(host.stdout);
        }, { request });
        const outcome = await remote.reconcileInstall(request, async () => true).then(value => ({ value }), error => ({ error }));
        assert.equal(fixtureError, '', fixtureError);
        assert.equal(counts.dispatch, 1);
        if (result === 'unknown') assert.equal(outcome.error?.code, unknown.code);
        else assert.equal(outcome.value, result, outcome.error?.message);
    });
}
