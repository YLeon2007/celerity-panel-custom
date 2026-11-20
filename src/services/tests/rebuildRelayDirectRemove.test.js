'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createRelayDirect } = require('../rebuildRelayDirect');

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), pin = 'c'.repeat(64);
const backupId = 'd'.repeat(32), baseline = 'e'.repeat(64);
const node = { _id: nodeId, ip: '192.0.2.19', ssh: { username: 'root', port: 22 } };
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
    C3_REBUILD_L2TP_RELAY_ID: nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: pin };
const network = { clientCidr: '10.255.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 };
const request = { nodeId, backupId, network };
const ok = value => ({ code: 0, stdout: JSON.stringify(value), stderr: '' });

function fixture(handler = () => undefined, expectedCensus) {
    const calls = [];
    class SSH {
        constructor(selected, options) {
            assert.equal(selected, node);
            assert.deepEqual(options, { expectedEndpoint: { ip: node.ip, port: 22, username: 'root' }, expectedHostKeySha256: pin });
        }
        connect() { assert.equal(this.usePool, false); calls.push('connect'); }
        disconnect() {}
        async exec(command, { stdin }) {
            const input = JSON.parse(stdin);
            calls.push(input.action);
            assert.ok(!command.includes(backupId));
            assert.deepEqual(input, { action: input.action, machineId, ...request, ...(input.action === 'remove' ? {
                baseline, ...(expectedCensus && { expectedCensus }),
            } : {}) });
            if (expectedCensus) assert.ok(!command.includes(expectedCensus));
            return handler(input) ?? (input.action === 'prepare-remove'
                ? ok({ ok: true, machineId, backupId, baseline }) : ok({ ok: true, backupId, removed: true }));
        }
    }
    return { remote: createRelayDirect({ node, env, SSH }), calls };
}

test('remove prepares an opaque, driver-bound single-use plan over pinned SSH', async () => {
    const { remote, calls } = fixture();
    assert.equal(await remote.remove(undefined, () => assert.fail()), false);
    const plan = await remote.prepareRemove({ ...request, network: { ...network } });
    assert.deepEqual(Object.keys(plan), []);
    assert.ok(Object.isFrozen(plan));
    assert.equal(await remote.remove({ ...plan }, () => assert.fail()), false);
    assert.equal(await fixture().remote.remove(plan, () => assert.fail()), false);
    assert.equal(await remote.remove(plan, () => { calls.push('lock'); }), true);
    assert.equal(await remote.remove(plan, () => assert.fail()), false);
    assert.deepEqual(calls, ['connect', 'prepare-remove', 'lock', 'remove', 'lock']);
    await remote.close();
});

test('remove gate rejects wrong inputs and refuses a lost lock without write dispatch', async () => {
    const { remote, calls } = fixture();
    for (const invalid of [{ nodeId: 'f'.repeat(24) }, { backupId: '../anything' },
        { command: 'ignored?' }, { expectedCensus: 'f'.repeat(64) + '\n' }, { expectedCensus: null },
        { backupId: backupId + '\n' }, { network: { ...network, fwmark: '77' } }, { network: { ...network, command: 'ignored?' } }]) {
        await assert.rejects(remote.prepareRemove({ ...request, ...invalid }));
    }
    assert.deepEqual(calls, []);
    const plan = await remote.prepareRemove(request);
    assert.equal(await remote.remove(plan, () => { throw Error('private lock error'); }), false);
    assert.equal(await remote.remove(plan, () => assert.fail()), false);
    assert.deepEqual(calls, ['connect', 'prepare-remove']);
    await remote.close();
});

test('confirmed Remove binds the census to the destructive command through the opaque plan', async () => {
    const expectedCensus = 'f'.repeat(64);
    const { remote, calls } = fixture(undefined, expectedCensus);
    const input = { ...request, expectedCensus };
    const plan = await remote.prepareRemove(input);
    input.expectedCensus = 'a'.repeat(64);
    assert.deepEqual(Object.keys(plan), []);
    assert.equal(await remote.remove(plan, () => true), true);
    assert.deepEqual(calls, ['connect', 'prepare-remove', 'remove']);
    await remote.close();
});

test('only exact no-effect refusal is negative; no unknown or late lock loss confirms absence', async () => {
    const refusal = { code: 70, stdout: '', stderr: 'DIRECT_REMOVE_REFUSED\n' };
    for (const [receipt, lostAfter, expectUnknown] of [
        [refusal, false, false], [{ ...refusal, stdout: 'spoofed' }, false, true],
        [{ ...refusal, stderr: 'DIRECT_RUNTIME_UNPROVED\n' }, false, true],
        [{ code: 75, stdout: '', stderr: '' }, false, true],
        [ok({ ok: true, backupId }), false, true], [ok({ ok: true, backupId: 'f'.repeat(32), removed: true }), false, true],
        [new Error('fixture private transport secret'), false, true], [undefined, true, true],
    ]) {
        const { remote } = fixture(input => {
            if (input.action !== 'remove') return undefined;
            if (receipt instanceof Error) throw receipt;
            return receipt;
        });
        const plan = await remote.prepareRemove(request);
        let checks = 0;
        const result = remote.remove(plan, () => ++checks === 1 || !lostAfter);
        if (expectUnknown) await assert.rejects(result, { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true });
        else assert.equal(await result, false);
        await remote.close();
    }
});
