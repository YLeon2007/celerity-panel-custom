'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createRelayDirect } = require('../rebuildRelayDirect');
const { readSessionCensus } = require('../rebuildRelayCounts');
const { createTransport } = require('../rebuildTransport');
const logger = require('../../utils/logger');

const nodeId = '1'.repeat(24), backupId = '2'.repeat(32), machineId = '3'.repeat(32), pin = '4'.repeat(64);
const network = Object.freeze({ clientCidr: '10.10.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 });
const installation = Object.freeze({ nodeId, backupId, network });
const user = Object.freeze({ login: 'fixture', password: 'synthetic-test-value', ipAddress: '10.10.1.2', enabled: true });
const count = { activeSessions: 0, activeIpsec: 0, census: '5'.repeat(64) };
const retiredCount = { ...count, activeClients: 0 };
const ack = value => ({ code: 0, stdout: JSON.stringify(value) + '\n', stderr: '' });
const refuse = suffix => ({ code: 70, stdout: '', stderr: `DIRECT_${suffix}\n` });
const required = refuse('RUNTIME_REATTEST_REQUIRED');
const receipt = { ok: true, backupId };
const inspection = { projection: 'desired', activeTargetSessions: 0 };
const removeReceipt = { ok: true, backupId, machineId, baseline: '6'.repeat(64) };
const identity = { code: 'REBUILD_L2TP_IDENTITY_CHANGED' };
const unknownWrite = { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true };

function fixture(respond, { check = async () => {}, machine = () => machineId } = {}) {
    const actions = [];
    let connects = 0, attestations = 0, disconnects = 0;
    const node = { _id: nodeId, ip: '192.0.2.20', ssh: { port: 22, username: 'root' } };
    class SSH {
        constructor(_, options) {
            assert.deepEqual(options, { expectedHostKeySha256: pin, expectedEndpoint: { ip: node.ip, port: 22, username: 'root' } });
        }
        async connectDirectOnce() {
            assert.equal(++connects, 1);
            assert.equal(this.usePool, false);
            return async (command, options, verify) => {
                if (command === '/usr/bin/head -c 34 /etc/machine-id') {
                    assert.equal(options.stdin, undefined);
                    return { code: 0, stdout: machine(++attestations) + '\n', stderr: '' };
                }
                assert.match(command, /^\/usr\/bin\/timeout /);
                assert.ok(!command.includes(user.password));
                assert.equal(typeof verify, 'function');
                await verify();
                const payload = JSON.parse(options.stdin);
                assert.equal(payload.machineId, machineId);
                actions.push(payload);
                if (payload.action === 'reattest-runtime') {
                    assert.deepEqual(payload, { action: 'reattest-runtime', machineId, ...installation });
                }
                return respond(payload, actions.length);
            };
        }
        disconnect() { disconnects++; }
    }
    const fence = { merged: true, listMode: true, source: 'db', check,
        binding: { nodeId, host: node.ip, port: 22, username: 'root', sshHostKeySha256: pin, machineId } };
    return { remote: createRelayDirect({ node, env: {}, SSH, fence, verifyRemoveStdin: true }), actions,
        names: () => actions.map(({ action }) => action), stats: () => [connects, attestations, disconnects] };
}

const lock = async () => true;
for (const [action, read, success, verifyResult] of [
    ['session-count', remote => remote.readSessionCount({ ...installation, currentUsers: [user] }, lock), count],
    ['retirement-count', remote => remote.readRetirementCount({ ...installation, transit: [], currentUsers: [user] }, lock), retiredCount],
    ['inspect-chap', remote => remote.inspectChap(installation, [user], [], lock, user.login),
        { ok: true, backupId, ...inspection, generation: '8'.repeat(32) }, result => assert.deepEqual(result, inspection)],
    ['check-chap', remote => remote.checkChap(installation, [user], [], lock),
        { ok: true, backupId, changed: true }, result => assert.deepEqual(result, { changed: true })],
    ['prepare-remove', remote => remote.prepareRemove({ ...installation, currentUsers: [user], transit: [],
        expectedCensus: count.census, retirement: true }, lock), removeReceipt, result => assert.deepEqual(result, {})],
]) {
    test(`${action} reattests only the installed identity and reruns the exact read on one pinned client`, async () => {
        const f = fixture((_, sequence) => [required, ack(receipt), ack(success)][sequence - 1]);
        const result = await read(f.remote);
        (verifyResult ?? (value => assert.deepEqual(value, success)))(result);
        assert.deepEqual(f.names(), [action, 'reattest-runtime', action]);
        assert.deepEqual(f.actions[0], f.actions[2]);
        assert.deepEqual(f.stats(), [1, 3, 0]);
        await f.remote.close();
    });
}

test('only the exact refusal from a completed read grants one reattestation', async () => {
    for (const bad of [{ ...required, code: 75 }, { ...required, stdout: ' ' }, { ...required, stderr: required.stderr + '\n' },
        refuse('SESSION_COUNT_UNPROVED'), { code: 124, stdout: '', stderr: '' },
        Object.assign(new Error('synthetic failure'), { code: 'REBUILD_L2TP_DIRECT_RUNTIME_REATTEST_REQUIRED' })]) {
        const f = fixture(() => { if (bad instanceof Error) throw bad; return bad; });
        await assert.rejects(f.remote.readSessionCount(installation, lock));
        assert.deepEqual(f.names(), ['session-count']);
        await f.remote.close();
    }
    const f = fixture((_, sequence) => sequence === 2 ? ack(receipt) : required);
    await assert.rejects(f.remote.readSessionCount(installation, lock), { code: 'REBUILD_L2TP_DIRECT_RUNTIME_REATTEST_REQUIRED' });
    assert.deepEqual(f.names(), ['session-count', 'reattest-runtime', 'session-count']);
    await f.remote.close();
});

test('no read or write follows a lost or malformed reattest acknowledgement', async () => {
    const lost = new Error('synthetic remote data');
    for (const bad of [lost, { ...ack(receipt), stderr: ' ' }, { ...ack(receipt), stdout: JSON.stringify(receipt) },
        ack({ ...receipt, backupId: 'a'.repeat(32) }), ack({ ...receipt, nodeId: 'a'.repeat(24) }),
        ack({ ...receipt, network: { ...network, fwmark: 123 } }), ack({ ...receipt, extra: true })]) {
        const f = fixture((_, sequence) => { if (sequence === 1) return required; if (bad === lost) throw lost; return bad; });
        await assert.rejects(f.remote.readSessionCount(installation, lock), unknownWrite);
        await assert.rejects(f.remote.readSessionCount(installation, lock), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
        assert.deepEqual(f.names(), ['session-count', 'reattest-runtime']);
        assert.deepEqual(f.stats(), [1, 2, 1]);
    }
});

test('reattest retains local and host identity vetoes and cannot cross lost lock authority', async () => {
    const other = 'a'.repeat(32);
    for (const [response, observe, expectedActions] of [
        [refuse('IDENTITY'), () => machineId, ['session-count', 'reattest-runtime']],
        [ack(receipt), i => i === 2 ? other : machineId, ['session-count']],
        [ack(receipt), i => i === 3 ? other : machineId, ['session-count', 'reattest-runtime']],
    ]) {
        const f = fixture((_, sequence) => sequence === 1 ? required : response, { machine: observe });
        await assert.rejects(f.remote.readSessionCount(installation, lock), identity);
        assert.deepEqual(f.names(), expectedActions);
    }
    const f = fixture(() => required);
    await assert.rejects(f.remote.readSessionCount(installation, () => f.actions.length === 0),
        { code: 'REBUILD_L2TP_DIRECT_LOCK_REQUIRED' });
    assert.deepEqual(f.names(), ['session-count']);
});

test('successful reattestation never substitutes for a fresh census', async () => {
    const values = [required, ack(receipt), ack(count), required, ack(receipt), ack({ ...count, activeSessions: 2 })];
    const f = fixture((_, sequence) => values[sequence - 1]);
    assert.deepEqual(await f.remote.readSessionCount(installation, lock), count);
    assert.equal((await f.remote.readSessionCount(installation, lock)).activeSessions, 2);
    assert.deepEqual(f.names(), ['session-count', 'reattest-runtime', 'session-count', 'session-count', 'reattest-runtime', 'session-count']);
    await f.remote.close();
});

test('Remove census forwards held authority and does not mask an uncertain metadata write', async () => {
    const f = fixture((_, sequence) => [required, ack(receipt), ack(retiredCount)][sequence - 1]);
    assert.deepEqual(await readSessionCensus(f.remote, installation, true, lock), retiredCount);
    assert.deepEqual(f.names(), ['retirement-count', 'reattest-runtime', 'retirement-count']);
    await f.remote.close();

    const g = fixture((_, sequence) => {
        if (sequence === 1) return required;
        throw new Error('lost reattestation receipt');
    });
    await assert.rejects(readSessionCensus(g.remote, installation, false, lock), unknownWrite);
    assert.deepEqual(g.names(), ['session-count', 'reattest-runtime']);
    await g.remote.close();
});

test('Remove and CHAP mutations never trigger reattestation even on the exact read refusal', async () => {
    for (const refusal of [required, refuse('NETWORK_OBSERVATION_REQUIRED')]) {
        const f = fixture(({ action }) => action === 'prepare-remove' ? ack(removeReceipt) : refusal);
        const plan = await f.remote.prepareRemove(installation, lock);
        await assert.rejects(f.remote.remove(plan, lock), unknownWrite);
        assert.equal(await f.remote.remove(plan, lock), false);
        assert.deepEqual(f.names(), ['prepare-remove', 'remove']);
        const g = fixture(({ action }) => action === 'check-chap' ? ack({ ok: true, backupId, changed: true }) : refusal);
        await g.remote.checkChap(installation, [user], [], lock);
        await assert.rejects(g.remote.syncChap(installation, [user], [], lock), unknownWrite);
        await assert.rejects(g.remote.syncChap(installation, [user], [], lock), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
        assert.deepEqual(g.names(), ['check-chap', 'sync-chap']);
    }
});

test('CHAP fence reads a fresh CAS preimage; failure to fence is never retried', async () => {
    const generation = '8'.repeat(32);
    const f = fixture((_, sequence) => [required, ack(receipt), ack({ ...receipt, generation }), required][sequence - 1]);
    await assert.rejects(f.remote.fenceChap(installation, [user], [], lock), unknownWrite);
    assert.deepEqual(f.names(), ['read-chap-generation', 'reattest-runtime', 'read-chap-generation', 'fence-chap']);
    assert.equal(f.actions[3].generation, generation);
});

test('exact foreign change stays distinct from a lost reattest acknowledgement', async () => {
    const f = fixture((_, sequence) => sequence === 1 ? required : refuse('RUNTIME_FOREIGN_CHANGE'));
    await assert.rejects(f.remote.readSessionCount(installation, lock), error => {
        assert.equal(error.code, 'REBUILD_L2TP_DIRECT_RUNTIME_FOREIGN_CHANGE');
        assert.equal(error.remoteOutcomeUncertain, undefined);
        return true;
    });
    assert.deepEqual(f.names(), ['session-count', 'reattest-runtime']);
    await f.remote.close();
});

test('missing network observation blocks DIRECT reads without inventing counts or write outcomes', async () => {
    const missing = refuse('NETWORK_OBSERVATION_REQUIRED');
    for (const [action, read] of [
        ['session-count', remote => readSessionCensus(remote, installation, false, lock)],
        ['retirement-count', remote => readSessionCensus(remote, installation, true, lock)],
        ['inspect-chap', remote => remote.inspectChap(installation, [user], [], lock, user.login)],
        ['prepare-remove', remote => remote.prepareRemove(installation, lock)],
    ]) {
        for (const replies of [[missing], [required, missing], [required, ack(receipt), missing]]) {
            const f = fixture((_, i) => replies[i - 1]);
            await assert.rejects(read(f.remote), error => {
                assert.equal(error.code, 'REBUILD_L2TP_DIRECT_NETWORK_OBSERVATION_REQUIRED');
                assert.equal(error.remoteOutcomeUncertain, undefined);
                return true;
            });
            assert.deepEqual(f.names(), [action, 'reattest-runtime', action].slice(0, replies.length));
            await f.remote.close();
        }
    }
    for (const bad of [{ ...missing, stdout: ' ' }, { ...missing, code: 75 }, { ...missing, stderr: missing.stderr + '\n' }]) {
        const f = fixture((_, i) => i === 1 ? required : bad);
        await assert.rejects(readSessionCensus(f.remote, installation, false, lock), unknownWrite);
        assert.deepEqual(f.names(), ['session-count', 'reattest-runtime']);
        await f.remote.close();
    }
});

function boundFixture(respond, { verify = async () => {}, actualMachine = machineId, storedNode = nodeId } = {}) {
    const rawActions = [], pinnedActions = [], proof = '7'.repeat(64);
    const observedMachine = { code: 0, stdout: machineId, stderr: '' };
    const state = { node: storedNode, rebuildMachineId: machineId, backupId, ...network,
        rebuildInstallToken: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };
    class SSH {
        async connectDirectOnce() {
            return async (command, options, guard) => {
                if (command === '/usr/bin/head -c 34 /etc/machine-id') {
                    assert.equal(options.stdin, undefined);
                    return { ...observedMachine, stdout: actualMachine };
                }
                const payload = JSON.parse(options.stdin);
                if (payload.action === 'reattest-runtime') {
                    assert.equal(typeof guard, 'function');
                    await guard();
                    assert.deepEqual(payload, { action: 'reattest-runtime', machineId, ...installation });
                }
                pinnedActions.push(payload);
                return respond(payload, pinnedActions.length) ?? ack({ ...receipt, proof });
            };
        }
        async exec(command, options) {
            if (command === '/usr/bin/head -c 34 /etc/machine-id') return observedMachine;
            rawActions.push(JSON.parse(options.stdin).action);
            return required;
        }
        disconnect() {}
    }
    const bound = createTransport({ _id: nodeId }, SSH, { machineId, installation: state, merged: true, verify });
    return { bound, proof, pinnedActions, rawActions, names: () => pinnedActions.map(({ action }) => action) };
}

test('bound link/retirement preview opts into metadata-only reattestation on the original exec', async () => {
    const f = boundFixture((_, sequence) => [required, ack(receipt)][sequence - 1]);
    await f.bound.attest();
    assert.equal(await f.bound.checkActivation({ readOnly: true, reattestRuntime: true }), f.proof);
    assert.deepEqual(f.names(), ['check-apply-network', 'reattest-runtime', 'check-apply-network']);
    assert.deepEqual(f.pinnedActions[0], f.pinnedActions[2]);
    assert.deepEqual(f.rawActions, []);
    await f.bound.close();
});

test('a lock veto at the bound reattest stdin boundary prevents the write and reread', async t => {
    t.mock.method(logger, 'warn', () => {});
    const veto = Object.assign(new Error('lock lost'), { code: 'REBUILD_LOCK_LOST' });
    let checks = 0;
    const f = boundFixture(() => required, { verify: async () => { if (++checks === 7) throw veto; } });
    await f.bound.attest();
    await assert.rejects(f.bound.checkActivation(), error => error === veto);
    assert.deepEqual(f.names(), ['check-apply-network']);
    await f.bound.close();
});

test('bound activation preserves exact foreign refusal, veto, and uncertain reattest without replay', async t => {
    t.mock.method(logger, 'warn', () => {});
    const kind = 'REBUILD_L2TP_APPLY_NETWORK_OUTCOME_UNKNOWN';
    for (const [outcome, expected, options, names] of [
        [refuse('RUNTIME_FOREIGN_CHANGE'), { code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED', reason: 'RUNTIME_FOREIGN_CHANGE' }],
        [refuse('NETWORK_OBSERVATION_REQUIRED'), { code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED', reason: 'NETWORK_OBSERVATION_REQUIRED' }],
        [{ ...refuse('NETWORK_OBSERVATION_REQUIRED'), stdout: ' ' }, { code: kind, remoteOutcomeUncertain: true }],
        [new Error('lost'), { code: kind, remoteOutcomeUncertain: true }],
        [ack({ ...receipt, extra: true }), { code: kind, remoteOutcomeUncertain: true }],
        [ack(receipt), { code: 'REBUILD_L2TP_SSH_CONNECT_FAILED' }, { actualMachine: '' }, ['check-apply-network']],
        [ack(receipt), identity, { actualMachine: '9'.repeat(32) }, ['check-apply-network']],
        [ack(receipt), { code: 'REBUILD_L2TP_APPLY_NETWORK_NOT_OWNED' }, { storedNode: '9'.repeat(24) }, ['check-apply-network']],
    ]) {
        const f = boundFixture((_, sequence) => {
            if (sequence === 1) return required;
            if (outcome instanceof Error) throw outcome;
            return outcome;
        }, options);
        await f.bound.attest();
        await assert.rejects(f.bound.checkActivation(), expected);
        assert.deepEqual(f.names(), names ?? ['check-apply-network', 'reattest-runtime']);
        assert.deepEqual(f.rawActions, []);
        await f.bound.close();
    }
});

test('bound read-only check reports missing network observation without attempting reattestation', async t => {
    t.mock.method(logger, 'warn', () => {});
    const f = boundFixture(() => refuse('NETWORK_OBSERVATION_REQUIRED'));
    await f.bound.attest();
    await assert.rejects(f.bound.checkActivation({ readOnly: true }), {
        code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED', reason: 'NETWORK_OBSERVATION_REQUIRED',
    });
    assert.deepEqual(f.names(), ['check-apply-network']);
    assert.deepEqual(f.rawActions, []);
    await f.bound.close();
});

test('an exact read refusal cannot induce reattest of the write-capable Apply prepare action', async t => {
    t.mock.method(logger, 'warn', () => {});
    const f = boundFixture(() => undefined);
    await f.bound.attest();
    await f.bound.checkActivation();
    await assert.rejects(f.bound.prepareActivation(), { code: 'REBUILD_L2TP_APPLY_NETWORK_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true });
    assert.deepEqual(f.names(), ['check-apply-network']);
    assert.deepEqual(f.rawActions, ['prepare-apply-network']);
    await f.bound.close();
});
