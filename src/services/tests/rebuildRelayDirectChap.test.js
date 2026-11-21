'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRelayDirect } = require('../rebuildRelayDirect');

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), backupId = 'c'.repeat(32);
const network = { clientCidr: '10.44.0.0/24', tproxyPort: 17891, fwmark: 123, routeTable: 201 };
const installation = { nodeId, backupId, network };
const row = { login: 'alice', password: 'only-a-test', ipAddress: '10.44.0.3', enabled: true };
const ack = value => ({ code: 0, stderr: '', stdout: `${JSON.stringify(value)}\n` });
const accepted = ack({ ok: true, backupId, changed: true });
const refused = { code: 70, stderr: 'DIRECT_CHAP_REFUSED\n', stdout: '' };

function driver(respond = () => accepted) {
    const seen = [];
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: nodeId,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: 'd'.repeat(64) };
    const node = { _id: nodeId, ip: '192.0.2.4', ssh: { port: 22, username: 'root' } };
    class SSH {
        async connect() {}
        disconnect() {}
        async exec(command, { stdin }, verifyBeforeStdin) {
            assert.ok(!command.includes(row.password));
            const input = JSON.parse(stdin);
            if (input.action.endsWith('-chap') || input.action === 'read-chap-generation') {
                assert.equal(typeof verifyBeforeStdin, 'function');
                await verifyBeforeStdin();
            } else {
                assert.equal(verifyBeforeStdin, undefined);
            }
            seen.push(input);
            return respond(input.action);
        }
    }
    return { remote: createRelayDirect({ node, env, SSH }), seen };
}

for (const [method, action] of [['checkChap', 'check-chap'], ['syncChap', 'sync-chap']]) {
    test(`${method} binds installation and both projections, and checks lock around dispatch`, async () => {
        const { remote, seen } = driver();
        if (method === 'syncChap') await remote.checkChap(installation, [], [row], () => true);
        const before = seen.length;
        const guardAt = [];
        assert.deepEqual(await remote[method](installation, [], [row], () => { guardAt.push(seen.length); }), { changed: true });
        assert.deepEqual(guardAt, [before, before, before + 1]);
        assert.deepEqual(seen.slice(before), [{ action, machineId, nodeId, backupId, network, currentUsers: [], desiredUsers: [row] }]);
    });

    test(`${method} refuses invalid inventory, installation or lost lock before dispatch`, async () => {
        const { remote, seen } = driver();
        for (const invalid of [null, [{ ...row, password: '@indirect' }], [{ ...row, login: 'alice\n' }],
            [{ ...row, ipAddress: '10.044.0.3' }], [{ ...row, enabled: 'false' }]]) {
            await assert.rejects(() => remote[method](installation, [], invalid, () => true), { code: 'REBUILD_L2TP_CHAP_INPUT_INVALID' });
        }
        await assert.rejects(() => remote[method]({ ...installation, backupId: '../foreign' }, [], [row], () => true));
        assert.equal(seen.length, 0);
        if (method === 'syncChap') await remote.checkChap(installation, [], [row], () => true);
        const before = seen.length;
        await assert.rejects(() => remote[method](installation, [], [row], () => false), { code: 'REBUILD_L2TP_DIRECT_LOCK_REQUIRED' });
        assert.equal(seen.length, before);
    });
}

test('read-only CHAP check reports failure without a possible write', async () => {
    const { remote } = driver(() => ({ ...accepted, stdout: `${accepted.stdout}\n` }));
    await assert.rejects(remote.checkChap(installation, [], [row], () => true), error => {
        assert.equal(error.code, 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN');
        assert.equal(error.remoteOutcomeUncertain, undefined);
        return true;
    });
});

test('inspectChap validates an exact, bounded read-only acknowledgement', async () => {
    const correct = { ok: true, backupId, projection: 'original', activeTargetSessions: 2 };
    const cases = [
        ack({ ...correct, backupId: machineId }), ack({ ...correct, projection: 'unknown' }),
        ack({ ...correct, unrequested: true }), accepted,
        ...[null, 'e'.repeat(31), 'F'.repeat(32), `${'e'.repeat(32)}\n`].map(generation => ack({ ...correct, generation })),
        ...[-1, 1.5, '0', null, Number.MAX_SAFE_INTEGER + 1].map(activeTargetSessions => ack({ ...correct, activeTargetSessions })),
        { ...ack(correct), stdout: `{"projection":"desired",${ack(correct).stdout.slice(1)}` },
        { ...ack(correct), stdout: ack(correct).stdout.trim() }, { ...ack(correct), stderr: 'fixture-secret' },
        { code: 75, stdout: '', stderr: '' }, { ...refused, stdout: ack(correct).stdout },
        new Error('fixture-secret'),
    ];
    for (const response of cases) {
        const { remote } = driver(() => { if (response instanceof Error) throw response; return response; });
        await assert.rejects(remote.inspectChap(installation, [row], [], () => true, 'alice'), error => {
            assert.equal(error.code, 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN');
            assert.equal(error.remoteOutcomeUncertain, undefined);
            assert.doesNotMatch(error.stack, /fixture-secret/);
            return true;
        });
    }
    const { remote } = driver(() => ack(correct));
    await assert.rejects(remote.inspectChap(installation, [], [row], () => true), { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN' });
});

test('inspectChap checks the caller guard before dispatch and again before returning proof', async () => {
    const proof = { projection: 'original', activeTargetSessions: 0 };
    const { remote, seen } = driver(() => ack({ ok: true, backupId, ...proof }));
    await assert.rejects(remote.inspectChap(installation, [], [row]), { code: 'REBUILD_L2TP_DIRECT_LOCK_REQUIRED' });
    await assert.rejects(remote.inspectChap(installation, [], [row], () => false), { code: 'REBUILD_L2TP_DIRECT_LOCK_REQUIRED' });
    await assert.rejects(remote.inspectChap({ ...installation, nodeId: backupId }, [], [row], () => true),
        { code: 'REBUILD_L2TP_CHAP_INPUT_INVALID' });
    assert.equal(seen.length, 0);
    await assert.rejects(remote.inspectChap(installation, [], [row], () => seen.length === 0),
        { code: 'REBUILD_L2TP_DIRECT_LOCK_REQUIRED' });
    assert.deepEqual(await remote.inspectChap(installation, [], [row], () => true), proof);
    assert.deepEqual(seen, Array(2).fill({ action: 'inspect-chap', ...installation, machineId, currentUsers: [], desiredUsers: [row] }));
});

test('fenceChap CAS is private and requires a fresh check or inspection before sync', async () => {
    const generation = 'e'.repeat(32);
    const proof = { projection: 'original', activeTargetSessions: 0 };
    const { remote, seen } = driver(action => ({
        'read-chap-generation': ack({ ok: true, backupId, generation: null }),
        'fence-chap': ack({ ok: true, backupId, fenced: true }),
        'check-chap': accepted,
        'inspect-chap': ack({ ok: true, backupId, ...proof, generation }),
        'sync-chap': accepted,
    })[action]);
    const args = [installation, [], [row], () => true];
    await assert.rejects(remote.syncChap(...args), { code: 'REBUILD_L2TP_DIRECT_CHAP_CHECK_REQUIRED' });
    await remote.checkChap(...args);
    await assert.rejects(remote.syncChap({ ...installation, backupId: 'f'.repeat(32) }, ...args.slice(1)),
        { code: 'REBUILD_L2TP_DIRECT_CHAP_CHECK_REQUIRED' });
    await assert.rejects(remote.fenceChap(installation, [], [row], () => seen.length === 1),
        { code: 'REBUILD_L2TP_DIRECT_LOCK_REQUIRED' });
    assert.deepEqual(seen.map(frame => frame.action), ['check-chap', 'read-chap-generation']);
    const beforeFence = seen.length, guardAt = [];
    assert.deepEqual(await remote.fenceChap(installation, [], [row], () => { guardAt.push(seen.length); }), { fenced: true });
    assert.deepEqual(guardAt, [beforeFence, beforeFence, beforeFence + 1, beforeFence + 1, beforeFence + 2]);
    assert.deepEqual(seen.slice(2), [
        { action: 'read-chap-generation', machineId, ...installation },
        { action: 'fence-chap', machineId, ...installation, currentUsers: [], desiredUsers: [row], generation: null },
    ]);
    await assert.rejects(remote.syncChap(...args), { code: 'REBUILD_L2TP_DIRECT_CHAP_CHECK_REQUIRED' });
    assert.deepEqual(await remote.inspectChap(...args), proof);
    assert.deepEqual(await remote.syncChap(...args), { changed: true });
    assert.deepEqual(seen.at(-1), { action: 'sync-chap', machineId, ...installation,
        currentUsers: [], desiredUsers: [row], generation });
});

test('an ambiguous fence write does not authorize inspection or another fence on the same remote', async () => {
    const generation = 'f'.repeat(32);
    const { remote, seen } = driver(action => action === 'read-chap-generation'
        ? ack({ ok: true, backupId, generation }) : ack({ ok: true, backupId, fenced: true, generation }));
    const args = [installation, [row], [], () => true, 'alice'];
    await assert.rejects(remote.fenceChap(...args), { remoteOutcomeUncertain: true });
    await assert.rejects(remote.inspectChap(...args), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
    await assert.rejects(remote.fenceChap(...args), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
    assert.deepEqual(seen.map(frame => frame.action), ['read-chap-generation', 'fence-chap']);
    assert.equal(seen.at(-1).generation, generation);
    assert.equal(seen.at(-1).revokedLogin, 'alice');
});

test('malformed or lost sync acknowledgement is unknown and poisons the driver', async () => {
    for (const respond of [() => ack({ ok: true, backupId, changed: 1 }), () => ({ ...accepted, stdout: accepted.stdout.trim() }),
        () => ({ ...refused, stderr: 'DIRECT_COMMAND_FAILED\n' }), () => ({ code: 75, stderr: '', stdout: '' }),
        () => { throw Error('transport lost'); }]) {
        const { remote, seen } = driver(action => action === 'check-chap' ? accepted : respond());
        await remote.checkChap(installation, [], [row], () => true);
        await assert.rejects(remote.syncChap(installation, [], [row], () => true), { remoteOutcomeUncertain: true });
        await assert.rejects(remote.syncChap(installation, [], [row], () => true), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
        assert.equal(seen.length, 2);
    }
});

test('sync treats post-dispatch guard loss as unknown even after a valid acknowledgement', async () => {
    const { remote, seen } = driver();
    await remote.checkChap(installation, [], [row], () => true);
    await assert.rejects(remote.syncChap(installation, [], [row], () => seen.length === 1), { remoteOutcomeUncertain: true });
    assert.equal(seen.length, 2);
});

test('a pending CHAP handoff stays busy and does not transfer stdin when its lock owner is lost', async () => {
    const { remote, seen } = driver();
    await remote.checkChap(installation, [], [row], () => true);
    const before = seen.length;
    const handoff = Promise.withResolvers(), owner = Promise.withResolvers();
    let checks = 0;
    const pending = remote.syncChap(installation, [], [row], () => {
        if (++checks === 1) return true;
        handoff.resolve();
        return owner.promise;
    });
    const rejected = assert.rejects(pending, { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true });
    // Detect a missing guard without hanging while waiting for the handoff.
    await Promise.race([handoff.promise, rejected]);
    assert.equal(checks, 2);
    assert.equal(seen.length, before);
    await assert.rejects(remote.checkChap(installation, [], [row], () => true), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
    owner.resolve(false);
    await rejected;
    assert.equal(seen.length, before);
});

test('exact sync refusal is settled and certifies no write', async () => {
    const { remote } = driver(action => action === 'check-chap' ? accepted : refused);
    await remote.checkChap(installation, [], [row], () => true);
    await assert.rejects(remote.syncChap(installation, [], [row], () => true), {
        code: 'REBUILD_L2TP_DIRECT_CHAP_REFUSED', commandSettled: true, noHostChanges: true,
    });
});

test('revoke joins the selected login to the existing CHAP write and requires an exact drain receipt', async () => {
    for (const [complete, sessionsTerminated] of [[true, 0], [true, 2], [false, Number.MAX_SAFE_INTEGER]]) {
        const receipt = { changed: true, sessionsTerminated, complete };
        const { remote, seen } = driver(action => action === 'check-chap' ? accepted : ack({ ok: true, backupId, ...receipt }));
        assert.deepEqual(await remote.checkChap(installation, [row], [], () => true, 'alice'), { changed: true });
        assert.deepEqual(await remote.syncChap(installation, [row], [], () => true, 'alice'), receipt);
        assert.deepEqual(seen.map(wire => wire.revokedLogin), ['alice', 'alice']);
        await remote.close();
    }
    for (const response of [accepted, ...[-1, 1.5, '2', null, Number.MAX_SAFE_INTEGER + 1].map(sessionsTerminated =>
        ack({ ok: true, backupId, changed: true, complete: true, sessionsTerminated }))]) {
        const { remote } = driver(action => action === 'check-chap' ? accepted : response);
        await remote.checkChap(installation, [row], [], () => true, 'alice');
        await assert.rejects(remote.syncChap(installation, [row], [], () => true, 'alice'), { remoteOutcomeUncertain: true });
        await remote.close();
    }
});

test('census and Remove receive private projection; Remove retains a copied inventory and confirmed token', async () => {
    const baseline = 'e'.repeat(64), census = 'f'.repeat(64);
    const { remote, seen } = driver(action => ({
        'session-count': ack({ activeSessions: 0, activeIpsec: 0, census }),
        'prepare-remove': ack({ ok: true, backupId, machineId, baseline }),
        remove: ack({ ok: true, backupId, removed: true }),
    })[action]);
    const currentUsers = [{ ...row }];
    await remote.readSessionCount({ ...installation, currentUsers });
    const plan = await remote.prepareRemove({ ...installation, currentUsers, expectedCensus: census });
    currentUsers[0].password = 'changed-by-caller';
    assert.equal(await remote.remove(plan, () => true), true);
    assert.deepEqual(seen, ['session-count', 'prepare-remove', 'remove'].map(action => ({
        action, machineId, ...installation, currentUsers: [row], ...(action === 'remove' && { baseline, expectedCensus: census }),
    })));
});
