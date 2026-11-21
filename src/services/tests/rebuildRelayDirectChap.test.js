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
        async exec(command, { stdin }) {
            assert.ok(!command.includes(row.password));
            seen.push(JSON.parse(stdin));
            return respond(seen.at(-1).action);
        }
    }
    return { remote: createRelayDirect({ node, env, SSH }), seen };
}

for (const [method, action] of [['checkChap', 'check-chap'], ['syncChap', 'sync-chap']]) {
    test(`${method} binds installation and both projections, and checks lock around dispatch`, async () => {
        const { remote, seen } = driver();
        const guardAt = [];
        assert.deepEqual(await remote[method](installation, [], [row], () => { guardAt.push(seen.length); }), { changed: true });
        assert.deepEqual(guardAt, [0, 1]);
        assert.deepEqual(seen, [{ action, machineId, nodeId, backupId, network, currentUsers: [], desiredUsers: [row] }]);
    });

    test(`${method} refuses invalid inventory, installation or lost lock before dispatch`, async () => {
        const { remote, seen } = driver();
        for (const invalid of [null, [{ ...row, password: '@indirect' }], [{ ...row, login: 'alice\n' }],
            [{ ...row, ipAddress: '10.044.0.3' }], [{ ...row, enabled: 'false' }]]) {
            await assert.rejects(() => remote[method](installation, [], invalid, () => true), { code: 'REBUILD_L2TP_CHAP_INPUT_INVALID' });
        }
        await assert.rejects(() => remote[method]({ ...installation, backupId: '../foreign' }, [], [row], () => true));
        await assert.rejects(() => remote[method](installation, [], [row], () => false), { code: 'REBUILD_L2TP_DIRECT_LOCK_REQUIRED' });
        assert.equal(seen.length, 0);
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

test('malformed or lost sync acknowledgement is unknown and poisons the driver', async () => {
    for (const respond of [() => ack({ ok: true, backupId, changed: 1 }), () => ({ ...accepted, stdout: accepted.stdout.trim() }),
        () => ({ ...refused, stderr: 'DIRECT_COMMAND_FAILED\n' }), () => ({ code: 75, stderr: '', stdout: '' }),
        () => { throw Error('transport lost'); }]) {
        const { remote, seen } = driver(respond);
        await assert.rejects(remote.syncChap(installation, [], [row], () => true), { remoteOutcomeUncertain: true });
        await assert.rejects(remote.syncChap(installation, [], [row], () => true), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
        assert.equal(seen.length, 1);
    }
});

test('sync treats post-dispatch guard loss as unknown even after a valid acknowledgement', async () => {
    const { remote, seen } = driver();
    await assert.rejects(remote.syncChap(installation, [], [row], () => seen.length === 0), { remoteOutcomeUncertain: true });
    assert.equal(seen.length, 1);
});

test('exact sync refusal is settled and certifies no write', async () => {
    const { remote } = driver(() => refused);
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
        const { remote } = driver(() => response);
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
