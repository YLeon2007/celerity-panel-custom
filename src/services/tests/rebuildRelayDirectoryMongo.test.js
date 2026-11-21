'use strict';

// Run only with a fresh loopback-only fixture replica set in a private netns.
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { randomBytes, randomUUID } = require('node:crypto');
const { createRebuildService } = require('../rebuildService');
const { createRebuildL2tpOverview } = require('../rebuildL2tpOverview');
const { createRebuildRelayAccountsStore } = require('../rebuildRelayAccountsStore');
const { decrypt, encrypt } = require('../../modules/relay-l2tp/services/secretBoxService');
const Node = require('../../models/hyNodeModel');
const Link = require('../../models/cascadeLinkModel');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
const port = process.env.C3_DIRECTORY_FIXTURE_PORT;
const db = mongoose.connection;
const id = n => String(n).repeat(24);
const machine = n => String(n).repeat(32);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const rendered = users => users.filter(u => u.enabled).map(({ login, password, ipAddress }) =>
    [login, password, ipAddress]).sort((a, b) => a[0].localeCompare(b[0]));

async function fixture(t, relayCount = 3) {
    assert.match(port, /^\d{4,5}$/);
    assert.deepEqual(Object.keys(require('node:os').networkInterfaces()), ['lo']);
    await mongoose.connect(`mongodb://127.0.0.1:${port}/?directConnection=true`, {
        dbName: `c3_directory_fixture_${randomBytes(8).toString('hex')}`, serverSelectionTimeoutMS: 2000,
    });
    t.after(async () => { try { await db.dropDatabase(); } finally { await mongoose.disconnect(); } });
    await Promise.all([Node, Link, State, User].map(model => model.init()));
    const accounts = db.collection('c3_rebuild_relay_accounts');
    const enrollment = [1, 2, 3].slice(0, relayCount).map(n => ({ nodeId: id(n), host: `192.0.2.${n}`, port: 22, username: 'root',
        sshHostKeySha256: String(n).repeat(64), machineId: machine(n) }));
    await Node.collection.insertMany(enrollment.map(({ nodeId, host: ip, port, username }) => ({
        _id: new mongoose.Types.ObjectId(nodeId), ip, active: true, type: 'xray', cascadeRole: 'relay', ssh: { port, username },
    })));
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
        C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify(enrollment), ENCRYPTION_KEY: 'fixture-only-key-'.repeat(3) };
    const hosts = new Map(), calls = [];
    const service = hostFactory => createRebuildService({ Node, Link, State, L2tpUser: User, env, cache: {}, sync: {},
        createRelayDirect: ({ node, binding }) => {
            const nodeId = String(node._id);
            calls.push(nodeId);
            if (hostFactory) return hostFactory(nodeId, binding);
            function check(users) { assert.ok(same(rendered(users), hosts.get(nodeId)), 'selected CHAP preimage'); }
            return {
                preflight: async () => ({ ppp: true, masked: false, machineId: enrollment.find(x => x.nodeId === nodeId).machineId }),
                prepare: async ({ desired }) => ({ desired, backupId: randomBytes(16).toString('hex') }),
                install: async ({ desired }, guard) => {
                    await guard(); assert.equal(hosts.has(nodeId), false); hosts.set(nodeId, rendered(desired.users)); return true;
                },
                verify: async ({ desired }) => { check(desired.users); return true; },
                checkChap: async (_, current, desired, guard) => { await guard(); check(current); return { changed: !same(current, desired) }; },
                syncChap: async (_, current, desired, guard, revokedLogin) => {
                    await guard(); check(current); hosts.set(nodeId, rendered(desired));
                    return { changed: !same(current, desired), ...(revokedLogin && { sessionsTerminated: 0, complete: true }) };
                },
                readSessionCount: async () => ({ activeSessions: 0, activeIpsec: 0, census: 'a'.repeat(64) }),
                prepareRemove: async ({ currentUsers }) => { if (currentUsers) check(currentUsers); return {}; },
                remove: async (_, guard) => {
                    await guard(); hosts.delete(nodeId); return true;
                },
                close: async () => {},
            };
        },
    });
    const users = nodeId => User.find({ ...(nodeId && { relayNode: nodeId }) }).select('+passwordEncrypted').sort('login').lean();
    return { service, env, users, hosts, calls, accounts, enrollment,
        overview: () => createRebuildL2tpOverview({ Node, State, L2tpUser: User, env }) };
}

const run = (name, fn) => test(name, { skip: !port }, async t => fn(await fixture(t), t));
for (const reorderOnly of [true, false]) {
    run(reorderOnly ? 'fresh intent settles with the stored field order' : 'fresh intent refuses same-owner BSON drift before sync', async (f, t) => {
        await f.service().installRelay(id(1));
        const original = await f.users();
        const host = structuredClone(f.hosts.get(id(1)));
        const findOne = f.accounts.findOne.bind(f.accounts);
        const reverseFields = row => Object.fromEntries(Object.entries(row).reverse());
        let rewrite;
        t.mock.method(f.accounts, 'findOne', async (filter, options) => {
            const row = await findOne(filter, options);
            if (rewrite || row === null || filter._id !== 'pending' || options?.projection) return row;
            assert.equal(options.readConcern.level, 'majority');
            rewrite = reorderOnly ? reverseFields({ ...row, relays: row.relays.map(relay =>
                reverseFields({ ...relay, network: reverseFields(relay.network) })) })
                : { ...row, relays: row.relays.map(relay => ({ ...relay, revision: 9 })) };
            assert.notEqual(JSON.stringify(rewrite), JSON.stringify(row));
            const updated = await f.accounts.replaceOne({ _id: row._id, intentId: row.intentId }, rewrite, { writeConcern: { w: 'majority' } });
            assert.equal(updated.modifiedCount, 1);
            return findOne(filter, options);
        });
        const result = f.service().createRelayAccount({ login: 'fresh-user', password: 'fixture-fresh' });
        if (reorderOnly) {
            assert.equal((await result).status, 'created');
            assert.equal(await findOne({ _id: 'pending' }), null);
            assert.deepEqual(f.hosts.get(id(1)).map(([login]) => login), ['fresh-user', 'relay-bootstrap']);
        } else {
            await assert.rejects(result, { code: 'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN', retryAllowed: false, confirmedNodeIds: [] });
            assert.deepEqual(await findOne({ _id: 'pending' }), rewrite);
            assert.deepEqual(await f.users(), original);
            assert.deepEqual(f.hosts.get(id(1)), host);
        }
        assert.ok(rewrite);
    });
}

run('legacy Remove-last → reinstall on another relay preserves encrypted identity and never enables disabled accounts', async f => {
    const { service, users, hosts, env, accounts } = f;
    await service().installRelay(id(1));
    await service().createRelayAccount({ login: 'disabled-user', password: 'fixture-disabled' });
    await service().disableRelayAccount({ login: 'disabled-user' });
    await service().createRelayAccount({ login: 'enabled-user', password: 'fixture-enabled' });
    // Stand in for a pre-upgrade database: the projections already existed.
    await accounts.deleteOne({ _id: 'directory' });
    const original = await users(id(1));
    await service().removeRelay(id(1));
    assert.equal((await users()).length, 0);
    assert.equal(hosts.size, 0);
    await Node.deleteOne({ _id: id(1) });
    const reinstated = await service().installRelay(id(2));
    assert.equal(reinstated.status, 'installed');
    const copies = await users(id(2));
    const shape = rows => rows.map(({ login, enabled, passwordEncrypted }) => ({ login, enabled, passwordEncrypted }));
    assert.ok(same(shape(original), shape(copies)), 'login, status and exact ciphertext survive');
    assert.deepEqual(hosts.get(id(2)).map(u => u[0]), ['enabled-user', 'relay-bootstrap']);
    assert.equal(decrypt(copies.find(row => row.login === 'enabled-user').passwordEncrypted, env.ENCRYPTION_KEY), 'fixture-enabled');
    const catalog = await accounts.findOne({ _id: 'directory' });
    assert.equal(catalog.accounts.find(a => a.login === 'enabled-user').id, String(original.find(a => a.login === 'enabled-user')._id));
    await service().removeRelay(id(2));
    const dormant = await f.overview().overview();
    assert.deepEqual(dormant.accounts.map(a => [a.login, a.enabled, a.addresses.length]), [
        ['disabled-user', false, 0], ['enabled-user', true, 0], ['relay-bootstrap', true, 0],
    ]);
    assert.ok(!JSON.stringify(dormant).includes('passwordEncrypted'));
    assert.equal(dormant.canManageAccounts, false);
    assert.equal(await f.overview().revealPassword('enabled-user'), 'fixture-enabled');
    await service().installRelay(id(2));
    assert.equal((await users(id(2))).length, 3);
    assert.ok(same(catalog, await accounts.findOne({ _id: 'directory' })));
});

run('multi-relay Install does not require a live source and Remove retires only selected projections', async f => {
    const { service, users, hosts, calls, accounts } = f;
    await service().installRelay(id(1));
    await service().createRelayAccount({ login: 'shared-user', password: 'fixture-shared' });
    const catalog = await accounts.findOne({ _id: 'directory' });
    calls.length = 0;
    await service().installRelay(id(2));
    assert.deepEqual(calls, [id(2)]);
    const before = await users(id(2));
    const hostBefore = structuredClone(hosts.get(id(2)));
    await service().removeRelay(id(1));
    assert.equal((await users(id(1))).length, 0);
    assert.deepEqual(await users(id(2)), before);
    assert.deepEqual(hosts.get(id(2)), hostBefore);
    assert.ok(same(catalog, await accounts.findOne({ _id: 'directory' })));
    await service().deleteRelayAccount({ login: 'shared-user' });
    await service().installRelay(id(3));
    assert.deepEqual((await users(id(3))).map(r => r.login), ['relay-bootstrap']);
});

run('a same-login envelope collision refuses Install and account mutation before transport', async f => {
    const { service, users, calls, env, accounts } = f;
    await service().installRelay(id(1));
    await service().createRelayAccount({ login: 'shared-user', password: 'fixture-shared' });
    const catalog = await accounts.findOne({ _id: 'directory' });
    const projected = (await users(id(1))).find(row => row.login === 'shared-user');
    await User.updateOne({ _id: projected._id }, { $set: { passwordEncrypted: encrypt('fixture-shared', env.ENCRYPTION_KEY) } });
    calls.length = 0;
    await assert.rejects(service().installRelay(id(2)), { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_CONFLICT' });
    await assert.rejects(service().disableRelayAccount({ login: 'shared-user' }), { code: 'REBUILD_L2TP_ACCOUNTS_ACCOUNT_CONFLICT' });
    assert.deepEqual(calls, []);
    assert.equal((await users(id(2))).length, 0);
    assert.ok(same(catalog, await accounts.findOne({ _id: 'directory' })));
});

run('failed Remove settlement rolls back selected projection deletes without changing the directory', async (f, t) => {
    const { service, users, accounts } = f;
    await service().installRelay(id(1));
    await service().createRelayAccount({ login: 'shared-user', password: 'fixture-shared' });
    const original = await users(id(1));
    const catalog = await accounts.findOne({ _id: 'directory' });
    const update = State.collection.updateMany.bind(State.collection);
    let failures = 0;
    t.mock.method(State.collection, 'updateMany', async (filter, change, options) => {
        if (change.$set.status === 'not_installed') {
            assert.ok(options.session.inTransaction());
            assert.equal(await User.countDocuments({ relayNode: id(1) }).session(options.session), 0);
            failures++;
            return { acknowledged: true, matchedCount: 0 };
        }
        return update(filter, change, options);
    });
    await assert.rejects(service().removeRelay(id(1)), { code: 'REBUILD_L2TP_REMOVE_FINISH_OUTCOME_UNKNOWN' });
    assert.equal(failures, 1);
    assert.ok(same(original, await users(id(1))));
    assert.ok(same(catalog, await accounts.findOne({ _id: 'directory' })));
    assert.equal((await State.findOne({ node: id(1) })).status, 'removing');
    await assert.rejects(service().installRelay(id(2)), { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_BUSY' });
});

run('legacy singleton can Remove and reinstall the same bootstrap without transactions', async f => {
    const { service, env, users, accounts } = f;
    delete env.C3_REBUILD_L2TP_RELAYS_JSON;
    env.C3_REBUILD_L2TP_RELAY_ID = id(1);
    env.C3_REBUILD_L2TP_RELAY_MACHINE_ID = machine(1);
    await service().installRelay(id(1));
    const [original] = await users(id(1));
    assert.equal(await accounts.findOne({ _id: 'directory' }), null);
    await service().removeRelay(id(1));
    const catalog = await accounts.findOne({ _id: 'directory' });
    assert.equal(catalog.accounts[0].id, String(original._id));
    assert.equal((await users()).length, 0);
    await service().installRelay(id(1));
    const [replica] = await users(id(1));
    assert.ok(replica.passwordEncrypted === original.passwordEncrypted);
    assert.equal(replica.login, original.login);
    assert.ok(same(catalog, await accounts.findOne({ _id: 'directory' })));
});

const recoveryLogin = 'pending-user';
const majority = { readPreference: 'primary', readConcern: { level: 'majority' } };
const runRecovery = (name, fn) => test(`legacy pending recovery: ${name}`, { skip: !port }, async t => fn(await fixture(t, 2)));

async function beginRecovery(f, action) {
    const { service, accounts, enrollment, hosts } = f;
    const ids = enrollment.map(row => row.nodeId);
    for (const nodeId of ids) await service().installRelay(nodeId);
    await service().createRelayAccount({ login: recoveryLogin, password: 'fixture-pending' });
    await service().createRelayAccount({ login: 'neighbor-user', password: 'fixture-neighbor' });

    const readRows = () => User.collection.find({}, majority).sort({ _id: 1 }).toArray();
    const readDirectory = () => accounts.findOne({ _id: 'directory' }, majority);
    const readPending = () => accounts.findOne({ _id: 'pending' }, majority);
    const readLock = () => db.collection('c3_rebuild_locks').findOne({ _id: 'apply' }, majority);
    const rows = await readRows(), directory = await readDirectory();
    assert.equal(rows.length, 6);
    assert.equal(directory.accounts.length, 3);
    const target = nodeId => rows.find(row => String(row.relayNode) === nodeId && row.login === recoveryLogin);
    const relays = await Promise.all(enrollment.map(async binding => {
        const { backupId, clientCidr, tproxyPort, fwmark, routeTable } = await State.findOne({ node: binding.nodeId }).lean();
        const { ip, desiredRevision: revision } = target(binding.nodeId);
        return { ...binding, backupId, network: { clientCidr, tproxyPort, fwmark, routeTable }, ip, revision };
    }));
    // The released begin stored only this intent (no host progress or desired inventory).
    const intent = { intentId: randomUUID(), action, login: recoveryLogin, createdAt: new Date(0), relays };
    await createRebuildRelayAccountsStore({ Node, State, L2tpUser: User }).begin(intent);
    const pending = { _id: 'pending', ...intent };
    assert.deepEqual(await readPending(), pending);

    f.calls.length = 0;
    await assert.rejects(service().installRelay(ids[0]), { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED' });
    assert.deepEqual(f.calls, [], 'the genuine pending gate refuses a sibling writer before host access');
    assert.equal(await readLock(), null);

    const sessions = new Map(ids.map(nodeId => [nodeId, hosts.get(nodeId).map(([login, , ip]) => [login, ip])]));
    const withoutTarget = values => values.filter(([login]) => login !== recoveryLogin);
    const events = [];
    let lockToken;
    const assertUnpublished = async () => {
        assert.ok(same(await readRows(), rows), 'original projection rows remain unchanged');
        assert.ok(same(await readDirectory(), directory), 'original directory remains unchanged');
    };
    const reconcile = ({ unknownNode, beforeFence } = {}) => service((nodeId, binding) => {
        assert.deepEqual(binding, enrollment.find(row => row.nodeId === nodeId));
        const step = async name => {
            const lock = await readLock();
            assert.match(lock?.token, /^[0-9a-f-]{36}$/);
            if (lockToken === undefined) {
                lockToken = lock.token;
                await assert.rejects(service().reconcileRelayAccounts(), { code: 'REBUILD_BUSY' });
            }
            assert.equal(lock.token, lockToken);
            assert.deepEqual(await readPending(), pending);
            events.push(`${name}:${nodeId}`);
        };
        const assertTarget = (current, revokedLogin, enabled) => {
            assert.equal(revokedLogin, recoveryLogin);
            const before = current.find(row => row.login === revokedLogin);
            assert.equal(before?.ipAddress, target(nodeId).ip);
            assert.equal(before.enabled, enabled);
        };
        const isTarget = ([login, ip]) => login === recoveryLogin && ip === target(nodeId).ip;
        return {
            async inspectChap(_installation, current, desired, guard, revokedLogin) {
                await guard();
                assertTarget(current, revokedLogin, true);
                await step('inspect');
                if (nodeId === unknownNode) throw new Error('fixture PPP census unavailable');
                const projection = same(hosts.get(nodeId), rendered(current)) ? 'original'
                    : same(hosts.get(nodeId), rendered(desired)) ? 'desired' : 'unknown';
                return { projection, activeTargetSessions: sessions.get(nodeId).filter(isTarget).length };
            },
            async fenceChap(installation, current, desired, guard, revokedLogin) {
                await guard();
                assert.equal(installation.nodeId, nodeId);
                assertTarget(current, revokedLogin, true);
                assert.ok(!rendered(desired).some(([login]) => login === revokedLogin));
                await step('fence');
                await beforeFence?.(nodeId);
                return { fenced: true };
            },
            async syncChap(_installation, current, desired, guard, revokedLogin) {
                await step('sync');
                await guard();
                assert.ok(same(rendered(current), hosts.get(nodeId)), 'exact live CHAP preimage');
                const changed = !same(rendered(desired), hosts.get(nodeId));
                assertTarget(current, revokedLogin, changed);
                if (changed) hosts.set(nodeId, rendered(desired));
                const before = sessions.get(nodeId);
                const remaining = before.filter(row => !isTarget(row));
                sessions.set(nodeId, remaining);
                return { changed, complete: true, sessionsTerminated: before.length - remaining.length };
            },
            async close() {
                await step('close');
                await assertUnpublished();
            },
        };
    }).reconcileRelayAccounts();
    const inspectionPass = ids.map(nodeId => `inspect:${nodeId}`);
    const fencePass = [...inspectionPass, ...ids.map(nodeId => `fence:${nodeId}`), ...inspectionPass];
    return { ids, rows, directory, pending, readRows, readDirectory, readPending, readLock, sessions, withoutTarget,
        events, inspectionPass, fencePass, reconcile, assertUnpublished };
}

for (const [action, status] of [['disable', 'disabled'], ['delete', 'deleted']]) {
    runRecovery(`${action} drains live target PPP after CHAP and publishes only the target`, async f => {
        const r = await beginRecovery(f, action);
        const [a, b] = r.ids;
        for (const nodeId of r.ids) f.hosts.set(nodeId, r.withoutTarget(f.hosts.get(nodeId)));
        // B already closed its target before recovery; A still has a live call.
        // Both hosts keep their neighboring/bootstrap sessions.
        r.sessions.set(b, r.withoutTarget(r.sessions.get(b)));
        const chap = structuredClone(f.hosts);
        const neighbors = new Map(r.ids.map(nodeId => [nodeId, r.withoutTarget(r.sessions.get(nodeId))]));

        assert.deepEqual(await r.reconcile(), { executionMode: 'rebuild', status, login: recoveryLogin,
            relayCount: 2, recovered: true, sessionsTerminated: 1 });
        assert.deepEqual(r.events.filter(event => !event.startsWith('close:')),
            [...r.fencePass, `sync:${a}`, ...r.inspectionPass]);
        assert.deepEqual(r.events.slice(-2).sort(), [`close:${a}`, `close:${b}`]);
        assert.ok(same([...f.hosts], [...chap]), 'CHAP is unchanged on both relays');
        assert.deepEqual(r.sessions, neighbors);

        const rows = await r.readRows(), directory = await r.readDirectory();
        const isNeighbor = row => row.login !== recoveryLogin;
        assert.ok(same(rows.filter(isNeighbor), r.rows.filter(isNeighbor)), 'full neighboring Mongo rows are unchanged');
        assert.notEqual(directory.generation, r.directory.generation);
        const expectedDirectory = action === 'delete' ? r.directory.accounts.filter(isNeighbor)
            : r.directory.accounts.map(row => isNeighbor(row) ? row : { ...row, enabled: false });
        assert.ok(same(directory.accounts, expectedDirectory), 'only the target directory entry changes');
        const targets = rows.filter(row => !isNeighbor(row));
        if (action === 'delete') assert.equal(targets.length, 0);
        else {
            const expected = r.rows.filter(row => !isNeighbor(row)).map(row => ({ ...row, enabled: false,
                desiredRevision: row.desiredRevision + 1, appliedRevision: row.appliedRevision + 1 }));
            const stable = ({ lastSyncedAt, updatedAt, ...row }) => row;
            assert.ok(same(targets.map(stable), expected.map(stable)), 'both disabled replicas retain identity and advance revisions');
        }
        assert.equal(await r.readPending(), null);
        assert.equal(await r.readLock(), null);
    });
}

for (const unknown of [false, true]) {
    runRecovery(unknown ? 'an unknown second host retains the intent without dispatch' : 'all-original CHAP cancels without replay', async f => {
        const r = await beginRecovery(f, 'delete');
        const [a, b] = r.ids;
        // A needs a target drain if B can be classified; do not dispatch it
        // while B's census is unknown.
        if (unknown) f.hosts.set(a, r.withoutTarget(f.hosts.get(a)));
        const chap = structuredClone(f.hosts), sessions = structuredClone(r.sessions);

        if (unknown) {
            await assert.rejects(r.reconcile({ unknownNode: b }), { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED', intentId: r.pending.intentId,
                retryAllowed: false, confirmedNodeIds: [], confirmedSessionsTerminated: 0 });
        } else {
            assert.deepEqual(await r.reconcile(), { executionMode: 'rebuild', status: 'canceled', login: recoveryLogin,
                relayCount: 2, recovered: true, sessionsTerminated: 0 });
        }
        const expectedPass = unknown ? r.inspectionPass : r.fencePass;
        assert.deepEqual(r.events.slice(0, expectedPass.length), expectedPass);
        assert.deepEqual(r.events.slice(expectedPass.length).sort(), [`close:${a}`, `close:${b}`]);
        assert.ok(same([...f.hosts], [...chap]), 'CHAP was not replayed');
        assert.deepEqual(r.sessions, sessions);
        await r.assertUnpublished();
        assert.deepEqual(await r.readPending(), unknown ? r.pending : null);
        assert.equal(await r.readLock(), null);
    });
}

runRecovery('late original writer before B fence cannot cause stale cancellation', async f => {
    const r = await beginRecovery(f, 'delete');
    const [a, b] = r.ids;
    const remainingSessions = new Map(r.ids.map(nodeId => [nodeId, r.withoutTarget(r.sessions.get(nodeId))]));
    assert.deepEqual(await r.reconcile({ async beforeFence(nodeId) {
        if (nodeId !== b) return;
        assert.deepEqual(r.events, [...r.inspectionPass, `fence:${a}`, `fence:${b}`]);
        assert.deepEqual(await r.readPending(), r.pending);
        await r.assertUnpublished();
        // The old command had acquired B's host lock just before rotation.
        f.hosts.set(b, r.withoutTarget(f.hosts.get(b)));
        r.sessions.set(b, remainingSessions.get(b));
    } }), { executionMode: 'rebuild', status: 'deleted', login: recoveryLogin,
        relayCount: 2, recovered: true, sessionsTerminated: 1 });
    assert.deepEqual(r.events.filter(event => !event.startsWith('close:')),
        [...r.fencePass, `sync:${a}`, ...r.inspectionPass]);
    assert.deepEqual(r.sessions, remainingSessions);
    assert.deepEqual(await r.readRows(), r.rows.filter(row => row.login !== recoveryLogin));
    assert.deepEqual((await r.readDirectory()).accounts, r.directory.accounts.filter(row => row.login !== recoveryLogin));
    assert.equal(await r.readPending(), null);
    assert.equal(await r.readLock(), null);
});
