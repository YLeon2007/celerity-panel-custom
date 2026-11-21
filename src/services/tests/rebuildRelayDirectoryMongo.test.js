'use strict';

// Run only with a fresh loopback-only fixture replica set in a private netns.
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { randomBytes } = require('node:crypto');
const { createRebuildService } = require('../rebuildService');
const { createRebuildL2tpOverview } = require('../rebuildL2tpOverview');
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

async function fixture(t) {
    assert.match(port, /^\d{4,5}$/);
    assert.deepEqual(Object.keys(require('node:os').networkInterfaces()), ['lo']);
    await mongoose.connect(`mongodb://127.0.0.1:${port}/?directConnection=true`, {
        dbName: `c3_directory_fixture_${randomBytes(8).toString('hex')}`, serverSelectionTimeoutMS: 2000,
    });
    t.after(async () => { try { await db.dropDatabase(); } finally { await mongoose.disconnect(); } });
    await Promise.all([Node, Link, State, User].map(model => model.init()));
    const accounts = db.collection('c3_rebuild_relay_accounts');
    const enrollment = [1, 2, 3].map(n => ({ nodeId: id(n), host: `192.0.2.${n}`, port: 22, username: 'root',
        sshHostKeySha256: String(n).repeat(64), machineId: machine(n) }));
    await Node.collection.insertMany(enrollment.map(({ nodeId, host: ip, port, username }) => ({
        _id: new mongoose.Types.ObjectId(nodeId), ip, active: true, type: 'xray', cascadeRole: 'relay', ssh: { port, username },
    })));
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
        C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify(enrollment), ENCRYPTION_KEY: 'fixture-only-key-'.repeat(3) };
    const hosts = new Map(), calls = [];
    const service = () => createRebuildService({ Node, Link, State, L2tpUser: User, env, cache: {}, sync: {},
        createRelayDirect: ({ node }) => {
            const nodeId = String(node._id);
            calls.push(nodeId);
            const rendered = users => users.filter(u => u.enabled).map(({ login, password, ipAddress }) =>
                [login, password, ipAddress]).sort((a, b) => a[0].localeCompare(b[0]));
            function check(users) { assert.ok(same(rendered(users), hosts.get(nodeId)), 'selected CHAP preimage'); }
            return {
                preflight: async () => ({ ppp: true, masked: false, machineId: enrollment.find(x => x.nodeId === nodeId).machineId }),
                prepare: async ({ desired }) => ({ desired, backupId: randomBytes(16).toString('hex') }),
                install: async ({ desired }, guard) => {
                    await guard(); assert.equal(hosts.has(nodeId), false); hosts.set(nodeId, rendered(desired.users)); return true;
                },
                verify: async ({ desired }) => { check(desired.users); return true; },
                checkChap: async (_, current, desired, guard) => { await guard(); check(current); return { changed: !same(current, desired) }; },
                syncChap: async (_, current, desired, guard) => {
                    await guard(); check(current); hosts.set(nodeId, rendered(desired)); return { changed: !same(current, desired) };
                },
                readSessionCount: async () => ({ activeSessions: 0, census: 'a'.repeat(64) }),
                prepareRemove: async ({ currentUsers }) => { if (currentUsers) check(currentUsers); return {}; },
                remove: async (_, guard) => {
                    await guard(); hosts.delete(nodeId); return true;
                },
                close: async () => {},
            };
        },
    });
    const users = nodeId => User.find({ ...(nodeId && { relayNode: nodeId }) }).select('+passwordEncrypted').sort('login').lean();
    return { service, env, users, hosts, calls, accounts, overview: () => createRebuildL2tpOverview({ Node, State, L2tpUser: User, env }) };
}

const run = (name, fn) => test(name, { skip: !port }, async t => fn(await fixture(t), t));
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
