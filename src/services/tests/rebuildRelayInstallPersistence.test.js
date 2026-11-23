'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: equal } = require('node:util');
const { Types, mongo } = require('mongoose');
const { createRebuildService } = require('../rebuildService');
const { createRebuildRelayInstallRecovery } = require('../rebuildRelayInstallRecovery');
const { makeDesired } = require('../rebuildRelayBackendDesired');
const { makeLocks, withNode } = require('../rebuildLocks');
const { decrypt, encrypt } = require('../../modules/relay-l2tp/services/secretBoxService');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
const Node = require('../../models/hyNodeModel');
const Link = require('../../models/cascadeLinkModel');
const joined = require('./helpers/rebuildRelayInstallJoined');
const { bindDirectory } = require('./helpers/rebuildRelayDirectoryFixture');

const id = 'a'.repeat(24), machineId = 'b'.repeat(32), backupId = 'rebuild-unique-backup';
const oid = value => new Types.ObjectId(value);
const copy = value => mongo.BSON.deserialize(mongo.BSON.serialize(value));
const projectedCopy = (value, promoteValues = true) => mongo.BSON.deserialize(mongo.BSON.serialize(value), { promoteValues });
const sameBson = (a, b) => mongo.BSON.serialize(a).equals(mongo.BSON.serialize(b));
const matches = (row, where) => Object.entries(where).every(([key, value]) => {
    if (key === '$expr') {
        assert.equal(value.$eq[0], '$$ROOT');
        return sameBson(row, value.$eq[1].$literal);
    }
    if (key === '$or') return value.some(filter => matches(row, filter));
    if (key === '$nor') return !value.some(filter => matches(row, filter));
    if (value && Object.hasOwn(value, '$exists')) return Object.hasOwn(row, key) === value.$exists
        && (!Object.hasOwn(value, '$eq') || equal(row[key], value.$eq));
    if (value && Object.hasOwn(value, '$eq')) return equal(row[key], value.$eq);
    if (value && Object.hasOwn(value, '$ne')) return !equal(row[key], value.$ne);
    if (value && Object.hasOwn(value, '$in')) return value.$in.some(item => equal(row[key], item));
    if (value === null) return row[key] == null;
    return equal(row[key], value);
});
function project(row, projection, promoteValues) {
    if (!row) return null;
    const columns = Object.keys(projection ?? {});
    if (columns.some(key => projection[key] === 1)) return projectedCopy(Object.fromEntries(
        Object.entries(row).filter(([key]) => key === '_id' || projection[key] === 1)), promoteValues);
    return projectedCopy(Object.fromEntries(Object.entries(row).filter(([key]) => projection?.[key] !== 0)), promoteValues);
}

// Real Mongoose schemas, casting and projections. Only the backing collection
// and direct host commands are simulated; no process, Mongo URI or SSH socket.
function bind(t, model, data, traces) {
    const handlers = {};
    const selectRows = session => session ? session.rows.get(data) : data;
    const invoke = async (kind, where, update, options) => {
        assert.ok((where._id?.$eq ?? where._id) instanceof Types.ObjectId);
        assert.deepEqual(options.writeConcern, options.session ? undefined : { w: 'majority' });
        traces.push(`${model.modelName}:${kind}`);
        const rows = selectRows(options.session);
        const index = rows.findIndex(row => matches(row, where));
        const apply = () => {
            if (kind === 'delete') {
                if (index !== -1) rows.splice(index, 1);
                return { acknowledged: true, deletedCount: Number(index !== -1) };
            }
            if (index === -1 && options.upsert) {
                rows.push(copy(update.$setOnInsert));
                return { acknowledged: true, upsertedCount: 1, matchedCount: 0 };
            }
            if (index !== -1 && Array.isArray(update)) {
                rows[index] = update[0].$replaceWith.$literal;
            } else if (index !== -1) {
                Object.assign(rows[index], copy(update.$set ?? {}));
                for (const key of Object.keys(update.$unset ?? {})) delete rows[index][key];
            }
            return { acknowledged: true, matchedCount: Number(index !== -1), upsertedCount: 0 };
        };
        return handlers[kind] ? handlers[kind]({ update, apply }) : apply();
    };
    t.mock.method(model.collection, 'findOne', async (where, { projection, session } = {}) => project(
        selectRows(session).find(row => matches(row, where)), projection));
    t.mock.method(model.collection, 'find', (where, { projection, limit, session, sort, promoteValues } = {}) => ({
        toArray: async () => {
            const rows = selectRows(session).filter(row => matches(row, where));
            if (sort) rows.sort((a, b) => String(a._id).localeCompare(String(b._id)));
            return rows.slice(0, limit).map(row => project(row, projection, promoteValues));
        },
    }));
    t.mock.method(model.collection, 'countDocuments', async (where, { session } = {}) =>
        selectRows(session).filter(row => matches(row, where)).length);
    if (model === User) t.mock.method(model.collection, 'insertMany', async (documents, options) => {
        assert.ok(options.session);
        const rows = selectRows(options.session);
        for (const row of documents) {
            assert.ok(!rows.some(existing => equal(existing._id, row._id) || (equal(existing.relayNode, row.relayNode)
                && (existing.login === row.login || existing.ip === row.ip))));
            rows.push(copy(row));
        }
        return { acknowledged: true, insertedCount: documents.length, insertedIds: documents.map(row => row._id) };
    });
    t.mock.method(model.collection, 'updateMany', (where, update, options) => invoke('update', where, update, options));
    t.mock.method(model.collection, 'deleteMany', (where, options) => invoke('delete', where, null, options));
    return handlers;
}

function deferred() {
    let done;
    const promise = new Promise(resolve => { done = resolve; });
    return { promise, done };
}
function fixture(t, planBackupId = backupId) {
    const directory = bindDirectory(t, User.db);
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: id,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, ENCRYPTION_KEY: 'test-only-credential-key-'.repeat(2), PANEL_DOMAIN: 'fixture.invalid' };
    const nodes = [{ _id: oid(id), ip: '192.0.2.4', domain: 'relay.fixture.invalid', type: 'xray', active: true,
        cascadeRole: 'relay', ssh: { port: 22, username: 'root' } }];
    const links = [], states = [], users = [], events = [];
    const stateHooks = bind(t, State, states, events);
    const userHooks = bind(t, User, users, events);
    bind(t, Node, nodes, events);
    bind(t, Link, links, events);
    const locks = [];
    const lockRows = session => session ? session.rows.get(locks) : locks;
    const lockHooks = {};
    const lockCollection = {
        async insertOne(row) {
            if (locks.length) throw Object.assign(new Error('duplicate'), { code: 11000 });
            locks.push(row);
            return { acknowledged: true };
        },
        async findOne(filter, options) {
            const row = lockRows(options?.session).find(row => matches(row, filter));
            return row ? copy(row) : null;
        },
        async updateOne(filter, { $set: { heartbeat } }) {
            const row = locks.find(row => matches(row, filter));
            if (row) row.heartbeat = heartbeat;
            return { acknowledged: true, matchedCount: Number(!!row) };
        },
        async updateMany(filter, update, options) {
            assert.ok(options.session || options.writeConcern?.w === 'majority');
            const row = lockRows(options.session).find(row => matches(row, filter));
            if (row) {
                for (const [key, value] of Object.entries(update.$set ?? {})) {
                    if (key === 'installRecovery.phase') row.installRecovery.phase = value;
                    else row[key] = value;
                }
                for (const key of Object.keys(update.$unset ?? {})) delete row[key];
            }
            return { acknowledged: true, matchedCount: Number(!!row) };
        },
        async deleteMany(filter, options) {
            const rows = lockRows(options?.session);
            const index = rows.findIndex(row => matches(row, filter));
            const matched = index >= 0 && !lockHooks.refuseRelease;
            if (matched) rows.splice(index, 1);
            return { acknowledged: true, deletedCount: Number(matched) };
        },
    };
    const originalCollection = State.db.collection.bind(State.db);
    t.mock.method(State.db, 'collection', (name, ...args) => name === 'c3_rebuild_locks' ? lockCollection
        : originalCollection(name, ...args));
    const plan = { backupId: planBackupId };
    let prepared;
    const hooks = {
        preflight: async () => ({ ppp: true, masked: false, unitsLoaded: true, machineId }),
        prepare: async () => plan,
        install: async guard => { await guard(); return true; },
        verify: async () => true,
        rollback: async guard => { await guard(); return true; },
        close: async () => {},
        checkChap: async () => ({ changed: false }),
    };
    const deps = { Node, Link, State, L2tpUser: User, env, cache: {}, sync: {}, locks: makeLocks(lockCollection),
        assertNoRelayAccountIntent: async () => {},
        createRelayDirect: ({ node, env: driverEnv }) => {
            assert.equal(driverEnv, env);
            if (String(node._id) !== id) {
                events.push('source-connect');
                assert.ok(locks[0]);
                return {
                    async checkChap(installation, current, desired, guard) {
                        await guard();
                        events.push('source-check');
                        assert.ok(locks[0]);
                        return hooks.checkChap(installation, current, desired);
                    },
                    async close() { events.push('source-close'); },
                };
            }
            events.push('connect');
            assert.deepEqual(node.ssh, nodes[0].ssh);
            return {
                async preflight() { events.push('preflight'); return hooks.preflight(); },
                async prepare(args) { events.push('prepare'); prepared = args; return hooks.prepare(); },
                async install(p, guard) { events.push('install'); assert.equal(p, plan); return hooks.install(guard); },
                async verify(p) { events.push('verify'); assert.equal(p, plan); return hooks.verify(); },
                async rollback(p, guard) { events.push('rollback'); assert.equal(p, plan); return hooks.rollback(guard); },
                async close() { events.push('close'); return hooks.close(); },
            };
        },
    };
    const create = overrides => createRebuildService({ ...deps, ...overrides });
    const enrollment = () => nodes.map(({ _id, ip: host, ssh: { port, username } }, i) => ({
        nodeId: String(_id), host, port, username, sshHostKeySha256: String(i + 1).repeat(64),
        machineId: i === 0 ? machineId : states.find(row => String(row.node) === String(_id))?.rebuildMachineId,
    }));
    const enroll = (rows = enrollment()) => {
        env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(rows);
        return create().installRelay;
    };
    return { env, events, create, enroll, enrollment, nodes, links, states, users, hooks, stateHooks, userHooks, directory,
        deps, locks, lockCollection, lockHooks, plan,
        get prepared() { return prepared; },
        get lockHeld() { return !!locks[0]; },
        loseLock: () => { locks.length = 0; } };
}

function priorRow() {
    return { _id: oid(), node: oid(id), desiredState: 'absent', status: 'not_installed', secretRevision: 0,
        clientCidr: '10.66.0.0/24', pskEncrypted: '', tproxyPort: null, routeGroup: null, updatedAt: new Date('2020-01-02') };
}

const sourceId = '6'.repeat(24), sourceMachineId = '7'.repeat(32);
function addSource(f, { source = sourceId, machine = sourceMachineId, prefix = '10.255.31', accounts } = {}) {
    const clock = new Date('2026-01-02');
    const node = { ...f.nodes[0], _id: oid(source), ip: `192.0.2.${30 + f.nodes.length}` };
    const state = { _id: oid(), node: node._id, status: 'installed', desiredState: 'installed', routingMode: 'follow-relay',
        routingVersion: 1, rebuildMachineId: machine, rebuildInstallToken: '00000000-0000-4000-8000-000000000003',
        backupId: '1'.repeat(32), secretRevision: 1, pskEncrypted: 'fixture-opaque-psk',
        installedAt: clock, lastVerifiedAt: clock, lastSyncAt: clock,
        clientCidr: `${prefix}.0/24`, localAddress: `${prefix}.1`, poolStart: `${prefix}.10`, poolEnd: `${prefix}.250`,
        tproxyPort: 12345, fwmark: 100, routeTable: 100 };
    const users = (accounts ?? [
        { login: 'relay-bootstrap', enabled: true, passwordEncrypted: encrypt('inherited-one', f.env.ENCRYPTION_KEY) },
        { login: 'disabled-user', enabled: false, passwordEncrypted: encrypt('inherited-two', f.env.ENCRYPTION_KEY) },
    ]).map(({ login, enabled, passwordEncrypted }, i) => ({ _id: oid(), relayNode: node._id,
        login, ip: `${prefix}.${i + 10}`, enabled, passwordEncrypted, desiredRevision: 2, appliedRevision: 2,
        syncStatus: 'synced', createdAt: clock, updatedAt: clock, lastSyncedAt: clock }));
    f.nodes.push(node);
    f.states.push(state);
    f.users.push(...users);
    return { node, state, users };
}

// Model only the local collection/session boundary, never a host or stand.
function sessionFixture(t, f, { graph = false } = {}) {
    const events = [], hooks = {};
    class Session {
        transaction = { transition: state => {
            hooks.transition?.();
            this.active = state !== 'TRANSACTION_COMMITTED';
        } };
        startTransaction(options) {
            assert.deepEqual(options, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            this.active = true;
            this.rows = new Map([f.states, f.users, f.nodes, f.links, f.locks].map(rows => [rows, rows.map(row => copy(row))]));
        }
        inTransaction() { return this.active; }
        abortTransaction() { events.push('abort'); this.active = false; }
        async commitTransaction() {
            assert.ok(this.active);
            events.push('commit');
            commit(this);
            this.active = false;
        }
        endSession() {
            const result = hooks.end?.();
            assert.equal(this.active, false);
            return result;
        }
    }
    function commit(session) {
        for (const rows of [f.states, f.users, f.locks, ...(graph ? [f.links, f.nodes] : [])]) {
            rows.splice(0, rows.length, ...session.rows.get(rows));
        }
        session.commitAccountIntent?.();
        session.commitDirectory?.();
        return { ok: 1 };
    }
    t.mock.method(State.db, 'startSession', async () => new Session());
    t.mock.method(State.db, 'getClient', () => ({ db(name) {
        assert.equal(name, 'admin');
        return { async command(command, { session }) {
            assert.equal(command.commitTransaction, 1);
            assert.equal(command.writeConcern.w, 'majority');
            assert.ok(session.inTransaction());
            events.push('commit');
            return hooks.commit ? hooks.commit(() => commit(session)) : commit(session);
        } };
    } }));
    return { events, hooks };
}

function recoveryFixture(t, { prior = false, source = false, pkg = false } = {}) {
    const planId = 'f'.repeat(32), actor = 'fixture-admin';
    const f = fixture(t, planId);
    const tx = sessionFixture(t, f);
    const before = prior ? priorRow() : null;
    if (before) f.states.push(copy(before));
    const neighbor = source && addSource(f);
    const enrollment = f.enrollment();
    f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(enrollment);
    let generation = 'original-grant', recovered = 0, closed = 0, packageBackup;
    const relayGrantStore = { snapshot: async () => ({ env: f.env,
        grants: [{ nodeId: id, generation }], sourceFor: n => n === id ? 'db' : 'env' }) };
    const hooks = { reconcile: async (_input, verifyLock) => { await verifyLock(); return 'absent'; },
        close: async () => {} };
    const installDeps = { ...f.deps, relayGrantStore, actor, createRelayDirect: options => {
        const direct = f.deps.createRelayDirect(options);
        return { ...direct, async preparePackages(backup, guard) { await guard(); packageBackup = backup; return true; } };
    } };
    if (pkg) {
        f.hooks.preflight = async () => ({ machineId, packagePreparation: '9'.repeat(64) });
        f.hooks.prepare = () => { f.plan.backupId = packageBackup; return f.plan; };
    }
    // Use the actual Install producer and the actual lock for the admission
    // receipt. The remote deliberately loses its reply at the first write.
    f.hooks.install = async guard => { await guard(); throw new Error('unacknowledged install'); };
    const install = target => f.create(installDeps).installRelay(target, { actor });
    const create = overrides => createRebuildRelayInstallRecovery({ ...installDeps,
        locks: makeLocks(f.lockCollection), createRelayDirect: async ({ fence }) => {
            assert.equal(fence.source, 'db');
            return {
                async reconcileInstall(input, verifyLock) { recovered++; return hooks.reconcile(input, verifyLock); },
                async close() { closed++; return hooks.close(); },
            };
        }, ...overrides });
    return { f, tx, before, neighbor, actor, install, create, hooks, generation: value => { generation = value; },
        get recovered() { return recovered; }, get closed() { return closed; },
        get backupId() { return pkg ? packageBackup : planId; } };
}

const notConfirmed = { code: 'REBUILD_L2TP_INSTALL_RECOVERY_UNCONFIRMED', retryAllowed: false };
const recoveryBlocked = { code: 'REBUILD_L2TP_INSTALL_RECOVERY_BLOCKED', retryAllowed: false };
const recoveryNoState = { code: 'REBUILD_L2TP_INSTALL_RECOVERY_NO_STATE', retryAllowed: false };

test('Install recovery: authorized empty state is distinct from an in-flight Install, orphan state or failed read', async t => {
    const r = recoveryFixture(t);
    const run = r.create({ createRelayDirect: () => assert.fail('must not create transport') });
    await assert.rejects(run(id), recoveryNoState);
    r.f.states.push(priorRow());
    await assert.rejects(run(id), recoveryNoState);
    r.f.states[0].backupId = 'f'.repeat(32);
    await assert.rejects(run(id), recoveryBlocked);
    r.f.states.length = 0;
    r.f.users.push({ _id: new Types.ObjectId(), relayNode: oid(id) });
    await assert.rejects(run(id), recoveryBlocked);
    r.f.users.length = 0;
    const findState = State.collection.find;
    t.mock.method(State.collection, 'find', () => { throw new Error('untrusted state read'); });
    await assert.rejects(run(id), recoveryBlocked);
    State.collection.find.mock.mockImplementation(findState);
    await makeLocks(r.f.lockCollection).run(async () => {
        await assert.rejects(run(id), recoveryBlocked);
    }, { allowStaleUnlock: false });
    const exactRead = r.f.lockCollection.findOne;
    t.mock.method(r.f.lockCollection, 'findOne', async () => { throw new Error('untrusted DB detail'); });
    await assert.rejects(run(id), recoveryBlocked);
    let reads = 0;
    r.f.lockCollection.findOne.mock.mockImplementation(async () => ++reads === 1 ? null : { _id: 'apply' });
    await assert.rejects(run(id), recoveryBlocked);
    assert.equal(reads, 2);
    r.f.lockCollection.findOne.mock.mockImplementation(exactRead);
    await assert.rejects(r.create({ relayGrantStore: { snapshot: async () => ({
        env: r.f.env, grants: [], sourceFor: () => 'env',
    }) } })(id), recoveryBlocked);
    assert.deepEqual(r.tx.events, []);
});

test('Install recovery: absent and rolled-back receipts restore only this relay, or preserve unresolved ownership', async t => {
    for (const result of ['absent', 'rolled_back', 'unsafe']) await t.test(result, async t => {
        const r = recoveryFixture(t, { prior: result === 'rolled_back', pkg: result === 'rolled_back', source: true });
        const { f } = r;
        const directory = { _id: 'directory', version: 1, generation: require('node:crypto').randomUUID(),
            accounts: r.neighbor.users.map(({ _id, login, enabled, passwordEncrypted }) =>
                ({ id: String(_id), login, enabled, passwordEncrypted })) };
        await f.directory.updateMany({ _id: 'directory', generation: directory.generation }, { $setOnInsert: directory },
            { upsert: true, writeConcern: { w: 'majority' } });
        await assert.rejects(r.install(id), { retryAllowed: false });
        const target = f.states.find(row => String(row.node) === id);
        assert.equal(target.backupId, r.backupId);
        assert.equal(f.locks[0].installRecovery.phase, 'ready');
        assert.deepEqual(await f.deps.locks.status(), { locked: true, stale: false });
        const original = copy({ states: f.states, users: f.users, locks: f.locks });
        r.hooks.reconcile = async (input, guard) => {
            assert.deepEqual(input, { nodeId: id, backupId: r.backupId,
                network: { clientCidr: target.clientCidr, tproxyPort: target.tproxyPort, fwmark: target.fwmark, routeTable: target.routeTable },
                ...(result === 'rolled_back' && { packagePreparation: '9'.repeat(64) }) });
            await guard();
            return result;
        };
        if (result === 'unsafe') {
            await assert.rejects(r.create()(id), notConfirmed);
            assert.deepEqual(f.states, original.states);
            assert.deepEqual(f.users, original.users);
            const { installRecoveryClaim, ...stillHeld } = f.locks[0];
            assert.ok(installRecoveryClaim);
            assert.deepEqual(stillHeld, original.locks[0]);
            await assert.rejects(r.create()(id), recoveryBlocked);
        } else {
            assert.deepEqual(await r.create()(id), { status: 'can_install_again' });
            assert.equal(f.lockHeld, false);
            assert.deepEqual(f.users, r.neighbor.users);
            assert.ok(sameBson({ state: f.states.find(row => String(row.node) === id) ?? null }, { state: r.before }));
            assert.deepEqual(f.states.find(row => String(row.node) === sourceId), r.neighbor.state);
        }
        assert.deepEqual(await f.directory.findOne({ _id: 'directory' }, { readConcern: { level: 'majority' } }), directory);
        assert.equal(r.recovered, 1);
        assert.equal(r.closed, 1);
    });
});

test('Install recovery: wrong generations, actor, credentials, scope or a legacy singleton never reach DIRECT', async t => {
    for (const [name, change] of Object.entries({
        actor: r => ({ actor: `${r.actor}-other` }),
        missing: r => { r.f.locks.length = 0; },
        ordinary: r => { r.f.locks[0].allowStaleUnlock = true; },
        legacy: r => { delete r.f.locks[0].installRecovery; r.f.locks[0].heartbeat = new Date(0); },
        active: r => { r.f.locks[0].installRecovery.phase = 'installing'; r.f.locks[0].heartbeat = new Date(0); },
        target: r => { r.f.locks[0].installRecovery.nodeId = sourceId; },
        lockGeneration: r => { r.f.locks[0].token = require('node:crypto').randomUUID(); },
        grantGeneration: r => r.generation('new-grant-same-binding'),
        key: r => { r.f.env.ENCRYPTION_KEY += 'changed'; },
        hostKey: r => { const [row] = r.f.enrollment(); row.sshHostKeySha256 = '2'.repeat(64);
            r.f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([row]); },
        machine: r => { const [row] = r.f.enrollment(); row.machineId = '3'.repeat(32);
            r.f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([row]); },
        state: r => { r.f.states[0].unexpected = true; },
        backup: r => { r.f.states[0].backupId = '2'.repeat(32); },
        copies: r => { r.f.users[0].unexpected = true; },
        duplicate: r => { r.f.states.push({ ...r.f.states[0], _id: oid() }); },
    })) await t.test(name, async t => {
        const r = recoveryFixture(t);
        await assert.rejects(r.install(id), { retryAllowed: false });
        const overrides = change(r);
        const original = copy({ states: r.f.states, users: r.f.users, locks: r.f.locks });
        await assert.rejects(r.create(overrides)(id), recoveryBlocked);
        assert.deepEqual({ states: r.f.states, users: r.f.users, locks: r.f.locks }, original);
        assert.equal(r.recovered, 0);
    });
});

test('Install recovery: neither active Install nor another recovery admits a competing claimant', async t => {
    const r = recoveryFixture(t);
    const entered = deferred(), release = deferred();
    r.f.hooks.install = async guard => { await guard(); entered.done(); await release.promise; throw new Error(); };
    const installing = assert.rejects(r.install(id), { retryAllowed: false });
    await entered.promise;
    assert.equal(r.f.locks[0].installRecovery.phase, 'installing');
    await assert.rejects(r.create()(id), recoveryBlocked);
    release.done();
    await installing;
    const inFlight = deferred(), settled = deferred();
    r.hooks.reconcile = async (_input, guard) => { await guard(); inFlight.done(); await settled.promise; return 'absent'; };
    const recovery = r.create()(id);
    await inFlight.promise;
    await assert.rejects(r.create()(id), recoveryBlocked);
    await assert.rejects(r.install(id), { code: 'REBUILD_BUSY' });
    settled.done();
    assert.deepEqual(await recovery, { status: 'can_install_again' });
    assert.equal(r.recovered, 1);
});

test('Install recovery: unclassified transport failures, even before a reported guard, preserve the reservation', async t => {
    for (const cut of ['before guard', 'after guard', 'close']) await t.test(cut, async t => {
        const r = recoveryFixture(t);
        await assert.rejects(r.install(id), { retryAllowed: false });
        const original = copy({ states: r.f.states, users: r.f.users });
        const originalToken = r.f.locks[0].token;
        r.hooks.reconcile = async (_input, guard) => {
            if (cut !== 'before guard') await guard();
            if (cut !== 'close') throw Object.assign(new Error('private transport fault'), { noRequestSent: true });
            return 'rolled_back';
        };
        if (cut === 'close') r.hooks.close = () => { throw new Error('private close fault'); };
        await assert.rejects(r.create()(id), notConfirmed);
        assert.deepEqual({ states: r.f.states, users: r.f.users }, original);
        assert.equal(r.f.locks[0].token, originalToken);
        assert.equal(r.closed, 1);
        assert.deepEqual(r.tx.events, ['commit', 'commit']);
        await assert.rejects(r.create()(id), recoveryBlocked);
        assert.equal(r.recovered, 1);
    });
});

test('Install recovery: claim cleanup failure after acknowledged COMMIT releases only the exact undispatched claim', async t => {
    for (const drift of [false, true]) await t.test(drift ? 'CAS drift' : 'exact claim', async t => {
        const r = recoveryFixture(t);
        await assert.rejects(r.install(id), { retryAllowed: false });
        const before = copy({ states: r.f.states, users: r.f.users, locks: r.f.locks });
        r.tx.hooks.end = () => {
            assert.ok(r.f.locks[0].installRecoveryClaim, 'claim commit must have landed');
            if (drift) r.f.locks[0].unexpected = 'independently changed';
            throw new Error('private session cleanup fault');
        };
        await assert.rejects(r.create()(id), drift ? notConfirmed : recoveryBlocked);
        assert.equal(r.recovered, 0);
        assert.deepEqual(r.tx.events, ['commit', 'commit']);
        if (drift) {
            assert.ok(r.f.locks[0].installRecoveryClaim);
            assert.equal(r.f.locks[0].unexpected, 'independently changed');
        } else {
            assert.deepEqual({ states: r.f.states, users: r.f.users, locks: r.f.locks }, before);
            delete r.tx.hooks.end;
            assert.deepEqual(await r.create()(id), { status: 'can_install_again' });
        }
    });
});

test('Install recovery: an unacknowledged claim COMMIT neither dispatches nor clears a possibly committed claim', async t => {
    const r = recoveryFixture(t);
    await assert.rejects(r.install(id), { retryAllowed: false });
    r.tx.hooks.commit = write => { write(); throw Error('private lost claim ACK'); };
    await assert.rejects(r.create()(id), notConfirmed);
    assert.ok(r.f.locks[0].installRecoveryClaim);
    await assert.rejects(r.create()(id), recoveryBlocked);
    assert.equal(r.recovered, 0);
    assert.deepEqual(r.tx.events, ['commit', 'commit']);
});

test('Install recovery: the original transport must close before handing back its lock', async t => {
    const r = recoveryFixture(t);
    r.f.hooks.close = () => { throw new Error('private original close fault'); };
    await assert.rejects(r.install(id), { retryAllowed: false });
    assert.equal(r.f.locks[0].installRecovery.phase, 'installing');
    await assert.rejects(r.create()(id), recoveryBlocked);
    assert.equal(r.recovered, 0);
});

test('Install recovery: a final lock CAS miss aborts earlier copy and state CAS writes', async t => {
    const r = recoveryFixture(t, { prior: true, source: true });
    await assert.rejects(r.install(id), { retryAllowed: false });
    const original = copy({ states: r.f.states, users: r.f.users });
    const originalToken = r.f.locks[0].token;
    r.f.lockHooks.refuseRelease = true;
    await assert.rejects(r.create()(id), notConfirmed);
    assert.deepEqual(r.f.events.slice(-3), ['L2tpUser:delete', 'L2tpUser:delete', 'RelayL2tpState:update']);
    assert.deepEqual(r.tx.events, ['commit', 'commit', 'abort']);
    assert.deepEqual({ states: r.f.states, users: r.f.users }, original);
    assert.equal(r.f.locks[0].token, originalToken);
    assert.ok(r.f.locks[0].installRecoveryClaim);
});

test('Install recovery: lost settlement response is not replayed regardless of whether commit landed', async t => {
    for (const committed of [false, true]) await t.test({ false: 'uncommitted', true: 'committed' }[committed], async t => {
        const r = recoveryFixture(t);
        await assert.rejects(r.install(id), { retryAllowed: false });
        const original = copy({ states: r.f.states, users: r.f.users });
        const originalToken = r.f.locks[0].token;
        r.hooks.reconcile = async (_input, guard) => {
            await guard();
            r.tx.hooks.commit = write => { if (committed) write(); throw Error('private lost ACK'); };
            return 'rolled_back';
        };
        await assert.rejects(r.create()(id), notConfirmed);
        assert.deepEqual(r.tx.events, ['commit', 'commit', 'commit']);
        if (committed) assert.deepEqual({ states: r.f.states, users: r.f.users, locks: r.f.locks }, { states: [], users: [], locks: [] });
        else {
            assert.deepEqual({ states: r.f.states, users: r.f.users }, original);
            assert.equal(r.f.locks[0].token, originalToken);
        }
        // A new explicit request may observe empty storage, but cannot
        // retroactively confirm the earlier lost settlement response.
        await assert.rejects(r.create()(id), committed ? recoveryNoState : recoveryBlocked);
        assert.equal(r.recovered, 1);
        assert.deepEqual(r.tx.events, ['commit', 'commit', 'commit']);
    });
});

test('second relay inherits every login and exact ciphertext, including disabled accounts, before dispatch', async t => {
    const f = fixture(t);
    const session = sessionFixture(t, f);
    const source = addSource(f);
    const original = source.users.map(copy);
    const targets = () => f.users.filter(row => String(row.relayNode) === id);
    f.hooks.checkChap = async (installation, current, desired) => {
        assert.deepEqual(installation, { nodeId: sourceId, backupId: source.state.backupId,
            network: { clientCidr: source.state.clientCidr, tproxyPort: 12345, fwmark: 100, routeTable: 100 } });
        assert.deepEqual(current, original.map(row => ({ login: row.login, enabled: row.enabled, ipAddress: row.ip,
            password: decrypt(row.passwordEncrypted, f.env.ENCRYPTION_KEY) })).sort((a, b) => a.login.localeCompare(b.login)));
        assert.deepEqual(current, desired);
        return { changed: false };
    };
    f.hooks.install = async guard => {
        await guard();
        const rows = targets();
        assert.deepEqual(rows.map(row => row.login).sort(), source.users.map(row => row.login).sort());
        assert.equal(new Set(rows.map(row => row.ip)).size, 2);
        for (const row of rows) {
            const before = source.users.find(candidate => candidate.login === row.login);
            assert.ok(row.passwordEncrypted === before.passwordEncrypted);
            assert.equal(row.enabled, before.enabled);
            assert.notEqual(row.ip, before.ip);
            assert.equal(row.syncStatus, 'pending');
        }
    };
    await f.enroll()(id);
    assert.deepEqual(f.users.filter(row => String(row.relayNode) === sourceId), original);
    assert.deepEqual(session.events, ['commit', 'commit']);
    assert.deepEqual(targets().map(row => row.syncStatus), ['synced', 'synced']);
    const { desired } = f.prepared;
    assert.equal(targets().find(row => row.login === 'relay-bootstrap').ip, desired.poolStart);
    assert.deepEqual(f.events.slice(0, 4), ['source-connect', 'source-check', 'source-close', 'connect']);
    assert.notEqual(desired.clientCidr, source.state.clientCidr);
    for (const row of targets()) {
        assert.notEqual(row.ip, desired.localAddress);
        const rendered = desired.users.find(candidate => candidate.login === row.login);
        assert.equal(rendered.ipAddress, row.ip);
        assert.equal(rendered.enabled, row.enabled);
        assert.ok(rendered.password === decrypt(row.passwordEncrypted, f.env.ENCRYPTION_KEY));
    }
});

test('second relay refuses an unbound source, missing rows, invalid credentials or outstanding sync before writes', async t => {
    const cases = [
        ['no binding', () => {}, 'ACCOUNT_SOURCE_NOT_ENROLLED'],
        ['missing accounts', f => f.users.splice(0), 'ACCOUNT_INVENTORY_INVALID'],
        ['sync reservation', f => { f.users[0].syncOperationId = oid(); }, 'ACCOUNT_SOURCE_BUSY'],
        ['install reservation', f => { f.states[0].status = 'installing'; }, 'ACCOUNT_SOURCE_BUSY'],
        ['unowned installed state', f => {
            f.users.splice(0);
            Object.assign(f.states[0], { routingMode: 'route-group', rebuildInstallToken: null, rebuildMachineId: null });
        }, 'ACCOUNT_INVENTORY_INVALID'],
        ['damaged ciphertext', f => { f.users[0].passwordEncrypted = 'invalid-envelope'; }, 'ACCOUNT_INVENTORY_INVALID'],
        ['orphan', f => f.states.splice(0), 'ACCOUNT_INVENTORY_INVALID'],
    ];
    for (const [name, alter, code] of cases) await t.test(name, async child => {
        const f = fixture(child);
        addSource(f);
        const rows = f.enrollment();
        alter(f);
        const install = f.enroll(name === 'no binding' ? rows.slice(0, 1) : rows);
        await assert.rejects(install(id), { code: `REBUILD_L2TP_${code}` });
        assert.deepEqual(f.events, []);
    });
});

test('independent legacy bootstraps conflict even when plaintext is the same', async t => {
    const f = fixture(t);
    const legacy = () => [{ login: 'relay-bootstrap', enabled: true,
        passwordEncrypted: encrypt('fixture-bootstrap', f.env.ENCRYPTION_KEY) }];
    addSource(f, { accounts: legacy() });
    addSource(f, { source: '8'.repeat(24), machine: '9'.repeat(32), prefix: '10.255.32', accounts: legacy() });
    await assert.rejects(f.enroll()(id), { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_CONFLICT' });
    assert.deepEqual(f.events, []);
});

test('cohort install refuses source binding, physical and logical disagreements before reservation', async t => {
    for (const [name, expected, alter] of [
        ['persisted machine mismatch', 'ACCOUNT_SOURCE_NOT_ENROLLED', ({ rows }) => { rows[1].machineId = 'f'.repeat(32); }],
        ['source endpoint mismatch', 'ACCOUNT_SOURCE_NOT_ENROLLED', ({ f }) => { f.nodes[1].ssh = { port: 2322, username: 'root' }; }],
        ['legacy singleton cannot inherit', 'ACCOUNT_SOURCE_NOT_ENROLLED', ({ f }) => f.create().installRelay],
        ['bootstrap disabled', 'ACCOUNT_INVENTORY_INVALID', ({ source }) => { source.users[0].enabled = false; }],
        ['enrollment pin changed after prepare', 'ACCOUNT_SOURCE_NOT_ENROLLED', ({ f, rows }) => {
            f.hooks.prepare = async () => {
                rows[1].sshHostKeySha256 = 'f'.repeat(64);
                f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(rows);
                return { backupId };
            };
        }],
        ['source has unapplied CHAP', 'ACCOUNT_SOURCE_PREFLIGHT_REFUSED', ({ f }) => {
            f.hooks.checkChap = async () => { throw new Error('source CHAP no longer agrees with persisted rows'); };
        }],
        ['ambiguous CHAP reply', 'ACCOUNT_SOURCE_PREFLIGHT_REFUSED', ({ f }) => {
            f.hooks.checkChap = async () => ({ changed: true });
        }],
    ]) await t.test(name, async child => {
        const f = fixture(child);
        const source = addSource(f);
        const rows = f.enrollment();
        const install = alter({ f, source, rows }) ?? f.enroll(rows);
        const before = [f.states.map(copy), f.users.map(copy)];
        await assert.rejects(install(id), { code: `REBUILD_L2TP_${expected}` });
        assert.deepEqual([f.states, f.users], before);
        assert.ok(!f.events.some(x => x.includes(':') || x === 'install'));
        if (expected === 'ACCOUNT_SOURCE_PREFLIGHT_REFUSED') {
            assert.deepEqual(f.events, ['source-connect', 'source-check', 'source-close']);
        }
    });
});

test('third relay requires every source to agree and to pass read-only CHAP before opening the target', async t => {
    for (const scenario of ['agrees', 'login drift', 'enablement drift', 'CHAP refusal on last source']) {
        await t.test(scenario, async child => {
            const f = fixture(child);
            const session = sessionFixture(child, f);
            const first = addSource(f);
            const second = addSource(f, { source: '8'.repeat(24), machine: '9'.repeat(32), prefix: '10.255.32', accounts: first.users });
            second.node.ip = 'SOURCE2.fixture.invalid.';
            const rows = f.enrollment();
            rows[2].host = 'source2.fixture.invalid';
            // Per-relay revisions need only be locally settled.
            Object.assign(second.users[1], { desiredRevision: 8, appliedRevision: 8 });
            if (scenario === 'login drift') second.users[1].login = 'different-login';
            if (scenario === 'enablement drift') second.users[1].enabled = true;
            let checked = 0;
            f.hooks.checkChap = async () => {
                if (++checked === 2 && scenario === 'CHAP refusal on last source') throw new Error('refused');
                return { changed: false };
            };
            const install = f.enroll(rows);
            if (scenario === 'agrees') {
                assert.equal((await install(id)).status, 'installed');
                assert.equal(checked, 2);
                assert.ok(f.events.indexOf('connect') > f.events.lastIndexOf('source-close'));
                assert.deepEqual(session.events, ['commit', 'commit']);
            } else {
                const before = [f.states.map(copy), f.users.map(copy)];
                await assert.rejects(install(id), { code: scenario === 'CHAP refusal on last source'
                    ? 'REBUILD_L2TP_ACCOUNT_SOURCE_PREFLIGHT_REFUSED' : 'REBUILD_L2TP_ACCOUNT_SOURCE_CONFLICT' });
                assert.equal(checked, scenario === 'CHAP refusal on last source' ? 2 : 0);
                assert.deepEqual(session.events, []);
                assert.deepEqual([f.states, f.users], before);
                assert.ok(!f.events.includes('connect'));
            }
        });
    }
});

test('Install passes the pinned source and persisted projection to real DIRECT, with no write on CHAP refusal', async t => {
    const f = fixture(t);
    const { node, state, users } = addSource(f);
    const rows = f.enrollment();
    f.enroll(rows);
    const { createRelayDirect } = require('../rebuildRelayDirect');
    let sent, disconnected = false;
    class SSH {
        constructor(selected, { expectedEndpoint, expectedHostKeySha256 }) {
            assert.equal(selected._id, String(node._id));
            assert.deepEqual(expectedEndpoint, { ip: rows[1].host, port: rows[1].port, username: rows[1].username });
            assert.ok(expectedHostKeySha256 === rows[1].sshHostKeySha256);
        }
        async connect() { assert.ok(f.lockHeld); }
        disconnect() { disconnected = true; }
        async exec(command, { stdin }) {
            assert.ok(f.lockHeld);
            assert.equal(sent, undefined);
            sent = JSON.parse(stdin);
            return { code: 70, stderr: 'DIRECT_CHAP_REFUSED\n', stdout: '' };
        }
    }
    const attested = require('./helpers/rebuildRelayDirectWire');
    const install = f.create({ createRelayDirect: options => createRelayDirect({ ...options,
        SSH: attested(SSH, state.rebuildMachineId) }) }).installRelay;
    await assert.rejects(install(id), { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_PREFLIGHT_REFUSED' });
    assert.equal(sent?.action, 'check-chap');
    assert.equal(sent.machineId, state.rebuildMachineId);
    assert.equal(sent.backupId, state.backupId);
    assert.deepEqual(sent.currentUsers.map(row => [row.login, row.ipAddress, row.enabled]), users
        .map(row => [row.login, row.ip, row.enabled]).sort((a, b) => a[0].localeCompare(b[0])));
    assert.ok(equal(sent.currentUsers, sent.desiredUsers));
    assert.ok(disconnected);
    assert.deepEqual(f.events, []);
});

test('second relay fails pool exhaustion before opening transport', async t => {
    const f = fixture(t);
    const passwordEncrypted = encrypt('fixture-only', f.env.ENCRYPTION_KEY);
    const source = addSource(f, { accounts: Array.from({ length: 242 }, (_, i) =>
        ({ login: i === 0 ? 'relay-bootstrap' : `account-${i}`, enabled: i % 2 === 0, passwordEncrypted })) });
    source.state.poolEnd = '10.255.31.251';
    await assert.rejects(f.enroll()(id), { code: 'REBUILD_L2TP_ACCOUNT_POOL_EXHAUSTED' });
    assert.deepEqual(f.events, []);
});

test('target pool allocation skips occupied addresses, including disabled accounts', () => {
    const key = 'fixture-only-key'.repeat(4);
    const { desired: baseline } = makeDesired(id, [], [], key);
    const prefix = baseline.poolStart.split('.').slice(0, 3).join('.');
    const passwordEncrypted = encrypt('fixture-only', key);
    const { accounts } = makeDesired(id, [], [], key, {
        allocations: [baseline.localAddress, `${prefix}.10`, `${prefix}.11`],
        inherited: [{ login: 'enabled', enabled: true, passwordEncrypted }, { login: 'disabled', enabled: false, passwordEncrypted }],
    });
    assert.deepEqual(accounts.map(row => row.ip), [`${prefix}.12`, `${prefix}.13`]);
});

test('second relay rejects a changed source snapshot after Prepare without persisting a reservation', async t => {
    const f = fixture(t);
    const session = sessionFixture(t, f);
    addSource(f);
    f.hooks.prepare = async () => { f.users[0].enabled = false; return { backupId }; };
    await assert.rejects(f.enroll()(id), { code: 'REBUILD_L2TP_RESERVATION_FAILED' });
    assert.deepEqual(session.events, ['abort']);
    assert.deepEqual(f.events, ['source-connect', 'source-check', 'source-close', 'connect', 'preflight', 'prepare', 'close']);
});

test('second relay aborts the complete reservation when the second replica write fails', async t => {
    const f = fixture(t);
    const session = sessionFixture(t, f);
    addSource(f);
    const before = [f.states.map(copy), f.users.map(copy)];
    let writes = 0;
    f.userHooks.update = ({ apply }) => {
        if (++writes === 2) throw new Error('fixture replica write refusal');
        return apply();
    };
    await assert.rejects(f.enroll()(id), { code: 'REBUILD_L2TP_RESERVATION_FAILED' });
    assert.deepEqual([f.states, f.users], before);
    assert.deepEqual(session.events, ['abort']);
    assert.ok(!f.events.includes('install'));
});

test('second relay rollback restores prior state atomically and leaves source accounts unchanged', async t => {
    const f = fixture(t);
    const session = sessionFixture(t, f);
    addSource(f);
    f.states.push(priorRow());
    const before = [f.states.map(copy), f.users.map(copy)];
    f.hooks.verify = async () => false;
    await assert.rejects(f.enroll()(id), { code: 'REBUILD_L2TP_VERIFY_FAILED' });
    assert.deepEqual([f.states, f.users], before);
    assert.deepEqual(session.events, ['commit', 'commit']);
    assert.equal(f.events.filter(event => event === 'L2tpUser:delete').length, 2);
});

test('second relay leaves all replicas pending when the second finish write fails', async t => {
    const f = fixture(t);
    const session = sessionFixture(t, f);
    addSource(f);
    let synced = 0;
    f.userHooks.update = ({ update, apply }) => {
        if (update.$set?.syncStatus === 'synced' && ++synced === 2) throw new Error('fixture finish write refusal');
        return apply();
    };
    await assert.rejects(f.enroll()(id), { code: 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN' });
    assert.deepEqual(session.events, ['commit', 'abort']);
    assert.deepEqual(f.users.filter(row => String(row.relayNode) === id).map(row => row.syncStatus), ['pending', 'pending']);
    assert.equal(f.states.find(row => String(row.node) === id).status, 'installing');
    assert.ok(!f.events.includes('rollback'));
});

test('second relay refuses to settle a reservation with an extra target account', async t => {
    const f = fixture(t);
    const session = sessionFixture(t, f);
    addSource(f);
    f.hooks.verify = async () => {
        f.users.push({ ...f.users.find(row => String(row.relayNode) === id), _id: oid(), login: 'unreserved',
            ip: f.prepared.desired.poolEnd });
        return true;
    };
    await assert.rejects(f.enroll()(id), { code: 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN' });
    assert.deepEqual(session.events, ['commit']);
    assert.deepEqual(f.users.filter(row => String(row.relayNode) === id).map(row => row.syncStatus), ['pending', 'pending', 'pending']);
    assert.equal(f.states.find(row => String(row.node) === id).status, 'installing');
    assert.ok(!f.events.includes('rollback'));
});

test('second relay never replays or rolls back an unacknowledged transaction commit', async t => {
    for (const phase of ['reservation', 'finish']) await t.test(phase, async child => {
        const f = fixture(child);
        const session = sessionFixture(child, f);
        addSource(f);
        const loseAt = phase === 'reservation' ? 1 : 2;
        session.hooks.commit = commit => {
            const reply = commit();
            if (session.events.length === loseAt) throw new Error('fixture acknowledgement loss after commit');
            return reply;
        };
        const install = f.enroll();
        await assert.rejects(install(id), { code: phase === 'reservation'
            ? 'REBUILD_L2TP_RESERVATION_FAILED' : 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN' });
        await assert.rejects(install(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
        assert.deepEqual(session.events, Array(loseAt).fill('commit'));
        assert.equal(f.events.includes('install'), phase === 'finish');
        assert.ok(!f.events.includes('rollback'));
        const status = phase === 'reservation' ? 'installing' : 'installed';
        assert.equal(f.states.find(row => String(row.node) === id).status, status);
        const sync = phase === 'reservation' ? 'pending' : 'synced';
        assert.deepEqual(f.users.filter(row => String(row.relayNode) === id).map(row => row.syncStatus), [sync, sync]);
    });
});

test('first list Install commits the bootstrap reservation before host dispatch and commits settlement after verification', async t => {
    const f = fixture(t);
    const { events } = sessionFixture(t, f);
    f.hooks.install = async guard => {
        await guard();
        assert.deepEqual(events, ['commit']);
        assert.deepEqual(f.states.map(row => row.status), ['installing']);
        assert.deepEqual(f.users.map(row => [row.login, row.syncStatus]), [['relay-bootstrap', 'pending']]);
        return true;
    };
    assert.equal((await f.enroll()(id)).status, 'installed');
    assert.deepEqual(events, ['commit', 'commit']);
    assert.deepEqual(f.states.map(row => row.status), ['installed']);
    assert.deepEqual(f.users.map(row => row.syncStatus), ['synced']);
});

test('first list Install aborts both collections when the later CAS fails', async t => {
    for (const phase of ['reserve', 'finish', 'restore']) await t.test(phase, async child => {
        const f = fixture(child);
        const { events } = sessionFixture(child, f);
        const refusal = { acknowledged: true, matchedCount: 0, upsertedCount: 0, deletedCount: 0 };
        if (phase === 'reserve') f.userHooks.update = () => refusal;
        if (phase === 'finish') f.stateHooks.update = ({ update, apply }) => update.$set?.status === 'installed' ? refusal : apply();
        if (phase === 'restore') {
            f.hooks.verify = async () => false;
            f.stateHooks.delete = () => refusal;
        }
        const code = { reserve: 'REBUILD_L2TP_RESERVATION_FAILED', finish: 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN',
            restore: 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN' }[phase];
        await assert.rejects(f.enroll()(id), { code });
        assert.deepEqual(events, phase === 'reserve' ? ['abort'] : ['commit', 'abort']);
        assert.deepEqual(f.states.map(row => row.status), phase === 'reserve' ? [] : ['installing']);
        assert.deepEqual(f.users.map(row => row.syncStatus), phase === 'reserve' ? [] : ['pending']);
        assert.equal(f.events.includes('install'), phase !== 'reserve');
        assert.equal(f.events.filter(event => event === 'rollback').length, Number(phase === 'restore'));
    });
});

test('first list Install never replays or compensates for a lost commit acknowledgement', async t => {
    for (const phase of ['reserve', 'finish', 'restore']) await t.test(phase, async child => {
        const f = fixture(child);
        const { events, hooks } = sessionFixture(child, f);
        const loseAt = phase === 'reserve' ? 1 : 2;
        hooks.commit = commit => {
            const reply = commit();
            if (events.length === loseAt) throw new Error('fixture acknowledgement loss after commit');
            return reply;
        };
        if (phase === 'restore') f.hooks.verify = async () => false;
        const code = { reserve: 'REBUILD_L2TP_RESERVATION_FAILED', finish: 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN',
            restore: 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN' }[phase];
        const install = f.enroll();
        await assert.rejects(install(id), { code });
        if (phase !== 'restore') await assert.rejects(install(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
        assert.deepEqual(events, Array(loseAt).fill('commit'));
        assert.deepEqual(f.states.map(row => row.status), { reserve: ['installing'], finish: ['installed'], restore: [] }[phase]);
        assert.deepEqual(f.users.map(row => row.syncStatus), { reserve: ['pending'], finish: ['synced'], restore: [] }[phase]);
        assert.equal(f.events.filter(event => event === 'install').length, Number(phase !== 'reserve'));
        assert.equal(f.events.filter(event => event === 'rollback').length, Number(phase === 'restore'));
    });
});

test('first list Install reports acknowledged commit plus cleanup failure without dispatch or reversal', async t => {
    for (const phase of ['reserve', 'finish', 'restore']) await t.test(phase, async child => {
        const f = fixture(child);
        const { events, hooks } = sessionFixture(child, f);
        const failAt = phase === 'reserve' ? 1 : 2;
        hooks.end = () => {
            if (events.length === failAt) throw new Error('fixture cleanup failure after acknowledged commit');
        };
        if (phase === 'restore') {
            f.states.push(priorRow());
            f.hooks.verify = async () => false;
        }
        const before = f.states.map(copy);
        const code = { reserve: 'REBUILD_L2TP_RESERVATION_CLEANUP_FAILED', finish: 'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED',
            restore: 'REBUILD_L2TP_ROLLBACK_CLEANUP_FAILED' }[phase];
        await assert.rejects(f.enroll()(id), { code, message: code });
        assert.deepEqual(events, Array(failAt).fill('commit'));
        assert.deepEqual(f.states.map(row => row.status), { reserve: ['installing'], finish: ['installed'], restore: ['not_installed'] }[phase]);
        if (phase === 'restore') assert.deepEqual(f.states, before);
        assert.deepEqual(f.users.map(row => row.syncStatus), { reserve: ['pending'], finish: ['synced'], restore: [] }[phase]);
        assert.equal(f.events.filter(event => event === 'install').length, Number(phase !== 'reserve'));
        assert.equal(f.events.filter(event => event === 'rollback').length, Number(phase === 'restore'));
    });
});

test('first list Install never ends a still-active session after attempting commit', async t => {
    for (const committedReply of [true, false]) await t.test(`commit acknowledged: ${committedReply}`, async child => {
        const f = fixture(child);
        const { events, hooks } = sessionFixture(child, f);
        hooks.commit = commit => {
            const reply = commit();
            if (!committedReply) throw new Error('fixture acknowledgement loss');
            return reply;
        };
        hooks.transition = () => { throw new Error('fixture local transition failure'); };
        hooks.end = () => { events.push('end'); };
        await assert.rejects(f.enroll()(id), { code: committedReply
            ? 'REBUILD_L2TP_RESERVATION_CLEANUP_FAILED' : 'REBUILD_L2TP_RESERVATION_FAILED' });
        assert.deepEqual(events, ['commit']);
        assert.deepEqual(f.states.map(row => row.status), ['installing']);
        assert.deepEqual(f.users.map(row => row.syncStatus), ['pending']);
        assert.ok(!f.events.includes('install') && !f.events.includes('rollback'));
    });
});

function addLink(f, portalNode, bridgeNode, geoRouting) {
    f.links.push({ _id: oid(), portalNode, bridgeNode, mode: 'reverse', active: true, status: 'deployed', ...(geoRouting ? { geoRouting } : {}) });
}

function accountIntentFixture(t, f) {
    let pending;
    const writes = [];
    t.mock.method(User.db, 'collection', name => {
        assert.equal(name, 'c3_rebuild_relay_accounts');
        assert.ok(f.lockHeld);
        return {
            async findOne(where, options) {
                if (where._id === 'directory') return f.directory.findOne(where, options);
                assert.equal(where._id, 'pending');
                return project(pending && matches(pending, where) ? pending : null, options?.projection);
            },
            async updateMany(where, update, options) {
                if (where._id === 'directory') return f.directory.updateMany(where, update, options);
                const { $setOnInsert } = update;
                assert.deepEqual(where, { _id: 'pending', intentId: $setOnInsert.intentId });
                assert.ok(options.session?.inTransaction());
                assert.equal(options.upsert, true);
                assert.equal(pending, undefined);
                options.session.commitAccountIntent = () => {
                    pending = { ...copy($setOnInsert), _id: 'pending' };
                    writes.push(`begin:${pending.action}`);
                };
                return { acknowledged: true, upsertedCount: 1 };
            },
            async deleteMany(where, options) {
                assert.ok(options.session?.inTransaction());
                assert.deepEqual(where, { _id: 'pending', intentId: pending?.intentId,
                    $expr: { $eq: ['$$ROOT', { $literal: pending }] } });
                options.session.commitAccountIntent = () => {
                    writes.push(`settle:${pending.action}`);
                    pending = undefined;
                };
                return { acknowledged: true, deletedCount: 1 };
            },
        };
    });
    return { writes, get pending() { return pending; } };
}

joined({ fixture, sessionFixture, accountIntentFixture, id, oid, machineId, decrypt });

// Reuse the joined wire, Python host and Debian model. This adapter seeds
// the companion Xray/manager state and disposable host-side test inputs.
const debianArchiveKeyring = '/usr/share/keyrings/debian-archive-keyring.gpg';
const fixedDebianIndexes = [
    'deb.debian.org_debian_dists_trixie',
    'deb.debian.org_debian_dists_trixie-updates',
    'security.debian.org_debian-security_dists_trixie-security',
].flatMap(stem => [`${stem}_InRelease`, `${stem}_main_binary-amd64_Packages`]).sort();

function emptyIndexHost(t, f, scenario) {
    const fs = require('node:fs');
    const { join, dirname } = require('node:path');
    const { tmpdir } = require('node:os');
    const { createHash } = require('node:crypto');
    const { spawnSync } = require('node:child_process');
    const { generateXraySystemdService } = require('../configGenerator');
    const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
    const root = fs.mkdtempSync(join(tmpdir(), '.relay-install-join-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const path = name => join(root, name);
    const put = (name, data, mode = 0o644) => {
        fs.mkdirSync(dirname(path(name)), { recursive: true });
        fs.writeFileSync(path(name), data, { mode });
        fs.chmodSync(path(name), mode);
    };
    const python = (file, input) => {
        const result = spawnSync('/usr/bin/python3', ['-I', '-B', join(__dirname, 'helpers', file), root, scenario],
            { input, env: {}, encoding: 'utf8', timeout: 10000, maxBuffer: 4 * 1024 * 1024 });
        assert.ifError(result.error);
        assert.ok([0, 70, 75].includes(result.status), `${file}: exit ${result.status}`);
        return result;
    };
    const initialized = python('rebuildRelayInstallPackageModel.py');
    assert.equal(initialized.status, 0, initialized.stderr);
    const packageModel = JSON.parse(initialized.stdout);
    if (scenario === 'package-stock-empty-foreign-source') {
        // Deliberately unrelated to the fixed source config consumed by APT.
        put('/etc/apt/sources.list.d/fixture-backports.sources', 'Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie-backports\nComponents: main\n');
        put('/var/cache/apt/archives/fixture-cached.deb', 'shared archive sentinel; never use\n');
        put('/var/cache/apt/archives/partial/fixture-partial.deb', 'shared partial sentinel; never use\n');
    }
    if (scenario === 'package-stock-empty-bad-keyring') {
        const keyring = fs.realpathSync(path(debianArchiveKeyring));
        assert.equal(dirname(keyring), path('/usr/share/keyrings'));
        fs.chmodSync(keyring, 0o666);
    }
    const relay = f.nodes[0];
    Object.assign(relay, { port: 21443, xray: { apiPort: 61001, security: 'none' },
        aclRules: ['reject(denied.invalid)'], ssh: { ...relay.ssh, password: 'local-fixture-only' } });
    const exit = { _id: oid('d'.repeat(24)), type: 'xray', active: true, ip: '192.0.2.99', cascadeRole: 'bridge', ssh: relay.ssh };
    f.nodes.push(exit);
    f.links.push({ _id: oid('e'.repeat(24)), portalNode: relay._id, bridgeNode: exit._id, mode: 'forward', active: true,
        status: 'deployed', tunnelProtocol: 'vmess', tunnelPort: 20443, tunnelUuid: '7b159424-f38c-4869-bbf8-cb426fa00354' });
    const profiles = composeRebuildProfiles({ nodes: f.nodes, links: f.links, usersByNode: { [id]: [] },
        dialerVersions: new Map([[String(exit._id), '26.3.27']]) });
    const main = profiles.find(row => row.nodeId === id && row.profile === 'main').config;
    const mainPath = '/usr/local/etc/xray/config.json';
    put(mainPath, JSON.stringify(main), 0o640);
    put('/usr/local/etc/xray-bridge/config.json', JSON.stringify(profiles.find(row => row.nodeId === id && row.profile === 'bridge').config), 0o640);
    put('/usr/local/bin/xray', 'synthetic executable; never run\n', 0o755);
    put('/etc/systemd/system/xray.service', generateXraySystemdService());
    put('/etc/machine-id', machineId + '\n');
    put('/etc/ppp/chap-secrets', '# stock chap\n', 0o600);
    put('/etc/ppp/options', '# stock options\n', 0o600);
    fs.mkdirSync(path('/etc/ipsec.d'));
    fs.mkdirSync(path('/etc/systemd/system/multi-user.target.wants'));
    if (scenario !== 'package-stock-empty-plan') require('./helpers/rebuildRelayStockSwan').seed(root);

    const absent = { LoadState: 'not-found', UnitFileState: '', ActiveState: 'inactive', SubState: 'dead', FragmentPath: '',
        MainPID: '0', InvocationID: '', DropInPaths: '', NeedDaemonReload: 'no', PrivateNetwork: 'no', KillMode: 'control-group', User: '' };
    const original = {
        'xray.service': { ...absent, LoadState: 'loaded', UnitFileState: 'enabled', ActiveState: 'active',
            SubState: 'running', FragmentPath: '/etc/systemd/system/xray.service', MainPID: '101', InvocationID: '0'.repeat(30) + '65',
            ControlGroup: '/system.slice/xray.service', User: 'nobody',
            ExecStart: `{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${mainPath} ; }` },
        'xray-bridge.service': absent, 'xl2tpd.service': absent, 'celerity-rebuild-l2tp-network.service': absent,
        'strongswan-starter.service': { ...absent, ControlGroup: '/system.slice/strongswan-starter.service',
            ExecStart: '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }' },
    };
    const packages = ['strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd', 'ppp', 'nftables'];
    put('manager.json', JSON.stringify({ packages, packageModel, machine: machineId, address: relay.ip, cohort: true,
        original, units: original, modules: ['ppp_generic', 'l2tp_ppp'], running: { 'xray.service': main }, nextPid: 300,
        ikeConnection: false, effects: [], rule: null, route: null, nft: null, rules6: [],
        stockRules: [[0, 255], [32766, 254], [32767, 253]].map(([priority, table]) => ({ priority, src: 'all', table: String(table) })),
        foreign: { rules: [], routes: [], tables: [], sockets: [] }, managerEnvironment: 'LANG=C\n',
        owners: { [fs.statSync(path(mainPath)).ino]: [65534, 65534] } }), 0o600);

    const read = name => JSON.parse(fs.readFileSync(path(name), 'utf8'));
    const key = Buffer.from('synthetic SSH wire key:' + id);
    const sha256 = data => createHash('sha256').update(data).digest('hex');
    const capture = name => {
        const st = fs.lstatSync(path(name), { bigint: true });
        const contents = st.isSymbolicLink() ? fs.readlinkSync(path(name)) : st.isFile() ? sha256(fs.readFileSync(path(name))) : null;
        return [name, st.ino, st.mode, st.ctimeNs, st.mtimeNs, contents];
    };
    const tree = base => fs.existsSync(path(base)) ? [base, ...fs.readdirSync(path(base), { recursive: true })
        .sort().map(name => join(base, name))].map(capture) : [];
    const aptConfig = () => [...tree('/etc/apt'), ...tree('/usr/share/keyrings')];
    const sharedArchives = () => tree('/var/cache/apt/archives');
    const indexes = () => fs.readdirSync(path('/var/lib/apt/lists')).filter(name => !['lock', 'partial', 'auxfiles'].includes(name)).sort();
    return { id, relay, key, pin: sha256(key), machineId, applyHandlers: new Map(), read, packages, aptConfig, indexes, capture, sharedArchives,
        exists: name => fs.existsSync(path(name)), execute: (command, stdin) => python('rebuildRelayInstallHost.py', `${JSON.stringify(command)}\n${stdin}`) };
}

for (const outcome of ['ok', 'foreign-source', 'bad-keyring', 'untrusted', 'acquisition', 'incomplete', 'tampered', 'plan']) {
    test(`joined empty-index Install with packed guard: ${outcome}`, async t => {
        const installs = outcome === 'ok' || outcome === 'foreign-source';
        const f = fixture(t);
        const { events } = sessionFixture(t, f);
        const host = emptyIndexHost(t, f, `package-stock-empty-${outcome}`);
        const config = host.aptConfig(), archives = host.sharedArchives(), statusBefore = host.capture('/var/lib/dpkg/status');
        const listsBefore = host.capture('/var/lib/apt/lists');
        const initialPackages = host.read('manager.json').packageModel.installed;
        const vault = '/var/lib/celerity-rebuild-l2tp-direct', pending = `${vault}/package-preparation.pending`;
        const execute = host.execute, replies = [];
        let reserved, proof;
        assert.deepEqual(host.indexes(), []);
        if (outcome === 'foreign-source') {
            assert.ok(host.exists('/etc/apt/sources.list.d/operator.list'));
            assert.ok(host.exists('/etc/apt/sources.list.d/fixture-backports.sources'));
            assert.ok(host.exists('/var/cache/apt/archives/fixture-cached.deb'));
            assert.ok(host.exists('/var/cache/apt/archives/partial/fixture-partial.deb'));
        }
        host.execute = (command, stdin) => {
            assert.ok(f.lockHeld);
            const request = JSON.parse(stdin);
            if (!replies.length) assert.deepEqual([events, f.states, f.users], [[], [], []]);
            else {
                assert.deepEqual(events, ['commit']);
                if (request.action === 'prepare-packages') {
                    reserved = f.states[0]?.backupId;
                    assert.match(reserved, /^[a-f0-9]{32}$/);
                }
                assert.deepEqual(f.states.map(row => [row.status, row.backupId]), [['installing', reserved]]);
                assert.deepEqual(f.users.map(row => row.syncStatus), ['pending']);
                if (request.backupId) assert.equal(request.backupId, reserved);
            }
            if (request.action === 'prepare-packages') {
                assert.deepEqual(request, { action: 'prepare-packages', machineId, backupId: reserved, packagePreparation: proof });
                assert.deepEqual(host.indexes(), []);
            }
            const result = execute(command, stdin);
            const model = host.read('manager.json');
            assert.deepEqual(model.faults ?? [], [], 'closed DIRECT command model');
            assert.deepEqual(host.aptConfig(), config, 'APT source/config generations must not change');
            assert.deepEqual(host.sharedArchives(), archives, 'shared archives and partial downloads must not change');
            if (!replies.length) {
                assert.deepEqual(host.indexes(), []);
                assert.deepEqual(host.capture('/var/lib/apt/lists'), listsBefore);
                assert.deepEqual(host.capture('/var/lib/dpkg/status'), statusBefore);
                assert.deepEqual([model.effects, model.packageModel.effects, model.packageModel.updates], [[], [], []]);
                assert.deepEqual(model.packageModel.aptReads, {}, 'empty-cache preflight does not consult APT');
                assert.equal(host.exists(vault), false);
                if (outcome !== 'bad-keyring') {
                    assert.equal(result.status, 0, JSON.stringify(model.lastRefusal));
                    const frame = JSON.parse(result.stdout);
                    assert.match(frame.packagePreparation, /^[a-f0-9]{64}$/);
                    proof = frame.packagePreparation;
                    assert.deepEqual(frame, { machineId, packagePreparation: proof });
                }
            }
            if (request.action === 'prepare-packages' && installs) {
                assert.equal(result.status, 0, JSON.stringify(model.lastRefusal));
                assert.deepEqual(JSON.parse(result.stdout), { ok: true, backupId: reserved, packagesReady: true });
            }
            replies.push({ status: result.status, hasOutput: Boolean(result.stdout) });
            return result;
        };
        const bindWire = joined({ id, wireOnly: true });
        const frames = bindWire(t, [host]);
        delete f.env.C3_REBUILD_L2TP_RELAY_ID;
        delete f.env.C3_REBUILD_L2TP_RELAY_MACHINE_ID;
        const grant = { nodeId: id, host: host.relay.ip, port: 22, username: 'root', machineId, sshHostKeySha256: host.pin,
            generation: 'a1f2edc4-676c-4a6e-b111-a1239fbbcd1e', createdBy: 'fixture', confirmedBy: 'fixture',
            createdAt: new Date(0), confirmedAt: new Date(0) };
        const grantDb = { readyState: 1, collection(name) {
            assert.equal(name, 'c3_rebuild_l2tp_relay_grants');
            return { find(filter, options) {
                assert.deepEqual(filter, {});
                assert.deepEqual(options.readConcern, { level: 'majority' });
                return { toArray: async () => [{ ...grant }] };
            } };
        } };
        const service = f.create({ grantDb, createRelayDirect: undefined });
        const { handler } = require('../../routes/panel/rebuildRelayInstall');
        let status = 200;
        const result = await handler(() => service)({ params: { id }, body: {} }, {
            status(value) { status = value; return this; }, json(value) { return value; },
        });
        const manager = host.read('manager.json');
        const model = manager.packageModel;
        assert.deepEqual(manager.faults ?? [], []);
        assert.deepEqual(host.aptConfig(), config);
        if (outcome === 'bad-keyring') {
            assert.equal(status, 409);
            assert.deepEqual(result.error, { code: 'REBUILD_L2TP_DIRECT_PREREQUISITE',
                outcome: 'refused', check: 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE' });
            assert.deepEqual(manager.lastRefusal?.slice(0, 2), ['PACKAGE_FILE', '_regular']);
            assert.deepEqual(frames, [[id, 'preflight']]);
            assert.deepEqual(replies, [{ status: 70, hasOutput: false }]);
            assert.deepEqual([events, f.states, f.users, model.updates], [[], [], [], []]);
            assert.deepEqual([model.afterUpdate, model.aptWrites, model.installed], [[], 0, initialPackages]);
            assert.equal(host.exists(vault), false);
            return;
        }
        const [update] = model.updates;
        assert.equal(model.updates.length, 1, JSON.stringify({ error: result.error, refusal: manager.lastRefusal, frames }));
        assert.deepEqual([update.action, update.backupId, update.argv], ['prepare-packages', reserved, ['/usr/bin/apt-get', '--error-on=any', 'update']]);
        assert.match(update.configDigest, /^[a-f0-9]{64}$/);
        assert.deepEqual(host.indexes(), update.indexes);
        const receipt = `${vault}/packages-${reserved}.json`;
        if (!installs) {
            const invalidPlan = outcome === 'plan';
            assert.equal(status, 409);
            assert.equal(result.error.outcome, 'unknown');
            assert.equal(result.error.retryAllowed, false);
            assert.deepEqual(frames, [[id, 'preflight'], [id, 'prepare-packages']]);
            assert.deepEqual(replies[1], { status: 75, hasOutput: false });
            assert.equal(result.error.check, invalidPlan ? 'PACKAGE_APT_PLAN' : 'PACKAGE_INDEXES_UNVERIFIED');
            if (invalidPlan) {
                assert.deepEqual(manager.lastRefusal?.slice(0, 2), ['PACKAGE_APT_PLAN', '_simulation']);
                assert.deepEqual(result.error, { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', outcome: 'unknown',
                    check: 'PACKAGE_APT_PLAN', retryAllowed: false });
            }
            assert.equal(update.status, ['incomplete', 'tampered', 'plan'].includes(outcome) ? 0 : 100);
            assert.equal(update.indexes.length, ({ untrusted: 0, tampered: 6, plan: 6 })[outcome] ?? 5);
            assert.deepEqual([model.afterUpdate, model.quiet, model.aptWrites, model.installed],
                [invalidPlan ? ['check', 'simulate'] : [], {}, 0, initialPackages]);
            assert.deepEqual(model.effects, ['enter', 'update']);
            assert.deepEqual(host.capture('/var/lib/dpkg/status'), statusBefore);
            assert.deepEqual([events, f.states.map(row => row.status), f.users.map(row => row.syncStatus)], [['commit'], ['installing'], ['pending']]);
            assert.equal(f.lockHeld, true);
            assert.equal(host.read(receipt).phase, 'preparing');
            assert.deepEqual(host.read(pending), host.read(receipt));
            assert.equal(host.exists(`${vault}/${reserved}`), false);
            assert.deepEqual(manager.effects, []);
            return;
        }
        assert.equal(status, 200, JSON.stringify({ error: result.error, refusal: manager.lastRefusal, frames }));
        assert.deepEqual(result, { executionMode: 'rebuild', status: 'installed', nodeId: id });
        assert.deepEqual(frames.map(([, action]) => action), ['preflight', 'prepare-packages', 'preflight', 'prepare', 'check', 'install', 'verify']);
        assert.deepEqual([update.status, update.indexes, model.aptWrites], [0, fixedDebianIndexes, 1]);
        assert.deepEqual(model.effects, ['enter', 'update', 'reload', 'apt', 'reload', 'reload']);
        assert.deepEqual(model.afterUpdate.filter(step => step === 'install'), ['install']);
        assert.ok(host.packages.every(name => Object.hasOwn(model.installed, name)));
        assert.deepEqual(model.quiet, { 'xl2tpd.service': 'generated', 'strongswan-starter.service': 'disabled', 'nftables.service': 'disabled' });
        assert.deepEqual([events, f.states.map(row => [row.status, row.backupId]), f.users.map(row => row.syncStatus)],
            [['commit', 'commit'], [['installed', reserved]], ['synced']]);
        assert.equal(f.lockHeld, false);
        assert.equal(host.read(receipt).phase, 'ready');
        assert.equal(host.read(`${vault}/${reserved}/manifest.json`).phase, 'installed');
        assert.equal(host.exists(pending), false);
    });
}

function admissionEffects(t, { twoRelays = false, useGrantDb = false } = {}) {
    const { Client } = require('ssh2');
    const { EventEmitter } = require('node:events');
    const { createHash, randomUUID } = require('node:crypto');
    const digest = value => createHash('sha256').update(value).digest('hex');
    const f = fixture(t);
    const session = sessionFixture(t, f);
    const intents = accountIntentFixture(t, f);
    delete f.env.C3_REBUILD_L2TP_RELAY_ID;
    delete f.env.C3_REBUILD_L2TP_RELAY_MACHINE_ID;
    if (twoRelays) f.nodes.push({ ...f.nodes[0], _id: oid('c'.repeat(24)), ip: '192.0.2.20' });
    for (const node of f.nodes) node.ssh = { ...node.ssh, password: 'fixture-only-ssh-auth' };
    const hosts = f.nodes.map(({ _id, ip, ssh }, index) => {
        const key = Buffer.from(`fixture host key ${index}`);
        const binding = { nodeId: String(_id), host: ip, port: ssh.port, username: ssh.username,
            machineId: index ? 'd'.repeat(32) : machineId, sshHostKeySha256: digest(key) };
        return { key, binding, machine: binding.machineId };
    });
    const grants = [];
    const list = 'C3_REBUILD_L2TP_RELAYS_JSON';
    if (twoRelays) f.env[list] = JSON.stringify([hosts[0].binding]);
    const grant = (host = hosts.at(-1)) => grants.push({ ...host.binding, generation: randomUUID() });
    const relayGrantStore = { async snapshot() {
        const rows = grants.map(row => ({ ...row }));
        const configured = JSON.parse(f.env[list] ?? '[]');
        const merged = [...configured, ...rows.map(({ generation, ...binding }) => binding)];
        return { env: Object.freeze({ ...f.env, [list]: JSON.stringify(merged) }), grants: rows,
            sourceFor: nodeId => rows.some(row => row.nodeId === nodeId) ? 'db'
                : configured.some(row => row.nodeId === nodeId) ? 'env' : null };
    } };
    const grantDb = { readyState: 1, collection(name) {
        assert.equal(name, 'c3_rebuild_l2tp_relay_grants');
        return { find(filter, options) {
            assert.deepEqual(filter, {});
            assert.deepEqual(options.readConcern, { level: 'majority' });
            return { async toArray() {
                return grants.map(row => ({ ...row, createdBy: 'fixture', confirmedBy: 'fixture',
                    createdAt: new Date(0), confirmedAt: new Date(0) }));
            } };
        } };
    } };
    const service = f.create({ ...(useGrantDb ? { grantDb } : { relayGrantStore }),
        createRelayDirect: require('../rebuildRelayDirect').createRelayDirect });
    const peers = new WeakMap(), attestedPeers = new WeakSet(), frames = [], effects = [], opens = [], hooks = {};
    const main = JSON.stringify({ inbounds: [{ tag: 'fwd-hop-a', protocol: 'vless', port: 443 }],
        outbounds: [{ tag: 'block', protocol: 'blackhole' }], routing: { rules: [
            { type: 'field', ruleTag: 'rebuild-policy-default', inboundTag: ['fwd-hop-a'], outboundTag: 'block' },
        ] } });
    t.mock.method(Client.prototype, 'connect', function (options) {
        const host = hosts.find(row => row.binding.host === options.host);
        assert.ok(f.lockHeld && host);
        assert.equal(options.port, host.binding.port);
        assert.equal(options.username, host.binding.username);
        assert.equal(typeof options.hostVerifier, 'function');
        opens.push(host.binding.nodeId);
        const pinned = options.hostVerifier(host.key);
        if (pinned) peers.set(this, host);
        queueMicrotask(() => pinned ? this.emit('ready') : this.emit('error', Error('fixture pin rejected')));
        return this;
    });
    t.mock.method(Client.prototype, 'end', function () { peers.delete(this); });
    t.mock.method(Client.prototype, 'exec', function (command, ready) {
        const host = peers.get(this);
        assert.ok(f.lockHeld && host);
        const stream = new EventEmitter(), chunks = [];
        stream.stderr = new EventEmitter();
        if (command === '/usr/bin/head -c 34 /etc/machine-id') {
            stream.write = stream.end = () => assert.fail('attestation may not send stdin');
            ready(null, stream);
            queueMicrotask(() => {
                hooks.beforeAttestation?.(host);
                attestedPeers.add(this);
                stream.emit('data', `${host.machine}\n`);
                stream.stderr.emit('end');
                stream.emit('close', 0);
            });
            return this;
        }
        assert.match(command, /^\/usr\/bin\/timeout -k /);
        assert.ok(attestedPeers.delete(this), 'fresh attestation must be on this exact client before the receiver opens');
        stream.write = chunk => { chunks.push(Buffer.from(chunk)); return true; };
        stream.end = done => {
            done();
            queueMicrotask(() => {
                const input = JSON.parse(Buffer.concat(chunks));
                const { action, backupId, machineId: expected, currentUsers, desiredUsers } = input;
                frames.push([host.binding.nodeId, action]);
                hooks.atDispatch?.(action, host);
                let value;
                const readiness = { machineId: host.machine, ppp: true, masked: false, unitsLoaded: true };
                if (expected !== host.machine) {
                    stream.stderr.emit('data', action === 'install' ? 'DIRECT_NO_WRITE_IDENTITY\n' : 'DIRECT_IDENTITY\n');
                    stream.stderr.emit('end');
                    return stream.emit('close', 70);
                }
                const reply = hooks.reply?.(input);
                if (reply) {
                    if (reply.stdout) stream.emit('data', reply.stdout);
                    if (reply.stderr) stream.stderr.emit('data', reply.stderr);
                    stream.stderr.emit('end');
                    return stream.emit('close', reply.code);
                }
                if (action === 'preflight') value = readiness;
                else if (action === 'prepare') value = { ...readiness, main, mainSha256: digest(main),
                    bridge: null, bridgeSha256: null, baseline: 'e'.repeat(64) };
                else if (action === 'session-count') value = { activeSessions: 0, activeIpsec: 0, census: 'e'.repeat(64) };
                else if (action === 'prepare-remove') value = { ok: true, backupId, machineId: host.machine, baseline: 'e'.repeat(64) };
                else if (action === 'check-chap') value = { ok: true, backupId, changed: !equal(currentUsers, desiredUsers) };
                else if (['check', 'install', 'verify', 'remove', 'rollback', 'sync-chap'].includes(action)) {
                    if (['install', 'remove', 'rollback', 'sync-chap'].includes(action)) effects.push([host.binding.nodeId, action]);
                    value = { ok: true, backupId, ...(action === 'remove' && { removed: true }),
                        ...(action === 'sync-chap' && { changed: true }) };
                } else assert.fail('unexpected DIRECT request');
                stream.emit('data', JSON.stringify(value) + '\n');
                stream.stderr.emit('end');
                stream.emit('close', 0);
            });
        };
        stream.close = () => {};
        hooks.beforeChannel?.(host);
        ready(null, stream);
        return this;
    });
    t.after(() => require('../sshPoolService').closeAll());
    return { ...f, get lockHeld() { return f.lockHeld; }, service, session, intents, hosts, grants, grant, frames, effects, opens, hooks };
}

const packageDigest = 'a1'.repeat(32);
const wire = value => ({ code: 0, stdout: JSON.stringify(value) + '\n' });
// Consumer-frame fixtures: real panel handler, locks, store and DIRECT driver;
// only the DB/session and SSH channel boundaries are modeled.
function packageFlow(t, { grant = true, proof = wire({ machineId, packagePreparation: packageDigest }), reply } = {}) {
    const f = admissionEffects(t);
    if (grant) f.grant();
    else f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([f.hosts[0].binding]);
    const byAction = () => f.frames.map(([, action]) => action);
    let initial = true;
    f.hooks.reply = input => {
        if (input.action === 'preflight' && initial) {
            initial = false;
            return proof;
        }
        return reply?.(input, f);
    };
    const path = require('../../routes/panel/rebuildRelayInstall').handler(() => f.service);
    const click = async (body = {}, query = {}) => {
        const response = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(value) { return value; } };
        const data = await path({ params: { id }, body, query }, response);
        return { status: response.statusCode, data };
    };
    return Object.assign(f, { click, byAction });
}

test('package flow: one panel click commits the reservation before exact stdin; the same pinned client finishes with that ID', async t => {
    let reserved;
    const f = packageFlow(t, { reply(input, f) {
        if (input.action === 'prepare-packages') {
            assert.deepEqual(f.session.events, ['commit']);
            assert.ok(f.lockHeld);
            reserved = f.states[0].backupId;
            assert.match(reserved, /^[a-f0-9]{32}$/);
            assert.deepEqual(input, { action: 'prepare-packages', machineId, backupId: reserved, packagePreparation: packageDigest });
            assert.deepEqual(f.states.map(row => row.status), ['installing']);
            assert.deepEqual(f.users.map(row => [row.syncStatus, Boolean(row.passwordEncrypted)]), [['pending', true]]);
            return wire({ ok: true, backupId: reserved, packagesReady: true });
        }
        if (['check', 'install', 'verify'].includes(input.action)) assert.equal(input.backupId, reserved);
    } });
    for (const key of ['machineId', 'backupId', 'packagePreparation']) {
        assert.equal((await f.click({ [key]: packageDigest })).status, 400);
        assert.equal((await f.click({}, { [key]: packageDigest })).status, 400);
    }
    assert.deepEqual(f.opens, []);
    assert.deepEqual(await f.click(), { status: 200, data: { executionMode: 'rebuild', status: 'installed', nodeId: id } });
    assert.deepEqual(f.opens, [id]);
    assert.deepEqual(f.byAction(), ['preflight', 'prepare-packages', 'preflight', 'prepare', 'check', 'install', 'verify']);
    assert.deepEqual(f.session.events, ['commit', 'commit']);
    assert.deepEqual(f.states.map(row => [row.status, row.backupId]), [['installed', reserved]]);
    assert.deepEqual(f.users.map(row => row.syncStatus), ['synced']);
    assert.equal(f.lockHeld, false);
});

test('package flow: unsupported and unsafe preflight frames refuse before reservation', async t => {
    const cases = [
        ['ENV-only', { grant: false }, 'refused', 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE'],
        ['guard refusal', { proof: { code: 70, stderr: 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n' } }, 'refused', 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE'],
        ['foreign machine', { proof: wire({ machineId: '1'.repeat(32), packagePreparation: packageDigest }) }, 'refused'],
        ...[true, 'G'.repeat(64), `${packageDigest}\n`, { sha: packageDigest }].map((value, i) => [`invalid digest ${i}`,
            { proof: wire({ machineId, packagePreparation: value }) }, 'unknown']),
        ['mixed proof', { proof: wire({ machineId, packagePreparation: packageDigest, ppp: true, masked: false, unitsLoaded: true }) }, 'unknown'],
        ['duplicate key', { proof: { code: 0, stdout: `{"machineId":"${machineId}","packagePreparation":"${packageDigest}","packagePreparation":"${packageDigest}"}\n` } }, 'unknown'],
    ];
    for (const [name, options, outcome, check] of cases) await t.test(name, async child => {
        const f = packageFlow(child, options);
        const { status, data } = await f.click();
        assert.equal(status, 409);
        assert.equal(data.error.outcome, outcome);
        assert.equal(data.error.check, check);
        if (name === 'foreign machine') assert.equal(data.error.code, 'REBUILD_L2TP_IDENTITY_CHANGED');
        assert.deepEqual(f.byAction(), ['preflight']);
        assert.deepEqual([f.session.events, f.states, f.users], [[], [], []]);
        assert.equal(f.lockHeld, false);
    });
});

test('package flow: lost majority reservation ACK never opens a package receiver or retries the reservation', async t => {
    const f = packageFlow(t);
    f.session.hooks.commit = commit => { commit(); throw Error('simulated lost reply'); };
    const { data } = await f.click();
    assert.deepEqual(data.error, { code: 'REBUILD_L2TP_RESERVATION_FAILED', outcome: 'unknown', retryAllowed: false });
    assert.deepEqual(f.byAction(), ['preflight']);
    assert.deepEqual(f.states.map(row => row.status), ['installing']);
    assert.deepEqual(f.users.map(row => row.syncStatus), ['pending']);
    assert.equal(f.lockHeld, true);
    assert.equal((await f.click()).data.error.code, 'REBUILD_BUSY');
    assert.deepEqual(f.session.events, ['commit']);
    assert.deepEqual(f.opens, [id]);
});

test('package flow: late identity or reservation drift vetoes stdin on the open pinned channel', async t => {
    for (const kind of ['machine', 'grant', 'reservation']) await t.test(kind, async child => {
        const f = packageFlow(child);
        f.hooks.beforeAttestation = host => {
            if (kind === 'machine' && f.states[0]?.status === 'installing') host.machine = '1'.repeat(32);
        };
        f.hooks.beforeChannel = () => {
            if (f.states[0]?.status !== 'installing') return;
            if (kind === 'grant') { f.grants.pop(); f.grant(); }
            if (kind === 'reservation') f.users[0].syncStatus = 'drifted';
        };
        const { data } = await f.click();
        assert.deepEqual(data.error, { code: kind === 'reservation' ? 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN' : 'REBUILD_L2TP_IDENTITY_CHANGED',
            outcome: 'unknown', retryAllowed: false });
        assert.deepEqual(f.byAction(), ['preflight']);
        assert.deepEqual(f.session.events, ['commit']);
        assert.equal(f.lockHeld, true);
    });
});

test('package flow: unknown package ACKs and failures after package success leave the original reservation fenced', async t => {
    const cases = [
        ['missing ACK', () => ({ code: 75 })],
        ['wrong ID', () => wire({ ok: true, backupId: '0'.repeat(32), packagesReady: true })],
        ['not ready', ({ backupId }) => wire({ ok: true, backupId, packagesReady: false })],
        ['numeric ready', ({ backupId }) => wire({ ok: true, backupId, packagesReady: 1 })],
        ['extra field', ({ backupId }) => wire({ ok: true, backupId, packagesReady: true, packagePreparation: packageDigest })],
        ['duplicate field', ({ backupId }) => ({ code: 0,
            stdout: `{"ok":true,"backupId":"${backupId}","packagesReady":true,"packagesReady":true}\n` })],
        ['tainted stderr', ({ backupId }) => ({ ...wire({ ok: true, backupId, packagesReady: true }), stderr: 'unexpected\n' })],
        ['foreign no-write frame', () => ({ code: 70, stderr: 'DIRECT_NO_WRITE_COMMAND_FAILED\n' })],
        ['package guard refusal after reservation', () => ({ code: 70, stderr: 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n' }),
            undefined, undefined, 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE'],
        ['stock refusal after ACK', null, 'preflight', { code: 70, stderr: 'DIRECT_RUNTIME_NATIVE_UNIT_REQUIRED\n' }, 'RUNTIME_NATIVE_UNIT_REQUIRED'],
        ['still requests packages', null, 'preflight', wire({ machineId, packagePreparation: packageDigest }), 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE'],
        ['install no-write after ACK', null, 'install', { code: 70, stderr: 'DIRECT_NO_WRITE_BASELINE_CHANGED\n' }],
    ];
    for (const [name, badAck, last, failure, check] of cases) await t.test(name, async child => {
        const f = packageFlow(child, { reply(input) {
            if (input.action === 'prepare-packages') return badAck ? badAck(input) : wire({ ok: true, backupId: input.backupId, packagesReady: true });
            if (input.action === last) return failure;
        } });
        const { status, data } = await f.click();
        assert.equal(status, 409);
        assert.equal(data.error.outcome, 'unknown');
        assert.equal(data.error.retryAllowed, false);
        assert.equal(data.error.check, check);
        const actions = ['preflight', 'prepare-packages'];
        if (last) actions.push('preflight');
        if (last === 'install') actions.push('prepare', 'check', 'install');
        assert.deepEqual(f.byAction(), actions);
        assert.deepEqual(f.session.events, ['commit']);
        assert.deepEqual(f.states.map(row => row.status), ['installing']);
        assert.deepEqual(f.users.map(row => row.syncStatus), ['pending']);
        assert.equal(f.lockHeld, true);
        assert.equal((await f.click()).data.error.code, 'REBUILD_BUSY');
        // The persisted reservation also refuses a fresh Install if the
        // global lock is no longer present; it never acts as a resume token.
        f.loseLock();
        assert.equal((await f.click()).data.error.code, 'REBUILD_L2TP_NOT_FRESH_RELAY');
        assert.deepEqual(f.byAction(), actions);
        assert.deepEqual(f.opens, [id]);
    });
});

async function assertGrantReachesInstall(t, useGrantDb) {
    const f = admissionEffects(t, { useGrantDb });
    const original = { ...f.env };
    await assert.rejects(f.service.installRelay(id), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    assert.deepEqual(f.opens, []);
    f.grant();
    assert.deepEqual(await f.service.installRelay(id), { executionMode: 'rebuild', status: 'installed', nodeId: id });
    assert.deepEqual(f.frames.map(([, action]) => action), ['preflight', 'preflight', 'prepare', 'check', 'install', 'verify']);
    assert.deepEqual(f.effects, [[id, 'install']]);
    assert.deepEqual(f.states.map(row => [row.status, row.rebuildMachineId]), [['installed', machineId]]);
    assert.deepEqual(f.users.map(row => row.syncStatus), ['synced']);
    assert.deepEqual(f.env, original);
}

test('admission effects: DB-only grant reaches real Install on the same service instance', async t => {
    await assertGrantReachesInstall(t, false);
});

test('admission effects: GrantStore collection read reaches real Install on the same service instance', async t => {
    try { require.resolve('../rebuildRelayGrantStore'); }
    catch (error) {
        if (error.code !== 'MODULE_NOT_FOUND') throw error;
        return t.skip('Requires the separately owned GrantStore commit');
    }
    await assertGrantReachesInstall(t, true);
});

test('admission effects: changed SSH key refuses Install before commands or persistence', async t => {
    const f = admissionEffects(t);
    f.grant();
    f.hosts[0].key = Buffer.from('different host key');
    await assert.rejects(f.service.installRelay(id), { code: 'REBUILD_L2TP_IDENTITY_CHANGED', outcome: 'refused' });
    assert.deepEqual(f.opens, [id]);
    assert.deepEqual([f.frames, f.effects, f.states, f.users], [[], [], [], []]);
});

test('admission effects: accepted Install, shared account creation and Remove attest each receiver', async t => {
    const f = admissionEffects(t, { twoRelays: true });
    const [a, b] = f.hosts.map(host => host.binding.nodeId);
    f.grant();
    for (const nodeId of [a, b]) await f.service.installRelay(nodeId);
    assert.deepEqual(f.effects, [[a, 'install'], [b, 'install']]);
    f.frames.length = f.effects.length = 0;

    await f.service.createRelayAccount({ login: 'new-user', password: 'local-fixture-account-value' });
    assert.deepEqual(f.frames, [[a, 'check-chap'], [b, 'check-chap'], [a, 'sync-chap'], [b, 'sync-chap']]);
    assert.deepEqual(f.effects, [[a, 'sync-chap'], [b, 'sync-chap']]);
    assert.equal(f.users.filter(row => row.login === 'new-user' && row.syncStatus === 'synced').length, 2);
    f.frames.length = f.effects.length = 0;

    const estimate = await f.service.previewRemoveRelay(b);
    assert.deepEqual(estimate, { nodeId: b, accountCount: 2, activeSessions: 0, activeIpsec: 0, confirmable: true });
    assert.deepEqual(await f.service.confirmRemoveRelay(b, estimate), { executionMode: 'rebuild', status: 'not_installed', nodeId: b });
    assert.deepEqual(f.frames, [[b, 'session-count'], [b, 'session-count'], [b, 'prepare-remove'], [b, 'remove']]);
    assert.deepEqual(f.effects, [[b, 'remove']]);
    assert.deepEqual(f.states.map(row => [String(row.node), row.status]), [[a, 'installed'], [b, 'not_installed']]);
    assert.ok(!Object.hasOwn(f.states[1], 'backupId'));
    assert.deepEqual(f.users.map(row => [String(row.relayNode), row.login]).sort(), [[a, 'new-user'], [a, 'relay-bootstrap']]);
});

test('admission effects: machine change on Install dispatch prevents writes and keeps the reservation', async t => {
    const f = admissionEffects(t);
    f.grant();
    f.hooks.atDispatch = (action, host) => { if (action === 'install') host.machine = '8'.repeat(32); };
    await assert.rejects(f.service.installRelay(id), { code: 'REBUILD_L2TP_IDENTITY_CHANGED', outcome: 'unknown', retryAllowed: false });
    assert.deepEqual(f.effects, []);
    assert.deepEqual(f.frames.map(([, action]) => action), ['preflight', 'preflight', 'prepare', 'check', 'install']);
    assert.deepEqual(f.states.map(row => row.status), ['installing']);
});

test('admission effects: late Install attestation mismatch blocks the secret receiver and rollback', async t => {
    const f = admissionEffects(t);
    f.grant();
    f.hooks.beforeAttestation = host => {
        if (f.frames.at(-1)?.[1] === 'check') host.machine = '8'.repeat(32);
    };
    await assert.rejects(f.service.installRelay(id), { code: 'REBUILD_L2TP_IDENTITY_CHANGED', outcome: 'unknown', retryAllowed: false });
    assert.deepEqual(f.frames.map(([, action]) => action), ['preflight', 'preflight', 'prepare', 'check']);
    assert.deepEqual(f.effects, []);
    assert.deepEqual(f.states.map(row => row.status), ['installing']);
});

test('admission effects: a same-binding grant replacement during the Install stdin handoff sends no payload', async t => {
    const f = admissionEffects(t);
    f.grant();
    f.hooks.beforeChannel = () => {
        if (f.frames.at(-1)?.[1] === 'check') {
            f.grants.pop();
            f.grant();
        }
    };
    await assert.rejects(f.service.installRelay(id), { code: 'REBUILD_L2TP_IDENTITY_CHANGED', outcome: 'unknown', retryAllowed: false });
    assert.deepEqual(f.frames.map(([, action]) => action), ['preflight', 'preflight', 'prepare', 'check']);
    assert.deepEqual(f.effects, []);
    assert.deepEqual(f.states.map(row => row.status), ['installing']);
});

test('admission effects: a foreign second machine blocks every account write in a mixed ENV/DB cohort', async t => {
    const f = admissionEffects(t, { twoRelays: true });
    const peer = f.hosts[1];
    f.grant(peer);
    for (const host of f.hosts) await f.service.installRelay(host.binding.nodeId);
    f.frames.length = 0;
    f.effects.length = 0;
    peer.machine = '8'.repeat(32);
    await assert.rejects(f.service.createRelayAccount({ login: 'new-user', password: 'local-fixture-account-value' }),
        { code: 'REBUILD_L2TP_IDENTITY_CHANGED' });
    assert.deepEqual(f.frames, [[f.hosts[0].binding.nodeId, 'check-chap']], 'changed peer received no account payload');
    assert.deepEqual([f.effects, f.intents.writes], [[], []]);
    assert.deepEqual(f.users.map(row => row.login), ['relay-bootstrap', 'relay-bootstrap']);
});

test('admission effects: Remove rejects a changed machine after confirmation without host writes', async t => {
    const f = admissionEffects(t);
    f.grant();
    await f.service.installRelay(id);
    const estimate = await f.service.previewRemoveRelay(id);
    assert.equal(estimate.confirmable, true);
    f.frames.length = 0;
    f.effects.length = 0;
    f.hooks.atDispatch = (action, host) => { if (action === 'remove') host.machine = '8'.repeat(32); };
    await assert.rejects(f.service.confirmRemoveRelay(id, estimate), { code: 'REBUILD_L2TP_IDENTITY_CHANGED', retryAllowed: false });
    assert.deepEqual(f.frames.map(([, action]) => action), ['session-count', 'prepare-remove', 'remove']);
    assert.deepEqual(f.effects, []);
    assert.deepEqual(f.states.map(row => row.status), ['removing']);
    assert.equal(f.users.length, 1);
});

test('admission effects: a changed machine during the Remove census is not unavailable telemetry', async t => {
    const f = admissionEffects(t);
    f.grant();
    await f.service.installRelay(id);
    const estimate = await f.service.previewRemoveRelay(id);
    assert.equal(estimate.confirmable, true);
    f.frames.length = 0;
    f.effects.length = 0;
    f.hosts[0].machine = '8'.repeat(32);
    await assert.rejects(f.service.previewRemoveRelay(id), { code: 'REBUILD_L2TP_IDENTITY_CHANGED' });
    await assert.rejects(f.service.confirmRemoveRelay(id, estimate), { code: 'REBUILD_L2TP_IDENTITY_CHANGED' });
    assert.deepEqual(f.frames, [], 'no census payload on either request');
    assert.deepEqual(f.effects, []);
    assert.deepEqual(f.states.map(row => row.status), ['installed']);
    assert.equal(f.users.length, 1);
});

test('admission effects: the census stdin guard retains an identity veto while closing the pinned channel', async t => {
    const f = admissionEffects(t);
    f.grant();
    await f.service.installRelay(id);
    f.frames.length = f.effects.length = 0;
    f.hooks.beforeChannel = () => {
        f.grants.pop();
        f.grant();
    };
    await assert.rejects(f.service.previewRemoveRelay(id), { code: 'REBUILD_L2TP_IDENTITY_CHANGED' });
    assert.deepEqual([f.frames, f.effects], [[], []]);
    assert.deepEqual(f.states.map(row => row.status), ['installed']);
});

test('admission effects: Remove confirmation cannot reuse an estimate from a replaced grant generation', async t => {
    const f = admissionEffects(t);
    f.grant();
    await f.service.installRelay(id);
    const estimate = await f.service.previewRemoveRelay(id);
    assert.equal(estimate.confirmable, true);
    f.grants.pop();
    f.grant();
    f.opens.length = f.frames.length = f.effects.length = 0;
    await assert.rejects(f.service.confirmRemoveRelay(id, estimate), { code: 'REBUILD_L2TP_IDENTITY_CHANGED' });
    assert.deepEqual([f.opens, f.frames, f.effects], [[], [], []]);
    assert.deepEqual(f.states.map(row => row.status), ['installed']);
});

test('operator list installs two relays under Apply exclusion and records their distinct physical IDs', async t => {
    const f = fixture(t);
    sessionFixture(t, f);
    const second = { ...f.nodes[0], _id: oid('c'.repeat(24)), ip: '192.0.2.20', ssh: { port: 2222, username: 'root' } };
    const rows = [f.nodes[0], second].map(({ _id, ip, ssh }, i) => ({ nodeId: String(_id), host: ip,
        ...ssh, machineId: (i ? 'd' : 'e').repeat(32), sshHostKeySha256: (i ? '1' : '2').repeat(64) }));
    f.nodes.push(second);
    f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(rows);
    const preflight = [];
    const service = f.create({ createRelayDirect: ({ node }) => {
        const selected = rows.find(row => row.nodeId === String(node._id));
        return {
            async preflight() {
                assert.equal(f.lockHeld, true);
                preflight.push(selected.nodeId);
                return { machineId: selected.machineId, ppp: true, masked: false, unitsLoaded: true };
            },
            async prepare({ nodeId }) { assert.equal(nodeId, selected.nodeId); return { backupId: selected.machineId }; },
            async checkChap(installation, current, desired, guard) {
                await guard();
                assert.ok(f.lockHeld);
                assert.equal(installation.nodeId, rows[0].nodeId);
                assert.deepEqual(desired, current);
                return { changed: false };
            },
            async install(plan, guard) { await guard(); },
            async verify() { return true; },
            async close() {},
        };
    } });
    for (const { nodeId } of rows) assert.equal((await service.installRelay(nodeId)).status, 'installed');
    assert.deepEqual(preflight, rows.map(({ nodeId }) => nodeId));
    assert.deepEqual(f.states.map(row => [String(row.node), row.rebuildMachineId]), rows.map(row => [row.nodeId, row.machineId]));
});

test('list Install refuses a bad card, host machine, or changed binding before reservation', async t => {
    const f = fixture(t);
    const row = { nodeId: id, host: f.nodes[0].ip, ...f.nodes[0].ssh, machineId, sshHostKeySha256: '1'.repeat(64) };
    f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([row]);
    const noLock = f.create({ locks: { run: () => assert.fail('invalid list must not acquire Apply lock') } });
    for (const entries of [[], [row, row]]) {
        f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(entries);
        await assert.rejects(noLock.installRelay(id), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    }
    f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([row]);
    const driftAtLock = f.create({ locks: { run: async fn => {
        f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([{ ...row, sshHostKeySha256: '2'.repeat(64) }]);
        return fn(async () => true);
    } } });
    await assert.rejects(driftAtLock.installRelay(id), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    assert.deepEqual(f.events, []);
    f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([row]);
    const service = f.create();
    f.nodes[0].ssh.port++;
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_BINDING_MISMATCH' });
    assert.deepEqual(f.events, []);
    f.nodes[0].ssh.port--;
    const preflight = f.hooks.preflight;
    f.hooks.preflight = async () => ({ ...await preflight(), machineId: 'e'.repeat(32) });
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH' });
    assert.deepEqual(f.events.splice(0), ['connect', 'preflight', 'close']);
    f.hooks.preflight = preflight;
    const prepare = f.hooks.prepare;
    f.hooks.prepare = async () => {
        f.nodes[0].ssh.port++;
        return prepare();
    };
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_BINDING_MISMATCH' });
    assert.deepEqual(f.events, ['connect', 'preflight', 'prepare', 'close']);
    assert.deepEqual([f.states, f.users], [[], []]);
});

test('createRebuildService installs follow-relay, reserves encrypted usable credentials before dispatch, and persists an owner receipt', async t => {
    const f = fixture(t);
    const downstream = { _id: oid(), type: 'xray', active: true, cascadeRole: 'relay', ip: '192.0.2.5' };
    const exit = { _id: oid(), type: 'xray', active: true, cascadeRole: 'bridge', ip: '192.0.2.6' };
    f.nodes.push(downstream, exit);
    addLink(f, oid(id), downstream._id);
    addLink(f, downstream._id, exit._id, { enabled: true, domains: ['full:target.invalid'] });
    f.hooks.install = async guard => {
        await guard();
        assert.equal(f.states[0].status, 'installing');
        assert.equal(f.users[0].syncStatus, 'pending');
    };
    f.hooks.verify = async () => { assert.equal(f.states[0].status, 'installing'); return true; };
    const service = f.create();
    const result = await service.installRelay(id);
    assert.deepEqual(result, { executionMode: 'rebuild', status: 'installed', nodeId: id });
    const { desired } = f.prepared;
    const [row] = f.states, [user] = f.users;
    assert.deepEqual(f.prepared.controlPlaneAddresses, ['fixture.invalid', '192.0.2.4', 'relay.fixture.invalid', '192.0.2.5', '192.0.2.6']);
    assert.equal(f.prepared.carryDomain, true);
    assert.equal(f.prepared.nodeId, id);
    assert.equal(desired.credentialRevision, 1);
    assert.deepEqual([desired.tproxyPort, desired.fwmark, desired.routeTable], [12345, 100, 100]);
    assert.match(desired.clientCidr, /^10\.255\.\d+\.0\/24$/);
    assert.match(desired.psk, /^[A-Za-z0-9_-]{32}$/);
    assert.deepEqual([row.status, row.desiredState, row.routingMode, row.routingVersion, row.secretRevision], ['installed', 'installed', 'follow-relay', 1, 1]);
    assert.equal(row.routeGroup, undefined);
    assert.equal(row.backupId, backupId);
    assert.equal(row.rebuildMachineId, machineId);
    assert.match(row.rebuildInstallToken, /^[a-f0-9-]{36}$/);
    assert.equal(decrypt(row.pskEncrypted, f.env.ENCRYPTION_KEY), desired.psk);
    assert.equal(desired.users.length, 1);
    assert.deepEqual(desired.users[0], { login: user.login, password: decrypt(user.passwordEncrypted, f.env.ENCRYPTION_KEY),
        ipAddress: user.ip, enabled: true });
    assert.deepEqual([user.syncStatus, user.desiredRevision, user.appliedRevision], ['synced', 1, 1]);
    assert.equal(JSON.stringify([result, row, user]).includes(desired.users[0].password), false);
    assert.equal(JSON.stringify([result, row, user]).includes(desired.psk), false);
    assert.deepEqual(f.events, ['connect', 'preflight', 'prepare', 'RelayL2tpState:update', 'L2tpUser:update', 'install',
        'verify', 'L2tpUser:update', 'RelayL2tpState:update', 'close']);
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    assert.equal(f.events.filter(x => x === 'connect').length, 1);
});

test('verified bootstrap rollback restores exact existing row', async t => {
    const f = fixture(t);
    f.states.push(priorRow());
    const old = copy(f.states[0]);

    f.hooks.verify = async () => false;
    await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_VERIFY_FAILED' });
    assert.deepEqual(f.states, [old]);
    assert.deepEqual(f.users, []);
    assert.deepEqual(f.events.slice(-5), ['verify', 'rollback', 'L2tpUser:delete', 'RelayL2tpState:update', 'close']);
});

test('later Apply retains ownership and adds the new policy to the live follow-relay profile', async t => {
    t.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());
    const f = fixture(t, '1'.repeat(32));
    const { createHash } = require('node:crypto');
    const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
    t.mock.method(require('../configGenerator'), 'buildPanelInlineCertificate', () => null);
    t.mock.method(Link.db, 'transaction', async fn => fn({}));
    t.mock.method(State.collection, 'updateOne', async (filter, update) => {
        const row = f.states[0];
        assert.ok(matches({ routeGroup: null, ...row }, filter));
        Object.assign(row, update.$set);
        return { acknowledged: true, matchedCount: 1 };
    });
    Object.assign(f.nodes[0], { port: 21000, xray: { security: 'none', transport: 'tcp', apiPort: 31000 } });
    const files = {};
    const service = f.create({
        sync: { _getUsersForNode: async () => [] }, cache: { invalidateAllSubscriptions: async () => {} },
        connect: () => assert.fail('installed relay must use the pinned transport'),
    });
    f.hooks.verify = async () => {
        const installed = { ...f.states[0], status: 'installed' };
        for (const { profile, config } of composeRebuildProfiles({ nodes: f.nodes, links: [], followRelayStates: [installed],
            controlPlaneAddresses: f.prepared.controlPlaneAddresses })) files[profile] = config;
        return true;
    };
    await service.installRelay(id);
    const old = copy(f.states[0]);
    const pppTag = 'rebuild-relay-ingress';
    const oldPort = files.main.inbounds.find(x => x.tag === pppTag).port;
    f.nodes[0].aclRules = ['reject(example.invalid)'];
    const { bindProfileWire, pin } = require('./helpers/rebuildBoundProfileWire');
    f.env.C3_REBUILD_L2TP_SSH_SHA256 = pin;
    f.nodes[0].ssh.password = 'fixture-ssh-auth';
    const preparedProof = '2'.repeat(64), publishedProof = '3'.repeat(64);
    const actions = [];
    let staged;
    bindProfileWire(t.mock.method.bind(t.mock), f.nodes[0].ip, machineId, () => ({
        relayNetwork: async ({ action, backupId, proof, nodeId, profiles }) => {
            actions.push(action);
            assert.equal(backupId, old.backupId);
            switch (action) {
                case 'check-apply-network':
                case 'prepare-apply-network':
                    assert.equal(proof, undefined);
                    return preparedProof;
                case 'verify-apply-network':
                    assert.equal(proof, preparedProof);
                    return preparedProof;
                case 'publish-apply-profiles':
                    assert.equal(proof, preparedProof);
                    assert.equal(nodeId, id);
                    assert.deepEqual(profiles, Object.fromEntries(staged.map(({ profile, config }) => [profile,
                        createHash('sha256').update(JSON.stringify(config)).digest('hex')])));
                    for (const { profile, config } of staged) files[profile] = structuredClone(config);
                    return publishedProof;
                case 'restart-apply-network':
                case 'finalize-apply-profiles':
                    assert.equal(proof, publishedProof);
                    return publishedProof;
                default:
                    assert.fail('unexpected DIRECT Apply action');
            }
        },
        requireSupportedCore: async () => {}, read: async name => structuredClone(files[name]),
        close: async () => {}, stagePair: async pair => { staged = pair; },
        // This callback models the stop of the old BRIDGE unit, not publication.
        putPair: async () => assert.equal(actions.at(-1), 'publish-apply-profiles'),
    }));
    assert.equal((await service.execute({ nodeId: id })).allowed, true);
    assert.deepEqual(actions, ['check-apply-network', 'prepare-apply-network', 'verify-apply-network',
        'publish-apply-profiles', 'restart-apply-network', 'finalize-apply-profiles']);
    assert.equal(files.main.inbounds.find(x => x.tag === pppTag).port, oldPort);
    assert.ok(files.main.routing.rules.some(x => x.outboundTag === 'block' && x.inboundTag.includes(pppTag)
        && x.domain?.includes('full:example.invalid')));
    assert.deepEqual([f.states[0].backupId, f.states[0].rebuildInstallToken, f.states[0].rebuildMachineId, f.states[0].pskEncrypted],
        [old.backupId, old.rebuildInstallToken, old.rebuildMachineId, old.pskEncrypted]);
    assert.equal(f.events.includes('rollback'), false);
    assert.equal(f.lockHeld, false);
});

test('settled install failure with verified rollback restores prior absence', async t => {
    const f = fixture(t);
    f.hooks.install = async () => { throw Object.assign(new Error('private output'), { commandSettled: true }); };
    await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_INSTALL_FAILED', message: 'REBUILD_L2TP_INSTALL_FAILED' });
    assert.deepEqual(f.states, []);
    assert.deepEqual(f.users, []);
    assert.equal(f.events.includes('verify'), false);
    assert.equal(f.events.filter(x => x === 'rollback').length, 1);
});

test('unverified rollback keeps the reservation and credentials', async t => {
    const f = fixture(t);
    f.hooks.install = async () => false;
    f.hooks.rollback = async () => false;
    const service = f.create();
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN' });
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    assert.equal(f.states[0].status, 'installing');
    assert.equal(f.users[0].syncStatus, 'pending');
    assert.equal(f.events.filter(x => x === 'rollback').length, 1);
});

test('SSH acknowledgement loss never starts rollback; close cannot mask the outcome', async t => {
    const f = fixture(t);
    f.hooks.install = async () => { throw new Error('remote command may still be running'); };
    f.hooks.close = async () => { throw new Error('cleanup'); };
    const service = f.create();
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN' });
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    assert.deepEqual(f.events.slice(-2), ['install', 'close']);
    assert.equal(f.states[0].status, 'installing');
});

test('lost DB finish response is not retried or rolled back even when the write committed', async t => {
    const f = fixture(t);
    f.stateHooks.update = ({ update, apply }) => {
        const result = apply();
        if (update.$set?.status === 'installed') throw new Error('committed, but acknowledgement lost');
        return result;
    };
    const service = f.create();
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN' });
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    assert.equal(f.states[0].status, 'installed');
    assert.equal(f.users[0].syncStatus, 'synced');
    assert.equal(f.events.filter(x => x === 'RelayL2tpState:update').length, 2);
    assert.equal(f.events.includes('rollback'), false);
});

test('DB reservation CAS refuses a changed prior snapshot before dispatch', async t => {
    const f = fixture(t);
    const before = priorRow();
    f.states.push(before);
    f.hooks.prepare = async () => { before.secretRevision = 2; return { backupId }; };
    await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_RESERVATION_FAILED' });
    assert.equal(f.events.includes('install'), false);
    assert.equal(f.states[0].secretRevision, 2);
    assert.deepEqual(f.users, []);
});

test('unknown reservation acknowledgement stops before remote install', async t => {
    const f = fixture(t);
    f.stateHooks.update = ({ apply }) => { apply(); throw new Error('write acknowledgement lost'); };
    const service = f.create();
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_RESERVATION_FAILED' });
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    assert.equal(f.states[0].status, 'installing');
    assert.deepEqual(f.users, []);
    assert.equal(f.events.includes('install'), false);
    assert.equal(f.events.includes('rollback'), false);
});

test('shared Mongo lock excludes Apply and another install, and withNode waits for the previous node writer', async t => {
    const f = fixture(t);
    const nodeEntered = deferred(), leaveNode = deferred(), entered = deferred(), leaveInstall = deferred();
    const writing = withNode(id, async () => { nodeEntered.done(); await leaveNode.promise; });
    await nodeEntered.promise;
    f.hooks.install = async () => { entered.done(); await leaveInstall.promise; };
    const pending = f.create().installRelay(id);
    try {
        await assert.rejects(f.create().execute({ nodeId: id, preview: true }), { code: 'REBUILD_BUSY' });
        assert.deepEqual(f.events, []);
        leaveNode.done();
        await entered.promise;
        await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_BUSY' });
        await assert.rejects(f.create().execute({ nodeId: id }), { code: 'REBUILD_BUSY' });
    } finally {
        leaveNode.done();
        leaveInstall.done();
        await Promise.all([writing, pending]);
    }
    assert.equal(f.events.filter(x => x === 'install').length, 1);
});

test('lost global lock forbids rollback even after a negative verification', async t => {
    const f = fixture(t);
    f.hooks.verify = async () => { f.loseLock(); return false; };
    await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN' });
    assert.equal(f.events.includes('rollback'), false);
    assert.equal(f.states[0].status, 'installing');
});

test('non-relay, orphan credentials, and unapplied topology are refused before any transport', async t => {
    const f = fixture(t);
    const service = f.create();
    f.nodes[0].cascadeRole = 'portal';
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    f.nodes[0].cascadeRole = 'relay';
    f.users.push({ _id: oid(), relayNode: oid(id), login: 'existing' });
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    f.users.pop();
    addLink(f, oid(id), oid());
    f.links[0].status = 'pending';
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_TOPOLOGY_NOT_APPLIED',
        outcome: 'refused', check: 'REBUILD_LINKS_NOT_APPLIED' });
    assert.deepEqual(f.events, []);
});
