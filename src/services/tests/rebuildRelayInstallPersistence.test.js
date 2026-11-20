'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: equal } = require('node:util');
const { Types, mongo } = require('mongoose');
const { createRebuildService } = require('../rebuildService');
const { makeLocks, withNode } = require('../rebuildLocks');
const { decrypt } = require('../../modules/relay-l2tp/services/secretBoxService');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
const Node = require('../../models/hyNodeModel');
const Link = require('../../models/cascadeLinkModel');
const joined = require('./helpers/rebuildRelayInstallJoined');

const id = 'a'.repeat(24), machineId = 'b'.repeat(32), backupId = 'rebuild-unique-backup';
const oid = value => new Types.ObjectId(value);
const copy = value => mongo.BSON.deserialize(mongo.BSON.serialize(value));
const matches = (row, where) => Object.entries(where).every(([key, value]) => {
    if (key === '$or') return value.some(filter => matches(row, filter));
    if (value && Object.hasOwn(value, '$exists')) return Object.hasOwn(row, key) === value.$exists
        && (!Object.hasOwn(value, '$eq') || equal(row[key], value.$eq));
    if (value && Object.hasOwn(value, '$eq')) return equal(row[key], value.$eq);
    if (value && Object.hasOwn(value, '$ne')) return !equal(row[key], value.$ne);
    if (value && Object.hasOwn(value, '$in')) return value.$in.some(item => equal(row[key], item));
    if (value === null) return row[key] == null;
    return equal(row[key], value);
});
function project(row, projection) {
    if (!row) return null;
    const columns = Object.keys(projection ?? {});
    if (columns.some(key => projection[key] === 1)) return copy(Object.fromEntries(
        Object.entries(row).filter(([key]) => key === '_id' || projection[key] === 1)));
    return copy(Object.fromEntries(Object.entries(row).filter(([key]) => projection?.[key] !== 0)));
}

// Real Mongoose schemas, casting and projections. Only the backing collection
// and direct host commands are simulated; no process, Mongo URI or SSH socket.
function bind(t, model, data, traces) {
    const handlers = {};
    const invoke = async (kind, where, update, options) => {
        assert.ok((where._id?.$eq ?? where._id) instanceof Types.ObjectId);
        assert.deepEqual(options.writeConcern, { w: 'majority' });
        traces.push(`${model.modelName}:${kind}`);
        const index = data.findIndex(row => matches(row, where));
        const apply = () => {
            if (kind === 'delete') {
                if (index !== -1) data.splice(index, 1);
                return { acknowledged: true, deletedCount: Number(index !== -1) };
            }
            if (index === -1 && options.upsert) {
                data.push(copy(update.$setOnInsert));
                return { acknowledged: true, upsertedCount: 1, matchedCount: 0 };
            }
            if (index !== -1) {
                Object.assign(data[index], copy(update.$set ?? {}));
                for (const key of Object.keys(update.$unset ?? {})) delete data[index][key];
            }
            return { acknowledged: true, matchedCount: Number(index !== -1), upsertedCount: 0 };
        };
        return handlers[kind] ? handlers[kind]({ update, apply }) : apply();
    };
    t.mock.method(model.collection, 'findOne', async (where, { projection } = {}) => project(
        data.find(row => matches(row, where)), projection));
    t.mock.method(model.collection, 'find', (where, { projection, limit } = {}) => ({
        toArray: async () => data.filter(row => matches(row, where)).slice(0, limit ?? data.length).map(row => project(row, projection)),
    }));
    t.mock.method(model.collection, 'updateMany', (where, update, options) => invoke('update', where, update, options));
    t.mock.method(model.collection, 'deleteMany', (where, options) => invoke('delete', where, null, options));
    return handlers;
}

function deferred() {
    let done;
    const promise = new Promise(resolve => { done = resolve; });
    return { promise, done };
}
function fixture(t) {
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: id,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, ENCRYPTION_KEY: 'test-only-credential-key-'.repeat(2), PANEL_DOMAIN: 'fixture.invalid' };
    const nodes = [{ _id: oid(id), ip: '192.0.2.4', domain: 'relay.fixture.invalid', type: 'xray', active: true,
        cascadeRole: 'relay', ssh: { port: 22, username: 'fixture' } }];
    const links = [], states = [], users = [], events = [];
    const stateHooks = bind(t, State, states, events);
    bind(t, User, users, events);
    bind(t, Node, nodes, events);
    bind(t, Link, links, events);
    let lock;
    const lockCollection = {
        async insertOne(row) {
            if (lock) throw Object.assign(new Error('duplicate'), { code: 11000 });
            lock = row;
        },
        async findOne(filter) { return lock && matches(lock, filter) ? lock : null; },
        async deleteOne(filter) { if (lock && matches(lock, filter)) lock = null; },
    };
    const plan = { backupId };
    let prepared;
    const hooks = {
        preflight: async () => ({ ppp: true, masked: false, machineId }),
        prepare: async () => plan,
        install: async guard => { await guard(); return true; },
        verify: async () => true,
        rollback: async guard => { await guard(); return true; },
        close: async () => {},
    };
    const create = (overrides = {}) => createRebuildService({ Node, Link, State, L2tpUser: User, env, cache: {}, sync: {}, locks: makeLocks(lockCollection),
        createRelayDirect: ({ node, env: driverEnv }) => {
            events.push('connect');
            assert.deepEqual(node.ssh, nodes[0].ssh);
            assert.equal(driverEnv, env);
            return {
                async preflight() { events.push('preflight'); return hooks.preflight(); },
                async prepare(args) { events.push('prepare'); prepared = args; return hooks.prepare(); },
                async install(p, guard) { events.push('install'); assert.equal(p, plan); return hooks.install(guard); },
                async verify(p) { events.push('verify'); assert.equal(p, plan); return hooks.verify(); },
                async rollback(p, guard) { events.push('rollback'); assert.equal(p, plan); return hooks.rollback(guard); },
                async close() { events.push('close'); return hooks.close(); },
            };
        },
        ...overrides,
    });
    return { env, events, create, nodes, links, states, users, hooks, stateHooks, get prepared() { return prepared; },
        get lockHeld() { return !!lock; },
        loseLock: () => { lock = undefined; } };
}

function priorRow() {
    return { _id: oid(), node: oid(id), desiredState: 'absent', status: 'not_installed', secretRevision: 0,
        clientCidr: '10.66.0.0/24', pskEncrypted: '', tproxyPort: null, routeGroup: null, updatedAt: new Date('2020-01-02') };
}

function addLink(f, portalNode, bridgeNode, geoRouting) {
    f.links.push({ _id: oid(), portalNode, bridgeNode, mode: 'reverse', active: true, status: 'deployed', ...(geoRouting ? { geoRouting } : {}) });
}

joined({ fixture, id, oid, machineId });

test('operator list installs two relays under Apply exclusion and records their distinct physical IDs', async t => {
    const f = fixture(t);
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
                return { machineId: selected.machineId, ppp: true, masked: false };
            },
            async prepare({ nodeId }) { assert.equal(nodeId, selected.nodeId); return { backupId }; },
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

test('verified rollback restores exact existing row and deletes only bootstrap account', async t => {
    const f = fixture(t);
    f.states.push(priorRow());
    const old = copy(f.states[0]);
    const other = { _id: oid(), relayNode: oid(), login: 'unrelated' };
    f.users.push(other);
    f.hooks.verify = async () => false;
    await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_VERIFY_FAILED' });
    assert.deepEqual(f.states, [old]);
    assert.deepEqual(f.users, [other]);
    assert.deepEqual(f.events.slice(-5), ['verify', 'rollback', 'L2tpUser:delete', 'RelayL2tpState:update', 'close']);
});

test('later Apply retains ownership and adds the new policy to the live follow-relay profile', async t => {
    t.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());
    const f = fixture(t);
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
        connect: () => ({ requireSupportedCore: async () => {}, read: async name => structuredClone(files[name]),
            close: async () => {}, stagePair: async () => {}, putPair: async pair => {
                for (const { profile, config } of pair) files[profile] = structuredClone(config);
            } }),
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
    assert.equal((await service.execute({ nodeId: id })).allowed, true);
    assert.equal(files.main.inbounds.find(x => x.tag === pppTag).port, oldPort);
    assert.ok(files.main.routing.rules.some(x => x.outboundTag === 'block' && x.inboundTag.includes(pppTag)
        && x.domain?.includes('full:example.invalid')));
    assert.deepEqual([f.states[0].backupId, f.states[0].rebuildInstallToken, f.states[0].rebuildMachineId, f.states[0].pskEncrypted],
        [old.backupId, old.rebuildInstallToken, old.rebuildMachineId, old.pskEncrypted]);
    assert.equal(f.events.includes('rollback'), false);
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
    await assert.rejects(service.installRelay(id), { code: 'REBUILD_L2TP_TOPOLOGY_NOT_APPLIED' });
    assert.deepEqual(f.events, []);
});
