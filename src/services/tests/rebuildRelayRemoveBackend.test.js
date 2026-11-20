'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: equal } = require('node:util');
const { Types, mongo } = require('mongoose');
const { createRebuildService } = require('../rebuildService');
const { makeLocks, withNode } = require('../rebuildLocks');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
const Node = require('../../models/hyNodeModel');
const Link = require('../../models/cascadeLinkModel');
const { encrypt, decrypt } = require('../../modules/relay-l2tp/services/secretBoxService');

const id = 'a'.repeat(24), machineId = 'b'.repeat(32), backupId = 'c'.repeat(32);
const oid = value => new Types.ObjectId(value);
const copy = value => mongo.BSON.deserialize(mongo.BSON.serialize(value));
const matches = (row, where) => Object.entries(where).every(([key, value]) => {
    if (key === '$or') return value.some(filter => matches(row, filter));
    if (value && Object.hasOwn(value, '$exists')) return Object.hasOwn(row, key) === value.$exists
        && (!Object.hasOwn(value, '$eq') || equal(row[key], value.$eq));
    if (value && Object.hasOwn(value, '$eq')) return equal(row[key], value.$eq);
    if (value && Object.hasOwn(value, '$ne')) return !equal(row[key], value.$ne);
    if (value && Object.hasOwn(value, '$in')) return value.$in.some(item => equal(row[key], item));
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
        if (!options.session) assert.deepEqual(options.writeConcern, { w: 'majority' });
        traces.push(`${model.modelName}:${kind}`);
        const rows = options.session?.rows.get(data) ?? data;
        const apply = () => {
            const index = rows.findIndex(row => matches(row, where));
            if (kind === 'delete') {
                if (index !== -1) rows.splice(index, 1);
                return { acknowledged: true, deletedCount: Number(index !== -1) };
            }
            if (index === -1 && options.upsert) {
                rows.push(copy(update.$setOnInsert));
                return { acknowledged: true, upsertedCount: 1, matchedCount: 0 };
            }
            if (index !== -1) {
                Object.assign(rows[index], copy(update.$set ?? {}));
                for (const key of Object.keys(update.$unset ?? {})) delete rows[index][key];
            }
            return { acknowledged: true, matchedCount: Number(index !== -1), upsertedCount: 0 };
        };
        return handlers[kind] ? handlers[kind]({ where, update, apply, session: options.session }) : apply();
    };
    t.mock.method(model.collection, 'findOne', async (where, { projection, session } = {}) => project(
        (session?.rows.get(data) ?? data).find(row => matches(row, where)), projection));
    t.mock.method(model.collection, 'find', (where, { projection, limit, session } = {}) => ({
        toArray: async () => (session?.rows.get(data) ?? data).filter(row => matches(row, where))
            .slice(0, limit).map(row => project(row, projection)),
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
    const userHooks = bind(t, User, users, events);
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
    const removePlan = Object.freeze({ opaque: true });
    let removeInput;
    const hooks = {
        preflight: async () => ({ ppp: true, masked: false, machineId }),
        prepare: async () => plan,
        install: async guard => { await guard(); return true; },
        verify: async () => true,
        rollback: async guard => { await guard(); return true; },
        prepareRemove: async () => removePlan,
        remove: async guard => { await guard(); return true; },
        close: async () => {},
    };
    const create = (overrides = {}) => createRebuildService({ Node, Link, State, L2tpUser: User, env, cache: {}, sync: {}, locks: makeLocks(lockCollection),
        assertNoRelayAccountIntent: async () => {},
        createRelayDirect: ({ node, env: driverEnv }) => {
            events.push('connect');
            assert.deepEqual(node.ssh, nodes[0].ssh);
            assert.equal(driverEnv, env);
            return {
                async preflight() { events.push('preflight'); return hooks.preflight(); },
                async prepare(args) { events.push('prepare'); return hooks.prepare(); },
                async install(p, guard) { events.push('install'); assert.equal(p, plan); return hooks.install(guard); },
                async verify(p) { events.push('verify'); assert.equal(p, plan); return hooks.verify(); },
                async rollback(p, guard) { events.push('rollback'); assert.equal(p, plan); return hooks.rollback(guard); },
                async prepareRemove(input) { events.push('prepareRemove'); removeInput = input; return hooks.prepareRemove(); },
                async remove(p, guard) { events.push('remove'); assert.equal(p, removePlan); return hooks.remove(guard); },
                async close() { events.push('close'); return hooks.close(); },
            };
        },
        ...overrides,
    });
    return { env, events, create, nodes, links, states, users, hooks, stateHooks, userHooks, get removeInput() { return removeInput; },
        loseLock: () => { lock = undefined; } };
}

async function installed(t) {
    const f = fixture(t);
    const service = f.create();
    await service.installRelay(id);
    f.events.length = 0;
    return { ...f, get removeInput() { return f.removeInput; }, service };
}

const outcomeUnknown = { code: 'REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN' };
const finishUnknown = { code: 'REBUILD_L2TP_REMOVE_FINISH_OUTCOME_UNKNOWN' };
const noOwner = { code: 'REBUILD_L2TP_REMOVE_NOT_OWNED' };
const privateError = () => new Error('private fixture details');

async function sharedFixture(t) {
    const f = await installed(t);
    const peerId = 'e'.repeat(24), peerMachine = 'd'.repeat(32), peerIp = '192.0.2.200';
    for (const node of f.nodes) node.ssh.username = 'root';
    f.nodes.push({ ...f.nodes[0], _id: oid(peerId), ip: peerIp });
    f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(f.nodes.map(({ _id, ip, ssh }, i) => ({
        nodeId: String(_id), host: ip, ...ssh, machineId: i ? peerMachine : machineId,
        sshHostKeySha256: (i ? '2' : '1').repeat(64),
    })));
    const target = f.states[0], prefix = target.poolStart.replace(/\.\d+$/, '');
    const peerPrefix = prefix === '10.255.16' ? '10.255.17' : '10.255.16';
    f.states.push({ ...copy(target), _id: oid(), node: oid(peerId), rebuildMachineId: peerMachine,
        backupId: 'f'.repeat(32), rebuildInstallToken: 'eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee',
        clientCidr: `${peerPrefix}.0/24`, localAddress: `${peerPrefix}.1`, poolStart: `${peerPrefix}.10`, poolEnd: `${peerPrefix}.250` });
    f.users.push({ ...copy(f.users[0]), _id: oid(), login: 'disabled-user', ip: `${prefix}.11`, enabled: false,
        desiredRevision: 3, appliedRevision: 3, passwordEncrypted: encrypt('fixture-disabled', f.env.ENCRYPTION_KEY) });
    f.users.push(...f.users.map(row => ({ ...copy(row), _id: oid(), relayNode: oid(peerId), ip: row.ip.replace(prefix, peerPrefix) })));
    const selected = () => f.users.filter(row => String(row.relayNode) === id);
    const sibling = () => f.users.filter(row => String(row.relayNode) === peerId);
    t.mock.method(User.collection, 'countDocuments', async where => f.users.filter(row => matches(row, where)).length);
    const bridgeNode = oid();
    f.links.push({ _id: oid(), portalNode: oid(id), bridgeNode, mode: 'reverse', active: true, status: 'deployed',
        rebuildApplied: { listener: oid(id), mode: 'reverse', protocol: 'vless', port: 22010,
            uuid: '00000000-0000-4000-8000-000000000009' } });

    const attempts = [];
    const dbHooks = {};
    class Session {
        transaction = { transition: value => { assert.equal(value, 'TRANSACTION_COMMITTED'); this.active = false; } };
        startTransaction(options) {
            assert.deepEqual(options, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            this.active = true;
            this.rows = new Map([f.states, f.users].map(rows => [rows, rows.map(copy)]));
        }
        inTransaction() { return this.active; }
        abortTransaction() { attempts.push('abort'); this.active = false; }
        endSession() { assert.equal(this.active, false); }
    }
    t.mock.method(State.db, 'startSession', async () => new Session());
    t.mock.method(State.db, 'getClient', () => ({ db(name) {
        assert.equal(name, 'admin');
        return { async command(command, { session }) {
            assert.equal(command.commitTransaction, 1);
            assert.equal(command.writeConcern.w, 'majority');
            assert.ok(session.inTransaction());
            attempts.push('commit');
            const apply = () => {
                for (const [rows, pending] of session.rows) rows.splice(0, rows.length, ...pending);
                return { ok: 1 };
            };
            return dbHooks.commit ? dbHooks.commit(apply) : apply();
        } };
    } }));
    const frames = [], census = '3'.repeat(64), baseline = '4'.repeat(64);
    const wire = {};
    const { createRelayDirect } = require('../rebuildRelayDirect');
    class SSH {
        connect() {}
        disconnect() {}
        async exec(_, { stdin }) {
            const frame = JSON.parse(stdin);
            if (!equal(frame.currentUsers, expectedUsers)) throw new Error('incorrect DB-derived CHAP proof');
            frames.push(frame);
            assert.equal(frame.nodeId, id);
            assert.equal(frame.machineId, machineId);
            assert.deepEqual(frame.transit, [{ linkId: String(f.links[0]._id), mode: 'reverse', port: 22010,
                uuid: '00000000-0000-4000-8000-000000000009' }]);
            if (frame.action === 'remove') {
                assert.equal(frame.baseline, baseline);
                assert.equal(frame.expectedCensus, census);
                assert.equal(f.states[0].status, 'removing');
                assert.equal(selected().length, 2);
            }
            const reply = await wire[frame.action]?.() ?? (frame.action === 'session-count' ? { activeSessions: 0, census }
                : { ok: true, machineId, backupId, baseline, removed: true });
            return Object.hasOwn(reply, 'code') ? reply : { code: 0, stderr: '', stdout: JSON.stringify(reply) + '\n' };
        }
    }
    const expectedUsers = selected().map(({ login, enabled, ip, passwordEncrypted }) => ({
        login, enabled, ipAddress: ip, password: decrypt(passwordEncrypted, f.env.ENCRYPTION_KEY),
    })).sort((a, b) => a.login.localeCompare(b.login));
    const service = f.create({ createRelayDirect: options => createRelayDirect({ ...options, SSH }) });
    return { ...f, service, selected, sibling, frames, attempts, dbHooks, wire };
}

test('shared Remove sends the same private DB projection to DIRECT and retires only the selected relay', async t => {
    const f = await sharedFixture(t);
    const before = f.sibling().map(copy), peer = copy(f.states[1]);
    const preview = await f.service.previewRemoveRelay(id);
    assert.deepEqual(preview, { nodeId: id, accountCount: 2, activeSessions: 0, confirmable: true });
    f.users.reverse(); // query order alone must not invalidate this proof
    assert.deepEqual(await f.service.confirmRemoveRelay(id, preview), { executionMode: 'rebuild', status: 'not_installed', nodeId: id });
    assert.deepEqual(f.frames.map(x => x.action), ['session-count', 'session-count', 'prepare-remove', 'remove']);
    assert.deepEqual(f.selected(), []);
    assert.deepEqual(f.sibling().reverse(), before);
    assert.deepEqual(f.states[1], peer);
    assert.deepEqual(f.attempts, ['commit']);
});

test('shared Remove invalidates a preview when a disabled row revision changes without changing CHAP', async t => {
    const f = await sharedFixture(t);
    const preview = await f.service.previewRemoveRelay(id);
    assert.equal(preview.confirmable, true);
    const disabled = f.selected().find(row => !row.enabled);
    disabled.desiredRevision++;
    disabled.appliedRevision++;
    await assert.rejects(f.service.confirmRemoveRelay(id, preview), { code: 'REBUILD_L2TP_REMOVE_PREVIEW_CHANGED' });
    assert.deepEqual(f.frames.map(x => x.action), ['session-count']);
    assert.deepEqual(f.events, []);
});

test('shared Remove rechecks disabled rows after prepare and the confirmed census before preparing', async t => {
    const f = await sharedFixture(t);
    const preview = await f.service.previewRemoveRelay(id);
    f.wire['session-count'] = () => ({ activeSessions: 0, census: '9'.repeat(64) });
    await assert.rejects(f.service.confirmRemoveRelay(id, preview), { code: 'REBUILD_L2TP_REMOVE_PREVIEW_CHANGED' });
    assert.deepEqual(f.frames.splice(0).map(x => x.action), ['session-count', 'session-count']);
    delete f.wire['session-count'];
    f.wire['prepare-remove'] = () => { f.selected().find(row => !row.enabled).comment = 'drift'; };
    await assert.rejects(f.service.confirmRemoveRelay(id, preview), { code: 'REBUILD_L2TP_REMOVE_CHANGED' });
    assert.deepEqual(f.frames.map(x => x.action), ['session-count', 'prepare-remove']);
    assert.deepEqual(f.events, []);
});

test('shared Remove restores the reservation on known host refusal and aborts an incomplete account retirement', async t => {
    const f = await sharedFixture(t);
    const rows = f.users.map(copy), initial = copy(f.states[0]);
    const preview = await f.service.previewRemoveRelay(id);
    f.wire.remove = () => ({ code: 70, stdout: '', stderr: 'DIRECT_REMOVE_REFUSED\n' });
    await assert.rejects(f.service.confirmRemoveRelay(id, preview), { code: 'REBUILD_L2TP_REMOVE_REFUSED' });
    assert.deepEqual(f.states[0], initial);
    assert.deepEqual(f.users, rows);
    assert.deepEqual(f.attempts, []);

    delete f.wire.remove;
    let deletes = 0;
    f.userHooks.delete = ({ where, apply, session }) => {
        assert.ok(session.inTransaction());
        assert.equal(String(where.relayNode.$eq), id);
        assert.deepEqual(f.users, rows);
        return ++deletes === 1 ? apply() : { acknowledged: true, deletedCount: 0 };
    };
    await assert.rejects(f.service.confirmRemoveRelay(id, preview), finishUnknown);
    assert.equal(deletes, 2);
    assert.deepEqual(f.attempts, ['abort']);
    assert.equal(f.states[0].status, 'removing');
    assert.deepEqual(f.users, rows);
});

test('shared Remove refuses invalid disabled credentials rather than falling back to the install receipt', async t => {
    const f = await sharedFixture(t);
    f.selected().find(row => !row.enabled).passwordEncrypted = 'invalid-envelope';
    assert.deepEqual(await f.service.previewRemoveRelay(id), { nodeId: id, accountCount: 2, activeSessions: null, confirmable: false });
    await assert.rejects(f.service.removeRelay(id), noOwner);
    assert.deepEqual(f.frames, []);
    assert.deepEqual(f.events, []);
});

test('trusted shared Remove also requires a fresh zero census before dispatch', async t => {
    const f = await sharedFixture(t);
    f.wire['session-count'] = () => ({ activeSessions: 1, census: '3'.repeat(64) });
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_SESSIONS_BUSY' });
    assert.deepEqual(f.frames.splice(0).map(x => x.action), ['session-count']);
    assert.deepEqual(f.events, []);
    delete f.wire['session-count'];
    await f.service.removeRelay(id);
    assert.deepEqual(f.frames.map(x => x.action), ['session-count', 'prepare-remove', 'remove']);
    assert.deepEqual(f.attempts, ['commit']);
});

for (const committed of [false, true]) {
    test(`shared Remove never retries an unacknowledged settlement commit (committed=${committed})`, async t => {
        const f = await sharedFixture(t);
        const selected = f.selected().map(copy), sibling = f.sibling().map(copy);
        f.dbHooks.commit = apply => { if (committed) apply(); throw privateError(); };
        await assert.rejects(f.service.removeRelay(id), finishUnknown);
        await assert.rejects(f.service.removeRelay(id), noOwner);
        assert.deepEqual(f.attempts, ['commit']);
        assert.equal(f.frames.filter(x => x.action === 'remove').length, 1);
        assert.equal(f.states[0].status, committed ? 'not_installed' : 'removing');
        assert.deepEqual(f.selected(), committed ? [] : selected);
        assert.deepEqual(f.sibling(), sibling);
    });
}

test('list Remove requires card corroboration and a preview from the same binding generation', async t => {
    const f = await installed(t);
    const row = { nodeId: id, host: f.nodes[0].ip, port: 22, username: 'root', machineId, sshHostKeySha256: '1'.repeat(64) };
    const key = 'C3_REBUILD_L2TP_RELAYS_JSON';
    f.env[key] = JSON.stringify([row]);
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_BINDING_MISMATCH' });
    assert.deepEqual(f.events, []);
    f.nodes[0].ssh.username = row.username;

    const actions = [];
    const { createRelayDirect } = require('../rebuildRelayDirect');
    class SSH {
        connect() {}
        disconnect() {}
        exec(_, { stdin }) {
            const { action, machineId: machine, expectedCensus } = JSON.parse(stdin);
            actions.push(action);
            assert.equal(machine, row.machineId);
            if (action === 'remove') assert.equal(expectedCensus, '3'.repeat(64));
            const reply = action === 'session-count' ? { activeSessions: 0, census: '3'.repeat(64) }
                : { ok: true, machineId: machine, backupId, baseline: '4'.repeat(64), removed: true };
            return { code: 0, stderr: '', stdout: JSON.stringify(reply) + '\n' };
        }
    }
    t.mock.method(User.collection, 'countDocuments', async () => f.users.length);
    const service = f.create({ createRelayDirect: options => createRelayDirect({ ...options, SSH }) });
    const preview = await service.previewRemoveRelay(id);
    assert.equal(preview.confirmable, true);
    f.env[key] = JSON.stringify([{ ...row, sshHostKeySha256: '2'.repeat(64) }]);
    await assert.rejects(service.confirmRemoveRelay(id, preview), { code: 'REBUILD_L2TP_REMOVE_PREVIEW_CHANGED' });
    assert.equal(f.states[0].status, 'installed');
    assert.equal(f.users.length, 1);
    assert.deepEqual(f.events, []);
    assert.deepEqual(actions, ['session-count']);

    const current = await service.previewRemoveRelay(id);
    assert.equal((await service.confirmRemoveRelay(id, current)).status, 'not_installed');
    assert.deepEqual(actions, ['session-count', 'session-count', 'session-count', 'prepare-remove', 'remove']);
});

test('final host refusal restores only the exact reservation; unknown outcomes retain it', async t => {
    const f = await installed(t);
    const prior = copy(f.states[0]), account = copy(f.users[0]);
    f.nodes[0].ssh.username = 'root';
    f.env.C3_REBUILD_L2TP_SSH_SHA256 = 'd'.repeat(64);
    const census = 'e'.repeat(64);
    const { createRelayDirect } = require('../rebuildRelayDirect');
    const calls = [];
    let receipt = { code: 70, stdout: '', stderr: 'DIRECT_REMOVE_REFUSED\n' }, beforeReply;
    class SSH {
        connect() {}
        disconnect() {}
        async exec(_, { stdin }) {
            const frame = JSON.parse(stdin);
            calls.push(frame.action);
            if (frame.action === 'remove') {
                assert.equal(frame.expectedCensus, census);
                assert.equal(f.states[0].status, 'removing');
                assert.deepEqual(f.users, [account]);
                beforeReply?.();
                return receipt;
            }
            const reply = frame.action === 'session-count' ? { activeSessions: 0, census }
                : { ok: true, machineId, backupId, baseline: 'f'.repeat(64) };
            assert.ok(['session-count', 'prepare-remove'].includes(frame.action));
            return { code: 0, stdout: JSON.stringify(reply) + '\n', stderr: '' };
        }
    }
    t.mock.method(User.collection, 'countDocuments', async () => f.users.length);
    const service = f.create({ createRelayDirect: options => createRelayDirect({ ...options, SSH }) });
    const tryRemove = async code => {
        const preview = await service.previewRemoveRelay(id);
        assert.equal(preview.confirmable, true);
        await assert.rejects(service.confirmRemoveRelay(id, preview), { code });
        assert.deepEqual(calls.splice(0), ['session-count', 'session-count', 'prepare-remove', 'remove']);
        assert.deepEqual(f.users, [account]);
        assert.ok(!f.events.includes('L2tpUser:delete'));
    };
    await tryRemove('REBUILD_L2TP_REMOVE_REFUSED');
    assert.deepEqual(f.states, [prior]);
    assert.deepEqual(f.events.splice(0), ['RelayL2tpState:update', 'RelayL2tpState:update']);
    receipt = { code: 124, stdout: '', stderr: '' };
    await tryRemove('REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN');
    assert.equal(f.states[0].status, 'removing');
    assert.deepEqual(f.events.splice(0), ['RelayL2tpState:update']);
    // Independent attempts in the same regression: neither a lost lease nor
    // a reservation drift immediately before the restoration may free the row.
    receipt = { code: 70, stdout: '', stderr: 'DIRECT_REMOVE_REFUSED\n' };
    f.states[0] = copy(prior);
    beforeReply = f.loseLock;
    await tryRemove('REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN');
    assert.equal(f.states[0].status, 'removing');
    assert.deepEqual(f.events.splice(0), ['RelayL2tpState:update']);
    f.states[0] = copy(prior);
    beforeReply = undefined;
    f.stateHooks.update = ({ update, apply }) => {
        if (update.$set.status === 'installed') f.states[0].updatedAt = new Date(100);
        return apply();
    };
    await tryRemove('REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN');
    assert.equal(f.states[0].status, 'removing');
    assert.deepEqual(f.states[0].updatedAt, new Date(100));
    assert.deepEqual(f.events, ['RelayL2tpState:update', 'RelayL2tpState:update']);
});

test('installed candidate -> removing before dispatch -> verified absence; only bootstrap credentials are retired', async t => {
    const f = await installed(t);
    const before = copy(f.states[0]), account = copy(f.users[0]);
    const other = { _id: oid(), relayNode: oid(), login: account.login, passwordEncrypted: 'unrelated' };
    f.users.push(other);
    const bridge = { _id: oid(), ip: '192.0.2.6', type: 'xray', active: true, cascadeRole: 'bridge' };
    f.nodes.push(bridge);
    const link = { _id: oid(), portalNode: oid(id), bridgeNode: bridge._id, mode: 'reverse', status: 'online', active: true,
        tunnelPort: 22001, tunnelUuid: '00000000-0000-4000-8000-000000000008' };
    link.rebuildApplied = { listener: link.portalNode, mode: 'reverse', protocol: 'vless',
        port: link.tunnelPort, uuid: link.tunnelUuid };
    f.links.push(link);
    f.hooks.remove = async guard => {
        await guard();
        assert.equal(f.states[0].status, 'removing');
        assert.equal(f.states[0].rebuildInstallToken, before.rebuildInstallToken);
        assert.deepEqual(f.users[0], account);
        return true;
    };
    assert.deepEqual(await f.service.removeRelay(id), { executionMode: 'rebuild', status: 'not_installed', nodeId: id });
    assert.deepEqual(f.removeInput, { nodeId: id, backupId, network: { clientCidr: before.clientCidr,
        tproxyPort: before.tproxyPort, fwmark: before.fwmark, routeTable: before.routeTable },
        transit: [{ linkId: String(link._id), mode: 'reverse', port: link.tunnelPort, uuid: link.tunnelUuid }] });
    assert.deepEqual(f.links, [link]);
    assert.deepEqual(f.users, [other]);
    const [row] = f.states;
    assert.deepEqual([row._id, row.node, row.status, row.desiredState], [before._id, before.node, 'not_installed', 'absent']);
    for (const k of ['pskEncrypted', 'pskHint', 'backupId', 'rebuildInstallToken', 'rebuildMachineId', 'routingVersion']) {
        assert.equal(Object.hasOwn(row, k), false);
    }
    assert.deepEqual(f.events, ['connect', 'prepareRemove', 'RelayL2tpState:update', 'remove', 'L2tpUser:delete',
        'RelayL2tpState:update', 'close']);
    await assert.rejects(f.service.removeRelay(id), noOwner);
    // The synthetic unrelated row is intentionally an orphan. Install now
    // validates its global source inventory; Remove did not touch that row.
    f.users.pop();
    await f.service.installRelay(id); // confirmed absence is a genuinely fresh install admission
});

test('refuses legacy, foreign and drifted installations before opening the driver', async t => {
    const f = await installed(t);
    const check = async (row, delta) => {
        const prior = { ...row };
        Object.assign(row, delta);
        try { await assert.rejects(f.service.removeRelay(id), noOwner); }
        finally { for (const key of Object.keys(delta)) Object.hasOwn(prior, key) ? row[key] = prior[key] : delete row[key]; }
    };
    for (const delta of [{ status: 'removing' }, { desiredState: 'absent' }, { routingMode: 'route-group' },
        { routingVersion: 2 }, { routeGroup: oid() }, { operationId: oid() }, { rebuildMachineId: 'c'.repeat(32) },
        { rebuildInstallToken: '' }, { backupId: '../wrong' }, { secretRevision: 2 }, { tproxyPort: 0 }]) await check(f.states[0], delta);
    for (const delta of [{ login: 'foreign' }, { ip: '10.255.0.14' }, { enabled: false }, { desiredRevision: 2 },
        { lastSyncedAt: new Date(0) }, { passwordEncrypted: '' }]) await check(f.users[0], delta);
    const account = f.users.pop();
    await assert.rejects(f.service.removeRelay(id), noOwner);
    f.users.push(account, { _id: oid(), relayNode: oid(id), login: 'extra', enabled: false });
    await assert.rejects(f.service.removeRelay(id), noOwner);
    f.users.pop();
    await check(f.nodes[0], { active: false });
    await check(f.nodes[0], { cascadeRole: 'bridge' });
    assert.deepEqual(f.events, []);
});

test('a later Apply preserves the ownership receipt and normal Apply works after remove', async t => {
    const f = fixture(t);
    t.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());
    const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
    t.mock.method(require('../configGenerator'), 'buildPanelInlineCertificate', () => null);
    t.mock.method(Link.db, 'transaction', fn => fn({}));
    t.mock.method(State.collection, 'updateOne', async (filter, update) => {
        const row = f.states.find(row => matches({ routeGroup: null, ...row }, filter));
        assert.ok(row);
        Object.assign(row, update.$set);
        return { acknowledged: true, matchedCount: 1 };
    });
    Object.assign(f.nodes[0], { port: 21000, xray: { security: 'none', transport: 'tcp', apiPort: 31000 } });
    const files = new Map();
    const writeProfiles = profiles => { for (const { profile, config } of profiles) files.set(profile, structuredClone(config)); };
    const profiles = followRelayStates => composeRebuildProfiles({ nodes: f.nodes, links: [], followRelayStates,
        controlPlaneAddresses: [f.env.PANEL_DOMAIN, f.nodes[0].ip, f.nodes[0].domain] });
    f.hooks.verify = async () => { writeProfiles(profiles([{ ...f.states[0], status: 'installed' }])); return true; };
    const connect = () => ({ requireSupportedCore: async () => {}, close: async () => {}, stagePair: async () => {},
        read: async profile => structuredClone(files.get(profile)), putPair: async pair => writeProfiles(pair) });
    const service = f.create({ sync: { _getUsersForNode: async () => [] }, cache: { invalidateAllSubscriptions: async () => {} }, connect });
    await service.installRelay(id);
    const { installedAt, rebuildInstallToken } = copy(f.states[0]);
    f.nodes[0].aclRules = ['reject(example.invalid)'];
    const { bindProfileWire, pin } = require('./helpers/rebuildBoundProfileWire');
    f.env.C3_REBUILD_L2TP_SSH_SHA256 = pin;
    f.nodes[0].ssh = { port: 22, username: 'root', password: 'fixture-ssh-auth' };
    bindProfileWire(t.mock.method.bind(t.mock), f.nodes[0].ip, f.env.C3_REBUILD_L2TP_RELAY_MACHINE_ID, connect);
    assert.equal((await service.execute({ nodeId: id })).allowed, true);
    assert.deepEqual([f.states[0].installedAt, f.states[0].rebuildInstallToken], [installedAt, rebuildInstallToken]);
    const main = files.get('main'), bridge = files.get('bridge');
    assert.ok(main.inbounds.some(i => i.tag === `relay-l2tp-${id}`));
    assert.ok(main.routing.rules.some(r => r.domain?.includes('full:example.invalid')));
    const withoutPpp = profiles([]).find(p => p.profile === 'main');
    f.hooks.remove = async guard => {
        await guard();
        // Model the sibling driver's postproof, retaining the latest non-PPP
        // policy and the BRIDGE config. No socket is opened in this fixture.
        files.set('main', withoutPpp.config);
        return true;
    };
    await service.removeRelay(id);
    assert.equal((await service.execute({ nodeId: id })).allowed, true);
    assert.ok(files.get('main').routing.rules.some(r => r.domain?.includes('full:example.invalid')));
    assert.equal(files.get('main').inbounds.some(i => i.tag === `relay-l2tp-${id}`), false);
    assert.deepEqual(files.get('bridge'), bridge);
});

test('same opt-in and strict/classic bans apply before acquiring a lock', async t => {
    const f = await installed(t);
    for (const overrides of [{ C3_REBUILD_ENABLED: 'false' }, { C3_REBUILD_L2TP_INSTALL_ENABLED: 'false' },
        { C3_REBUILD_L2TP_RELAY_ID: 'e'.repeat(24) }, { CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'true' },
        { TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' }, { L2TP_EXECUTION_ENABLED: 'true' }]) {
        const service = f.create({ env: { ...f.env, ...overrides }, locks: { run: () => assert.fail('must not lock') } });
        await assert.rejects(service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_DISABLED' });
    }
    await assert.rejects(f.service.removeRelay(id + '\n'), { code: 'REBUILD_INVALID_REQUEST' });
    assert.deepEqual(f.events, []);
});

test('read-only remote drift and missing direct capability cannot reserve or dispatch', async t => {
    const f = await installed(t);
    f.hooks.prepareRemove = async () => { throw Object.assign(privateError(), { code: 'REBUILD_L2TP_DIRECT_BASELINE_CHANGED' }); };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_DIRECT_BASELINE_CHANGED', message: 'REBUILD_L2TP_DIRECT_BASELINE_CHANGED' });
    const service = f.create({ createRelayDirect: () => ({ close: async () => {} }) });
    await assert.rejects(service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_BACKEND_UNAVAILABLE' });
    assert.deepEqual(f.events, ['connect', 'prepareRemove', 'close']);
    assert.equal(f.states[0].status, 'installed');
    assert.equal(f.users.length, 1);
});

test('reservation CAS rejects a different generation; account drift and changed node block dispatch', async t => {
    const f = await installed(t);
    let plan;
    const takePlan = f.hooks.prepareRemove;
    f.hooks.prepareRemove = async () => {
        plan = await takePlan();
        f.users[0].passwordEncrypted = 'changed';
        return plan;
    };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_CHANGED' });
    assert.equal(f.states[0].status, 'installed');
    f.hooks.prepareRemove = async () => { f.nodes[0].ip = '192.0.2.77'; return plan; };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_CHANGED' });
    f.hooks.prepareRemove = takePlan;
    f.stateHooks.update = ({ apply }) => {
        f.states[0].rebuildInstallToken = 'd'.repeat(8) + '-dddd-4ddd-addd-' + 'd'.repeat(12);
        return apply();
    };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_CHANGED' });
    assert.equal(f.events.includes('remove'), false);
    assert.equal(f.states[0].status, 'installed');
});

test('ambiguous reserve acknowledgement stops dispatch even if removing committed', async t => {
    const f = await installed(t);
    f.stateHooks.update = ({ apply }) => { apply(); throw privateError(); };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_RESERVATION_OUTCOME_UNKNOWN' });
    assert.equal(f.states[0].status, 'removing');
    await assert.rejects(f.service.removeRelay(id), noOwner);
    await assert.rejects(f.service.execute({ nodeId: id }), { code: 'REBUILD_L2TP_STATE_TRANSITION' });
    assert.equal(f.events.includes('remove'), false);
    assert.equal(f.users.length, 1);
});

for (const [name, lose] of [['SSH outcome lost', () => { throw privateError(); }], ['non-true physical proof', () => ({ok: true})],
    ['negative physical proof', () => false], ['lock revoked by driver dispatch time', async (f, guard) => { f.loseLock(); await guard(); }]]) {
    test(`${name}: no cleanup, rollback, or second dispatch`, async t => {
        const f = await installed(t);
        f.hooks.remove = async guard => { await guard(); return lose(f, guard); };
        f.hooks.close = async () => { throw privateError(); };
        await assert.rejects(f.service.removeRelay(id), outcomeUnknown);
        await assert.rejects(f.service.removeRelay(id), noOwner);
        assert.deepEqual(f.events, ['connect', 'prepareRemove', 'RelayL2tpState:update', 'remove', 'close']);
        assert.equal(f.states[0].status, 'removing');
        assert.equal(f.users.length, 1);
    });
}

test('foreign user appearing after reservation but before dispatch stops the driver', async t => {
    const f = await installed(t);
    f.stateHooks.update = ({ apply }) => {
        const result = apply();
        f.users.push({ _id: oid(), relayNode: oid(id), login: 'extra' });
        return result;
    };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVE_CHANGED' });
    assert.equal(f.states[0].status, 'removing');
    assert.equal(f.events.includes('remove'), false);
    assert.equal(f.users.length, 2);
});

test('postproof lock loss cannot retire credentials', async t => {
    const f = await installed(t);
    f.hooks.remove = async guard => { await guard(); f.loseLock(); return true; };
    await assert.rejects(f.service.removeRelay(id), finishUnknown);
    assert.equal(f.states[0].status, 'removing');
    assert.equal(f.users.length, 1);
    assert.equal(f.events.includes('L2tpUser:delete'), false);
});

test('same-looking replacement account after physical proof cannot be deleted', async t => {
    const f = await installed(t);
    const replacement = { ...f.users[0], _id: oid() };
    f.hooks.remove = async guard => { await guard(); f.users[0] = replacement; return true; };
    await assert.rejects(f.service.removeRelay(id), finishUnknown);
    assert.equal(f.states[0].status, 'removing');
    assert.deepEqual(f.users, [replacement]);
    assert.equal(f.events.includes('L2tpUser:delete'), false);
});

for (const committed of [false, true]) {
    test(`ambiguous owned-account delete (committed=${committed}) never publishes absence`, async t => {
        const f = await installed(t);
        f.userHooks.delete = ({ apply }) => { if (committed) apply(); throw privateError(); };
        await assert.rejects(f.service.removeRelay(id), finishUnknown);
        await assert.rejects(f.service.removeRelay(id), noOwner);
        assert.equal(f.states[0].status, 'removing');
        assert.equal(f.users.length, committed ? 0 : 1);
        assert.equal(f.events.filter(x => x === 'L2tpUser:delete').length, 1);
        assert.equal(f.events.filter(x => x === 'RelayL2tpState:update').length, 1);
    });
    test(`ambiguous final CAS (committed=${committed}) is never reported as absent or replayed`, async t => {
        const f = await installed(t);
        f.stateHooks.update = ({ update, apply }) => {
            if (update.$set.status === 'removing') return apply();
            if (committed) apply();
            throw privateError();
        };
        await assert.rejects(f.service.removeRelay(id), finishUnknown);
        await assert.rejects(f.service.removeRelay(id), noOwner);
        assert.equal(f.states[0].status, committed ? 'not_installed' : 'removing');
        assert.equal(f.events.filter(x => x === 'RelayL2tpState:update').length, 2);
        assert.equal(f.events.filter(x => x === 'remove').length, 1);
    });
}

test('revocation during read-only prepare cannot reserve or dispatch', async t => {
    const f = await installed(t);
    const original = f.hooks.prepareRemove;
    f.hooks.prepareRemove = async () => { f.loseLock(); return original(); };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_LOCK_LOST' });
    assert.deepEqual(f.events, ['connect', 'prepareRemove', 'close']);
    assert.equal(f.states[0].status, 'installed');
    assert.equal(f.users.length, 1);
});

test('cleanup failure does not replay an acknowledged terminal state', async t => {
    const f = await installed(t);
    f.hooks.close = async () => { throw privateError(); };
    await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_L2TP_REMOVED_CLEANUP_FAILED' });
    assert.equal(f.states[0].status, 'not_installed');
    assert.equal(f.users.length, 0);
    await assert.rejects(f.service.removeRelay(id), noOwner);
    assert.equal(f.events.filter(x => x === 'remove').length, 1);
});

test('holds the shared Apply lock and waits for the same node writer', { timeout: 5000 }, async t => {
    const f = await installed(t);
    const nodeEntered = deferred(), leaveNode = deferred(), entered = deferred(), leaveRemove = deferred();
    const writing = withNode(id, async () => { nodeEntered.done(); await leaveNode.promise; });
    await nodeEntered.promise;
    f.hooks.remove = async guard => { await guard(); entered.done(); await leaveRemove.promise; return true; };
    const removing = f.service.removeRelay(id);
    try {
        await assert.rejects(f.service.execute({ nodeId: id }), { code: 'REBUILD_BUSY' });
        assert.deepEqual(f.events, []);
        leaveNode.done();
        await entered.promise;
        await assert.rejects(f.service.installRelay(id), { code: 'REBUILD_BUSY' });
        await assert.rejects(f.service.removeRelay(id), { code: 'REBUILD_BUSY' });
    } finally {
        leaveNode.done();
        leaveRemove.done();
        await Promise.all([writing, removing]);
    }
});
