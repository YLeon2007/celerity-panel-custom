'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: equal } = require('node:util');
const { Types, mongo } = require('mongoose');
const { createRebuildService } = require('../rebuildService');
const { makeDesired } = require('../rebuildRelayBackendDesired');
const { makeLocks, withNode } = require('../rebuildLocks');
const { decrypt, encrypt } = require('../../modules/relay-l2tp/services/secretBoxService');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
const Node = require('../../models/hyNodeModel');
const Link = require('../../models/cascadeLinkModel');
const joined = require('./helpers/rebuildRelayInstallJoined');

const id = 'a'.repeat(24), machineId = 'b'.repeat(32), backupId = 'rebuild-unique-backup';
const oid = value => new Types.ObjectId(value);
const copy = value => mongo.BSON.deserialize(mongo.BSON.serialize(value));
const matches = (row, where) => Object.entries(where).every(([key, value]) => {
    if (key === '$expr') {
        assert.equal(value.$eq[0], '$$ROOT');
        return equal(row, value.$eq[1].$literal);
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
            if (index !== -1) {
                Object.assign(rows[index], copy(update.$set ?? {}));
                for (const key of Object.keys(update.$unset ?? {})) delete rows[index][key];
            }
            return { acknowledged: true, matchedCount: Number(index !== -1), upsertedCount: 0 };
        };
        return handlers[kind] ? handlers[kind]({ update, apply }) : apply();
    };
    t.mock.method(model.collection, 'findOne', async (where, { projection, session } = {}) => project(
        selectRows(session).find(row => matches(row, where)), projection));
    t.mock.method(model.collection, 'find', (where, { projection, limit, session } = {}) => ({
        toArray: async () => selectRows(session).filter(row => matches(row, where)).slice(0, limit).map(row => project(row, projection)),
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
function fixture(t) {
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: id,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, ENCRYPTION_KEY: 'test-only-credential-key-'.repeat(2), PANEL_DOMAIN: 'fixture.invalid' };
    const nodes = [{ _id: oid(id), ip: '192.0.2.4', domain: 'relay.fixture.invalid', type: 'xray', active: true,
        cascadeRole: 'relay', ssh: { port: 22, username: 'root' } }];
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
    let prepared;
    const hooks = {
        preflight: async () => ({ ppp: true, masked: false, machineId }),
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
                assert.ok(lock);
                return {
                    async checkChap(installation, current, desired, guard) {
                        await guard();
                        events.push('source-check');
                        assert.ok(lock);
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
    return { env, events, create, enroll, enrollment, nodes, links, states, users, hooks, stateHooks, userHooks,
        get prepared() { return prepared; },
        get lockHeld() { return !!lock; },
        loseLock: () => { lock = undefined; } };
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
function sessionFixture(t, f) {
    const events = [], hooks = {};
    class Session {
        transaction = { transition: state => {
            hooks.transition?.();
            this.active = state !== 'TRANSACTION_COMMITTED';
        } };
        startTransaction(options) {
            assert.deepEqual(options, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            this.active = true;
            this.rows = new Map([f.states, f.users, f.nodes, f.links].map(rows => [rows, rows.map(copy)]));
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
        for (const rows of [f.states, f.users]) rows.splice(0, rows.length, ...session.rows.get(rows));
        session.commitAccountIntent?.();
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
    const install = f.create({ createRelayDirect: options => createRelayDirect({ ...options, SSH }) }).installRelay;
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
            async findOne(where) {
                assert.equal(where._id, 'pending');
                return pending && matches(pending, where) ? { _id: pending._id } : null;
            },
            async updateMany(where, { $setOnInsert }, options) {
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
                assert.deepEqual(where, { _id: 'pending', intentId: pending?.intentId });
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
                return { machineId: selected.machineId, ppp: true, masked: false };
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
    const { bindProfileWire, pin } = require('./helpers/rebuildBoundProfileWire');
    f.env.C3_REBUILD_L2TP_SSH_SHA256 = pin;
    f.nodes[0].ssh.password = 'fixture-ssh-auth';
    bindProfileWire(t.mock.method.bind(t.mock), f.nodes[0].ip, machineId, () => ({
        requireSupportedCore: async () => {}, read: async name => structuredClone(files[name]),
        close: async () => {}, stagePair: async () => {}, putPair: async pair => {
            for (const { profile, config } of pair) files[profile] = structuredClone(config);
        },
    }));
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
