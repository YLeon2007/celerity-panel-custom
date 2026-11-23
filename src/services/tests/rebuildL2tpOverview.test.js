'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');
const { resolve } = require('node:path');
const { renderFile } = require('ejs');
const { Types } = require('mongoose');
const Node = require('../../models/hyNodeModel');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { encrypt } = require('../../modules/relay-l2tp/services/secretBoxService');
const { createRebuildRelayAdmission } = require('../rebuildRelayAdmission');

const key = 'local-fixture-key-not-for-production';
const password = 'fixture-password';
const login = 'relay-bootstrap';
const oid = hex => new Types.ObjectId(hex.repeat(24));
const idA = String(oid('a')), idB = String(oid('b')), idC = String(oid('c'));
const stamp = new Date('2026-01-01T00:00:00Z');
const listKey = 'C3_REBUILD_L2TP_RELAYS_JSON';
const grantCollection = 'c3_rebuild_l2tp_relay_grants';
const auditCollection = 'c3_rebuild_l2tp_relay_grant_audit';
const fieldAt = (row, path) => path.split('.').reduce((v, k) => v?.[k], row);
const eq = (a, b) => b instanceof Types.ObjectId ? a instanceof Types.ObjectId && a.equals(b) : a === b || (b === null && a === undefined);

function matches(row, filter) {
    return Object.entries(filter).every(([path, expected]) => {
        if (path === '$nor') return expected.every(f => !matches(row, f));
        if (path === '$or') return expected.some(f => matches(row, f));
        if (path === '$expr') {
            const [[field, values]] = expected.$not.map(expr => expr.$in);
            return !values.includes(fieldAt(row, field.slice(1)));
        }
        const actual = fieldAt(row, path);
        if (expected && Object.hasOwn(expected, '$in')) return expected.$in.some(v => eq(actual, v));
        if (expected && Object.hasOwn(expected, '$nin')) return !expected.$nin.some(v => eq(actual, v));
        if (expected && Object.hasOwn(expected, '$ne')) return !eq(actual, expected.$ne);
        return eq(actual, expected);
    });
}

// Intercept the collection, not Mongoose Query.select or the model schema.
function project(row, fields) {
    assert.ok(fields && Object.values(fields).every(v => v === 1), 'expected an explicit inclusion projection');
    const result = { _id: row._id };
    for (const path of Object.keys(fields)) {
        const val = fieldAt(row, path);
        if (val === undefined) continue;
        const names = path.split('.');
        let target = result;
        for (const part of names.slice(0, -1)) target = target[part] ??= {};
        target[names.at(-1)] = val;
    }
    return result;
}

function fixture(t, { legacy = false } = {}) {
    const { createRebuildL2tpOverview } = require('../rebuildL2tpOverview');
    const cards = ['a', 'b', 'c'].map((hex, i) => ({ _id: oid(hex), name: `Relay ${i + 1}`, ip: `192.0.2.${i + 1}`,
        ssh: { port: 22 + i, username: 'root', password: 'fixture-ssh-secret', privateKey: 'fixture-ssh-private-key' },
        cascadeRole: 'relay', active: true, type: 'xray', useCustomConfig: false, xray: { agentToken: 'fixture-private-token' } }));
    const bindings = cards.map((card, i) => ({ nodeId: String(card._id), host: card.ip, port: card.ssh.port, username: 'root',
        machineId: String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64) }));
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', ENCRYPTION_KEY: key,
        C3_REBUILD_L2TP_RELAY_ID: idA, C3_REBUILD_L2TP_RELAY_MACHINE_ID: bindings[0].machineId,
        C3_REBUILD_L2TP_SSH_SHA256: bindings[0].sshHostKeySha256,
        ...(!legacy && { C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify(bindings) }) };
    const replicas = legacy ? [0] : [0, 1];
    const states = replicas.map(i => ({ _id: cards[i]._id, node: cards[i]._id, status: 'installed', desiredState: 'installed',
        routingMode: FOLLOW_RELAY_MODE, routingVersion: FOLLOW_RELAY_VERSION, secretRevision: 1,
        backupId: String(i + 4).repeat(32), rebuildMachineId: bindings[i].machineId,
        rebuildInstallToken: `12345678-1234-4abc-8123-00000000000${i}`, pskHint: 'fixture-hint',
        pskEncrypted: encrypt(`fixture-psk-${i + 1}`, key), poolStart: `10.66.${i}.11`, poolEnd: `10.66.${i}.200`, installedAt: stamp,
        lastVerifiedAt: stamp, lastSyncAt: stamp }));
    const passwordEncrypted = encrypt(password, key);
    const users = replicas.map(i => ({ _id: cards[i]._id, relayNode: cards[i]._id, login,
        enabled: true, ip: states[i].poolStart, syncStatus: 'synced', desiredRevision: 1, appliedRevision: 1,
        passwordEncrypted, updatedAt: stamp, createdAt: stamp, lastSyncedAt: stamp, comment: 'fixture-private-comment' }));
    const queries = [];
    const f = { cards, bindings, states, users, env, queries, grants: [], audit: [], pending: false, fenceReads: 0, retiredReads: [],
        busy: { l2tpoperations: [], remoteadmissions: [], nodeoperationlocks: [], c3_rebuild_locks: [] } };
    for (const [model, rows] of [[Node, cards], [State, states], [User, users]]) {
        const get = (filter, options) => {
            if (!options.session?.inTransaction()) {
                assert.equal(options.readPreference.mode ?? options.readPreference, 'primary');
                assert.equal(options.readConcern.level ?? options.readConcern, 'majority');
            }
            queries.push({ model, fields: options.projection });
            const result = rows.filter(row => matches(row, filter)).map(row => project(row, options.projection));
            f.afterRead?.(model, options.projection);
            return result;
        };
        t.mock.method(model.collection, 'find', (filter, options) => ({ toArray: async () => get(filter, options) }));
        t.mock.method(model.collection, 'findOne', async (filter, options) => get(filter, options)[0] ?? null);
    }
    const db = { readyState: 1, createCollection: async name => assert.equal(name, auditCollection) };
    db.db = db;
    class Session {
        transaction = { transition: state => {
            assert.equal(state, 'TRANSACTION_COMMITTED');
            this.writes = null;
        } };
        inTransaction() { return !!this.writes; }
        startTransaction() { this.writes = []; }
        async abortTransaction() { this.writes = null; }
        async endSession() { assert.equal(this.inTransaction(), false); }
    }
    db.startSession = async () => new Session();
    db.getClient = () => ({ db(database) {
        assert.equal(database, 'admin');
        return { async command(command, { session }) {
            assert.equal(command.commitTransaction, 1);
            assert.equal(command.writeConcern.w, 'majority');
            assert.ok(session.inTransaction());
            // Applying the raw command does not alter driver-local state.
            for (const apply of session.writes) apply();
            return { ok: 1 };
        } };
    } });
    db.collection = name => {
        if (name === 'c3_rebuild_l2tp_retired_relays') return { find(filter) {
            f.retiredReads.push(...filter._id.$in);
            return { async toArray() { return []; } }; // No tombstones, even for a missing card.
        } };
        if (name === grantCollection) return {
            find(filter, options) {
                assert.deepEqual(filter, {});
                if (!options.session) {
                    assert.equal(options.readPreference, 'primary');
                    assert.equal(options.readConcern.level, 'majority');
                }
                return { async toArray() {
                    if (f.grantError) throw new Error('fixture-private-registry-error');
                    return structuredClone(f.grants);
                } };
            },
            async createIndexes(specs) { assert.equal(specs.length, 4); },
            async insertOne(row, { session }) {
                session.writes.push(() => f.grants.push(row));
                return { acknowledged: true };
            },
        };
        if (name === auditCollection) return { async insertOne(row, { session }) {
            if (session) session.writes.push(() => f.audit.push(row));
            else f.audit.push(row);
            return { acknowledged: true };
        } };
        if (name === Node.collection.collectionName || name === 'hynodes') return Node.collection;
        if (name === State.collection.collectionName) return {
            find(filter, options) {
                const cursor = State.collection.find(filter, options);
                return { ...cursor, limit() { return cursor; } };
            },
        };
        if (name === User.collection.collectionName) return User.collection;
        if (Object.hasOwn(f.busy, name)) return {
            find(filter, options) {
                assert.equal(name, 'l2tpoperations');
                assert.equal(options.readPreference, 'primary');
                assert.equal(options.readConcern.level, 'majority');
                assert.deepEqual(options.projection, { _id: 1, node: 1, status: 1 });
                return { async toArray() {
                    if (f.operationsError) throw new Error('fixture-private-operation-error');
                    return f.busy[name].filter(row => matches(row, filter)).slice(0, options.limit)
                        .map(row => project(row, options.projection));
                } };
            },
            async findOne(filter, options) {
                if (name === 'l2tpoperations' && f.operationsError) throw new Error('fixture-private-operation-error');
                const row = f.busy[name].find(row => matches(row, filter));
                return row ? project(row, options.projection) : null;
            },
            async distinct(field, filter, options) {
                assert.equal(options.readConcern.level, 'majority');
                return f.busy[name].filter(row => matches(row, filter)).map(row => row[field]);
            },
        };
        assert.equal(name, 'c3_rebuild_relay_accounts');
        return { async findOne(filter, options) {
            if (filter._id === 'directory') {
                if (f.directoryError) throw new Error('fixture-private-directory-error');
                if (!f.directory || !options.projection) return f.directory ?? null;
                return { ...f.directory, accounts: f.directory.accounts.map(({ passwordEncrypted, ...row }) => row) };
            }
            assert.deepEqual(filter, { _id: 'pending' });
            assert.equal(options.readConcern.level, 'majority');
            assert.equal(options.readPreference, 'primary');
            if (options.projection?.['relays.nodeId']) {
                assert.equal(Object.hasOwn(options.projection, 'passwordEncrypted'), false);
                const source = f.pendingRelays ?? f.states.map((state, i) => ({ ...f.bindings[i], backupId: state.backupId,
                    ...(f.grants.find(g => g.nodeId === String(state.node)) && {
                        grantGeneration: f.grants.find(g => g.nodeId === String(state.node)).generation,
                    }) }));
                const fields = Object.fromEntries(Object.entries(options.projection).filter(([field]) => field.startsWith('relays.'))
                    .map(([field, value]) => [field.slice('relays.'.length), value]));
                return f.pending ? { _id: 'pending', intentId: '12345678-1234-4abc-8123-abcdef123456', action: 'delete',
                    login: 'subscriber', relays: source.map(row => project(row, fields)) } : null;
            }
            assert.deepEqual(options.projection, { _id: 1 });
            f.fenceReads++;
            if (f.fenceError) throw new Error('fixture-private-storage-error');
            return f.pending ? { _id: 'pending' } : null;
        } };
    };
    f.probes = [];
    const probeField = field => async card => {
        f.probes.push(field);
        return f.bindings.find(b => b.nodeId === card._id)[field];
    };
    f.admission = () => createRebuildRelayAdmission({ db, env,
        locks: { run: fn => fn(async () => true) },
        probe: { probeKey: probeField('sshHostKeySha256'), readMachine: probeField('machineId') },
    });
    f.decipher = t.mock.method(crypto, 'createDecipheriv');
    const resolver = require('../rebuildRelayAuthorization').resolveRelayBinding;
    const onFixtureDb = Model => ({ db, schema: Model.schema, find: Model.find.bind(Model), findOne: Model.findOne.bind(Model) });
    f.makeOverview = options => createRebuildL2tpOverview({ Node: onFixtureDb(Node), State: onFixtureDb(State), L2tpUser: onFixtureDb(User),
        ...options, env, resolveRelayBinding(currentEnv, id, node) {
        assert.deepEqual(Object.keys(node).sort(), ['_id', 'cascadeRole', 'ip', 'name', 'ssh']);
        assert.deepEqual(Object.keys(node.ssh).sort(), ['port', 'username']);
        return resolver(currentEnv, id, node);
    } });
    f.service = f.makeOverview();
    return f;
}

function grantRow(binding) {
    return { ...binding, createdAt: stamp, confirmedAt: stamp, createdBy: 'fixture-admin', confirmedBy: 'fixture-admin',
        generation: crypto.randomUUID() };
}

test('overview uses real model projections, showing only safe relay and per-relay account data', async t => {
    const f = fixture(t);
    f.cards.push({ ...f.cards[0], _id: oid('d'), cascadeRole: 'portal' });
    const result = await f.service.overview();
    const relay = (id, i, status, canInstall, canRemove, canRevealPsk) => ({ id, name: `Relay ${i}`, ip: `192.0.2.${i}`,
        status, bound: true, canInstall, canRemove, canRevealPsk,
        grantSource: 'env', grantProblem: null, canGrant: false, canReconfirm: false, canRevoke: false });
    assert.deepEqual(result, {
        relays: [relay(idA, 1, 'installed', false, true, true), relay(idB, 2, 'installed', false, true, true),
            relay(idC, 3, 'not_installed', true, false, false)],
        accounts: [{ login, enabled: true, consistent: true, canRevealPassword: true, addresses: [{ id: idA, ip: '10.66.0.11' }, { id: idB, ip: '10.66.1.11' }] }],
        canManageAccounts: true,
        accountsPending: false,
        canReconcileAccounts: false,
        grantProblem: null,
    });
    assert.equal(f.decipher.mock.callCount(), 0);
    for (const { fields } of f.queries) {
        for (const field of ['pskEncrypted', 'passwordEncrypted', 'pskHint', 'ssh', 'ssh.password', 'ssh.privateKey', 'comment', 'xray']) {
            assert.equal(Object.hasOwn(fields, field), false, `ordinary read selected ${field}`);
        }
    }
});

test('install affordance reflects static node eligibility, state and residual account rows', async t => {
    const f = fixture(t);
    const install = async () => (await f.service.overview()).relays.find(row => row.id === idC).canInstall;
    const card = f.cards[2];
    for (const [field, bad, good] of [['active', false, true], ['type', 'hysteria', 'xray'], ['useCustomConfig', true, false]]) {
        card[field] = bad;
        assert.equal(await install(), false);
        card[field] = good;
    }
    const absent = { _id: card._id, node: card._id, status: 'not_installed', desiredState: 'absent' };
    f.states.push(absent);
    assert.equal(await install(), true);
    absent.pskEncrypted = 'retained-fixture-envelope';
    assert.equal(await install(), false);
    delete absent.pskEncrypted;
    f.users.push({ ...f.users[0], _id: card._id, relayNode: card._id });
    assert.equal(await install(), false);
});

const relayActions = ['canGrant', 'canReconfirm', 'canRevoke', 'canInstall', 'canRemove', 'canRevealPsk'];
const enabledActions = row => relayActions.filter(action => row[action] === true);

function classicState(f) {
    const state = { _id: oid('c'), node: oid('c'), status: 'not_installed', desiredState: 'not_installed',
        routingMode: 'route-group', routeGroup: oid('f'), operationId: oid('e'), activePathKey: 'classic-path',
        appliedTopologyRevision: 17, secretRevision: 4, backupId: 'classic-backup', managedVersion: 'fixture-classic',
        pskEncrypted: 'fixture-classic-psk', pskHint: 'fixture-classic-hint', clientCidr: '10.65.0.0/24',
        localAddress: '10.65.0.1', poolStart: '10.65.0.11', poolEnd: '10.65.0.200', tproxyPort: 15001,
        fwmark: 10077, routeTable: 200 };
    const operation = { _id: state.operationId, node: state.node, kind: 'install', status: 'succeeded' };
    f.states.push(state);
    f.busy.l2tpoperations.push(operation);
    return { state, operation };
}

test('dormant classic row is not a cohort member and cannot become a target; unresolved operations stay blocking', async t => {
    const f = fixture(t);
    const { state, operation } = classicState(f);
    const fresh = { ...f.bindings[1], nodeId: String(oid('d')), host: '192.0.2.4', machineId: '4'.repeat(32),
        sshHostKeySha256: '4'.repeat(64) };
    f.cards.push({ ...f.cards[1], _id: oid('d'), ip: fresh.host });
    f.env[listKey] = JSON.stringify(f.bindings.slice(0, 2));
    const beforeGrant = await f.service.overview();
    assert.deepEqual(enabledActions(beforeGrant.relays[2]), []);
    assert.deepEqual(enabledActions(beforeGrant.relays[3]), ['canGrant']);
    f.grants.push(grantRow(f.bindings[2]), grantRow(fresh));
    for (const status of ['succeeded', 'failed', 'cancelled', 'rolled_back', 'running', 'unknown']) {
        operation.status = status;
        const settled = !['running', 'unknown'].includes(status);
        const view = await f.service.overview();
        assert.deepEqual(enabledActions(view.relays[2]), [], status);
        assert.deepEqual(enabledActions(view.relays[3]), settled ? ['canReconfirm', 'canRevoke', 'canInstall'] : ['canReconfirm', 'canRevoke'], status);
        assert.equal(view.canManageAccounts, settled, status);
        assert.equal(view.accounts[0].canRevealPassword, settled, status);
        assert.deepEqual(view.accounts[0].addresses.map(row => row.id), [idA, idB], status);
        assert.equal((await f.service.revealPassword(login)) === password, settled, status);
        assert.equal(await f.service.revealPsk(idC), null, status);
    }
    operation.status = 'succeeded';
    for (const change of [
        () => { state.rebuildInstallToken = 'unexpected-ownership'; return () => delete state.rebuildInstallToken; },
        () => { state.rebuildMachineId = f.bindings[2].machineId; return () => delete state.rebuildMachineId; },
        () => { f.states.push({ ...state, _id: oid('f') }); return () => f.states.pop(); },
        () => { f.users.push({ ...f.users[0], _id: state._id, relayNode: state.node, login: 'foreign' }); return () => f.users.pop(); },
        () => { operation.node = oid('f'); return () => { operation.node = state.node; }; },
        () => {
            f.busy.l2tpoperations.push({ _id: oid('f'), node: state.node, status: 'running' });
            return () => f.busy.l2tpoperations.pop();
        },
    ]) {
        const undo = change();
        const view = await f.service.overview();
        assert.equal(view.canManageAccounts, false);
        assert.equal(view.accounts[0].canRevealPassword, false);
        assert.equal(await f.service.revealPassword(login), null);
        undo();
    }
    f.busy.l2tpoperations.length = 0;
    assert.equal((await f.service.overview()).canManageAccounts, true, 'confirmed missing operation is not a failed read');
    delete state.operationId;
    state.desiredState = 'absent';
    assert.equal((await f.service.overview()).canManageAccounts, true, 'classic teardown need not retain an operation reference');
    assert.deepEqual(enabledActions((await f.service.overview()).relays[2]), [], 'retained classic fields are not target freshness');
    state.replacementFence = 1;
    assert.equal((await f.service.overview()).canManageAccounts, false);
    assert.equal(await f.service.revealPassword(login), null);
});

test('dormant classic operation proof is reread before reveal and errors fail closed', async t => {
    const f = fixture(t);
    const { operation } = classicState(f);
    for (const injectAfter of [1, 2]) {
        let envelopes = 0;
        f.afterRead = (_, fields) => {
            if (fields.passwordEncrypted && ++envelopes === injectAfter) operation.status = 'running';
        };
        assert.equal(await f.service.revealPassword(login), null);
        assert.equal(envelopes, injectAfter);
        assert.equal(f.decipher.mock.callCount(), 0);
        operation.status = 'succeeded';
    }
    f.operationsError = true;
    const view = await f.service.overview();
    assert.equal(view.canManageAccounts, false);
    assert.equal(view.accounts[0].canRevealPassword, false);
    assert.deepEqual(view.accounts[0].addresses.map(row => row.id), [idA, idB]);
    assert.equal(await f.service.revealPassword(login), null);
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('directory inventory survives a dormant classic row, but not users without a settled DIRECT cohort', async t => {
    const f = fixture(t);
    f.directory = { _id: 'directory', version: 1, generation: crypto.randomUUID(),
        accounts: [{ id: idA, login, enabled: true, passwordEncrypted: f.users[0].passwordEncrypted }] };
    f.states.length = f.users.length = 0;
    const { state, operation } = classicState(f);
    let view = await f.service.overview();
    assert.deepEqual(view.accounts, [{ login, enabled: true, consistent: true, canRevealPassword: true, addresses: [] }]);
    assert.equal(view.canManageAccounts, false);
    assert.equal((await f.service.revealPassword(login)) === password, true);
    operation.status = 'running';
    assert.deepEqual((await f.service.overview()).accounts, []);
    assert.equal(await f.service.revealPassword(login), null);
    operation.status = 'succeeded';
    f.users.push({ _id: state._id, relayNode: state.node, login: 'foreign' });
    view = await f.service.overview();
    assert.deepEqual(view.accounts, []);
    assert.equal(await f.service.revealPassword(login), null);
});

test('overview → admission confirmation → overview observes a committed grant without a restart', async t => {
    const f = fixture(t, { legacy: true });
    const read = () => f.service.overview();
    const before = await read();
    assert.deepEqual(before.relays.map(row => row.grantSource), ['env', null, null]);
    assert.deepEqual(enabledActions(before.relays[2]), ['canGrant']);
    assert.equal(before.canManageAccounts, false);
    assert.equal(f.audit.length, 0);
    assert.equal(f.grants.length, 0);
    assert.deepEqual(f.probes, []);
    const perform = f.admission().perform;
    const scope = { nodeId: idC, actor: 'fixture-admin', sessionId: 'fixture-session' };
    const first = await perform({ ...scope, action: 'probe' });
    const second = await perform({ ...scope, action: 'verify', challenge: first.challenge });
    assert.equal(f.grants.length, 0);
    assert.equal((await perform({ ...scope, action: 'confirm', challenge: second.challenge })).source, 'db');
    const after = await read();
    assert.deepEqual(after.relays.map(row => row.grantSource), ['env', null, 'db']);
    assert.deepEqual(enabledActions(after.relays[2]), ['canReconfirm', 'canRevoke', 'canInstall']);
    assert.equal(after.relays[2].status, 'not_installed');
    assert.equal(f.states.length, 1);
    assert.equal(f.users.length, 1);
    assert.equal(await f.service.revealPsk(idC), null);
    assert.deepEqual(f.probes, ['sshHostKeySha256', 'machineId', 'machineId']);
    assert.deepEqual(f.audit.map(({ action, outcome }) => [action, outcome]), [
        ['probe', 'success'], ['verify', 'success'], ['grant', 'success'],
    ]);
    assert.equal(Object.hasOwn(f.env, listKey), false);
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('stale ENV list with no node or tombstone reserves identity but does not hide unrelated inventory or stop a disjoint grant', async t => {
    const f = fixture(t);
    f.cards.pop(); // idC is still in ENV; never retired and has no state/users.
    const stale = f.bindings[2];
    const fresh = { ...stale, nodeId: String(oid('d')), host: '192.0.2.4', machineId: '4'.repeat(32),
        sshHostKeySha256: '4'.repeat(64) };
    f.bindings.push(fresh);
    const card = { ...f.cards[1], _id: oid('d'), ip: stale.host, ssh: { ...f.cards[1].ssh, port: stale.port } };
    f.cards.push(card);
    const perform = f.admission().perform;
    const scope = { nodeId: fresh.nodeId, actor: 'fixture-admin', sessionId: 'fixture-session' };
    const read = async () => {
        const view = await f.service.overview();
        assert.equal(view.grantProblem, null);
        assert.deepEqual(view.relays.map(row => row.id), [idA, idB, fresh.nodeId]);
        assert.deepEqual(view.accounts[0].addresses.map(row => row.id), [idA, idB]);
        assert.equal(view.canManageAccounts, true);
        return view.relays[2];
    };
    const confirm = async () => {
        const { challenge } = await perform({ ...scope, action: 'probe' });
        const verified = await perform({ ...scope, action: 'verify', challenge });
        return perform({ ...scope, action: 'confirm', challenge: verified.challenge });
    };
    const endpointCollision = await read();
    assert.equal(endpointCollision.grantProblem, 'REBUILD_L2TP_GRANT_CONFLICT');
    assert.deepEqual(enabledActions(endpointCollision), []);
    await assert.rejects(perform({ ...scope, nodeId: idC, action: 'probe' }),
        { code: 'REBUILD_L2TP_GRANT_CONFLICT', detail: 'env-read-only' });
    await assert.rejects(confirm(), { code: 'REBUILD_L2TP_GRANT_CONFLICT', detail: 'endpoint' });
    card.ip = fresh.host;
    for (const field of ['machineId', 'sshHostKeySha256']) {
        assert.deepEqual(enabledActions(await read()), ['canGrant']); // Probe identity is not known to GET.
        const original = fresh[field];
        fresh[field] = stale[field];
        await assert.rejects(confirm(), { code: 'REBUILD_L2TP_GRANT_CONFLICT', detail: field });
        fresh[field] = original;
    }
    assert.deepEqual(f.grants, []);
    assert.equal((await confirm()).source, 'db');
    assert.deepEqual(enabledActions(await read()), ['canReconfirm', 'canRevoke', 'canInstall']);
    assert.equal((await f.service.revealPassword(login)) === password, true);
    assert.ok(f.retiredReads.includes(idC));
    assert.equal(JSON.parse(f.env[listKey]).some(binding => binding.nodeId === idC), true);

    // A conflicting *persisted* DB grant poisons the union, unlike a refused
    // contender. The read-only inventory is still visible, with no secrets.
    f.grants[0].sshHostKeySha256 = stale.sshHostKeySha256;
    const conflict = await f.service.overview();
    assert.equal(conflict.grantProblem, 'REBUILD_L2TP_GRANT_CONFLICT');
    assert.ok(conflict.relays.every(row => enabledActions(row).length === 0));
    assert.deepEqual(conflict.accounts[0].addresses.map(row => row.id), [idA, idB]);
    assert.equal(conflict.accounts[0].canRevealPassword, false);
});

test('explicit [] masks singleton variables; unset uses legacy, while either accepts actual DB-only authority without a singleton', async t => {
    const f = fixture(t, { legacy: true });
    const read = () => f.service.overview();
    assert.equal((await read()).relays[0].grantSource, 'env');
    assert.equal((await read()).accounts[0].consistent, true);
    f.env[listKey] = '[]';
    assert.equal((await read()).relays[0].grantSource, null);
    assert.deepEqual((await read()).accounts, []);
    assert.equal(await f.service.revealPassword(login), null);
    f.grants.push(grantRow(f.bindings[0]));
    const readDbInventory = async () => {
        const view = await read();
        assert.equal(view.relays[0].grantSource, 'db');
        assert.deepEqual(view.accounts[0].addresses, [{ id: idA, ip: f.users[0].ip }]);
        assert.equal(view.canManageAccounts, true);
        assert.equal((await f.service.revealPassword(login)) === password, true);
    };
    await readDbInventory();
    delete f.env[listKey];
    assert.equal((await read()).grantProblem, 'REBUILD_L2TP_GRANT_CONFLICT');
    for (const field of ['C3_REBUILD_L2TP_RELAY_ID', 'C3_REBUILD_L2TP_RELAY_MACHINE_ID', 'C3_REBUILD_L2TP_SSH_SHA256']) delete f.env[field];
    await readDbInventory();
});

test('DB-only grants expose first Install only on a fresh relay, without creating ownership or allowing accounts', async t => {
    const f = fixture(t);
    for (const name of [listKey, 'C3_REBUILD_L2TP_RELAY_ID', 'C3_REBUILD_L2TP_RELAY_MACHINE_ID', 'C3_REBUILD_L2TP_SSH_SHA256']) {
        delete f.env[name];
    }
    f.states.length = f.users.length = 0;
    f.grants.push(grantRow(f.bindings[1]));
    const result = await f.service.overview();
    assert.deepEqual(result.relays.map(row => row.grantSource), [null, 'db', null]);
    assert.deepEqual(enabledActions(result.relays[1]), ['canReconfirm', 'canRevoke', 'canInstall']);
    assert.deepEqual(result.accounts, []);
    assert.equal(result.canManageAccounts, false);
    assert.equal(await f.service.revealPassword(login), null);
    assert.equal(await f.service.revealPsk(idB), null);
    f.busy.nodeoperationlocks.push({ node: oid('b') });
    assert.deepEqual(enabledActions((await f.service.overview()).relays[1]), []);
    f.busy.nodeoperationlocks.length = 0;
    f.env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'false';
    assert.ok((await f.service.overview()).relays.every(row => enabledActions(row).length === 0));
    assert.deepEqual(f.probes, []);
});

test('an injected store failure is sanitized and does not fall back to ENV', async t => {
    const f = fixture(t);
    const service = f.makeOverview({ relayGrantStore: { async snapshot() { throw new Error('fixture-private-registry-error'); } } });
    const result = await service.overview();
    assert.equal(result.grantProblem, 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE');
    assert.ok(result.relays.every(row => enabledActions(row).length === 0));
    await assert.rejects(service.revealPsk(idA), { message: result.grantProblem });
});

test('admission flags respect retained state/locks, endpoint drift, and same-binding installed ownership', async t => {
    const f = fixture(t);
    f.env[listKey] = JSON.stringify(f.bindings.slice(0, 1));
    f.grants.push(grantRow(f.bindings[1]));
    const read = async i => (await f.service.overview()).relays[i];
    assert.deepEqual(enabledActions(await read(1)), ['canReconfirm', 'canRemove', 'canRevealPsk']);
    assert.deepEqual(enabledActions(await read(2)), ['canGrant']);
    f.cards[1].ssh.port = 2222;
    assert.equal((await read(1)).grantProblem, 'REBUILD_L2TP_IDENTITY_CHANGED');
    assert.deepEqual(enabledActions(await read(1)), []);
    f.states.pop();
    f.users.pop();
    assert.deepEqual(enabledActions(await read(1)), ['canReconfirm']);
    const absent = { _id: oid('b'), node: oid('b'), status: 'not_installed', desiredState: 'absent', replacementFence: 2 };
    f.states.push(absent);
    f.cards[1].ssh.port = f.bindings[1].port;
    assert.deepEqual(enabledActions(await read(1)), ['canReconfirm', 'canRevoke']);
    absent.lastErrorCode = 'retained';
    assert.deepEqual(enabledActions(await read(1)), []);
    delete absent.lastErrorCode;
    f.busy.l2tpoperations.push({ node: oid('b'), status: 'running' });
    f.busy.remoteadmissions.push({ nodeId: idC, phase: 'held' });
    assert.deepEqual(enabledActions(await read(1)), []);
    assert.deepEqual(enabledActions(await read(2)), []);
    f.busy.l2tpoperations[0].status = 'succeeded';
    f.busy.remoteadmissions[0].phase = 'completed';
    assert.deepEqual(enabledActions(await read(1)), ['canReconfirm', 'canRevoke']);
    assert.deepEqual(enabledActions(await read(2)), ['canGrant']);
    f.cards[2].ip = f.bindings[0].host;
    f.cards[2].ssh.port = f.bindings[0].port;
    assert.equal((await read(2)).grantProblem, 'REBUILD_L2TP_GRANT_CONFLICT');
    assert.deepEqual(enabledActions(await read(2)), []);
    f.cards[2].ip = f.bindings[2].host;
    f.cards[2].ssh.username = 'invalid username';
    assert.deepEqual(enabledActions(await read(2)), []);
});

for (const [name, breakAuthority, code] of [
    ['ENV/DB node conflict', f => f.grants.push(grantRow(f.bindings[0])), 'REBUILD_L2TP_GRANT_CONFLICT'],
    ['ENV/DB endpoint conflict', f => {
        f.env[listKey] = JSON.stringify(f.bindings.slice(0, 2));
        f.grants.push(grantRow({ ...f.bindings[2], host: f.bindings[0].host, port: f.bindings[0].port }));
    }, 'REBUILD_L2TP_GRANT_CONFLICT'],
    ['malformed ENV', f => { f.env[listKey] = '{invalid'; }, 'REBUILD_L2TP_GRANT_ENV_INVALID'],
    ['invalid DB registry', f => f.grants.push({ ...grantRow(f.bindings[0]), generation: 'invalid' }), 'REBUILD_L2TP_GRANT_REGISTRY_INVALID'],
    ['DB read failure', f => { f.grantError = true; }, 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE'],
]) {
    test(`${name} retains inventory but never falls back to ENV for actions or reveals`, async t => {
        const f = fixture(t);
        breakAuthority(f);
        for (const pending of [false, true]) {
            f.pending = pending;
            const view = await f.service.overview();
            assert.equal(view.grantProblem, code);
            assert.equal(view.accountsPending, pending);
            assert.equal(view.canReconcileAccounts, false);
            assert.equal(view.canManageAccounts, false);
            assert.deepEqual(view.relays.map(row => row.status), ['installed', 'installed', 'not_installed']);
            assert.ok(view.relays.every(row => enabledActions(row).length === 0 && row.bound === false));
            assert.deepEqual(view.accounts.map(row => [row.login, row.addresses.length, row.canRevealPassword]), [[login, 2, false]]);
        }
        f.pending = false;
        await assert.rejects(f.service.revealPassword(login), { code });
        await assert.rejects(f.service.revealPsk(idA), { code });
        assert.equal(f.decipher.mock.callCount(), 0);
        assert.ok(f.queries.every(({ fields }) => !fields.passwordEncrypted && !fields.pskEncrypted));
    });
}

test('pending recovery requires the merged installed cohort and its recorded grant generation', async t => {
    const f = fixture(t);
    f.env[listKey] = JSON.stringify(f.bindings.slice(0, 1));
    f.grants.push(grantRow(f.bindings[1]), grantRow(f.bindings[2]));
    f.pending = true;
    f.directoryError = true;
    f.pendingRelays = f.states.map((s, i) => ({ ...f.bindings[i], backupId: s.backupId,
        ...(i === 1 && { grantGeneration: f.grants[0].generation }) }));
    const { operation } = classicState(f);
    const valid = await f.service.overview();
    assert.equal(valid.canReconcileAccounts, true);
    assert.ok(valid.relays.every(row => enabledActions(row).length === 0));
    operation.status = 'running';
    assert.equal((await f.service.overview()).canReconcileAccounts, false);
    operation.status = 'succeeded';
    for (const [row, field, replacement] of [
        [f.grants[0], 'generation', crypto.randomUUID()],
        [f.cards[1], 'ip', 'replacement.example'],
        [f.states[1], 'backupId', 'a'.repeat(32)],
    ]) {
        const original = row[field];
        assert.notEqual(original, replacement);
        row[field] = replacement;
        const stale = await f.service.overview();
        assert.equal(stale.accountsPending, true, field);
        assert.equal(stale.canReconcileAccounts, false, field);
        assert.equal(stale.grantProblem, 'REBUILD_L2TP_IDENTITY_CHANGED', field);
        row[field] = original;
    }
    assert.equal((await f.service.overview()).canReconcileAccounts, true);
});

test('actual view renders a localized registry error and read-only inventory during conflict and outage', async t => {
    const f = fixture(t);
    const { t: translate } = require('../../middleware/i18n');
    f.grants.push(grantRow(f.bindings[0]));
    for (const problemKey of ['grantConflict', 'grantUnavailable']) {
        const overview = await f.service.overview();
        for (const lang of ['en', 'ru', 'zh-CN']) {
            const html = await renderFile(resolve(__dirname, '../../../views/rebuild-l2tp.ejs'), { ...overview,
                t: key => translate(key, lang), csrfToken: 'fixture', rebuildL2tpScriptVersion: 'fixture' });
            assert.ok(html.includes(`role="alert">${translate(`rebuildL2tp.admission.${problemKey}`, lang)}</p>`));
            assert.match(html, /Relay 1/);
            assert.match(html, /relay-bootstrap/);
            assert.doesNotMatch(html, /data-(?:secret-url|admission-action|install-url|remove-link|account-action|reconcile-url)\b|data-create\b/);
            assert.doesNotMatch(html, /fixture-private|fixture-ssh/);
        }
        f.grants.length = 0;
        f.grantError = true;
    }
});

test('reveals use merged authority and reread grant generation after the final envelope query', async t => {
    const f = fixture(t);
    f.env[listKey] = JSON.stringify(f.bindings.slice(0, 1));
    f.grants.push(grantRow(f.bindings[1]));
    for (const [field, reveal, expected] of [['passwordEncrypted', () => f.service.revealPassword(login), password],
        ['pskEncrypted', () => f.service.revealPsk(idB), 'fixture-psk-2']]) {
        f.afterRead = undefined;
        assert.ok((await reveal()) === expected, 'unchanged merged authority must reveal');
        let envelopes = 0;
        f.afterRead = (_, fields) => {
            if (fields[field] && ++envelopes === 2) f.grants[0].generation = crypto.randomUUID();
        };
        const deciphers = f.decipher.mock.callCount();
        assert.equal(await reveal(), null);
        assert.equal(envelopes, 2);
        assert.equal(f.decipher.mock.callCount(), deciphers);
    }
});

test('legacy secret rereads reject an ENV pin change and a failed final registry read', async t => {
    const f = fixture(t, { legacy: true });
    f.afterRead = (_, fields) => { if (fields.pskEncrypted) f.env.C3_REBUILD_L2TP_SSH_SHA256 = '9'.repeat(64); };
    assert.equal(await f.service.revealPsk(idA), null);
    f.afterRead = (_, fields) => { if (fields.passwordEncrypted) f.grantError = true; };
    await assert.rejects(f.service.revealPassword(login), { code: 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE' });
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('legacy singleton supports display and explicit reads, but not account mutations or list fallback', async t => {
    const f = fixture(t, { legacy: true });
    f.users.push({ ...f.users[0], _id: oid('d'), relayNode: oid('d') });
    const overview = await f.service.overview();
    assert.equal(overview.canManageAccounts, false);
    assert.equal(overview.accounts.length, 1);
    assert.equal(overview.accounts[0].consistent, true);
    assert.equal(overview.accounts[0].canRevealPassword, true);
    assert.equal(overview.relays[0].canRevealPsk, true);
    assert.equal(await f.service.revealPassword(login) === password, true);
    assert.equal(await f.service.revealPsk(idA) === 'fixture-psk-1', true);
    for (const config of [JSON.stringify(f.bindings.slice(1)), '{invalid']) {
        f.env.C3_REBUILD_L2TP_RELAYS_JSON = config;
        assert.equal((await f.service.overview()).relays[0].bound, false);
        if (config === '{invalid') {
            await assert.rejects(f.service.revealPassword(login), { code: 'REBUILD_L2TP_GRANT_ENV_INVALID' });
            await assert.rejects(f.service.revealPsk(idA), { code: 'REBUILD_L2TP_GRANT_ENV_INVALID' });
        } else {
            assert.equal(await f.service.revealPassword(login), null);
            assert.equal(await f.service.revealPsk(idA), null);
        }
    }
    assert.equal(f.decipher.mock.callCount(), 2);
});

test('legacy singleton does not reveal a bootstrap alongside unknown local accounts', async t => {
    const f = fixture(t, { legacy: true });
    f.users.push({ ...f.users[0], _id: oid('d'), login: 'unowned' });
    assert.equal((await f.service.overview()).accounts[0].canRevealPassword, false);
    assert.ok((await f.service.revealPassword(login)) === null, 'unexpected legacy reveal');
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('list mode requires a settled in-pool replica and enabled bootstrap on each member before reveal', async t => {
    const f = fixture(t);
    const [a, b] = f.users;
    f.users.push({ ...a, _id: oid('d'), login: 'subscriber', ip: '10.66.0.12' },
        { ...b, _id: oid('e'), login: 'subscriber', ip: '10.77.1.12' });
    assert.equal((await f.service.overview()).canManageAccounts, false);
    assert.ok((await f.service.revealPassword('subscriber')) === null, 'unexpected out-of-pool reveal');
    f.users[3].ip = '10.66.1.12';
    b.enabled = false;
    assert.equal((await f.service.overview()).canManageAccounts, false);
    assert.ok((await f.service.revealPassword('subscriber')) === null, 'unexpected reveal without valid bootstrap');
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('explicit reveals decrypt exactly one envelope each, scoped to the requested field', async t => {
    const f = fixture(t);
    f.users.push({ ...f.users[0], _id: oid('d'), relayNode: oid('c'), login: 'unrelated' });
    assert.equal((await f.service.overview()).canManageAccounts, true);
    f.queries.length = 0;
    assert.equal(await f.service.revealPassword(login) === password, true);
    assert.equal(f.decipher.mock.callCount(), 1);
    assert.ok(f.queries.some(({ model, fields }) => model === User && fields.passwordEncrypted === 1));
    assert.equal(f.queries.some(({ fields }) => fields.pskEncrypted), false);
    f.queries.length = 0;
    assert.equal(await f.service.revealPsk(idB) === 'fixture-psk-2', true);
    assert.equal(f.decipher.mock.callCount(), 2);
    assert.ok(f.queries.some(({ model, fields }) => model === State && fields.pskEncrypted === 1));
    assert.equal(f.queries.some(({ fields }) => fields.passwordEncrypted), false);
});

test('disabled list replicas can agree without sharing a relay IP or sync revision', async t => {
    const f = fixture(t);
    const [a, b] = f.users;
    f.users.push({ ...a, _id: oid('d'), login: 'subscriber', ip: '10.66.0.12', enabled: false, desiredRevision: 2, appliedRevision: 2 },
        { ...b, _id: oid('e'), login: 'subscriber', ip: '10.66.1.17', enabled: false, desiredRevision: 3, appliedRevision: 3 });
    assert.deepEqual((await f.service.overview()).accounts[1], {
        login: 'subscriber', enabled: false, consistent: true, canRevealPassword: true, addresses: [{ id: idA, ip: '10.66.0.12' }, { id: idB, ip: '10.66.1.17' }],
    });
    assert.equal(await f.service.revealPassword('subscriber') === password, true);
    assert.equal(f.decipher.mock.callCount(), 1);
});

test('legacy bootstrap login alone is not an account finish receipt', async t => {
    const f = fixture(t, { legacy: true });
    delete f.users[0].lastSyncedAt;
    assert.deepEqual((await f.service.overview()).accounts, []);
    assert.ok((await f.service.revealPassword(login)) === null, 'unexpected legacy reveal');
    assert.equal(f.decipher.mock.callCount(), 0);
});

for (const [name, change] of [
    ['missing replica', f => f.users.pop()],
    ['unsigned state', f => delete f.states[1].rebuildInstallToken],
    ['foreign-machine receipt', f => { f.states[1].rebuildMachineId = 'f'.repeat(32); }],
    ['endpoint drift', f => { f.cards[1].ssh.port = 2222; }],
    ['missing node', f => f.cards.splice(1, 1)],
    ['classic installed state', f => { f.states[1].routingMode = 'route-group'; }],
    ['non-relay cohort member', f => { f.cards[1].cascadeRole = 'bridge'; }],
    ['retained installation', f => { f.states[1].status = 'installing'; }],
    ['retained removal', f => { Object.assign(f.states[1], { status: 'removing', desiredState: 'absent' }); }],
    ['retained operation', f => { f.states[1].operationId = oid('e'); }],
    ['unsynced row', f => { f.users[1].syncStatus = 'error'; }],
    ['pending sync operation', f => { f.users[1].syncOperationId = oid('e'); }],
    ['mismatched revision', f => { f.users[1].desiredRevision++; }],
    ['divergent ciphertext even for equal plaintext', f => { f.users[1].passwordEncrypted = encrypt(password, key); }],
    ['different enablement', f => { f.users[1].enabled = false; }],
    ['non-boolean enablement', f => { f.users[1].enabled = 1; }],
    ['orphan login replica', f => f.users.push({ ...f.users[0], _id: oid('d'), relayNode: oid('d') })],
    ['duplicate login replica', f => f.users.push({ ...f.users[0], _id: oid('d') })],
]) {
    test(`password reveal refuses ${name} before decrypt`, async t => {
        const f = fixture(t);
        change(f);
        assert.equal(await f.service.revealPassword(login), null);
        assert.equal(f.decipher.mock.callCount(), 0);
    });
}

test('overview excludes classic account addresses and reveal is not inferred from status', async t => {
    const f = fixture(t);
    f.states[1].routingMode = 'route-group';
    delete f.states[1].rebuildInstallToken;
    const result = await f.service.overview();
    assert.equal(result.canManageAccounts, false);
    assert.deepEqual(result.accounts, [{ login, enabled: true, consistent: false, canRevealPassword: false, addresses: [{ id: idA, ip: '10.66.0.11' }] }]);
    assert.equal(result.relays[1].status, 'installed');
    assert.equal(result.relays[1].canRemove, false);
    assert.equal(result.relays[1].canRevealPsk, false);
    assert.equal(await f.service.revealPsk(idB), null);
    f.states[0].rebuildMachineId = 'f'.repeat(32);
    assert.equal(await f.service.revealPsk(idA), null);
    f.states[0].status = 'not_installed';
    assert.equal(await f.service.revealPsk(idA), null);
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('a pending intent, including one observed during the read, fences all secret reveals', async t => {
    const f = fixture(t);
    f.pending = true;
    assert.equal(await f.service.revealPassword(login), null);
    assert.equal(await f.service.revealPsk(idA), null);
    f.directoryError = true;
    const result = await f.service.overview();
    assert.equal(result.accountsPending, true);
    assert.equal(result.canReconcileAccounts, true);
    assert.equal(result.canManageAccounts, false);
    assert.ok(result.relays.every(r => !r.canInstall && !r.canRemove && !r.canRevealPsk));
    assert.ok(result.accounts.every(row => !row.consistent));
    f.directoryError = false;
    for (const [reveal, field] of [[() => f.service.revealPassword(login), 'passwordEncrypted'],
        [() => f.service.revealPsk(idA), 'pskEncrypted']]) {
        f.pending = false;
        f.afterRead = (_, fields) => { if (fields[field]) f.pending = true; };
        const before = f.fenceReads;
        assert.equal(await reveal(), null);
        assert.ok(f.fenceReads >= before + 2);
    }
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('a known pending fence is not a read error, and singleton mode cannot trigger reconciliation', async t => {
    const f = fixture(t, { legacy: true });
    f.pending = true;
    const result = await f.service.overview();
    assert.equal(result.accountsPending, true);
    assert.equal(result.canReconcileAccounts, false);
    assert.equal(result.canManageAccounts, false);
    f.fenceError = true;
    await assert.rejects(f.service.overview(), { code: 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE' });
});

test('password reveal refuses a Remove reservation that appears while loading replicas', async t => {
    const f = fixture(t);
    f.afterRead = (_, fields) => {
        if (fields.passwordEncrypted) Object.assign(f.states[1], { status: 'removing', desiredState: 'absent' });
    };
    assert.ok((await f.service.revealPassword(login)) === null, 'unexpected reveal during Remove reservation');
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('password reveal refuses rows changed by publication that cleared the pending intent', async t => {
    const f = fixture(t);
    f.afterRead = (_, fields) => {
        if (fields.passwordEncrypted) for (const row of f.users) row.desiredRevision = row.appliedRevision = 2;
    };
    assert.ok((await f.service.revealPassword(login)) === null, 'unexpected reveal during publication');
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('PSK reveal refuses binding drift that appears while loading the state', async t => {
    const f = fixture(t);
    f.afterRead = (_, fields) => { if (fields.pskEncrypted) f.cards[0].ssh.port = 2222; };
    assert.ok((await f.service.revealPsk(idA)) === null, 'unexpected PSK reveal after binding drift');
    assert.equal(f.decipher.mock.callCount(), 0);
});

test('returns null for invalid inputs, missing rows and unreadable or absent ciphertext', async t => {
    const f = fixture(t);
    assert.equal(await f.service.revealPassword({ $ne: null }), null);
    assert.equal(await f.service.revealPsk(`${idA}\n`), null);
    assert.equal(await f.service.revealPassword('missing'), null);
    assert.equal(await f.service.revealPsk(idC), null);
    assert.equal(f.decipher.mock.callCount(), 0);
    delete f.states[0].pskEncrypted;
    assert.equal(await f.service.revealPsk(idA), null);
    for (const user of f.users) user.passwordEncrypted = 'not-a-fixture-envelope';
    assert.equal(await f.service.revealPassword(login), null);
    f.fenceError = true;
    await assert.rejects(f.service.revealPsk(idB), { code: 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE' });
    assert.equal(f.decipher.mock.callCount(), 0);
});
