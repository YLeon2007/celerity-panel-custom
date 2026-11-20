'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');
const { Types } = require('mongoose');
const Node = require('../../models/hyNodeModel');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { encrypt } = require('../../modules/relay-l2tp/services/secretBoxService');

const key = 'local-fixture-key-not-for-production';
const password = 'fixture-password';
const login = 'relay-bootstrap';
const oid = hex => new Types.ObjectId(hex.repeat(24));
const idA = String(oid('a')), idB = String(oid('b')), idC = String(oid('c'));
const stamp = new Date('2026-01-01T00:00:00Z');
const fieldAt = (row, path) => path.split('.').reduce((v, k) => v?.[k], row);
const eq = (a, b) => b instanceof Types.ObjectId ? a instanceof Types.ObjectId && a.equals(b) : a === b || (b === null && a === undefined);

function matches(row, filter) {
    return Object.entries(filter).every(([path, expected]) => {
        if (path === '$nor') return expected.every(f => !matches(row, f));
        if (path === '$or') return expected.some(f => matches(row, f));
        const actual = fieldAt(row, path);
        if (expected && Object.hasOwn(expected, '$in')) return expected.$in.some(v => eq(actual, v));
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
        pskEncrypted: encrypt(`fixture-psk-${i + 1}`, key), poolStart: `10.66.${i}.11`, installedAt: stamp,
        lastVerifiedAt: stamp, lastSyncAt: stamp }));
    const passwordEncrypted = encrypt(password, key);
    const users = replicas.map(i => ({ _id: cards[i]._id, relayNode: cards[i]._id, login,
        enabled: true, ip: states[i].poolStart, syncStatus: 'synced', desiredRevision: 1, appliedRevision: 1,
        passwordEncrypted, updatedAt: stamp, createdAt: stamp, lastSyncedAt: stamp, comment: 'fixture-private-comment' }));
    const queries = [];
    const f = { cards, bindings, states, users, env, queries, pending: false, fenceReads: 0 };
    for (const [model, rows] of [[Node, cards], [State, states], [User, users]]) {
        const get = (filter, options) => {
            assert.equal(options.readPreference.mode ?? options.readPreference, 'primary');
            assert.equal(options.readConcern.level ?? options.readConcern, 'majority');
            queries.push({ model, fields: options.projection });
            const result = rows.filter(row => matches(row, filter)).map(row => project(row, options.projection));
            f.afterRead?.(model, options.projection);
            return result;
        };
        t.mock.method(model.collection, 'find', (filter, options) => ({ toArray: async () => get(filter, options) }));
        t.mock.method(model.collection, 'findOne', async (filter, options) => get(filter, options)[0] ?? null);
    }
    const db = Node.db;
    assert.ok(State.db === db && User.db === db);
    t.mock.method(db, 'collection', name => {
        assert.equal(name, 'c3_rebuild_relay_accounts');
        return { async findOne(filter, options) {
            assert.deepEqual(filter, { _id: 'pending' });
            assert.deepEqual(options.projection, { _id: 1 });
            assert.equal(options.readConcern.level, 'majority');
            assert.equal(options.readPreference, 'primary');
            f.fenceReads++;
            if (f.fenceError) throw new Error('fixture-private-storage-error');
            return f.pending ? { _id: 'pending' } : null;
        } };
    });
    f.decipher = t.mock.method(crypto, 'createDecipheriv');
    const resolver = require('../rebuildRelayAuthorization').resolveRelayBinding;
    f.service = createRebuildL2tpOverview({ env, resolveRelayBinding(currentEnv, id, node) {
        assert.deepEqual(Object.keys(node).sort(), ['_id', 'cascadeRole', 'ip', 'name', 'ssh']);
        assert.deepEqual(Object.keys(node.ssh).sort(), ['port', 'username']);
        return resolver(currentEnv, id, node);
    } });
    return f;
}

test('overview uses real model projections, showing only safe relay and per-relay account data', async t => {
    const f = fixture(t);
    f.cards.push({ ...f.cards[0], _id: oid('d'), cascadeRole: 'portal' });
    const result = await f.service.overview();
    const relay = (id, i, status, canInstall, canRemove, canRevealPsk) => ({ id, name: `Relay ${i}`, ip: `192.0.2.${i}`,
        status, bound: true, canInstall, canRemove, canRevealPsk });
    assert.deepEqual(result, {
        relays: [relay(idA, 1, 'installed', false, true, true), relay(idB, 2, 'installed', false, true, true),
            relay(idC, 3, 'not_installed', true, false, false)],
        accounts: [{ login, enabled: true, consistent: true, addresses: [{ id: idA, ip: '10.66.0.11' }, { id: idB, ip: '10.66.1.11' }] }],
        canManageAccounts: true,
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

test('legacy singleton supports display and explicit reads, but not account mutations or list fallback', async t => {
    const f = fixture(t, { legacy: true });
    const overview = await f.service.overview();
    assert.equal(overview.canManageAccounts, false);
    assert.equal(overview.accounts.length, 1);
    assert.equal(overview.accounts[0].consistent, true);
    assert.equal(overview.relays[0].canRevealPsk, true);
    assert.equal(await f.service.revealPassword(login) === password, true);
    assert.equal(await f.service.revealPsk(idA) === 'fixture-psk-1', true);
    for (const config of [JSON.stringify(f.bindings.slice(1)), '{invalid']) {
        f.env.C3_REBUILD_L2TP_RELAYS_JSON = config;
        assert.equal((await f.service.overview()).relays[0].bound, false);
        assert.equal(await f.service.revealPassword(login), null);
        assert.equal(await f.service.revealPsk(idA), null);
    }
    assert.equal(f.decipher.mock.callCount(), 2);
});

test('explicit reveals decrypt exactly one envelope each, scoped to the requested field', async t => {
    const f = fixture(t);
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
        login: 'subscriber', enabled: false, consistent: true, addresses: [{ id: idA, ip: '10.66.0.12' }, { id: idB, ip: '10.66.1.17' }],
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
    assert.deepEqual(result.accounts, [{ login, enabled: true, consistent: false, addresses: [{ id: idA, ip: '10.66.0.11' }] }]);
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
    const result = await f.service.overview();
    assert.equal(result.canManageAccounts, false);
    assert.ok(result.relays.every(r => !r.canInstall && !r.canRemove && !r.canRevealPsk));
    assert.ok(result.accounts.every(row => !row.consistent));
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
