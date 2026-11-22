'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRelayGrantStore } = require('../rebuildRelayGrantStore');
const { resolveRelayBinding } = require('../rebuildRelayAuthorization');

const LIST = 'C3_REBUILD_L2TP_RELAYS_JSON';
const GRANTS = 'c3_rebuild_l2tp_relay_grants';
const AUDIT = 'c3_rebuild_l2tp_relay_grant_audit';
const enabled = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true' };
const binding = n => ({ nodeId: n.repeat(24), host: `relay-${n}.invalid`, port: 22, username: 'root',
    machineId: n.repeat(32), sshHostKeySha256: n.repeat(64) });
const a = binding('a'), b = binding('b');
const actor = 'fixture-admin';
const withList = (...rows) => ({ ...enabled, [LIST]: JSON.stringify(rows) });
const legacy = { ...enabled, C3_REBUILD_L2TP_RELAY_ID: a.nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: a.machineId,
    C3_REBUILD_L2TP_SSH_SHA256: a.sshHostKeySha256 };
const card = row => ({ _id: row.nodeId, ip: row.host, ssh: { port: row.port, username: row.username } });
const code = suffix => ({ code: `REBUILD_L2TP_GRANT_${suffix}` });

// Model snapshot visibility, write-time unique-index checks, and the separate
// server settlement and driver-local states of a raw commit.
function fixture(env = { ...enabled }) {
    let state = { [GRANTS]: [], [AUDIT]: [] };
    let indexes = [];
    const controls = {}, touches = [], lifecycle = [];
    let inventory;
    const match = (row, filter) => Object.keys(filter).every(key => row[key] === filter[key]);
    function unique(rows, row) {
        for (const { key } of indexes) {
            if (rows.some(other => match(other, Object.fromEntries(Object.keys(key).map(k => [k, row[k]]))))) {
                throw Object.assign(new Error('fixture should not be in public Mongo errors'), { code: 11000, keyPattern: key });
            }
        }
    }
    const requireTransaction = session => { assert.ok(session.inTransaction()); return session.view; };
    const recoveryToken = { recoveryShardId: 'fixture' };
    const db = {
        readyState: 1,
        collection(name) {
            if (name === 'hynodes') return { async findOne(filter, options) {
                touches.push(name);
                assert.deepEqual(options.projection, { _id: 1, ip: 1, 'ssh.port': 1, 'ssh.username': 1 });
                assert.equal(String(filter._id), a.nodeId);
                return inventory ?? null;
            } };
            if (name === GRANTS) return {
                async createIndexes(specs, options) {
                    assert.equal(options.writeConcern.w, 'majority');
                    if (controls.indexFailure) throw new Error('fixture private index failure');
                    indexes = structuredClone(specs);
                },
                find(_filter, options) {
                    if (options.session?.inTransaction()) assert.equal(options.readConcern, undefined);
                    else assert.equal(options.readConcern.level, 'majority');
                    return { async toArray() {
                        if (controls.readFailure) throw new Error('fixture private Mongo URI');
                        return structuredClone((options.session?.view ?? state)[name]);
                    } };
                },
                async insertOne(row, { session }) {
                    lifecycle.push('grant insert');
                    await controls.beforeInsert?.();
                    unique(state[name], row);
                    const apply = rows => { unique(rows, row); rows.push(row); };
                    apply(requireTransaction(session)[name]);
                    session.operations.push(next => apply(next[name]));
                    return { acknowledged: true };
                },
                async updateOne(filter, { $set }, { session }) {
                    const apply = rows => {
                        const i = rows.findIndex(row => match(row, filter));
                        if (i < 0) return false;
                        const row = { ...rows[i], ...$set };
                        unique(rows.filter((_, j) => i !== j), row);
                        rows[i] = row;
                        return true;
                    };
                    if (controls.casMiss || !apply(requireTransaction(session)[name])) return { acknowledged: true, matchedCount: 0 };
                    session.operations.push(next => assert.ok(apply(next[name])));
                    return { acknowledged: true, matchedCount: 1 };
                },
                async deleteOne(filter, { session }) {
                    const apply = rows => {
                        const i = rows.findIndex(row => match(row, filter));
                        if (i < 0) return false;
                        rows.splice(i, 1);
                        return true;
                    };
                    if (controls.casMiss || !apply(requireTransaction(session)[name])) return { acknowledged: true, deletedCount: 0 };
                    session.operations.push(next => assert.ok(apply(next[name])));
                    return { acknowledged: true, deletedCount: 1 };
                },
            };
            assert.equal(name, AUDIT);
            return { async insertOne(row, { session, writeConcern }) {
                if (controls.auditFailure) throw new Error('fixture private audit failure');
                if (session) {
                    lifecycle.push('audit insert');
                    requireTransaction(session)[name].push(row);
                    session.operations.push(next => next[name].push(row));
                    controls.afterAudit?.();
                } else {
                    assert.equal(writeConcern.w, 'majority');
                    state[name].push(row);
                }
                return { acknowledged: true };
            } };
        },
        getClient() {
            return { db(name) {
                assert.equal(name, 'admin');
                return { async command(command, { session, maxTimeMS, timeoutMS, readPreference }) {
                    lifecycle.push('raw commit');
                    assert.deepEqual(command, { commitTransaction: 1, recoveryToken,
                        writeConcern: { w: 'majority', wtimeout: 5000 }, maxTimeMS: 5000 });
                    assert.deepEqual({ maxTimeMS, timeoutMS, readPreference }, { maxTimeMS: 5000, timeoutMS: 5000, readPreference: 'primary' });
                    requireTransaction(session);
                    const next = structuredClone(state);
                    for (const operation of session.operations) operation(next);
                    state = next;
                    if (controls.afterCommit) return controls.afterCommit();
                    return { ok: 1 };
                } };
            } };
        },
        async startSession() {
            lifecycle.push('session');
            return {
                transaction: { recoveryToken, transition(state) {
                    lifecycle.push(state);
                    controls.transitionFailure?.();
                    if (!controls.noTransition) delete this.session.view;
                } },
                inTransaction() { return Boolean(this.view); },
                startTransaction(options) {
                    this.transaction.session = this;
                    this.view = structuredClone(state);
                    this.operations = [];
                    assert.equal(options?.writeConcern.w, 'majority');
                },
                async abortTransaction() {
                    lifecycle.push('abort');
                    delete this.view;
                },
                async endSession() {
                    lifecycle.push('end');
                    if (this.inTransaction()) await this.abortTransaction();
                    controls.endFailure?.();
                    this.ended = true;
                },
            };
        },
    };
    const store = createRelayGrantStore({ db, env });
    const mutate = (binding, action = 'grant', expectedGeneration = null, session) =>
        store.mutate({ action, binding, expectedGeneration, actor, session });
    return { db, store, mutate, controls, touches, lifecycle, setCard: row => { inventory = row; },
        records: () => state[GRANTS], history: () => state[AUDIT], indexes: () => indexes };
}

test('grant/reconfirm/revoke/regrant rotate generation, enforce CAS and keep safe durable history', async () => {
    const env = { ...enabled };
    const f = fixture(env);
    const first = await f.mutate({ ...a, host: 'RELAY-A.INVALID.', password: 'not-authority' });
    assert.equal(first.host, a.host);
    assert.equal(first.createdBy, actor);
    assert.equal(first.confirmedBy, actor);
    assert.ok(first.createdAt instanceof Date);
    const restored = createRelayGrantStore({ db: f.db, env });
    const one = await restored.snapshot();
    assert.equal(one.sourceFor(a.nodeId), 'db');
    assert.equal(one.sourceFor(b.nodeId), null);
    assert.equal(one.grants[0].generation, first.generation);
    assert.deepEqual(resolveRelayBinding(one.env, a.nodeId, card(a)), a);
    assert.deepEqual(env, enabled);
    assert.deepEqual(f.indexes().map(i => [i.key, i.unique]), [
        [{ nodeId: 1 }, true], [{ machineId: 1 }, true], [{ sshHostKeySha256: 1 }, true], [{ host: 1, port: 1 }, true],
    ]);
    const second = await f.mutate({ ...a, host: b.host }, 'reconfirm', first.generation);
    assert.notEqual(second.generation, first.generation);
    assert.equal(+second.createdAt, +first.createdAt);
    await assert.rejects(f.mutate(a, 'reconfirm', first.generation), code('CHANGED'));
    await assert.rejects(f.mutate({ nodeId: a.nodeId }, 'revoke', first.generation), code('CHANGED'));
    await f.mutate({ nodeId: a.nodeId }, 'revoke', second.generation);
    assert.deepEqual((await restored.snapshot()).grants, []);
    const third = await f.mutate(a);
    assert.equal(new Set([first.generation, second.generation, third.generation]).size, 3);
    assert.deepEqual(f.history().map(row => row.action), ['grant', 'reconfirm', 'revoke', 'grant']);
    for (const row of f.history()) {
        assert.deepEqual(Object.keys(row).sort(), ['action', 'actor', 'at', 'code', 'nodeId', 'outcome']);
        assert.equal(row.actor, actor);
        assert.equal(row.outcome, 'success');
    }
});

test('ENV list + DB is a disjoint union, preserves gates, and does not project grant metadata', async () => {
    const env = withList(a);
    const f = fixture(env);
    await f.mutate(b);
    const merged = await f.store.snapshot();
    assert.deepEqual(JSON.parse(merged.env[LIST]), [a, b]);
    assert.deepEqual(JSON.parse(env[LIST]), [a]);
    assert.equal(merged.sourceFor(a.nodeId), 'env');
    assert.equal(merged.sourceFor(b.nodeId), 'db');
    assert.ok(Object.isFrozen(merged.env));
    assert.throws(() => { merged.env[LIST] = '[]'; }, TypeError);
    const original = structuredClone(merged.grants);
    await f.mutate(b, 'revoke', original[0].generation);
    assert.deepEqual(JSON.parse((await f.store.snapshot()).env[LIST]), [a]);
    assert.deepEqual(merged.grants, original);
    assert.deepEqual(JSON.parse(merged.env[LIST]), [a, b]);
    assert.equal(merged.sourceFor(b.nodeId), 'db');
    await f.mutate(b);
    env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'false';
    const disabled = await f.store.snapshot();
    assert.throws(() => resolveRelayBinding(disabled.env, b.nodeId, card(b)), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    await assert.rejects(f.mutate(binding('c')), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    env[LIST] = JSON.stringify([a, b]);
    await assert.rejects(f.store.snapshot(), { ...code('CONFLICT'), field: 'nodeId', sources: ['env', 'db'] });
});

test('DB-only works with explicit empty list; invalid raw ENV JSON fails closed', async () => {
    const env = withList();
    const f = fixture(env);
    await f.mutate(b);
    assert.deepEqual(resolveRelayBinding((await f.store.snapshot()).env, b.nodeId), b);
    env[LIST] = `[${JSON.stringify(a).slice(0, -1)},"p\\u006frt":22}]`;
    await assert.rejects(f.store.snapshot(), code('ENV_INVALID'));
    await assert.rejects(f.mutate(binding('c')), code('ENV_INVALID'));
    assert.equal(f.history().length, 1);
});

test('legacy mode is unchanged without DB records; any union requires the inventory endpoint', async () => {
    const f = fixture(legacy);
    const old = await f.store.snapshot();
    assert.equal(old.sourceFor(a.nodeId), 'env');
    assert.equal(Object.hasOwn(old.env, LIST), false);
    assert.deepEqual(resolveRelayBinding(old.env, a.nodeId, card(a)), a);
    assert.deepEqual(f.touches, []);
    await assert.rejects(f.mutate(b), code('ENV_INVALID'));
    assert.deepEqual(f.records(), []);
    f.setCard(card(a));
    await f.mutate(b);
    const joined = await f.store.snapshot();
    assert.deepEqual(JSON.parse(joined.env[LIST]), [a, b]);
    assert.equal(joined.sourceFor(a.nodeId), 'env');
    await assert.rejects(f.mutate({ ...binding('c'), host: 'RELAY-A.INVALID.' }),
        { ...code('CONFLICT'), field: 'endpoint', sources: ['env', 'db'] });
    f.setCard(card({ ...a, host: b.host }));
    await assert.rejects(f.store.snapshot(), { ...code('CONFLICT'), field: 'endpoint', sources: ['env', 'db'] });
    f.setCard(null);
    await assert.rejects(f.store.snapshot(), code('ENV_INVALID'));
});

const collisions = [
    ['nodeId', { nodeId: a.nodeId }], ['machineId', { machineId: a.machineId }],
    ['sshHostKeySha256', { sshHostKeySha256: a.sshHostKeySha256 }], ['endpoint', { host: 'RELAY-A.INVALID.' }],
];
for (const [field, override] of collisions) {
    test(`rejects ${field} collisions against ENV and concurrent DB grants`, async () => {
        const next = { ...b, ...override };
        const env = fixture(withList(a));
        await assert.rejects(env.mutate(next), { ...code('CONFLICT'), field, sources: ['env', 'db'] });
        const f = fixture();
        let inserts = 0;
        const first = f.mutate(a);
        f.controls.beforeInsert = async () => {
            // Both snapshots predate publication, but one insert observes the
            // winner at its unique-index write boundary, not during commit.
            if (++inserts !== 2) return;
            await first;
            if (field === 'endpoint') throw Object.assign(new Error('write conflict'), { code: 112 });
        };
        const results = await Promise.allSettled([first, f.mutate(next)]);
        assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
        assert.deepEqual(results.filter(r => r.status === 'rejected').map(({ reason }) => [reason.code, reason.field, reason.sources]),
            [[code('CONFLICT').code, field, ['db', 'db']]]);
        assert.equal(f.records().length, 1);
        assert.equal(f.history().length, 1);
        assert.equal(inserts, 2);
        assert.equal(f.lifecycle.filter(step => step === 'session').length, 2);
        assert.equal(f.lifecycle.filter(step => step === 'raw commit').length, 1);
    });
}

test('IPv6 and IPv4-mapped spellings use the canonical endpoint key; different ports are distinct', async () => {
    const f = fixture();
    await f.mutate({ ...a, host: '2001:0DB8:0000:0::1' });
    await assert.rejects(f.mutate({ ...b, host: '2001:db8::1' }), { ...code('CONFLICT'), field: 'endpoint' });
    await f.mutate({ ...b, host: '2001:db8::1', port: 2222 });
    await f.mutate({ ...binding('c'), host: '192.0.2.19' });
    await assert.rejects(f.mutate({ ...binding('d'), host: '::ffff:c000:213' }), { ...code('CONFLICT'), field: 'endpoint' });
    assert.deepEqual(f.records().map(r => r.host), ['2001:db8::1', '2001:db8::1', '192.0.2.19']);
});

test('failed reads, indexes, CAS and audit fail closed without publishing a partial grant', async () => {
    const f = fixture(withList());
    f.db.readyState = 0;
    await assert.rejects(f.store.snapshot(), code('PERSISTENCE_UNAVAILABLE'));
    f.db.readyState = 1;
    f.controls.readFailure = true;
    await assert.rejects(f.store.snapshot(), { ...code('PERSISTENCE_UNAVAILABLE'), message: code('PERSISTENCE_UNAVAILABLE').code });
    delete f.controls.readFailure;
    f.controls.indexFailure = true;
    await assert.rejects(f.mutate(a), code('PERSISTENCE_UNAVAILABLE'));
    delete f.controls.indexFailure;
    f.controls.auditFailure = true;
    await assert.rejects(f.mutate(a), code('PERSISTENCE_UNAVAILABLE'));
    assert.equal(f.records().length, 0);
    delete f.controls.auditFailure;
    const first = await f.mutate(a);
    f.controls.casMiss = true;
    await assert.rejects(f.mutate(a, 'reconfirm', first.generation), code('CHANGED'));
    await assert.rejects(f.mutate(a, 'revoke', first.generation), code('CHANGED'));
    delete f.controls.casMiss;
    f.controls.auditFailure = true;
    await assert.rejects(f.mutate(a, 'revoke', first.generation), code('PERSISTENCE_UNAVAILABLE'));
    assert.deepEqual(f.records(), [first]);
    assert.equal(f.history().length, 1);
});

test('caller transaction stages both changes, may roll back, and aborts on store failure', async () => {
    const f = fixture();
    const session = await f.db.startSession();
    const start = () => session.startTransaction({ writeConcern: { w: 'majority' } });
    await assert.rejects(f.mutate(a, 'grant', null, session), code('PERSISTENCE_UNAVAILABLE'));
    start();
    await f.mutate(a, 'grant', null, session);
    assert.equal((await f.store.snapshot({ session })).sourceFor(a.nodeId), 'db');
    assert.equal((await f.store.snapshot()).sourceFor(a.nodeId), null);
    assert.equal(f.history().length, 0);
    await session.abortTransaction();
    assert.equal(f.records().length, 0);
    start();
    f.controls.auditFailure = true;
    await assert.rejects(f.mutate(a, 'grant', null, session), code('PERSISTENCE_UNAVAILABLE'));
    assert.equal(session.inTransaction(), false);
    assert.equal(session.ended, undefined);
    assert.equal(f.records().length, 0);
});

test('standalone denial audit projects only known fields and allowlisted reason codes', async () => {
    const f = fixture();
    const sensitive = 'REBUILD_L2TP_PASSWORD_EXAMPLE';
    await f.store.audit({ action: 'grant', actor, nodeId: a.nodeId, outcome: 'denied', code: code('CONFLICT').code,
        password: sensitive, host: a.host, error: new Error(sensitive) });
    await f.store.audit({ action: 'grant', actor, nodeId: sensitive, outcome: 'denied', code: sensitive });
    assert.equal(f.history()[0].code, code('CONFLICT').code);
    assert.equal(f.history()[0].nodeId, a.nodeId);
    assert.equal(f.history()[1].nodeId, null);
    assert.ok(!JSON.stringify(f.history()).includes(sensitive));
    assert.ok(!JSON.stringify(f.history()).includes(a.host));
});

test('ENV authority change before commit aborts the grant and its staged audit', async () => {
    const env = withList();
    const f = fixture(env);
    f.controls.afterAudit = () => { env[LIST] = JSON.stringify([a]); };
    await assert.rejects(f.mutate(a), code('CHANGED'));
    assert.deepEqual(f.records(), []);
    assert.deepEqual(f.history(), []);
    assert.deepEqual(f.lifecycle, ['session', 'grant insert', 'audit insert', 'abort', 'end']);
    assert.equal((await f.store.snapshot()).sourceFor(a.nodeId), 'env');
});

const commitLifecycle = ['session', 'grant insert', 'audit insert', 'raw commit', 'TRANSACTION_COMMITTED'];
test('no replay or inferred rollback on a lost or invalid commit acknowledgement', async () => {
    for (const afterCommit of [() => { throw Object.assign(new Error('private fixture commit error'), { code: 11000 }); },
        () => undefined, () => ({ ok: 0 }), () => ({ ok: 1, writeConcernError: {} }),
        () => ({ ok: 1, writeErrors: [{}] }), () => ({ ok: 1, errorLabels: ['UnknownTransactionCommitResult'] })]) {
        const f = fixture();
        f.controls.afterCommit = afterCommit;
        await assert.rejects(f.mutate(a), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false });
        assert.deepEqual(f.lifecycle, [...commitLifecycle, 'end']);
        assert.equal(f.records().length, 1);
        assert.equal(f.history().length, 1);
    }
});

test('do not end an active driver session after attempting commit', async () => {
    for (const fault of [{ transitionFailure() { throw new Error('transition failure'); } }, { noTransition: true }]) {
        const f = fixture();
        Object.assign(f.controls, fault, { afterCommit: () => ({ ok: 1, writeConcernError: {} }) });
        await assert.rejects(f.mutate(a), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false });
        assert.deepEqual(f.lifecycle, commitLifecycle);
    }
});

test('session disposal failure does not turn an acknowledged commit into an unknown outcome', async () => {
    const f = fixture();
    f.controls.endFailure = () => { throw new Error('cleanup failure'); };
    assert.equal((await f.mutate(a)).nodeId, a.nodeId);
    assert.deepEqual(f.lifecycle, [...commitLifecycle, 'end']);
    assert.equal(f.records().length, 1);
    assert.equal(f.history().length, 1);
});

test('pre-commit write conflict does not replay the mutation or manufacture a duplicate', async () => {
    const f = fixture();
    f.controls.beforeInsert = () => { throw Object.assign(new Error('private write conflict'), { code: 112 }); };
    await assert.rejects(f.mutate(a), code('CHANGED'));
    assert.deepEqual(f.lifecycle, ['session', 'grant insert', 'abort', 'end']);
    assert.deepEqual(f.records(), []);
    assert.deepEqual(f.history(), []);
});
