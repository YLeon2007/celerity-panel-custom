'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mongo: { BSON }, Types: { ObjectId } } = require('mongoose');
const { createRetireStore } = require('../rebuildRelayRetireStore');

// Socket-free collection model evaluates the actual read projection and delete
// expression; the opt-in Mongo suite verifies server comparison/transactions.
const encode = BSON.serialize;
const same = (a, b) => encode({ value: a }).equals(encode({ value: b }));
function bsonType(value) {
    if (value === undefined) return 'missing';
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    if (value._bsontype) return { Int32: 'int', Double: 'double', ObjectId: 'objectId' }[value._bsontype];
    return typeof value === 'boolean' ? 'bool' : typeof value;
}
function evaluate(expr, vars) {
    if (typeof expr === 'string' && expr.startsWith('$$')) {
        return expr.slice(2).split('.').reduce((parent, key) => parent?.[key], vars);
    }
    if (Array.isArray(expr)) return expr.map(value => evaluate(value, vars));
    if (!expr || typeof expr !== 'object') return expr;
    if (Object.hasOwn(expr, '$literal')) return expr.$literal;
    if (expr.$type) return bsonType(evaluate(expr.$type, vars));
    if (expr.$isArray) return Array.isArray(evaluate(expr.$isArray, vars));
    if (expr.$map) {
        const { input, as, in: item } = expr.$map;
        return evaluate(input, vars).map(value => evaluate(item, { ...vars, [as]: value }));
    }
    if (expr.$cond) return evaluate(expr.$cond[evaluate(expr.$cond[0], vars) ? 1 : 2], vars);
    if (expr.$in) {
        const [value, array] = evaluate(expr.$in, vars);
        return array.some(entry => same(entry, value));
    }
    if (expr.$eq) {
        // Mongo compares numeric values across BSON numeric types. Do not
        // accidentally supply a stronger CAS than the server in this fixture.
        return same(...evaluate(expr.$eq, vars).map(value => BSON.deserialize(encode({ value })).value));
    }
    return Object.fromEntries(Object.entries(expr).map(([key, value]) => [key, evaluate(value, vars)])
        .filter(([, value]) => value !== undefined));
}

function fixture() {
    const id = new ObjectId('1'.repeat(24));
    const node = { _id: id, type: 'xray', cascadeRole: 'relay', ip: '192.0.2.1',
        ssh: { port: new BSON.Int32(22), username: 'fixture-user' },
        xray: { agentToken: '$fixture-agent', manualKey: { $ne: 'fixture-literal' }, extraInbounds: [{ port: 'fixture-port' }] } };
    const writes = [], projected = [];
    let deleteHook, beforeDelete, aborted = false;
    const client = {}, session = { client, inTransaction: () => !aborted, abortTransaction: async () => { aborted = true; } };
    const empty = { findOne: async () => null, find: () => ({ toArray: async () => [] }),
        insertOne: async (_row, options) => { assert.equal(options.session, session); writes.push('tombstone'); return { acknowledged: true }; } };
    const db = { getClient: () => client, collection: () => empty, models: { HyUser: { collection: {
        updateMany: async (_filter, _update, options) => {
            assert.equal(options.session, session);
            writes.push('users');
            beforeDelete?.(node);
            return { acknowledged: true };
        },
    } } } };
    db.models.HyUser.db = db;
    const model = { db, collection: empty };
    const Node = { db, collection: {
        async findOne({ _id }, options) {
            assert.ok(_id.equals(id));
            assert.equal(options.raw, true);
            const row = options.projection ? Object.fromEntries(Object.entries(options.projection).map(([field, expression]) => [
                field, expression === 1 ? node[field] : evaluate(expression, { ROOT: node }),
            ])) : node;
            projected.push(row);
            return encode(row);
        },
        async deleteOne(filter, options) {
            assert.equal(options.session, session);
            assert.deepEqual(options.collation, { locale: 'simple' });
            assert.ok(filter._id.equals(id));
            deleteHook?.(node);
            writes.push('node');
            return { acknowledged: true, deletedCount: Number(evaluate(filter.$expr, { ROOT: node })) };
        },
    } };
    const store = createRetireStore({ Node, State: model, Link: model, L2tpUser: model, env: {} });
    return { session, store, node, id, writes, projected, aborted: () => aborted,
        beforeDelete: fn => { beforeDelete = fn; }, onDelete: fn => { deleteHook = fn; } };
}

test('projected capture ignores telemetry-only branches and preserves opaque typed authority', async () => {
    const { store, node, id, session, projected, writes } = fixture();
    const snap = await store.capture(id);
    node.updatedAt = new Date(2);
    node.xray.accessLogs = { status: 'pending', lastBatchAt: new Date(1) };
    node.xray.extraInbounds[0].unrelated = 'fixture';
    assert.equal(store.sameSnapshot(snap, await store.capture(id)), true);
    assert.deepEqual(Object.keys(projected.at(-1)), ['_id', 'image']);
    assert.equal(JSON.stringify(snap), '{}');
    await store.finish(snap, session, async () => true);
    assert.deepEqual(writes, ['tombstone', 'users', 'node']);
});

test('missing, array and BSON type changes miss the late delete predicate and abort the session', async () => {
    for (const mutate of [node => { node.ssh.password = null; }, node => { node.ssh.username = ['fixture-user']; },
        node => { node.ssh.port = new BSON.Double(22); }, node => { node.xray.alpn = [new BSON.Double(1)]; }]) {
        const f = fixture();
        f.node.xray.alpn = [new BSON.Int32(1)];
        const snap = await f.store.capture(f.id);
        f.onDelete(mutate);
        await assert.rejects(f.store.finish(snap, f.session, async () => true), { code: 'REBUILD_NODE_RETIRE_CHANGED' });
        assert.deepEqual(f.writes, ['tombstone', 'users', 'node']);
        assert.equal(f.aborted(), true);
        assert.equal(f.store.sameSnapshot(snap, snap), false);
    }
});

test('the final projected read catches byte drift Mongo numeric equality would accept', async () => {
    const f = fixture();
    f.node.ssh.port = new BSON.Double(-0);
    const snap = await f.store.capture(f.id);
    f.beforeDelete(node => { node.ssh.port = new BSON.Double(0); });
    await assert.rejects(f.store.finish(snap, f.session, async () => true), { code: 'REBUILD_NODE_RETIRE_CHANGED' });
    assert.deepEqual(f.writes, ['tombstone', 'users']);
    assert.equal(f.aborted(), true);
});
