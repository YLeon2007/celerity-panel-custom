'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { assertNoPendingRelayAccounts, createRebuildRelayAccountsStore } = require('../rebuildRelayAccountsStore');

function fixture() {
    let pending, session;
    const events = [];
    const collection = {
        async findOne(filter, options) {
            assert.equal(filter._id, 'pending');
            assert.equal(options.readPreference, 'primary');
            assert.equal(options.readConcern.level, 'majority');
            assert.deepEqual(options.projection, { _id: 1 });
            return pending && (!filter.intentId || pending.intentId === filter.intentId) ? { _id: 'pending' } : null;
        },
        async updateMany(filter, update, options) {
            assert.equal(options.writeConcern.w, 'majority');
            assert.equal(options.upsert, true);
            assert.deepEqual(filter, { _id: 'pending', intentId: update.$setOnInsert.intentId });
            if (pending) throw Object.assign(new Error('duplicate'), { code: 11000 });
            pending = structuredClone(update.$setOnInsert);
            return { acknowledged: true, upsertedCount: 1 };
        },
        async deleteMany(filter, options) {
            assert.equal(options.writeConcern.w, 'majority');
            assert.equal(filter._id, 'pending');
            if (!pending || pending.intentId !== filter.intentId) return { acknowledged: true, deletedCount: 0 };
            pending = undefined;
            return { acknowledged: true, deletedCount: 1 };
        },
    };
    const db = { collection(name) { assert.equal(name, 'c3_rebuild_relay_accounts'); return collection; },
        async startSession() { assert.ok(session); return session; } };
    const item = { _id: 'user-on-a', syncOperationId: null, ip: '10.255.16.11' };
    const User = { db,
        async insertMany(rows, opts) { assert.equal(opts.session, session); events.push('insert'); return rows; },
        async updateMany(filter, update, opts) {
            assert.deepEqual(filter, { _id: { $eq: item._id }, ip: { $eq: item.ip },
                syncOperationId: { $eq: null, $exists: true } });
            assert.deepEqual(update, { $set: { enabled: false } });
            assert.equal(opts.session, session);
            assert.equal(opts.timestamps, false);
            events.push('update');
            return { acknowledged: true, matchedCount: 1 };
        },
        async deleteMany(filter, opts) {
            assert.equal(filter._id.$eq, item._id);
            assert.equal(opts.session, session);
            events.push('delete');
            return { acknowledged: true, deletedCount: 1 };
        },
    };
    const store = createRebuildRelayAccountsStore({ Node: { db }, State: { db }, L2tpUser: User });
    return { db, collection, store, item, events, setSession(s) { session = s; } };
}

test('separate global majority fence blocks other callers and cannot be released by a different owner', async () => {
    const { db, store } = fixture();
    await assertNoPendingRelayAccounts(db);
    await store.begin({ intentId: 'original', action: 'create' });
    await assert.rejects(store.begin({ intentId: 'different' }), { code: 11000 });
    await assert.rejects(store.verifyIntent('different'), { code: 'REBUILD_L2TP_ACCOUNTS_CHANGED' });
    await assert.rejects(store.release('different'), { code: 'REBUILD_L2TP_ACCOUNTS_CHANGED' });
    await assert.rejects(assertNoPendingRelayAccounts(db), { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED', retryAllowed: false });
    await store.verifyIntent('original');
    await store.release('original');
    await assertNoPendingRelayAccounts(db);
});

test('global fence read failure is a refusal and does not expose storage diagnostics', async () => {
    const { db, collection } = fixture();
    collection.findOne = async () => { throw new Error('private storage detail'); };
    await assert.rejects(assertNoPendingRelayAccounts(db), { code: 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE' });
});

for (const [action, write] of [['create', 'insert'], ['disable', 'update'], ['delete', 'delete']]) {
    test(`${action} publication uses one transaction and leaves the intent intact on commit acknowledgement loss`, async () => {
        const { db, store, item, setSession, events } = fixture();
        const lost = new Error('lost commit acknowledgment');
        const session = {
            startTransaction(opts) {
                assert.equal(opts.readConcern.level, 'snapshot');
                assert.equal(opts.writeConcern.w, 'majority');
                events.push('start');
            },
            async commitTransaction() { events.push('commit'); throw lost; },
            inTransaction() { return true; },
            async abortTransaction() { events.push('abort'); },
            async endSession() { events.push('end'); },
        };
        setSession(session);
        await store.begin({ intentId: 'original', action });
        await assert.rejects(store.publish({ action, changes: [{ before: item, after: { enabled: false } }],
            async recheck(s) { assert.equal(s, session); events.push('snapshot'); },
            async verifyAuthority() { events.push('guard'); },
        }), err => err === lost);
        await assert.rejects(assertNoPendingRelayAccounts(db), { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED' });
        assert.deepEqual(events, ['start', 'snapshot', write, 'guard', 'commit', 'end']);
    });
}
