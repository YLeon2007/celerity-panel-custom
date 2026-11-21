'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { assertNoPendingRelayAccounts, createRebuildRelayAccountsStore } = require('../rebuildRelayAccountsStore');

const code = suffix => ({ code: `REBUILD_L2TP_ACCOUNTS_${suffix}` });
const intent = { intentId: 'original', action: 'create', login: 'fixture-account' };
const item = { _id: 'user-on-a', syncOperationId: null, ip: '10.255.16.11' };

function fixture() {
    let pending, users = [], directory;
    const events = [], hooks = {};
    class Session {
        transaction = { transition: state => { assert.equal(state, 'TRANSACTION_COMMITTED'); this.active = false; } };
        startTransaction(options) {
            assert.deepEqual(options, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            events.push('start');
            this.active = true;
            this.pending = structuredClone(pending);
            this.users = structuredClone(users);
        }
        inTransaction() { return this.active; }
        commitTransaction() { assert.fail('driver commitTransaction may automatically retry'); }
        abortTransaction() { events.push('abort'); this.active = false; }
        endSession() { assert.equal(this.active, false); events.push('end'); }
    }
    const inTxn = session => assert.ok(session instanceof Session && session.inTransaction());
    const matchesOwner = (filter, row) => {
        if (!row || (filter.intentId && row.intentId !== filter.intentId)) return false;
        if (!filter.$expr) return true;
        const { $eq } = filter.$expr;
        assert.equal($eq[0], '$$ROOT');
        return JSON.stringify($eq[1].$literal) === JSON.stringify({ _id: 'pending', ...row });
    };
    const collection = {
        async findOne(filter, options) {
            assert.equal(filter._id, 'pending');
            assert.equal(options.readPreference, 'primary');
            assert.equal(options.readConcern.level, 'majority');
            if (options.projection) assert.deepEqual(options.projection, { _id: 1 });
            return matchesOwner(filter, pending) ? options.projection ? { _id: 'pending' }
                : { _id: 'pending', ...structuredClone(pending) } : null;
        },
        async updateMany(filter, update, { session, ...options }) {
            inTxn(session);
            assert.deepEqual(options, { upsert: true });
            if (filter._id === 'directory') {
                assert.equal(filter.generation, update.$setOnInsert.generation);
                session.directory = structuredClone(update.$setOnInsert);
                events.push('directory');
                return { acknowledged: true, upsertedCount: 1 };
            }
            assert.deepEqual(filter, { _id: 'pending', intentId: update.$setOnInsert.intentId });
            events.push('intent');
            if (session.pending) throw Object.assign(new Error('duplicate'), { code: 11000 });
            session.pending = structuredClone(update.$setOnInsert);
            return { acknowledged: true, upsertedCount: 1 };
        },
        async deleteMany(filter, { session, ...options }) {
            inTxn(session);
            assert.deepEqual(options, {});
            assert.equal(filter._id, 'pending');
            events.push('settle');
            if (!matchesOwner(filter, session.pending)) return { acknowledged: true, deletedCount: 0 };
            session.pending = undefined;
            return { acknowledged: true, deletedCount: 1 };
        },
    };
    const db = { collection(name) { assert.equal(name, 'c3_rebuild_relay_accounts'); return collection; },
        startSession: () => new Session(),
        getClient: () => ({ db(name) {
            assert.equal(name, 'admin');
            return { async command(command, { session }) {
                inTxn(session);
                assert.equal(command.commitTransaction, 1);
                assert.equal(command.writeConcern.w, 'majority');
                events.push('commit');
                const land = () => { pending = session.pending; users = session.users; directory = session.directory; return { ok: 1 }; };
                return hooks.commit ? hooks.commit(land) : land();
            } };
        } }),
    };
    const User = { db,
        async insertMany(rows, { session }) {
            inTxn(session); events.push('insert');
            const inserted = rows.map(row => ({ ...row, _id: 'a'.repeat(24) }));
            session.users.push(...inserted);
            return inserted;
        },
        async updateMany(filter, update, options) {
            assert.deepEqual(filter, { _id: { $eq: item._id }, ip: { $eq: item.ip },
                syncOperationId: { $eq: null, $exists: true } });
            assert.deepEqual(update, { $set: { enabled: false } });
            inTxn(options.session);
            assert.equal(options.timestamps, false);
            events.push('update');
            return { acknowledged: true, matchedCount: 1 };
        },
        async deleteMany(filter, options) {
            assert.equal(filter._id.$eq, item._id);
            inTxn(options.session);
            events.push('delete');
            return { acknowledged: true, deletedCount: 1 };
        },
    };
    const store = createRebuildRelayAccountsStore({ Node: { db }, State: { db }, L2tpUser: User });
    const publish = (action, intentId, changed, expected) => store.publish({ action, intentId, intent: expected,
        login: intent.login,
        directoryBase: [{ id: 'b'.repeat(24), login: 'relay-bootstrap', enabled: true, passwordEncrypted: 'fixture-envelope' },
            ...(action !== 'create' ? [{ id: 'a'.repeat(24), login: intent.login, enabled: changed, passwordEncrypted: 'fixture-envelope' }] : [])],
        changes: [{ before: item, after: !changed ? undefined : action === 'create'
             ? { login: intent.login, enabled: true, passwordEncrypted: 'fixture-envelope' } : { enabled: false } }],
        async recheck(session) { inTxn(session); events.push('snapshot'); },
        async verifyAuthority() { await store.verifyIntent(intentId, expected); events.push('guard'); },
    });
    const cancel = expected => store.cancel({ intent: expected,
        async recheck(session) { inTxn(session); events.push('snapshot'); },
        async verifyAuthority() { await store.verifyIntent(expected.intentId, expected); events.push('guard'); },
    });
    return { db, collection, store, publish, cancel, events, hooks, get pending() { return pending; }, get users() { return users; },
        get directory() { return directory; } };
}

test('transaction commits the actual majority intent; another owner cannot overwrite or settle it', async () => {
    const f = fixture();
    f.hooks.commit = land => { assert.equal(f.pending, undefined); return land(); };
    await assertNoPendingRelayAccounts(f.db);
    await f.store.begin(intent);
    assert.deepEqual(f.pending, intent);
    assert.deepEqual(f.events.splice(0), ['start', 'intent', 'commit', 'end']);
    await assert.rejects(f.store.begin({ intentId: 'different' }), { code: 11000 });
    assert.deepEqual(f.events.splice(0), ['start', 'intent', 'abort', 'end']);
    const foreign = { ...await f.store.pending(), intentId: 'different' };
    await assert.rejects(f.store.verifyIntent('different', foreign), code('CHANGED'));
    await assert.rejects(f.publish('create', 'different', true, foreign), code('CHANGED'));
    assert.deepEqual(f.events, ['start', 'snapshot', 'insert', 'directory', 'settle', 'abort', 'end']);
    assert.equal(f.directory, undefined);
    assert.deepEqual(f.users, []);
    await assert.rejects(assertNoPendingRelayAccounts(f.db), { ...code('BLOCKED'), retryAllowed: false });
    await f.store.verifyIntent(intent.intentId, await f.store.pending());
});

test('authority and settlement never fall back to UUID-only when a full row is missing', async () => {
    const f = fixture();
    await f.store.begin(intent);
    const row = await f.store.pending();
    f.events.length = 0;
    for (const invalid of [undefined, { ...row, intentId: 'different' }, { ...row, _id: 'directory' }]) {
        await assert.rejects(f.store.verifyIntent(intent.intentId, invalid), code('CHANGED'));
        await assert.rejects(f.publish('create', intent.intentId, true, invalid), code('CHANGED'));
    }
    await assert.rejects(f.cancel(undefined), code('CHANGED'));
    assert.deepEqual(f.events, []);
    assert.deepEqual(await f.store.pending(), row);
});

test('committed intent with lost majority acknowledgement stays visible, without retry or abort', async () => {
    const f = fixture();
    f.hooks.commit = land => ({ ...land(), writeConcernError: { code: 91 }, errorLabels: ['RetryableWriteError'] });
    await assert.rejects(f.store.begin(intent), /transaction commit unconfirmed/);
    assert.deepEqual(f.events, ['start', 'intent', 'commit', 'end']);
    assert.deepEqual(f.pending, intent);
    await assert.rejects(assertNoPendingRelayAccounts(f.db), { ...code('BLOCKED'), retryAllowed: false });
});

test('global fence read failure is a refusal and does not expose storage diagnostics', async () => {
    const { db, collection } = fixture();
    collection.findOne = async () => { throw new Error('private storage detail'); };
    await assert.rejects(assertNoPendingRelayAccounts(db), code('PERSISTENCE_UNAVAILABLE'));
});

for (const [action, write] of [['create', 'insert'], ['disable', 'update'], ['delete', 'delete']]) {
    test(`${action} publishes accounts and settles the intent in the same transaction`, async () => {
        const f = fixture();
        await f.store.begin(intent);
        f.events.length = 0;
        f.hooks.commit = land => { assert.deepEqual(f.pending, intent); return land(); };
        await f.publish(action, intent.intentId, true, await f.store.pending());
        assert.deepEqual(f.events, ['start', 'snapshot', write, 'directory', 'settle', 'guard', 'commit', 'end']);
        const account = f.directory.accounts.find(row => row.login === intent.login);
        assert.equal(account?.enabled, { create: true, disable: false, delete: undefined }[action]);
        await assertNoPendingRelayAccounts(f.db);
    });
}

test('already-disabled settlement closes the intent transaction without writing an unchanged user', async () => {
    const f = fixture();
    await f.store.begin(intent);
    f.events.length = 0;
    await f.publish('disable', intent.intentId, false, await f.store.pending());
    assert.deepEqual(f.events, ['start', 'snapshot', 'directory', 'settle', 'guard', 'commit', 'end']);
    await assertNoPendingRelayAccounts(f.db);
});

test('lost publish acknowledgement does not retry or abort; an uncommitted attempt preserves its intent', async () => {
    const f = fixture();
    await f.store.begin(intent);
    const lost = new Error('lost commit acknowledgement');
    f.events.length = 0;
    f.hooks.commit = () => { throw lost; };
    const observed = await f.store.pending();
    await assert.rejects(f.publish('create', intent.intentId, true, observed), err => err === lost);
    assert.deepEqual(f.events, ['start', 'snapshot', 'insert', 'directory', 'settle', 'guard', 'commit', 'end']);
    assert.equal(f.directory, undefined);
    assert.deepEqual(f.users, []);
    await f.store.verifyIntent(intent.intentId, observed);
});

test('read the full majority pending row and cancel only that row in one transaction', async () => {
    const f = fixture();
    assert.equal(await f.store.pending(), null);
    await f.store.begin(intent);
    const observed = await f.store.pending();
    assert.deepEqual(observed, { _id: 'pending', ...intent });
    f.events.length = 0;
    await f.cancel(observed);
    assert.deepEqual(f.events, ['start', 'snapshot', 'settle', 'guard', 'commit', 'end']);
    assert.deepEqual(f.users, []);
    assert.equal(f.directory, undefined);
    assert.equal(await f.store.pending(), null);
});

for (const settlement of ['cancel', 'publish']) {
    test(`${settlement} cannot consume a modified raw row even with the same UUID`, async () => {
        const f = fixture();
        await f.store.begin(intent);
        const observed = await f.store.pending();
        f.pending.extra = true;
        await assert.rejects(f.store.verifyIntent(intent.intentId, observed), code('CHANGED'));
        f.events.length = 0;
        await assert.rejects(settlement === 'cancel' ? f.cancel(observed) : f.publish('create', intent.intentId, true, observed), code('CHANGED'));
        assert.deepEqual(f.events, ['start', 'snapshot', ...(settlement === 'publish' ? ['insert', 'directory'] : []),
            'settle', 'abort', 'end']);
        assert.deepEqual(f.users, []);
        assert.equal(f.directory, undefined);
        assert.equal(f.pending.extra, true);
    });
}

test('unknown cancellation commit is not automatically retried or aborted', async () => {
    const f = fixture();
    await f.store.begin(intent);
    f.events.length = 0;
    f.hooks.commit = () => { throw Error('unknown cancel'); };
    await assert.rejects(f.cancel(await f.store.pending()), /unknown cancel/);
    assert.deepEqual(f.events, ['start', 'snapshot', 'settle', 'guard', 'commit', 'end']);
    await assert.rejects(f.store.assertNoPending(), code('BLOCKED'));
});
