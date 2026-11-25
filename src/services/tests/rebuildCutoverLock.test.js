'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual } = require('node:util');
const { makeLocks, cutoverOwner, installOwner } = require('../rebuildLocks');

const identity = Object.freeze({ scope: 'component-1', operationId: '11111111-1111-4111-8111-111111111111',
    fenceId: '22222222-2222-4222-8222-222222222222', planDigest: 'a'.repeat(64) });
const lost = { code: 'REBUILD_LOCK_LOST' };
const unconfirmed = { code: 'REBUILD_LOCK_RELEASE_UNCONFIRMED' };
const stale = { code: 'REBUILD_LOCK_NOT_STALE' };
const gate = () => { let open; const wait = new Promise(resolve => { open = resolve; }); return { open, wait }; };

// Model at the raw collection boundary, not at the lock/verifier boundary.
function fixture() {
    let row, now = 0;
    const writes = [], hooks = {};
    const match = filter => row && Object.entries(filter).every(([key, value]) => {
        if (key === '$expr') {
            const [field, rhs] = value.$eq;
            if (field === '$$ROOT') return isDeepStrictEqual(row, rhs.$literal);
            assert.equal(field, '$allowStaleUnlock');
            return row.allowStaleUnlock === rhs;
        }
        if (key === 'heartbeat') return row.heartbeat <= value.$lte;
        if (key === 'cutover') return Object.hasOwn(row, key) === value.$exists;
        return row[key] === value;
    });
    const store = {
        async insertOne(value) {
            if (row) throw Object.assign(new Error('duplicate'), { code: 11000 });
            row = structuredClone(value);
            return { acknowledged: true };
        },
        async findOne(filter, options) {
            const result = match(filter) ? structuredClone(row) : null;
            return hooks.read ? hooks.read(filter, options, result) : result;
        },
        async updateOne(filter, { $set }) {
            writes.push('heartbeat');
            await hooks.heartbeat?.();
            const matchedCount = match(filter) ? 1 : 0;
            if (matchedCount) Object.assign(row, structuredClone($set));
            return { acknowledged: true, matchedCount };
        },
        async updateMany(filter, { $set }, options) {
            writes.push('promote');
            assert.equal(options.writeConcern.w, 'majority');
            assert.deepEqual(filter.$expr, { $eq: ['$$ROOT', { $literal: row }] });
            hooks.beforePromote?.(row);
            const matchedCount = match(filter) ? 1 : 0;
            if (matchedCount) Object.assign(row, structuredClone($set));
            const reply = { acknowledged: true, matchedCount, modifiedCount: matchedCount };
            return hooks.promote ? hooks.promote(reply) : reply;
        },
        async deleteMany(filter, options) {
            writes.push('release');
            if (options) assert.equal(options.writeConcern.w, 'majority');
            hooks.beforeRelease?.(row, filter, options);
            const deletedCount = match(filter) ? 1 : 0;
            if (deletedCount) row = null;
            const reply = { acknowledged: true, deletedCount };
            return hooks.release ? hooks.release(reply) : reply;
        },
        async deleteOne(filter) {
            const deletedCount = match(filter) ? 1 : 0;
            if (deletedCount) row = null;
            return { acknowledged: true, deletedCount };
        },
    };
    const fresh = () => makeLocks(store, () => now);
    return { store, fresh, locks: fresh(), hooks, writes, row: () => row, age: () => { now += 120001; } };
}

async function blocked(f, token) {
    f.age();
    const fresh = f.fresh();
    assert.deepEqual(await fresh.status(), { locked: true, stale: false });
    await assert.rejects(fresh.unlock(token), stale);
    await assert.rejects(fresh.run(() => assert.fail('competing writer entered')), { code: 'REBUILD_BUSY' });
    await assert.rejects(fresh.readInstallRecovery({ collection: () => f.store }, 'node', 'actor'),
        { code: 'REBUILD_L2TP_INSTALL_RECOVERY_BLOCKED' });
}

test('already-held ordinary caller promotes before dispatch; only the original outer run releases after proof', async () => {
    const f = fixture();
    let token;
    f.hooks.beforeRelease = (row, filter, options) => {
        assert.deepEqual(filter, { _id: 'apply', token, $expr: { $eq: ['$$ROOT', { $literal: row }] } });
        assert.equal(options.writeConcern.w, 'majority');
    };
    const result = await f.locks.run(async (raw, retain) => {
        assert.equal(f.row().allowStaleUnlock, true);
        token = f.row().token;
        await raw();
        const nestedApply = async () => {
            const owner = cutoverOwner(retain);
            const proof = await owner.promote(identity);
            assert.equal(f.row().token, token);
            assert.equal(f.row().allowStaleUnlock, false);
            assert.deepEqual(f.row().cutover, identity);
            f.hooks.read = (filter, options, result) => {
                assert.ok(filter.$expr);
                assert.equal(options.readConcern.level, 'majority');
                assert.equal(options.readPreference, 'primary');
                return result;
            };
            assert.equal(await proof.verify(), true);
            await raw();
            await assert.rejects(owner.promote(identity), lost);
            await assert.rejects(f.fresh().run(() => assert.fail('competing writer entered')), { code: 'REBUILD_BUSY' });
            await proof.settle(async () => { assert.equal(await proof.verify(), true); return true; });
            await assert.rejects(proof.verify(), lost);
            await assert.rejects(proof.settle(() => assert.fail('replayed settlement')), lost);
            return 'finished';
        };
        const value = await nestedApply();
        assert.deepEqual(f.writes, ['promote']);
        assert.ok(f.row());
        return value;
    });
    assert.equal(result, 'finished');
    assert.deepEqual(f.writes, ['promote', 'release']);
    assert.equal(f.row(), null);
});

test('unknown journal or settlement and outer callback failure leave the aged global row blocked', async t => {
    for (const failure of ['journal', 'false-proof', 'throwing-proof', 'outer-failure-after-proof', 'explicit-retain']) await t.test(failure, async () => {
        const f = fixture();
        const primary = Object.freeze(new Error('primary refusal'));
        let token;
        const action = f.locks.run(async (_, retain) => {
            token = f.row().token;
            const proof = await cutoverOwner(retain).promote(identity);
            if (failure === 'journal') return;
            if (failure === 'outer-failure-after-proof') {
                await proof.settle(() => true);
                throw primary;
            }
            if (failure === 'explicit-retain') {
                await proof.settle(() => true);
                retain();
                return;
            }
            await assert.rejects(proof.settle(() => {
                if (failure === 'throwing-proof') throw primary;
                return false;
            }), lost);
            await assert.rejects(proof.settle(() => assert.fail('retrospective proof')), lost);
        });
        await assert.rejects(action, failure === 'outer-failure-after-proof' ? e => e === primary : unconfirmed);
        assert.deepEqual(f.writes, ['promote']);
        await blocked(f, token);
    });
});

test('applied promotion with lost or unacknowledged reply never grants dispatch or tries cleanup', async t => {
    for (const [name, fault] of [
        ['lost reply', () => { throw new Error('private DB detail'); }],
        ['unacknowledged reply', reply => ({ ...reply, acknowledged: false })],
    ]) await t.test(name, async () => {
        const f = fixture();
        f.hooks.promote = fault;
        let token;
        await assert.rejects(f.locks.run(async (raw, retain) => {
            token = f.row().token;
            const owner = cutoverOwner(retain);
            await assert.rejects(owner.promote(identity), lost);
            await assert.rejects(raw(), lost);
            await assert.rejects(owner.promote(identity), lost);
        }), unconfirmed);
        assert.deepEqual(f.writes, ['promote']);
        assert.deepEqual(f.row().cutover, identity);
        await blocked(f, token);
    });
});

test('same-token drift is not adopted at promotion, at verification, during proof or at deletion', async t => {
    for (const phase of ['promotion', 'first-read', 'verification', 'proof', 'release']) await t.test(phase, async () => {
        const f = fixture();
        let token;
        const drift = row => { row.unexpected = true; };
        if (phase === 'promotion') f.hooks.beforePromote = drift;
        if (phase === 'first-read') f.hooks.promote = reply => { drift(f.row()); return reply; };
        if (phase === 'release') f.hooks.beforeRelease = drift;
        await assert.rejects(f.locks.run(async (raw, retain) => {
            token = f.row().token;
            const promote = () => cutoverOwner(retain).promote(identity);
            if (phase === 'promotion' || phase === 'first-read') {
                await assert.rejects(promote(), lost);
                await assert.rejects(raw(), lost);
                return;
            }
            const proof = await promote();
            if (phase === 'verification') {
                drift(f.row());
                await assert.rejects(raw(), lost);
                delete f.row().unexpected;
                await assert.rejects(proof.verify(), lost); // a repaired row cannot revive the old proof
                drift(f.row());
            }
            const finish = () => proof.settle(() => { if (phase === 'proof') drift(f.row()); return true; });
            if (phase === 'release') await finish();
            else await assert.rejects(finish(), lost);
        }), unconfirmed);
        assert.deepEqual(f.writes, phase === 'release' ? ['promote', 'release'] : ['promote']);
        assert.equal(f.row().token, token);
        assert.equal(f.row().unexpected, true);
        if (phase !== 'promotion') await blocked(f, token);
        else assert.equal(f.row().allowStaleUnlock, true); // no promotion or dispatch occurred
    });
});

test('a detached verifier cannot resolve positively after the original callback exits', async () => {
    const f = fixture(), reading = gate(), completeRead = gate();
    let owner, proof, retained, detached, raw, reads = 0;
    await assert.rejects(f.locks.run(async (verify, retain) => {
        raw = verify;
        retained = retain;
        owner = cutoverOwner(retain);
        proof = await owner.promote(identity);
        f.hooks.read = async (_filter, _options, result) => {
            reads++;
            reading.open();
            await completeRead.wait;
            return result;
        };
        detached = assert.rejects(proof.verify(), lost);
        await reading.wait;
    }), unconfirmed);
    completeRead.open();
    await detached;
    assert.equal(cutoverOwner(retained), undefined);
    await assert.rejects(owner.promote(identity), lost);
    await assert.rejects(raw(), lost);
    await assert.rejects(proof.verify(), lost);
    await assert.rejects(proof.settle(() => assert.fail('detached settlement')), lost);
    assert.equal(reads, 1);
    assert.deepEqual(f.writes, ['promote']);
    f.hooks.read = undefined;
    await blocked(f, f.row().token);
});

test('a promoted row cannot become stale-unlockable via same-token eligibility drift', async () => {
    const f = fixture();
    await assert.rejects(f.locks.run(async (_, retain) => {
        const proof = await cutoverOwner(retain).promote(identity);
        f.row().allowStaleUnlock = true;
        await assert.rejects(proof.verify(), lost);
    }), unconfirmed);
    await blocked(f, f.row().token);
    assert.deepEqual(f.writes, ['promote']);
});

test('a detached promotion with a late acknowledgement leaves no verifier and no owner cleanup', async () => {
    const f = fixture(), committed = gate(), ack = gate();
    f.hooks.promote = async reply => { committed.open(); await ack.wait; return reply; };
    let promotion;
    await assert.rejects(f.locks.run(async (_, retain) => {
        promotion = assert.rejects(cutoverOwner(retain).promote(identity), lost);
        await committed.wait;
    }), unconfirmed);
    ack.open();
    await promotion;
    assert.deepEqual(f.writes, ['promote']);
    await blocked(f, f.row().token);
});

test('lost exact release acknowledgement is not retried or replaced with a new claim', async () => {
    const f = fixture();
    f.hooks.release = reply => {
        assert.equal(reply.deletedCount, 1);
        throw new Error('private DB detail');
    };
    await assert.rejects(f.locks.run(async (_, retain) => {
        const proof = await cutoverOwner(retain).promote(identity);
        await proof.settle(() => true);
    }), unconfirmed);
    assert.equal(f.row(), null); // Delete may have committed: don't reconstruct the vanished row.
    assert.deepEqual(f.writes, ['promote', 'release']);
});

test('promotion drains an in-flight heartbeat and stops renewal before pinning the row', async t => {
    t.mock.timers.enable({ apis: ['setInterval'] });
    const f = fixture(), beating = gate(), completeBeat = gate();
    f.hooks.heartbeat = async () => { beating.open(); await completeBeat.wait; };
    await f.locks.run(async (_, retain) => {
        f.age();
        t.mock.timers.tick(15000);
        await beating.wait;
        const promotion = cutoverOwner(retain).promote(identity);
        await Promise.resolve();
        assert.deepEqual(f.writes, ['heartbeat']);
        completeBeat.open();
        const proof = await promotion;
        t.mock.timers.tick(15000);
        await proof.verify();
        await proof.settle(() => true);
    });
    assert.deepEqual(f.writes, ['heartbeat', 'promote', 'release']);
});

test('Install reservation and cutover promotion cannot share a generation', async () => {
    const f = fixture();
    const db = { collection: () => f.store }, session = { inTransaction: () => true };
    await f.locks.run(async (_, retain) => {
        const install = installOwner(retain);
        const proof = await cutoverOwner(retain).promote(identity);
        await assert.rejects(install.bind(db, session, {}), lost);
        await proof.settle(() => true);
    }, { allowStaleUnlock: false });
    assert.deepEqual(f.writes, ['promote', 'release']);
});
