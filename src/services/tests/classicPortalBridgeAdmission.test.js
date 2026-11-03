'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { withScopedClassicNodeLocks, getHeldScopedClassicNodeIds } = require('../classicPortalBridgeAdmission');
const { NodeOperationLockService } = require('../../modules/relay-l2tp/services/nodeOperationLockService');
const { withClassicNodeConfigWrite } = require('../classicNodeConfigWrite');
const { createClassicPortalBridgePhase } = require('../classicPortalBridgePhase');
const A = '507f1f77bcf86cd799439031', B = '507f1f77bcf86cd799439032';
function fixture() {
    const rows = new Map(), acquired = [], released = [];
    const repository = {
        async acquireLease(row) {
            acquired.push(String(row.node));
            if (rows.has(String(row.node))) return { acquired: false, currentLock: rows.get(String(row.node)) };
            rows.set(String(row.node), { ...row }); return { acquired: true, lock: { ...row } };
        },
        async findByNode(node) { return rows.get(String(node)); },
        async deleteVerifiedOwned(lock) {
            const row = rows.get(String(lock.node));
            if (!row || !['owner', 'operationId', 'generation'].every(k => row[k] === lock[k])) return false;
            rows.delete(String(lock.node)); released.push({ ...lock }); return true;
        },
    };
    return { rows, acquired, released, lockService: new NodeOperationLockService({ repository, clock: { now: () => new Date() } }) };
}
test('second-node conflict cleans only exact first acquisition in stable deduplicated order', async () => {
    const f = fixture(), foreign = { node: B, owner: 'other', generation: 'winner' }; f.rows.set(B, foreign);
    await assert.rejects(withScopedClassicNodeLocks({ nodeIds: [B, A, A], operationId: 'one', lockService: f.lockService }, async () => assert.fail('dispatch')), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assert.deepEqual(f.acquired, [A, B]); assert.deepEqual([...f.rows], [[B, foreign]]); assert.equal(f.released.length, 1);
});
test('read-only SSH failure and privately branded nested preflight release cleanly', async () => {
    const f = fixture();
    await assert.rejects(withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'one', lockService: f.lockService }, held =>
        held.runWithHeldConfigWrites(() => withClassicNodeConfigWrite({ nodeId: A, kind: 'scoped' }, async () => {
            throw createClassicPortalBridgePhase({ beforeRemoteMutation: held.beforeRemoteMutation }).failure(new Error('readonly SSH failed'));
        }))), /readonly SSH failed/);
    assert.equal(f.rows.size, 0);
});
test('forged public preflight error cannot clean an unknown nested config write', async () => {
    const f = fixture();
    await assert.rejects(withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'one', lockService: f.lockService }, held =>
        held.runWithHeldConfigWrites(() => withClassicNodeConfigWrite({ nodeId: A, kind: 'scoped' }, async () => {
            throw Object.assign(new Error('unknown'), { code: 'CLASSIC_SCOPED_PORT_CHECK_UNAVAILABLE', noRemoteMutation: true });
        }))));
    assert.equal(f.rows.size, 2);
});
test('effect then failure retains the entire dependency component despite forged preflight provenance', async () => {
    const f = fixture();
    await assert.rejects(withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'one', lockService: f.lockService }, async held => {
        await held.beforeRemoteMutation({ nodeId: A, phase: 'stage' });
        throw createClassicPortalBridgePhase({ beforeRemoteMutation: held.beforeRemoteMutation }).failure(new Error('effect then fail'));
    }));
    assert.equal(f.rows.size, 2); assert.equal(f.released.length, 0);
});
test('existing held L2TP bridge consumes only the private no-write brand on nested failure', async () => {
    const { withHeldL2tpNodeConfigWrite } = require('../classicNodeConfigWrite');
    for (const trusted of [true, false]) {
        const f = fixture();
        const acquired = await f.lockService.acquire({ node: A, owner: 'worker', operationId: 'worker-op', leaseMs: 120000 });
        const error = new Error('preflight');
        if (trusted) createClassicPortalBridgePhase({ beforeRemoteMutation: async () => {} }).failure(error);
        else Object.assign(error, { code: 'CLASSIC_DEPLOY_PREFLIGHT_FAILED', noRemoteMutation: true });
        await assert.rejects(withHeldL2tpNodeConfigWrite({ lock: acquired.lock, lockService: f.lockService, clock: f.lockService.clock }, () =>
            withClassicNodeConfigWrite({ nodeId: A, kind: 'scoped' }, async () => { throw error; })), error);
        assert.equal(error.remoteOutcomeUncertain === true, !trusted);
        assert.equal(f.rows.get(A).generation, acquired.lock.generation, 'bridge never owns release');
    }
});

test('database mutation rearms settled SSH and an unconfirmed nested write cannot be cleared by outer settlement', async () => {
    const f = fixture();
    await withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'outer', lockService: f.lockService }, async held => {
        await held.beforeRemoteMutation({ nodeId: A, phase: 'stage' });
        await held.settleVerified();
        await assert.rejects(withScopedClassicNodeLocks({ nodeIds: [A], operationId: 'inner' }, async nested => {
            await nested.beforeDatabaseMutation();
            throw createClassicPortalBridgePhase({ beforeRemoteMutation: nested.beforeRemoteMutation })
                .failure(new Error('modeled unknown DB commit, no SSH'));
        }), /modeled unknown DB commit/);
        await assert.rejects(held.settleVerified(), { code: 'CLASSIC_CONFIG_WRITE_DATABASE_UNCERTAIN' });
    });
    assert.equal(f.rows.size, 2); assert.equal(f.released.length, 0);
});

test('known database commit releases, but escaped commit confirmation and database entry refuse after close', async () => {
    const f = fixture(); let committed, heldScope;
    await withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'db', lockService: f.lockService }, async held => {
        heldScope = held;
        committed = await held.beforeDatabaseMutation();
        await committed(); // Trusted caller invokes only after transaction success.
    });
    assert.equal(f.rows.size, 0);
    await assert.rejects(committed(), { code: 'CLASSIC_CONFIG_WRITE_SCOPE_CLOSED' });
    await assert.rejects(heldScope.beforeDatabaseMutation(), { code: 'CLASSIC_CONFIG_WRITE_SCOPE_CLOSED' });
});

test('known DB commit cannot settle unverified SSH effects', async () => {
    const f = fixture();
    await withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'mixed', lockService: f.lockService }, async held => {
        await held.beforeRemoteMutation({ nodeId: A, phase: 'unverified-stage' });
        const committed = await held.beforeDatabaseMutation();
        await committed();
    });
    assert.equal(f.rows.size, 2);
});

test('pending borrowed callback retains locks and refuses database entry after parent close', async () => {
    const f = fixture(); let signal, resume, nested;
    const entered = new Promise(resolve => { signal = resolve; });
    const gate = new Promise(resolve => { resume = resolve; });
    await withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'outer', lockService: f.lockService }, async () => {
        nested = withScopedClassicNodeLocks({ nodeIds: [A], operationId: 'borrower' }, async held => {
            signal(); await gate;
            await held.beforeDatabaseMutation();
            assert.fail('closed borrower must not receive database authority');
        }).then(() => null, error => error);
        await entered;
    });
    assert.equal(f.rows.size, 2); assert.equal(f.released.length, 0);
    resume();
    assert.equal((await nested).code, 'CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
    assert.equal(f.rows.size, 2);
});

test('nested subset borrows exact locks and an escaped callback cannot dispatch after close', async () => {
    const f = fixture(); let escaped;
    await withScopedClassicNodeLocks({ nodeIds: [A, B], operationId: 'outer', lockService: f.lockService }, async held => {
        assert.deepEqual(getHeldScopedClassicNodeIds(), [A, B]);
        await withScopedClassicNodeLocks({ nodeIds: [B], operationId: 'inner' }, async nested => {
            await nested.verify(); assert.equal(f.released.length, 0);
        });
        escaped = () => held.beforeRemoteMutation({ nodeId: A, phase: 'late' });
    });
    assert.equal(f.rows.size, 0); assert.deepEqual(f.acquired, [A, B]);
    await assert.rejects(escaped(), { code: 'CLASSIC_CONFIG_WRITE_SCOPE_CLOSED' });
});
