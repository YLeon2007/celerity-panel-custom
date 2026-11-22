'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRebuildRelayRemove } = require('../rebuildRelayRemove');
const { createRelayDirect } = require('../rebuildRelayDirect');
const { makeLocks } = require('../rebuildLocks');
const attested = require('./helpers/rebuildRelayDirectWire');

const id = 'a'.repeat(24), machineId = 'b'.repeat(32), backupId = 'c'.repeat(32);
const baseline = 'd'.repeat(64), census = 'e'.repeat(64);
const err = suffix => ({ code: `REBUILD_L2TP_REMOVE_${suffix}` });
const frame = data => ({ code: 0, stdout: `${JSON.stringify(data)}\n`, stderr: '' });
const counts = (activeSessions, activeIpsec, fingerprint = census) => ({ activeSessions, activeIpsec, census: fingerprint });

function fixture() {
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: id,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: 'f'.repeat(64) };
    const node = { _id: id, ip: '192.0.2.12', active: true, type: 'xray', cascadeRole: 'relay', ssh: { username: 'root', port: 22 } };
    const installedAt = new Date(1234);
    const state = { _id: 'state', node: id, status: 'installed', desiredState: 'installed', routingMode: 'follow-relay', routingVersion: 1,
        pskEncrypted: 'opaque', secretRevision: 1, rebuildMachineId: machineId, backupId,
        rebuildInstallToken: '01234567-89ab-4def-abcd-0123456789ab', clientCidr: '10.5.0.0/24', tproxyPort: 12345,
        fwmark: 25, routeTable: 125, poolStart: '10.5.0.10', installedAt, lastVerifiedAt: installedAt, lastSyncAt: installedAt };
    const user = { _id: '1'.repeat(24), relayNode: id, login: 'relay-bootstrap', ip: state.poolStart, enabled: true,
        desiredRevision: 1, appliedRevision: 1, syncStatus: 'synced', passwordEncrypted: 'opaque',
        createdAt: installedAt, updatedAt: installedAt, lastSyncedAt: installedAt };
    const f = { state, user, node, env, frames: [], writes: [], count: counts(0, 0), removed: false,
        reply: frame({ ok: true, backupId, removed: true }) };
    let lock, acquisitions = 0;
    const locks = makeLocks({
        async insertOne(row) { acquisitions++; assert.equal(lock, undefined, 'must not reenter global lock'); lock = row; },
        async findOne({ token }) { return lock?.token === token ? lock : null; },
        async deleteMany({ token }) { assert.equal(lock.token, token); lock = undefined; return { acknowledged: true, deletedCount: 1 }; },
    });
    const live = new WeakMap();
    const boundLocks = { run: fn => locks.run(async (raw, retain) => {
        const verify = async () => { assert.ok(live.has(verify)); await raw(); };
        live.set(verify, retain);
        try { return await fn(verify, retain); } finally { live.delete(verify); }
    }) };
    const withHeldLock = async (verify, requestedRetain, fn) => {
        const retain = live.get(verify);
        if (!retain || (requestedRetain !== undefined && requestedRetain !== retain)) {
            throw Object.assign(new Error('lock lost'), { code: 'REBUILD_LOCK_LOST' });
        }
        await verify();
        return fn(verify, retain);
    };
    const query = get => {
        const q = { lean: async () => structuredClone(get()) };
        for (const method of ['select', 'read', 'readConcern', 'limit', 'maxTimeMS']) q[method] = () => q;
        return q;
    };
    f.directory = null;
    const User = {
        find: () => query(() => f.removed ? [] : [user]),
        countDocuments: () => ({ read: () => ({ readConcern: () => ({ maxTimeMS: async () => f.removed ? 0 : 1 }) }) }),
        deleteMany: async () => { f.writes.push('delete-account'); f.removed = true; return { acknowledged: true, deletedCount: 1 }; },
        db: { collection: () => ({ findOne: async () => structuredClone(f.directory), updateMany: async (_, update) => {
            f.writes.push('directory'); f.directory = update.$setOnInsert; return { acknowledged: true, upsertedCount: 1 };
        } }) },
    };
    const State = {
        findOne: () => query(() => f.readState?.(state) ?? state),
        updateMany: async (filter, update) => {
            if (f.readState && JSON.stringify(filter.$expr?.$eq?.[1].$literal) !== JSON.stringify(f.readState(state))) {
                return { acknowledged: true, matchedCount: 0 };
            }
            f.writes.push(update.$set.status); Object.assign(state, update.$set);
            for (const key of Object.keys(update.$unset ?? {})) delete state[key];
            return { acknowledged: true, matchedCount: 1 };
        },
    };
    class Wire {
        connect() {}
        disconnect() {}
        async exec(_, { stdin }, verify) {
            const request = JSON.parse(stdin);
            if (request.action === 'remove') f.beforeRemoveStdin?.();
            await verify();
            assert.ok(lock);
            f.frames.push(request);
            if (request.action === 'session-count') return frame(f.count);
            if (request.action === 'retirement-count') return frame({ ...f.count, activeClients: f.activeClients ?? (f.count.activeSessions === 0 && f.count.activeIpsec === 0 ? 0 : null) });
            if (request.action === 'prepare-remove') return frame({ ok: true, backupId, machineId, baseline });
            assert.equal(request.action, 'remove');
            assert.equal(request.expectedCensus, census);
            assert.equal(state.status, 'removing');
            return f.reply;
        }
    }
    const deps = { Node: { findById: () => query(() => node) }, State, L2tpUser: User, locks: boundLocks, env,
        createRelayDirect: options => createRelayDirect({ ...options, SSH: attested(Wire, machineId) }) };
    return Object.assign(f, { service: createRebuildRelayRemove({ ...deps, withHeldLock }),
        unwired: createRebuildRelayRemove(deps), held: fn => boundLocks.run(fn),
        actions: () => f.frames.map(input => input.action), acquisitions: () => acquisitions, lock: () => lock });
}

test('retirement is an already-held path with no lock reentry and an opaque idle proof', async () => {
    const f = fixture();
    // Model order-sensitive whole-document equality. An expected JS
    // transition need not reproduce the field order of the stored BSON.
    f.readState = state => state.status !== 'removing' ? state : { updatedAt: state.updatedAt, ...state };
    const estimate = await f.held(verify => f.service.previewRetireL2tp(id, verify));
    assert.deepEqual(estimate, { nodeId: id, accountCount: 1, activeSessions: 0, activeIpsec: 0, activeClients: 0, confirmable: true });
    const result = await f.held(async (verify, retain) => {
        await assert.rejects(f.service.confirmRemoveRelay(id, estimate), err('CONFIRMATION_REQUIRED'));
        await assert.rejects(f.service.confirmRetireL2tp(id, { ...estimate }, verify), err('CONFIRMATION_REQUIRED'));
        return f.service.confirmRetireL2tp(id, estimate, verify, retain);
    });
    assert.equal(result.status, 'not_installed');
    assert.equal(f.acquisitions(), 2);
    assert.deepEqual(f.actions(), ['retirement-count', 'retirement-count', 'prepare-remove', 'remove']);
    assert.deepEqual(f.writes, ['removing', 'directory', 'delete-account', 'not_installed']);
    assert.equal(f.lock(), undefined);
});

test('only the original joined positive retirement estimate authorizes active Remove', async () => {
    const f = fixture();
    f.count = counts(1, 1);
    f.activeClients = 1;
    const ordinary = await f.service.previewRemoveRelay(id);
    assert.equal(ordinary.confirmable, false);
    await f.held(async verify => {
        const estimate = await f.service.previewRetireL2tp(id, verify);
        assert.equal(estimate.activeClients, 1);
        assert.equal(estimate.confirmable, true);
        await assert.rejects(f.service.confirmRetireL2tp(id, { ...estimate }, verify), err('CONFIRMATION_REQUIRED'));
        assert.equal((await f.service.confirmRetireL2tp(id, estimate, verify)).status, 'not_installed');
        await assert.rejects(f.service.confirmRetireL2tp(id, estimate, verify), err('CONFIRMATION_REQUIRED'));
    });
    assert.deepEqual(f.actions(), ['session-count', 'retirement-count', 'retirement-count', 'prepare-remove', 'remove']);
    assert.deepEqual(f.frames.slice(-2).map(row => [row.retirement, row.drain, row.expectedCensus]), [
        [true, true, census], [true, true, census],
    ]);
});

test('retirement cannot accept missing, fake, expired, or mismatched held capabilities', async () => {
    const f = fixture();
    const lockLost = { code: 'REBUILD_LOCK_LOST' };
    const expired = await f.held(async verify => ({ verify }));
    await assert.rejects(f.service.previewRetireL2tp(id), lockLost);
    await assert.rejects(f.service.previewRetireL2tp(id, async () => true), lockLost);
    await assert.rejects(f.service.previewRetireL2tp(id, expired.verify), lockLost);
    await f.held(async verify => {
        await assert.rejects(f.unwired.previewRetireL2tp(id, verify), lockLost);
        await assert.rejects(f.service.previewRetireL2tp(id, verify, () => {}), lockLost);
    });
    assert.deepEqual(f.actions(), []);
    assert.deepEqual(f.writes, []);
});

for (const [name, sample] of [
    ['possible overlap', counts(1, 1)], ['PPP only', counts(2, 0)], ['IPsec only', counts(0, 3)],
    ['partial observation', counts(null, 3, null)], ['invalid observation', counts(0, 0, 'malformed')],
]) {
    test(`${name}: retirement does not sum or arm an unproved drain; legacy Remove stays unchanged`, async () => {
        const f = fixture();
        f.count = sample;
        const legacy = await f.service.previewRemoveRelay(id);
        assert.equal(legacy.confirmable, false);
        assert.equal(Object.hasOwn(legacy, 'activeClients'), false);
        await assert.rejects(f.service.confirmRemoveRelay(id, legacy), err('CONFIRMATION_REQUIRED'));
        await f.held(async verify => {
            const estimate = await f.service.previewRetireL2tp(id, verify);
            assert.equal(estimate.activeClients, null);
            assert.equal(estimate.confirmable, false);
            await assert.rejects(f.service.confirmRetireL2tp(id, estimate, verify), err('CONFIRMATION_REQUIRED'));
        });
        assert.deepEqual(f.actions(), ['session-count', 'retirement-count']);
        assert.deepEqual(f.writes, []);
    });
}

for (const [change, error, expectedActions] of [
    [f => { f.user.comment = 'changed without changing count'; }, err('PREVIEW_CHANGED'), ['session-count']],
    [f => { f.state.rebuildInstallToken = '12345678-89ab-4def-abcd-0123456789ab'; }, err('PREVIEW_CHANGED'), ['session-count']],
    [f => { f.env.C3_REBUILD_L2TP_SSH_SHA256 = '1'.repeat(64); }, err('PREVIEW_CHANGED'), ['session-count']],
    [f => { f.directory = { _id: 'directory', version: 1, generation: '12345678-89ab-4def-abcd-0123456789ab',
        accounts: [{ id: f.user._id, login: f.user.login, enabled: true, passwordEncrypted: f.user.passwordEncrypted }] }; },
    err('PREVIEW_CHANGED'), ['session-count']],
    [f => { f.count = counts(0, 0, '1'.repeat(64)); }, err('PREVIEW_CHANGED'), ['session-count', 'session-count']],
    [f => { f.count = counts(1, 1); }, err('PREVIEW_CHANGED'), ['session-count', 'session-count']],
]) {
    test(`retirement rechecks the exact estimate before reservation (${expectedActions.length}, ${error.code})`, async () => {
        const f = fixture();
        const estimate = await f.held(verify => f.service.previewRetireL2tp(id, verify));
        change(f);
        await f.held(verify => assert.rejects(f.service.confirmRetireL2tp(id, estimate, verify), error));
        assert.deepEqual(f.actions(), expectedActions.map(() => 'retirement-count'));
        assert.deepEqual(f.writes, []);
    });
}

for (const reason of ['REMOVE_REFUSED', 'REMOVE_PREVIEW_CHANGED', null]) {
    test(`positive retirement preserves late host refusal versus uncertainty (${reason})`, async () => {
        const f = fixture();
        f.count = counts(1, 1);
        f.activeClients = 1;
        f.readState = state => state.status !== 'removing' ? state : { updatedAt: state.updatedAt, ...state };
        f.reply = reason ? { code: 70, stdout: '', stderr: `DIRECT_${reason}\n` } : { code: 75, stdout: '', stderr: '' };
        const estimate = await f.held(verify => f.service.previewRetireL2tp(id, verify));
        await assert.rejects(f.held(verify => f.service.confirmRetireL2tp(id, estimate, verify)), reason ? err(reason.slice(7))
            : { ...err('OUTCOME_UNKNOWN'), outcome: 'unknown', retryAllowed: false });
        assert.equal(f.state.status, reason ? 'installed' : 'removing');
        assert.equal(Boolean(f.lock()), !reason);
        assert.equal(f.removed, false);
        assert.equal(f.actions().filter(action => action === 'remove').length, 1);
        if (reason) await f.held(verify => assert.rejects(f.service.confirmRetireL2tp(id, estimate, verify), err('CONFIRMATION_REQUIRED')));
    });
}

test('retirement checks the inventory again at DIRECT stdin handoff, including the no-list singleton', async () => {
    const f = fixture();
    const estimate = await f.held(verify => f.service.previewRetireL2tp(id, verify));
    f.beforeRemoveStdin = () => { f.user.comment = 'late account drift'; };
    await assert.rejects(f.held(verify => f.service.confirmRetireL2tp(id, estimate, verify)), {
        ...err('OUTCOME_UNKNOWN'), outcome: 'unknown', retryAllowed: false,
    });
    assert.deepEqual(f.actions(), ['retirement-count', 'retirement-count', 'prepare-remove']);
    assert.equal(f.state.status, 'removing');
    assert.equal(f.removed, false);
    assert.ok(f.lock());
});
