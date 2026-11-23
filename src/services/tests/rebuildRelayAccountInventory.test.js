'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Types: { ObjectId } } = require('mongoose');
const { inspectAccountSources, isDormantClassicState, readClassicOperations } = require('../rebuildRelayAccountInventory');
const { createStore, isPristine } = require('../rebuildRelayBackendStore');
const { makeDesired } = require('../rebuildRelayBackendDesired');

const targetId = 'a'.repeat(24);
const oid = digit => new ObjectId(digit.repeat(24));
const neighbor = oid('b');
const pointer = oid('c');
const sourceId = oid('d');
const invalid = { code: 'REBUILD_L2TP_ACCOUNT_INVENTORY_INVALID' };
const busy = { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_BUSY' };
const classic = (overrides = {}) => ({ _id: oid('1'), node: neighbor, routingMode: 'route-group',
    status: 'not_installed', desiredState: 'not_installed', routeGroup: oid('2'), operationId: pointer,
    activePathKey: 'historical-path', pskEncrypted: 'synthetic-envelope', secretRevision: 1,
    clientCidr: '10.66.0.0/24', localAddress: '10.66.0.1', poolStart: '10.66.0.10', poolEnd: '10.66.0.250', ...overrides });
const operation = (status, overrides) => ({ _id: pointer, node: neighbor, status, ...overrides });
const inspect = (state, classicOperations, users = []) => inspectAccountSources({ nodeId: targetId, listMode: true,
    rows: { states: Array.isArray(state) ? state : [state], users, ...(classicOperations !== undefined && { classicOperations }) } });
const terminal = ['succeeded', 'failed', 'cancelled', 'rolled_back'];

test('settled historical classic neighbors with terminal operations do not reserve the overlapping pool', () => {
    const fixtureKey = 'synthetic'.repeat(4);
    const { desired: first } = makeDesired(targetId, [], [], fixtureKey);
    const historicalPoolStart = `${first.poolStart.split('.').slice(0, 3).join('.')}.11`;
    for (const desiredState of ['not_installed', 'absent']) {
        for (const status of terminal) {
            const row = classic({ desiredState, clientCidr: first.clientCidr, localAddress: first.poolStart,
                poolStart: historicalPoolStart, poolEnd: first.poolEnd });
            const inventory = inspect(row, [operation(status)]);
            assert.equal(inventory.sources.size, 0);
            assert.deepEqual(inventory.occupied, []);
            assert.deepEqual(inventory.allocations, []);
            const { desired } = makeDesired(targetId, inventory.occupied, [], fixtureKey, inventory);
            assert.equal(desired.clientCidr, first.clientCidr);
            assert.equal(desired.users[0].ipAddress, first.poolStart);
            assert.equal(isDormantClassicState(row), true);
            assert.equal(isPristine(row), false, 'the same retained row is not a fresh Install target');
            assert.equal(row.operationId, pointer, 'inventory did not alter the historical row');
        }
    }
});

test('idle shape is not idle authority: active operations, missing evidence and transitional states block', () => {
    for (const status of ['queued', 'running', 'rolling_back']) {
        assert.equal(isDormantClassicState(classic()), true);
        assert.throws(() => inspect(classic(), [operation(status)]), busy);
        assert.throws(() => inspect(classic(), [operation('succeeded'), operation(status, { _id: oid('f') })]), busy);
    }
    for (const operationId of [pointer, null]) {
        assert.throws(() => inspect(classic({ operationId })), invalid);
        assert.throws(() => inspect(classic({ operationId }), null), invalid);
        assert.deepEqual(inspect(classic({ operationId }), []).occupied, []);
    }
    for (const status of ['queued', 'preflight', 'installing', 'removing', 'drifted', 'error']) {
        const state = classic({ status });
        assert.equal(isDormantClassicState(state), false);
        assert.throws(() => inspect(state, []), busy);
    }
    assert.throws(() => inspect(classic({ desiredState: 'installed' }), []), busy);
    assert.throws(() => inspect(classic({ status: 'installed' }), []), invalid);
});

test('malformed states, operation identities/statuses, and classic replica rows are not silently skipped', () => {
    const fakeId = { toString: () => String(pointer) };
    for (const patch of [{ status: 'unknown' }, { desiredState: undefined }, { routingMode: 'other' },
        { routingVersion: 1 }, { node: fakeId }, { _id: null }, { operationId: fakeId }, { operationId: '' }, { routeGroup: false }]) {
        assert.equal(isDormantClassicState(classic(patch)), false);
        assert.throws(() => inspect(classic(patch), []), invalid);
    }
    for (const evidence of [[operation('done')], [operation(['failed'])], [operation(undefined)],
        [operation('succeeded', { _id: fakeId })], [operation('succeeded', { _id: String(pointer) })],
        [operation('succeeded', { node: sourceId })], [operation('succeeded', { node: String(neighbor) })],
        [operation('succeeded'), operation('succeeded')], [operation('failed', { _id: oid('f') })]]) {
        assert.throws(() => inspect(classic(), evidence), invalid);
    }
    assert.throws(() => inspect(classic(), [], [{ relayNode: neighbor }]), invalid);
    assert.throws(() => inspect(classic({ node: new ObjectId(targetId) }), []), invalid);
    assert.deepEqual(inspect(classic({ node: String(neighbor), operationId: String(pointer) }),
        [operation('succeeded', { node: String(neighbor), _id: String(pointer) })]).occupied, []);
});

const owned = (overrides = {}) => ({ ...classic({ _id: oid('3'), node: sourceId, routeGroup: null,
    operationId: null, activePathKey: '', clientCidr: '10.77.0.0/24', localAddress: '10.77.0.1',
    poolStart: '10.77.0.10', poolEnd: '10.77.0.250' }), routingMode: 'follow-relay', routingVersion: 1,
    desiredState: 'installed', status: 'installed', rebuildMachineId: '4'.repeat(32),
    rebuildInstallToken: '550e8400-e29b-41d4-a716-446655440000', backupId: '5'.repeat(32), installedAt: new Date(0), ...overrides });
const bootstrap = { _id: oid('6'), relayNode: sourceId, login: 'relay-bootstrap', ip: '10.77.0.10', enabled: true,
    passwordEncrypted: 'expected-envelope', syncStatus: 'synced', desiredRevision: 1, appliedRevision: 1 };

test('existing Rebuild ownership, replica and fence predicates still apply', () => {
    const state = owned();
    const inventory = inspect([classic(), state], [operation('failed')], [bootstrap]);
    assert.deepEqual(inventory.occupied, [state]);
    assert.deepEqual(inventory.allocations, [state.localAddress, bootstrap.ip]);
    assert.deepEqual(inventory.legacy, [{ id: String(bootstrap._id), login: bootstrap.login, enabled: true,
        passwordEncrypted: bootstrap.passwordEncrypted }]);
    for (const patch of [{ rebuildMachineId: '4'.repeat(32) }, { rebuildInstallToken: state.rebuildInstallToken },
        { routingMode: 'follow-relay', routingVersion: 1 }, { replacementFence: 1 }, { pppDriftQueueFence: 1 }]) {
        assert.equal(isDormantClassicState(classic(patch)), false);
        assert.throws(() => inspect(classic(patch), []));
    }
    for (const patch of [{ replacementFence: 1 }, { pppDriftQueueFence: 1 }, { operationId: pointer }]) {
        assert.throws(() => inspect(owned(patch), [], [bootstrap]), invalid);
    }
    assert.throws(() => inspect(state, [], [{ ...bootstrap, syncStatus: 'pending' }]), busy);
    assert.throws(() => inspect(state, [], []), invalid);
});

// Model only the collection boundary. Keep persisted string and BSON equality
// distinct and apply the emitted scope, result limit and inclusion projection.
function matches(row, query) {
    return Object.entries(query).every(([key, filter]) => {
        if (key === '$or') return filter.some(part => matches(row, part));
        if (key === '$expr') {
            const { $in: [field, statuses] } = filter.$not[0];
            assert.equal(field, '$status');
            return !statuses.includes(row.status);
        }
        const values = Array.isArray(row[key]) ? row[key] : [row[key]];
        return filter.$in.some(wanted => values.some(value => wanted instanceof ObjectId
            ? value instanceof ObjectId && wanted.equals(value) : wanted === value));
    });
}

function operationDb(operations, { error, onFind } = {}) {
    return { collection(name) {
        assert.equal(name, 'l2tpoperations');
        return { find(filter, options) {
            onFind?.(filter, options);
            return { async toArray() {
                if (error) throw error;
                return operations.filter(row => matches(row, filter)).slice(0, options.limit)
                    .map(row => Object.fromEntries(Object.entries(row).filter(([key]) => options.projection[key] === 1)));
            } };
        } };
    } };
}

test('authoritative read projects only _id/node/status and detects newer operations despite an idle or absent pointer', async () => {
    const historical = operation('failed');
    const newer = operation('queued', { _id: oid('f') });
    const db = operationDb([newer, { ...historical, plan: 'not projected' }, operation('cancelled', { _id: oid('7') }),
        operation('running', { _id: oid('8'), node: sourceId })], { onFind: (_, options) => {
        assert.equal(options.readPreference, 'primary');
        assert.deepEqual(options.readConcern, { level: 'majority' });
        assert.ok(options.maxTimeMS > 0 && Number.isSafeInteger(options.limit));
    } });
    assert.deepEqual(await readClassicOperations(db, [classic()]), [historical, newer]);
    const noPointer = classic({ operationId: null });
    const evidence = await readClassicOperations(db, [noPointer]);
    assert.deepEqual(evidence, [newer]);
    assert.throws(() => inspect(noPointer, evidence), busy);
    assert.deepEqual(await readClassicOperations(undefined, [owned()]), []);
    const stringState = classic({ node: String(neighbor), operationId: String(pointer) });
    const stringOp = operation('rolled_back', { node: String(neighbor), _id: String(pointer) });
    assert.deepEqual(await readClassicOperations(operationDb([stringOp]), [stringState]), [stringOp]);
});

test('a verified absent operation differs from a failed read and malformed database evidence', async () => {
    const state = classic();
    const noRows = await readClassicOperations(operationDb([]), [state]);
    assert.deepEqual(inspect(state, noRows).occupied, []);
    const error = new Error('modeled read failed');
    await assert.rejects(readClassicOperations(operationDb([], { error }), [state]), err => err === error);
    await assert.rejects(readClassicOperations(operationDb([]), [state], { inTransaction: () => false }), invalid);
    for (const evidence of [operation('failed', { node: sourceId }), operation('failed', { _id: String(pointer) }),
        operation(['failed'], { _id: oid('7') }), operation('running', { _id: oid('7'), node: String(neighbor) })]) {
        await assert.rejects(readClassicOperations(operationDb([evidence]), [state]), invalid);
    }
    const tooMany = Array.from({ length: 4097 }, (_, i) => operation('queued', { _id: new ObjectId(i.toString(16).padStart(24, '0')) }));
    await assert.rejects(readClassicOperations(operationDb(tooMany), [state]), invalid);
});

test('reservation reads operation evidence again in the original snapshot transaction before any write', async () => {
    const calls = [];
    let active = false;
    const session = {
        startTransaction(options) { assert.equal(options.readConcern.level, 'snapshot'); active = true; },
        inTransaction: () => active,
        transaction: { transition: () => assert.fail('no commit attempted') },
        async abortTransaction() { assert.ok(active); active = false; calls.push('abort'); },
        async endSession() { assert.equal(active, false); calls.push('end'); },
    };
    const history = [operation('cancelled')];
    const operationDatabase = operationDb(history, { onFind: (_, options) => {
        calls.push(options.session ? 'txn operations' : 'preview operations');
        if (options.session) {
            assert.equal(options.session, session);
            assert.ok(active);
            assert.equal(Object.hasOwn(options, 'readConcern'), false);
            assert.equal(Object.hasOwn(options, 'readPreference'), false);
        }
    } });
    const db = { startSession: async () => session, collection(name) {
        if (name !== 'c3_rebuild_relay_accounts') return operationDatabase.collection(name);
        return { async findOne(_, options) {
            assert.equal(options.session, active ? session : undefined);
            return null;
        } };
    } };
    const query = rows => ({ select() { return this; }, read() { assert.equal(active, false); return this; },
        readConcern() { return this; }, session(s) { assert.equal(s, session); assert.ok(active); return this; },
        async lean() { return [...rows]; } });
    const unexpectedWrite = () => assert.fail('no reservation or replica writes on evidence drift');
    const State = { db, find: () => query([classic()]), updateMany: unexpectedWrite };
    const User = { db, find: () => query([]), updateMany: unexpectedWrite };
    const store = createStore(State, User, true);
    const sourceSnapshot = await store.sourceRows(targetId);
    assert.deepEqual(sourceSnapshot.classicOperations, history);
    history.push(operation('running', { _id: oid('f') }));
    await assert.rejects(store.reserve({ nodeId: targetId, machineId: '4'.repeat(32), backupId: '5'.repeat(32),
        state: {}, accounts: [bootstrap], sourceSnapshot }, unexpectedWrite), { code: 'REBUILD_L2TP_RESERVATION_CHANGED' });
    assert.deepEqual(calls, ['preview operations', 'txn operations', 'abort', 'end']);
});
