'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    EXECUTION_SECRET_SELECT,
    L2tpStateManagementRepository,
    STATE_MANAGEMENT_SAFE_SELECT,
    VERIFIED_STATE_SAFE_SELECT,
} = require('../repositories/l2tpStateManagementRepository');

const TEST_SESSION = { id: 'test-session' };
const TEST_DB = { transaction: async work => work(TEST_SESSION) };
const TEST_CLAIM = Object.freeze({
    owner: 'worker-1', ownerGeneration: 'op-generation-1', lockGeneration: 'lock-generation-1',
});
function operationFence(db = TEST_DB) {
    return { db, updateOne: async () => ({ matchedCount: 1 }) };
}
function nodeFence(db = TEST_DB) {
    return { db, updateOne: async () => ({ matchedCount: 1 }) };
}
function createTopologyModel(result = { stateTransitionRevision: 0 }) {
    return {
        db: TEST_DB,
        findById() {
            return { select() { return this; }, session() { return this; }, lean: async () => result };
        },
        findOneAndUpdate() {
            return { select() { return this; }, lean: async () => ({ stateTransitionRevision: 1 }) };
        },
    };
}

function createQueryModel(result = null) {
    const calls = [];
    const query = () => ({
        select(paths) {
            calls.push({ method: 'select', paths });
            return this;
        },
        lean(options) {
            calls.push({ method: 'lean', options });
            return Promise.resolve(result);
        },
    });

    return {
        db: TEST_DB,
        calls,
        findById(id) {
            calls.push({ method: 'findById', id });
            return query();
        },
        findOne(filter) {
            calls.push({ method: 'findOne', filter });
            return query();
        },
        findOneAndUpdate(filter, update, options) {
            calls.push({ method: 'findOneAndUpdate', filter, update, options });
            return query();
        },
    };
}

test('state transition fences a held replacement on the same singleton without changing topology revision', async () => {
    const session = { id: 'transaction' };
    const calls = [];
    const db = { transaction: async work => work(session) };
    const RelayL2tpState = {
        db,
        findOneAndUpdate(filter, update, options) {
            calls.push({ kind: 'state', filter, update, options });
            return { select() { return this; }, lean: async () => ({ node: 'relay-1' }) };
        },
    };
    const CascadeTopologyState = {
        db,
        findById(id) {
            calls.push({ kind: 'snapshot', id });
            return { select() { return this; }, session(actual) {
                assert.equal(actual, session); return this;
            }, lean: async () => ({ stateTransitionRevision: 4, replacementReservation: { ownerToken: 'held' } }) };
        },
        findOneAndUpdate(filter, update, options) {
            calls.push({ kind: 'fence', filter, update, options });
            return { select() { return this; }, lean: async () => ({ stateTransitionRevision: 5 }) };
        },
    };
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(), CascadeRouteGroup: createQueryModel(),
        RelayL2tpState, CascadeTopologyState,
    });
    await assert.rejects(
        repository.configureRelay({ node: 'relay-1', desiredState: 'installed' }),
        { code: 'TOPOLOGY_REPLACEMENT_RESERVED' },
    );
    assert.deepEqual(calls.map(call => call.kind), ['snapshot']);
    assert.equal(calls.some(call => call.kind === 'state' || call.kind === 'fence'), false);
});

test('reservation arriving after state snapshot aborts the state transaction', async () => {
    let persisted = { status: 'not_installed' };
    let reservationAcquired = false;
    const db = { async transaction(work) {
        const before = { ...persisted };
        try { return await work({ id: 'race' }); }
        catch (error) { persisted = before; throw error; }
    } };
    const RelayL2tpState = { db, findOneAndUpdate() {
        persisted = { status: 'installed' };
        return { select() { return this; }, lean: async () => persisted };
    } };
    const CascadeTopologyState = { db,
        findById() { return { select() { return this; }, session() { return this; },
            lean: async () => ({ stateTransitionRevision: 2 }) }; },
        findOneAndUpdate: filter => {
            assert.deepEqual(filter.replacementReservation, { $exists: false });
            reservationAcquired = true;
            return { select() { return this; }, lean: async () => reservationAcquired ? null : {} };
        },
    };
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(), CascadeRouteGroup: createQueryModel(),
        RelayL2tpState, CascadeTopologyState,
        L2tpOperation: operationFence(db), NodeOperationLock: nodeFence(db),
    });
    await assert.rejects(repository.markInstalledAfterVerification({
        node: 'relay-1', operationId: 'operation-17', admissionId: 'admission-1', ...TEST_CLAIM,
        verifiedAt: new Date(),
    }), /topology singleton conflict/);
    assert.deepEqual(persisted, { status: 'not_installed' });
});

test('missing singleton and split connections fail closed before configuration writes', async () => {
    let writes = 0;
    const db = { transaction: async work => work({}) };
    const RelayL2tpState = { db, findOneAndUpdate() { writes++; throw Error('unexpected write'); } };
    const CascadeTopologyState = createTopologyModel(null);
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(), CascadeRouteGroup: createQueryModel(),
        RelayL2tpState, CascadeTopologyState,
    });
    await assert.rejects(repository.configureRelay({ node: 'relay-1' }), /one transactional Mongo connection/);
    CascadeTopologyState.db = db;
    await assert.rejects(repository.configureRelay({ node: 'relay-1' }), /requires a topology singleton/);
    assert.equal(writes, 0);
});

test('legacy singleton lacking counter uses absent-field CAS and marks no-match without a bump', async () => {
    let bumps = 0;
    const db = { transaction: async work => work({}) };
    const RelayL2tpState = { db, findOneAndUpdate() {
        return { select() { return this; }, lean: async () => null };
    } };
    const CascadeTopologyState = { db,
        findById() { return { select() { return this; }, session() { return this; },
            lean: async () => ({ revision: 7 }) }; },
        findOneAndUpdate(filter) { bumps++;
            assert.deepEqual(filter.stateTransitionRevision, { $exists: false });
            assert.deepEqual(filter.replacementReservation, { $exists: false });
            return { select() { return this; }, lean: async () => ({}) }; },
    };
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(), CascadeRouteGroup: createQueryModel(),
        RelayL2tpState, CascadeTopologyState,
    });
    await assert.rejects(repository.markInstalledAfterVerification({ node: 'relay-1' }),
        /operation and node fences/);
    assert.equal(bumps, 0);
    RelayL2tpState.findOneAndUpdate = () => ({ select() { return this; },
        lean: async () => ({ node: 'relay-1' }) });
    assert.deepEqual(await repository.configureRelay({ node: 'relay-1' }), { node: 'relay-1' });
    assert.equal(bumps, 1);
});

test('repository adapter writes an encrypted select:false PSK and returns only safe state', async () => {
    const HyNode = createQueryModel({ _id: 'relay-1', cascadeRole: 'relay' });
    const CascadeRouteGroup = createQueryModel({ _id: 'group-a' });
    const RelayL2tpState = createQueryModel({
        _id: 'state-1',
        node: 'relay-1',
        desiredState: 'installed',
        status: 'not_installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        secretRevision: 1,
        pskEncrypted: 'v1:must-not-be-returned',
        psk: 'raw-must-not-be-returned',
        unknown: 'must-not-be-returned',
    });
    const repository = new L2tpStateManagementRepository({
        HyNode,
        RelayL2tpState,
        CascadeRouteGroup,
        CascadeTopologyState: createTopologyModel(),
    });

    assert.deepEqual(await repository.findNodeById('relay-1'), {
        _id: 'relay-1',
        cascadeRole: 'relay',
    });
    assert.deepEqual(await repository.findRouteGroupById('group-a'), { _id: 'group-a' });

    const result = await repository.configureRelay({
        node: 'relay-1',
        desiredState: 'installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        pskEncrypted: 'v1:encrypted-envelope',
        psk: 'raw-must-not-be-written',
        secretRevision: 999,
        status: 'installed',
        unknown: 'must-not-be-written',
    });

    assert.deepEqual(HyNode.calls, [
        { method: 'findById', id: 'relay-1' },
        { method: 'select', paths: '_id cascadeRole' },
        { method: 'lean', options: undefined },
    ]);
    assert.deepEqual(CascadeRouteGroup.calls, [
        { method: 'findById', id: 'group-a' },
        { method: 'select', paths: '_id' },
        { method: 'lean', options: undefined },
    ]);
    assert.deepEqual(RelayL2tpState.calls, [
        {
            method: 'findOneAndUpdate',
            filter: { node: 'relay-1' },
            update: {
                $set: {
                    node: 'relay-1',
                    desiredState: 'installed',
                    routeGroup: 'group-a',
                    clientCidr: '10.77.0.0/24',
                    localAddress: '10.77.0.1',
                    poolStart: '10.77.0.10',
                    poolEnd: '10.77.0.200',
                    dnsServers: ['1.1.1.1'],
                    tproxyPort: 12345,
                    fwmark: 77,
                    routeTable: 177,
                    routingMode: 'route-group',
                    pskEncrypted: 'v1:encrypted-envelope',
                },
                $inc: { secretRevision: 1 },
                $setOnInsert: { status: 'not_installed' },
            },
            options: {
                new: true,
                runValidators: true,
                setDefaultsOnInsert: false,
                upsert: true,
                session: TEST_SESSION,
            },
        },
        { method: 'select', paths: STATE_MANAGEMENT_SAFE_SELECT },
        { method: 'lean', options: undefined },
    ]);
    assert.deepEqual(result, {
        _id: 'state-1',
        node: 'relay-1',
        desiredState: 'installed',
        status: 'not_installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        secretRevision: 1,
    });
    assert.doesNotMatch(JSON.stringify(result), /psk|must-not-be-returned/i);
});

test('execution lookup selects only matching state identity, revision, and encrypted PSK', async () => {
    const executionState = {
        node: 'relay-1',
        desiredState: 'installed',
        secretRevision: 7,
        pskEncrypted: 'v1:execution-only',
    };
    const RelayL2tpState = createQueryModel(executionState);
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(),
        RelayL2tpState,
        CascadeRouteGroup: createQueryModel(),
        CascadeTopologyState: createTopologyModel(),
    });

    assert.strictEqual(
        await repository.findExecutionStateByNodeId('relay-1'),
        executionState,
    );
    assert.equal(EXECUTION_SECRET_SELECT, 'node desiredState secretRevision +pskEncrypted');
    assert.deepEqual(RelayL2tpState.calls, [
        { method: 'findOne', filter: { node: 'relay-1' } },
        { method: 'select', paths: EXECUTION_SECRET_SELECT },
        { method: 'lean', options: undefined },
    ]);
});

test('verified install rejects a stale operation generation before changing relay state', async () => {
    let stateWrites = 0;
    const L2tpOperation = { db: TEST_DB, updateOne: async () => ({ matchedCount: 0 }) };
    const NodeOperationLock = { db: TEST_DB, updateOne: async () => { throw new Error('lock touched'); } };
    const RelayL2tpState = {
        db: TEST_DB,
        findOneAndUpdate() { stateWrites++; throw new Error('state touched'); },
    };
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(), CascadeRouteGroup: createQueryModel(),
        RelayL2tpState, CascadeTopologyState: createTopologyModel(),
        L2tpOperation, NodeOperationLock,
    });
    await assert.rejects(repository.markInstalledAfterVerification({
        node: 'relay-1', operationId: 'operation-17', admissionId: 'admission-1',
        owner: 'worker-1', ownerGeneration: 'operation-generation-1',
        lockGeneration: 'node-generation-1', credentialRevision: 7,
        topologyRevision: 23, activePathKey: 'primary', verifiedAt: new Date(),
    }), /operation.*fence/i);
    assert.equal(stateWrites, 0);
});

test('verified install rejects an expired node-lock generation before changing relay state', async () => {
    let stateWrites = 0;
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(), CascadeRouteGroup: createQueryModel(),
        RelayL2tpState: { db: TEST_DB, findOneAndUpdate() { stateWrites++; return null; } },
        CascadeTopologyState: createTopologyModel(),
        L2tpOperation: { db: TEST_DB, updateOne: async () => ({ matchedCount: 1 }) },
        NodeOperationLock: { db: TEST_DB, updateOne: async () => ({ matchedCount: 0 }) },
    });
    await assert.rejects(repository.markInstalledAfterVerification({
        node: 'relay-1', operationId: 'operation-17', admissionId: 'admission-1',
        owner: 'worker-1', ownerGeneration: 'operation-generation-1',
        lockGeneration: 'node-generation-1', credentialRevision: 7,
        topologyRevision: 23, activePathKey: 'primary', verifiedAt: new Date(),
    }), /node.*fence/i);
    assert.equal(stateWrites, 0);
});

test('verified install reconciliation atomically fences current desired state and writes safe fields only', async () => {
    const verifiedAt = new Date('2026-09-22T10:00:00.000Z');
    const storedState = {
        node: 'relay-1',
        desiredState: 'installed',
        status: 'installed',
        secretRevision: 7,
        operationId: 'operation-17',
        appliedTopologyRevision: 23,
        activePathKey: 'primary',
        lastVerifiedAt: verifiedAt,
        lastErrorCode: '',
        lastError: '',
        pskEncrypted: 'must-not-be-returned',
        unknown: 'must-not-be-returned',
    };
    const RelayL2tpState = createQueryModel(storedState);
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(),
        RelayL2tpState,
        CascadeRouteGroup: createQueryModel(),
        CascadeTopologyState: createTopologyModel(),
        L2tpOperation: operationFence(), NodeOperationLock: nodeFence(),
    });

    const result = await repository.markInstalledAfterVerification({
        node: 'relay-1',
        operationId: 'operation-17',
        admissionId: 'admission-1',
        ...TEST_CLAIM,
        credentialRevision: 7,
        topologyRevision: 23,
        activePathKey: 'primary',
        verifiedAt,
        status: 'error',
        pskEncrypted: 'must-not-be-written',
        lastError: 'must-not-be-written',
    });

    assert.deepEqual(RelayL2tpState.calls, [
        {
            method: 'findOneAndUpdate',
            filter: {
                node: 'relay-1',
                desiredState: 'installed',
                secretRevision: 7,
            },
            update: {
                $set: {
                    status: 'installed',
                    operationId: 'operation-17',
                    appliedTopologyRevision: 23,
                    activePathKey: 'primary',
                    lastVerifiedAt: verifiedAt,
                    lastErrorCode: '',
                    lastError: '',
                },
            },
            options: {
                new: true,
                runValidators: true,
                session: TEST_SESSION,
            },
        },
        { method: 'select', paths: VERIFIED_STATE_SAFE_SELECT },
        { method: 'lean', options: undefined },
    ]);
    assert.deepEqual(result, {
        node: 'relay-1',
        desiredState: 'installed',
        status: 'installed',
        secretRevision: 7,
        operationId: 'operation-17',
        appliedTopologyRevision: 23,
        activePathKey: 'primary',
        lastVerifiedAt: verifiedAt,
        lastErrorCode: '',
        lastError: '',
    });
    assert.ok(VERIFIED_STATE_SAFE_SELECT.split(/\s+/).every(path => !path.startsWith('-')));
    assert.doesNotMatch(JSON.stringify({ calls: RelayL2tpState.calls, result }), /psk|secret-envelope/i);
});

test('verified install reconciliation preserves a rejected atomic fence as null', async () => {
    const RelayL2tpState = createQueryModel(null);
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(),
        RelayL2tpState,
        CascadeRouteGroup: createQueryModel(),
        CascadeTopologyState: createTopologyModel(),
        L2tpOperation: operationFence(), NodeOperationLock: nodeFence(),
    });

    const result = await repository.markInstalledAfterVerification({
        node: 'relay-1',
        operationId: 'operation-17',
        admissionId: 'admission-1',
        ...TEST_CLAIM,
        credentialRevision: 7,
        topologyRevision: 23,
        activePathKey: 'primary',
        verifiedAt: new Date('2026-09-22T10:00:00.000Z'),
    });

    assert.equal(result, null);
});
