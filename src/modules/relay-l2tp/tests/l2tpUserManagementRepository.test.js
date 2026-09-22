'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpUserManagementRepository,
    SAFE_USER_SELECT,
} = require('../repositories/l2tpUserManagementRepository');
const L2tpOperation = require('../models/l2tpOperationModel');

const RELAY_ID = '507f1f77bcf86cd799439011';

function queryResult(result, calls, kind) {
    return {
        select(fields) {
            calls.push({ method: `${kind}.select`, fields });
            return this;
        },
        sort(order) {
            calls.push({ method: `${kind}.sort`, order });
            return this;
        },
        lean() {
            calls.push({ method: `${kind}.lean` });
            return Promise.resolve(result);
        },
    };
}

function createModels(overrides = {}) {
    const calls = [];
    const HyNode = {
        findById(nodeId) {
            calls.push({ method: 'HyNode.findById', nodeId });
            return queryResult({ _id: nodeId, cascadeRole: 'relay' }, calls, 'HyNode');
        },
    };
    const RelayL2tpState = {
        findOneAndUpdate(filter, update, options) {
            calls.push({ method: 'RelayL2tpState.findOneAndUpdate', filter, update, options });
            return queryResult({ secretRevision: 7 }, calls, 'RelayL2tpState');
        },
    };
    const L2tpUser = {
        find(filter) {
            calls.push({ method: 'L2tpUser.find', filter });
            return queryResult([], calls, 'L2tpUser.find');
        },
        findOne(filter) {
            calls.push({ method: 'L2tpUser.findOne', filter });
            return queryResult(null, calls, 'L2tpUser.findOne');
        },
        findOneAndUpdate(filter, update, options) {
            calls.push({ method: 'L2tpUser.findOneAndUpdate', filter, update, options });
            return queryResult(null, calls, 'L2tpUser.findOneAndUpdate');
        },
        async create(fields) {
            calls.push({ method: 'L2tpUser.create', fields });
            return { _id: 'user-1', ...fields };
        },
    };
    return {
        calls,
        HyNode: overrides.HyNode ?? HyNode,
        RelayL2tpState: overrides.RelayL2tpState ?? RelayL2tpState,
        L2tpUser: overrides.L2tpUser ?? L2tpUser,
    };
}

function createModelBackedOperationStore(calls, persistedPlans) {
    return {
        async create(documents, options) {
            calls.push({ method: 'L2tpOperation.create', documents, options });
            const operations = documents.map(document => new L2tpOperation(document));
            for (const operation of operations) await operation.validate();
            persistedPlans.push(...operations.map(operation => operation.plan.toObject()));
            return operations;
        },
    };
}

test('lists users with an explicit safe projection and deterministic order', async () => {
    const models = createModels();
    const rows = [{
        _id: 'user-1',
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: false,
        passwordEncrypted: 'must-not-be-projected',
    }];
    models.L2tpUser.find = filter => {
        models.calls.push({ method: 'L2tpUser.find', filter });
        return queryResult(rows, models.calls, 'L2tpUser.find');
    };
    const repository = new L2tpUserManagementRepository(models);

    const users = await repository.listByRelay('relay-1');

    assert.deepEqual(users, rows);
    assert.deepEqual(models.calls, [
        { method: 'L2tpUser.find', filter: { relayNode: 'relay-1' } },
        { method: 'L2tpUser.find.select', fields: SAFE_USER_SELECT },
        { method: 'L2tpUser.find.sort', order: { login: 1, _id: 1 } },
        { method: 'L2tpUser.find.lean' },
    ]);
    assert.doesNotMatch(SAFE_USER_SELECT, /password|cipher|secret/i);
    assert.equal(SAFE_USER_SELECT.split(/\s+/).includes('syncOperationId'), true);
});

test('detects duplicate login or IP within one relay while excluding the updated user', async () => {
    const models = createModels();
    const repository = new L2tpUserManagementRepository(models);

    await repository.findConflict(
        'relay-1',
        { login: 'alice', ip: '10.77.0.10' },
        'user-1',
    );

    assert.deepEqual(models.calls, [
        {
            method: 'L2tpUser.findOne',
            filter: {
                relayNode: 'relay-1',
                _id: { $ne: 'user-1' },
                $or: [{ login: 'alice' }, { ip: '10.77.0.10' }],
            },
        },
        { method: 'L2tpUser.findOne.select', fields: '_id' },
        { method: 'L2tpUser.findOne.lean' },
    ]);
});

test('reserves one relay credential revision without upserting unconfigured state', async () => {
    const models = createModels();
    const repository = new L2tpUserManagementRepository(models);

    const revision = await repository.reserveCredentialRevision('relay-1');

    assert.equal(revision, 7);
    assert.deepEqual(models.calls, [
        {
            method: 'RelayL2tpState.findOneAndUpdate',
            filter: { node: 'relay-1' },
            update: { $inc: { secretRevision: 1 } },
            options: { new: true, runValidators: true },
        },
        { method: 'RelayL2tpState.select', fields: 'secretRevision' },
        { method: 'RelayL2tpState.lean' },
    ]);
});

test('create, update, and disable queues persist the exact model-valid sync plan', async t => {
    const scenarios = [
        {
            name: 'create',
            operationId: '507f1f77bcf86cd799439012',
            run(repository) {
                return repository.createUserAndQueueSync({
                    relayNode: RELAY_ID,
                    login: 'alice',
                    ip: '10.77.0.10',
                    enabled: true,
                    passwordEncrypted: 'sealed-create-password',
                });
            },
        },
        {
            name: 'update',
            operationId: '507f1f77bcf86cd799439013',
            run(repository) {
                return repository.updateUserAndQueueSync(
                    RELAY_ID,
                    'user-1',
                    6,
                    { ip: '10.77.0.20', passwordEncrypted: 'sealed-update-password' },
                );
            },
        },
        {
            name: 'disable',
            operationId: '507f1f77bcf86cd799439014',
            run(repository) {
                return repository.updateUserAndQueueSync(
                    RELAY_ID,
                    'user-1',
                    6,
                    { enabled: false },
                );
            },
        },
    ];

    for (const scenario of scenarios) {
        await t.test(scenario.name, async () => {
            const models = createModels();
            const session = { id: `${scenario.name}-transaction` };
            const persistedPlans = [];
            models.L2tpUser.create = async documents => [{ _id: 'user-1', ...documents[0] }];
            models.L2tpUser.findOneAndUpdate = (filter, update, options) => queryResult({
                _id: 'user-1',
                relayNode: RELAY_ID,
                login: 'alice',
                ip: update.$set.ip ?? '10.77.0.10',
                enabled: update.$set.enabled ?? true,
                desiredRevision: 7,
                appliedRevision: 6,
                syncStatus: 'pending',
            }, models.calls, 'L2tpUser.findOneAndUpdate');
            const repository = new L2tpUserManagementRepository({
                ...models,
                L2tpOperation: createModelBackedOperationStore(models.calls, persistedPlans),
                operationIdFactory: () => scenario.operationId,
                transactionRunner: work => work(session),
            });

            await scenario.run(repository);

            assert.deepEqual(persistedPlans, [{
                ok: true,
                operationId: scenario.operationId,
                relayId: RELAY_ID,
                desired: { credentialRevision: 7 },
                steps: [
                    { type: 'backup' },
                    {
                        type: 'sync_users',
                        artifacts: [{ type: 'desired', path: 'desired.json' }],
                    },
                    { type: 'verify_users' },
                ],
            }]);
            assert.doesNotMatch(
                JSON.stringify(persistedPlans),
                /sealed|password|ciphertext|plaintext|secret/i,
            );
        });
    }
});

test('creates only internal allowlisted fields and never returns password ciphertext', async () => {
    const models = createModels();
    const repository = new L2tpUserManagementRepository(models);

    const user = await repository.createUser({
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        passwordEncrypted: 'sealed-password',
        desiredRevision: 7,
        rawCommand: 'must-not-be-written',
    });

    assert.deepEqual(models.calls, [{
        method: 'L2tpUser.create',
        fields: {
            relayNode: 'relay-1',
            login: 'alice',
            ip: '10.77.0.10',
            enabled: true,
            passwordEncrypted: 'sealed-password',
            desiredRevision: 7,
            appliedRevision: 0,
            syncStatus: 'pending',
            lastErrorCode: '',
            lastError: '',
        },
    }]);
    assert.deepEqual(user, {
        _id: 'user-1',
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        desiredRevision: 7,
        appliedRevision: 0,
        syncStatus: 'pending',
        lastErrorCode: '',
    });
    assert.doesNotMatch(JSON.stringify(user), /sealed-password|password|rawCommand/);
});

test('updates one relay-owned user, resets sync state, and returns the safe projection', async () => {
    const models = createModels();
    const updated = {
        _id: 'user-1',
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.20',
        enabled: false,
        desiredRevision: 8,
        appliedRevision: 7,
        syncStatus: 'pending',
    };
    models.L2tpUser.findOneAndUpdate = (filter, update, options) => {
        models.calls.push({ method: 'L2tpUser.findOneAndUpdate', filter, update, options });
        return queryResult(updated, models.calls, 'L2tpUser.findOneAndUpdate');
    };
    const repository = new L2tpUserManagementRepository(models);

    const user = await repository.updateUser('relay-1', 'user-1', {
        ip: '10.77.0.20',
        enabled: false,
        passwordEncrypted: 'sealed-replacement',
        desiredRevision: 8,
        rawCommand: 'must-not-be-written',
    });

    assert.deepEqual(models.calls, [
        {
            method: 'L2tpUser.findOneAndUpdate',
            filter: { relayNode: 'relay-1', _id: 'user-1' },
            update: {
                $set: {
                    ip: '10.77.0.20',
                    enabled: false,
                    passwordEncrypted: 'sealed-replacement',
                    desiredRevision: 8,
                    syncStatus: 'pending',
                    syncOperationId: null,
                    lastErrorCode: '',
                    lastError: '',
                },
            },
            options: { new: true, runValidators: true },
        },
        { method: 'L2tpUser.findOneAndUpdate.select', fields: SAFE_USER_SELECT },
        { method: 'L2tpUser.findOneAndUpdate.lean' },
    ]);
    assert.strictEqual(user, updated);
    assert.doesNotMatch(SAFE_USER_SELECT, /password|cipher|secret/i);
});

test('creates a user and its revision-keyed sync operation in one transaction', async () => {
    const models = createModels();
    const session = { id: 'transaction-session' };
    models.L2tpUser.create = async (documents, options) => {
        models.calls.push({ method: 'L2tpUser.create', documents, options });
        return [{ _id: 'user-1', ...documents[0] }];
    };
    const L2tpOperation = {
        async create(documents, options) {
            models.calls.push({ method: 'L2tpOperation.create', documents, options });
            return documents;
        },
    };
    const repository = new L2tpUserManagementRepository({
        ...models,
        L2tpOperation,
        operationIdFactory: () => 'sync-operation-7',
        transactionRunner: async work => {
            models.calls.push({ method: 'transaction.begin', session });
            const result = await work(session);
            models.calls.push({ method: 'transaction.commit', session });
            return result;
        },
    });

    const result = await repository.createUserAndQueueSync({
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        passwordEncrypted: 'sealed-password',
    });

    assert.equal(result.operationId, 'sync-operation-7');
    assert.equal(result.user.desiredRevision, 7);
    assert.equal(result.user.syncStatus, 'pending');
    assert.doesNotMatch(JSON.stringify(result), /sealed-password|password/i);
    const stateWrite = models.calls.find(call => (
        call.method === 'RelayL2tpState.findOneAndUpdate'
    ));
    assert.equal(stateWrite.options.session, session);
    const userWrite = models.calls.find(call => call.method === 'L2tpUser.create');
    assert.equal(userWrite.options.session, session);
    assert.equal(userWrite.documents[0].desiredRevision, 7);
    const operationWrite = models.calls.find(call => call.method === 'L2tpOperation.create');
    assert.equal(operationWrite.options.session, session);
    assert.deepEqual(operationWrite.documents, [{
        _id: 'sync-operation-7',
        node: 'relay-1',
        kind: 'sync_users',
        status: 'queued',
        idempotencyKey: 'sync-users:relay-1:revision-7',
        progress: 0,
        attempts: 0,
        plan: {
            ok: true,
            operationId: 'sync-operation-7',
            relayId: 'relay-1',
            desired: { credentialRevision: 7 },
            steps: [
                { type: 'backup' },
                {
                    type: 'sync_users',
                    artifacts: [{ type: 'desired', path: 'desired.json' }],
                },
                { type: 'verify_users' },
            ],
        },
    }]);
    assert.doesNotMatch(
        JSON.stringify(operationWrite.documents),
        /sealed-password|passwordEncrypted|"password"/i,
    );
    assert.deepEqual(
        models.calls.filter(call => call.method.startsWith('transaction.')).map(call => call.method),
        ['transaction.begin', 'transaction.commit'],
    );
});

test('updates by desired-revision CAS and queues the next sync in the same transaction', async () => {
    const models = createModels();
    const session = { id: 'transaction-session' };
    models.RelayL2tpState.findOneAndUpdate = (filter, update, options) => {
        models.calls.push({ method: 'RelayL2tpState.findOneAndUpdate', filter, update, options });
        return queryResult({ secretRevision: 8 }, models.calls, 'RelayL2tpState');
    };
    models.L2tpUser.findOneAndUpdate = (filter, update, options) => {
        models.calls.push({ method: 'L2tpUser.findOneAndUpdate', filter, update, options });
        return queryResult({
            _id: 'user-1',
            relayNode: 'relay-1',
            login: 'alice',
            ip: '10.77.0.20',
            enabled: false,
            desiredRevision: 8,
            appliedRevision: 4,
            syncStatus: 'pending',
        }, models.calls, 'L2tpUser.findOneAndUpdate');
    };
    const L2tpOperation = {
        async create(documents, options) {
            models.calls.push({ method: 'L2tpOperation.create', documents, options });
            return documents;
        },
    };
    const repository = new L2tpUserManagementRepository({
        ...models,
        L2tpOperation,
        operationIdFactory: () => 'sync-operation-8',
        transactionRunner: work => work(session),
    });

    const result = await repository.updateUserAndQueueSync(
        'relay-1',
        'user-1',
        4,
        { ip: '10.77.0.20', enabled: false },
    );

    assert.equal(result.operationId, 'sync-operation-8');
    assert.equal(result.user.desiredRevision, 8);
    const userWrite = models.calls.find(call => call.method === 'L2tpUser.findOneAndUpdate');
    assert.deepEqual(userWrite.filter, {
        relayNode: 'relay-1',
        _id: 'user-1',
        desiredRevision: 4,
    });
    assert.deepEqual(userWrite.update, {
        $set: {
            ip: '10.77.0.20',
            enabled: false,
            desiredRevision: 8,
            syncStatus: 'pending',
            lastErrorCode: '',
            lastError: '',
        },
    });
    assert.equal(userWrite.options.session, session);
    const operationWrite = models.calls.find(call => call.method === 'L2tpOperation.create');
    assert.equal(operationWrite.options.session, session);
    assert.equal(operationWrite.documents[0].idempotencyKey, 'sync-users:relay-1:revision-8');
    assert.equal(operationWrite.documents[0].plan.desired.credentialRevision, 8);
});
