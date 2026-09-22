'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpUserManagementRepository,
    SAFE_USER_SELECT,
} = require('../repositories/l2tpUserManagementRepository');

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
