'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpUserManagementService,
} = require('../services/l2tpUserManagementService');

function createRepository(overrides = {}) {
    return {
        async findRelayNodeById(nodeId) {
            return { _id: nodeId, cascadeRole: 'relay' };
        },
        async findConflict() {
            return null;
        },
        async reserveCredentialRevision() {
            return 7;
        },
        async createUser(fields) {
            return {
                _id: 'user-1',
                ...fields,
                appliedRevision: 0,
                syncStatus: 'pending',
                password: 'must-not-escape',
            };
        },
        ...overrides,
    };
}

test('creates a validated user with an encrypted password and returns only safe fields', async () => {
    const calls = [];
    const repository = createRepository({
        async findConflict(relayNode, identity) {
            calls.push({ method: 'findConflict', relayNode, identity });
            return null;
        },
        async reserveCredentialRevision(relayNode) {
            calls.push({ method: 'reserveCredentialRevision', relayNode });
            return 7;
        },
        async createUser(fields) {
            calls.push({ method: 'createUser', fields });
            return {
                _id: 'user-1',
                ...fields,
                appliedRevision: 0,
                syncStatus: 'pending',
                password: 'must-not-escape',
                rawCommand: 'must-not-escape',
            };
        },
    });
    const service = new L2tpUserManagementService({
        repository,
        secretBox: {
            encrypt(plaintext, key) {
                calls.push({ method: 'encrypt', plaintext, key });
                return 'sealed-password';
            },
        },
        secretKey: 'test-secret-key',
    });

    const user = await service.createUser('relay-1', {
        login: 'alice',
        ip: '10.77.0.10',
        password: 'test-account-password',
        enabled: true,
    });

    assert.deepEqual(calls, [
        {
            method: 'findConflict',
            relayNode: 'relay-1',
            identity: { login: 'alice', ip: '10.77.0.10' },
        },
        {
            method: 'encrypt',
            plaintext: 'test-account-password',
            key: 'test-secret-key',
        },
        { method: 'reserveCredentialRevision', relayNode: 'relay-1' },
        {
            method: 'createUser',
            fields: {
                relayNode: 'relay-1',
                login: 'alice',
                ip: '10.77.0.10',
                enabled: true,
                passwordEncrypted: 'sealed-password',
                desiredRevision: 7,
            },
        },
    ]);
    assert.deepEqual(user, {
        id: 'user-1',
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        desiredRevision: 7,
        appliedRevision: 0,
        syncStatus: 'pending',
    });
    assert.doesNotMatch(JSON.stringify(user), /test-account-password|sealed-password|password|rawCommand/);
});

test('rejects unknown fields and invalid login, IP, password, or enabled values before writes', async () => {
    const writes = [];
    const repository = createRepository({
        async reserveCredentialRevision() {
            writes.push('reserve');
            return 1;
        },
        async createUser() {
            writes.push('create');
        },
    });
    const service = new L2tpUserManagementService({
        repository,
        secretBox: {
            encrypt() {
                writes.push('encrypt');
                return 'sealed';
            },
        },
        secretKey: 'test-secret-key',
    });
    const valid = {
        login: 'alice',
        ip: '10.77.0.10',
        password: 'test-account-password',
        enabled: true,
    };
    const cases = [
        [{ ...valid, command: 'rm -rf /' }, 'INVALID_L2TP_USER'],
        [{ ...valid, login: 'bad login' }, 'INVALID_L2TP_LOGIN'],
        [{ ...valid, login: 'a'.repeat(65) }, 'INVALID_L2TP_LOGIN'],
        [{ ...valid, ip: '10.077.0.10' }, 'INVALID_L2TP_IP'],
        [{ ...valid, ip: '2001:db8::1' }, 'INVALID_L2TP_IP'],
        [{ ...valid, password: '' }, 'INVALID_L2TP_PASSWORD'],
        [{ ...valid, password: 'line\nbreak' }, 'INVALID_L2TP_PASSWORD'],
        [{ ...valid, password: 'x'.repeat(1025) }, 'INVALID_L2TP_PASSWORD'],
        [{ ...valid, enabled: 'true' }, 'INVALID_L2TP_ENABLED'],
    ];

    for (const [input, expectedCode] of cases) {
        await assert.rejects(
            service.createUser('relay-1', input),
            error => error?.code === expectedCode,
            expectedCode,
        );
    }
    assert.deepEqual(writes, []);
});

test('rejects duplicate login or IP without encrypting and translates duplicate-key races safely', async () => {
    let encryptions = 0;
    const duplicateService = new L2tpUserManagementService({
        repository: createRepository({
            async findConflict() { return { _id: 'existing-user' }; },
        }),
        secretBox: {
            encrypt() {
                encryptions += 1;
                return 'sealed';
            },
        },
        secretKey: 'test-secret-key',
    });
    const input = {
        login: 'alice',
        ip: '10.77.0.10',
        password: 'test-account-password',
        enabled: true,
    };

    await assert.rejects(
        duplicateService.createUser('relay-1', input),
        error => {
            assert.equal(error.code, 'L2TP_USER_CONFLICT');
            assert.doesNotMatch(error.message, /existing-user|alice|10\.77\.0\.10/);
            return true;
        },
    );
    assert.equal(encryptions, 0);

    const raceService = new L2tpUserManagementService({
        repository: createRepository({
            async createUser() {
                throw Object.assign(new Error('E11000 keyValue passwordEncrypted=sealed'), {
                    code: 11000,
                });
            },
        }),
        secretBox: { encrypt: () => 'sealed' },
        secretKey: 'test-secret-key',
    });
    await assert.rejects(
        raceService.createUser('relay-1', input),
        error => {
            assert.equal(error.code, 'L2TP_USER_CONFLICT');
            assert.doesNotMatch(error.message, /E11000|keyValue|sealed/);
            return true;
        },
    );
});

test('lists enabled and disabled users without returning credentials or arbitrary repository fields', async () => {
    const service = new L2tpUserManagementService({
        repository: createRepository({
            async listByRelay(relayNode) {
                assert.equal(relayNode, 'relay-1');
                return [
                    {
                        _id: 'user-1',
                        relayNode,
                        login: 'active',
                        ip: '10.77.0.10',
                        enabled: true,
                        desiredRevision: 2,
                        appliedRevision: 2,
                        syncStatus: 'synced',
                        passwordEncrypted: 'sealed-active',
                    },
                    {
                        _id: 'user-2',
                        relayNode,
                        login: 'disabled',
                        ip: '10.77.0.11',
                        enabled: false,
                        desiredRevision: 3,
                        appliedRevision: 2,
                        syncStatus: 'pending',
                        password: 'raw-disabled',
                    },
                ];
            },
        }),
        secretBox: { encrypt: () => 'unused' },
        secretKey: 'test-secret-key',
    });

    const users = await service.listUsers('relay-1');

    assert.deepEqual(users, [
        {
            id: 'user-1',
            relayNode: 'relay-1',
            login: 'active',
            ip: '10.77.0.10',
            enabled: true,
            desiredRevision: 2,
            appliedRevision: 2,
            syncStatus: 'synced',
        },
        {
            id: 'user-2',
            relayNode: 'relay-1',
            login: 'disabled',
            ip: '10.77.0.11',
            enabled: false,
            desiredRevision: 3,
            appliedRevision: 2,
            syncStatus: 'pending',
        },
    ]);
    assert.doesNotMatch(JSON.stringify(users), /sealed-active|raw-disabled|password/i);
});

test('updates allowlisted fields, encrypts a replacement password, and advances desired revision', async () => {
    const calls = [];
    const existing = {
        _id: 'user-1',
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        desiredRevision: 4,
        appliedRevision: 4,
        syncStatus: 'synced',
    };
    const service = new L2tpUserManagementService({
        repository: createRepository({
            async findByRelayAndId(relayNode, userId) {
                calls.push({ method: 'findByRelayAndId', relayNode, userId });
                return existing;
            },
            async findConflict(relayNode, identity, excludeUserId) {
                calls.push({ method: 'findConflict', relayNode, identity, excludeUserId });
                return null;
            },
            async reserveCredentialRevision(relayNode) {
                calls.push({ method: 'reserveCredentialRevision', relayNode });
                return 8;
            },
            async updateUser(relayNode, userId, fields) {
                calls.push({ method: 'updateUser', relayNode, userId, fields });
                return {
                    ...existing,
                    ...fields,
                    passwordEncrypted: 'sealed-replacement',
                    rawCommand: 'must-not-escape',
                };
            },
        }),
        secretBox: {
            encrypt(plaintext, key) {
                calls.push({ method: 'encrypt', plaintext, key });
                return 'sealed-replacement';
            },
        },
        secretKey: 'test-secret-key',
    });

    const user = await service.updateUser('relay-1', 'user-1', {
        ip: '10.77.0.20',
        password: 'replacement-password',
        enabled: false,
    });

    assert.deepEqual(calls, [
        { method: 'findByRelayAndId', relayNode: 'relay-1', userId: 'user-1' },
        {
            method: 'findConflict',
            relayNode: 'relay-1',
            identity: { login: 'alice', ip: '10.77.0.20' },
            excludeUserId: 'user-1',
        },
        { method: 'encrypt', plaintext: 'replacement-password', key: 'test-secret-key' },
        { method: 'reserveCredentialRevision', relayNode: 'relay-1' },
        {
            method: 'updateUser',
            relayNode: 'relay-1',
            userId: 'user-1',
            fields: {
                ip: '10.77.0.20',
                enabled: false,
                passwordEncrypted: 'sealed-replacement',
                desiredRevision: 8,
            },
        },
    ]);
    assert.deepEqual(user, {
        id: 'user-1',
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.20',
        enabled: false,
        desiredRevision: 8,
        appliedRevision: 4,
        syncStatus: 'synced',
    });
    assert.doesNotMatch(JSON.stringify(user), /replacement-password|sealed-replacement|rawCommand/);
});

test('disable is idempotent for an already disabled user and performs no credential write', async () => {
    const writes = [];
    const disabled = {
        _id: 'user-2',
        relayNode: 'relay-1',
        login: 'disabled',
        ip: '10.77.0.11',
        enabled: false,
        desiredRevision: 3,
        appliedRevision: 2,
        syncStatus: 'pending',
    };
    const service = new L2tpUserManagementService({
        repository: createRepository({
            async findByRelayAndId() { return disabled; },
            async reserveCredentialRevision() {
                writes.push('reserve');
                return 4;
            },
            async updateUser() {
                writes.push('update');
            },
        }),
        secretBox: { encrypt: () => 'unused' },
        secretKey: 'test-secret-key',
    });

    const user = await service.disableUser('relay-1', 'user-2');

    assert.equal(user.enabled, false);
    assert.equal(user.desiredRevision, 3);
    assert.deepEqual(writes, []);
});
