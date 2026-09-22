'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    EXECUTION_USER_SELECT,
    L2tpUserExecutionRepository,
} = require('../repositories/l2tpUserExecutionRepository');
const {
    L2tpUserResolver,
} = require('../services/l2tpUserResolver');

test('loads only enabled users for the claimed relay with the explicit secret projection', async () => {
    const calls = [];
    const rows = [{
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        desiredRevision: 3,
        passwordEncrypted: 'sealed-alice-password',
        enabled: true,
        comment: 'must not be projected',
    }];
    const model = {
        find(filter) {
            calls.push({ method: 'find', filter });
            return {
                select(projection) {
                    calls.push({ method: 'select', projection });
                    return this;
                },
                sort(order) {
                    calls.push({ method: 'sort', order });
                    return this;
                },
                lean() {
                    calls.push({ method: 'lean' });
                    return Promise.resolve(rows);
                },
            };
        },
    };
    const decryptCalls = [];
    const resolver = new L2tpUserResolver({
        repository: new L2tpUserExecutionRepository({ model }),
        secretBox: {
            decrypt(envelope, key) {
                decryptCalls.push({ envelope, key });
                return 'alice-password';
            },
        },
        secretKey: 'worker-secret-key',
    });

    const users = await resolver.resolve({
        operationId: 'operation-1',
        kind: 'install',
        nodeId: 'relay-1',
        credentialRevision: 9,
    });

    assert.deepEqual(calls, [
        { method: 'find', filter: { relayNode: 'relay-1', enabled: true } },
        { method: 'select', projection: EXECUTION_USER_SELECT },
        { method: 'sort', order: { login: 1, _id: 1 } },
        { method: 'lean' },
    ]);
    assert.match(EXECUTION_USER_SELECT, /(?:^|\s)\+passwordEncrypted(?:\s|$)/);
    assert.doesNotMatch(EXECUTION_USER_SELECT, /comment|createdBy|updatedBy|lastError/);
    assert.deepEqual(decryptCalls, [{
        envelope: 'sealed-alice-password',
        key: 'worker-secret-key',
    }]);
    assert.deepEqual(users, [{
        login: 'alice',
        password: 'alice-password',
        ip: '10.77.0.10',
    }]);
    assert.deepEqual(Object.keys(users[0]), ['login', 'password', 'ip']);
});

test('repository filtering excludes disabled and other-relay rows before decryption', async () => {
    const allRows = [
        {
            relayNode: 'relay-1',
            login: 'active',
            ip: '10.77.0.10',
            desiredRevision: 1,
            passwordEncrypted: 'sealed-active',
            enabled: true,
        },
        {
            relayNode: 'relay-1',
            login: 'disabled',
            ip: '10.77.0.11',
            desiredRevision: 1,
            passwordEncrypted: 'sealed-disabled',
            enabled: false,
        },
        {
            relayNode: 'relay-2',
            login: 'other-relay',
            ip: '10.88.0.10',
            desiredRevision: 1,
            passwordEncrypted: 'sealed-other-relay',
            enabled: true,
        },
    ];
    const model = {
        find(filter) {
            const result = allRows.filter(row => (
                row.relayNode === filter.relayNode && row.enabled === filter.enabled
            ));
            return {
                select() { return this; },
                sort() { return this; },
                lean: async () => result,
            };
        },
    };
    const decrypted = [];
    const resolver = new L2tpUserResolver({
        repository: new L2tpUserExecutionRepository({ model }),
        secretBox: {
            decrypt(envelope) {
                decrypted.push(envelope);
                return 'active-password';
            },
        },
        secretKey: 'worker-secret-key',
    });

    const users = await resolver.resolve({
        kind: 'install',
        nodeId: 'relay-1',
        credentialRevision: 1,
    });

    assert.deepEqual(users, [{
        login: 'active',
        password: 'active-password',
        ip: '10.77.0.10',
    }]);
    assert.deepEqual(decrypted, ['sealed-active']);
});

test('fails closed when an enabled user password cannot be decrypted', async () => {
    const resolver = new L2tpUserResolver({
        repository: {
            async findEnabledByRelayNode() {
                return [{
                    relayNode: 'relay-1',
                    login: 'alice',
                    ip: '10.77.0.10',
                    enabled: true,
                    desiredRevision: 1,
                    passwordEncrypted: 'damaged-envelope',
                }];
            },
        },
        secretBox: {
            decrypt() {
                throw new Error('ciphertext and key details must not escape');
            },
        },
        secretKey: 'worker-secret-key',
    });

    await assert.rejects(
        resolver.resolve({ kind: 'install', nodeId: 'relay-1', credentialRevision: 1 }),
        error => {
            assert.equal(error.name, 'L2tpUserResolutionError');
            assert.equal(error.code, 'L2TP_USER_DECRYPTION_FAILED');
            assert.doesNotMatch(error.message, /ciphertext|key|damaged-envelope/);
            return true;
        },
    );
});

test('rejects invalid operation revisions and invalid enabled user identities before use', async () => {
    const validRow = {
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        desiredRevision: 1,
        passwordEncrypted: 'sealed-password',
    };
    const invalidRows = [
        { ...validRow, relayNode: 'relay-2' },
        { ...validRow, login: 'bad login' },
        { ...validRow, ip: '10.077.0.10' },
        { ...validRow, enabled: false },
        { ...validRow, desiredRevision: 0 },
        { ...validRow, desiredRevision: 1.5 },
        { ...validRow, passwordEncrypted: '' },
    ];

    for (const row of invalidRows) {
        let decryptions = 0;
        const resolver = new L2tpUserResolver({
            repository: { async findEnabledByRelayNode() { return [row]; } },
            secretBox: {
                decrypt() {
                    decryptions += 1;
                    return 'password';
                },
            },
            secretKey: 'worker-secret-key',
        });
        await assert.rejects(
            resolver.resolve({ kind: 'install', nodeId: 'relay-1', credentialRevision: 1 }),
            error => error?.code === 'INVALID_L2TP_USER',
        );
        assert.equal(decryptions, 0);
    }

    const resolver = new L2tpUserResolver({
        repository: { async findEnabledByRelayNode() { return []; } },
        secretBox: { decrypt() { return 'password'; } },
        secretKey: 'worker-secret-key',
    });
    for (const credentialRevision of [undefined, 0, -1, 1.5, '1']) {
        await assert.rejects(
            resolver.resolve({ kind: 'install', nodeId: 'relay-1', credentialRevision }),
            error => error?.code === 'CREDENTIAL_REVISION_MISMATCH',
        );
    }
});

test('resolves a revision-fenced sync snapshot including disabled users only after claim', async () => {
    const decryptions = [];
    const resolver = new L2tpUserResolver({
        repository: {
            async findEnabledByRelayNode() {
                throw new Error('install-only query must not run for sync_users');
            },
            async findByRelayNode(nodeId) {
                assert.equal(nodeId, 'relay-1');
                return [
                    {
                        _id: 'user-active', relayNode: 'relay-1', login: 'alice', ip: '10.77.0.10',
                        enabled: true, desiredRevision: 8, passwordEncrypted: 'sealed-active',
                    },
                    {
                        _id: 'user-disabled', relayNode: 'relay-1', login: 'disabled', ip: '10.77.0.11',
                        enabled: false, desiredRevision: 9, passwordEncrypted: 'sealed-disabled',
                    },
                ];
            },
        },
        secretBox: {
            decrypt(envelope) {
                decryptions.push(envelope);
                return envelope === 'sealed-active' ? 'active-password' : 'disabled-password';
            },
        },
        secretKey: 'worker-secret-key',
    });

    const snapshot = await resolver.resolveSyncSnapshot({
        kind: 'sync_users', nodeId: 'relay-1', credentialRevision: 9,
    });

    assert.deepEqual(snapshot, {
        credentialRevision: 9,
        users: [
            {
                id: 'user-active', relayNode: 'relay-1', login: 'alice', password: 'active-password',
                ip: '10.77.0.10', enabled: true, desiredRevision: 8,
            },
            {
                id: 'user-disabled', relayNode: 'relay-1', login: 'disabled', password: 'disabled-password',
                ip: '10.77.0.11', enabled: false, desiredRevision: 9,
            },
        ],
    });
    assert.deepEqual(decryptions, ['sealed-active', 'sealed-disabled']);
});
