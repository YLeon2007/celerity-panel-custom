'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpStateManagementService,
} = require('../services/l2tpStateManagementService');

const SECRET_KEY = 'test-envelope-key';
const RAW_PSK = 'correct horse battery staple';

function validInput(overrides = {}) {
    return {
        routeGroupId: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        psk: RAW_PSK,
        ...overrides,
    };
}

test('configureRelay persists only canonical desired fields with an encrypted PSK', async () => {
    const calls = [];
    const repository = {
        async findNodeById(nodeId) {
            calls.push({ method: 'findNodeById', nodeId });
            return { _id: nodeId, cascadeRole: 'relay' };
        },
        async findRouteGroupById(routeGroupId) {
            calls.push({ method: 'findRouteGroupById', routeGroupId });
            return { _id: routeGroupId };
        },
        async configureRelay(fields) {
            calls.push({ method: 'configureRelay', fields });
            return {
                ...fields,
                status: 'not_installed',
                secretRevision: 4,
            };
        },
    };
    const secretBox = {
        encrypt(plaintext, key) {
            calls.push({ method: 'encrypt', plaintext, key });
            return 'v1:encrypted-envelope';
        },
        decrypt() {
            throw new Error('not used');
        },
    };
    const service = new L2tpStateManagementService({
        repository,
        secretBox,
        secretKey: SECRET_KEY,
    });

    const result = await service.configureRelay('relay-1', validInput({
        desiredState: 'absent',
        status: 'installed',
        pskEncrypted: 'attacker-controlled-envelope',
        secretRevision: 999,
        unknown: 'must-not-be-persisted',
    }));

    assert.deepEqual(calls, [
        { method: 'findNodeById', nodeId: 'relay-1' },
        { method: 'findRouteGroupById', routeGroupId: 'group-a' },
        { method: 'encrypt', plaintext: RAW_PSK, key: SECRET_KEY },
        {
            method: 'configureRelay',
            fields: {
                node: 'relay-1',
                desiredState: 'installed',
                routeGroup: 'group-a',
                clientCidr: '10.77.0.0/24',
                localAddress: '10.77.0.1',
                poolStart: '10.77.0.10',
                poolEnd: '10.77.0.200',
                dnsServers: ['1.1.1.1', '9.9.9.9'],
                tproxyPort: 12345,
                fwmark: 77,
                routeTable: 177,
                routingMode: 'route-group',
                pskEncrypted: 'v1:encrypted-envelope',
            },
        },
    ]);
    assert.deepEqual(result, {
        node: 'relay-1',
        desiredState: 'installed',
        status: 'not_installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        secretRevision: 4,
    });
    assert.doesNotMatch(JSON.stringify(result), /correct horse|psk|encrypted-envelope/i);
});

test('configureRelay generates a high-entropy PSK server-side without exposing it', async () => {
    const calls = [];
    const repository = {
        async findNodeById() { return { _id: 'relay-1', cascadeRole: 'relay' }; },
        async findRouteGroupById() { return { _id: 'group-a' }; },
        async configureRelay(fields) {
            calls.push({ method: 'configureRelay', fields });
            return { ...fields, secretRevision: 1 };
        },
    };
    const secretBox = {
        encrypt(plaintext) {
            calls.push({ method: 'encrypt', plaintext });
            return 'generated-envelope';
        },
        decrypt() { throw new Error('not used'); },
    };
    const randomBytes = size => {
        calls.push({ method: 'randomBytes', size });
        return Buffer.alloc(size, 0xab);
    };
    const service = new L2tpStateManagementService({
        repository,
        secretBox,
        secretKey: SECRET_KEY,
        randomBytes,
    });

    const result = await service.configureRelay('relay-1', validInput({
        psk: undefined,
        generatePsk: true,
    }));

    assert.equal(calls[0].method, 'randomBytes');
    assert.equal(calls[0].size, 32);
    assert.equal(calls[1].method, 'encrypt');
    assert.equal(Buffer.from(calls[1].plaintext, 'base64url').byteLength, 32);
    assert.equal(calls[2].method, 'configureRelay');
    assert.equal(calls[2].fields.pskEncrypted, 'generated-envelope');
    assert.doesNotMatch(JSON.stringify(result), /psk|generated-envelope|q6urq6/i);
});

test('configureRelay reusePsk keeps the stored PSK instead of rotating it', async () => {
    const calls = [];
    const repository = {
        async findNodeById() { return { _id: 'relay-1', cascadeRole: 'relay' }; },
        async findRouteGroupById() { return { _id: 'group-a' }; },
        async findExecutionStateByNodeId() {
            return { node: 'relay-1', pskEncrypted: 'stored-envelope' };
        },
        async configureRelay(fields) {
            calls.push({ method: 'configureRelay', fields });
            return { ...fields, secretRevision: 2 };
        },
    };
    const secretBox = {
        encrypt(plaintext) {
            calls.push({ method: 'encrypt', plaintext });
            return 'reencrypted-envelope';
        },
        decrypt(envelope) {
            calls.push({ method: 'decrypt', envelope });
            return 'stored-psk-plain';
        },
    };
    const randomBytes = () => { throw new Error('reusePsk must not generate'); };
    const service = new L2tpStateManagementService({
        repository,
        secretBox,
        secretKey: SECRET_KEY,
        randomBytes,
    });

    await service.configureRelay('relay-1', validInput({ psk: undefined, reusePsk: true }));

    assert.deepEqual(calls.map(c => c.method), ['decrypt', 'encrypt', 'configureRelay']);
    assert.equal(calls[0].envelope, 'stored-envelope');
    assert.equal(calls[1].plaintext, 'stored-psk-plain');
    assert.equal(calls[2].fields.pskEncrypted, 'reencrypted-envelope');
});

test('configureRelay reusePsk falls back to a fresh PSK when none is stored', async () => {
    const calls = [];
    const repository = {
        async findNodeById() { return { _id: 'relay-1', cascadeRole: 'relay' }; },
        async findRouteGroupById() { return { _id: 'group-a' }; },
        async findExecutionStateByNodeId() { return null; },
        async configureRelay(fields) {
            calls.push({ method: 'configureRelay', fields });
            return { ...fields, secretRevision: 1 };
        },
    };
    const secretBox = {
        encrypt(plaintext) {
            calls.push({ method: 'encrypt', plaintext });
            return 'fresh-envelope';
        },
        decrypt() { throw new Error('nothing to decrypt'); },
    };
    const service = new L2tpStateManagementService({
        repository,
        secretBox,
        secretKey: SECRET_KEY,
        randomBytes: size => Buffer.alloc(size, 0xcd),
    });

    await service.configureRelay('relay-1', validInput({ psk: undefined, reusePsk: true }));

    assert.deepEqual(calls.map(c => c.method), ['encrypt', 'configureRelay']);
    assert.equal(calls[1].fields.pskEncrypted, 'fresh-envelope');
});

test('resolveOperationSecrets decrypts only the matching installed relay PSK in memory', async () => {
    const calls = [];
    const repository = {
        async findExecutionStateByNodeId(nodeId) {
            calls.push({ method: 'findExecutionStateByNodeId', nodeId });
            return {
                node: 'relay-1',
                desiredState: 'installed',
                secretRevision: 4,
                pskEncrypted: 'v1:worker-only-envelope',
            };
        },
    };
    const secretBox = {
        encrypt() { throw new Error('not used'); },
        decrypt(envelope, key) {
            calls.push({ method: 'decrypt', envelope, key });
            return RAW_PSK;
        },
    };
    const service = new L2tpStateManagementService({
        repository,
        secretBox,
        secretKey: SECRET_KEY,
    });

    const secrets = await service.resolveOperationSecrets({
        operationId: 'operation-1',
        kind: 'install',
        nodeId: 'relay-1',
        credentialRevision: 4,
        secret: 'psk',
    });

    assert.deepEqual(secrets, { psk: RAW_PSK });
    assert.deepEqual(calls, [
        { method: 'findExecutionStateByNodeId', nodeId: 'relay-1' },
        {
            method: 'decrypt',
            envelope: 'v1:worker-only-envelope',
            key: SECRET_KEY,
        },
    ]);
});

test('resolveOperationSecrets rejects invalid execution context and unsafe state without leaking secrets', async t => {
    const operation = {
        operationId: 'operation-1',
        kind: 'install',
        nodeId: 'relay-1',
        credentialRevision: 4,
        secret: 'psk',
    };
    const installedState = {
        node: 'relay-1',
        desiredState: 'installed',
        secretRevision: 4,
        pskEncrypted: 'sensitive-envelope-value',
    };

    async function rejects({
        operationOverrides = {},
        state = installedState,
        decrypt = () => RAW_PSK,
        expectedCode,
        expectedQueries = 1,
        expectedDecryptions = 0,
    }) {
        let queries = 0;
        let decryptions = 0;
        const service = new L2tpStateManagementService({
            repository: {
                async findExecutionStateByNodeId() {
                    queries += 1;
                    return state;
                },
            },
            secretBox: {
                encrypt() { throw new Error('not used'); },
                decrypt(...args) {
                    decryptions += 1;
                    return decrypt(...args);
                },
            },
            secretKey: SECRET_KEY,
        });

        await assert.rejects(
            service.resolveOperationSecrets({ ...operation, ...operationOverrides }),
            error => {
                assert.equal(error.name, 'L2tpStateManagementError');
                assert.equal(error.code, expectedCode);
                assert.doesNotMatch(error.message, /sensitive-envelope-value|correct horse/i);
                return true;
            },
        );
        assert.equal(queries, expectedQueries);
        assert.equal(decryptions, expectedDecryptions);
    }

    await t.test('wrong operation kind', () => rejects({
        operationOverrides: { kind: 'remove' },
        expectedCode: 'INVALID_OPERATION_KIND',
        expectedQueries: 0,
    }));
    await t.test('wrong secret kind', () => rejects({
        operationOverrides: { secret: 'password' },
        expectedCode: 'INVALID_SECRET_KIND',
        expectedQueries: 0,
    }));
    await t.test('missing node', () => rejects({
        operationOverrides: { nodeId: '' },
        expectedCode: 'INVALID_OPERATION_NODE',
        expectedQueries: 0,
    }));
    await t.test('missing state', () => rejects({
        state: null,
        expectedCode: 'RELAY_L2TP_STATE_NOT_FOUND',
    }));
    await t.test('state for a different node', () => rejects({
        state: { ...installedState, node: 'relay-2' },
        expectedCode: 'RELAY_L2TP_STATE_MISMATCH',
    }));
    await t.test('state is not installed', () => rejects({
        state: { ...installedState, desiredState: 'absent' },
        expectedCode: 'DESIRED_STATE_NOT_INSTALLED',
    }));
    await t.test('credential revision is stale', () => rejects({
        operationOverrides: { credentialRevision: 3 },
        expectedCode: 'CREDENTIAL_REVISION_MISMATCH',
    }));
    await t.test('encrypted PSK is missing', () => rejects({
        state: { ...installedState, pskEncrypted: '' },
        expectedCode: 'PSK_NOT_CONFIGURED',
    }));
    await t.test('encrypted PSK was tampered', () => rejects({
        decrypt() {
            throw new Error(`authentication failed for ${installedState.pskEncrypted}`);
        },
        expectedCode: 'PSK_DECRYPTION_FAILED',
        expectedDecryptions: 1,
    }));
});

test('configureRelay rejects non-relays and requires an existing explicit route group', async t => {
    async function rejects({ node, routeGroup, inputOverrides = {}, expectedCode }) {
        let writes = 0;
        const service = new L2tpStateManagementService({
            repository: {
                async findNodeById() { return node; },
                async findRouteGroupById() { return routeGroup; },
                async configureRelay() { writes += 1; },
            },
            secretBox: {
                encrypt() { throw new Error('must not encrypt'); },
                decrypt() { throw new Error('not used'); },
            },
            secretKey: SECRET_KEY,
        });
        await assert.rejects(
            service.configureRelay('relay-1', validInput(inputOverrides)),
            error => error.code === expectedCode,
        );
        assert.equal(writes, 0);
    }

    await t.test('missing node', () => rejects({
        node: null,
        routeGroup: { _id: 'group-a' },
        expectedCode: 'NODE_NOT_FOUND',
    }));
    await t.test('non-relay node', () => rejects({
        node: { _id: 'relay-1', cascadeRole: 'bridge' },
        routeGroup: { _id: 'group-a' },
        expectedCode: 'NODE_NOT_RELAY',
    }));
    await t.test('missing explicit route group', () => rejects({
        node: { _id: 'relay-1', cascadeRole: 'relay' },
        routeGroup: { _id: 'group-a' },
        inputOverrides: { routeGroupId: '' },
        expectedCode: 'ROUTE_GROUP_REQUIRED',
    }));
    await t.test('unknown route group', () => rejects({
        node: { _id: 'relay-1', cascadeRole: 'relay' },
        routeGroup: null,
        expectedCode: 'ROUTE_GROUP_NOT_FOUND',
    }));
});

test('configureRelay rejects non-canonical network fields, unsafe numeric fields, and ambiguous PSKs', async t => {
    const cases = [
        ['client CIDR', { clientCidr: '10.77.0.1/24' }, 'INVALID_CLIENT_CIDR'],
        ['local IP', { localAddress: '10.077.0.1' }, 'INVALID_LOCAL_ADDRESS'],
        ['pool order', { poolStart: '10.77.0.200', poolEnd: '10.77.0.10' }, 'INVALID_CLIENT_POOL'],
        ['pool excludes local IP', { poolStart: '10.77.0.1' }, 'INVALID_CLIENT_POOL'],
        ['DNS literals', { dnsServers: ['example.com'] }, 'INVALID_DNS_SERVERS'],
        ['DNS duplicates', { dnsServers: ['1.1.1.1', '1.1.1.1'] }, 'INVALID_DNS_SERVERS'],
        ['TPROXY port', { tproxyPort: 65536 }, 'INVALID_TPROXY_PORT'],
        ['firewall mark', { fwmark: 0 }, 'INVALID_FWMARK'],
        ['route table', { routeTable: 1.5 }, 'INVALID_ROUTE_TABLE'],
        ['missing PSK source', { psk: undefined }, 'PSK_SOURCE_REQUIRED'],
        ['ambiguous PSK source', { generatePsk: true }, 'PSK_SOURCE_REQUIRED'],
        ['unsafe PSK', { psk: 'do-not-leak-this\nvalue' }, 'INVALID_PSK'],
    ];

    for (const [name, inputOverrides, expectedCode] of cases) {
        await t.test(name, async () => {
            let writes = 0;
            const service = new L2tpStateManagementService({
                repository: {
                    async findNodeById() { return { _id: 'relay-1', cascadeRole: 'relay' }; },
                    async findRouteGroupById() { return { _id: 'group-a' }; },
                    async configureRelay() { writes += 1; },
                },
                secretBox: {
                    encrypt() { throw new Error('must not encrypt invalid input'); },
                    decrypt() { throw new Error('not used'); },
                },
                secretKey: SECRET_KEY,
            });
            await assert.rejects(
                service.configureRelay('relay-1', validInput(inputOverrides)),
                error => {
                    assert.equal(error.code, expectedCode);
                    assert.doesNotMatch(error.message, /do-not-leak-this|correct horse/i);
                    return true;
                },
            );
            assert.equal(writes, 0);
        });
    }
});

test('configureRelay wraps secret-envelope failures without leaking the PSK', async () => {
    const service = new L2tpStateManagementService({
        repository: {
            async findNodeById() { return { _id: 'relay-1', cascadeRole: 'relay' }; },
            async findRouteGroupById() { return { _id: 'group-a' }; },
            async configureRelay() { throw new Error('must not write'); },
        },
        secretBox: {
            encrypt(plaintext) {
                throw new Error(`encryption failed for ${plaintext}`);
            },
            decrypt() { throw new Error('not used'); },
        },
        secretKey: SECRET_KEY,
    });

    await assert.rejects(
        service.configureRelay('relay-1', validInput()),
        error => {
            assert.equal(error.code, 'PSK_ENCRYPTION_FAILED');
            assert.doesNotMatch(error.message, /correct horse/i);
            return true;
        },
    );
});

test('reconcileVerifiedOperation persists canonical verified install identity through the fenced repository method', async () => {
    const calls = [];
    const verifiedAt = new Date('2026-09-22T10:00:00.000Z');
    const repository = {
        async markInstalledAfterVerification(fields) {
            calls.push(fields);
            return {
                node: fields.node,
                desiredState: 'installed',
                status: 'installed',
                secretRevision: fields.credentialRevision,
                operationId: fields.operationId,
                appliedTopologyRevision: fields.topologyRevision,
                activePathKey: fields.activePathKey,
                lastVerifiedAt: fields.verifiedAt,
                lastErrorCode: '',
                lastError: '',
                pskEncrypted: 'must-not-be-returned',
            };
        },
    };
    const service = new L2tpStateManagementService({
        repository,
        secretBox: {
            encrypt() { throw new Error('not used'); },
            decrypt() { throw new Error('not used'); },
        },
        secretKey: SECRET_KEY,
    });

    const result = await service.reconcileVerifiedOperation({
        operation: {
            id: 'operation-17',
            node: 'relay-1',
            kind: 'install',
            plan: {
                operationId: 'operation-17',
                relayId: 'relay-1',
                topologyRevision: 23,
                selectedPathKey: 'primary',
                desired: { credentialRevision: 7 },
            },
        },
        verifiedAt,
    });

    assert.deepEqual(calls, [{
        node: 'relay-1',
        operationId: 'operation-17',
        credentialRevision: 7,
        topologyRevision: 23,
        activePathKey: 'primary',
        verifiedAt,
    }]);
    assert.deepEqual(result, {
        node: 'relay-1',
        operationId: 'operation-17',
        desiredState: 'installed',
        status: 'installed',
        secretRevision: 7,
        appliedTopologyRevision: 23,
        activePathKey: 'primary',
        lastVerifiedAt: verifiedAt,
        lastErrorCode: '',
        lastError: '',
    });
    assert.doesNotMatch(JSON.stringify(result), /psk|must-not-be-returned/i);
});

test('reconcileVerifiedOperation rejects stale or revoked state without reporting success', async t => {
    for (const stateChange of ['stale credential revision', 'revoked desired state']) {
        await t.test(stateChange, async () => {
            let writes = 0;
            const service = new L2tpStateManagementService({
                repository: {
                    async markInstalledAfterVerification() {
                        writes += 1;
                        return null;
                    },
                },
                secretBox: {
                    encrypt() { throw new Error('not used'); },
                    decrypt() { throw new Error('not used'); },
                },
                secretKey: SECRET_KEY,
            });

            await assert.rejects(
                service.reconcileVerifiedOperation({
                    operation: {
                        id: 'operation-17',
                        node: 'relay-1',
                        kind: 'install',
                        plan: {
                            operationId: 'operation-17',
                            relayId: 'relay-1',
                            topologyRevision: 23,
                            selectedPathKey: 'primary',
                            desired: { credentialRevision: 7 },
                        },
                    },
                    verifiedAt: new Date('2026-09-22T10:00:00.000Z'),
                }),
                error => error?.code === 'L2TP_STATE_RECONCILIATION_REJECTED',
            );
            assert.equal(writes, 1);
        });
    }
});

test('reconcileVerifiedOperation rejects mismatched operation or node identity before persistence', async t => {
    for (const [name, operation] of [
        ['operation id', {
            id: 'operation-17',
            node: 'relay-1',
            kind: 'install',
            plan: {
                operationId: 'operation-stale',
                relayId: 'relay-1',
                topologyRevision: 23,
                selectedPathKey: 'primary',
                desired: { credentialRevision: 7 },
            },
        }],
        ['node id', {
            id: 'operation-17',
            node: 'relay-1',
            kind: 'install',
            plan: {
                operationId: 'operation-17',
                relayId: 'relay-revoked',
                topologyRevision: 23,
                selectedPathKey: 'primary',
                desired: { credentialRevision: 7 },
            },
        }],
    ]) {
        await t.test(name, async () => {
            let writes = 0;
            const service = new L2tpStateManagementService({
                repository: {
                    async markInstalledAfterVerification() { writes += 1; },
                },
                secretBox: {
                    encrypt() { throw new Error('not used'); },
                    decrypt() { throw new Error('not used'); },
                },
                secretKey: SECRET_KEY,
            });

            await assert.rejects(
                service.reconcileVerifiedOperation({
                    operation,
                    verifiedAt: new Date('2026-09-22T10:00:00.000Z'),
                }),
                error => error?.code === 'OPERATION_IDENTITY_MISMATCH',
            );
            assert.equal(writes, 0);
        });
    }
});
