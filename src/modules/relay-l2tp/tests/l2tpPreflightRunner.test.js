'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpPreflightRunner,
} = require('../services/l2tpPreflightRunner');

const SECRET_PSK = 'preflight-psk-must-not-leak';
const SECRET_PASSWORD = 'preflight-password-must-not-leak';
const OPERATION_ID = `preflight-${'ab'.repeat(12)}`;

function validContext(overrides = {}) {
    return {
        node: {
            id: 'relay-1',
            cascadeRole: 'relay',
            ssh: { privateKey: 'node-private-key-must-not-leak' },
        },
        relay: {
            id: 'relay-1',
            role: 'relay',
            ssh: { password: 'relay-ssh-password-must-not-leak' },
        },
        state: {
            desiredState: 'installed',
            pskEncrypted: SECRET_PSK,
        },
        desired: {
            desiredState: 'installed',
            clientCidr: '10.77.0.0/24',
            localAddress: '10.77.0.1',
            poolStart: '10.77.0.10',
            poolEnd: '10.77.0.200',
            dnsServers: ['1.1.1.1', '9.9.9.9'],
            tproxyPort: 12345,
            fwmark: 77,
            routeTable: 177,
            routingMode: 'route-group',
            psk: SECRET_PSK,
            users: [{ login: 'alice', password: SECRET_PASSWORD }],
        },
        routeGroup: { id: 'group-a' },
        relayGroupPlan: {
            decision: { nextHopNodeId: 'bridge-1' },
            bridge: { ssh: { password: 'bridge-secret-must-not-leak' } },
        },
        topologyRevision: 17,
        input: {
            clientCidr: '10.77.0.0/24',
            routeGroupId: 'group-a',
            expectedTopologyRevision: 17,
        },
        ...overrides,
    };
}

function successfulChecks() {
    return [
        { check: 'os', status: 'ok', id: 'debian', version: '13' },
        { check: 'client_cidr', status: 'ok', cidr: '10.77.0.0/24' },
        { check: 'xray', status: 'ok', version: 'Xray 26.3.27' },
        {
            check: 'xray_config',
            status: 'ok',
            path: '/usr/local/etc/xray/config.json',
        },
        { check: 'xray_unit', status: 'ok', unit: 'xray.service' },
    ];
}

test('uploads one fixed secret-free desired artifact and runs typed preflight on the target relay', async () => {
    const calls = [];
    const checks = successfulChecks();
    const transport = {
        async uploadRootFile(request) {
            calls.push({ method: 'uploadRootFile', request });
            return { ok: true, path: 'remote-path-must-not-escape' };
        },
        async runArtifactCommand(request) {
            calls.push({ method: 'runArtifactCommand', request });
            return {
                ok: true,
                checks,
                stdout: 'remote-stdout-must-not-escape',
                stderr: 'remote-stderr-must-not-escape',
            };
        },
        async exec() {
            assert.fail('generic exec must not be used');
        },
    };
    const runner = new L2tpPreflightRunner({
        randomBytes(size) {
            assert.equal(size, 12);
            return Buffer.alloc(size, 0xab);
        },
        async transportResolver(request) {
            calls.push({ method: 'transportResolver', request });
            return transport;
        },
    });

    const result = await runner.run(validContext());

    const desiredContent = `${JSON.stringify({
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
    })}\n`;
    assert.deepEqual(calls, [
        {
            method: 'transportResolver',
            request: { operationId: OPERATION_ID, nodeId: 'relay-1' },
        },
        {
            method: 'uploadRootFile',
            request: {
                operationId: OPERATION_ID,
                type: 'desired',
                path: 'desired.json',
                content: desiredContent,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            },
        },
        {
            method: 'runArtifactCommand',
            request: { operationId: OPERATION_ID, command: 'preflight' },
        },
    ]);
    assert.deepEqual(result, { ok: true, checks });
    assert.doesNotMatch(JSON.stringify(calls), new RegExp(SECRET_PSK));
    assert.doesNotMatch(JSON.stringify(calls), new RegExp(SECRET_PASSWORD));
    assert.doesNotMatch(JSON.stringify(result), /remote-(?:stdout|stderr|path)/);
});

test('rejects an invalid install context before randomness or transport resolution', async () => {
    let randomCalls = 0;
    let resolverCalls = 0;
    const runner = new L2tpPreflightRunner({
        randomBytes() {
            randomCalls += 1;
            return Buffer.alloc(12);
        },
        async transportResolver() {
            resolverCalls += 1;
            throw new Error('must not resolve');
        },
    });

    const result = await runner.run(validContext({
        relay: { id: 'portal-1', role: 'portal' },
    }));

    assert.deepEqual(result, {
        ok: false,
        checks: [],
        error: { code: 'PREFLIGHT_CONTEXT_INVALID' },
    });
    assert.equal(randomCalls, 0);
    assert.equal(resolverCalls, 0);
});

test('maps a failed lazy relay transport resolution to a safe preflight result', async () => {
    const secret = 'resolver-private-key-must-not-leak';
    const resolverCalls = [];
    const runner = new L2tpPreflightRunner({
        randomBytes: size => Buffer.alloc(size, 0xcd),
        async transportResolver(request) {
            resolverCalls.push(request);
            throw Object.assign(new Error(`SSH failed: ${secret}`), {
                node: { ssh: { privateKey: secret } },
                stdout: secret,
                stderr: secret,
            });
        },
    });

    const result = await runner.run(validContext());

    assert.deepEqual(resolverCalls, [{
        operationId: `preflight-${'cd'.repeat(12)}`,
        nodeId: 'relay-1',
    }]);
    assert.deepEqual(result, {
        ok: false,
        checks: [],
        error: { code: 'PREFLIGHT_TRANSPORT_UNAVAILABLE' },
    });
    assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test('maps typed upload and command failures without exposing remote details', async t => {
    const secret = 'remote-command-output-must-not-leak';
    const cases = [
        {
            name: 'upload',
            expectedCode: 'PREFLIGHT_UPLOAD_FAILED',
            transport: {
                async uploadRootFile() {
                    throw Object.assign(new Error(secret), { stdout: secret, stderr: secret });
                },
                async runArtifactCommand() {
                    assert.fail('command must not run after upload failure');
                },
            },
        },
        {
            name: 'command',
            expectedCode: 'PREFLIGHT_COMMAND_FAILED',
            transport: {
                async uploadRootFile() { return { ok: true }; },
                async runArtifactCommand() {
                    throw Object.assign(new Error(secret), { stdout: secret, stderr: secret });
                },
            },
        },
    ];

    for (const candidate of cases) {
        await t.test(candidate.name, async () => {
            const runner = new L2tpPreflightRunner({
                randomBytes: size => Buffer.alloc(size, 0xef),
                transportResolver: async () => candidate.transport,
            });

            const result = await runner.run(validContext());

            assert.deepEqual(result, {
                ok: false,
                checks: [],
                error: { code: candidate.expectedCode },
            });
            assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
        });
    }
});

test('sanitizes structured preflight failures and rejects unvalidated responses', async t => {
    const secret = 'remote-response-secret-must-not-leak';
    const cases = [
        {
            name: 'validated artifact failure',
            response: {
                ok: false,
                checks: [{
                    check: 'os',
                    status: 'error',
                    code: 'UNSUPPORTED_OS',
                    id: 'alpine',
                    version: '3.20',
                    stdout: secret,
                    node: { ssh: { password: secret } },
                }],
                error: { code: 'UNSUPPORTED_OS', message: secret, stderr: secret },
                stdout: secret,
                stderr: secret,
            },
            expected: {
                ok: false,
                checks: [{
                    check: 'os',
                    status: 'error',
                    code: 'UNSUPPORTED_OS',
                    id: 'alpine',
                    version: '3.20',
                }],
                error: { code: 'UNSUPPORTED_OS' },
            },
        },
        {
            name: 'unvalidated response',
            response: {
                ok: false,
                checks: [{ check: 'ssh', status: 'error', code: secret }],
                error: { code: secret },
                stdout: secret,
                stderr: secret,
            },
            expected: {
                ok: false,
                checks: [],
                error: { code: 'PREFLIGHT_RESPONSE_INVALID' },
            },
        },
    ];

    for (const candidate of cases) {
        await t.test(candidate.name, async () => {
            const runner = new L2tpPreflightRunner({
                randomBytes: size => Buffer.alloc(size, 0xfa),
                transportResolver: async () => ({
                    async uploadRootFile() { return { ok: true }; },
                    async runArtifactCommand() { return candidate.response; },
                }),
            });

            const result = await runner.run(validContext());

            assert.deepEqual(result, candidate.expected);
            assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
        });
    }
});

test('fails closed before resolution when operation id entropy is invalid', async () => {
    let resolverCalls = 0;
    const runner = new L2tpPreflightRunner({
        randomBytes() {
            return { toString: () => '../unsafe-operation-id' };
        },
        async transportResolver() {
            resolverCalls += 1;
            return null;
        },
    });

    const result = await runner.run(validContext());

    assert.deepEqual(result, {
        ok: false,
        checks: [],
        error: { code: 'PREFLIGHT_OPERATION_ID_FAILED' },
    });
    assert.equal(resolverCalls, 0);
});

module.exports = { successfulChecks, validContext };
