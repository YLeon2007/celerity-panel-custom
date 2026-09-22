'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    TOPOLOGY_NODE_ARTIFACT_ID,
    TOPOLOGY_NODE_COMMANDS,
    TOPOLOGY_NODE_RUNNER_PATH,
    TopologyNodeTransport,
} = require('../services/topologyNodeTransport');

const artifactContent = '{"marker":"candidate-secret-canary"}\n';
const candidateHash = `sha256:${createHash('sha256').update(artifactContent).digest('hex')}`;
const basePlan = Object.freeze({
    operationId: 'topology-operation-17',
    nodeId: 'bridge-node-2',
    candidateHash,
    backupId: 'topology-backup-17-bridge-2',
    targetProfile: 'xray-bridge',
});

function receipt(command, overrides = {}) {
    return {
        ok: true,
        command,
        ...basePlan,
        ...overrides,
    };
}

function execResult(value) {
    return { code: 0, stdout: `${JSON.stringify(value)}\n`, stderr: '' };
}

test('prepare sends one fixed Xray candidate to the fixed topology runner and returns a bound receipt', async () => {
    const calls = [];
    const transport = new TopologyNodeTransport({
        async invokeArtifact(runnerPath, request) {
            calls.push({ runnerPath, request });
            return execResult(receipt('prepare'));
        },
    });

    const result = await transport.prepare({
        ...basePlan,
        artifact: {
            id: 'xray-config',
            content: artifactContent,
        },
    });

    assert.equal(TOPOLOGY_NODE_RUNNER_PATH, '/usr/local/bin/celerity-topology-node-runner');
    assert.equal(TOPOLOGY_NODE_ARTIFACT_ID, 'xray-config');
    assert.deepEqual(TOPOLOGY_NODE_COMMANDS, Object.freeze({
        PREPARE: 'prepare',
        COMMIT: 'commit',
        VERIFY: 'verify',
        ROLLBACK: 'rollback',
    }));
    assert.deepEqual(calls, [{
        runnerPath: TOPOLOGY_NODE_RUNNER_PATH,
        request: {
            command: 'prepare',
            ...basePlan,
            artifact: {
                id: TOPOLOGY_NODE_ARTIFACT_ID,
                content: artifactContent,
            },
        },
    }]);
    assert.deepEqual(result, receipt('prepare'));
    assert.equal(Object.isFrozen(result), true);
});

test('exposes only the four typed topology lifecycle methods', () => {
    const transport = new TopologyNodeTransport({ invokeArtifact: async () => null });

    assert.deepEqual(
        Object.getOwnPropertyNames(Object.getPrototypeOf(transport)),
        ['constructor', 'prepare', 'commit', 'verify', 'rollback'],
    );
    assert.equal(transport.exec, undefined);
    assert.equal(transport.run, undefined);
    assert.deepEqual(Object.keys(transport), []);
});

test('plan identity fields must be primitive strings in the closed schema', async () => {
    for (const key of ['operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile']) {
        const request = {
            ...basePlan,
            [key]: { toString: () => basePlan[key] },
        };
        const transport = new TopologyNodeTransport({
            async invokeArtifact() {
                assert.fail('non-string identity reached the runner');
            },
        });

        await assert.rejects(transport.commit(request), error => {
            assert.equal(error.code, 'INVALID_PLAN');
            return true;
        });
    }
});

test('commit, verify, and rollback send only the closed bound plan', async () => {
    for (const command of ['commit', 'verify', 'rollback']) {
        const calls = [];
        const transport = new TopologyNodeTransport({
            async invokeArtifact(runnerPath, request) {
                calls.push({ runnerPath, request });
                return execResult(receipt(command));
            },
        });

        assert.deepEqual(await transport[command]({ ...basePlan }), receipt(command));
        assert.deepEqual(calls, [{
            runnerPath: TOPOLOGY_NODE_RUNNER_PATH,
            request: { command, ...basePlan },
        }]);
    }
});

test('rejects raw execution, path, environment, and extra artifact fields before invocation', async () => {
    const forbiddenFields = [
        ['exec', 'id'],
        ['shell', 'sh -c id'],
        ['argv', ['--config', '/tmp/foreign.json']],
        ['env', { TOKEN: 'raw-field-secret' }],
        ['path', '/tmp/foreign.json'],
    ];

    for (const command of ['prepare', 'commit', 'verify', 'rollback']) {
        for (const [key, value] of forbiddenFields) {
            const calls = [];
            const transport = new TopologyNodeTransport({
                async invokeArtifact(...args) {
                    calls.push(args);
                    return execResult(receipt(command));
                },
            });
            const request = {
                ...basePlan,
                ...(command === 'prepare'
                    ? { artifact: { id: TOPOLOGY_NODE_ARTIFACT_ID, content: artifactContent } }
                    : {}),
                [key]: value,
            };

            await assert.rejects(
                transport[command](request),
                error => {
                    assert.equal(error.name, 'TopologyNodeTransportError');
                    assert.equal(error.code, 'INVALID_PLAN');
                    assert.equal(error.message, 'Invalid topology node plan');
                    assert.doesNotMatch(JSON.stringify(error), /raw-field-secret|\/tmp|sh -c|\bid\b/);
                    return true;
                },
            );
            assert.deepEqual(calls, []);
        }
    }
});

test('prepare accepts only the fixed artifact identifier with content matching candidateHash', async () => {
    const invalidRequests = [
        { ...basePlan },
        { ...basePlan, artifact: { id: 'raw-file', content: artifactContent } },
        { ...basePlan, artifact: { id: TOPOLOGY_NODE_ARTIFACT_ID, content: '' } },
        {
            ...basePlan,
            artifact: {
                id: TOPOLOGY_NODE_ARTIFACT_ID,
                content: artifactContent,
                path: '/tmp/foreign.json',
            },
        },
        {
            ...basePlan,
            candidateHash: `sha256:${'0'.repeat(64)}`,
            artifact: { id: TOPOLOGY_NODE_ARTIFACT_ID, content: artifactContent },
        },
    ];

    for (const request of invalidRequests) {
        let invoked = false;
        const transport = new TopologyNodeTransport({
            async invokeArtifact() {
                invoked = true;
                return execResult(receipt('prepare'));
            },
        });
        await assert.rejects(transport.prepare(request), error => {
            assert.equal(error.name, 'TopologyNodeTransportError');
            assert.match(error.code, /INVALID_PLAN|INVALID_ARTIFACT|CANDIDATE_HASH_MISMATCH/);
            assert.doesNotMatch(JSON.stringify(error), /candidate-secret-canary|\/tmp/);
            return true;
        });
        assert.equal(invoked, false);
    }
});

test('receipts are strict and bound to command, operation, node, hash, backup, and profile', async () => {
    const secret = 'remote-receipt-secret-canary';
    const invalidReceipts = [
        receipt('verify', { command: 'commit' }),
        receipt('verify', { operationId: 'another-operation' }),
        receipt('verify', { nodeId: 'another-node' }),
        receipt('verify', { candidateHash: `sha256:${'0'.repeat(64)}` }),
        receipt('verify', { backupId: 'another-backup' }),
        receipt('verify', { targetProfile: 'xray-main' }),
        { ...receipt('verify'), diagnostics: secret },
        { ...receipt('verify'), ok: false },
    ];

    for (const invalidReceipt of invalidReceipts) {
        const transport = new TopologyNodeTransport({
            async invokeArtifact() {
                return execResult(invalidReceipt);
            },
        });
        await assert.rejects(transport.verify({ ...basePlan }), error => {
            assert.equal(error.name, 'TopologyNodeTransportError');
            assert.equal(error.code, 'INVALID_RECEIPT');
            assert.equal(error.message, 'Invalid topology node receipt');
            assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
            return true;
        });
    }
});

test('malformed runner output and invocation failures become sanitized errors', async () => {
    const secret = 'untrusted-runner-secret-canary';
    const responses = [
        { code: 1, stdout: '', stderr: secret },
        { code: 0, stdout: `${secret}\n`, stderr: '' },
        { code: 0, stdout: `${JSON.stringify(receipt('commit'))}\n${secret}\n`, stderr: '' },
        { code: 0, stdout: `${JSON.stringify(receipt('commit'))}\n`, stderr: secret },
    ];

    for (const response of responses) {
        const transport = new TopologyNodeTransport({
            async invokeArtifact() {
                return response;
            },
        });
        await assert.rejects(transport.commit({ ...basePlan }), error => {
            assert.equal(error.name, 'TopologyNodeTransportError');
            assert.equal(error.code, 'INVALID_RECEIPT');
            assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
            return true;
        });
    }

    const transport = new TopologyNodeTransport({
        async invokeArtifact() {
            throw new Error(secret);
        },
    });
    await assert.rejects(transport.rollback({ ...basePlan }), error => {
        assert.equal(error.code, 'ARTIFACT_INVOCATION_FAILED');
        assert.equal(error.message, 'Topology node artifact invocation failed');
        assert.equal(Object.hasOwn(error, 'cause'), false);
        assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
        return true;
    });
});
