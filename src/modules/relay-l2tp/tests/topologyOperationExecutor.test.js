'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    TopologyOperationExecutor,
} = require('../services/topologyOperationExecutor');

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalize(value[key])]),
    );
}

function candidateContent({ nodeRef }) {
    return `${JSON.stringify(canonicalize({
        inbounds: [{ tag: `client-${nodeRef}` }],
        outbounds: [{ tag: 'direct' }],
        routing: { rules: [] },
    }))}\n`;
}

function candidateArtifact(content) {
    return {
        mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
        bytes: [...Buffer.from(content)],
        sha256: createHash('sha256').update(content).digest('hex'),
    };
}

const CANDIDATE_CONTENT = candidateContent({
    nodeRef: 'portal',
});
const CANDIDATE_DIGEST = createHash('sha256').update(CANDIDATE_CONTENT).digest('hex');

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
}

function frozenNode(overrides = {}) {
    const role = overrides.role || 'portal';
    const targetProfile = overrides.targetProfile
        || (role === 'portal' ? 'xray-main' : 'xray-bridge');
    const nodeRef = overrides.nodeRef || (role === 'relay' ? 'relay-1' : role);
    const checks = overrides.checks || [];
    const content = candidateContent({ nodeRef });
    const candidate = candidateArtifact(content);
    return deepFreeze({
        nodeRef,
        role,
        targetProfile,
        serviceUnit: targetProfile === 'xray-main' ? 'xray.service' : 'xray-bridge.service',
        serviceUnitPath: targetProfile === 'xray-main'
            ? '/etc/systemd/system/xray.service'
            : '/etc/systemd/system/xray-bridge.service',
        configPath: targetProfile === 'xray-main'
            ? '/usr/local/etc/xray/config.json'
            : '/usr/local/etc/xray-bridge/config.json',
        candidate,
        checks,
        node: overrides.node || `${role}-node`,
        candidateHash: candidate.sha256,
        ...overrides,
    });
}

function prepareContext(node = frozenNode()) {
    return {
        operationId: 'topology-operation-17',
        topologyRevision: 17,
        priorDeployedRevision: 16,
        node,
    };
}

function runnerRequest(command) {
    const fields = Object.fromEntries([
        ['operationId', '--operation-id'],
        ['nodeId', '--node-id'],
        ['candidateHash', '--candidate-hash'],
        ['backupId', '--backup-id'],
        ['targetProfile', '--target-profile'],
    ].map(([field, flag]) => [field, command.match(new RegExp(`${flag} ([A-Za-z0-9._:-]+)`))?.[1]]));
    fields.command = command.match(/--command ([a-z]+)/)?.[1];
    const checksToken = command.match(/--checks ([A-Za-z0-9_-]+)/)?.[1];
    if (checksToken) {
        fields.checks = JSON.parse(Buffer.from(checksToken, 'base64url').toString('utf8'));
    }
    return fields;
}

function execResult(request, overrides = {}) {
    const { checks: _checks, ...receiptRequest } = request;
    return {
        code: 0,
        stdout: `${JSON.stringify({ ok: true, ...receiptRequest, ...overrides })}\n`,
        stderr: '',
    };
}

function lifecycleContext(preparedResult, node = frozenNode()) {
    return {
        ...prepareContext(node),
        backupId: preparedResult.backupId,
        prepared: preparedResult.prepared,
    };
}

function executorFixture({ responseOverrides = {} } = {}) {
    const events = [];
    const nodeSSH = {
        async exec(command, options) {
            const request = runnerRequest(command);
            events.push({ method: 'transport', request, options });
            return execResult(request, responseOverrides[request.command]);
        },
        async writeFile() {},
    };
    const nodeExecutionResolver = {
        async resolve(request) {
            events.push({ method: 'resolve', request });
            return nodeSSH;
        },
    };
    class FakeBootstrapper {
        constructor(options) {
            events.push({ method: 'bootstrapper', target: options.target });
        }

        async ensureRunner() {
            events.push({ method: 'ensureRunner' });
            return { ok: true };
        }
    }
    return {
        events,
        executor: new TopologyOperationExecutor({
            target: 'test',
            nodeExecutionResolver,
            RunnerBootstrapper: FakeBootstrapper,
        }),
    };
}

test('resolves one frozen test node, bootstraps first, and prepares through the role-bound transport', async () => {
    const events = [];
    const storedSecret = 'stored-node-private-key-secret';
    const nodeSSH = {
        node: { ssh: { privateKey: storedSecret } },
        async exec(command, options) {
            const request = runnerRequest(command);
            events.push({ method: 'transport', request, options });
            return execResult(request);
        },
        async writeFile() {
            assert.fail('the fake bootstrapper must not upload a runner');
        },
    };
    const nodeExecutionResolver = {
        async resolve(request) {
            events.push({ method: 'resolve', request });
            return nodeSSH;
        },
    };
    class FakeBootstrapper {
        constructor(options) {
            events.push({
                method: 'bootstrapper',
                target: options.target,
                sameNodeSSH: options.nodeSSH === nodeSSH,
            });
        }

        async ensureRunner() {
            events.push({ method: 'ensureRunner' });
            return { ok: true };
        }
    }
    const executor = new TopologyOperationExecutor({
        target: 'test',
        nodeExecutionResolver,
        RunnerBootstrapper: FakeBootstrapper,
    });

    const result = await executor.prepare(prepareContext());

    assert.deepEqual(events.map(event => event.method), [
        'resolve',
        'bootstrapper',
        'ensureRunner',
        'transport',
    ]);
    assert.deepEqual(events[0].request, { nodeId: 'portal-node', role: 'portal' });
    assert.deepEqual(events[1], {
        method: 'bootstrapper',
        target: 'test',
        sameNodeSSH: true,
    });
    assert.deepEqual(events[3].request, {
        operationId: 'topology-operation-17',
        nodeId: 'portal-node',
        candidateHash: `sha256:${CANDIDATE_DIGEST}`,
        backupId: events[3].request.backupId,
        targetProfile: 'xray-main',
        command: 'prepare',
    });
    assert.match(events[3].request.backupId, /^topology-[a-f0-9]{64}$/);
    assert.deepEqual(events[3].options, { stdin: CANDIDATE_CONTENT });
    assert.deepEqual(result, {
        ok: true,
        backupId: events[3].request.backupId,
        prepared: {
            ok: true,
            command: 'prepare',
            operationId: 'topology-operation-17',
            nodeId: 'portal-node',
            candidateHash: `sha256:${CANDIDATE_DIGEST}`,
            backupId: events[3].request.backupId,
            targetProfile: 'xray-main',
        },
    });
    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.prepared), true);
    assert.deepEqual(Object.keys(executor), []);
    assert.equal(executor.exec, undefined);
    assert.equal(executor.shell, undefined);
    assert.doesNotMatch(JSON.stringify({ executor, result }), new RegExp(storedSecret));
});

test('reuses the prepared binding for closed commit, verify, and rollback receipts', async () => {
    const { events, executor } = executorFixture();
    const node = frozenNode({
        role: 'relay',
        node: 'relay-node',
        nodeRef: 'relay-1',
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
        checks: [
            {
                type: 'service',
                serviceUnit: 'xray-bridge.service',
                expectedState: 'active',
            },
            {
                type: 'port',
                protocol: 'tcp',
                port: 12001,
                expectedState: 'listening',
            },
        ],
    });
    const nodeContent = Buffer.from(node.candidate.bytes).toString('utf8');
    const nodeCandidateHash = `sha256:${node.candidateHash}`;
    const prepared = await executor.prepare(prepareContext(node));
    const context = lifecycleContext(prepared, node);

    const committed = await executor.commit(context);
    const verified = await executor.verify(context);
    const rolledBack = await executor.rollback(context);

    assert.deepEqual(events.filter(event => event.method === 'resolve'), [{
        method: 'resolve',
        request: { nodeId: 'relay-node', role: 'relay' },
    }]);
    assert.deepEqual(
        events.filter(event => event.method === 'transport').map(event => ({
            command: event.request.command,
            operationId: event.request.operationId,
            nodeId: event.request.nodeId,
            candidateHash: event.request.candidateHash,
            backupId: event.request.backupId,
            targetProfile: event.request.targetProfile,
            checks: event.request.checks,
            options: event.options,
        })),
        ['prepare', 'commit', 'verify', 'rollback'].map((command, index) => ({
            command,
            operationId: 'topology-operation-17',
            nodeId: 'relay-node',
            candidateHash: nodeCandidateHash,
            backupId: prepared.backupId,
            targetProfile: 'xray-bridge',
            checks: index === 2 ? node.checks : undefined,
            options: index === 0 ? { stdin: nodeContent } : undefined,
        })),
    );
    for (const [receipt, command] of [
        [committed, 'commit'],
        [verified, 'verify'],
        [rolledBack, 'rollback'],
    ]) {
        assert.deepEqual(receipt, {
            ok: true,
            command,
            operationId: 'topology-operation-17',
            nodeId: 'relay-node',
            candidateHash: nodeCandidateHash,
            backupId: prepared.backupId,
            targetProfile: 'xray-bridge',
        });
        assert.equal(Object.isFrozen(receipt), true);
    }
});

test('cleanupPrepared uses only the fixed rollback for a prepare-only artifact', async () => {
    const { events, executor } = executorFixture();
    const node = frozenNode({
        role: 'bridge',
        node: 'bridge-node',
        nodeRef: 'bridge',
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    });
    const nodeCandidateHash = `sha256:${node.candidateHash}`;
    const prepared = await executor.prepare(prepareContext(node));

    const cleaned = await executor.cleanupPrepared(lifecycleContext(prepared, node));

    assert.deepEqual(
        events.filter(event => event.method === 'transport')
            .map(event => event.request.command),
        ['prepare', 'rollback'],
    );
    assert.deepEqual(cleaned, {
        ok: true,
        command: 'rollback',
        operationId: 'topology-operation-17',
        nodeId: 'bridge-node',
        candidateHash: nodeCandidateHash,
        backupId: prepared.backupId,
        targetProfile: 'xray-bridge',
    });
    await assert.rejects(
        executor.commit(lifecycleContext(prepared, node)),
        error => error?.code === 'INVALID_FROZEN_NODE_PLAN',
    );
});

test('fails closed outside test and rejects non-frozen, role-mismatched, or expanded plans before lookup', async () => {
    let resolverCalls = 0;
    const nodeExecutionResolver = {
        async resolve() {
            resolverCalls += 1;
            throw new Error('must not resolve invalid input');
        },
    };

    assert.throws(
        () => new TopologyOperationExecutor({
            target: 'production',
            nodeExecutionResolver,
        }),
        error => error?.code === 'UNSAFE_TOPOLOGY_TARGET',
    );
    assert.throws(
        () => new TopologyOperationExecutor({
            target: 'test',
            nodeExecutionResolver,
            topologyRepository: { find: 'live-topology-lookup' },
        }),
        error => error?.code === 'INVALID_EXECUTOR_CONFIGURATION',
    );

    const legacyContent = `${JSON.stringify({
        schemaVersion: 1,
        kind: 'xray-topology-node-candidate',
        mode: 'forward',
        nodeRef: 'portal',
        role: 'portal',
        targetProfile: 'xray-main',
        links: [],
        checks: [],
    })}\n`;
    const legacyCandidate = candidateArtifact(legacyContent);
    const nonCanonicalContent = `${JSON.stringify({
        outbounds: [],
        inbounds: [],
    }, null, 2)}\n`;
    const nonCanonicalCandidate = candidateArtifact(nonCanonicalContent);
    const invalidContexts = [
        prepareContext({ ...frozenNode() }),
        prepareContext(frozenNode({ targetProfile: 'xray-bridge' })),
        prepareContext(frozenNode({
            candidate: legacyCandidate,
            candidateHash: legacyCandidate.sha256,
        })),
        prepareContext(frozenNode({
            candidate: nonCanonicalCandidate,
            candidateHash: nonCanonicalCandidate.sha256,
        })),
        { ...prepareContext(), users: [{ password: 'user-secret-canary' }] },
        prepareContext(deepFreeze({
            ...frozenNode(),
            ssh: { password: 'request-credential-canary' },
        })),
        prepareContext(deepFreeze({
            ...frozenNode(),
            candidate: {
                ...frozenNode().candidate,
                shell: 'sh -c id',
            },
        })),
    ];

    const executor = new TopologyOperationExecutor({
        target: 'test',
        nodeExecutionResolver,
    });
    for (const context of invalidContexts) {
        await assert.rejects(executor.prepare(context), error => {
            assert.equal(error.name, 'TopologyOperationExecutorError');
            assert.equal(error.code, 'INVALID_FROZEN_NODE_PLAN');
            assert.equal(error.message, 'Invalid frozen topology node plan');
            assert.doesNotMatch(
                JSON.stringify(error),
                /user-secret-canary|request-credential-canary|sh -c|live-topology-lookup/,
            );
            return true;
        });
    }
    assert.equal(resolverCalls, 0);
});

test('sanitizes hash-bound transport failures and retains only the binding needed for fixed rollback', async () => {
    const remoteSecret = 'untrusted-transport-secret-canary';
    const { events, executor } = executorFixture({
        responseOverrides: {
            commit: {
                candidateHash: `sha256:${'0'.repeat(64)}`,
                diagnostics: remoteSecret,
            },
        },
    });
    const node = frozenNode();
    const prepared = await executor.prepare(prepareContext(node));
    const context = lifecycleContext(prepared, node);

    await assert.rejects(executor.commit(context), error => {
        assert.equal(error.name, 'TopologyOperationExecutorError');
        assert.equal(error.code, 'TOPOLOGY_OPERATION_EXECUTION_FAILED');
        assert.equal(error.message, 'Topology node operation failed');
        assert.equal(Object.hasOwn(error, 'cause'), false);
        assert.doesNotMatch(JSON.stringify(error), new RegExp(remoteSecret));
        return true;
    });
    const rolledBack = await executor.rollback(context);

    assert.equal(rolledBack.ok, true);
    assert.deepEqual(
        events.filter(event => event.method === 'transport')
            .map(event => event.request.command),
        ['prepare', 'commit', 'rollback'],
    );
    assert.equal(events.filter(event => event.method === 'resolve').length, 1);
    assert.doesNotMatch(JSON.stringify({ executor, rolledBack }), new RegExp(remoteSecret));
});

test('a malformed prepare receipt triggers only fixed rollback and exposes no prepared binding', async () => {
    const remoteSecret = 'malformed-prepare-secret-canary';
    const { events, executor } = executorFixture({
        responseOverrides: {
            prepare: { diagnostics: remoteSecret },
        },
    });

    await assert.rejects(executor.prepare(prepareContext()), error => {
        assert.equal(error.code, 'TOPOLOGY_OPERATION_EXECUTION_FAILED');
        assert.doesNotMatch(JSON.stringify(error), new RegExp(remoteSecret));
        return true;
    });
    assert.deepEqual(
        events.filter(event => event.method === 'transport')
            .map(event => event.request.command),
        ['prepare', 'rollback'],
    );
    assert.doesNotMatch(JSON.stringify(executor), new RegExp(remoteSecret));
});

test('rehydrates a durable prepared binding without preparing or reading current topology', async () => {
    const { events, executor } = executorFixture();
    const node = frozenNode({
        role: 'bridge',
        node: 'bridge-node',
        nodeRef: 'bridge',
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    });
    const backupId = 'topology-durable-backup-bridge';

    const rehydrated = await executor.rehydrate({
        ...prepareContext(node),
        backupId,
    });

    assert.deepEqual(events.filter(event => event.method), [
        { method: 'resolve', request: { nodeId: 'bridge-node', role: 'bridge' } },
        { method: 'bootstrapper', target: 'test' },
        { method: 'ensureRunner' },
    ]);
    assert.equal(events.filter(event => event.method === 'transport').length, 0);
    assert.deepEqual(rehydrated, {
        ok: true,
        backupId,
        prepared: {
            ok: true,
            command: 'prepare',
            operationId: 'topology-operation-17',
            nodeId: 'bridge-node',
            candidateHash: `sha256:${node.candidateHash}`,
            backupId,
            targetProfile: 'xray-bridge',
        },
    });

    const rolledBack = await executor.rollback({
        ...prepareContext(node),
        backupId,
        prepared: rehydrated.prepared,
    });
    assert.equal(rolledBack.ok, true);
    assert.deepEqual(events.filter(event => event.method === 'transport')
        .map(event => event.request), [{
        operationId: 'topology-operation-17',
        nodeId: 'bridge-node',
        candidateHash: `sha256:${node.candidateHash}`,
        backupId,
        targetProfile: 'xray-bridge',
        command: 'rollback',
    }]);
    assert.doesNotMatch(JSON.stringify({ executor, rehydrated }), /secret|privateKey|topology-lookup/);
});
