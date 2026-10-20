'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');
const { executionFence, bindingRecord, bindingReader, runnerRequest, v2Receipt, freeze } = require('./helpers/topologyV2Fixture');

const {
    TopologyOperationExecutor,
    TopologyOperationExecutorError,
} = require('../services/topologyOperationExecutor');

test('real V2 worker settles only after held proofs and keeps failure recovery read-only', async t => {
    for (const fault of ['none', 'users', 'ppp', 'close', 'persist', 'settle']) await t.test(fault, async () => {
        const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
        const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
        const terminal = { phase: 'closed', terminal: true, terminalOutcome: 'verified', completedCommand: 'close' };
        const { executor, reader, events } = executorFixture({ responseOverrides: {
            close: fault === 'close' ? { ...terminal, bootId: 'wrong-boot' } : terminal, status: terminal } });
        let held = 0, marker = null, claims = 0;
        // Explicit LOCAL held-authority simulation, not operational attestation.
        reader.withVerifiedBinding = async (expected, work) => {
            held++;
            try { return await work(await reader.readVerified(expected), async () => {}); }
            finally { held--; }
        };
        reader.withReadOnlyVerifiedBinding = reader.withVerifiedBinding;
        const node = frozenNode();
        const operation = { _id: prepareContext().operationId, executionContext: TEST,
            idempotencyKey: 'topology:test:revision-17:host-test.infograd.online:00000000-0000-0000-0000-000000000000',
            topologyRevision: 17, priorDeployedRevision: 16, attempts: 1, heldTopologyAdmission: true,
            status: 'preparing', nodes: [{ ...node, state: 'pending', backupId: '' }] };
        const order = [];
        const worker = new TopologyOperationWorker({ executionContext: TEST, executor,
            allowUnprovenTestExecution: true, workerId: executionFence.owner, leaseMs: 30000,
            clock: { now: () => new Date() },
            operationRepository: { async claim() { claims++; return operation; }, async renewLease() { return true; },
                async recordNode() { return true; }, async setPhase() { return true; }, async finishClaimed() { throw new Error('no terminal fallback'); } },
            lockService: { async acquire() { return { ok: true, lock: { generation: executionFence.generation } }; },
                async renew() { return { ok: true }; }, async release() { throw new Error('no separate release'); } },
            userResync: { async resyncPlan() { assert.ok(held); order.push('users'); return { ok: fault !== 'users' }; } },
            pppReadinessGate: { async verifyPlan() { assert.ok(held); order.push('ppp'); return { ok: fault !== 'ppp', relayRevisions: [] }; } },
            finalizer: { async finalizeSucceeded() { throw new Error('legacy publish forbidden'); },
                async probeV2Settlement() { return marker; },
                async beginV2Closure({ bindings }) {
                    marker = freeze({ status: 'committing', retained: true, terminal: { bindings } });
                    order.push('intent'); return true;
                },
                async persistV2TerminalProofs({ proofs }) {
                    assert.equal(require('../services/topologyOperationExecutor').isTopologyTerminalProof(proofs[0]), true);
                    order.push('persist'); if (fault === 'persist') throw new Error('unknown persistence'); return true;
                },
                async finalizeV2Succeeded() { order.push('atomic-settle'); if (fault === 'settle') throw new Error('unknown transaction'); return true; } },
        });
        const result = await worker.run(operation._id);
        if (fault === 'none') {
            assert.equal(result.status, 'succeeded', JSON.stringify(result));
            assert.deepEqual(order, ['intent', 'users', 'ppp', 'persist', 'atomic-settle']);
            assert.deepEqual(events.filter(event => event.method === 'transport').map(event => event.request.command),
                ['prepare', 'commit', 'verify', 'close', 'status']);
        } else {
            assert.equal(result.status, 'committing');
            assert.equal(result.drainUncertain, true);
            const before = [...order]; events.length = 0;
            const recovered = await worker.run(operation._id);
            assert.equal(recovered.errorCode, 'TOPOLOGY_V2_RECOVERY_REQUIRES_SETTLEMENT_REVIEW');
            assert.equal(claims, 1);
            assert.deepEqual(order, before, 'recovery must not retry mutation, close, persistence or settlement');
            assert.deepEqual(events.map(event => event.method), ['resolve', 'transport']);
            assert.equal(events[1].request.command, 'status');
            assert.equal(events[1].request.commandId, marker.terminal.bindings[0].commandIds.close);
        }
        assert.equal(held, 0);
    });
});

test('V2 recovery probes only the persisted close ID without bootstrap or mutating dispatch', async () => {
    const terminal = { phase: 'closed', terminal: true, terminalOutcome: 'verified', completedCommand: 'close' };
    const { executor, reader, events } = executorFixture({ responseOverrides: { close: terminal, status: terminal } });
    reader.withVerifiedBinding = async (expected, work) => work(await reader.readVerified(expected), async () => {});
    reader.withReadOnlyVerifiedBinding = reader.withVerifiedBinding;
    const prepared = await executor.prepare(prepareContext());
    const context = lifecycleContext(prepared);
    await executor.commit(context); await executor.verify(context); await executor.close(context);
    const binding = await reader.readVerified({ nodeId: context.node.node });
    events.length = 0;
    const proof = await executor.probeTerminalBinding(binding);
    assert.equal(proof.commandId, binding.commandIds.close);
    assert.equal(proof.command, 'status');
    assert.deepEqual(events.map(event => event.method), ['resolve', 'transport']);
    assert.equal(events[1].request.command, 'status');
});

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
        executionFence,
        node,
    };
}

function execResult(request, overrides = {}) {
    const { checks: _checks, ...receiptRequest } = request;
    return {
        code: 0,
        stdout: `${JSON.stringify(v2Receipt(receiptRequest, overrides))}\n`,
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

function fixtureReader(host = 'test.infograd.online', backupId) {
    return bindingReader(['portal', 'relay', 'bridge'].map(role => bindingRecord({
        ...prepareContext(frozenNode({ role })), ...(backupId ? { backupId } : {}),
    }, host)));
}

function executorFixture({ responseOverrides = {},
    contour = { target: 'test', hostIdentity: 'test.infograd.online' }, backupId, onEnsureRunner, onResolve } = {}) {
    const events = [];
    const reader = fixtureReader(contour.hostIdentity, backupId);
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
            onResolve?.(reader);
            return nodeSSH;
        },
    };
    class FakeBootstrapper {
        constructor(options) {
            events.push({ method: 'bootstrapper', target: options.target,
                hostIdentity: options.hostIdentity, role: options.role });
        }

        async ensureRunner() {
            events.push({ method: 'ensureRunner' });
            onEnsureRunner?.(reader);
            return { ok: true };
        }
    }
    return {
        events, reader,
        executor: new TopologyOperationExecutor({
            ...contour,
            executionBindingReader: reader,
            nodeExecutionResolver,
            RunnerBootstrapper: FakeBootstrapper,
        }),
    };
}

test('missing durable execution authority refuses before node lookup or bootstrap', async () => {
    const events = [];
    const executor = new TopologyOperationExecutor({
        target: 'test', hostIdentity: 'test.infograd.online',
        nodeExecutionResolver: { async resolve() { events.push('resolve'); return {}; } },
        RunnerBootstrapper: class { async ensureRunner() { events.push('bootstrap'); } },
    });
    await assert.rejects(executor.prepare(prepareContext()), error => {
        assert.equal(error.code, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
        assert.equal(error.remoteOutcomeUncertain, false);
        return true;
    });
    assert.deepEqual(events, []);
});

test('binding authority without explicit trusted connection reader cannot resolve or bootstrap', async () => {
    const { executor, events, reader } = executorFixture();
    delete reader.readVerifiedConnection;
    await assert.rejects(executor.prepare(prepareContext()), {
        code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
    });
    assert.deepEqual(events, []);
});

test('trusted connection authority is read after binding and only its exact pin is passed as resolver second argument', async () => {
    const { SIMULATED_TRUSTED_CONNECTION: pin } = require('./helpers/topologyV2Fixture');
    const reader = fixtureReader('lm1.infograd.online');
    const order = [];
    const read = reader.readVerified.bind(reader);
    reader.readVerified = async expected => { order.push('binding'); return read(expected); };
    const connection = reader.readVerifiedConnection.bind(reader);
    reader.readVerifiedConnection = async (expected, durable) => {
        assert.deepEqual(durable, await read(expected));
        order.push('pin');
        return connection(expected);
    };
    const executor = new TopologyOperationExecutor({ target: 'production', hostIdentity: 'lm1.infograd.online',
        executionBindingReader: reader,
        nodeExecutionResolver: { async resolve(request, trustedConnection) {
            order.push('resolve');
            assert.deepEqual(request, { nodeId: 'portal-node', role: 'portal' });
            assert.equal(trustedConnection, pin);
            assert.equal(Object.isFrozen(trustedConnection.expectedEndpoint), true);
            return {};
        } },
        RunnerBootstrapper: class { async ensureRunner() { order.push('bootstrap'); } },
        NodeTransportFactory: class { async create() { return { async prepare({ artifact: _, ...request }) {
            order.push('prepare'); return v2Receipt({ ...request, command: 'prepare' });
        } }; } },
    });
    await executor.prepare(prepareContext());
    assert.deepEqual(order, ['binding', 'pin', 'resolve', 'binding', 'pin', 'bootstrap', 'binding', 'pin', 'prepare']);
});

test('connection authority rejects missing malformed mutable and cross-binding proof before resolution', async t => {
    const { SIMULATED_TRUSTED_CONNECTION: pin, simulatedConnectionAuthority } = require('./helpers/topologyV2Fixture');
    const cases = {
        missing: () => undefined,
        noPin: row => freeze({ binding: row, connection: undefined }),
        callerShape: () => pin,
        extra: row => freeze({ ...simulatedConnectionAuthority(row), forged: true }),
        mutable: row => ({ binding: row, connection: pin }),
        mutableEndpoint: row => Object.freeze({ binding: row, connection: Object.freeze({
            ...pin, expectedEndpoint: { ...pin.expectedEndpoint },
        }) }),
        invalidHash: row => simulatedConnectionAuthority(row, freeze({ ...pin, expectedHostKeySha256: 'SHA256:forged' })),
        extraEndpoint: row => simulatedConnectionAuthority(row, freeze({ ...pin,
            expectedEndpoint: { ...pin.expectedEndpoint, privateKey: 'request-secret' } })),
        invalidPort: row => simulatedConnectionAuthority(row, freeze({ ...pin,
            expectedEndpoint: { ...pin.expectedEndpoint, port: '22' } })),
        ...Object.fromEntries(['operationId', 'nodeId', 'targetProfile', 'executionContext', 'maintenanceId',
            'generation', 'attemptId', 'bootId', 'owner', 'candidateHash', 'backupId'].map(key => [key,
            row => simulatedConnectionAuthority(freeze({ ...row, [key]: 'foreign' }))])),
        changedCommands: row => simulatedConnectionAuthority(freeze({ ...row,
            commandIds: { ...row.commandIds, close: 'foreign' } })),
    };
    for (const [name, change] of Object.entries(cases)) await t.test(name, async () => {
        const { executor, events, reader } = executorFixture();
        reader.readVerifiedConnection = async () => change(reader.rows.get('portal-node'));
        await assert.rejects(executor.prepare(prepareContext()), {
            code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
        });
        assert.deepEqual(events, []);
    });
});

test('connection authority is revalidated after resolution/bootstrap and before every prepared dispatch', async t => {
    const { SIMULATED_TRUSTED_CONNECTION: pin, simulatedConnectionAuthority } = require('./helpers/topologyV2Fixture');
    for (const boundary of ['resolution', 'bootstrap', 'commit', 'verify', 'rollback', 'cleanupPrepared']) {
        await t.test(boundary, async () => {
            const revoke = reader => { reader.readVerifiedConnection = async expected => simulatedConnectionAuthority(
                reader.rows.get(expected.nodeId), freeze({ ...pin, expectedHostKeySha256: '3'.repeat(64) })); };
            const { executor, reader, events } = executorFixture({
                ...(boundary === 'resolution' ? { onResolve: revoke } : {}),
                ...(boundary === 'bootstrap' ? { onEnsureRunner: revoke } : {}),
            });
            if (['resolution', 'bootstrap'].includes(boundary)) {
                await assert.rejects(executor.prepare(prepareContext()));
                assert.equal(events.some(e => e.method === 'transport'), false);
                if (boundary === 'resolution') assert.equal(events.some(e => e.method === 'bootstrapper'), false);
            } else {
                const prepared = await executor.prepare(prepareContext());
                revoke(reader);
                await assert.rejects(executor[boundary](lifecycleContext(prepared)), {
                    code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
                });
                assert.deepEqual(events.filter(e => e.method === 'transport').map(e => e.request.command), ['prepare']);
            }
        });
    }
});

test('terminal status cannot dispatch after trusted connection authority is revoked by close', async () => {
    const reader = fixtureReader();
    reader.withVerifiedBinding = async (expected, work) => work(await reader.readVerified(expected), async () => {});
    let statuses = 0;
    const terminalReceipt = (request, command) => v2Receipt({ ...request, command }, {
        phase: 'closed', terminal: true, terminalOutcome: 'verified', completedCommand: 'close',
    });
    const executor = new TopologyOperationExecutor({ target: 'test', hostIdentity: 'test.infograd.online',
        executionBindingReader: reader, nodeExecutionResolver: { async resolve() { return {}; } },
        RunnerBootstrapper: class { async ensureRunner() {} },
        NodeTransportFactory: class { async create() { return {
            async prepare({ artifact: _, ...request }) { return v2Receipt({ ...request, command: 'prepare' }); },
            async verify(request) { return v2Receipt({ ...request, command: 'verify' }); },
            async close(request) {
                reader.readVerifiedConnection = async () => { throw new Error('maintenance pin revoked'); };
                return terminalReceipt(request, 'close');
            },
            async status({ completedCommand: _, ...request }) { statuses++; return terminalReceipt(request, 'status'); },
        }; } },
    });
    const prepared = await executor.prepare(prepareContext());
    const context = lifecycleContext(prepared);
    await executor.verify(context);
    await assert.rejects(executor.close(context), { remoteOutcomeUncertain: true });
    assert.equal(statuses, 0);
});

test('production lifecycle seam sends the full server pair and frozen role to bootstrapper', async () => {
    const { executor, events } = executorFixture({
        contour: { target: 'production', hostIdentity: 'lm1.infograd.online' },
    });
    const prepared = await executor.prepare(prepareContext());
    await executor.commit(lifecycleContext(prepared));
    await executor.verify(lifecycleContext(prepared));
    await executor.rollback(lifecycleContext(prepared));
    assert.deepEqual(events.find(event => event.method === 'bootstrapper'), {
        method: 'bootstrapper', target: 'production',
        hostIdentity: 'lm1.infograd.online', role: 'portal',
    });
    assert.deepEqual(events.filter(event => event.method === 'transport').map(event => event.request.command),
        ['prepare', 'commit', 'verify', 'rollback']);
});

test('production default bootstrap enters the paired portal preflight before any write', async () => {
    const calls = [];
    const executor = new TopologyOperationExecutor({
        target: 'production', hostIdentity: 'lm1.infograd.online',
        executionBindingReader: fixtureReader('lm1.infograd.online'),
        nodeExecutionResolver: { async resolve() { return {
            async exec(command) { calls.push(command); return { code: 1, stdout: '', stderr: '' }; },
            async writeFile() { calls.push('upload'); assert.fail('must not upload'); },
        }; } },
    });
    await assert.rejects(executor.prepare(prepareContext()), error => {
        assert.equal(error.cause?.code, 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE');
        return true;
    });
    assert.equal(calls.length, 1);
    assert.match(calls[0], /sha256sum.*celerity-topology-node-runner/);
});

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
    const executor = new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online',
        target: 'test',
        executionBindingReader: fixtureReader(),
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
        executionContext: 'test.infograd.online', attemptId: 'attempt-1',
        generation: executionFence.generation, predecessorGeneration: 'none', commandId: 'prepare-portal-node',
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

test('fails closed on cross-paired context and rejects non-frozen, role-mismatched, or expanded plans before lookup', async () => {
    let resolverCalls = 0;
    const nodeExecutionResolver = {
        async resolve() {
            resolverCalls += 1;
            throw new Error('must not resolve invalid input');
        },
    };

    assert.throws(
        () => new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online',
            target: 'production',
            nodeExecutionResolver,
        }),
        error => error?.code === 'UNSAFE_TOPOLOGY_TARGET',
    );
    assert.throws(
        () => new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online',
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

    const executor = new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online',
        target: 'test',
        nodeExecutionResolver,
    });
    for (const context of invalidContexts) {
        await assert.rejects(executor.prepare(context), error => {
            assert.equal(error.name, 'TopologyOperationExecutorError');
            assert.equal(error.code, 'INVALID_FROZEN_NODE_PLAN');
            assert.equal(error.remoteOutcomeUncertain, false);
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

test('sanitizes hash-bound commit failures while preserving remote uncertainty', async () => {
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
        assert.equal(error.remoteOutcomeUncertain, true);
        assert.equal(error.backupId, prepared.backupId);
        assert.equal(Object.hasOwn(error, 'cause'), false);
        assert.doesNotMatch(JSON.stringify(error), new RegExp(remoteSecret));
        return true;
    });
    assert.deepEqual(
        events.filter(event => event.method === 'transport')
            .map(event => event.request.command),
        ['prepare', 'commit'],
    );
    assert.equal(events.filter(event => event.method === 'resolve').length, 1);
    assert.doesNotMatch(JSON.stringify(executor), new RegExp(remoteSecret));
});

test('transport exceptions cannot claim a commit was locally rejected before dispatch', async t => {
    for (const transportError of [
        Object.assign(new Error('untrusted-error-canary'), { remoteOutcomeUncertain: false }),
        Object.assign(new TopologyOperationExecutorError('INVALID_FROZEN_NODE_PLAN', 'untrusted-error-canary'),
            { remoteOutcomeUncertain: false }),
    ]) await t.test(transportError.name, async () => {
        let commits = 0;
        class NodeTransportFactory {
            async create() { return {
                async prepare({ artifact: _artifact, ...request }) {
                    return v2Receipt({ command: 'prepare', ...request });
                },
                async commit() { commits++; throw transportError; },
            }; }
        }
        const executor = new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online', target: 'test',
            executionBindingReader: fixtureReader(),
            nodeExecutionResolver: { async resolve() { return {}; } },
            RunnerBootstrapper: class { async ensureRunner() {} }, NodeTransportFactory });
        const prepared = await executor.prepare(prepareContext());
        await assert.rejects(executor.commit(lifecycleContext(prepared)), error => {
            assert.equal(error.code, 'TOPOLOGY_OPERATION_EXECUTION_FAILED');
            assert.equal(error.remoteOutcomeUncertain, true);
            assert.equal(error.backupId, prepared.backupId);
            assert.doesNotMatch(JSON.stringify(error), /untrusted-error-canary/);
            return true;
        });
        assert.equal(commits, 1);
    });
});

test('a malformed prepare receipt retains uncertainty and exposes no prepared binding', async () => {
    const remoteSecret = 'malformed-prepare-secret-canary';
    const { events, executor } = executorFixture({
        responseOverrides: {
            prepare: { diagnostics: remoteSecret },
        },
    });

    await assert.rejects(executor.prepare(prepareContext()), error => {
        assert.equal(error.code, 'TOPOLOGY_OPERATION_EXECUTION_FAILED');
        assert.equal(error.remoteOutcomeUncertain, true);
        assert.doesNotMatch(JSON.stringify(error), new RegExp(remoteSecret));
        return true;
    });
    assert.deepEqual(
        events.filter(event => event.method === 'transport')
            .map(event => event.request.command),
        ['prepare'],
    );
    assert.doesNotMatch(JSON.stringify(executor), new RegExp(remoteSecret));
});

test('rehydrates a durable prepared binding without preparing or reading current topology', async () => {
    const { events, executor } = executorFixture({ backupId: 'topology-durable-backup-bridge' });
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
        { method: 'bootstrapper', target: 'test', hostIdentity: 'test.infograd.online', role: 'bridge' },
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
        executionContext: 'test.infograd.online', attemptId: 'attempt-1',
        generation: executionFence.generation, predecessorGeneration: 'none', commandId: 'rollback-bridge-node',
    }]);
    assert.doesNotMatch(JSON.stringify({ executor, rehydrated }), /secret|privateKey|topology-lookup/);
});

// A local timeout does not join the remote prepare process.
test('prepare timeout exposes uncertainty and never races a cleanup command', async () => {
    const calls = [];
    class RunnerBootstrapper { async ensureRunner() {} }
    class NodeTransportFactory {
        async create() { return {
            async prepare() { calls.push('prepare'); throw new Error('local timeout'); },
            async rollback() { calls.push('rollback'); throw new Error('cleanup unavailable'); },
        }; }
    }
    const executor = new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online', target: 'test',
        executionBindingReader: fixtureReader(),
            nodeExecutionResolver: { async resolve() { return {}; } },
        RunnerBootstrapper, NodeTransportFactory });
    await assert.rejects(executor.prepare(prepareContext()), error => {
        assert.equal(error.remoteOutcomeUncertain, true);
        assert.match(error.backupId, /^topology-[a-f0-9]{64}$/);
        return true;
    });
    assert.deepEqual(calls, ['prepare']);
});

test('runner bootstrap timeout is uncertain even before prepare dispatch', async () => {
    const executor = new TopologyOperationExecutor({ hostIdentity: 'test.infograd.online', target: 'test',
        executionBindingReader: fixtureReader(),
            nodeExecutionResolver: { async resolve() { return {}; } },
        RunnerBootstrapper: class { async ensureRunner() { throw new Error('upload timeout'); } },
    });
    await assert.rejects(executor.prepare(prepareContext()), error => {
        assert.equal(error.remoteOutcomeUncertain, true);
        assert.match(error.backupId, /^topology-[a-f0-9]{64}$/);
        return true;
    });
});
test('durable proof precedes bootstrap and binds every V2 command to the canonical host', async () => {
    const { executor, events } = executorFixture();
    const prepared = await executor.prepare(prepareContext());
    for (const command of ['commit', 'verify', 'rollback']) await executor[command](lifecycleContext(prepared));
    for (const event of events.filter(event => event.method === 'transport')) {
        assert.equal(event.request.executionContext, 'test.infograd.online');
        assert.equal(event.request.generation, executionFence.generation);
        assert.equal(event.request.attemptId, 'attempt-1');
        assert.equal(event.request.predecessorGeneration, 'none');
        assert.equal(event.request.commandId, `${event.request.command}-portal-node`);
    }
});

test('ownership lost during bootstrap refuses the prepare command', async () => {
    const { executor, events } = executorFixture({ onEnsureRunner(reader) { reader.rows.clear(); } });
    await assert.rejects(executor.prepare(prepareContext()), error => {
        assert.equal(error.cause?.code, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
        assert.equal(error.remoteOutcomeUncertain, true, 'bootstrap is already a remote boundary');
        return true;
    });
    assert.equal(events.some(event => event.method === 'transport'), false);
});

test('missing foreign stale mutable or incomplete durable bindings fail closed before every external boundary', async t => {
    const cases = {
        missing: () => null,
        foreignHost: row => freeze({ ...row, executionContext: 'lm1.infograd.online' }),
        foreignOperation: row => freeze({ ...row, operationId: 'foreign-operation' }),
        foreignNode: row => freeze({ ...row, nodeId: 'foreign-node' }),
        foreignOwner: row => freeze({ ...row, owner: 'foreign-worker' }),
        staleAttempt: row => freeze({ ...row, attempt: 0 }),
        staleGeneration: row => freeze({ ...row, generation: '00000000-0000-4000-8000-000000000018' }),
        changedCandidate: row => freeze({ ...row, candidateHash: `sha256:${'0'.repeat(64)}` }),
        changedRevision: row => freeze({ ...row, topologyRevision: 18 }),
        mutable: row => ({ ...row }),
        missingPredecessor: row => { const { predecessorGeneration: _old, ...rest } = row; return freeze(rest); },
        reusedCommand: row => freeze({ ...row, commandIds: { ...row.commandIds, commit: row.commandIds.prepare } }),
    };
    for (const [name, change] of Object.entries(cases)) await t.test(name, async () => {
        const { executor, events, reader } = executorFixture();
        reader.rows.set('portal-node', change(reader.rows.get('portal-node')));
        await assert.rejects(executor.prepare(prepareContext()), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false });
        assert.deepEqual(events, []);
    });
});

test('lifecycle rereads durable authority and rejects changed IDs without dispatch', async t => {
    for (const command of ['commit', 'verify', 'rollback', 'cleanupPrepared']) await t.test(command, async () => {
        const { executor, events, reader } = executorFixture();
        const prepared = await executor.prepare(prepareContext());
        const original = reader.rows.get('portal-node');
        reader.rows.set('portal-node', freeze({ ...original,
            predecessorGeneration: 'foreign-predecessor',
            commandIds: { ...original.commandIds, commit: 'replaced-command' },
        }));
        await assert.rejects(executor[command](lifecycleContext(prepared)), {
            code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
        });
        assert.deepEqual(events.filter(event => event.method === 'transport').map(event => event.request.command), ['prepare']);
    });
});

test('recovery cannot adopt a fresh acquired generation or request-supplied predecessor', async () => {
    const { executor, events } = executorFixture({ backupId: 'durable-backup' });
    await assert.rejects(executor.rehydrate({ ...prepareContext(), backupId: 'durable-backup',
        executionFence: Object.freeze({ ...executionFence, generation: '00000000-0000-4000-8000-000000000018' }),
    }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    await assert.rejects(executor.prepare({ ...prepareContext(), predecessorGeneration: 'none' }), { code: 'INVALID_FROZEN_NODE_PLAN' });
    assert.deepEqual(events, []);
});

test('ownership lost during node resolution cannot enter bootstrap', async () => {
    const { executor, events } = executorFixture({ onResolve(reader) { reader.rows.clear(); } });
    await assert.rejects(executor.prepare(prepareContext()));
    assert.deepEqual(events.map(event => event.method), ['resolve']);
});
