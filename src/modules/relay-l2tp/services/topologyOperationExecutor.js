'use strict';

const { createHash } = require('node:crypto');

const {
    TopologyNodeTransportFactory,
} = require('./topologyNodeTransportFactory');
const {
    TopologyRunnerBootstrapper,
} = require('./topologyRunnerBootstrapper');
const {
    projectCanonicalXrayCandidate,
} = require('./topologyXrayCandidate');

const TEST_TARGET = 'test';
const { topologyExecutionContext } = require('../domain/topologyExecutionContext');
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CONTEXT_KEYS = Object.freeze([
    'executionFence',
    'node',
    'operationId',
    'priorDeployedRevision',
    'topologyRevision',
]);
const LIFECYCLE_CONTEXT_KEYS = Object.freeze([
    'backupId',
    ...CONTEXT_KEYS,
    'prepared',
].sort());
const REHYDRATE_CONTEXT_KEYS = Object.freeze([
    'backupId',
    ...CONTEXT_KEYS,
].sort());
const NODE_KEYS = Object.freeze([
    'candidate',
    'candidateHash',
    'checks',
    'configPath',
    'node',
    'nodeRef',
    'role',
    'serviceUnit',
    'serviceUnitPath',
    'targetProfile',
]);
const PUBLIC_RECEIPT_KEYS = Object.freeze([
    'backupId',
    'candidateHash',
    'command',
    'nodeId',
    'ok',
    'operationId',
    'targetProfile',
]);
const TARGET_BY_ROLE = Object.freeze({
    portal: Object.freeze({
        targetProfile: 'xray-main',
        serviceUnit: 'xray.service',
        serviceUnitPath: '/etc/systemd/system/xray.service',
        configPath: '/usr/local/etc/xray/config.json',
    }),
    relay: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
    bridge: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
});

class TopologyOperationExecutorError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'TopologyOperationExecutorError';
        this.code = code;
    }
}

function hasExactKeys(value, expectedKeys) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function isDeepFrozen(value) {
    if (!value || typeof value !== 'object') return true;
    if (!Object.isFrozen(value)) return false;
    return Object.values(value).every(isDeepFrozen);
}

function invalidPlan() {
    return new TopologyOperationExecutorError(
        'INVALID_FROZEN_NODE_PLAN',
        'Invalid frozen topology node plan',
    );
}

function executionFailed() {
    return new TopologyOperationExecutorError(
        'TOPOLOGY_OPERATION_EXECUTION_FAILED',
        'Topology node operation failed',
    );
}

const { validNodeRef } = require('./topologyNodeRef');

function validChecks(checks, target) {
    return Array.isArray(checks) && checks.every(check => {
        if (check?.type === 'service') {
            return hasExactKeys(check, ['expectedState', 'serviceUnit', 'type'])
                && check.serviceUnit === target.serviceUnit
                && check.expectedState === 'active';
        }
        if (check?.type === 'port') {
            return hasExactKeys(check, ['expectedState', 'port', 'protocol', 'type'])
                && check.protocol === 'tcp'
                && Number.isSafeInteger(check.port)
                && check.port >= 1
                && check.port <= 65535
                && check.expectedState === 'listening';
        }
        return false;
    });
}

function projectFrozenNode(context, durableBackupId) {
    if (!hasExactKeys(context, CONTEXT_KEYS)
        || typeof context.operationId !== 'string'
        || !SAFE_ID_PATTERN.test(context.operationId)
        || !Number.isSafeInteger(context.topologyRevision)
        || context.topologyRevision < 0
        || !Number.isSafeInteger(context.priorDeployedRevision)
        || context.priorDeployedRevision < 0
        || !isDeepFrozen(context.node)
        || !hasExactKeys(context.node, NODE_KEYS)) {
        throw invalidPlan();
    }

    const node = context.node;
    const target = TARGET_BY_ROLE[node.role];
    if (!target
        || typeof node.node !== 'string'
        || !SAFE_ID_PATTERN.test(node.node)
        || typeof node.nodeRef !== 'string'
        || !validNodeRef(node.role, node.nodeRef)
        || node.targetProfile !== target.targetProfile
        || node.serviceUnit !== target.serviceUnit
        || node.serviceUnitPath !== target.serviceUnitPath
        || node.configPath !== target.configPath
        || !validChecks(node.checks, target)) {
        throw invalidPlan();
    }

    let projectedCandidate;
    try {
        projectedCandidate = projectCanonicalXrayCandidate(node.candidate, node.candidateHash);
    } catch {
        throw invalidPlan();
    }
    const content = projectedCandidate.content;
    const candidateHash = `sha256:${node.candidateHash}`;
    const generatedBackupId = `topology-${createHash('sha256').update([
        context.operationId,
        node.node,
        candidateHash,
        node.targetProfile,
    ].join('\0')).digest('hex')}`;
    const backupId = durableBackupId === undefined ? generatedBackupId : durableBackupId;
    if (typeof backupId !== 'string' || !SAFE_ID_PATTERN.test(backupId)) throw invalidPlan();
    return Object.freeze({
        operationId: context.operationId,
        nodeId: node.node,
        role: node.role,
        candidateHash,
        backupId,
        targetProfile: node.targetProfile,
        checks: node.checks,
        content,
    });
}

const COMMANDS = Object.freeze(['prepare', 'commit', 'verify', 'rollback', 'close']);
const FENCE_KEYS = Object.freeze(['executionContext', 'attemptId', 'generation', 'predecessorGeneration']);
const RECORD_KEYS = Object.freeze([
    'operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile',
    'topologyRevision', 'priorDeployedRevision', 'owner', 'attempt',
    ...FENCE_KEYS, 'commandIds', 'bootId', 'maintenanceId',
].sort());
const V2_RECEIPT_KEYS = Object.freeze([
    ...PUBLIC_RECEIPT_KEYS, ...FENCE_KEYS, 'commandId', 'protocolVersion',
    'completion', 'phase', 'terminal', 'terminalOutcome', 'ownershipRetained',
    'bootId', 'systemdJob', 'serviceState', 'completedCommand',
].sort());
function unprovenBinding() {
    return new TopologyOperationExecutorError(
        'TOPOLOGY_EXECUTION_BINDING_UNPROVEN',
        'Durable topology execution binding is unproven',
    );
}
function safeToken(value) {
    return typeof value === 'string' && SAFE_ID_PATTERN.test(value) && !['.', '..'].includes(value);
}
function transportRequest(binding, command) {
    return {
        operationId: binding.operationId,
        nodeId: binding.nodeId,
        candidateHash: binding.candidateHash,
        backupId: binding.backupId,
        targetProfile: binding.targetProfile,
        ...Object.fromEntries(FENCE_KEYS.map(key => [key, binding.durable[key]])),
        commandId: binding.durable.commandIds[command],
        ...(command === 'verify' ? { checks: binding.checks } : {}),
    };
}
function assertReceipt(receipt, command, binding) {
    const expected = transportRequest(binding, command);
    if (!hasExactKeys(receipt, V2_RECEIPT_KEYS)
        || receipt.ok !== true || receipt.command !== command
        || receipt.protocolVersion !== 2 || receipt.completion !== 'completed'
        || receipt.phase !== ({ prepare: 'prepared', commit: 'committed', verify: 'verified', rollback: 'rolledback' })[command]
        || receipt.terminal !== false || receipt.terminalOutcome !== 'not-terminal'
        || receipt.ownershipRetained !== true || receipt.bootId !== binding.durable.bootId
        || receipt.completedCommand !== command
        || receipt.systemdJob !== (command === 'prepare' ? 'not-applicable' : 'completed')
        || (command === 'prepare' ? receipt.serviceState !== 'not-applicable'
            : receipt.serviceState !== 'active:running'
                && !(command === 'rollback' && receipt.serviceState === 'inactive:dead'))
        || Object.keys(expected).some(key => key !== 'checks' && receipt[key] !== expected[key])) {
        throw executionFailed();
    }
    // Preserve the public typed executor receipt semantics. This is explicitly
    // NOT a terminal V2 readback or authority to release database ownership.
    return Object.freeze(Object.fromEntries(PUBLIC_RECEIPT_KEYS.map(key => [key, receipt[key]])));
}

function assertTerminalReceipt(receipt, command, binding, outcome) {
    const expected = transportRequest(binding, 'close');
    if (!hasExactKeys(receipt, V2_RECEIPT_KEYS)
        || receipt.ok !== true || receipt.command !== command
        || receipt.protocolVersion !== 2 || receipt.completion !== 'completed'
        || receipt.phase !== 'closed' || receipt.terminal !== true
        || receipt.terminalOutcome !== outcome || receipt.ownershipRetained !== true
        || receipt.bootId !== binding.durable.bootId || receipt.completedCommand !== 'close'
        || receipt.systemdJob !== 'completed'
        || !(receipt.serviceState === 'active:running'
            || (outcome === 'rolledback' && receipt.serviceState === 'inactive:dead'))
        || Object.keys(expected).some(key => receipt[key] !== expected[key])) throw executionFailed();
    return Object.freeze({ ...receipt });
}

function preparedReceipt(binding) {
    return Object.freeze({
        ok: true,
        command: 'prepare',
        operationId: binding.operationId,
        nodeId: binding.nodeId,
        candidateHash: binding.candidateHash,
        backupId: binding.backupId,
        targetProfile: binding.targetProfile,
    });
}

class TopologyOperationExecutor {
    #target;
    #hostIdentity;
    #nodeExecutionResolver;
    #RunnerBootstrapper;
    #NodeTransportFactory;
    #preparedBindings = new WeakMap();
    #executionBindingReader;

    constructor(options = {}) {
        const allowedKeys = new Set([
            'NodeTransportFactory',
            'RunnerBootstrapper',
            'nodeExecutionResolver',
            'target',
            'hostIdentity',
            'executionBindingReader',
        ]);
        if (!options || typeof options !== 'object' || Array.isArray(options)
            || Object.keys(options).some(key => !allowedKeys.has(key))) {
            throw new TopologyOperationExecutorError(
                'INVALID_EXECUTOR_CONFIGURATION',
                'Invalid topology operation executor configuration',
            );
        }
        const {
            target,
            hostIdentity,
            nodeExecutionResolver,
            executionBindingReader,
            RunnerBootstrapper = TopologyRunnerBootstrapper,
            NodeTransportFactory = TopologyNodeTransportFactory,
        } = options;
        if (!topologyExecutionContext(target, hostIdentity)) {
            throw new TopologyOperationExecutorError(
                'UNSAFE_TOPOLOGY_TARGET',
                'Topology execution requires an exact server execution context',
            );
        }
        if (!nodeExecutionResolver || typeof nodeExecutionResolver.resolve !== 'function') {
            throw new TypeError('TopologyOperationExecutor requires nodeExecutionResolver.resolve');
        }
        if (typeof RunnerBootstrapper !== 'function' || typeof NodeTransportFactory !== 'function') {
            throw new TypeError('TopologyOperationExecutor requires fixed topology lifecycle adapters');
        }
        if (executionBindingReader !== undefined
            && typeof executionBindingReader?.readVerified !== 'function') {
            throw new TypeError('Topology executor binding reader requires readVerified');
        }
        this.#executionBindingReader = executionBindingReader;
        this.#target = target;
        this.#hostIdentity = hostIdentity;
        this.#nodeExecutionResolver = nodeExecutionResolver;
        this.#RunnerBootstrapper = RunnerBootstrapper;
        this.#NodeTransportFactory = NodeTransportFactory;
    }

    // Real V2 execution never grants classic/bootstrap quiescence or handback.
    get executionProtocolVersion() { return 2; }

    // Trusted server-owned seam only. readVerified must establish persisted
    // immutable binding + current exact claim/physical-node lock ownership;
    // a frozen object by itself is NOT durability or remote enrollment proof.
    // No production implementation is installed by the composed runtime.
    async #proveBinding(context, binding, previous, reader = this.#executionBindingReader) {
        const fence = context.executionFence;
        if (!this.#executionBindingReader
            || !hasExactKeys(fence, ['attempt', 'generation', 'owner'])
            || !Object.isFrozen(fence) || !safeToken(fence.owner)
            || !Number.isSafeInteger(fence.attempt) || fence.attempt < 1
            || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(fence.generation)) {
            throw unprovenBinding();
        }
        const expected = Object.freeze({
            executionContext: this.#hostIdentity,
            operationId: binding.operationId, nodeId: binding.nodeId,
            candidateHash: binding.candidateHash, backupId: binding.backupId,
            targetProfile: binding.targetProfile,
            topologyRevision: context.topologyRevision,
            priorDeployedRevision: context.priorDeployedRevision,
            ...fence,
        });
        let durable;
        try { durable = await reader.readVerified(expected); }
        catch { throw unprovenBinding(); }
        if (!hasExactKeys(durable, RECORD_KEYS) || !isDeepFrozen(durable)
            || Object.entries(expected).some(([key, value]) => durable[key] !== value)
            || !safeToken(durable.attemptId) || !safeToken(durable.predecessorGeneration)
            || !safeToken(durable.bootId) || !safeToken(durable.maintenanceId)
            || durable.generation === 'none' || durable.predecessorGeneration === durable.generation
            || !hasExactKeys(durable.commandIds, [...COMMANDS].sort())
            || !Object.values(durable.commandIds).every(safeToken)
            || new Set(Object.values(durable.commandIds)).size !== COMMANDS.length
            || (previous && RECORD_KEYS.some(key => key === 'commandIds'
                ? COMMANDS.some(command => durable.commandIds[command] !== previous.commandIds[command])
                : durable[key] !== previous[key]))) throw unprovenBinding();
        return Object.freeze({ ...binding, durable, expected });
    }

    async #createTransport(binding, context) {
        const nodeSSH = await this.#nodeExecutionResolver.resolve({
            nodeId: binding.nodeId,
            role: binding.role,
        });
        await this.#proveBinding(context, binding, binding.durable);
        const bootstrapper = new this.#RunnerBootstrapper({
            nodeSSH,
            target: this.#target,
            hostIdentity: this.#hostIdentity,
            role: binding.role,
        });
        await bootstrapper.ensureRunner();
        const factory = new this.#NodeTransportFactory({
            executionContext: this.#hostIdentity,
            nodeExecutionResolver: {
                resolve: async () => nodeSSH,
            },
        });
        return factory.create({
            nodeId: binding.nodeId,
            role: binding.role,
        });
    }

    async prepare(context) {
        let binding;
        try {
            binding = projectFrozenNode(context);
            binding = await this.#proveBinding(context, binding);
        } catch (error) {
            // Local validation is the only failure before any remote adapter.
            error.remoteOutcomeUncertain = false;
            throw error;
        }
        try {
            const transport = await this.#createTransport(binding, context);
            await this.#proveBinding(context, binding, binding.durable);
            const receipt = assertReceipt(await transport.prepare({
                ...transportRequest(binding, 'prepare'),
                artifact: {
                    id: 'xray-config',
                    content: binding.content,
                },
            }), 'prepare', binding);
            this.#preparedBindings.set(receipt, { binding, transport });
            return Object.freeze({
                ok: true,
                backupId: binding.backupId,
                prepared: receipt,
            });
        } catch (error) {
            // A rejected/malformed prepare response cannot prove the remote
            // process has exited. Do not race it with rollback or infer safety
            // from a later rollback receipt; retain the exact backup identity.
            const wrapped = executionFailed();
            // Runner bootstrap can itself time out with a remote writer alive.
            wrapped.remoteOutcomeUncertain = true;
            wrapped.backupId = binding.backupId;
            wrapped.cause = error;
            throw wrapped;
        }
    }

    async rehydrate(context) {
        if (!hasExactKeys(context, REHYDRATE_CONTEXT_KEYS)
            || typeof context.backupId !== 'string'
            || !SAFE_ID_PATTERN.test(context.backupId)) {
            throw invalidPlan();
        }
        try {
            let binding = projectFrozenNode({
                executionFence: context.executionFence,
                operationId: context.operationId,
                topologyRevision: context.topologyRevision,
                priorDeployedRevision: context.priorDeployedRevision,
                node: context.node,
            }, context.backupId);
            binding = await this.#proveBinding(context, binding);
            const transport = await this.#createTransport(binding, context);
            const prepared = preparedReceipt(binding);
            this.#preparedBindings.set(prepared, { binding, transport });
            return Object.freeze({
                ok: true,
                backupId: binding.backupId,
                prepared,
            });
        } catch (error) {
            if (error instanceof TopologyOperationExecutorError
                && ['INVALID_FROZEN_NODE_PLAN', 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN'].includes(error.code)) {
                throw error;
            }
            throw executionFailed();
        }
    }

    #preparedBinding(context) {
        if (!hasExactKeys(context, LIFECYCLE_CONTEXT_KEYS)
            || typeof context.backupId !== 'string'
            || !SAFE_ID_PATTERN.test(context.backupId)
            || !context.prepared
            || typeof context.prepared !== 'object'
            || !Object.isFrozen(context.prepared)) {
            throw invalidPlan();
        }
        const projected = projectFrozenNode({
            executionFence: context.executionFence,
            operationId: context.operationId,
            topologyRevision: context.topologyRevision,
            priorDeployedRevision: context.priorDeployedRevision,
            node: context.node,
        }, context.backupId);
        const state = this.#preparedBindings.get(context.prepared);
        if (!state
            || context.backupId !== state.binding.backupId
            || projected.operationId !== state.binding.operationId
            || projected.nodeId !== state.binding.nodeId
            || projected.role !== state.binding.role
            || projected.candidateHash !== state.binding.candidateHash
            || projected.backupId !== state.binding.backupId
            || projected.targetProfile !== state.binding.targetProfile) {
            throw invalidPlan();
        }
        return state;
    }

    async #invokePrepared(command, context) {
        let state, ownsBusy = false;
        try {
            state = this.#preparedBinding(context);
            if (state.phase === 'rollback') throw invalidPlan();
            if (state.busy || state.uncertain || state.terminal) throw unprovenBinding();
            state.busy = true;
            ownsBusy = true;
            await this.#proveBinding(context, state.binding, state.binding.durable);
        } catch (error) {
            // Only our local binding validation proves no command was invoked.
            if (ownsBusy) state.busy = false;
            error.remoteOutcomeUncertain = false;
            throw error;
        }
        try {
            const receipt = assertReceipt(
                await state.transport[command](transportRequest(
                    state.binding,
                    command,
                )),
                command,
                state.binding,
            );
            state.phase = command;
            return receipt;
        } catch {
            state.uncertain = true;
            const wrapped = executionFailed();
            if (COMMANDS.includes(command)) {
                // Transport rejection, nonzero exit, or a malformed receipt
                // cannot prove the remote writer has exited. Never propagate
                // a transport-supplied pre-dispatch claim across this boundary.
                wrapped.remoteOutcomeUncertain = true;
                wrapped.backupId = state.binding.backupId;
            }
            throw wrapped;
        } finally {
            state.busy = false;
        }
    }

    // DORMANT data-only API: never called by worker; never releases ownership.
    async close(context) {
        const state = this.#preparedBinding(context);
        if (state.busy || state.uncertain || state.terminal
            || !['verify', 'rollback'].includes(state.phase)
            || typeof this.#executionBindingReader?.withVerifiedBinding !== 'function') {
            throw unprovenBinding();
        }
        state.busy = true;
        try {
            const binding = await this.#proveBinding(context, state.binding, state.binding.durable);
            const outcome = state.phase === 'verify' ? 'verified' : 'rolledback';
            const proof = await this.#executionBindingReader.withVerifiedBinding(binding.expected,
                async (durable, assertCurrent) => {
                    if (typeof assertCurrent !== 'function') throw unprovenBinding();
                    await this.#proveBinding(context, binding, binding.durable, {
                        readVerified: async () => durable,
                    });
                    await assertCurrent();
                    const closed = assertTerminalReceipt(await state.transport.close(
                        transportRequest(binding, 'close')), 'close', binding, outcome);
                    await assertCurrent();
                    // Status queries the exact durable close ID, not a newly minted command.
                    const status = assertTerminalReceipt(await state.transport.status({
                        ...transportRequest(binding, 'close'), completedCommand: 'close',
                    }), 'status', binding, outcome);
                    if (V2_RECEIPT_KEYS.some(key => key !== 'command' && status[key] !== closed[key])) {
                        throw executionFailed();
                    }
                    await assertCurrent();
                    return status;
                });
            state.terminal = true;
            return proof;
        } catch (error) {
            state.uncertain = true;
            const wrapped = executionFailed();
            wrapped.remoteOutcomeUncertain = true;
            wrapped.backupId = state.binding.backupId;
            wrapped.cause = error;
            throw wrapped;
        } finally { state.busy = false; }
    }

    commit(context) {
        return this.#invokePrepared('commit', context);
    }

    verify(context) {
        return this.#invokePrepared('verify', context);
    }

    cleanupPrepared(context) {
        // Prepare stages without activation; request its bound rollback only.
        // This receipt is not terminal readback or classic/bootstrap handback.
        // The worker retains ownership for every V2 lifecycle outcome.
        return this.#invokePrepared('rollback', context);
    }

    rollback(context) {
        return this.#invokePrepared('rollback', context);
    }
}

module.exports = {
    TEST_TARGET,
    TopologyOperationExecutor,
    TopologyOperationExecutorError,
    isDeepFrozen,
};
