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
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CONTEXT_KEYS = Object.freeze([
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
const RECEIPT_KEYS = Object.freeze([
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

function validNodeRef(role, nodeRef) {
    if (role === 'relay') return /^relay-[1-9][0-9]*$/.test(nodeRef);
    // The default bridge keeps the plain 'bridge' ref; geo-routing branch
    // bridges get deterministic 'bridge-N' refs.
    if (role === 'bridge') return /^bridge(-[1-9][0-9]*)?$/.test(nodeRef);
    // Single-portal chains keep 'portal'; fan-in domains use 'portal-N'.
    if (role === 'portal') return /^portal(-[1-9][0-9]*)?$/.test(nodeRef);
    return nodeRef === role;
}

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

function transportRequest(binding, includeChecks = false) {
    return {
        operationId: binding.operationId,
        nodeId: binding.nodeId,
        candidateHash: binding.candidateHash,
        backupId: binding.backupId,
        targetProfile: binding.targetProfile,
        ...(includeChecks ? { checks: binding.checks } : {}),
    };
}

function assertReceipt(receipt, command, binding) {
    if (!hasExactKeys(receipt, RECEIPT_KEYS)
        || receipt.ok !== true
        || receipt.command !== command
        || receipt.operationId !== binding.operationId
        || receipt.nodeId !== binding.nodeId
        || receipt.candidateHash !== binding.candidateHash
        || receipt.backupId !== binding.backupId
        || receipt.targetProfile !== binding.targetProfile) {
        throw executionFailed();
    }
    return Object.freeze({
        ok: true,
        command,
        operationId: binding.operationId,
        nodeId: binding.nodeId,
        candidateHash: binding.candidateHash,
        backupId: binding.backupId,
        targetProfile: binding.targetProfile,
    });
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
    #nodeExecutionResolver;
    #RunnerBootstrapper;
    #NodeTransportFactory;
    #preparedBindings = new WeakMap();

    constructor(options = {}) {
        const allowedKeys = new Set([
            'NodeTransportFactory',
            'RunnerBootstrapper',
            'nodeExecutionResolver',
            'target',
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
            nodeExecutionResolver,
            RunnerBootstrapper = TopologyRunnerBootstrapper,
            NodeTransportFactory = TopologyNodeTransportFactory,
        } = options;
        if (target !== TEST_TARGET) {
            throw new TopologyOperationExecutorError(
                'UNSAFE_TOPOLOGY_TARGET',
                'Topology execution is restricted to the test target',
            );
        }
        if (!nodeExecutionResolver || typeof nodeExecutionResolver.resolve !== 'function') {
            throw new TypeError('TopologyOperationExecutor requires nodeExecutionResolver.resolve');
        }
        if (typeof RunnerBootstrapper !== 'function' || typeof NodeTransportFactory !== 'function') {
            throw new TypeError('TopologyOperationExecutor requires fixed topology lifecycle adapters');
        }
        this.#target = target;
        this.#nodeExecutionResolver = nodeExecutionResolver;
        this.#RunnerBootstrapper = RunnerBootstrapper;
        this.#NodeTransportFactory = NodeTransportFactory;
    }

    async #createTransport(binding) {
        const nodeSSH = await this.#nodeExecutionResolver.resolve({
            nodeId: binding.nodeId,
            role: binding.role,
        });
        const bootstrapper = new this.#RunnerBootstrapper({
            nodeSSH,
            target: this.#target,
        });
        await bootstrapper.ensureRunner();
        const factory = new this.#NodeTransportFactory({
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
        const binding = projectFrozenNode(context);
        let transport;
        try {
            transport = await this.#createTransport(binding);
            const receipt = assertReceipt(await transport.prepare({
                ...transportRequest(binding),
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
            if (transport) {
                try {
                    await transport.rollback(transportRequest(binding));
                } catch {
                    // Fixed rollback is the only cleanup fallback after prepare starts.
                }
            }
            if (error instanceof TopologyOperationExecutorError
                && error.code === 'INVALID_FROZEN_NODE_PLAN') {
                throw error;
            }
            const wrapped = executionFailed();
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
            const binding = projectFrozenNode({
                operationId: context.operationId,
                topologyRevision: context.topologyRevision,
                priorDeployedRevision: context.priorDeployedRevision,
                node: context.node,
            }, context.backupId);
            const transport = await this.#createTransport(binding);
            const prepared = preparedReceipt(binding);
            this.#preparedBindings.set(prepared, { binding, transport });
            return Object.freeze({
                ok: true,
                backupId: binding.backupId,
                prepared,
            });
        } catch (error) {
            if (error instanceof TopologyOperationExecutorError
                && error.code === 'INVALID_FROZEN_NODE_PLAN') {
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

    async #invokePrepared(command, context, release = false) {
        const state = this.#preparedBinding(context);
        try {
            return assertReceipt(
                await state.transport[command](transportRequest(
                    state.binding,
                    command === 'verify',
                )),
                command,
                state.binding,
            );
        } catch (error) {
            if (error instanceof TopologyOperationExecutorError
                && error.code === 'INVALID_FROZEN_NODE_PLAN') {
                throw error;
            }
            throw executionFailed();
        } finally {
            if (release) this.#preparedBindings.delete(context.prepared);
        }
    }

    commit(context) {
        return this.#invokePrepared('commit', context);
    }

    verify(context) {
        return this.#invokePrepared('verify', context);
    }

    cleanupPrepared(context) {
        // The fixed runner's prepare command stages and validates only; it never activates.
        // Its closed rollback command therefore removes/restores that prepared state safely.
        return this.#invokePrepared('rollback', context, true);
    }

    rollback(context) {
        return this.#invokePrepared('rollback', context, true);
    }
}

module.exports = {
    TEST_TARGET,
    TopologyOperationExecutor,
    TopologyOperationExecutorError,
    isDeepFrozen,
};
