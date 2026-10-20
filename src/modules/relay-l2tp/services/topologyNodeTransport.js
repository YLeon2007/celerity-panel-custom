'use strict';

const { createHash } = require('node:crypto');

const TOPOLOGY_NODE_RUNNER_PATH = '/usr/local/bin/celerity-topology-node-runner';
const TOPOLOGY_NODE_ARTIFACT_ID = 'xray-config';
const TOPOLOGY_NODE_COMMANDS = Object.freeze({
    PREPARE: 'prepare',
    COMMIT: 'commit',
    VERIFY: 'verify',
    ROLLBACK: 'rollback',
    CLOSE: 'close',
    STATUS: 'status',
});
const TARGET_PROFILES = new Set(['xray-main', 'xray-bridge']);
const SERVICE_BY_TARGET_PROFILE = Object.freeze({
    'xray-main': 'xray.service',
    'xray-bridge': 'xray-bridge.service',
});
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CANDIDATE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const FENCE_KEYS = Object.freeze(['executionContext', 'attemptId', 'generation', 'predecessorGeneration', 'commandId']);
const BASE_KEYS = Object.freeze([
    ...FENCE_KEYS,
    'backupId',
    'candidateHash',
    'nodeId',
    'operationId',
    'targetProfile',
]);
const RECEIPT_KEYS = Object.freeze([
    ...BASE_KEYS,
    'command',
    'ok', 'protocolVersion', 'completion', 'phase', 'terminal', 'terminalOutcome',
    'ownershipRetained', 'bootId', 'systemdJob', 'serviceState', 'completedCommand',
].sort());

class TopologyNodeTransportError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'TopologyNodeTransportError';
        this.code = code;
        this.ownershipRetained = true;
        this.remoteOutcomeUnknown = ['INVALID_RECEIPT', 'ARTIFACT_INVOCATION_FAILED'].includes(code);
    }
}

function hasExactKeys(value, expectedKeys) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function assertBasePlan(plan, extraKeys = []) {
    if (!hasExactKeys(plan, [...BASE_KEYS, ...extraKeys].sort())) {
        throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid topology node plan');
    }
    if (BASE_KEYS.some(key => typeof plan[key] !== 'string')
        || !SAFE_ID_PATTERN.test(plan.operationId)
        || !SAFE_ID_PATTERN.test(plan.nodeId)
        || !SAFE_ID_PATTERN.test(plan.backupId)
        || ['attemptId', 'generation', 'predecessorGeneration', 'commandId'].some(key => !SAFE_ID_PATTERN.test(plan[key]) || ['.', '..'].includes(plan[key]))
        || ['.', '..'].includes(plan.operationId) || ['.', '..'].includes(plan.nodeId) || ['.', '..'].includes(plan.backupId)
        || plan.generation === 'none'
        || !['test.infograd.online', 'lm1.infograd.online'].includes(plan.executionContext)
        || !CANDIDATE_HASH_PATTERN.test(plan.candidateHash)
        || !TARGET_PROFILES.has(plan.targetProfile)) {
        throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid topology node plan');
    }
}

function validChecks(checks, targetProfile) {
    const serviceUnit = SERVICE_BY_TARGET_PROFILE[targetProfile];
    return Array.isArray(checks) && checks.every(check => {
        if (check?.type === 'service') {
            return hasExactKeys(check, ['expectedState', 'serviceUnit', 'type'])
                && check.serviceUnit === serviceUnit
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

function isCanonicalXrayConfig(content) {
    let document;
    try {
        document = JSON.parse(content);
    } catch {
        return false;
    }
    return Boolean(document)
        && typeof document === 'object'
        && !Array.isArray(document)
        && Array.isArray(document.inbounds)
        && Array.isArray(document.outbounds)
        && content === `${JSON.stringify(document)}\n`;
}

function assertArtifact(artifact, candidateHash) {
    if (!hasExactKeys(artifact, ['content', 'id'])
        || artifact.id !== TOPOLOGY_NODE_ARTIFACT_ID
        || typeof artifact.content !== 'string'
        || !isCanonicalXrayConfig(artifact.content)) {
        throw new TopologyNodeTransportError('INVALID_ARTIFACT', 'Invalid topology node artifact');
    }
    const actualHash = `sha256:${createHash('sha256').update(artifact.content).digest('hex')}`;
    if (actualHash !== candidateHash) {
        throw new TopologyNodeTransportError('CANDIDATE_HASH_MISMATCH', 'Topology candidate hash mismatch');
    }
}

// Completion is bounded to this runner's admitted commands, not arbitrary host
// writers, bootstrap uploads, classic config ownership or database lock release.
function validCompletion(receipt, completedCommand) {
    const phases = { prepare: 'prepared', commit: 'committed', verify: 'verified', rollback: 'rolledback', close: 'closed' };
    if (receipt.protocolVersion !== 2 || receipt.completion !== 'completed'
        || receipt.ownershipRetained !== true || typeof receipt.bootId !== 'string'
        || !SAFE_ID_PATTERN.test(receipt.bootId)
        || receipt.completedCommand !== completedCommand || !Object.hasOwn(phases, completedCommand)
        || receipt.phase !== phases[completedCommand]
        || receipt.terminal !== (completedCommand === 'close')) return false;
    if (completedCommand === 'close') {
        if (!['verified', 'rolledback', 'cancelled'].includes(receipt.terminalOutcome)) return false;
    } else if (receipt.terminalOutcome !== 'not-terminal') return false;
    if (completedCommand === 'prepare' || receipt.terminalOutcome === 'cancelled') {
        return receipt.systemdJob === 'not-applicable' && receipt.serviceState === 'not-applicable';
    }
    return receipt.systemdJob === 'completed'
        && (receipt.serviceState === 'active:running'
            || ((completedCommand === 'rollback' || receipt.terminalOutcome === 'rolledback')
                && receipt.serviceState === 'inactive:dead'));
}

function parseReceipt(result, command, expected) {
    if (!result || typeof result !== 'object'
        || result.code !== 0
        || result.stderr !== ''
        || typeof result.stdout !== 'string'
        || !result.stdout.endsWith('\n')) {
        const error = new TopologyNodeTransportError(
            'INVALID_RECEIPT',
            'Invalid topology node receipt',
        );
        // Keep the error sanitized for API consumers (untrusted node output);
        // diagnostics go to the server log only.
        try {
            const logger = require('../../../utils/logger');
            logger.error('[TopologyNodeTransport] invalid receipt; remote outcome unknown, ownership retained');
        } catch { /* logger unavailable in tests */ }
        throw error;
    }
    const serialized = result.stdout.slice(0, -1);
    if (!serialized || /[\r\n]/.test(serialized)) {
        throw new TopologyNodeTransportError('INVALID_RECEIPT', 'Invalid topology node receipt');
    }
    let receipt;
    try {
        receipt = JSON.parse(serialized);
    } catch {
        throw new TopologyNodeTransportError('INVALID_RECEIPT', 'Invalid topology node receipt');
    }
    if (!hasExactKeys(receipt, RECEIPT_KEYS)
        || receipt.ok !== true
        || JSON.stringify(receipt) !== serialized
        || receipt.command !== command
        || !validCompletion(receipt, command === 'status' ? expected.completedCommand : command)
        || BASE_KEYS.some(key => receipt[key] !== expected[key])) {
        throw new TopologyNodeTransportError('INVALID_RECEIPT', 'Invalid topology node receipt');
    }
    return Object.freeze({ ...receipt });
}

class TopologyNodeTransport {
    #invokeArtifact;

    constructor({ invokeArtifact } = {}) {
        if (typeof invokeArtifact !== 'function') {
            throw new TypeError('TopologyNodeTransport requires invokeArtifact');
        }
        this.#invokeArtifact = invokeArtifact;
    }

    async #invoke(command, request, artifactRequired = false) {
        request = { ...request }; // Freeze primitive binding before the first await.
        const checksRequired = command === TOPOLOGY_NODE_COMMANDS.VERIFY;
        const statusRequired = command === TOPOLOGY_NODE_COMMANDS.STATUS;
        assertBasePlan(request, artifactRequired
            ? ['artifact']
            : (checksRequired ? ['checks'] : (statusRequired ? ['completedCommand'] : [])));
        if (statusRequired && !['prepare', 'commit', 'verify', 'rollback', 'close'].includes(request.completedCommand)) {
            throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid topology node plan');
        }
        if (artifactRequired) assertArtifact(request.artifact, request.candidateHash);
        if (checksRequired && !validChecks(request.checks, request.targetProfile)) {
            throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid topology node plan');
        }

        let result;
        try {
            result = await this.#invokeArtifact(TOPOLOGY_NODE_RUNNER_PATH, {
                command,
                ...Object.fromEntries(FENCE_KEYS.map(key => [key, request[key]])),
                ...(statusRequired ? { completedCommand: request.completedCommand } : {}),
                operationId: request.operationId,
                nodeId: request.nodeId,
                candidateHash: request.candidateHash,
                backupId: request.backupId,
                targetProfile: request.targetProfile,
                ...(checksRequired ? { checks: request.checks.map(check => ({ ...check })) } : {}),
                ...(artifactRequired ? { artifact: { ...request.artifact } } : {}),
            });
        } catch {
            throw new TopologyNodeTransportError(
                'ARTIFACT_INVOCATION_FAILED',
                'Topology node artifact invocation failed',
            );
        }
        return parseReceipt(result, command, request);
    }

    async restoreUsers(request) {
        const { bootId, users, ...binding } = request || {};
        assertBasePlan(binding);
        const { validReadiness, parseReadinessReceipt } = require('./topologyReadinessProtocol');
        if (!hasExactKeys(request, [...BASE_KEYS, 'bootId', 'users'].sort())
            || binding.targetProfile !== 'xray-main' || !Array.isArray(users) || users.length < 1 || users.length > 4096
            || users.some(user => !hasExactKeys(user, ['email', 'id'])
                || typeof user.id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(user.id)
                || typeof user.email !== 'string' || !/^[A-Za-z0-9@._+-]{1,128}$/.test(user.email))
            || new Set(users.map(u => u.email)).size !== users.length || new Set(users.map(u => u.id)).size !== users.length) {
            throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid user snapshot');
        }
        const snapshot = `${JSON.stringify({ users: users.map(({ id, email }) => ({ id, email })) })}\n`;
        const readiness = { bootId, snapshotSha256: createHash('sha256').update(snapshot).digest('hex'), userCount: users.length };
        if (!validReadiness('restore-users', readiness)) throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid user snapshot');
        const invocation = { command: 'restore-users', ...binding, readiness, snapshot };
        try {
            return parseReadinessReceipt(await this.#invokeArtifact(TOPOLOGY_NODE_RUNNER_PATH, invocation), 'restore-users', invocation);
        } catch { throw new TopologyNodeTransportError('INVALID_RECEIPT', 'Unconfirmed user restoration'); }
    }

    async verifyPppUsers(request) {
        const { bootId, expectation, ...binding } = request || {};
        assertBasePlan(binding);
        const { validReadiness, parseReadinessReceipt } = require('./topologyReadinessProtocol');
        const readiness = { bootId, ...expectation };
        if (!hasExactKeys(request, [...BASE_KEYS, 'bootId', 'expectation'].sort())
            || !hasExactKeys(expectation, ['expectedCredentialRevision', 'expectedEnabledUserCount', 'operationId'])
            || !validReadiness('verify-ppp-users', readiness)) {
            throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid readiness request');
        }
        const invocation = { command: 'verify-ppp-users', ...binding, readiness };
        try {
            const result = await this.#invokeArtifact(TOPOLOGY_NODE_RUNNER_PATH, invocation);
            return parseReadinessReceipt(result, 'verify-ppp-users', invocation);
        } catch {
            throw new TopologyNodeTransportError('INVALID_RECEIPT', 'Unconfirmed readiness');
        }
    }

    prepare(request) {
        return this.#invoke(TOPOLOGY_NODE_COMMANDS.PREPARE, request, true);
    }

    commit(request) {
        return this.#invoke(TOPOLOGY_NODE_COMMANDS.COMMIT, request);
    }

    verify(request) {
        return this.#invoke(TOPOLOGY_NODE_COMMANDS.VERIFY, request);
    }

    rollback(request) {
        return this.#invoke(TOPOLOGY_NODE_COMMANDS.ROLLBACK, request);
    }

    close(request) {
        return this.#invoke(TOPOLOGY_NODE_COMMANDS.CLOSE, request);
    }

    status(request) {
        return this.#invoke(TOPOLOGY_NODE_COMMANDS.STATUS, request);
    }
}

module.exports = {
    TOPOLOGY_NODE_ARTIFACT_ID,
    TOPOLOGY_NODE_COMMANDS,
    TOPOLOGY_NODE_RUNNER_PATH,
    TopologyNodeTransport,
    TopologyNodeTransportError,
};
