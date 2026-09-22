'use strict';

const { createHash } = require('node:crypto');

const TOPOLOGY_NODE_RUNNER_PATH = '/usr/local/bin/celerity-topology-node-runner';
const TOPOLOGY_NODE_ARTIFACT_ID = 'xray-config';
const TOPOLOGY_NODE_COMMANDS = Object.freeze({
    PREPARE: 'prepare',
    COMMIT: 'commit',
    VERIFY: 'verify',
    ROLLBACK: 'rollback',
});
const TARGET_PROFILES = new Set(['xray-main', 'xray-bridge']);
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CANDIDATE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const BASE_KEYS = Object.freeze([
    'backupId',
    'candidateHash',
    'nodeId',
    'operationId',
    'targetProfile',
]);
const RECEIPT_KEYS = Object.freeze([
    ...BASE_KEYS,
    'command',
    'ok',
].sort());

class TopologyNodeTransportError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'TopologyNodeTransportError';
        this.code = code;
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
        || !CANDIDATE_HASH_PATTERN.test(plan.candidateHash)
        || !TARGET_PROFILES.has(plan.targetProfile)) {
        throw new TopologyNodeTransportError('INVALID_PLAN', 'Invalid topology node plan');
    }
}

function assertArtifact(artifact, candidateHash) {
    if (!hasExactKeys(artifact, ['content', 'id'])
        || artifact.id !== TOPOLOGY_NODE_ARTIFACT_ID
        || typeof artifact.content !== 'string'
        || artifact.content.length === 0) {
        throw new TopologyNodeTransportError('INVALID_ARTIFACT', 'Invalid topology node artifact');
    }
    const actualHash = `sha256:${createHash('sha256').update(artifact.content).digest('hex')}`;
    if (actualHash !== candidateHash) {
        throw new TopologyNodeTransportError('CANDIDATE_HASH_MISMATCH', 'Topology candidate hash mismatch');
    }
}

function parseReceipt(result, command, expected) {
    if (!result || typeof result !== 'object'
        || result.code !== 0
        || result.stderr !== ''
        || typeof result.stdout !== 'string'
        || !result.stdout.endsWith('\n')) {
        throw new TopologyNodeTransportError(
            'INVALID_RECEIPT',
            'Invalid topology node receipt',
        );
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
        || receipt.command !== command
        || BASE_KEYS.some(key => receipt[key] !== expected[key])) {
        throw new TopologyNodeTransportError('INVALID_RECEIPT', 'Invalid topology node receipt');
    }
    return Object.freeze({
        ok: true,
        command,
        operationId: expected.operationId,
        nodeId: expected.nodeId,
        candidateHash: expected.candidateHash,
        backupId: expected.backupId,
        targetProfile: expected.targetProfile,
    });
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
        assertBasePlan(request, artifactRequired ? ['artifact'] : []);
        if (artifactRequired) assertArtifact(request.artifact, request.candidateHash);

        let result;
        try {
            result = await this.#invokeArtifact(TOPOLOGY_NODE_RUNNER_PATH, {
                command,
                operationId: request.operationId,
                nodeId: request.nodeId,
                candidateHash: request.candidateHash,
                backupId: request.backupId,
                targetProfile: request.targetProfile,
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
}

module.exports = {
    TOPOLOGY_NODE_ARTIFACT_ID,
    TOPOLOGY_NODE_COMMANDS,
    TOPOLOGY_NODE_RUNNER_PATH,
    TopologyNodeTransport,
    TopologyNodeTransportError,
};
