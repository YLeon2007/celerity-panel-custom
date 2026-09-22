'use strict';

const { createHash } = require('node:crypto');

const {
    TOPOLOGY_NODE_ARTIFACT_ID,
    TOPOLOGY_NODE_COMMANDS,
    TOPOLOGY_NODE_RUNNER_PATH,
    TopologyNodeTransport,
} = require('./topologyNodeTransport');

const TARGET_PROFILE_BY_ROLE = Object.freeze({
    portal: 'xray-main',
    relay: 'xray-bridge',
    bridge: 'xray-bridge',
});
const COMMANDS = new Set(Object.values(TOPOLOGY_NODE_COMMANDS));
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CANDIDATE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const BASE_RUNNER_REQUEST_KEYS = Object.freeze([
    'backupId',
    'candidateHash',
    'command',
    'nodeId',
    'operationId',
    'targetProfile',
]);

class TopologyNodeTransportFactoryError extends Error {
    constructor() {
        super('Topology node transport is unavailable');
        this.name = 'TopologyNodeTransportFactoryError';
        this.code = 'TOPOLOGY_NODE_TRANSPORT_UNAVAILABLE';
    }
}

function hasExactKeys(value, expectedKeys) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function isExactResolutionRequest(request) {
    return hasExactKeys(request, ['nodeId', 'role'])
        && typeof request.nodeId === 'string'
        && SAFE_ID_PATTERN.test(request.nodeId)
        && typeof request.role === 'string'
        && Object.hasOwn(TARGET_PROFILE_BY_ROLE, request.role);
}

function assertRunnerRequest(runnerPath, request, binding) {
    const artifactRequired = request?.command === TOPOLOGY_NODE_COMMANDS.PREPARE;
    const expectedKeys = artifactRequired
        ? [...BASE_RUNNER_REQUEST_KEYS, 'artifact'].sort()
        : BASE_RUNNER_REQUEST_KEYS;
    if (
        runnerPath !== TOPOLOGY_NODE_RUNNER_PATH
        || !hasExactKeys(request, expectedKeys)
        || !COMMANDS.has(request.command)
        || request.nodeId !== binding.nodeId
        || request.targetProfile !== binding.targetProfile
        || !SAFE_ID_PATTERN.test(request.operationId)
        || !SAFE_ID_PATTERN.test(request.nodeId)
        || !SAFE_ID_PATTERN.test(request.backupId)
        || !CANDIDATE_HASH_PATTERN.test(request.candidateHash)
        || (
            artifactRequired
            && (
                !hasExactKeys(request.artifact, ['content', 'id'])
                || request.artifact.id !== TOPOLOGY_NODE_ARTIFACT_ID
                || typeof request.artifact.content !== 'string'
                || request.artifact.content.length === 0
                || `sha256:${createHash('sha256').update(request.artifact.content).digest('hex')}`
                    !== request.candidateHash
            )
        )
    ) {
        throw new TopologyNodeTransportFactoryError();
    }
}

function runnerCommand(request) {
    return [
        TOPOLOGY_NODE_RUNNER_PATH,
        `--command ${request.command}`,
        `--operation-id ${request.operationId}`,
        `--node-id ${request.nodeId}`,
        `--candidate-hash ${request.candidateHash}`,
        `--backup-id ${request.backupId}`,
        `--target-profile ${request.targetProfile}`,
    ].join(' ');
}

function createArtifactInvoker(nodeSSH, binding) {
    return async (runnerPath, request) => {
        assertRunnerRequest(runnerPath, request, binding);
        try {
            if (request.command === TOPOLOGY_NODE_COMMANDS.PREPARE) {
                return await nodeSSH.exec(
                    runnerCommand(request),
                    { stdin: request.artifact.content },
                );
            }
            return await nodeSSH.exec(runnerCommand(request));
        } catch {
            throw new TopologyNodeTransportFactoryError();
        }
    };
}

class TopologyNodeTransportFactory {
    #nodeExecutionResolver;
    #NodeTransport;

    constructor({ nodeExecutionResolver, NodeTransport = TopologyNodeTransport } = {}) {
        if (!nodeExecutionResolver || typeof nodeExecutionResolver.resolve !== 'function') {
            throw new TypeError('TopologyNodeTransportFactory requires nodeExecutionResolver.resolve');
        }
        if (typeof NodeTransport !== 'function') {
            throw new TypeError('TopologyNodeTransportFactory requires NodeTransport');
        }
        this.#nodeExecutionResolver = nodeExecutionResolver;
        this.#NodeTransport = NodeTransport;
    }

    async create(request) {
        if (!isExactResolutionRequest(request)) {
            throw new TopologyNodeTransportFactoryError();
        }

        let nodeSSH;
        try {
            nodeSSH = await this.#nodeExecutionResolver.resolve({
                nodeId: request.nodeId,
                role: request.role,
            });
        } catch {
            throw new TopologyNodeTransportFactoryError();
        }
        if (!nodeSSH || typeof nodeSSH.exec !== 'function') {
            throw new TopologyNodeTransportFactoryError();
        }

        try {
            return new this.#NodeTransport({
                invokeArtifact: createArtifactInvoker(nodeSSH, {
                    nodeId: request.nodeId,
                    targetProfile: TARGET_PROFILE_BY_ROLE[request.role],
                }),
            });
        } catch {
            throw new TopologyNodeTransportFactoryError();
        }
    }
}

module.exports = {
    TARGET_PROFILE_BY_ROLE,
    TopologyNodeTransportFactory,
    TopologyNodeTransportFactoryError,
};
