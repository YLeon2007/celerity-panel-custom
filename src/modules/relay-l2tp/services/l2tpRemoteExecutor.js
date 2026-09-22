'use strict';

const STEP_COMMANDS = Object.freeze({
    preflight: 'preflight',
    install_runtime: 'install_runtime',
    backup: 'backup',
    stage_managed_files: 'stage_managed_files',
    compose_xray_fragment: 'compose_xray_fragment',
    validate_xray: 'validate_xray',
    validate_nft: 'validate_nft',
    activate_xray: 'activate_xray',
    apply_firewall_policy: 'apply_firewall_policy',
    start_l2tp: 'start_l2tp',
    sync_users: 'sync_users',
    verify: 'verify',
    commit: 'commit',
});
const STEP_ARTIFACT_PATHS = Object.freeze({
    preflight: Object.freeze({ desired: 'desired.json' }),
    stage_managed_files: Object.freeze({ artifact: 'artifacts.json' }),
    compose_xray_fragment: Object.freeze({ xrayCandidate: 'xray-candidate.json' }),
});

class L2tpRemoteExecutorError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'L2tpRemoteExecutorError';
        this.code = code;
    }
}

function assertNoPathTraversal(path) {
    const components = typeof path === 'string' ? path.split(/[\\/]/) : [];
    if (
        components.length === 0
        || path.startsWith('/')
        || path.startsWith('\\')
        || components.some(component => component === '' || component === '.' || component === '..')
    ) {
        throw new L2tpRemoteExecutorError(
            'PATH_TRAVERSAL_NOT_ALLOWED',
            'Artifact path traversal is not allowed',
        );
    }
}

function artifactError(code, message) {
    return new L2tpRemoteExecutorError(code, message);
}

function validatedArtifacts(step) {
    const expectedArtifacts = STEP_ARTIFACT_PATHS[step.type];
    const artifacts = step.artifacts;

    if (!expectedArtifacts) {
        if (artifacts === undefined || (Array.isArray(artifacts) && artifacts.length === 0)) {
            return [];
        }
        throw artifactError(
            'ARTIFACT_NOT_ALLOWED',
            'Artifact is not allowed for this L2TP operation step',
        );
    }

    const expectedEntries = Object.entries(expectedArtifacts);
    if (!Array.isArray(artifacts) || artifacts.length !== expectedEntries.length) {
        throw artifactError(
            'ARTIFACT_REQUIRED',
            'Exactly one materialized artifact is required for this L2TP operation step',
        );
    }

    return artifacts.map((artifact, index) => {
        const [expectedType, expectedPath] = expectedEntries[index];
        if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
            throw artifactError(
                'ARTIFACT_PAYLOAD_INVALID',
                'The L2TP operation artifact payload is invalid',
            );
        }
        assertNoPathTraversal(artifact.path);
        if (artifact.type !== expectedType || artifact.path !== expectedPath) {
            throw artifactError(
                'ARTIFACT_NOT_ALLOWED',
                'Artifact is not allowed for this L2TP operation step',
            );
        }
        if (
            Object.keys(artifact).length !== 3
            || !Object.hasOwn(artifact, 'content')
            || typeof artifact.content !== 'string'
        ) {
            throw artifactError(
                'ARTIFACT_PAYLOAD_INVALID',
                'The L2TP operation artifact payload is invalid',
            );
        }
        return artifact;
    });
}

async function uploadRootFile(transport, request) {
    try {
        await transport.uploadRootFile(request);
    } catch {
        throw new L2tpRemoteExecutorError(
            'REMOTE_UPLOAD_FAILED',
            'Failed to upload an L2TP operation artifact',
        );
    }
}

async function runArtifactCommand(transport, request) {
    try {
        await transport.runArtifactCommand(request);
    } catch {
        throw new L2tpRemoteExecutorError(
            'REMOTE_COMMAND_FAILED',
            'Failed to run an L2TP artifact command',
        );
    }
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function nodeExecutionUnavailableError() {
    return new L2tpRemoteExecutorError(
        'NODE_EXECUTION_UNAVAILABLE',
        'Node execution is unavailable',
    );
}

class L2tpRemoteExecutor {
    #transportPromises = new Map();

    constructor({ transport, transportResolver } = {}) {
        const hasTransport = transport !== undefined && transport !== null;
        const hasTransportResolver = typeof transportResolver === 'function';
        if (hasTransport === hasTransportResolver) {
            throw new TypeError('L2tpRemoteExecutor requires exactly one transport or transportResolver');
        }
        this.transport = hasTransport ? transport : null;
        Object.defineProperty(this, 'transportResolver', {
            value: hasTransportResolver ? transportResolver : null,
            enumerable: false,
            writable: false,
            configurable: false,
        });
    }

    async resolveTransport(operation) {
        if (this.transport) return this.transport;

        const operationId = String(operation._id ?? operation.id);
        if (!this.#transportPromises.has(operationId)) {
            const resolution = Promise.resolve()
                .then(() => this.transportResolver({
                    operationId,
                    nodeId: entityId(operation.node),
                }))
                .then(transport => {
                    if (
                        !transport
                        || typeof transport.uploadRootFile !== 'function'
                        || typeof transport.runArtifactCommand !== 'function'
                    ) {
                        throw new TypeError('Invalid L2TP node transport');
                    }
                    return transport;
                })
                .catch(() => {
                    throw nodeExecutionUnavailableError();
                });
            this.#transportPromises.set(operationId, resolution);
        }
        return this.#transportPromises.get(operationId);
    }

    releaseOperation(operation) {
        if (!this.transport) {
            const operationId = String(operation._id ?? operation.id);
            this.#transportPromises.delete(operationId);
        }
    }

    async executeStep({ operation, step }) {
        const command = STEP_COMMANDS[step?.type];
        if (!command) {
            throw new L2tpRemoteExecutorError(
                'UNKNOWN_STEP_TYPE',
                'Unsupported L2TP operation step',
            );
        }
        if (['command', 'argv', 'shell'].some(field => Object.hasOwn(step, field))) {
            throw new L2tpRemoteExecutorError(
                'RAW_COMMAND_NOT_ALLOWED',
                'Raw commands are not accepted by the L2TP executor',
            );
        }

        const operationId = String(operation._id ?? operation.id);
        const artifacts = validatedArtifacts(step);
        const transport = await this.resolveTransport(operation);

        for (const artifact of artifacts) {
            await uploadRootFile(transport, {
                operationId,
                type: artifact.type,
                path: artifact.path,
                content: artifact.content,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            });
        }

        await runArtifactCommand(transport, {
            operationId,
            command,
        });

        return {
            ok: true,
            operationId,
            step: step.type,
        };
    }

    async rollback({ operation }) {
        const operationId = String(operation._id ?? operation.id);
        const transport = await this.resolveTransport(operation);

        await runArtifactCommand(transport, {
            operationId,
            command: 'rollback',
        });

        return {
            ok: true,
            operationId,
            step: 'rollback',
        };
    }
}

module.exports = {
    L2tpRemoteExecutor,
    L2tpRemoteExecutorError,
    STEP_COMMANDS,
};
