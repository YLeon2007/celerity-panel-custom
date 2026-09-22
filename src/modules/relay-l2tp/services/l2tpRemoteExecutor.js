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

class L2tpRemoteExecutor {
    constructor({ transport }) {
        this.transport = transport;
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
        const artifacts = step.artifacts || [];

        for (const artifact of artifacts) {
            assertNoPathTraversal(artifact.path);
            const allowedArtifacts = STEP_ARTIFACT_PATHS[step.type];
            if (
                !allowedArtifacts
                || !Object.hasOwn(allowedArtifacts, artifact.type)
                || allowedArtifacts[artifact.type] !== artifact.path
            ) {
                throw new L2tpRemoteExecutorError(
                    'ARTIFACT_NOT_ALLOWED',
                    'Artifact is not allowed for this L2TP operation step',
                );
            }
        }

        for (const artifact of artifacts) {
            await uploadRootFile(this.transport, {
                operationId,
                type: artifact.type,
                path: artifact.path,
                content: artifact.content,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            });
        }

        await runArtifactCommand(this.transport, {
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

        await runArtifactCommand(this.transport, {
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
