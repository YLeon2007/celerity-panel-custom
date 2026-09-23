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
    sync_users: 'sync-users',
    verify_users: 'verify-users',
    verify: 'verify',
    commit: 'commit',
});
const STEP_ARTIFACT_PATHS = Object.freeze({
    preflight: Object.freeze({ desired: 'desired.json' }),
    stage_managed_files: Object.freeze({ artifact: 'artifacts.json' }),
    compose_xray_fragment: Object.freeze({ xrayCandidate: 'xray-candidate.json' }),
    sync_users: Object.freeze({ desired: 'desired.json' }),
});
const DESIRED_USER_KEYS = Object.freeze(['enabled', 'ipAddress', 'login', 'password']);
const DESIRED_USERS_KEYS = Object.freeze(['credentialRevision', 'users']);
const USER_VERIFICATION_RESULT_KEYS = Object.freeze([
    'code',
    'credentialRevision',
    'enabledUserCount',
    'managedUserCount',
    'ok',
]);
const USER_VERIFICATION_FAILURE_CODES = new Set([
    'MANAGED_USERS_MISSING',
    'MANAGED_USERS_EXTRA',
    'MANAGED_USERS_DUPLICATE',
    'MANAGED_USERS_ALTERED',
    'DISABLED_USERS_PRESENT',
    'MANAGED_BLOCK_INVALID',
    'CHAP_SECRETS_INVALID',
]);
const LOGIN_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;
const RAW_COMMAND_FIELDS = Object.freeze([
    'args',
    'arguments',
    'argv',
    'command',
    'cwd',
    'env',
    'options',
    'shell',
    'stdin',
]);

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

function validatedArtifacts(operation, step) {
    const expectedArtifacts = STEP_ARTIFACT_PATHS[step.type];
    const artifacts = step.artifacts;
    const artifactsRequired = step.type !== 'sync_users' || operation?.kind === 'sync_users';

    if (!expectedArtifacts) {
        if (artifacts === undefined || (Array.isArray(artifacts) && artifacts.length === 0)) {
            return [];
        }
        throw artifactError(
            'ARTIFACT_NOT_ALLOWED',
            'Artifact is not allowed for this L2TP operation step',
        );
    }

    if (
        !artifactsRequired
        && (artifacts === undefined || (Array.isArray(artifacts) && artifacts.length === 0))
    ) {
        return [];
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

function hasExactKeys(value, expectedKeys) {
    return value
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function isCanonicalIpv4(value) {
    if (typeof value !== 'string') return false;
    const octets = value.split('.');
    return octets.length === 4
        && octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
}

function desiredUsersError(code, message) {
    return new L2tpRemoteExecutorError(code, message);
}

function parseDesiredUsersExpectation(content, operation) {
    const expectedCredentialRevision = operation?.plan?.desired?.credentialRevision;
    if (
        !Number.isSafeInteger(expectedCredentialRevision)
        || expectedCredentialRevision < 1
    ) {
        throw desiredUsersError(
            'CREDENTIAL_REVISION_INVALID',
            'Invalid L2TP user credential revision',
        );
    }

    let desired;
    try {
        desired = JSON.parse(content);
    } catch {
        throw desiredUsersError(
            'DESIRED_USERS_INVALID',
            'Invalid desired L2TP users artifact',
        );
    }
    if (
        !hasExactKeys(desired, DESIRED_USERS_KEYS)
        || !Number.isSafeInteger(desired.credentialRevision)
        || desired.credentialRevision < 1
        || !Array.isArray(desired.users)
    ) {
        throw desiredUsersError(
            'DESIRED_USERS_INVALID',
            'Invalid desired L2TP users artifact',
        );
    }
    if (desired.credentialRevision !== expectedCredentialRevision) {
        throw desiredUsersError(
            'CREDENTIAL_REVISION_MISMATCH',
            'L2TP user credential revision does not match the operation',
        );
    }

    const logins = new Set();
    let expectedEnabledUserCount = 0;
    for (const user of desired.users) {
        if (
            !hasExactKeys(user, DESIRED_USER_KEYS)
            || typeof user.login !== 'string'
            || !LOGIN_PATTERN.test(user.login)
            || logins.has(user.login)
            || typeof user.password !== 'string'
            || user.password.length === 0
            || /[\r\n\0]/.test(user.password)
            || !isCanonicalIpv4(user.ipAddress)
            || typeof user.enabled !== 'boolean'
        ) {
            throw desiredUsersError(
                'DESIRED_USERS_INVALID',
                'Invalid desired L2TP users artifact',
            );
        }
        logins.add(user.login);
        if (user.enabled) expectedEnabledUserCount += 1;
    }

    return { expectedCredentialRevision, expectedEnabledUserCount };
}

function invalidUserVerificationResult() {
    return new L2tpRemoteExecutorError(
        'USER_VERIFICATION_INVALID',
        'Invalid L2TP user verification result',
    );
}

function sanitizeUserVerificationResult(value, expectation) {
    if (
        !hasExactKeys(value, USER_VERIFICATION_RESULT_KEYS)
        || typeof value.ok !== 'boolean'
        || !Number.isSafeInteger(value.credentialRevision)
        || value.credentialRevision !== expectation.expectedCredentialRevision
        || !Number.isSafeInteger(value.enabledUserCount)
        || value.enabledUserCount !== expectation.expectedEnabledUserCount
        || !Number.isSafeInteger(value.managedUserCount)
        || value.managedUserCount < 0
        || Object.is(value.managedUserCount, -0)
        || typeof value.code !== 'string'
    ) {
        throw invalidUserVerificationResult();
    }
    if (value.ok) {
        if (
            value.code !== 'USERS_VERIFIED'
            || value.managedUserCount !== expectation.expectedEnabledUserCount
        ) {
            throw invalidUserVerificationResult();
        }
    } else if (!USER_VERIFICATION_FAILURE_CODES.has(value.code)) {
        throw invalidUserVerificationResult();
    }

    return {
        ok: value.ok,
        credentialRevision: value.credentialRevision,
        enabledUserCount: value.enabledUserCount,
        managedUserCount: value.managedUserCount,
        code: value.code,
    };
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
        return await transport.runArtifactCommand(request);
    } catch (error) {
        // Preserve precise runner artifact codes (e.g. NFT_VERIFY_FAILED)
        // instead of flattening everything into REMOTE_COMMAND_FAILED.
        const code = typeof error?.code === 'string'
            && /^[A-Z][A-Z0-9_]{2,63}$/.test(error.code)
            ? error.code
            : 'REMOTE_COMMAND_FAILED';
        throw new L2tpRemoteExecutorError(
            code,
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

    #userVerificationExpectations = new Map();

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
        const operationId = String(operation._id ?? operation.id);
        this.#userVerificationExpectations.delete(operationId);
        if (!this.transport) {
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
        if (RAW_COMMAND_FIELDS.some(field => Object.hasOwn(step, field))) {
            throw new L2tpRemoteExecutorError(
                'RAW_COMMAND_NOT_ALLOWED',
                'Raw commands are not accepted by the L2TP executor',
            );
        }

        const operationId = String(operation._id ?? operation.id);
        const artifacts = validatedArtifacts(operation, step);
        const desiredExpectation = step.type === 'sync_users' && artifacts.length === 1
            ? parseDesiredUsersExpectation(artifacts[0].content, operation)
            : null;
        const verificationExpectation = step.type === 'verify_users'
            ? this.#userVerificationExpectations.get(operationId)
            : null;
        if (step.type === 'verify_users' && !verificationExpectation) {
            throw new L2tpRemoteExecutorError(
                'USER_VERIFICATION_EXPECTATION_MISSING',
                'L2TP user verification expectation is unavailable',
            );
        }

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

        const commandResult = await runArtifactCommand(transport, {
            operationId,
            command,
            ...(step.type === 'verify_users' ? verificationExpectation : {}),
        });

        if (desiredExpectation) {
            this.#userVerificationExpectations.set(operationId, desiredExpectation);
        }
        if (step.type === 'verify_users') {
            return sanitizeUserVerificationResult(commandResult, verificationExpectation);
        }

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
