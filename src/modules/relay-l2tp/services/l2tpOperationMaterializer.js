'use strict';

const { buildL2tpArtifacts } = require('./l2tpConfigService');
const { INSTALL_STEP_TYPES } = require('./l2tpProvisionPlanService');
const { reconcileChapSecrets } = require('./l2tpUserSyncService');

const INSTALL_DESIRED_FIELDS = Object.freeze([
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
]);

const INSTALL_STEP_ARTIFACTS = Object.freeze({
    preflight: Object.freeze([
        Object.freeze({ type: 'desired', path: 'desired.json' }),
    ]),
    stage_managed_files: Object.freeze([
        Object.freeze({ type: 'artifact', path: 'artifacts.json' }),
    ]),
    compose_xray_fragment: Object.freeze([
        Object.freeze({ type: 'xrayCandidate', path: 'xray-candidate.json' }),
    ]),
});
const SYNC_USERS_STEP_TYPES = Object.freeze(['backup', 'sync_users', 'verify_users']);

class L2tpOperationMaterializationError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'L2tpOperationMaterializationError';
        this.code = code;
    }
}

function assertInstallPlan(plan) {
    if (plan?.ok !== true || !Array.isArray(plan.steps)) {
        throw new L2tpOperationMaterializationError(
            'INSTALL_PLAN_REJECTED',
            'A successful L2TP install plan is required',
        );
    }

    const stepTypes = plan.steps.map(step => step?.type);
    if (
        stepTypes.length !== INSTALL_STEP_TYPES.length
        || stepTypes.some((type, index) => type !== INSTALL_STEP_TYPES[index])
    ) {
        throw new L2tpOperationMaterializationError(
            'INVALID_INSTALL_PLAN',
            'The L2TP install plan has an invalid step sequence',
        );
    }
}

function pickDesired(desired) {
    const picked = {};
    for (const field of INSTALL_DESIRED_FIELDS) {
        if (desired?.[field] !== undefined) {
            picked[field] = Array.isArray(desired[field])
                ? [...desired[field]]
                : desired[field];
        }
    }
    if (desired?.secretRevision !== undefined) {
        picked.credentialRevision = desired.secretRevision;
    } else if (desired?.credentialRevision !== undefined) {
        picked.credentialRevision = desired.credentialRevision;
    }
    return picked;
}

function referencedSteps(steps) {
    return steps.map(step => {
        const artifacts = INSTALL_STEP_ARTIFACTS[step.type];
        return artifacts
            ? { type: step.type, artifacts: artifacts.map(artifact => ({ ...artifact })) }
            : { type: step.type };
    });
}

function materializeUsers(users) {
    if (!Array.isArray(users)) {
        throw new TypeError('Resolved L2TP users must be an array');
    }
    const desiredUsers = users.map(user => {
        if (
            !user
            || typeof user !== 'object'
            || Array.isArray(user)
            || Object.keys(user).length !== 3
            || !Object.hasOwn(user, 'login')
            || !Object.hasOwn(user, 'password')
            || !Object.hasOwn(user, 'ip')
        ) {
            throw new TypeError('Resolved L2TP user has an invalid shape');
        }
        return {
            login: user.login,
            password: user.password,
            ipAddress: user.ip,
            enabled: true,
        };
    });
    reconcileChapSecrets('', desiredUsers);
    return desiredUsers;
}

function materializeSyncUsers(users) {
    if (!Array.isArray(users)) {
        throw new TypeError('Resolved L2TP sync users must be an array');
    }
    const desiredUsers = users.map(user => {
        if (
            !user
            || typeof user !== 'object'
            || Array.isArray(user)
            || Object.keys(user).sort().join('\0') !== [
                'id', 'relayNode', 'login', 'password', 'ip', 'enabled', 'desiredRevision',
            ].sort().join('\0')
            || typeof user.id !== 'string'
            || user.id.length === 0
            || typeof user.relayNode !== 'string'
            || user.relayNode.length === 0
            || !Number.isSafeInteger(user.desiredRevision)
            || user.desiredRevision < 1
        ) {
            throw new TypeError('Resolved L2TP sync user has an invalid shape');
        }
        return {
            login: user.login,
            password: user.password,
            ipAddress: user.ip,
            enabled: user.enabled,
        };
    });
    reconcileChapSecrets('', desiredUsers);
    return desiredUsers;
}

function plainObject(value) {
    return value && typeof value.toObject === 'function'
        ? value.toObject()
        : value;
}

function hasExactKeys(value, expectedKeys) {
    const plain = plainObject(value);
    return plain
        && typeof plain === 'object'
        && !Array.isArray(plain)
        && Object.keys(plain).sort().join('\0') === [...expectedKeys].sort().join('\0');
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function assertSyncUsersContext(operation, plan, snapshot) {
    if (
        !operation
        || typeof operation !== 'object'
        || operation.kind !== 'sync_users'
        || operation.status !== 'running'
        || entityId(operation) !== plan.operationId
        || entityId(operation.node) !== plan.relayId
        || (
            snapshot !== undefined
            && (
                !hasExactKeys(snapshot, ['credentialRevision', 'users'])
                || snapshot.credentialRevision !== plan.desired.credentialRevision
                || !Array.isArray(snapshot.users)
            )
        )
    ) {
        throw new L2tpOperationMaterializationError(
            'INVALID_SYNC_USERS_CONTEXT',
            'The claimed L2TP sync_users execution context is invalid',
        );
    }
}

function assertSyncUsersPlan(plan) {
    const plain = plainObject(plan);
    const desired = plainObject(plain?.desired);
    const steps = plain?.steps?.map(plainObject);
    if (
        !hasExactKeys(plain, ['ok', 'operationId', 'relayId', 'desired', 'steps'])
        || plain.ok !== true
        || typeof plain.operationId !== 'string'
        || plain.operationId.length === 0
        || typeof plain.relayId !== 'string'
        || plain.relayId.length === 0
        || !hasExactKeys(desired, ['credentialRevision'])
        || !Number.isSafeInteger(desired.credentialRevision)
        || desired.credentialRevision < 1
        || !Array.isArray(steps)
        || steps.length !== SYNC_USERS_STEP_TYPES.length
        || steps.some((step, index) => step?.type !== SYNC_USERS_STEP_TYPES[index])
        || !hasExactKeys(steps[0], ['type'])
        || !hasExactKeys(steps[2], ['type'])
        || !hasExactKeys(steps[1], ['type', 'artifacts'])
        || !Array.isArray(steps[1].artifacts)
        || steps[1].artifacts.length !== 1
    ) {
        throw new L2tpOperationMaterializationError(
            'INVALID_SYNC_USERS_PLAN',
            'The L2TP sync_users plan is invalid',
        );
    }
    const artifact = plainObject(steps[1].artifacts[0]);
    if (
        !hasExactKeys(artifact, ['type', 'path'])
        || artifact.type !== 'desired'
        || artifact.path !== 'desired.json'
    ) {
        throw new L2tpOperationMaterializationError(
            'INVALID_SYNC_USERS_PLAN',
            'The L2TP sync_users plan is invalid',
        );
    }
    return plain;
}

function materializeSyncUsersOperation({ operation, plan, snapshot } = {}) {
    const validPlan = assertSyncUsersPlan(plan);
    assertSyncUsersContext(operation, validPlan, snapshot);
    const persistedPlan = {
        ok: true,
        operationId: validPlan.operationId,
        relayId: validPlan.relayId,
        desired: { credentialRevision: validPlan.desired.credentialRevision },
        steps: [
            { type: 'backup' },
            {
                type: 'sync_users',
                artifacts: [{ type: 'desired', path: 'desired.json' }],
            },
            { type: 'verify_users' },
        ],
    };
    const remoteArtifacts = [];
    if (snapshot !== undefined) {
        const users = materializeSyncUsers(snapshot.users);
        remoteArtifacts.push({
            stepType: 'sync_users',
            type: 'desired',
            path: 'desired.json',
            content: `${JSON.stringify({
                credentialRevision: snapshot.credentialRevision,
                users,
            })}\n`,
        });
    }
    return { persistedPlan, remoteArtifacts };
}

function materializeInstallOperation(
    { plan, desired, secrets },
    { buildArtifacts = buildL2tpArtifacts } = {},
) {
    assertInstallPlan(plan);
    const selectedDesired = desired ?? plan.desired;
    const persistedPlan = {
        ok: true,
        operationId: plan.operationId,
        topologyRevision: plan.topologyRevision,
        relayId: plan.relayId,
        routeGroupId: plan.routeGroupId,
        selectedPathKey: plan.selectedPathKey,
        nextHopNodeId: plan.nextHopNodeId,
        desired: pickDesired(selectedDesired),
        steps: referencedSteps(plan.steps),
    };
    const remoteArtifacts = [];

    if (secrets !== undefined) {
        const resolvedDesired = {
            ...persistedPlan.desired,
            psk: secrets.psk,
        };
        delete resolvedDesired.credentialRevision;
        const desiredUsers = materializeUsers(secrets.users);
        const generatedArtifacts = buildArtifacts(resolvedDesired);
        remoteArtifacts.push(
            {
                stepType: 'preflight',
                type: 'desired',
                path: 'desired.json',
                // This staged desired.json is the only desired document on the
                // node during install (sync_users carries no artifact for
                // install operations), so later steps — apply_firewall_policy
                // and verify — read fwmark/routeTable from it as well.
                content: `${JSON.stringify({
                    ...persistedPlan.desired,
                    users: desiredUsers,
                })}\n`,
            },
            {
                stepType: 'stage_managed_files',
                type: 'artifact',
                path: 'artifacts.json',
                content: `${JSON.stringify(generatedArtifacts)}\n`,
            },
        );
    }

    return { persistedPlan, remoteArtifacts };
}

module.exports = {
    INSTALL_DESIRED_FIELDS,
    INSTALL_STEP_ARTIFACTS,
    L2tpOperationMaterializationError,
    materializeInstallOperation,
    materializeSyncUsersOperation,
};
