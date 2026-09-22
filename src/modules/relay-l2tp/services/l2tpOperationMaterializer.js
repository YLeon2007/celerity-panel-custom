'use strict';

const { buildL2tpArtifacts } = require('./l2tpConfigService');
const { INSTALL_STEP_TYPES } = require('./l2tpProvisionPlanService');

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
        const generatedArtifacts = buildArtifacts(resolvedDesired);
        remoteArtifacts.push(
            {
                stepType: 'preflight',
                type: 'desired',
                path: 'desired.json',
                content: `${JSON.stringify({
                    clientCidr: persistedPlan.desired.clientCidr,
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
};
