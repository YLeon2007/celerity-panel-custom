'use strict';

const INSTALL_STEP_TYPES = Object.freeze([
    'preflight',
    'install_runtime',
    'backup',
    'stage_managed_files',
    'compose_xray_fragment',
    'validate_xray',
    'validate_nft',
    'activate_xray',
    'apply_firewall_policy',
    'start_l2tp',
    'sync_users',
    'verify',
    'commit',
]);

class L2tpProvisionPlanError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'L2tpProvisionPlanError';
        this.code = code;
        Object.assign(this, details);
    }
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function buildInstallPlan({
    operationId,
    topologyRevision,
    relay,
    routeGroup,
    relayGroupPlan,
    desired,
}) {
    if (desired?.desiredState !== 'installed') {
        throw new L2tpProvisionPlanError(
            'DESIRED_STATE_NOT_INSTALLED',
            'L2TP install planning requires desiredState installed',
            { desiredState: desired?.desiredState },
        );
    }
    if (relay?.role !== 'relay') {
        throw new L2tpProvisionPlanError(
            'NODE_NOT_RELAY',
            'L2TP install planning requires a relay node',
            {
                relayId: entityId(relay),
                role: relay?.role,
            },
        );
    }

    const routeGroupId = entityId(routeGroup);
    const selectedRouteGroupId = entityId(desired.routeGroup);
    if (!routeGroupId || !selectedRouteGroupId || selectedRouteGroupId !== routeGroupId) {
        throw new L2tpProvisionPlanError(
            'ROUTE_GROUP_MISMATCH',
            'The desired L2TP route group does not match the install target',
            {
                selectedRouteGroupId,
                routeGroupId,
            },
        );
    }

    const compiledRouteGroupId = entityId(relayGroupPlan?.groupId);
    const decisionRouteGroupId = entityId(relayGroupPlan?.decision?.groupId);
    if (
        compiledRouteGroupId !== routeGroupId
        || (decisionRouteGroupId !== null && decisionRouteGroupId !== routeGroupId)
    ) {
        throw new L2tpProvisionPlanError(
            'ROUTE_GROUP_MISMATCH',
            'The compiled relay plan does not match the install target route group',
            {
                routeGroupId,
                compiledRouteGroupId,
                decisionRouteGroupId,
            },
        );
    }

    const selectedPathKey = relayGroupPlan?.decision?.pathKey;
    const selectedCandidate = Array.isArray(relayGroupPlan?.candidates)
        ? relayGroupPlan.candidates.find(candidate => candidate.pathKey === selectedPathKey)
        : undefined;
    const hasHealthySelection = relayGroupPlan?.decision?.decision === 'select'
        && typeof selectedPathKey === 'string'
        && selectedPathKey.length > 0
        && selectedCandidate
        && selectedCandidate.healthy !== false;
    const planIdentity = {
        operationId: String(operationId),
        topologyRevision,
        relayId: entityId(relay),
        routeGroupId,
    };

    if (!hasHealthySelection) {
        return {
            ok: false,
            ...planIdentity,
            error: { code: 'NO_HEALTHY_PATH' },
            steps: [],
        };
    }

    return {
        ok: true,
        ...planIdentity,
        selectedPathKey,
        nextHopNodeId: String(
            relayGroupPlan.decision.nextHopNodeId ?? selectedCandidate.nextHopNodeId,
        ),
        steps: INSTALL_STEP_TYPES.map(type => ({ type })),
    };
}

module.exports = {
    INSTALL_STEP_TYPES,
    L2tpProvisionPlanError,
    buildInstallPlan,
};
