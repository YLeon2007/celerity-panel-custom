'use strict';

const STATE_MANAGEMENT_SAFE_FIELDS = Object.freeze([
    '_id',
    'node',
    'desiredState',
    'status',
    'routeGroup',
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
    'routingMode',
    'secretRevision',
    'createdAt',
    'updatedAt',
]);
const STATE_MANAGEMENT_SAFE_SELECT = STATE_MANAGEMENT_SAFE_FIELDS.join(' ');
const EXECUTION_SECRET_SELECT = 'node desiredState secretRevision +pskEncrypted';
const VERIFIED_STATE_SAFE_FIELDS = Object.freeze([
    'node',
    'desiredState',
    'status',
    'secretRevision',
    'operationId',
    'appliedTopologyRevision',
    'activePathKey',
    'lastVerifiedAt',
    'lastErrorCode',
    'lastError',
]);
const VERIFIED_STATE_SAFE_SELECT = VERIFIED_STATE_SAFE_FIELDS.join(' ');
const CONFIGURATION_WRITE_FIELDS = Object.freeze([
    'node',
    'desiredState',
    'routeGroup',
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
    'routingMode',
    'pskEncrypted',
]);

function pickDefined(source, fields) {
    return fields.reduce((result, field) => {
        if (source?.[field] !== undefined) {
            result[field] = Array.isArray(source[field]) ? [...source[field]] : source[field];
        }
        return result;
    }, {});
}

class L2tpStateManagementRepository {
    constructor({ HyNode, RelayL2tpState, CascadeRouteGroup }) {
        if (!HyNode) throw new TypeError('HyNode model is required');
        if (!RelayL2tpState) throw new TypeError('RelayL2tpState model is required');
        if (!CascadeRouteGroup) throw new TypeError('CascadeRouteGroup model is required');
        this.HyNode = HyNode;
        this.RelayL2tpState = RelayL2tpState;
        this.CascadeRouteGroup = CascadeRouteGroup;
    }

    async findNodeById(nodeId) {
        return this.HyNode.findById(nodeId)
            .select('_id cascadeRole')
            .lean();
    }

    async findRouteGroupById(routeGroupId) {
        return this.CascadeRouteGroup.findById(routeGroupId)
            .select('_id')
            .lean();
    }

    async configureRelay(fields) {
        const state = await this.RelayL2tpState.findOneAndUpdate(
            { node: fields.node },
            {
                $set: pickDefined(fields, CONFIGURATION_WRITE_FIELDS),
                $inc: { secretRevision: 1 },
                $setOnInsert: { status: 'not_installed' },
            },
            {
                new: true,
                runValidators: true,
                setDefaultsOnInsert: false,
                upsert: true,
            },
        )
            .select(STATE_MANAGEMENT_SAFE_SELECT)
            .lean();
        return pickDefined(state, STATE_MANAGEMENT_SAFE_FIELDS);
    }

    async findExecutionStateByNodeId(nodeId) {
        return this.RelayL2tpState.findOne({ node: nodeId })
            .select(EXECUTION_SECRET_SELECT)
            .lean();
    }

    async markInstalledAfterVerification({
        node,
        operationId,
        credentialRevision,
        topologyRevision,
        activePathKey,
        verifiedAt,
    }) {
        const state = await this.RelayL2tpState.findOneAndUpdate(
            {
                node,
                desiredState: 'installed',
                secretRevision: credentialRevision,
            },
            {
                $set: {
                    status: 'installed',
                    operationId,
                    appliedTopologyRevision: topologyRevision,
                    activePathKey,
                    lastVerifiedAt: verifiedAt,
                    lastErrorCode: '',
                    lastError: '',
                },
            },
            {
                new: true,
                runValidators: true,
            },
        )
            .select(VERIFIED_STATE_SAFE_SELECT)
            .lean();
        return state ? pickDefined(state, VERIFIED_STATE_SAFE_FIELDS) : null;
    }
}

module.exports = {
    CONFIGURATION_WRITE_FIELDS,
    EXECUTION_SECRET_SELECT,
    L2tpStateManagementRepository,
    STATE_MANAGEMENT_SAFE_FIELDS,
    STATE_MANAGEMENT_SAFE_SELECT,
    VERIFIED_STATE_SAFE_FIELDS,
    VERIFIED_STATE_SAFE_SELECT,
};
