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

function rejectedFence(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
}

class L2tpStateManagementRepository {
    constructor({ HyNode, RelayL2tpState, CascadeRouteGroup, CascadeTopologyState,
        L2tpOperation, NodeOperationLock }) {
        if (!HyNode) throw new TypeError('HyNode model is required');
        if (!RelayL2tpState) throw new TypeError('RelayL2tpState model is required');
        if (!CascadeRouteGroup) throw new TypeError('CascadeRouteGroup model is required');
        this.HyNode = HyNode;
        this.RelayL2tpState = RelayL2tpState;
        this.CascadeRouteGroup = CascadeRouteGroup;
        this.CascadeTopologyState = CascadeTopologyState;
        this.L2tpOperation = L2tpOperation;
        this.NodeOperationLock = NodeOperationLock;
    }

    async withStateTransition(write) {
        const connection = this.RelayL2tpState.db;
        if (!connection || typeof connection.transaction !== 'function'
            || this.CascadeTopologyState?.db !== connection) {
            throw new TypeError('L2TP state transition requires models on one transactional Mongo connection');
        }
        return connection.transaction(async session => {
            const topology = await this.CascadeTopologyState.findById('singleton')
                .select('stateTransitionRevision replacementReservation').session(session).lean();
            // Never create a topology document as a side effect of configuring a relay.
            if (!topology) throw new Error('L2TP state transition requires a topology singleton');
            if (topology.replacementReservation) {
                const error = new Error('A topology replacement owns the relay state transition fence');
                error.code = 'TOPOLOGY_REPLACEMENT_RESERVED';
                throw error;
            }
            const state = await write(session);
            if (!state) return null;
            const expected = topology.stateTransitionRevision;
            const fenced = await this.CascadeTopologyState.findOneAndUpdate(
                { _id: 'singleton', replacementReservation: { $exists: false },
                    stateTransitionRevision: expected === undefined
                        ? { $exists: false } : expected },
                { $inc: { stateTransitionRevision: 1 } },
                { session, new: true, upsert: false },
            ).select('stateTransitionRevision').lean();
            if (!fenced) throw new Error('L2TP state transition topology singleton conflict');
            return state;
        });
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
        const state = await this.withStateTransition(session => this.RelayL2tpState.findOneAndUpdate(
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
                session,
            },
        )
            .select(STATE_MANAGEMENT_SAFE_SELECT)
            .lean());
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
        admissionId,
        owner,
        ownerGeneration,
        lockGeneration,
        credentialRevision,
        topologyRevision,
        activePathKey,
        verifiedAt,
    }) {
        if (!node || !operationId || !admissionId || !owner || !ownerGeneration || !lockGeneration
            || !(verifiedAt instanceof Date) || Number.isNaN(verifiedAt.getTime())
            || this.L2tpOperation?.db !== this.RelayL2tpState.db
            || this.NodeOperationLock?.db !== this.RelayL2tpState.db) {
            throw new TypeError('Verified install requires same-connection operation and node fences');
        }
        const state = await this.withStateTransition(async session => {
            const leaseCheckAt = new Date();
            const active = await this.L2tpOperation.updateOne({
                _id: operationId, node, kind: 'install', status: 'running', admissionId,
                leaseOwner: owner, ownerGeneration, leaseUntil: { $gt: leaseCheckAt },
            }, { $currentDate: { updatedAt: true } }, { session });
            if (active.matchedCount !== 1) {
                throw rejectedFence('L2TP_OPERATION_FENCE_REJECTED', 'L2TP operation fence rejected');
            }
            const locked = await this.NodeOperationLock.updateOne({
                node, operationId, owner, generation: lockGeneration,
                remoteUncertain: true, leaseUntil: { $gt: leaseCheckAt },
            }, { $currentDate: { updatedAt: true } }, { session });
            if (locked.matchedCount !== 1) {
                throw rejectedFence('L2TP_NODE_FENCE_REJECTED', 'L2TP node fence rejected');
            }
            return this.RelayL2tpState.findOneAndUpdate(
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
                session,
            },
        )
            .select(VERIFIED_STATE_SAFE_SELECT)
            .lean();
        });
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
