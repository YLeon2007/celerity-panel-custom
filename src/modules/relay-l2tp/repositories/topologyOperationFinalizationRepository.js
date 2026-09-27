'use strict';

const FINALIZATION_REJECTED = Symbol('TOPOLOGY_OPERATION_FINALIZATION_REJECTED');

// Operation kinds whose commit is confined to the links they explicitly
// touched: an autoDeploy link.apply / domain.reconcile must mark only its own
// linkIds deployed and must never advance the global deployedRevision.
const SCOPED_OPERATION_KINDS = new Set(['link.apply', 'domain.reconcile']);

function validDate(value) {
    return value instanceof Date && Number.isFinite(value.getTime());
}

function validRevision(value) {
    return Number.isSafeInteger(value) && value >= 0;
}

function assertFinalizationRequest(request) {
    if (!request
        || typeof request !== 'object'
        || Array.isArray(request)
        || typeof request.operationId !== 'string'
        || request.operationId.length === 0
        || typeof request.owner !== 'string'
        || request.owner.length === 0
        || !validDate(request.leaseUntil)
        || !validDate(request.now)
        || !validRevision(request.topologyRevision)
        || !validRevision(request.priorDeployedRevision)) {
        throw new TypeError('Invalid topology operation finalization request');
    }
}

function defaultTransactionRunner(TopologyOperation, CascadeTopologyState) {
    const connection = TopologyOperation?.db;
    if (!connection
        || CascadeTopologyState?.db !== connection
        || typeof connection.transaction !== 'function') {
        return null;
    }
    return work => connection.transaction(work);
}

function rejectFinalization() {
    throw FINALIZATION_REJECTED;
}

async function loadOperationScope(TopologyOperation, operationId, session) {
    if (typeof TopologyOperation.findById !== 'function') return null;
    const operation = await TopologyOperation.findById(operationId)
        .select('kind linkIds')
        .session(session)
        .lean();
    if (!operation
        || !SCOPED_OPERATION_KINDS.has(operation.kind)
        || !Array.isArray(operation.linkIds)
        || operation.linkIds.length === 0
        || !operation.linkIds.every(linkId => typeof linkId === 'string' && linkId.length > 0)) {
        return null;
    }
    return { kind: operation.kind, linkIds: [...operation.linkIds] };
}

class TopologyOperationFinalizationRepository {
    constructor({ TopologyOperation, CascadeTopologyState, CascadeLink, transactionRunner } = {}) {
        if (!TopologyOperation || typeof TopologyOperation.updateOne !== 'function') {
            throw new TypeError('Topology operation finalization requires TopologyOperation');
        }
        if (!CascadeTopologyState || typeof CascadeTopologyState.updateOne !== 'function') {
            throw new TypeError('Topology operation finalization requires CascadeTopologyState');
        }
        const runTransaction = transactionRunner
            ?? defaultTransactionRunner(TopologyOperation, CascadeTopologyState);
        if (typeof runTransaction !== 'function') {
            throw new TypeError('Topology operation finalization requires a transaction runner');
        }
        this.TopologyOperation = TopologyOperation;
        this.CascadeTopologyState = CascadeTopologyState;
        this.CascadeLink = CascadeLink || null;
        this.transactionRunner = runTransaction;
    }

    async finalizeSucceeded(request) {
        assertFinalizationRequest(request);
        const {
            operationId,
            owner,
            leaseUntil,
            topologyRevision,
            priorDeployedRevision,
            now,
        } = request;
        try {
            return await this.transactionRunner(async session => {
                const operation = await this.TopologyOperation.updateOne({
                    _id: operationId,
                    topologyRevision,
                    priorDeployedRevision,
                    status: 'committing',
                    leaseOwner: owner,
                    leaseUntil: { $eq: leaseUntil, $gt: now },
                }, {
                    $set: {
                        status: 'succeeded',
                        finishedAt: now,
                        leaseUntil: null,
                    },
                }, { runValidators: true, session });
                if (operation?.matchedCount !== 1) rejectFinalization();

                const scope = await loadOperationScope(
                    this.TopologyOperation,
                    operationId,
                    session,
                );

                if (!scope) {
                    const topology = await this.CascadeTopologyState.updateOne({
                        _id: 'singleton',
                        revision: topologyRevision,
                        deployedRevision: priorDeployedRevision,
                    }, {
                        $set: { deployedRevision: topologyRevision },
                    }, {
                        runValidators: true,
                        session,
                        timestamps: false,
                    });
                    if (topology?.matchedCount !== 1) rejectFinalization();
                }

                if (this.CascadeLink && typeof this.CascadeLink.updateMany === 'function') {
                    const linkFilter = scope
                        ? { _id: { $in: scope.linkIds } }
                        : { active: true };
                    await this.CascadeLink.updateMany(
                        linkFilter,
                        { $set: { status: 'deployed' } },
                        { runValidators: true, session },
                    );
                }

                return {
                    operationId,
                    topologyRevision,
                    deployedRevision: topologyRevision,
                    finishedAt: now,
                };
            });
        } catch (error) {
            if (error === FINALIZATION_REJECTED) return null;
            throw error;
        }
    }
}

module.exports = {
    TopologyOperationFinalizationRepository,
    assertFinalizationRequest,
};
