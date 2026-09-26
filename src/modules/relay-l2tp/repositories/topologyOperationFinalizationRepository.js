'use strict';

const FINALIZATION_REJECTED = Symbol('TOPOLOGY_OPERATION_FINALIZATION_REJECTED');

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

                const topology = request.domainKey
                    // Per-domain deploy: fence the global draft revision, then
                    // upsert the domain state document. The singleton
                    // deployedRevision is left to legacy whole-graph ops.
                    ? await this.CascadeTopologyState.updateOne({
                        _id: `domain:${request.domainKey}`,
                    }, {
                        $set: {
                            domainKey: request.domainKey,
                            label: request.domainLabel ?? null,
                            revision: topologyRevision,
                            deployedRevision: topologyRevision,
                        },
                    }, {
                        runValidators: true,
                        upsert: true,
                        session,
                        timestamps: true,
                    })
                    : await this.CascadeTopologyState.updateOne({
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
                if (topology?.matchedCount !== 1 && !topology?.upsertedCount) rejectFinalization();

                if (request.domainKey) {
                    // The global draft revision fence still applies to
                    // domain-scoped ops: the graph must not have changed
                    // between pin and finalization.
                    const fence = await this.CascadeTopologyState.updateOne({
                        _id: 'singleton',
                        revision: topologyRevision,
                    }, {
                        $set: { revision: topologyRevision },
                    }, {
                        runValidators: true,
                        session,
                        timestamps: false,
                    });
                    if (fence?.matchedCount !== 1) rejectFinalization();
                }

                if (this.CascadeLink && typeof this.CascadeLink.updateMany === 'function') {
                    await this.CascadeLink.updateMany(
                        { active: true },
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
