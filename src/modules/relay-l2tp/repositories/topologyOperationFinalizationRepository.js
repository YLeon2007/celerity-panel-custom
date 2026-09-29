'use strict';

const FINALIZATION_REJECTED = Symbol('TOPOLOGY_OPERATION_FINALIZATION_REJECTED');

// Operation kinds whose commit is confined to the links they explicitly
// touched: an autoDeploy link.apply / domain.reconcile must mark only its own
// linkIds deployed and must never advance the global deployedRevision.
const SCOPED_OPERATION_KINDS = new Set(['link.apply', 'domain.reconcile', 'link.replace', 'link.attach']);

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
        .select('kind linkId linkIds staged oldLinkId groupId pathKey ownerNodeId oldPathLinkIds ownerTopologyRevision ownerCredentialRevision')
        .session(session)
        .lean();
    if (!operation) return { invalid: true };
    if (operation.kind === undefined || operation.kind === 'domain.sync') {
        return operation.linkId === undefined && operation.linkIds === undefined
            && operation.staged === undefined && operation.oldLinkId === undefined
            && operation.groupId === undefined && operation.pathKey === undefined
            && operation.ownerNodeId === undefined && operation.oldPathLinkIds === undefined
            && operation.ownerTopologyRevision === undefined
            && operation.ownerCredentialRevision === undefined
            ? null : { invalid: true };
    }
    if (!SCOPED_OPERATION_KINDS.has(operation.kind)
        || typeof operation.linkId !== 'string' || operation.linkId.length === 0
        || !Array.isArray(operation.linkIds)
        || operation.linkIds.length === 0
        || new Set(operation.linkIds).size !== operation.linkIds.length
        || !operation.linkIds.includes(operation.linkId)
        || !operation.linkIds.every(linkId => typeof linkId === 'string' && linkId.length > 0)
        || (operation.kind === 'link.apply'
            ? typeof operation.staged !== 'boolean'
            : operation.staged !== undefined)
        || (operation.kind === 'link.attach'
            ? operation.oldLinkId !== undefined || operation.oldPathLinkIds !== undefined
                || operation.pathKey !== 'main'
                || !['groupId', 'ownerNodeId'].every(key =>
                    typeof operation[key] === 'string' && operation[key].length > 0)
                || operation.linkIds.length < 2
                || operation.linkIds.at(-1) !== operation.linkId
                || !validRevision(operation.ownerTopologyRevision)
                || !validRevision(operation.ownerCredentialRevision)
            : operation.ownerTopologyRevision !== undefined
                || operation.ownerCredentialRevision !== undefined)
        || (operation.kind === 'link.replace'
            ? !['oldLinkId', 'groupId', 'pathKey', 'ownerNodeId'].every(key =>
                typeof operation[key] === 'string' && operation[key].length > 0)
                || operation.oldLinkId === operation.linkId
                || operation.linkIds.includes(operation.oldLinkId)
                || !Array.isArray(operation.oldPathLinkIds)
                || operation.oldPathLinkIds.length < 2
                || operation.oldPathLinkIds.at(-1) !== operation.oldLinkId
                || new Set(operation.oldPathLinkIds).size !== operation.oldPathLinkIds.length
            : operation.kind === 'link.attach' ? false
                : operation.oldLinkId !== undefined || operation.groupId !== undefined
                || operation.pathKey !== undefined || operation.ownerNodeId !== undefined
                || operation.oldPathLinkIds !== undefined)) {
        return { invalid: true };
    }
    return { kind: operation.kind, linkId: operation.linkId,
        linkIds: [...operation.linkIds], staged: operation.staged,
        ...(operation.kind === 'link.replace' ? {
            oldLinkId: operation.oldLinkId, groupId: operation.groupId,
            pathKey: operation.pathKey, ownerNodeId: operation.ownerNodeId,
            oldPathLinkIds: [...operation.oldPathLinkIds],
        } : {}),
        ...(operation.kind === 'link.attach' ? {
            groupId: operation.groupId, pathKey: operation.pathKey,
            ownerNodeId: operation.ownerNodeId,
            ownerTopologyRevision: operation.ownerTopologyRevision,
            ownerCredentialRevision: operation.ownerCredentialRevision,
        } : {}),
    };
}

class TopologyOperationFinalizationRepository {
    constructor({ TopologyOperation, CascadeTopologyState, CascadeLink,
        CascadeRouteGroup, RelayL2tpState, transactionRunner } = {}) {
        if (!TopologyOperation || typeof TopologyOperation.updateOne !== 'function'
            || typeof TopologyOperation.findById !== 'function') {
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
        this.CascadeRouteGroup = CascadeRouteGroup || null;
        this.RelayL2tpState = RelayL2tpState || null;
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
                const admission = await this.TopologyOperation.findById(operationId)
                    .select('heldTopologyAdmission')
                    .session(session)
                    .lean();
                if (!admission) rejectFinalization();
                const releasesAdmission = admission.heldTopologyAdmission === true;
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
                        ...(releasesAdmission ? { heldTopologyAdmission: false } : {}),
                    },
                }, { runValidators: true, session });
                if (operation?.matchedCount !== 1) rejectFinalization();

                const scope = await loadOperationScope(
                    this.TopologyOperation,
                    operationId,
                    session,
                );

                if (scope?.invalid) rejectFinalization();
                if (scope && typeof this.CascadeLink?.updateMany !== 'function') rejectFinalization();
                if (scope?.kind === 'link.replace'
                    && (!releasesAdmission || typeof this.CascadeRouteGroup?.updateOne !== 'function'
                        || typeof this.CascadeLink?.updateOne !== 'function'
                        || typeof this.RelayL2tpState?.updateOne !== 'function'
                        || (this.RelayL2tpState.db && this.RelayL2tpState.db !== this.CascadeTopologyState.db))) {
                    rejectFinalization();
                }
                if (scope?.kind === 'link.attach'
                    && (!releasesAdmission || typeof this.CascadeRouteGroup?.updateOne !== 'function'
                        || typeof this.RelayL2tpState?.updateOne !== 'function'
                        || (this.CascadeRouteGroup.db && this.CascadeRouteGroup.db !== this.CascadeTopologyState.db)
                        || (this.RelayL2tpState.db && this.RelayL2tpState.db !== this.CascadeTopologyState.db)
                        || (this.CascadeLink.db && this.CascadeLink.db !== this.CascadeTopologyState.db))) {
                    rejectFinalization();
                }
                const topology = await this.CascadeTopologyState.updateOne({
                    _id: 'singleton',
                    revision: topologyRevision,
                    deployedRevision: priorDeployedRevision,
                    ...(releasesAdmission ? { topologyAdmissionCount: 1 } : {}),
                    ...(scope?.kind === 'link.replace' || scope?.kind === 'link.attach'
                        ? { replacementReservation: { $exists: false } } : {}),
                }, {
                    // A scoped commit only checks the fence; it cannot claim
                    // the rest of the draft revision has been deployed.
                    $set: { deployedRevision: scope ? priorDeployedRevision : topologyRevision },
                    ...(releasesAdmission ? { $inc: { topologyAdmissionCount: -1 } } : {}),
                }, {
                    runValidators: true,
                    session,
                    timestamps: false,
                });
                if (topology?.matchedCount !== 1) rejectFinalization();

                if (scope?.kind === 'link.replace') {
                    // Write the installed owner's document in this transaction;
                    // a concurrent L2TP uninstall/update must conflict rather
                    // than slipping past a snapshot-only status read.
                    const installed = await this.RelayL2tpState.updateOne({
                        routeGroup: scope.groupId, node: scope.ownerNodeId,
                        activePathKey: scope.pathKey, status: 'installed',
                        desiredState: 'installed',
                    }, { $inc: { replacementFence: 1 } }, { session });
                    if (installed?.matchedCount !== 1) rejectFinalization();
                    // The positional update changes one path, not the entire
                    // group. Match the exact installed sequence frozen at queue
                    // time; no partial or foreign path can become the new route.
                    const group = await this.CascadeRouteGroup.updateOne({
                        _id: scope.groupId,
                        paths: { $elemMatch: {
                            pathKey: scope.pathKey, enabled: { $ne: false },
                            linkIds: scope.oldPathLinkIds,
                        } },
                    }, { $set: { 'paths.$.linkIds': [
                        ...scope.oldPathLinkIds.slice(0, -1), scope.linkId,
                    ] } }, { runValidators: true, session });
                    if (group?.matchedCount !== 1) rejectFinalization();
                    const replacement = await this.CascadeLink.updateOne({
                        _id: scope.linkId, active: true, status: { $in: ['pending'] },
                    }, { $set: { status: 'deployed' } }, { runValidators: true, session });
                    if (replacement?.matchedCount !== 1) rejectFinalization();
                    const old = await this.CascadeLink.updateOne({
                        _id: scope.oldLinkId, active: true,
                        status: { $in: ['deployed', 'online', 'staged'] },
                    }, { $set: { active: false, status: 'offline' } },
                    { runValidators: true, session });
                    if (old?.matchedCount !== 1) rejectFinalization();
                    const baseline = scope.linkIds.filter(id => id !== scope.linkId);
                    if (baseline.length) {
                        const linked = await this.CascadeLink.updateMany({
                            _id: { $in: baseline }, active: true,
                            status: { $in: ['deployed', 'online', 'staged'] },
                        }, { $set: { status: 'deployed' } }, { runValidators: true, session });
                        if (linked?.matchedCount !== baseline.length) rejectFinalization();
                    }
                }

                if (scope?.kind === 'link.attach') {
                    // A user edit reserves a new secretRevision on this same
                    // owner document. Writing the fence forces a transaction
                    // conflict with concurrent user or L2TP state changes.
                    const installed = await this.RelayL2tpState.updateOne({
                        routeGroup: scope.groupId, node: scope.ownerNodeId,
                        activePathKey: scope.pathKey, status: 'installed',
                        desiredState: 'installed',
                        appliedTopologyRevision: scope.ownerTopologyRevision,
                        secretRevision: scope.ownerCredentialRevision,
                    }, { $inc: { replacementFence: 1 } }, { session });
                    if (installed?.matchedCount !== 1) rejectFinalization();
                    // Never append or replace a route: only the exact empty
                    // group can become the sole, enabled main path.
                    const group = await this.CascadeRouteGroup.updateOne({
                        _id: scope.groupId, paths: [],
                    }, { $set: { paths: [{ pathKey: scope.pathKey,
                        linkIds: scope.linkIds, priority: 1, enabled: true }] } },
                    { runValidators: true, session });
                    if (group?.matchedCount !== 1) rejectFinalization();
                    const suffix = await this.CascadeLink.updateMany({
                        _id: { $in: [scope.linkId] }, active: true,
                        status: { $in: ['pending'] },
                    }, { $set: { status: 'deployed' } }, { runValidators: true, session });
                    if (suffix?.matchedCount !== 1) rejectFinalization();
                    const baseline = scope.linkIds.slice(0, -1);
                    const prefix = await this.CascadeLink.updateMany({
                        _id: { $in: baseline }, active: true,
                        status: { $in: ['deployed', 'online', 'staged'] },
                    }, { $set: { status: 'deployed' } }, { runValidators: true, session });
                    if (prefix?.matchedCount !== baseline.length) rejectFinalization();
                }

                if (scope?.kind !== 'link.replace'
                    && scope?.kind !== 'link.attach'
                    && this.CascadeLink && typeof this.CascadeLink.updateMany === 'function') {
                    const isStagedApply = scope?.kind === 'link.apply' && scope.staged === true;
                    const linkIds = isStagedApply ? [scope.linkId] : scope?.linkIds;
                    const linkFilter = scope
                        ? { _id: { $in: linkIds } }
                        : { active: true };
                    const linked = await this.CascadeLink.updateMany(
                        linkFilter,
                        { $set: { status: isStagedApply ? 'staged' : 'deployed' } },
                        { runValidators: true, session },
                    );
                    if (scope && linked?.matchedCount !== linkIds.length) rejectFinalization();
                }

                return {
                    operationId,
                    topologyRevision,
                    deployedRevision: scope ? priorDeployedRevision : topologyRevision,
                    ...(scope ? { scopeKind: scope.kind } : {}),
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
