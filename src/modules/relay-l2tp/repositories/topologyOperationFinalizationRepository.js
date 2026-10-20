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
        || Reflect.ownKeys(request).some(key => typeof key !== 'string')
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

async function verifyAttachChain(CascadeLink, scope, session) {
    // Validate the frozen identity against the actual edges in the same
    // transaction as publication. The scoped set has no route order of its own.
    const edges = await CascadeLink.find({ _id: { $in: scope.linkIds } })
        .select('_id portalNode bridgeNode').session(session).lean();
    if (!Array.isArray(edges) || edges.length !== scope.linkIds.length) rejectFinalization();
    const byId = new Map(edges.map(edge => [String(edge._id), edge]));
    if (byId.size !== scope.linkIds.length) rejectFinalization();
    const prefixIds = scope.linkIds.filter(id => !scope.newPathLinkIds.includes(id));
    if (!prefixIds.length) rejectFinalization();
    let node = scope.ownerNodeId;
    const suffixNodes = new Set([node]);
    for (const id of scope.newPathLinkIds) {
        const edge = byId.get(id);
        if (!edge || String(edge.portalNode) !== node || !edge.bridgeNode
            || suffixNodes.has(String(edge.bridgeNode))) rejectFinalization();
        node = String(edge.bridgeNode);
        suffixNodes.add(node);
    }
    // Every other scoped edge must form one unbranched upstream path into
    // the installed owner, with no unrelated or cyclic edge accepted.
    const byTarget = new Map();
    for (const id of prefixIds) {
        const edge = byId.get(id);
        if (!edge?.portalNode || !edge.bridgeNode) rejectFinalization();
        const target = String(edge.bridgeNode);
        if (byTarget.has(target) || String(edge.portalNode) === target) rejectFinalization();
        byTarget.set(target, edge);
    }
    node = scope.ownerNodeId;
    const seen = new Set();
    while (byTarget.has(node)) {
        const edge = byTarget.get(node);
        const id = String(edge._id);
        if (seen.has(id)) rejectFinalization();
        seen.add(id);
        node = String(edge.portalNode);
        if (suffixNodes.has(node)) rejectFinalization();
    }
    if (seen.size !== prefixIds.length) rejectFinalization();
}

async function loadOperationScope(TopologyOperation, operationId, session) {
    if (typeof TopologyOperation.findById !== 'function') return null;
    const operation = await TopologyOperation.findById(operationId)
        .select('kind linkId linkIds newPathLinkIds staged oldLinkId groupId pathKey ownerNodeId oldPathLinkIds ownerTopologyRevision ownerCredentialRevision')
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
            && operation.newPathLinkIds === undefined
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
                || !Array.isArray(operation.newPathLinkIds)
                || operation.newPathLinkIds.length < 2
                || operation.newPathLinkIds.length >= operation.linkIds.length
                || new Set(operation.newPathLinkIds).size !== operation.newPathLinkIds.length
                || operation.newPathLinkIds.at(-1) !== operation.linkId
                || !operation.newPathLinkIds.every(id => operation.linkIds.includes(id))
                || !validRevision(operation.ownerTopologyRevision)
                || !validRevision(operation.ownerCredentialRevision)
            : operation.ownerTopologyRevision !== undefined
                || operation.ownerCredentialRevision !== undefined
                || operation.newPathLinkIds !== undefined)
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
            newPathLinkIds: [...operation.newPathLinkIds],
        } : {}),
    };
}

class TopologyOperationFinalizationRepository {
    constructor({ TopologyOperation, CascadeTopologyState, CascadeLink,
        CascadeRouteGroup, RelayL2tpState, transactionRunner, NodeOperationLock,
        TopologyConfigOwner, TopologyExecutionBinding, TopologyExecutionEnrollment, HyNode, L2tpUser, L2tpOperation } = {}) {
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
        Object.assign(this, { NodeOperationLock, TopologyConfigOwner, TopologyExecutionBinding, TopologyExecutionEnrollment,
            HyNode, L2tpUser, L2tpOperation });
    }

    beginV2Closure(request) {
        assertFinalizationRequest(request);
        return require('./topologyV2Settlement').begin(this, request);
    }

    persistV2TerminalProofs(request) {
        assertFinalizationRequest(request);
        return require('./topologyV2Settlement').persist(this, request);
    }

    finalizeV2Succeeded(request) {
        assertFinalizationRequest(request);
        // Only this lexical callback can join publication to the settlement
        // transaction. No request field or exported capability authorizes it.
        return require('./topologyV2Settlement').settle(this, request,
            session => this.#finalizeSucceeded(request, session));
    }

    probeV2Settlement({ operationId }) {
        return require('./topologyV2Settlement').probe(this, operationId);
    }

    async finalizeRolledBack({ operationId, topologyRevision, priorDeployedRevision, now }) {
        if (typeof operationId !== 'string' || !operationId
            || !validRevision(topologyRevision) || !validRevision(priorDeployedRevision)
            || !validDate(now)) {
            throw new TypeError('Invalid rolled-back topology finalization request');
        }
        return this.transactionRunner(async session => {
            const durable = await this.TopologyOperation.findById(operationId)
                .select('nodes.state nodes.backupId v2Terminal').session(session).lean();
            if (durable?.v2Terminal) rejectFinalization();
            // Terminal labels alone are not rollback proof. A failed or still
            // prepared/committed node must retain the topology admission.
            if (!Array.isArray(durable?.nodes) || !durable.nodes.length
                || durable.nodes.some(node => !['pending', 'rolled_back'].includes(node.state)
                    || (node.state === 'pending' ? node.backupId !== ''
                        : typeof node.backupId !== 'string' || !node.backupId))) return null;
            const operation = await this.TopologyOperation.updateOne({
                _id: operationId,
                topologyRevision,
                priorDeployedRevision,
                status: 'rolled_back',
                heldTopologyAdmission: true,
            }, {
                $set: { heldTopologyAdmission: false },
            }, { runValidators: true, session });
            if (operation?.matchedCount !== 1) rejectFinalization();
            const topology = await this.CascadeTopologyState.updateOne({
                _id: 'singleton',
                deployedRevision: priorDeployedRevision,
                topologyAdmissionCount: 1,
            }, {
                $inc: { topologyAdmissionCount: -1 },
            }, { runValidators: true, session, timestamps: false });
            if (topology?.matchedCount !== 1) rejectFinalization();
            return {
                operationId,
                topologyRevision,
                deployedRevision: priorDeployedRevision,
                finishedAt: now,
            };
        });
    }

    async finalizeSucceeded(request) {
        assertFinalizationRequest(request);
        const allowed = ['operationId', 'owner', 'leaseUntil', 'topologyRevision', 'priorDeployedRevision', 'now', 'pppProof'];
        if (Reflect.ownKeys(request).some(key => !allowed.includes(key))) {
            throw new TypeError('Invalid public topology finalization request');
        }
        return this.#finalizeSucceeded(request);
    }

    async #finalizeSucceeded(request, settlementSession) {
        assertFinalizationRequest(request);
        if (settlementSession && (settlementSession.inTransaction() !== true
            || settlementSession.client !== this.TopologyOperation.db.getClient())) rejectFinalization();
        const {
            operationId,
            owner,
            leaseUntil,
            topologyRevision,
            priorDeployedRevision,
            now,
        } = request;
        const run = settlementSession ? work => work(settlementSession) : this.transactionRunner;
        try {
            return await run(async session => {
                const admission = await this.TopologyOperation.findById(operationId)
                    .select('heldTopologyAdmission pppWait nodes v2Terminal')
                    .session(session)
                    .lean();
                if (!admission || (admission.v2Terminal && !settlementSession)
                    || (settlementSession && (session !== settlementSession || !session.inTransaction()
                        || admission.v2Terminal?.state !== 'proven'))) rejectFinalization();
                const wait = admission.pppWait;
                if (wait || request.pppProof !== undefined) {
                    const proof = request.pppProof;
                    const relayNodes = admission.nodes?.filter(node => node.role === 'relay')
                        .map(node => String(node.node));
                    if (!wait || admission.heldTopologyAdmission !== true
                        || typeof wait.relayNode !== 'string'
                        || !Array.isArray(wait.locks) || !wait.locks.length
                        || wait.locks.some(lock => typeof lock.generation !== 'string'
                            || !lock.generation)
                        || !Array.isArray(wait.releasedNodes)
                        || (wait.probeLocks !== undefined
                            && (!Array.isArray(wait.probeLocks) || wait.probeLocks.length !== 0))
                        || wait.locks.some(lock => !wait.releasedNodes.includes(String(lock.node)))
                        || !Array.isArray(proof) || !proof.length
                        || !Array.isArray(relayNodes)
                        || !relayNodes.includes(wait.relayNode)
                        || new Set(relayNodes).size !== relayNodes.length
                        || proof.length > relayNodes.length
                        || !proof.some(item => item.relayNode === wait.relayNode)
                        || new Set(proof.map(item => item.relayNode)).size !== proof.length
                        || proof.some(item => !relayNodes.includes(item.relayNode)
                            || !validRevision(item.credentialRevision) || item.credentialRevision < 1)
                        || (proof.length < relayNodes.length
                            && typeof this.RelayL2tpState?.findOne !== 'function')
                        || typeof this.RelayL2tpState?.updateOne !== 'function'
                        || this.RelayL2tpState.db !== this.CascadeTopologyState.db) {
                        rejectFinalization();
                    }
                    for (const { relayNode, credentialRevision } of proof) {
                        // A write conflicts with concurrent user edits in this transaction.
                        const fenced = await this.RelayL2tpState.updateOne({
                            node: relayNode, status: 'installed', desiredState: 'installed',
                            secretRevision: credentialRevision,
                        }, { $inc: { replacementFence: 1 } }, { session });
                        if (fenced?.matchedCount !== 1) rejectFinalization();
                    }
                    const provedRelays = new Set(proof.map(item => item.relayNode));
                    for (const relayNode of relayNodes) {
                        if (provedRelays.has(relayNode)) continue;
                        // The gate already checked zero users and no active sync for
                        // this transit relay. Fence its explicit non-PPP state in
                        // the same transaction as topology publication; a user
                        // edit/install changes this document and cannot slip in.
                        const skipped = await this.RelayL2tpState.findOne({ node: relayNode })
                            .select('status desiredState secretRevision').session(session).lean();
                        if (skipped?.status !== 'not_installed'
                            || !['absent', 'not_installed'].includes(skipped.desiredState)
                            || !validRevision(skipped.secretRevision)) rejectFinalization();
                        const fenced = await this.RelayL2tpState.updateOne({
                            node: relayNode, status: 'not_installed',
                            desiredState: skipped.desiredState,
                            secretRevision: skipped.secretRevision,
                        }, { $inc: { replacementFence: 1 } }, { session });
                        if (fenced?.matchedCount !== 1) rejectFinalization();
                    }
                }
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
                        clientReadiness: 'unverified',
                        finishedAt: now,
                        leaseUntil: null,
                        ...(releasesAdmission ? { heldTopologyAdmission: false } : {}),
                    },
                    ...(wait ? { $unset: { pppWait: 1 } } : {}),
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
                        || typeof this.CascadeLink?.find !== 'function'
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
                    await verifyAttachChain(this.CascadeLink, scope, session);
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
                    // Only an empty group or its sole enabled empty main path
                    // may be published. Keep the existing path's metadata when
                    // filling it; both alternatives CAS within this transaction.
                    const group = await this.CascadeRouteGroup.updateOne({
                        _id: scope.groupId, paths: [],
                    }, { $set: { paths: [{ pathKey: scope.pathKey,
                        linkIds: scope.newPathLinkIds, priority: 1, enabled: true }] } },
                    { runValidators: true, session });
                    if (group?.matchedCount !== 1) {
                        const existing = await this.CascadeRouteGroup.updateOne({
                            _id: scope.groupId, paths: { $size: 1 },
                            'paths.0.pathKey': scope.pathKey,
                            'paths.0.linkIds': [],
                            'paths.0.enabled': { $ne: false },
                        }, { $set: { 'paths.0.linkIds': scope.newPathLinkIds } },
                        { runValidators: true, session });
                        if (existing?.matchedCount !== 1) rejectFinalization();
                    }
                    const suffix = await this.CascadeLink.updateMany({
                        _id: { $in: [scope.linkId] }, active: true,
                        status: { $in: ['pending'] },
                    }, { $set: { status: 'deployed' } }, { runValidators: true, session });
                    if (suffix?.matchedCount !== 1) rejectFinalization();
                    const baseline = scope.linkIds.filter(id => id !== scope.linkId);
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
