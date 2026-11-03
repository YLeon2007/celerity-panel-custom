'use strict';

const { randomUUID } = require('node:crypto');
const { entityId } = require('../domain/topologyDraft');

// Include old and new endpoints, and every path changed by dependency cleanup.
// This is deliberately independent of active/status projection: inactive drafts
// still share the same endpoint configuration writers.
function mutationNodeIds(snapshot, mutation) {
    if (Object.keys(mutation.changes || {}).some(key => /^(portalNode|bridgeNode|source|target|paths)\./.test(key))) {
        throw new TopologyDraftRepositoryError('TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED',
            'Dotted structural changes cannot establish a selected-node lock scope');
    }
    const links = snapshot.links || [];
    const groups = snapshot.groups || [];
    const ids = new Set();
    const addLink = link => {
        if (!link) throw new TopologyDraftRepositoryError('TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED', 'A draft dependency disappeared');
        for (const endpoint of [link.portalNode ?? link.source, link.bridgeNode ?? link.target]) {
            const id = entityId(endpoint);
            if (!id) throw new TopologyDraftRepositoryError('TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED', 'A draft endpoint is missing');
            ids.add(id);
        }
    };
    const addGroup = group => {
        for (const path of group?.paths || []) {
            for (const id of path.linkIds || []) addLink(links.find(link => entityId(link) === entityId(id)));
        }
    };
    if (mutation.kind === 'link.create') addLink(mutation.document);
    else if (mutation.kind === 'link.update' || mutation.kind === 'link.delete') {
        const old = links.find(link => entityId(link) === entityId(mutation.id));
        addLink(old);
        if (mutation.kind === 'link.update') addLink({ ...old, ...mutation.changes });
        const affected = new Set([
            ...(mutation.groupUpdates || []).map(update => entityId(update.id)),
            ...(mutation.groupDeletes || []).map(entityId),
        ]);
        for (const group of groups) {
            if (affected.has(entityId(group)) || (group.paths || []).some(path =>
                (path.linkIds || []).some(id => entityId(id) === entityId(mutation.id)))) addGroup(group);
        }
        for (const update of mutation.groupUpdates || []) addGroup(update);
    } else if (mutation.kind.startsWith('group.')) {
        const old = groups.find(group => entityId(group) === entityId(mutation.id));
        addGroup(old);
        if (mutation.kind === 'group.create') addGroup(mutation.document);
        if (mutation.kind === 'group.update') addGroup({ ...old, ...mutation.changes });
    }
    return [...ids].sort();
}

function isStandaloneClassicMutation(snapshot, mutation) {
    if (!['link.create', 'link.update', 'link.delete'].includes(mutation.kind)
        || mutation.groupUpdates?.length || mutation.groupDeletes?.length) return false;
    const old = (snapshot.links || []).find(link => entityId(link) === entityId(mutation.id));
    const variants = mutation.kind === 'link.create' ? [mutation.document]
        : mutation.kind === 'link.delete' ? [old] : [old, { ...old, ...mutation.changes }];
    const roles = new Map((snapshot.nodes || []).map(node => [entityId(node), node.cascadeRole]));
    const nodes = new Set();
    for (const link of variants) {
        const source = entityId(link?.portalNode), target = entityId(link?.bridgeNode);
        if (!source || !target || source === target || (link.mode ?? 'reverse') !== 'reverse'
            || roles.get(source) !== 'portal' || roles.get(target) !== 'bridge'
            || link.geoRouting?.enabled === true || mutation.changes?.['geoRouting.enabled'] === true) return false;
        nodes.add(source); nodes.add(target);
    }
    // Inspect the whole connected draft component, including disabled siblings:
    // a hidden continuation through a sibling bridge is not a standalone pair.
    let expanded = true;
    while (expanded) {
        expanded = false;
        for (const link of snapshot.links || []) {
            const source = entityId(link.portalNode), target = entityId(link.bridgeNode);
            if (!nodes.has(source) && !nodes.has(target)) continue;
            for (const id of [source, target]) {
                if (id && !nodes.has(id)) { nodes.add(id); expanded = true; }
            }
        }
    }
    const touching = (snapshot.links || []).filter(link =>
        nodes.has(entityId(link.portalNode)) || nodes.has(entityId(link.bridgeNode)));
    // A shared portal may have sibling terminal bridges, but no transit/forward
    // links or incoming portal hop may participate in this narrow exception.
    if (touching.some(link => (link.mode ?? 'reverse') !== 'reverse'
        || roles.get(entityId(link.portalNode)) !== 'portal'
        || roles.get(entityId(link.bridgeNode)) !== 'bridge'
        || link.geoRouting?.enabled === true)) return false;
    const touchingIds = new Set(touching.map(entityId));
    for (const link of variants) touchingIds.add(entityId(link));
    if ((snapshot.groups || []).some(group => (group.paths || []).some(path =>
        (path.linkIds || []).some(id => touchingIds.has(entityId(id)))))) return false;
    // Missing reference inventory is not proof of independence.
    if (!Array.isArray(snapshot.relayReferences) || snapshot.relayReferences.some(row =>
        nodes.has(entityId(row.node)))) return false;
    return true;
}

const ACTIVE_NODE_ROLES = Object.freeze(['portal', 'relay', 'bridge']);
const ACTIVE_RELAY_STATUSES = Object.freeze([
    'queued',
    'preflight',
    'installing',
    'installed',
    'degraded',
    'drifted',
    'removing',
]);
const NODE_FILTER = Object.freeze({
    type: 'xray',
    active: true,
    cascadeRole: Object.freeze({ $in: ACTIVE_NODE_ROLES }),
});
const ACTIVE_ROUTE_GROUP_FILTER = Object.freeze({
    routeGroup: Object.freeze({ $ne: null }),
    $or: Object.freeze([
        Object.freeze({ desiredState: 'installed' }),
        Object.freeze({ status: Object.freeze({ $in: ACTIVE_RELAY_STATUSES }) }),
    ]),
});
const NODE_SELECT = '_id cascadeRole';
const LINK_SELECT = '_id portalNode bridgeNode mode active status geoRouting.enabled';
const GROUP_SELECT = '_id name mode strategy paths.pathKey paths.linkIds paths.priority paths.enabled';
const ROUTE_GROUP_REFERENCE_SELECT = 'routeGroup status node activePathKey appliedTopologyRevision secretRevision';
const TOPOLOGY_STATE_SELECT = 'revision deployedRevision replacementReservation topologyAdmissionCount';

class TopologyDraftRepositoryError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyDraftRepositoryError';
        this.code = code;
        Object.assign(this, details);
    }
}

function staleRevision(expectedRevision, actualRevision) {
    return new TopologyDraftRepositoryError(
        'STALE_TOPOLOGY_REVISION',
        'The topology changed before this draft mutation could be committed',
        { expectedTopologyRevision: expectedRevision, topologyRevision: actualRevision },
    );
}

function defaultTransactionRunner(models) {
    const connection = models.CascadeTopologyState?.db;
    const participatingModels = [
        models.HyNode,
        models.CascadeLink,
        models.CascadeRouteGroup,
        models.CascadeTopologyState,
        models.RelayL2tpState,
    ];
    if (
        !connection
        || participatingModels.some(model => model?.db !== connection)
        || typeof connection.transaction !== 'function'
    ) {
        return null;
    }
    return work => connection.transaction(work);
}

function withSession(query, session) {
    return session === undefined ? query : query.session(session);
}

class TopologyDraftRepository {
    constructor({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        CascadeTopologyState,
        RelayL2tpState,
        transactionRunner,
        withScopedNodeLocks,
        allowStandaloneClassicDrafts = false,
    } = {}) {
        const models = {
            HyNode,
            CascadeLink,
            CascadeRouteGroup,
            CascadeTopologyState,
            RelayL2tpState,
        };
        if (!HyNode || typeof HyNode.find !== 'function') {
            throw new TypeError('Topology draft repository requires HyNode.find');
        }
        if (
            !CascadeLink
            || typeof CascadeLink.find !== 'function'
            || typeof CascadeLink.create !== 'function'
            || typeof CascadeLink.updateOne !== 'function'
            || typeof CascadeLink.deleteOne !== 'function'
        ) {
            throw new TypeError('Topology draft repository requires the CascadeLink model');
        }
        if (
            !CascadeRouteGroup
            || typeof CascadeRouteGroup.find !== 'function'
            || typeof CascadeRouteGroup.create !== 'function'
            || typeof CascadeRouteGroup.updateOne !== 'function'
            || typeof CascadeRouteGroup.deleteOne !== 'function'
        ) {
            throw new TypeError('Topology draft repository requires the CascadeRouteGroup model');
        }
        if (
            !CascadeTopologyState
            || typeof CascadeTopologyState.findById !== 'function'
            || typeof CascadeTopologyState.findOneAndUpdate !== 'function'
        ) {
            throw new TypeError('Topology draft repository requires the CascadeTopologyState model');
        }
        if (!RelayL2tpState || typeof RelayL2tpState.find !== 'function') {
            throw new TypeError('Topology draft repository requires RelayL2tpState.find');
        }
        const runTransaction = transactionRunner ?? defaultTransactionRunner(models);
        if (typeof runTransaction !== 'function') {
            throw new TypeError('Topology draft repository requires a transaction runner');
        }
        Object.assign(this, models);
        if (withScopedNodeLocks !== undefined && typeof withScopedNodeLocks !== 'function') {
            throw new TypeError('Topology draft repository requires withScopedNodeLocks to be a function');
        }
        this.withScopedNodeLocks = withScopedNodeLocks;
        this.allowStandaloneClassicDrafts = allowStandaloneClassicDrafts === true;
        this.transactionRunner = runTransaction;
    }

    async readDraft(session) {
        const topologyQuery = this.CascadeTopologyState.findById('singleton')
            .select(TOPOLOGY_STATE_SELECT);
        const nodeQuery = this.HyNode.find(NODE_FILTER).select(NODE_SELECT);
        const linkQuery = this.CascadeLink.find({}).select(LINK_SELECT);
        const groupQuery = this.CascadeRouteGroup.find({}).select(GROUP_SELECT);
        const relayStateQuery = this.RelayL2tpState.find(this.withScopedNodeLocks ? {} : ACTIVE_ROUTE_GROUP_FILTER)
            .select(this.withScopedNodeLocks
                ? `${ROUTE_GROUP_REFERENCE_SELECT} desiredState installedRouteGroup` : ROUTE_GROUP_REFERENCE_SELECT);
        const state = await withSession(topologyQuery, session).lean();
        const nodes = await withSession(nodeQuery, session).lean();
        const links = await withSession(linkQuery, session).lean();
        const groups = await withSession(groupQuery, session).lean();
        const relayStates = await withSession(relayStateQuery, session).lean();
        const activeRelayStates = this.withScopedNodeLocks ? (relayStates || []).filter(row =>
            row.routeGroup != null && (row.desiredState === 'installed' || ACTIVE_RELAY_STATUSES.includes(row.status))) : relayStates;
        return {
            ...(this.withScopedNodeLocks ? { relayReferences: relayStates || [] } : {}),
            revision: state?.revision ?? 0,
            deployedRevision: state?.deployedRevision ?? 0,
            ...(state?.topologyAdmissionCount !== undefined ? { topologyAdmissionCount: state.topologyAdmissionCount } : {}),
            ...(state?.replacementReservation ? { replacementReservation: state.replacementReservation } : {}),
            nodes: nodes || [],
            links: links || [],
            groups: groups || [],
            activeRouteGroupIds: (activeRelayStates || [])
                .map(relayState => relayState.routeGroup)
                .filter(routeGroup => routeGroup !== undefined && routeGroup !== null),
            installedRouteGroupIds: (activeRelayStates || [])
                .filter(relayState => relayState.status === 'installed')
                .map(relayState => relayState.routeGroup)
                .filter(routeGroup => routeGroup !== undefined && routeGroup !== null),
            installedRouteOwners: (activeRelayStates || [])
                .filter(relayState => relayState.status === 'installed'
                    && relayState.routeGroup != null && relayState.node != null)
                .map(relayState => ({
                    groupId: relayState.routeGroup,
                    nodeId: relayState.node,
                    pathKey: relayState.activePathKey,
                    ...(relayState.appliedTopologyRevision !== undefined ? {
                        ownerTopologyRevision: relayState.appliedTopologyRevision,
                    } : {}),
                    ...(relayState.secretRevision !== undefined ? {
                        ownerCredentialRevision: relayState.secretRevision,
                    } : {}),
                })),
        };
    }

    async persistMutation(mutation, session) {
        if (mutation?.kind === 'link.create') {
            await this.CascadeLink.create([mutation.document], { session });
            return;
        }
        if (mutation?.kind === 'link.update') {
            const result = await this.CascadeLink.updateOne(
                { _id: mutation.id },
                { $set: mutation.changes || {} },
                { runValidators: true, session },
            );
            if (result.matchedCount !== 1) {
                throw new TopologyDraftRepositoryError(
                    'CASCADE_LINK_NOT_FOUND',
                    'The cascade link was not found',
                    { linkId: mutation.id },
                );
            }
            return;
        }
        if (mutation?.kind === 'link.delete') {
            const result = await this.CascadeLink.deleteOne({ _id: mutation.id }, { session });
            if (result.deletedCount !== 1) {
                throw new TopologyDraftRepositoryError(
                    'CASCADE_LINK_NOT_FOUND',
                    'The cascade link was not found',
                    { linkId: mutation.id },
                );
            }
            // Apply the group side effects computed by the draft builder:
            // strip paths that referenced the link and drop emptied groups.
            for (const update of mutation.groupUpdates || []) {
                await this.CascadeRouteGroup.updateOne(
                    { _id: update.id },
                    { $set: { paths: update.paths } },
                    { runValidators: true, session },
                );
            }
            for (const groupId of mutation.groupDeletes || []) {
                await this.CascadeRouteGroup.deleteOne({ _id: groupId }, { session });
            }
            return;
        }
        if (mutation?.kind === 'group.create') {
            await this.CascadeRouteGroup.create([mutation.document], { session });
            return;
        }
        if (mutation?.kind === 'group.update') {
            const result = await this.CascadeRouteGroup.updateOne(
                { _id: mutation.id },
                { $set: mutation.changes || {} },
                { runValidators: true, session },
            );
            if (result.matchedCount !== 1) {
                throw new TopologyDraftRepositoryError(
                    'CASCADE_ROUTE_GROUP_NOT_FOUND',
                    'The cascade route group was not found',
                    { routeGroupId: mutation.id },
                );
            }
            return;
        }
        if (mutation?.kind === 'group.delete') {
            const result = await this.CascadeRouteGroup.deleteOne(
                { _id: mutation.id },
                { session },
            );
            if (result.deletedCount !== 1) {
                throw new TopologyDraftRepositoryError(
                    'CASCADE_ROUTE_GROUP_NOT_FOUND',
                    'The cascade route group was not found',
                    { routeGroupId: mutation.id },
                );
            }
            return;
        }
        throw new TopologyDraftRepositoryError(
            'UNSUPPORTED_TOPOLOGY_MUTATION',
            `Unsupported topology mutation: ${mutation?.kind}`,
        );
    }

    async commitDraft({ expectedRevision, prepare }) {
        if (typeof prepare !== 'function') {
            throw new TypeError('Topology draft commit requires a prepare function');
        }
        try {
            const commit = (held, heldIds) => this.transactionRunner(async session => {
                const snapshot = await this.readDraft(session);
                if (snapshot.revision !== expectedRevision) {
                    throw staleRevision(expectedRevision, snapshot.revision);
                }
                let prepared = heldIds ? await prepare(snapshot) : null;
                const standalone = !!held && this.allowStandaloneClassicDrafts
                    && isStandaloneClassicMutation(snapshot, prepared?.mutation);
                if (heldIds) {
                    const changedIds = mutationNodeIds(snapshot, prepared?.mutation);
                    if (changedIds.some(id => !heldIds.has(id))) {
                        throw new TopologyDraftRepositoryError('TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED',
                            'The fresh draft mutation exceeds its selected-node locks');
                    }
                    if (held) await held.verify();
                }
                if (!standalone && snapshot.replacementReservation) {
                    throw new TopologyDraftRepositoryError(
                        'TOPOLOGY_REPLACEMENT_RESERVED',
                        'A topology replacement owns the draft mutation fence',
                    );
                }
                if (!standalone && snapshot.topologyAdmissionCount > 0) {
                    throw new TopologyDraftRepositoryError('TOPOLOGY_DEPLOY_BUSY', 'An active operation owns the exact topology revision');
                }
                prepared ??= await prepare(snapshot);
                await this.persistMutation(prepared?.mutation, session);
                const update = { $inc: { revision: 1 } };
                if (expectedRevision === 0) {
                    update.$setOnInsert = { deployedRevision: 0 };
                }
                const state = await this.CascadeTopologyState.findOneAndUpdate(
                    {
                        _id: 'singleton',
                        revision: expectedRevision,
                        // Independent classic drafts still serialize through the
                        // real global revision CAS, but do not own or clear an
                        // unrelated native operation's reservation/counters.
                        ...(!standalone ? {
                            topologyAdmissionCount: 0,
                            replacementReservation: { $exists: false },
                        } : {}),
                    },
                    update,
                    {
                        new: true,
                        runValidators: true,
                        session,
                        upsert: expectedRevision === 0,
                    },
                )
                    .select(TOPOLOGY_STATE_SELECT)
                    .lean();
                if (!state) throw staleRevision(expectedRevision, null);
                if (held) await held.verify();
                return {
                    revision: state.revision,
                    deployedRevision: state.deployedRevision ?? 0,
                    ...(standalone ? { standaloneClassicDraft: true } : {}),
                };
            });
            if (!this.withScopedNodeLocks) return await commit();
            const snapshot = await this.readDraft();
            if (snapshot.revision !== expectedRevision) throw staleRevision(expectedRevision, snapshot.revision);
            const prepared = await prepare(snapshot);
            const nodeIds = mutationNodeIds(snapshot, prepared?.mutation);
            // Empty groups have no node writers to exclude. Still recheck the
            // empty changed-set inside the transaction and retain strict CAS.
            if (nodeIds.length === 0) return await commit(undefined, new Set());
            return await this.withScopedNodeLocks({
                nodeIds, operationId: `classic-draft:${randomUUID()}`,
            }, async held => {
                if (typeof held?.verify !== 'function') throw new TypeError('Draft node locks require held.verify');
                await held.verify();
                // No beforeRemoteMutation: this scope is pure transactional DB work.
                return commit(held, new Set(nodeIds));
            });
        } catch (error) {
            if (expectedRevision === 0 && (error?.code === 11000 || error?.code === 11001)) {
                throw staleRevision(expectedRevision, null);
            }
            throw error;
        }
    }
}

module.exports = {
    // Checked deletion can derive its outer union with the same dependency
    // rules before entering a reentrant draft/config lock scope.
    mutationNodeIds,
    isStandaloneClassicMutation,
    ACTIVE_NODE_ROLES,
    ACTIVE_RELAY_STATUSES,
    ACTIVE_ROUTE_GROUP_FILTER,
    GROUP_SELECT,
    LINK_SELECT,
    NODE_FILTER,
    NODE_SELECT,
    ROUTE_GROUP_REFERENCE_SELECT,
    TOPOLOGY_STATE_SELECT,
    TopologyDraftRepository,
    TopologyDraftRepositoryError,
};
