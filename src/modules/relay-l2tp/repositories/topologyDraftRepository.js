'use strict';

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
const LINK_SELECT = '_id portalNode bridgeNode mode active';
const GROUP_SELECT = '_id name mode strategy paths.pathKey paths.linkIds paths.priority';
const ROUTE_GROUP_REFERENCE_SELECT = 'routeGroup';
const TOPOLOGY_STATE_SELECT = 'revision deployedRevision';

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
        this.transactionRunner = runTransaction;
    }

    async readDraft(session) {
        const topologyQuery = this.CascadeTopologyState.findById('singleton')
            .select(TOPOLOGY_STATE_SELECT);
        const nodeQuery = this.HyNode.find(NODE_FILTER).select(NODE_SELECT);
        const linkQuery = this.CascadeLink.find({}).select(LINK_SELECT);
        const groupQuery = this.CascadeRouteGroup.find({}).select(GROUP_SELECT);
        const relayStateQuery = this.RelayL2tpState.find(ACTIVE_ROUTE_GROUP_FILTER)
            .select(ROUTE_GROUP_REFERENCE_SELECT);
        const state = await withSession(topologyQuery, session).lean();
        const nodes = await withSession(nodeQuery, session).lean();
        const links = await withSession(linkQuery, session).lean();
        const groups = await withSession(groupQuery, session).lean();
        const activeRelayStates = await withSession(relayStateQuery, session).lean();
        return {
            revision: state?.revision ?? 0,
            deployedRevision: state?.deployedRevision ?? 0,
            nodes: nodes || [],
            links: links || [],
            groups: groups || [],
            activeRouteGroupIds: (activeRelayStates || [])
                .map(relayState => relayState.routeGroup)
                .filter(routeGroup => routeGroup !== undefined && routeGroup !== null),
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
            return await this.transactionRunner(async session => {
                const snapshot = await this.readDraft(session);
                if (snapshot.revision !== expectedRevision) {
                    throw staleRevision(expectedRevision, snapshot.revision);
                }
                const prepared = await prepare(snapshot);
                await this.persistMutation(prepared?.mutation, session);
                const update = { $inc: { revision: 1 } };
                if (expectedRevision === 0) {
                    update.$setOnInsert = { deployedRevision: 0 };
                }
                const state = await this.CascadeTopologyState.findOneAndUpdate(
                    { _id: 'singleton', revision: expectedRevision },
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
                return {
                    revision: state.revision,
                    deployedRevision: state.deployedRevision ?? 0,
                };
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
