'use strict';

// Keeps the L2TP auto route-group paths in sync with the live cascade graph.
// Deleting a link strips the paths that used it (draft mutation), and without
// this hook the group stayed empty until a full L2TP reinstall — silently
// stranding every L2TP client (fail-closed block). Maintenance may populate
// an empty owned path from a confirmed, client-ready chain. A nonempty
// installed path is never switched here: replacement needs separate ingress
// preparation and atomic finalization, even when the new links look deployed.
//
// Safety contract:
// - Only active deployed/online suffixes reaching a bridge-role node are
//   eligible. A delete/recreate gap or partial/unconfirmed chain defers the
//   update: no empty, partial or pending path is ever written.
// - The write populates only the recorded path key owned by this relay;
//   paths of other relays sharing the group are preserved.
// - RelayL2tpState, the route group identity and PPP credentials are never
//   touched — the group update sets `paths` and nothing else.

const { buildDefaultChainPath } = require('../domain/defaultChainPath');

function entityId(entity) {
    if (!entity) return '';
    if (typeof entity === 'string') return entity;
    if (typeof entity === 'object') {
        // bson ObjectId exposes a self-referencing `_id` getter — stringify
        // it before the generic `_id`/`id` branches to avoid recursion.
        if (typeof entity.toHexString === 'function') return entity.toHexString();
        if (entity._id !== undefined && entity._id !== entity) return entityId(entity._id);
        if (entity.id !== undefined && entity.id !== entity) return entityId(entity.id);
    }
    return String(entity);
}

function samePaths(groupPaths, wanted) {
    const normalize = paths => (paths || []).map(path => ({
        key: path.pathKey,
        links: (path.linkIds || []).map(String),
    }));
    return JSON.stringify(normalize(groupPaths)) === JSON.stringify(normalize(wanted));
}

// Route-group path keys are unique by schema and are recorded on the installed
// relay state. Do not infer ownership from the first link: that link may have
// been deleted or reassigned before this maintenance pass. Two installed relays
// claiming the same key in one group are ambiguous; leave the group untouched.
function pathKeyForState(state) {
    return typeof state.activePathKey === 'string' && state.activePathKey.trim()
        ? state.activePathKey
        : 'main';
}

function maintenanceError(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
}

function defaultTransactionRunner(models) {
    const connection = models.CascadeTopologyState?.db;
    if (!connection || typeof connection.transaction !== 'function'
        || Object.values(models).some(model => model?.db !== connection)) {
        throw new TypeError('L2TP path maintenance requires models on one transactional Mongo connection');
    }
    return work => connection.transaction(work);
}

async function maintainAutoL2tpPaths({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    RelayL2tpState,
    CascadeTopologyState,
    transactionRunner,
    logger,
} = {}) {
    const models = { HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState, CascadeTopologyState };
    const runTransaction = transactionRunner ?? defaultTransactionRunner(models);
    if (typeof runTransaction !== 'function') {
        throw new TypeError('L2TP path maintenance requires a transaction runner');
    }
    // Graph, group paths and the singleton CAS share one Mongo snapshot. A
    // reservation arriving after this read also conflicts with the CAS below;
    // Mongo aborts the transaction and rolls back every staged group path.
    return runTransaction(async session => {
        const topology = await CascadeTopologyState.findById('singleton')
            .select('revision replacementReservation').session(session).lean();
        if (topology?.replacementReservation) {
            throw maintenanceError('TOPOLOGY_REPLACEMENT_RESERVED', 'A topology replacement owns the maintenance fence');
        }
        const expectedRevision = topology?.revision ?? 0;
        const states = await RelayL2tpState.find({
            desiredState: 'installed',
            routeGroup: { $ne: null },
        }).session(session).lean();
        if (!Array.isArray(states) || states.length === 0) {
            return { updated: 0, deferred: [], revision: null };
        }

        // Draft links are not proof of a client-ready cascade. A pending,
        // staged, offline, errored or disabled hop cannot be auto-published.
        const links = (await CascadeLink.find({}).session(session).lean() || [])
            .filter(link => link.active !== false && ['deployed', 'online'].includes(link.status));
        const nodes = await HyNode.find({}).select('_id cascadeRole').session(session).lean();
        const nodesById = new Map((nodes || []).map(node => [String(node._id), node]));

        let updated = 0;
        const deferred = [];
        for (const state of states) {
            const relayId = entityId(state.node);
            const groupId = entityId(state.routeGroup);
            if (!groupId) continue;
            const pathKey = pathKeyForState(state);
            const claimants = states.filter(other =>
                entityId(other.routeGroup) === groupId && pathKeyForState(other) === pathKey);
            if (claimants.length !== 1) {
                logger?.warn?.(`[L2TP] auto path rebuild deferred for relay ${relayId}: ambiguous route group path key`);
                deferred.push({ relayNode: relayId, routeGroup: groupId, reason: 'AMBIGUOUS_ROUTE_GROUP_OWNERSHIP' });
                continue;
            }
            const group = await CascadeRouteGroup.findById(groupId).session(session).lean();
            if (!group) continue;

            let chain;
            try {
                chain = buildDefaultChainPath({ links, nodesById, startNodeId: relayId });
            } catch (error) {
                // Ambiguous branch or loop: the graph is mid-rebuild — leave the
                // group untouched and let the operator finish the topology.
                logger?.warn?.(`[L2TP] auto path rebuild skipped for relay ${relayId}: ${error.message}`);
                deferred.push({ relayNode: relayId, routeGroup: groupId, reason: error.code });
                continue;
            }
            if (!chain.complete || chain.linkIds.length === 0) {
                // Gap or partial suffix: keep the last working path. Publishing an
                // empty or bridge-less path would strand L2TP clients or leak PPP
                // traffic without a cascade egress; fail-closed with automatic
                // recovery on the next link mutation instead.
                logger?.warn?.(`[L2TP] auto path rebuild deferred for relay ${relayId}: chain does not reach a bridge yet`);
                deferred.push({ relayNode: relayId, routeGroup: groupId, reason: 'CHAIN_INCOMPLETE' });
                continue;
            }

            const existingPaths = group.paths || [];
            const ownedIndexes = existingPaths
                .map((path, index) => (path.pathKey === pathKey ? index : -1))
                .filter(index => index >= 0);
            if (ownedIndexes.length > 1) {
                logger?.warn?.(`[L2TP] auto path rebuild deferred for relay ${relayId}: duplicate route group path key`);
                deferred.push({ relayNode: relayId, routeGroup: groupId, reason: 'AMBIGUOUS_ROUTE_GROUP_OWNERSHIP' });
                continue;
            }
            const newPath = { pathKey, linkIds: chain.linkIds, priority: 1, enabled: true };
            // Replace the recorded key in place; foreign keys keep their entries.
            const wanted = ownedIndexes.length === 0
                ? [...existingPaths, newPath]
                : existingPaths
                    .map((path, index) => (index === ownedIndexes[0] ? newPath : path))
                    .filter((path, index) => !ownedIndexes.includes(index) || index === ownedIndexes[0]);
            if (samePaths(existingPaths, wanted)) continue;

            // A confirmed link alone does not prove that replacement ingress
            // was prepared. Only the dedicated replacement operation can
            // atomically switch an installed, nonempty path to different hops.
            // Keep the old route even if its links vanished from the draft.
            if (ownedIndexes.length && existingPaths[ownedIndexes[0]].linkIds?.length) {
                logger?.warn?.(`[L2TP] auto path rebuild deferred for relay ${relayId}: replacement requires prepared ingress`);
                deferred.push({ relayNode: relayId, routeGroup: groupId, reason: 'REPLACEMENT_REQUIRES_PREPARED_INGRESS' });
                continue;
            }

            const result = await CascadeRouteGroup.updateOne(
                { _id: groupId }, { $set: { paths: wanted } }, { runValidators: true, session },
            );
            if (result.matchedCount !== 1) {
                throw maintenanceError('CASCADE_ROUTE_GROUP_NOT_FOUND', 'The route group changed during maintenance');
            }
            updated += 1;
        }

        if (updated === 0) return { updated, deferred, revision: null };
        const update = { $inc: { revision: 1 } };
        if (!topology) update.$setOnInsert = { deployedRevision: 0 };
        const state = await CascadeTopologyState.findOneAndUpdate(
            {
                _id: 'singleton',
                revision: expectedRevision,
                replacementReservation: { $exists: false },
            },
            update,
            { new: true, runValidators: true, session, upsert: !topology },
        ).select('revision').lean();
        if (!state) {
            throw maintenanceError('TOPOLOGY_MAINTENANCE_CONFLICT', 'The topology changed during L2TP path maintenance');
        }
        return { updated, deferred, revision: state.revision };
    });
}

module.exports = { maintainAutoL2tpPaths };
