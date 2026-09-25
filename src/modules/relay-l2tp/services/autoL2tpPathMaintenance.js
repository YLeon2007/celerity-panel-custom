'use strict';

// Keeps the L2TP auto route-group paths in sync with the live cascade graph.
// Deleting a link strips the paths that used it (draft mutation), and without
// this hook the group stayed empty until a full L2TP reinstall — silently
// stranding every L2TP client (fail-closed block). After any link
// create/update/delete the panel rebuilds the default-chain path for every
// relay with an installed L2TP state, so a rebuilt topology heals the L2TP
// path on the next topology sync instead of requiring a reinstall.

const { buildDefaultChainLinkIds } = require('../domain/defaultChainPath');

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

async function maintainAutoL2tpPaths({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    RelayL2tpState,
    CascadeTopologyState,
    logger,
} = {}) {
    const states = await RelayL2tpState.find({
        desiredState: 'installed',
        routeGroup: { $ne: null },
    }).lean();
    if (!Array.isArray(states) || states.length === 0) return { updated: 0 };

    const links = await CascadeLink.find({}).lean();
    const nodes = await HyNode.find({}).select('_id cascadeRole').lean();
    const nodesById = new Map((nodes || []).map(node => [String(node._id), node]));

    let updated = 0;
    for (const state of states) {
        const groupId = entityId(state.routeGroup);
        if (!groupId) continue;
        const group = await CascadeRouteGroup.findById(groupId).lean();
        if (!group) continue;

        let linkIds;
        try {
            linkIds = buildDefaultChainLinkIds({ links, nodesById, startNodeId: entityId(state.node) });
        } catch (error) {
            // Ambiguous branch or loop: the graph is mid-rebuild — leave the
            // group untouched and let the operator finish the topology.
            logger?.warn?.(`[L2TP] auto path rebuild skipped for relay ${entityId(state.node)}: ${error.message}`);
            continue;
        }
        const wanted = linkIds.length > 0
            ? [{ pathKey: 'main', linkIds, priority: 1, enabled: true }]
            : [];
        if (samePaths(group.paths, wanted)) continue;

        await CascadeRouteGroup.findByIdAndUpdate(groupId, { $set: { paths: wanted } });
        updated += 1;
        logger?.info?.(`[L2TP] auto-l2tp path rebuilt for relay ${entityId(state.node)} (${linkIds.length} hop(s))`);
    }

    if (updated > 0 && CascadeTopologyState) {
        await CascadeTopologyState.findByIdAndUpdate(
            'singleton',
            { $inc: { revision: 1 } },
            { upsert: true },
        );
    }
    return { updated };
}

module.exports = { maintainAutoL2tpPaths };
