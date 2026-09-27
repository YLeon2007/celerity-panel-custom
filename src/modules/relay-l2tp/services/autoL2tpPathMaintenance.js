'use strict';

// Keeps the L2TP auto route-group paths in sync with the live cascade graph.
// Deleting a link strips the paths that used it (draft mutation), and without
// this hook the group stayed empty until a full L2TP reinstall — silently
// stranding every L2TP client (fail-closed block). After any link
// create/update/delete the panel rebuilds the default-chain path for every
// relay with an installed L2TP state, so a rebuilt topology heals the L2TP
// path on the next topology sync instead of requiring a reinstall.
//
// Safety contract:
// - Only a suffix that actually reaches a bridge-role node is published. A
//   temporary delete/recreate gap or a partial chain defers the update: the
//   last working path stays in the group and no empty/partial path is ever
//   written ("no empty/partial path published").
// - The write replaces only the path owned by this relay (first hop leaves
//   the relay); paths of other relays sharing the group are preserved.
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

// A path belongs to a relay when its first hop leaves that relay. Paths whose
// first link is gone (mid-delete) are treated as foreign and preserved — the
// draft mutation is responsible for stripping dangling references.
function pathOwnedByRelay(path, linksById, relayId) {
    const firstLinkId = (path?.linkIds || [])[0];
    if (firstLinkId === undefined || firstLinkId === null) return false;
    const firstLink = linksById.get(entityId(firstLinkId));
    return firstLink !== undefined && entityId(firstLink.portalNode) === relayId;
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
    if (!Array.isArray(states) || states.length === 0) {
        return { updated: 0, deferred: [], revision: null };
    }

    const links = await CascadeLink.find({}).lean();
    const nodes = await HyNode.find({}).select('_id cascadeRole').lean();
    const nodesById = new Map((nodes || []).map(node => [String(node._id), node]));
    const linksById = new Map((links || []).map(link => [entityId(link._id), link]));

    let updated = 0;
    const deferred = [];
    for (const state of states) {
        const relayId = entityId(state.node);
        const groupId = entityId(state.routeGroup);
        if (!groupId) continue;
        const group = await CascadeRouteGroup.findById(groupId).lean();
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
        const newPath = { pathKey: 'main', linkIds: chain.linkIds, priority: 1, enabled: true };
        // Replace this relay's own path in place (stable order keeps the
        // write idempotent across multiple relays sharing one group); append
        // only when the relay had no path of its own. Foreign paths keep
        // their entries and positions untouched.
        const ownedIndexes = existingPaths
            .map((path, index) => (pathOwnedByRelay(path, linksById, relayId) ? index : -1))
            .filter(index => index >= 0);
        const wanted = ownedIndexes.length === 0
            ? [...existingPaths, newPath]
            : existingPaths
                .map((path, index) => (index === ownedIndexes[0] ? newPath : path))
                .filter((path, index) => !ownedIndexes.includes(index) || index === ownedIndexes[0]);
        if (samePaths(existingPaths, wanted)) continue;

        await CascadeRouteGroup.findByIdAndUpdate(groupId, { $set: { paths: wanted } });
        updated += 1;
        logger?.info?.(`[L2TP] auto-l2tp path rebuilt for relay ${relayId} (${chain.linkIds.length} hop(s))`);
    }

    let revision = null;
    if (updated > 0 && CascadeTopologyState) {
        // Re-read the post-maintenance revision so callers never act on a
        // snapshot taken before the path write.
        const state = await CascadeTopologyState.findByIdAndUpdate(
            'singleton',
            { $inc: { revision: 1 } },
            { upsert: true, new: true },
        );
        revision = state?.revision ?? null;
    }
    return { updated, deferred, revision };
}

module.exports = { maintainAutoL2tpPaths };
