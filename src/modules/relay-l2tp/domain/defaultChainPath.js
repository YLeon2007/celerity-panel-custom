'use strict';

// Shared "default chain" walk: starting at a relay, follow the single
// non-geoRouting hop at every branching node until a bridge-role node (or the
// end of the chain). Geo links are side branches and never part of the
// automatic L2TP path. Used by the L2TP auto route-group builder and by the
// topology link maintenance hook, so both agree on what the main path is.

const DEFAULT_MAX_HOPS = 16;

class DefaultChainPathError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'DefaultChainPathError';
        this.code = code;
    }
}

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

function nodeRole(node) {
    return node?.cascadeRole || 'standalone';
}

function buildDefaultChainPath({
    links,
    nodesById,
    startNodeId,
    maxHops = DEFAULT_MAX_HOPS,
} = {}) {
    const byPortal = new Map();
    for (const link of links || []) {
        const portal = entityId(link.portalNode);
        if (!byPortal.has(portal)) byPortal.set(portal, []);
        byPortal.get(portal).push(link);
    }

    const ordered = [];
    let current = String(startNodeId);
    const visited = new Set([current]);
    // A start node that already is the bridge egress needs no hops.
    if (nodeRole(nodesById?.get(current)) === 'bridge') {
        return { linkIds: ordered, complete: true, endNodeId: current };
    }
    for (let hop = 0; hop < maxHops; hop += 1) {
        // Geo links are side branches and never part of the automatic L2TP
        // path — not even when they are the only outgoing link. Filtering
        // them up front also keeps a lone geo branch from being treated as
        // the default hop.
        const candidates = (byPortal.get(current) ?? [])
            .filter(candidate => candidate?.geoRouting?.enabled !== true);
        if (candidates.length === 0) break;
        if (candidates.length > 1) {
            throw new DefaultChainPathError(
                'ROUTE_GROUP_AMBIGUOUS',
                'Automatic L2TP route group creation needs a linear cascade chain',
            );
        }
        const link = candidates[0];
        ordered.push(link._id);
        current = entityId(link.bridgeNode);
        if (visited.has(current)) {
            throw new DefaultChainPathError(
                'ROUTE_GROUP_AMBIGUOUS',
                'Automatic L2TP route group creation detected a cascade loop',
            );
        }
        visited.add(current);
        if (nodeRole(nodesById?.get(current)) === 'bridge') {
            return { linkIds: ordered, complete: true, endNodeId: current };
        }
    }
    // The walk ended without reaching a bridge-role node: the suffix is a
    // partial chain and must not be published as an egress path.
    return { linkIds: ordered, complete: false, endNodeId: current };
}

function buildDefaultChainLinkIds(options = {}) {
    return buildDefaultChainPath(options).linkIds;
}

module.exports = {
    DefaultChainPathError,
    buildDefaultChainLinkIds,
    buildDefaultChainPath,
};
