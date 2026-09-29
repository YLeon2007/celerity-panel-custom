'use strict';

// Private, in-memory candidate only. No persisted mutation, queueing or rollout.
const { entityId, projectGroups, projectLinks, projectNodes } = require('./topologyDraft');
const { compileTopology } = require('./topologyCompiler');
const { cascadePathIngressPort, cascadePathIngressTag } = require('./cascadePathIngress');

const CONFIRMED = new Set(['deployed', 'online', 'staged']);

class TopologyReplacementError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'TopologyReplacementError';
        this.code = code;
    }
}

function fail(code, message) {
    throw new TopologyReplacementError(code, message);
}

function unique(rows, code) {
    const result = new Map();
    for (const row of rows || []) {
        const id = entityId(row);
        if (!id || result.has(id)) fail(code, 'Replacement requires unique, nonempty identities');
        result.set(id, row);
    }
    return result;
}

function pathIds(path) {
    if (!Array.isArray(path?.linkIds)) fail('INCOMPLETE_PATH', 'The installed path has no link sequence');
    return path.linkIds.map(entityId);
}

/**
 * Derive the effective graph of one installed, enabled L2TP path with its
 * downstream link replaced. The persisted snapshot remains untouched.
 * The returned topology/compiled pair is directly consumable by the frozen
 * composer with separately hydrated metadata; it is NOT a deployment plan.
 */
function deriveReplacementTopology(snapshot, request) {
    if (!snapshot || !Array.isArray(snapshot.nodes) || !Array.isArray(snapshot.links)
        || !Array.isArray(snapshot.groups) || !Array.isArray(snapshot.activeRouteGroupIds)
        || !Array.isArray(snapshot.installedRouteGroupIds)
        || !request || typeof request !== 'object'
        || !['groupId', 'pathKey', 'oldLinkId', 'newLinkId'].every(key =>
            typeof request[key] === 'string' && request[key].length > 0)
        || request.oldLinkId === request.newLinkId) {
        fail('INVALID_REPLACEMENT_REQUEST', 'A complete installed snapshot and distinct replacement identities are required');
    }
    const nodesById = unique(snapshot.nodes, 'AMBIGUOUS_NODE');
    const linksById = unique(snapshot.links, 'AMBIGUOUS_LINK');
    const groupsById = unique(snapshot.groups, 'AMBIGUOUS_GROUP');
    const activeGroups = snapshot.activeRouteGroupIds.map(entityId);
    if (new Set(activeGroups).size !== activeGroups.length) fail('AMBIGUOUS_GROUP', 'Installed group identities overlap');
    const group = groupsById.get(request.groupId);
    for (const candidateGroup of snapshot.groups) {
        if (!Array.isArray(candidateGroup.paths)
            || candidateGroup.paths.some(candidate => !candidate
                || typeof candidate.pathKey !== 'string' || !candidate.pathKey
                || !Array.isArray(candidate.linkIds)
                || candidate.linkIds.some(id => !entityId(id)))) {
            fail('INVALID_FOREIGN_PATH', 'Every route group must have well-formed paths');
        }
    }
    if (!group || !activeGroups.includes(request.groupId)
        || !snapshot.installedRouteGroupIds.map(entityId).includes(request.groupId)) {
        fail('GROUP_NOT_INSTALLED', 'Replacement requires an installed route group');
    }
    if (!Array.isArray(group.paths)) fail('INCOMPLETE_PATH', 'The installed route group has no paths');
    const paths = group.paths.filter(path => path.pathKey === request.pathKey);
    if (paths.length !== 1 || group.paths.some(path => !path?.pathKey)
        || new Set(group.paths.map(path => path.pathKey)).size !== group.paths.length) {
        fail('AMBIGUOUS_PATH', 'Replacement path ownership must be unique');
    }
    const path = paths[0];
    if (path.enabled === false) fail('INACTIVE_PATH', 'The installed path is disabled');
    const originalIds = pathIds(path);
    if (originalIds.length < 2 || originalIds.at(-1) !== request.oldLinkId
        || new Set(originalIds).size !== originalIds.length) {
        fail('INCOMPLETE_PATH', 'The old link must terminate a complete, unique path');
    }
    // No other path, including a disabled or uninstalled one, can silently
    // retain the outgoing edge while the effective chain omits it.
    for (const otherGroup of snapshot.groups) {
        for (const otherPath of otherGroup.paths || []) {
            if (otherGroup === group && otherPath === path) continue;
            if ((otherPath.linkIds || []).some(id => entityId(id) === request.oldLinkId
                || entityId(id) === request.newLinkId)) {
                fail('AMBIGUOUS_LINK_OWNERSHIP', 'Replacement links have another route-path owner');
            }
        }
    }
    const old = linksById.get(request.oldLinkId);
    const replacement = linksById.get(request.newLinkId);
    if (!old || !replacement || old.active === false || replacement.active === false
        || !CONFIRMED.has(old.status) || replacement.status !== 'pending') {
        fail('INVALID_LINK_STATE', 'Old must be confirmed and new must be active and pending');
    }
    if (old.geoRouting?.enabled === true || replacement.geoRouting?.enabled === true) {
        fail('GEO_REPLACEMENT_UNSUPPORTED', 'Geo leaf replacement is not supported');
    }
    const source = link => entityId(link.portalNode ?? link.source);
    const target = link => entityId(link.bridgeNode ?? link.target);
    if (source(old) !== source(replacement) || target(old) !== target(replacement)) {
        fail('REPLACEMENT_ENDPOINT_MISMATCH', 'Replacement must retain the old relay and bridge endpoints');
    }
    if (old.mode !== replacement.mode) {
        fail('REPLACEMENT_METADATA_MISMATCH', 'Replacement must retain the old hop mode');
    }
    let cursor = null;
    for (const [index, id] of originalIds.entries()) {
        const link = linksById.get(id);
        if (!link || link.active === false || !CONFIRMED.has(link.status)) {
            fail('UNCONFIRMED_BASELINE', 'Every old path member must already be applied');
        }
        const from = source(link);
        const to = target(link);
        if (!from || !to || !nodesById.has(from) || !nodesById.has(to)
            || (index > 0 && cursor !== from)) {
            fail('INCOMPLETE_PATH', 'The installed route path is discontinuous');
        }
        if (index === 0) {
            const role = nodesById.get(from).cascadeRole ?? nodesById.get(from).role;
            if (role !== 'portal' && role !== 'relay') {
                fail('INCOMPLETE_PATH', 'The installed route path must start at a portal or L2TP relay');
            }
            if (role === 'relay') {
                const owners = (snapshot.installedRouteOwners || []).filter(owner =>
                    entityId(owner.groupId) === request.groupId && entityId(owner.nodeId) === from);
                if (owners.length !== 1) {
                    fail('GROUP_NOT_INSTALLED', 'The installed L2TP route must start at its owner relay');
                }
            }
        }
        cursor = to;
    }
    if ((nodesById.get(source(old)).cascadeRole ?? nodesById.get(source(old)).role) !== 'relay'
        || (nodesById.get(cursor).cascadeRole ?? nodesById.get(cursor).role) !== 'bridge') {
        fail('INCOMPLETE_PATH', 'The old downstream hop must go from relay to bridge');
    }
    // Confirmed links in the same connected component are retained; unrelated
    // domains and pending staged drafts cannot be pulled into this candidate.
    const confirmed = snapshot.links.filter(link => link.active !== false
        && CONFIRMED.has(link.status) && entityId(link) !== request.oldLinkId);
    const eligible = [...confirmed, replacement];
    const connected = new Set([source(old), target(old)]);
    let changed = true;
    while (changed) {
        changed = false;
        for (const link of eligible) {
            if (!connected.has(source(link)) && !connected.has(target(link))) continue;
            for (const id of [source(link), target(link)]) {
                if (!connected.has(id)) { connected.add(id); changed = true; }
            }
        }
    }
    if (![...connected].some(id => {
        const node = nodesById.get(id);
        return (node?.cascadeRole ?? node?.role) === 'portal';
    })) {
        fail('INCOMPLETE_PATH', 'The installed relay-root path requires a confirmed upstream portal');
    }
    for (const link of snapshot.links) {
        if (link.active === false || link.status !== 'pending' || entityId(link) === request.newLinkId) continue;
        // Unrelated upstream drafts (for example a second portal entering the
        // installed L2TP relay) are deliberately omitted, never activated.
        // A second pending exit from this relay or into the same bridge would
        // make the downstream replacement ambiguous, so fail closed there.
        if (source(link) === source(old) || target(link) === target(old)) {
            fail('CONFLICTING_PENDING_LINK', 'Another pending link competes for the downstream hop');
        }
    }
    const included = eligible.filter(link => connected.has(source(link)) && connected.has(target(link)));
    if (included.some(link => entityId(link) !== request.newLinkId
        && source(link) === source(old) && link.geoRouting?.enabled !== true)) {
        fail('AMBIGUOUS_DEFAULT_CHAIN', 'The relay has another confirmed default outgoing link');
    }
    const includedIds = new Set(included.map(entityId));
    const projectedGroups = projectGroups(snapshot.groups).filter(projected => {
        const ids = (projected.paths || []).flatMap(candidate => candidate.linkIds);
        if (projected._id === request.groupId) {
            if (ids.some(id => id !== request.oldLinkId && !includedIds.has(id))) {
                fail('FOREIGN_PATH_OUTSIDE_COMPONENT', 'A path in the installed group leaves the candidate component');
            }
            return true;
        }
        const inside = ids.some(id => includedIds.has(id));
        if (inside && ids.some(id => !includedIds.has(id))) {
            fail('FOREIGN_PATH_OUTSIDE_COMPONENT', 'A foreign group crosses the candidate boundary');
        }
        return inside;
    });
    const projectedPath = projectedGroups.find(entry => entry._id === request.groupId)
        .paths.find(entry => entry.pathKey === request.pathKey);
    projectedPath.linkIds = [...originalIds.slice(0, -1), request.newLinkId];
    const topology = {
        nodes: projectNodes(snapshot.nodes).filter(node => connected.has(node.id))
            .sort((a, b) => a.id.localeCompare(b.id, 'en')),
        links: projectLinks(included).sort((a, b) => a.id.localeCompare(b.id, 'en')),
        groups: projectedGroups.sort((a, b) => a._id.localeCompare(b._id, 'en')),
    };
    const compiled = compileTopology(topology);
    if (!compiled.valid) fail('INVALID_EFFECTIVE_TOPOLOGY', 'The effective route group cannot be compiled');
    const projectedLinksById = new Map(topology.links.map(link => [link.id, link]));
    const relayIngress = new Map();
    for (const projectedGroup of topology.groups) {
        for (const candidate of projectedGroup.paths || []) {
            if (candidate.enabled === false) continue;
            const relays = new Set((candidate.linkIds || [])
                .map(id => projectedLinksById.get(id)?.source)
                .filter(id => topology.nodes.some(node => node.id === id && node.role === 'relay')));
            for (const relayId of relays) {
                const key = `${relayId}:${projectedGroup._id}:${candidate.pathKey}`;
                const tag = cascadePathIngressTag(candidate.pathKey);
                const port = cascadePathIngressPort(projectedGroup._id, candidate.pathKey);
                for (const [otherKey, entry] of relayIngress) {
                    if (otherKey !== key && entry.relayId === relayId
                        && (entry.tag === tag || entry.port === port)) {
                        fail('INGRESS_COLLISION', 'Relay path ingress identities collide');
                    }
                }
                relayIngress.set(key, { relayId, tag, port });
            }
        }
    }
    return { topology, compiled, oldPathLinkIds: [...originalIds] };
}

module.exports = { TopologyReplacementError, deriveReplacementTopology };
