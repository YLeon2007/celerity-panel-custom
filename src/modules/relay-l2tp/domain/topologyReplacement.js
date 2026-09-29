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
    const owners = (snapshot.installedRouteOwners || []).filter(owner =>
        entityId(owner.groupId) === request.groupId);
    const ownerNodeId = owners.length === 1 ? entityId(owners[0].nodeId) : null;
    if (!ownerNodeId || !originalIds.some(id => source(linksById.get(id)) === ownerNodeId)
        || (nodesById.get(ownerNodeId)?.cascadeRole ?? nodesById.get(ownerNodeId)?.role) !== 'relay') {
        fail('GROUP_NOT_INSTALLED', 'Replacement requires one installed L2TP owner on the route path');
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
    return { topology, compiled, oldPathLinkIds: [...originalIds], ownerNodeId };
}

const APPLIED = new Set(['deployed', 'online', 'staged']);

/** Build one private attach candidate from the installed owner, never from a caller-supplied path. */
function deriveAttachTopology(snapshot, request) {
    if (!snapshot || !Array.isArray(snapshot.nodes) || !Array.isArray(snapshot.links)
        || !Array.isArray(snapshot.groups) || !Array.isArray(snapshot.activeRouteGroupIds)
        || !Array.isArray(snapshot.installedRouteGroupIds)
        || !Array.isArray(snapshot.installedRouteOwners)
        || !request || !['groupId', 'pathKey', 'linkId'].every(key =>
            typeof request[key] === 'string' && request[key].length > 0)) {
        fail('INVALID_ATTACH_REQUEST', 'Attach requires a complete snapshot and group, path and link identities');
    }
    const nodes = unique(snapshot.nodes, 'AMBIGUOUS_NODE');
    unique(snapshot.links, 'AMBIGUOUS_LINK');
    const groups = unique(snapshot.groups, 'AMBIGUOUS_GROUP');
    const activeIds = snapshot.activeRouteGroupIds.map(entityId);
    const installedIds = snapshot.installedRouteGroupIds.map(entityId);
    if (new Set(activeIds).size !== activeIds.length
        || new Set(installedIds).size !== installedIds.length) {
        fail('AMBIGUOUS_GROUP', 'Route group identities must be unique');
    }
    const group = groups.get(request.groupId);
    if (!group || !activeIds.includes(request.groupId) || !installedIds.includes(request.groupId)) {
        fail('GROUP_NOT_INSTALLED', 'Attach requires an installed route group');
    }
    const owners = snapshot.installedRouteOwners.filter(owner => entityId(owner.groupId) === request.groupId);
    if (!owners.length) fail('GROUP_NOT_INSTALLED', 'Attach requires an installed L2TP owner');
    // readDraft currently projects groupId/nodeId, but not activePathKey. Do not
    // substitute the request pathKey for proof of the installed owner's key.
    if (owners.some(owner => typeof owner.pathKey !== 'string' || !owner.pathKey)) {
        fail('MISSING_OWNER_PATH_KEY', 'Installed owner projection must include its active path key');
    }
    if (owners.length !== 1 || new Set(owners.map(owner => owner.pathKey)).size !== owners.length) {
        fail('AMBIGUOUS_PATH', 'Attach needs exactly one owner for the installed group');
    }
    const owner = owners[0];
    const ownerId = entityId(owner.nodeId);
    if (owner.pathKey !== request.pathKey || !ownerId ||
        (nodes.get(ownerId)?.cascadeRole ?? nodes.get(ownerId)?.role) !== 'relay') {
        fail('GROUP_NOT_INSTALLED', 'The installed relay does not own the requested path');
    }
    if (!Array.isArray(group.paths) || group.paths.some(path => !path
        || typeof path.pathKey !== 'string' || !path.pathKey || !Array.isArray(path.linkIds)
        || path.linkIds.some(id => !entityId(id)))
        || new Set(group.paths.map(path => path.pathKey)).size !== group.paths.length) {
        fail('AMBIGUOUS_PATH', 'The installed group needs unique, well-formed paths');
    }
    const existing = group.paths.find(path => path.pathKey === request.pathKey);
    if (existing && (existing.enabled === false || existing.linkIds.length !== 0)) {
        fail('INCOMPLETE_PATH', 'Attach requires an enabled empty owned path');
    }
    const source = link => entityId(link.portalNode ?? link.source);
    const target = link => entityId(link.bridgeNode ?? link.target);
    const eligible = snapshot.links.filter(link => link.active !== false
        && (APPLIED.has(link.status) || link.status === 'pending')
        && link.geoRouting?.enabled !== true);
    const incoming = id => eligible.filter(link => target(link) === id);
    const outgoing = id => eligible.filter(link => source(link) === id);
    const walk = (start, direction) => {
        const result = [];
        const seen = new Set([start]);
        let current = start;
        for (let hop = 0; hop <= nodes.size; hop += 1) {
            const role = nodes.get(current)?.cascadeRole ?? nodes.get(current)?.role;
            if (direction === 'up' && role === 'portal') return result.reverse();
            if (direction === 'down' && role === 'bridge') return result;
            if (role !== 'relay') {
                fail('INCOMPLETE_PATH', 'The attach chain has an invalid intermediate role');
            }
            const candidates = direction === 'up' ? incoming(current) : outgoing(current);
            if (candidates.length > 1) fail('AMBIGUOUS_CHAIN', 'Attach chain has competing default links');
            if (candidates.length === 0) fail('INCOMPLETE_PATH', 'Attach chain does not reach its endpoint');
            const link = candidates[0];
            const next = direction === 'up' ? source(link) : target(link);
            if (!next || !nodes.has(next) || seen.has(next) || next === current) {
                fail('INCOMPLETE_PATH', 'Attach chain has a missing node or a cycle');
            }
            if (direction === 'down' && incoming(next).length !== 1) {
                fail('AMBIGUOUS_CHAIN', 'Attach suffix has an ambiguous incoming link');
            }
            result.push(link);
            seen.add(next);
            current = next;
        }
        fail('INCOMPLETE_PATH', 'Attach chain exceeds the snapshot node count');
    };
    const prefix = walk(ownerId, 'up');
    const suffix = walk(ownerId, 'down');
    if (suffix.length === 0 || entityId(suffix.at(-1)) !== request.linkId) {
        fail('INCOMPLETE_PATH', 'Requested link must be the final bridge hop');
    }
    const chain = [...prefix, ...suffix];
    if (new Set(chain.map(entityId)).size !== chain.length) {
        fail('AMBIGUOUS_CHAIN', 'Attach chain repeats a link');
    }
    for (const link of chain) {
        if (link.mode !== group.mode) fail('REPLACEMENT_METADATA_MISMATCH', 'Attach link mode differs from its group');
        if (entityId(link) === request.linkId ? link.status !== 'pending' : !APPLIED.has(link.status)) {
            fail('UNCONFIRMED_BASELINE', 'Only the requested final hop may be pending');
        }
    }
    if (Array.isArray(request.linkIds) && (request.linkIds.length !== chain.length
        || request.linkIds.some((id, index) => entityId(id) !== entityId(chain[index])))) {
        fail('INCOMPLETE_PATH', 'Supplied links do not match the unique installed-owner chain');
    }
    const used = new Set(chain.map(entityId));
    for (const candidateGroup of snapshot.groups) {
        if (!Array.isArray(candidateGroup.paths)) fail('INVALID_FOREIGN_PATH', 'Every group must have paths');
        for (const path of candidateGroup.paths) {
            if (!path || !Array.isArray(path.linkIds)) fail('INVALID_FOREIGN_PATH', 'Every path needs link identities');
            if (candidateGroup === group && path === existing) continue;
            if (path.linkIds.some(id => used.has(entityId(id)))) {
                fail('AMBIGUOUS_LINK_OWNERSHIP', 'Another path owns an attach chain link');
            }
        }
    }
    const projectedGroup = projectGroups([{ ...group, paths: existing
        ? group.paths.map(path => path === existing
            ? { ...path, linkIds: suffix.map(entityId) } : path)
        : [...group.paths, { pathKey: request.pathKey, linkIds: suffix.map(entityId),
            priority: 1, enabled: true }] }])[0];
    const included = new Set(chain.flatMap(link => [source(link), target(link)]));
    const topology = {
        nodes: projectNodes(snapshot.nodes).filter(node => included.has(node.id))
            .sort((a, b) => a.id.localeCompare(b.id, 'en')),
        links: projectLinks(chain).sort((a, b) => a.id.localeCompare(b.id, 'en')),
        groups: [projectedGroup],
    };
    const compiled = compileTopology(topology);
    if (!compiled.valid || !compiled.relays.some(relay => relay.nodeId === ownerId
        && relay.routeGroups.some(routeGroup => routeGroup.groupId === request.groupId
            && routeGroup.candidates.some(candidate => candidate.pathKey === request.pathKey)))) {
        fail('INVALID_EFFECTIVE_TOPOLOGY', 'The attach candidate cannot be compiled for its owner');
    }
    return { topology, compiled, ownerNodeId: ownerId };
}

module.exports = { TopologyReplacementError, deriveReplacementTopology, deriveAttachTopology };
