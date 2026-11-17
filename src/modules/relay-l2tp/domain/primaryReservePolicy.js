'use strict';

const { compileTopology } = require('./topologyCompiler');

// Configuration intent only. This does NOT attest tunnel/agent/client health.
// Reuse the supported priority selector for enabled paths in the admitted
// descriptor, never include desired-only links or publish runtime readiness.
function compileConfiguredTopology(topology) {
    const admitted = new Set(topology.links.map(link => String(link.id)));
    const configured = Object.fromEntries((topology.groups || []).flatMap(group =>
        (group.paths || []).map(path => [`${group._id ?? group.id}:${path.pathKey}`,
            path.linkIds.length > 0 && path.linkIds.every(id => admitted.has(String(id)))])));
    return compileTopology({ ...topology, healthByPathKey: configured });
}

// The supported primary/reserve case: explicit priority-failover leaf exits
// from one relay. Do not reinterpret geo branches, arbitrary splits, or peer
// groups as default policy. Existing chain validation checks the remaining graph.
function primaryReservePolicies(topology, compiled = compileConfiguredTopology(topology)) {
    const links = new Map(topology.links.map(link => [String(link.id), link]));
    const roles = new Map(topology.nodes.map(node => [String(node.id), node.role]));
    const policies = [];
    for (const group of topology.groups || []) {
        if (group.strategy !== 'priority-failover' || !Array.isArray(group.paths) || group.paths.length < 1) continue;
        const candidates = group.paths.map(path => ({ path, link: links.get(String(path.linkIds?.[0])) }));
        if (candidates.some(({ path, link }) => path.linkIds.length !== 1 || !link
            || roles.get(link.source) !== 'relay' || roles.get(link.target) !== 'bridge'
            || link.geo === true || link.geoRouting?.enabled === true)) continue;
        const source = candidates[0].link.source;
        if (candidates.some(({ link }) => link.source !== source)
            || new Set(candidates.map(({ link }) => link.id)).size !== candidates.length) continue;
        const groupId = String(group._id ?? group.id);
        const decision = compiled.relays.find(relay => relay.nodeId === source)
            ?.routeGroups?.find(entry => entry.groupId === groupId)?.decision;
        if (!decision || !['select', 'block'].includes(decision.decision)) {
            throw Object.assign(new Error('Frozen primary/reserve selection is missing'), { code: 'COMPILED_TOPOLOGY_MISMATCH' });
        }
        const selected = decision.decision === 'select'
            ? candidates.find(({ path }) => path.pathKey === decision.pathKey && path.enabled !== false) : null;
        if (decision.decision === 'select' && (!selected || decision.nextHopNodeId !== selected.link.target)) {
            throw Object.assign(new Error('Frozen primary/reserve selection does not match its descriptor'), { code: 'COMPILED_TOPOLOGY_MISMATCH' });
        }
        if (policies.some(policy => policy.source === source)) {
            throw Object.assign(new Error('Ambiguous default route groups'), { code: 'NON_LINEAR_TOPOLOGY' });
        }
        policies.push({ groupId, source, group, candidates, selected,
            // A blocked group still prepares both transports, but no default
            // traffic may use this deterministic shape carrier.
            carrier: selected || [...candidates].sort((a, b) =>
                a.path.priority - b.path.priority || a.path.pathKey.localeCompare(b.path.pathKey))[0] });
    }
    return policies;
}

function installedPrimaryReserve(topology, installedPath) {
    if (!installedPath?.preserveGroupPaths) return null;
    const policy = primaryReservePolicies(topology).find(policy => policy.groupId === installedPath.groupId
        && policy.source === installedPath.ownerNodeId);
    if (!policy || !policy.group.paths.some(path => path.pathKey === installedPath.pathKey)
        || (policy.selected?.path.pathKey ?? null) !== installedPath.selectedPathKey) {
        throw Object.assign(new Error('Installed primary/reserve selection changed'), { code: 'TOPOLOGY_INSTALLED_PATH_MISMATCH' });
    }
    return policy;
}

// One explicit non-owned leaf DELETE may remove its own path reference. Applied
// policy is derived only from the verified baseline; a saved enable toggle in
// the desired group is preserved, never promoted to applied policy by DELETE.
function selectedReserveLeafDeletion(topology, desiredGroup, owner, linkId) {
    const same = require('node:util').isDeepStrictEqual;
    const groupId = String(owner.groupId), source = String(owner.ownerNodeId ?? owner.nodeId);
    const applied = topology.groups.find(group => String(group._id ?? group.id) === groupId);
    if (!applied || !desiredGroup || !applied.paths.some(path => path.pathKey !== owner.pathKey
        && path.linkIds.length === 1 && String(path.linkIds[0]) === String(linkId))) return null;
    const policy = primaryReservePolicies({ ...topology, groups: [applied] }).find(row => row.source === source);
    const anchor = applied.paths.find(path => path.pathKey === owner.pathKey);
    const stripEnabled = group => ({ ...group, paths: group.paths.map(({ enabled: ignored, ...path }) => path) });
    if (!policy || !anchor || anchor.linkIds.includes(String(linkId))
        || !same(stripEnabled(applied), stripEnabled(desiredGroup))) {
        throw Object.assign(new Error('Selected reserve deletion policy changed'), { code: 'TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED' });
    }
    const without = group => ({ ...group, paths: group.paths.filter(path => !path.linkIds.includes(String(linkId))) });
    return { appliedGroup: without(applied), desiredGroup: without(desiredGroup) };
}

module.exports = { compileConfiguredTopology, primaryReservePolicies, installedPrimaryReserve, selectedReserveLeafDeletion };
