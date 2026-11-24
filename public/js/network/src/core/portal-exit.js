'use strict';

const hexId = value => typeof value === 'string' && /^[a-f0-9]{24}(?![\s\S])/i.test(value) ? value.toLowerCase() : null;

// The DTO uses null for a known shared policy, omission for unavailable
// metadata. Do not turn invalid data into a shared-route decision.
function readExit(value) {
    if (value === null) return null;
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.hasOwn(value, 'nodeId')
        || Object.keys(value).some(k => k !== 'nodeId' && k !== 'relayGeo')
        || (Object.hasOwn(value, 'relayGeo') && typeof value.relayGeo !== 'boolean')) return undefined;
    if (value.nodeId === null) return null;
    const nodeId = hexId(value.nodeId);
    return nodeId ? { nodeId, relayGeo: value.relayGeo !== false } : undefined;
}

function sameExit(a, b) {
    return a === b || a != null && b != null && a.nodeId === b.nodeId && a.relayGeo === b.relayGeo;
}

function enabled(link) {
    return link.active !== false && link.enabled !== false && link.canEdit !== false
        && !link.lifecycle && !link.rebuildDelete && link.applicationState !== 'deleting';
}

function selectablePortalHop(index, source, target) {
    const from = index.nodes.get(source), to = index.nodes.get(target);
    return from?.cascadeRole === 'portal' && to?.cascadeRole === 'relay'
        && [from, to].every(n => n.type === 'xray' && n.active !== false && n.useCustomConfig !== true);
}

function linkKey(link) {
    const key = link.id.startsWith('link-') ? hexId(link.id.slice(5)) : null;
    return key && (link.linkId == null || hexId(link.linkId) === key) ? key : null;
}

function relayEdges(index, relay) {
    return (index.out.get(relay) || []).filter(link => {
        const target = index.nodes.get(link.target);
        return enabled(link) && linkKey(link) && ['bridge', 'relay'].includes(target?.cascadeRole)
            && target.type === 'xray' && target.active !== false && target.useCustomConfig !== true;
    });
}

const directExit = (index, link) => index.nodes.get(link.target)?.cascadeRole === 'bridge';
function exitChoiceNodes(index, relay) {
    const groups = new Map();
    for (const link of relayEdges(index, relay)) {
        if (!directExit(index, link) || !hexId(link.target)) continue;
        if (!groups.has(link.target)) groups.set(link.target, []);
        groups.get(link.target).push(link);
    }
    return [...groups.values()].map(lowestUniquePriority).filter(Boolean).map(link => index.nodes.get(link.target));
}
const isGeo = link => link.geoRouting?.enabled === true;
const isPending = link => link.hasUnappliedChanges === true || link.status === 'pending' || link.status === 'staged'
    || ['not_applied', 'applying', 'reconcile_required'].includes(link.applicationState);
const previouslyApplied = link => link.rebuildApplied === true || link.applicationState === 'applied';
const available = link => enabled(link) && (previouslyApplied(link) || (link.rebuildApplied !== false && !isPending(link)));

function lowestUniquePriority(choices) {
    const priorities = choices.map(l => l.priority);
    // The compiler blocks duplicate priorities instead of choosing an ID or a
    // display label to break ties. Keep that distinction in the map too.
    if (priorities.some(priority => !Number.isFinite(priority)) || new Set(priorities).size !== priorities.length) return null;
    return choices.reduce((best, link) => !best || link.priority < best.priority ? link : best, null);
}

function resolve(index, inventory, setting, actual = false) {
    if (setting === undefined) return { kind: 'unknown', main: null, geo: [] };
    const outgoing = actual ? inventory.filter(available) : inventory;
    const choices = outgoing.filter(link => directExit(index, link));
    // The policy refers to the exit node; chains and graph focus still need
    // a physical edge. A geo outlet can also be the explicit main route.
    const candidates = setting && inventory.filter(link => link.target === setting.nodeId && directExit(index, link));
    const selected = candidates && lowestUniquePriority(candidates);
    if (candidates?.length && !selected) return { kind: 'unknown', main: null, geo: [] };
    const relayGeo = setting?.relayGeo !== false;
    const geoProved = !relayGeo || outgoing.every(link => typeof link.geoRouting?.enabled === 'boolean'
        && (!isGeo(link) || (directExit(index, link) && Number.isFinite(link.priority))) && (!actual || !isPending(link)));
    const geo = relayGeo && geoProved ? choices.filter(isGeo)
        .sort((a, b) => a.priority - b.priority || (a.id < b.id ? -1 : 1)) : [];
    if (setting && !selected) return { kind: 'missing', main: null, geo };
    // Topology must explicitly classify the relay edges. An omitted geo flag
    // isn't proof the edge is unrestricted, and an edited policy isn't readback.
    if (!geoProved || (actual && selected && (!available(selected) || isPending(selected)))) {
        return { kind: 'unknown', main: null, geo: [] };
    }
    if (selected) return { kind: 'explicit', main: selected, geo };
    const ordinary = outgoing.filter(link => !isGeo(link));
    if (ordinary.some(link => !Number.isFinite(link.priority))) return { kind: 'unknown', main: null, geo };
    const main = lowestUniquePriority(choices.filter(link => !isGeo(link)));
    // A second relay is outside this feature's one-relay resolution. Do not
    // claim a direct default if such an edge can change the compiler's choice.
    const priorities = new Map();
    for (const { priority } of ordinary) priorities.set(priority, (priorities.get(priority) || 0) + 1);
    if (ordinary.some(link => !directExit(index, link) && (!main || link.priority <= main.priority
        || priorities.get(link.priority) !== 1))) {
        return { kind: 'unknown', main: null, geo };
    }
    return { kind: 'shared', main, geo };
}

function portalRoute(index, link) {
    if (!link || !selectablePortalHop(index, link.source, link.target)) return null;
    if (typeof link.canEdit !== 'boolean' && !Object.hasOwn(link, 'rebuildExit')
        && !Object.hasOwn(link, 'appliedRebuildExit')) return null;
    if (index.portalRoutes.has(link.id)) return index.portalRoutes.get(link.id);
    const desired = readExit(link.rebuildExit);
    const applied = readExit(link.appliedRebuildExit);
    const effective = enabled(link) ? applied : undefined;
    const outgoing = relayEdges(index, link.target);
    const route = { actual: resolve(index, outgoing, effective, true),
        draft: enabled(link) && desired !== undefined && !sameExit(desired, effective)
            ? resolve(index, outgoing, desired) : null };
    index.portalRoutes.set(link.id, route);
    return route;
}

// Shared by both renderers. Route changes must invalidate derived views, but
// must not trigger a structural layout or reset positions.
function routeKey(link) {
    return JSON.stringify([link.linkId, link.active, link.enabled, link.canEdit, link.lifecycle?.state, !!link.lifecycle,
        !!link.rebuildDelete, link.applicationState, link.rebuildApplied, link.hasUnappliedChanges,
        link.status === 'pending' || link.status === 'staged', link.priority, link.geoRouting?.enabled,
        Object.hasOwn(link, 'rebuildExit'), readExit(link.rebuildExit) ?? (link.rebuildExit === null ? null : 'unavailable'),
        Object.hasOwn(link, 'appliedRebuildExit'), readExit(link.appliedRebuildExit) ?? (link.appliedRebuildExit === null ? null : 'unavailable')]);
}

module.exports = { readExit, sameExit, exitChoiceNodes, selectablePortalHop, portalRoute, routeKey };
