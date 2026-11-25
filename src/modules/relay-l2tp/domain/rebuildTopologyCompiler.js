'use strict';

const { isIP } = require('node:net');
const { selectActivePath } = require('./routePolicy');
const { normalizeRebuildExit, PORTAL_EXIT_INVALID } = require('./rebuildPortalExit');

const DEFAULT_PRIORITY = 100; // CascadeLink.priority, including old lean documents
const ID = /^[A-Za-z0-9_-]+$/;
const ROLES = new Set(['portal', 'relay', 'bridge', 'standalone']);
const PORTAL_EXIT_UNSUPPORTED = 'REBUILD_PORTAL_EXIT_UNSUPPORTED';
const PORTAL_EXIT_AMBIGUOUS = 'REBUILD_PORTAL_EXIT_AMBIGUOUS';
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;

function requireRebuild(condition, code) {
    if (!condition) throw Object.assign(new Error(code), { code });
}

function rebuildId(value) {
    const id = value?.toHexString?.() ?? value;
    requireRebuild(typeof id === 'string' && ID.test(id), 'REBUILD_INVALID_ID');
    return id;
}

function refId(value) {
    return rebuildId(value?.toHexString ? value : value?._id ?? value?.id ?? value);
}

function geoSelectors(geo) {
    if (geo?.enabled !== true) return {};
    const normalize = (values, convert) => {
        if (values === undefined) return [];
        requireRebuild(Array.isArray(values), 'REBUILD_INVALID_GEO');
        return [...new Set(values.map(value => {
            requireRebuild(typeof value === 'string' && value.trim(), 'REBUILD_INVALID_GEO');
            return convert(value.trim());
        }))];
    };
    const domains = normalize(geo.domains, value => value.includes(':') ? value : `geosite:${value}`);
    const geoip = normalize(geo.geoip, value => {
        const [address, mask, extra] = value.split('/');
        const version = isIP(address);
        if (version && extra === undefined && (mask === undefined
            || /^\d{1,3}$/.test(mask) && Number(mask) <= (version === 4 ? 32 : 128))) return value;
        const tag = value.toLowerCase().replace(/^geoip:/, '');
        requireRebuild(/^[a-z]{2}$|^private$/.test(tag), 'REBUILD_INVALID_GEO');
        return `geoip:${tag}`;
    });
    // A malformed geo edge must not silently become an unrestricted exit.
    requireRebuild(domains.length || geoip.length, 'REBUILD_INVALID_GEO');
    return { domains, geoip };
}

function unshadowedGeoLinks(entry) {
    const domains = new Set(), ips = new Set();
    const add = (seen, values) => {
        const uncovered = values.some(value => !seen.has(value));
        for (const value of values) seen.add(value);
        return uncovered;
    };
    // Xray evaluates geo rules first in this order, including closed geo
    // branches that block their matches. Catch complete literal shadowing;
    // the compiler does not expand geodata or interpret Xray domain matchers.
    const routed = new Set();
    for (const link of entry.geoLinks) {
        const domain = add(domains, link.domains);
        const ip = add(ips, link.geoip);
        if (domain || ip) routed.add(link);
    }
    return routed;
}

function selectDefaultLink(links) {
    const selection = selectActivePath(links.map(link => ({
        key: link.id, priority: link.priority, enabled: true, complete: true,
    })), Object.fromEntries(links.map(link => [link.id, true])));
    return links.find(link => link.id === selection.pathKey) ?? null;
}

// Compute reachability once per selected bridge, in reverse topological order.
// A geo-only transit leg is not an unrestricted path. An ambiguous preferred
// suffix must not silently select a less preferred path.
function exitResolver(byNodeId, nodeIds) {
    const byExit = new Map();
    return (relayId, nodeId) => {
        if (byNodeId.get(nodeId)?.role !== 'bridge') return null;
        if (!byExit.has(nodeId)) {
            const reachable = new Map([[nodeId, {}]]);
            for (let i = nodeIds.length - 1; i >= 0; i--) {
                const entry = byNodeId.get(nodeIds[i]);
                if (entry.role !== 'relay' || entry.node.useCustomConfig || (entry.node.type && entry.node.type !== 'xray')) continue;
                const usable = entry.outgoing.filter(link => link.target === nodeId
                    || (!link.domains && reachable.has(link.target)));
                if (!usable.length) continue;
                // Preserve a legacy direct pick even if the same bridge is
                // reachable via a longer path. Order alternatives by priority.
                const direct = usable.filter(link => link.target === nodeId);
                const edge = selectDefaultLink(direct.length ? direct : usable);
                reachable.set(entry.id, { edge, ambiguous: !edge || reachable.get(edge.target).ambiguous });
            }
            byExit.set(nodeId, reachable);
        }
        const reachable = byExit.get(nodeId);
        const first = reachable.get(relayId);
        if (!first) return null;
        requireRebuild(!first.ambiguous, PORTAL_EXIT_AMBIGUOUS);
        const path = [];
        for (let step = first; step.edge; step = reachable.get(step.edge.target)) path.push(step.edge);
        return path.length ? path : null;
    };
}

function resolvePortalExits(portal, picks, byNodeId, resolvePath) {
    const geo = unshadowedGeoLinks(portal);
    for (const [incoming, { nodeId, relayGeo }] of picks) {
        const path = resolvePath(incoming.target, nodeId);
        requireRebuild(path, PORTAL_EXIT_INVALID);
        requireRebuild(incoming === portal.defaultLink || geo.has(incoming), PORTAL_EXIT_UNSUPPORTED);
        const selected = path.at(-1);
        const geoLinks = relayGeo ? byNodeId.get(selected.source).geoLinks : [];
        const endsInRelay = edge => {
            const target = byNodeId.get(edge.target);
            return target.hasExit && target.role === 'relay';
        };
        // A closed geo branch still blocks its matches. A live branch into
        // another relay would turn this into a policy for more than one relay.
        requireRebuild(!geoLinks.some(endsInRelay), PORTAL_EXIT_UNSUPPORTED);
        incoming.portalExit = { geoLinks, defaultLink: selected, path };
    }
}

// Separate from strict topology validation and the persisted route-group compiler.
function compileRebuildGraph({ nodes, links, affectedNodeIds }) {
    requireRebuild(Array.isArray(nodes) && Array.isArray(links)
        && (affectedNodeIds === undefined || Array.isArray(affectedNodeIds)), 'REBUILD_INVALID_INPUT');
    const scope = affectedNodeIds === undefined ? null : new Set(affectedNodeIds.map(rebuildId));
    const byNodeId = new Map();
    for (const node of nodes) {
        const id = refId(node);
        if (scope && !scope.has(id)) continue;
        const role = node.role ?? node.cascadeRole ?? 'standalone';
        requireRebuild(ROLES.has(role), 'REBUILD_INVALID_ROLE');
        requireRebuild(!byNodeId.has(id), 'REBUILD_DUPLICATE_NODE');
        byNodeId.set(id, { id, role, node, incoming: [], outgoing: [] });
    }
    for (const id of scope || []) requireRebuild(byNodeId.has(id), 'REBUILD_UNKNOWN_NODE');

    const byLinkId = new Map();
    const portalPicks = new Map();
    for (const link of links) {
        if (link.active === false || link.rebuildDelete === true || link.lifecycle?.state === 'deleting') continue;
        const source = refId(link.source ?? link.portalNode);
        const target = refId(link.target ?? link.bridgeNode);
        if (scope && !scope.has(source) && !scope.has(target)) continue;
        const from = byNodeId.get(source);
        const to = byNodeId.get(target);
        requireRebuild(!scope || scope.has(source) && scope.has(target), 'REBUILD_INCOMPLETE_SCOPE');
        requireRebuild(from && to, 'REBUILD_UNKNOWN_NODE');
        const rebuildExit = normalizeRebuildExit(link.rebuildExit);
        requireRebuild(rebuildExit == null || (from.role === 'portal' && to.role === 'relay'), PORTAL_EXIT_INVALID);
        requireRebuild(source !== target, 'REBUILD_CYCLE');
        requireRebuild((from.role === 'portal' || from.role === 'relay')
            && (to.role === 'relay' || to.role === 'bridge'), 'REBUILD_INVALID_EDGE_ROLE');
        requireRebuild(from.node.active !== false && to.node.active !== false, 'REBUILD_INACTIVE_ENDPOINT');
        const id = refId(link);
        const mode = link.mode === undefined ? 'reverse' : link.mode;
        const storedProtocol = link.tunnelProtocol ?? 'vless';
        const protocol = mode === 'reverse' ? 'vless' : storedProtocol;
        const priority = link.priority === undefined ? DEFAULT_PRIORITY : link.priority;
        requireRebuild(mode === 'reverse' || mode === 'forward', 'REBUILD_INVALID_MODE');
        requireRebuild(['vless','vmess'].includes(storedProtocol), 'REBUILD_INVALID_TUNNEL');
        requireRebuild(Number.isFinite(priority), 'REBUILD_INVALID_PRIORITY');
        requireRebuild(!byLinkId.has(id), 'REBUILD_DUPLICATE_LINK');
        // Preserve the original descriptor, including non-persisted key material.
        const entry = { id, source, target, mode, protocol, priority, ...geoSelectors(link.geoRouting), link };
        byLinkId.set(id, entry);
        from.outgoing.push(entry);
        to.incoming.push(entry);
        if (rebuildExit?.nodeId != null) portalPicks.set(entry, rebuildExit);
    }

    // Kahn's algorithm, deterministic roots and edges. No recursion or path enumeration.
    const nodeIds = [];
    const remaining = new Map();
    const byId = (a, b) => compare(a.id, b.id);
    for (const id of [...byNodeId.keys()].sort(compare)) {
        const entry = byNodeId.get(id);
        entry.incoming.sort(byId);
        entry.outgoing.sort(byId);
        remaining.set(id, entry.incoming.length);
        if (!entry.incoming.length) nodeIds.push(id);
    }
    for (let i = 0; i < nodeIds.length; i++) {
        for (const { target } of byNodeId.get(nodeIds[i]).outgoing) {
            const pending = remaining.get(target) - 1;
            remaining.set(target, pending);
            if (!pending) nodeIds.push(target);
        }
    }
    requireRebuild(nodeIds.length === byNodeId.size, 'REBUILD_CYCLE');

    const resolvePath = exitResolver(byNodeId, nodeIds);
    for (let i = nodeIds.length - 1; i >= 0; i--) {
        const entry = byNodeId.get(nodeIds[i]);
        entry.isExit = entry.role === 'bridge' && entry.incoming.length > 0;
        entry.geoLinks = entry.outgoing.filter(link => link.domains)
            .sort((a, b) => a.priority - b.priority || byId(a, b));
        entry.defaultLink = selectDefaultLink(entry.outgoing.filter(link => !link.domains && byNodeId.get(link.target).hasExit));
        const routedLinks = entry.geoLinks.filter(link => byNodeId.get(link.target).hasExit);
        entry.hasExit = entry.isExit || !!entry.defaultLink || routedLinks.length > 0;
        if (entry.role === 'portal' && portalPicks.size) {
            const picks = entry.outgoing.filter(link => portalPicks.has(link)).map(link => [link, portalPicks.get(link)]);
            if (picks.length) resolvePortalExits(entry, picks, byNodeId, resolvePath);
        }
        // Native reverse does not carry route-only sniff metadata. Work out
        // whether a client (or forward-hop) sniff must replace the destination
        // before crossing a reverse edge to a later domain policy.
        if (entry.defaultLink) routedLinks.push(entry.defaultLink);
        // An opted-in edge ends at this relay's own policy, not its shared
        // downstream paths. Do not change the relay's shared carry decision.
        const hasDomainPolicy = link => link.portalExit
            ? link.portalExit.geoLinks.some(edge => edge.domains.length > 0)
            : byNodeId.get(link.target).hasDomainPolicy;
        entry.hasDomainPolicy = (entry.hasExit && entry.geoLinks.some(link => link.domains.length > 0))
            || routedLinks.some(hasDomainPolicy);
        entry.carryDomain = routedLinks.some(link => (!link.portalExit && byNodeId.get(link.target).carryDomain)
            || ((link.mode === 'reverse' || link.portalExit?.path.slice(0, -1).some(edge => edge.mode === 'reverse'))
                && hasDomainPolicy(link)));
    }
    const orderedNodes = new Map(nodeIds.map(id => [id, byNodeId.get(id)]));
    const orderedLinks = new Map([...byLinkId].sort(([a], [b]) => compare(a, b)));
    return { nodeIds, byNodeId: orderedNodes, byLinkId: orderedLinks };
}

module.exports = { compileRebuildGraph, rebuildId, requireRebuild, normalizeRebuildExit, PORTAL_EXIT_AMBIGUOUS };
