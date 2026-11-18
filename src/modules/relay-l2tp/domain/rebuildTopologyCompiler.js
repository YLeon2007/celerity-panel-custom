'use strict';

const { isIP } = require('node:net');
const { selectActivePath } = require('./routePolicy');

const DEFAULT_PRIORITY = 100; // CascadeLink.priority, including old lean documents
const ID = /^[A-Za-z0-9_-]+$/;
const ROLES = new Set(['portal', 'relay', 'bridge', 'standalone']);
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
    return rebuildId(value?._id ?? value?.id ?? value);
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
    for (const link of links) {
        if (link.active === false || link.lifecycle?.state === 'deleting') continue;
        const source = refId(link.source ?? link.portalNode);
        const target = refId(link.target ?? link.bridgeNode);
        if (scope && !scope.has(source) && !scope.has(target)) continue;
        const from = byNodeId.get(source);
        const to = byNodeId.get(target);
        requireRebuild(!scope || scope.has(source) && scope.has(target), 'REBUILD_INCOMPLETE_SCOPE');
        requireRebuild(from && to, 'REBUILD_UNKNOWN_NODE');
        requireRebuild(source !== target, 'REBUILD_CYCLE');
        requireRebuild((from.role === 'portal' || from.role === 'relay')
            && (to.role === 'relay' || to.role === 'bridge'), 'REBUILD_INVALID_EDGE_ROLE');
        requireRebuild(from.node.active !== false && to.node.active !== false, 'REBUILD_INACTIVE_ENDPOINT');
        const id = refId(link);
        const mode = link.mode === undefined ? 'reverse' : link.mode;
        const priority = link.priority === undefined ? DEFAULT_PRIORITY : link.priority;
        requireRebuild(mode === 'reverse' || mode === 'forward', 'REBUILD_INVALID_MODE');
        requireRebuild(Number.isFinite(priority), 'REBUILD_INVALID_PRIORITY');
        requireRebuild(!byLinkId.has(id), 'REBUILD_DUPLICATE_LINK');
        const entry = { id, source, target, mode, priority, ...geoSelectors(link.geoRouting), link };
        byLinkId.set(id, entry);
        from.outgoing.push(entry);
        to.incoming.push(entry);
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

    for (let i = nodeIds.length - 1; i >= 0; i--) {
        const entry = byNodeId.get(nodeIds[i]);
        entry.isExit = entry.role === 'bridge' && entry.incoming.length > 0;
        entry.geoLinks = entry.outgoing.filter(link => link.domains)
            .sort((a, b) => a.priority - b.priority || byId(a, b));
        const possibleDefaults = entry.outgoing.filter(link => !link.domains && byNodeId.get(link.target).hasExit);
        const selection = selectActivePath(possibleDefaults.map(link => ({
            key: link.id, priority: link.priority, enabled: true, complete: true,
        })), Object.fromEntries(possibleDefaults.map(link => [link.id, true])));
        entry.defaultLink = possibleDefaults.find(link => link.id === selection.pathKey) ?? null;
        entry.hasExit = entry.isExit || !!entry.defaultLink || entry.geoLinks.some(link => byNodeId.get(link.target).hasExit);
    }
    const orderedNodes = new Map(nodeIds.map(id => [id, byNodeId.get(id)]));
    const orderedLinks = new Map([...byLinkId].sort(([a], [b]) => compare(a, b)));
    return { nodeIds, byNodeId: orderedNodes, byLinkId: orderedLinks };
}

module.exports = { compileRebuildGraph, rebuildId, requireRebuild };
