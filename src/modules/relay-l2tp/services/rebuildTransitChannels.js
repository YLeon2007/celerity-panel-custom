'use strict';

const { createHash, createHmac } = require('node:crypto');
const { requireRebuild } = require('../domain/rebuildTopologyCompiler');

const sameStock = (entry, policy) => entry.defaultLink === policy.defaultLink
    && entry.geoLinks.length === policy.geoLinks.length
    && entry.geoLinks.every((edge, i) => edge === policy.geoLinks[i]);
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

// A policy path is a chain of physical links plus an ordered terminal policy.
// Derive a separate authenticated TCP pair only where that suffix differs
// from the shared policy. The real graph remains unchanged for PPP/legacy.
function buildTransitChannels(graph) {
    const channels = new Map(), incoming = new Map(), outgoing = new Map(), policies = new Map();
    const carryFrom = new Set();
    const append = (map, id, value) => {
        if (!map.has(id)) map.set(id, []);
        map.get(id).push(value);
    };
    const addPolicy = (entry, edge, policy, carryDomain) => {
        append(policies, entry.id, { edge, policy });
        if (carryDomain && edge.mode === 'forward') carryFrom.add(edge.id);
    };
    for (const ingress of graph.byLinkId.values()) {
        if (!ingress.portalExit) continue;
        const { path, geoLinks, defaultLink } = ingress.portalExit;
        let policy = { geoLinks, defaultLink };
        let hasReverse = false;
        const domain = geoLinks.some(edge => edge.domains.length > 0);
        for (let i = path.length - 2; i >= 0; i--) {
            const base = path[i], downstream = graph.byNodeId.get(base.target);
            let wire = base;
            if (!sameStock(downstream, policy)) {
                requireRebuild((base.link.tunnelTransport ?? 'tcp') === 'tcp', 'REBUILD_SCOPED_TRANSIT_TCP_REQUIRED');
                const key = JSON.stringify([base.id, base.mode, policy.defaultLink.id,
                    policy.geoLinks.map(edge => [edge.id, edge.domains, edge.geoip, graph.byNodeId.get(edge.target).hasExit])]);
                wire = channels.get(key);
                if (!wire) {
                    const digest = createHash('sha256').update('rebuild-relay-channel-v1\0').update(key).digest();
                    const id = digest.subarray(0, 12).toString('hex');
                    requireRebuild(!graph.byLinkId.has(id) && uuid.test(base.link.tunnelUuid), 'REBUILD_SCOPED_TRANSIT_IDENTITY_INVALID');
                    const auth = createHmac('sha256', base.link.tunnelUuid.toLowerCase()).update(digest).digest();
                    auth[6] = (auth[6] & 0x0f) | 0x40;
                    auth[8] = (auth[8] & 0x3f) | 0x80;
                    const hex = auth.subarray(0, 16).toString('hex');
                    const tunnelUuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
                    // Not a probing allocator: adding another policy may not
                    // move an installed listener. Normal profile ownership
                    // validation rejects collisions, including DIRECT ports.
                    const tunnelPort = 26000 + digest.readUInt32BE(12) % 6000;
                    const link = { ...base.link, tunnelTransport: 'tcp', tunnelPort, tunnelUuid };
                    const keys = Object.getOwnPropertyDescriptor(base.link, '_rebuildVless');
                    if (keys) Object.defineProperty(link, '_rebuildVless', keys);
                    wire = { ...base, id, physicalId: base.id, link };
                    channels.set(key, wire);
                    append(incoming, base.target, wire);
                    append(outgoing, base.source, wire);
                    addPolicy(downstream, wire, policy, domain && hasReverse);
                }
            }
            hasReverse ||= wire.mode === 'reverse';
            policy = { geoLinks: [], defaultLink: wire };
        }
        addPolicy(graph.byNodeId.get(ingress.target), ingress, policy, path.length > 1 && domain && hasReverse);
    }
    const artifacts = [...channels.values()].sort((a, b) => a.id.localeCompare(b.id));
    return { artifacts, incoming, outgoing, policies, carryFrom };
}

module.exports = { buildTransitChannels };
