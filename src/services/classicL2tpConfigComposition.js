'use strict';

const { isDeepStrictEqual: equal } = require('node:util');

const { cascadePathIngressPort } = require('../modules/relay-l2tp/domain/cascadePathIngress');

function id(value) { return String(value?._id ?? value); }
function invalidPath() {
    return Object.assign(new Error('Classic L2TP path has no exact configured cascade egress'), {
        code: 'CLASSIC_L2TP_PATH_UNAVAILABLE',
    });
}

function finishClassicConfigRouting(config) {
    const generator = require('./configGenerator');
    // The existing helper removes scoped single geoip:private rules too.
    // Retain L2TP refusal before any selected-path catch-all.
    const scoped = (config.routing?.rules || []).filter(rule => rule.inboundTag?.length
        && rule.ip?.length === 1 && rule.ip[0] === 'geoip:private');
    generator.ensurePrivateIpBlock(config);
    config.routing.rules.unshift(...scoped);
    return config;
}

// Only compose existing classic credentials. No deterministic topology UUIDs,
// balancer inference, or direct/freedom fallback is permitted here.
function applyClassicL2tpPathIngress(config, { nodeId, groups = [], links = [], mode, materializedLinkIds = [] } = {}) {
    const generator = require('./configGenerator');
    // Internal writer input: these IDs are present in the candidate being
    // installed, not statuses supplied by a public request. Keep the ordinary
    // status fence for every other suffix hop; a prefix before this ingress is
    // not carrying packets that enter here.
    const materialized = new Set(materializedLinkIds.map(String));
    const byId = new Map(links.map(link => [id(link), link]));
    const seenTags = new Set((config.inbounds || []).map(row => row.tag));
    const seenPorts = new Set((config.inbounds || []).map(row => row.port));
    const requestedTags = new Set(), requestedPorts = new Set();
    for (const group of groups) {
        if (group.mode !== mode) continue;
        for (const path of group.paths || []) {
            if (path.enabled === false) continue;
            const pathLinks = (path.linkIds || []).map(linkId => byId.get(id(linkId)));
            const start = pathLinks.findIndex(link => link && id(link.portalNode) === id(nodeId));
            if (start < 0) continue;
            if (pathLinks.some((link, index) => !link || link.active !== true
                || (link.mode || 'reverse') !== mode
                || typeof link.tunnelUuid !== 'string' || !link.tunnelUuid
                || (index >= start && !['deployed', 'online'].includes(link.status)
                    && !(index === start && mode === 'reverse' && materialized.has(id(link)))))) throw invalidPath();
            if (mode === 'reverse' && materialized.has(id(pathLinks[start]))) {
                const link = pathLinks[start], suffix = id(link).slice(-8);
                const portals = (config.reverse?.portals || []).filter(row => row.tag === `portal-down-${suffix}`);
                const tunnels = (config.inbounds || []).filter(row => row.tag === `conn-down-${suffix}`);
                if (portals.length !== 1 || portals[0].domain !== (link.tunnelDomain || `${suffix}.reverse.tunnel.internal`)
                    || tunnels.length !== 1 || tunnels[0].protocol !== 'vless'
                    || tunnels[0].port !== (link.tunnelPort || 10086)
                    || tunnels[0].settings?.clients?.length !== 1
                    || tunnels[0].settings.clients[0].id !== link.tunnelUuid) throw invalidPath();
            }
            const nodes = new Set([id(pathLinks[0].portalNode)]);
            for (let index = 0; index < pathLinks.length; index++) {
                const link = pathLinks[index];
                if ((index > 0 && id(pathLinks[index - 1].bridgeNode) !== id(link.portalNode))
                    || nodes.has(id(link.bridgeNode))) throw invalidPath();
                nodes.add(id(link.bridgeNode));
            }
            const tag = `cascade-${path.pathKey}`;
            const port = cascadePathIngressPort(id(group), path.pathKey);
            if (requestedTags.has(tag) || requestedPorts.has(port)) throw invalidPath();
            requestedTags.add(tag); requestedPorts.add(port);
            const reuse = seenTags.has(tag) || seenPorts.has(port);
            if (reuse) {
                const matching = (config.inbounds || []).filter(row => row.tag === tag || row.port === port);
                const expected = { tag, listen: '127.0.0.1', port, protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } };
                const target = mode === 'reverse' ? `portal-down-${id(pathLinks[start]).slice(-8)}` : `fwd-${id(pathLinks.at(-1)).slice(-8)}`;
                const rules = config.routing.rules.filter(rule => rule.inboundTag?.includes(tag));
                if (matching.length !== 1 || !equal(matching[0], expected)
                    || !equal(rules, [{ type: 'field', inboundTag: [tag], outboundTag: target }])) throw invalidPath();
            }
            seenTags.add(tag);
            seenPorts.add(port);
            if (mode === 'reverse') {
                const egressTag = `portal-down-${id(pathLinks[start]).slice(-8)}`;
                if (!config.reverse?.portals?.some(row => row.tag === egressTag)) throw invalidPath();
                if (!reuse) generator.applyCascadePathIngress(config, [{ pathKey: path.pathKey, port, egressTag }]);
            } else {
                const suffix = pathLinks.slice(start);
                if (suffix.some(link => !link.bridgeNode?.ip && !link.bridgeNode?.domain)) throw invalidPath();
                // Reuse the exact existing generator; do not overwrite any
                // already-composed outbound with a differently ordered chain.
                const fragment = { inbounds: [], outbounds: [], routing: { rules: [] } };
                generator.applyForwardChain(fragment, suffix, [], [{ pathKey: path.pathKey, port }]);
                // A selected path is an exact suffix, not a geo predicate. The
                // ordinary generator's geo-only exit rules have no catch-all.
                fragment.routing.rules = [{ type: 'field', inboundTag: [tag], outboundTag: `fwd-${id(suffix[suffix.length - 1]).slice(-8)}` }];
                for (const outbound of fragment.outbounds) {
                    const existing = (config.outbounds || []).find(row => row.tag === outbound.tag);
                    if (existing && !equal(existing, outbound)) throw invalidPath();
                    if (!existing) (config.outbounds ||= []).push(outbound);
                }
                if (!reuse) {
                    (config.inbounds ||= []).push(...fragment.inbounds);
                    (config.routing ||= { rules: [] }).rules.push(...fragment.routing.rules);
                }
            }
        }
    }
    // Newly appended ingress routes must precede the generator's final block.
    finishClassicConfigRouting(config);
    return config;
}

const MANAGED_TAG = /^(?:relay-l2tp-|cascade-|fwd-|conn-|portal-|bridge-|tunnel(?:-|$))/;

// Regenerate subscription clients normally, but retain the already materialized
// classic cascade graph. The resolver must read the live MAIN profile under the
// same node lock as install; this helper does not supply execution authority.
function preserveClassicXraySections(generated, current, { replaceInboundTag } = {}) {
    if (!current || typeof current !== 'object' || Array.isArray(current)
        || !Array.isArray(current.inbounds) || !Array.isArray(current.outbounds)
        || !Array.isArray(current.routing?.rules)) throw invalidPath();
    const result = JSON.parse(JSON.stringify(generated));
    const managed = tag => typeof tag === 'string' && MANAGED_TAG.test(tag);
    const replacedRule = rule => rule.inboundTag?.includes(replaceInboundTag);
    const rules = current.routing.rules.filter(rule => !replacedRule(rule) && (
        rule.inboundTag?.some(managed) || managed(rule.outboundTag)
        || ['cascade-balancer', 'down-balancer'].includes(rule.balancerTag)
    ));
    const needed = new Set(rules.map(rule => rule.outboundTag).filter(Boolean));
    const appendUnique = (target, rows) => {
        const known = new Set(target.map(row => row.tag));
        for (const row of rows) {
            if (!known.has(row.tag)) { target.push(row); known.add(row.tag); }
        }
    };
    appendUnique(result.inbounds ||= [], current.inbounds.filter(row => managed(row.tag) && row.tag !== replaceInboundTag));
    appendUnique(result.outbounds ||= [], current.outbounds.filter(row => managed(row.tag) || needed.has(row.tag)));
    const knownRules = new Set((result.routing ||= { rules: [] }).rules.map(row => JSON.stringify(row)));
    for (const rule of rules) {
        if (!knownRules.has(JSON.stringify(rule))) result.routing.rules.push(rule);
        knownRules.add(JSON.stringify(rule));
    }
    if (current.reverse) result.reverse = JSON.parse(JSON.stringify(current.reverse));
    if (current.routing.balancers) {
        appendUnique(result.routing.balancers ||= [], current.routing.balancers);
    }
    if (rules.length > 0 && current.routing.domainStrategy) result.routing.domainStrategy = current.routing.domainStrategy;
    finishClassicConfigRouting(result);
    return result;
}

module.exports = { applyClassicL2tpPathIngress, preserveClassicXraySections, finishClassicConfigRouting };
