'use strict';

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
function applyClassicL2tpPathIngress(config, { nodeId, groups = [], links = [], mode } = {}) {
    const generator = require('./configGenerator');
    const byId = new Map(links.map(link => [id(link), link]));
    const seenTags = new Set((config.inbounds || []).map(row => row.tag));
    const seenPorts = new Set((config.inbounds || []).map(row => row.port));
    for (const group of groups) {
        if (group.mode !== mode) continue;
        for (const path of group.paths || []) {
            if (path.enabled === false) continue;
            const pathLinks = (path.linkIds || []).map(linkId => byId.get(id(linkId)));
            const start = pathLinks.findIndex(link => link && id(link.portalNode) === id(nodeId));
            if (start < 0) continue;
            if (pathLinks.some(link => !link || link.active !== true
                || !['deployed', 'online'].includes(link.status) || (link.mode || 'reverse') !== mode
                || typeof link.tunnelUuid !== 'string' || !link.tunnelUuid)) throw invalidPath();
            const nodes = new Set([id(pathLinks[0].portalNode)]);
            for (let index = 0; index < pathLinks.length; index++) {
                const link = pathLinks[index];
                if ((index > 0 && id(pathLinks[index - 1].bridgeNode) !== id(link.portalNode))
                    || nodes.has(id(link.bridgeNode))) throw invalidPath();
                nodes.add(id(link.bridgeNode));
            }
            const tag = `cascade-${path.pathKey}`;
            const port = cascadePathIngressPort(id(group), path.pathKey);
            if (seenTags.has(tag) || seenPorts.has(port)) throw invalidPath();
            seenTags.add(tag);
            seenPorts.add(port);
            if (mode === 'reverse') {
                const egressTag = `portal-down-${id(pathLinks[start]).slice(-8)}`;
                if (!config.reverse?.portals?.some(row => row.tag === egressTag)) throw invalidPath();
                generator.applyCascadePathIngress(config, [{ pathKey: path.pathKey, port, egressTag }]);
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
                    if (existing && JSON.stringify(existing) !== JSON.stringify(outbound)) throw invalidPath();
                    if (!existing) (config.outbounds ||= []).push(outbound);
                }
                (config.inbounds ||= []).push(...fragment.inbounds);
                (config.routing ||= { rules: [] }).rules.push(...fragment.routing.rules);
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
