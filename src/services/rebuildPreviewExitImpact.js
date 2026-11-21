'use strict';

const { REBUILD_POLICY_RULE_PREFIX: prefix, egressTag } = require('../modules/relay-l2tp/services/rebuildTopologyComposer');

function policy(config) {
    const rules = Array.isArray(config?.routing?.rules) ? config.routing.rules : [];
    const defaultTag = rules.find(r => r?.ruleTag === `${prefix}default`)?.outboundTag;
    const geo = rules.some(r => typeof r?.ruleTag === 'string' && r.ruleTag.startsWith(`${prefix}geo-`)
        && typeof r.outboundTag === 'string' && r.outboundTag !== 'block');
    return { defaultTag, geo };
}

function addRemoveExitImpacts(report, links, observedMain, candidates, nodeRole) {
    const targets = new Map();
    for (const link of links) {
        const id = String(link._id), source = String(link.portalNode), target = String(link.bridgeNode);
        if (!targets.has(source)) targets.set(source, new Map());
        const outgoing = targets.get(source);
        // The stored mode may be a draft edit; either generated tag identifies the edge.
        for (const mode of ['forward', 'reverse']) {
            const tag = egressTag({ id, mode });
            outgoing.set(tag, outgoing.has(tag) ? null : target);
        }
    }
    const before = new Map([...observedMain].map(([id, config]) => [id, policy(config)]));
    const after = new Map(candidates.filter(p => p.profile === 'main').map(p => [p.nodeId, policy(p.config)]));

    // Follow only the composer's explicit default decisions. A default hop to
    // a relay with a geo-only policy is not an end-to-end default. Other route
    // predicates, peer profiles and runtime health are outside this advisory.
    function defaultPath(policies, id) {
        const visited = new Set();
        let geo = false;
        while (id && !visited.has(id)) {
            if (nodeRole(id) === 'bridge') return { hasDefault: true, geo };
            visited.add(id);
            const route = policies.get(id);
            geo ||= !!route?.geo;
            if (route?.defaultTag === 'block') return { hasDefault: false, geo };
            id = targets.get(id)?.get(route?.defaultTag);
        }
        return { hasDefault: undefined, geo }; // legacy, manual, or ambiguous
    }

    for (const node of report) {
        const role = nodeRole(node.nodeId);
        if (['portal', 'relay', 'bridge'].includes(role)) node.role = role;
        if (role !== 'portal') continue;
        const next = after.get(node.nodeId);
        // Generated policy routes to non-block targets only when the compiler
        // found a configured exit. A surviving geo route is not a total loss.
        const hasExit = next?.geo || (next?.defaultTag && next.defaultTag !== 'block');
        const previous = defaultPath(before, node.nodeId);
        if (!hasExit) node.exitImpact = previous.hasDefault || previous.geo ? 'lost' : 'blocked';
        else if (previous.hasDefault && defaultPath(after, node.nodeId).hasDefault === false) node.exitImpact = 'default-lost';
    }
}

module.exports = { addRemoveExitImpacts };
