'use strict';

const { isDeepStrictEqual } = require('node:util');
const { REBUILD_POLICY_RULE_PREFIX: prefix, egressTag, ingressTag } = require('../modules/relay-l2tp/services/rebuildTopologyComposer');
const { id: objectId, plainName } = require('./rebuildExit');

// The stored mode may be a draft edit. Resolve the mode from the observed
// outbound tag and carry that same edge's payload ingress tag into the relay.
function routeGraphs(links, nodeRole) {
    const targets = new Map();
    for (const link of links) {
        const id = String(link._id), source = String(link.portalNode), target = String(link.bridgeNode);
        if (!targets.has(source)) targets.set(source, new Map());
        const outgoing = targets.get(source);
        for (const mode of ['forward', 'reverse']) {
            const edge = { id, mode, target, name: plainName(link.name) };
            const tag = egressTag(edge);
            outgoing.set(tag, outgoing.has(tag) ? null : edge);
        }
    }

    function policy(profiles, nodeId, incoming) {
        const rules = profiles.get(nodeId)?.routing?.rules;
        const transit = incoming && ingressTag(incoming);
        const scopedPrefix = incoming && `portal-${incoming.id.slice(-8)}-`;
        const geo = [], seen = { domain: new Set(), ip: new Set() };
        let scoped = false;
        for (const rule of Array.isArray(rules) ? rules : []) {
            const { ruleTag, outboundTag, inboundTag } = rule ?? {};
            if (typeof ruleTag !== 'string' || !ruleTag.startsWith(prefix) || typeof outboundTag !== 'string') continue;
            const suffix = ruleTag.slice(prefix.length);
            const dedicated = !!scopedPrefix && suffix.startsWith(scopedPrefix);
            const matchesIngress = Array.isArray(inboundTag) && inboundTag.includes(transit);
            if ((dedicated || (transit && Array.isArray(inboundTag))) && !matchesIngress) continue;
            const kind = dedicated ? suffix.slice(scopedPrefix.length) : suffix;
            const match = /^geo-\d+-(domain|ip)$/.exec(kind)?.[1];
            if (kind !== 'default' && !match) continue;
            if (!Object.keys(rule).every(key => ['type', 'ruleTag', 'outboundTag', 'inboundTag', match].includes(key))) continue;
            if (kind === 'default') return { defaultTag: outboundTag, geo, scoped: scoped || dedicated };
            if (!Array.isArray(rule[match]) || !rule[match].every(value => typeof value === 'string')) continue;
            const selectors = [...new Set(rule[match])].filter(value => !seen[match].has(value)).sort();
            for (const value of selectors) seen[match].add(value);
            if (!selectors.length) continue; // Earlier branches already match these literals.
            geo.push({ match, selectors, outboundTag });
            scoped ||= dedicated;
        }
        return { geo, scoped };
    }

    const edgeFor = (nodeId, outboundTag) => targets.get(nodeId)?.get(outboundTag) ?? undefined;
    const hasGeoExit = route => route.geo.some(rule => rule.outboundTag !== 'block');
    function defaultPath(profiles, nodeId, edge, outboundTag) {
        const visited = new Set();
        let geo = false;
        while (nodeId && !visited.has(nodeId)) {
            if (nodeRole(nodeId) === 'bridge') return { exit: nodeId, edge, geo };
            visited.add(nodeId);
            if (outboundTag === undefined) {
                const route = policy(profiles, nodeId, edge);
                geo ||= hasGeoExit(route);
                outboundTag = route.defaultTag;
            }
            if (outboundTag === 'block') return { exit: null, geo };
            edge = edgeFor(nodeId, outboundTag);
            nodeId = edge?.target;
            outboundTag = undefined;
        }
        // Legacy/manual/unmapped isn't an observed blackhole.
        return { exit: undefined, geo };
    }

    function portalPolicy(profiles, nodeId) {
        const root = policy(profiles, nodeId);
        const fromRule = outboundTag => {
            const edge = edgeFor(nodeId, outboundTag);
            return { edge, path: defaultPath(profiles, nodeId, undefined, outboundTag),
                relay: nodeRole(edge?.target) === 'relay' ? policy(profiles, edge.target, edge) : null };
        };
        const resolveRelayGeo = ({ edge, relay }) => (relay?.geo ?? []).map(({ match, selectors, outboundTag }) => ({
            match, selectors, path: defaultPath(profiles, edge.target, edge, outboundTag),
        }));
        return { root, primary: fromRule(root.defaultTag), geo: root.geo.map(rule => ({ ...rule, ...fromRule(rule.outboundTag) })),
            resolveRelayGeo };
    }
    return { portalPolicy, hasGeoExit };
}

const channel = edge => edge && [edge.target, edge.id];
const destination = ({ exit, edge }) => [exit, channel(edge)];
const geoSignature = ({ match, selectors, path }) => [match, selectors, destination(path)];

function compareGeo(previous, next) {
    // Don't infer geo policy from a legacy or unreadable root. Include portal
    // geo rules themselves, and at a relay only add detail for a portal that
    // uses (or used) the dedicated policy on this reachable ingress.
    if (previous.root.defaultTag === undefined || next.root.defaultTag === undefined) return;
    const scoped = new Set([...previous.geo, ...next.geo].filter(branch => branch.relay?.scoped).map(branch => branch.edge.id));
    const portalGeo = side => side.geo.map(branch => {
        const dedicated = scoped.has(branch.edge?.id);
        const relayGeo = dedicated ? side.resolveRelayGeo(branch) : [];
        return {
            signature: [branch.match, branch.selectors, channel(branch.edge), destination(branch.path), relayGeo.map(geoSignature)],
            paths: [...relayGeo.map(entry => entry.path), branch.path],
        };
    });
    const before = [], after = [];
    const prior = portalGeo(previous), proposed = portalGeo(next);
    if (!isDeepStrictEqual(prior.map(branch => branch.signature), proposed.map(branch => branch.signature))) {
        before.push(...prior.flatMap(branch => branch.paths));
        after.push(...proposed.flatMap(branch => branch.paths));
    }
    if (previous.primary.relay?.scoped || next.primary.relay?.scoped) {
        const prior = previous.resolveRelayGeo(previous.primary), proposed = next.resolveRelayGeo(next.primary);
        if (!isDeepStrictEqual(prior.map(geoSignature), proposed.map(geoSignature))) {
            before.push(...prior.map(entry => entry.path));
            after.push(...proposed.map(entry => entry.path));
        }
    }
    if (before.length || after.length) return { before, after };
}

function addExitImpacts(report, links, observedMain, candidates, nodeRole, nodeName, remove = false) {
    const { portalPolicy, hasGeoExit } = routeGraphs(links, nodeRole);
    const proposedMain = new Map(candidates.filter(p => p.profile === 'main').map(p => [p.nodeId, p.config]));
    function publicExit({ exit, edge }, withChannel = false) {
        if (exit == null) return exit;
        const nodeId = objectId(exit);
        if (!nodeId) return undefined;
        const linkId = withChannel && objectId(edge?.id);
        return { nodeId, name: plainName(nodeName?.(nodeId)) || nodeId,
            ...(linkId ? { linkId, ...(edge.name && { linkName: edge.name }) } : {}) };
    }
    for (const node of report) {
        const role = nodeRole(node.nodeId);
        if (remove && ['portal', 'relay', 'bridge'].includes(role)) node.role = role;
        if (role !== 'portal') continue;
        const previous = portalPolicy(observedMain, node.nodeId), next = portalPolicy(proposedMain, node.nodeId);
        const fromPath = previous.primary.path, toPath = next.primary.path;
        if (remove) {
            const { defaultTag } = next.root;
            const hasExit = hasGeoExit(next.root) || (defaultTag && defaultTag !== 'block');
            if (!hasExit) node.exitImpact = fromPath.exit || fromPath.geo || hasGeoExit(previous.root) ? 'lost' : 'blocked';
            else if (fromPath.exit && toPath.exit === null) node.exitImpact = 'default-lost';
        }
        const channelChanged = fromPath.exit === toPath.exit && !!objectId(fromPath.edge?.id) && !!objectId(toPath.edge?.id)
            && fromPath.edge.id !== toPath.edge.id;
        const from = publicExit(fromPath, channelChanged), to = publicExit(toPath, channelChanged);
        if (from !== undefined && to !== undefined && (fromPath.exit !== toPath.exit || channelChanged)) {
            node.portalExitChange = { before: from, after: to };
        }
        const geo = compareGeo(previous, next);
        if (geo) {
            // Selectors, rule tags and raw MAIN data never enter the report.
            const publish = paths => paths.map(path => path.exit === null ? null : publicExit(path, true) ?? {});
            const before = publish(geo.before), after = publish(geo.after);
            if ([...before, ...after].some(exit => exit?.nodeId)) node.portalExitGeoChange = { before, after };
        }
    }
}

function addRemoveExitImpacts(report, links, observedMain, candidates, nodeRole) {
    return addExitImpacts(report, links, observedMain, candidates, nodeRole, undefined, true);
}

module.exports = { addExitImpacts, addRemoveExitImpacts };
