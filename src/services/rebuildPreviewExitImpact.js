'use strict';

const { isDeepStrictEqual } = require('node:util');
const { REBUILD_POLICY_RULE_PREFIX: prefix, egressTag, ingressTag } = require('../modules/relay-l2tp/services/rebuildTopologyComposer');
const { id: objectId, plainName } = require('./rebuildExit');

const transitRule = /^rebuild-policy-transit-([a-f0-9]{8})-default$/;
const list = value => Array.isArray(value) ? value : [];
const scopedRules = config => list(config?.routing?.rules).filter(rule =>
    typeof rule?.ruleTag === 'string' && rule.ruleTag.startsWith(`${prefix}transit-`));
const hasObservedScopedTransit = profiles => [...profiles.values()].some(config => scopedRules(config).length > 0);
const listenerTag = (mode, suffix) => mode === 'reverse' ? `rebuild-rp-conn-${suffix}` : `fwd-hop-${suffix}`;
const validTcpListener = row => row?.streamSettings?.network === 'tcp' && Number.isInteger(row.port)
    && row.port > 0 && row.port <= 65535;

// Preview only. The emitted config records only the eight-character tag
// suffix. Corroborate the pair against both MAIN profiles; never invent a
// full link ID, publish credentials, or use the result as Apply authority.
function observedChannels(links, profiles, nodeRole) {
    const physical = new Map(), taken = new Set(links.map(row => String(row._id).slice(-8)));
    for (const row of links) {
        const source = String(row.portalNode), target = String(row.bridgeNode);
        if (nodeRole(source) !== 'relay' || nodeRole(target) !== 'relay') continue;
        if (!physical.has(target)) physical.set(target, new Set());
        physical.get(target).add(source);
    }
    const rows = new Map(), ambiguous = new Set();
    const unique = (items, tag) => {
        const matches = list(items).filter(row => row?.tag === tag);
        return matches.length === 1 ? matches[0] : undefined;
    };
    for (const [target, targetProfile] of profiles) {
        for (const rule of scopedRules(targetProfile)) {
            const suffix = transitRule.exec(rule.ruleTag)?.[1];
            if (!suffix || taken.has(suffix) || !Array.isArray(rule.inboundTag) || rule.inboundTag.length !== 1) continue;
            const tag = rule.inboundTag[0];
            const mode = tag === `rebuild-rp-ingress-${suffix}` ? 'reverse'
                : tag === `fwd-hop-${suffix}` ? 'forward' : null;
            if (!mode) continue;
            const reverse = mode === 'reverse';
            for (const source of physical.get(target) ?? []) {
                const sourceProfile = profiles.get(source);
                const listener = unique((reverse ? sourceProfile : targetProfile)?.inbounds, listenerTag(mode, suffix));
                const dialer = unique((reverse ? targetProfile : sourceProfile)?.outbounds,
                    reverse ? `rebuild-rp-dial-${suffix}` : `fwd-${suffix}`);
                const endpoint = reverse ? dialer?.settings : dialer?.settings?.vnext?.[0];
                const client = listener?.settings?.clients?.[0];
                const user = reverse ? endpoint : endpoint?.users?.[0];
                if (!validTcpListener(listener) || dialer?.streamSettings?.network !== 'tcp'
                    || dialer.protocol !== listener.protocol || endpoint?.port !== listener.port
                    || typeof client?.id !== 'string' || client.id !== user?.id
                    || (reverse && (client.reverse?.tag !== `rebuild-rp-egress-${suffix}` || endpoint.reverse?.tag !== tag))) continue;
                if (rows.has(suffix)) ambiguous.add(suffix);
                rows.set(suffix, { id: suffix, source, target, mode });
            }
        }
    }
    return [...rows].filter(([key]) => !ambiguous.has(key)).map(([, row]) => row);
}

// The stored mode may be a draft edit. Resolve the mode from the observed
// outbound tag and carry that same edge's payload ingress tag into the relay.
function routeGraphs(links, nodeRole, multiHop) {
    const targets = new Map();
    for (const link of links) {
        const id = String(link._id), source = String(link.portalNode), target = String(link.bridgeNode);
        if (!targets.has(source)) targets.set(source, new Map());
        const outgoing = targets.get(source);
        for (const mode of ['forward', 'reverse']) {
            const edge = { id, mode, target, name: plainName(link.name), scoped: link.scoped === true };
            const tag = egressTag(edge);
            outgoing.set(tag, outgoing.has(tag) ? null : edge);
        }
    }

    function policy(profiles, nodeId, incoming) {
        const rules = profiles.get(nodeId)?.routing?.rules;
        const transit = incoming && ingressTag(incoming);
        const scopedPrefix = incoming && `${incoming.scoped ? 'transit' : 'portal'}-${incoming.id.slice(-8)}-`;
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
        const hops = [], relays = [];
        let geo = false;
        while (nodeId && !visited.has(nodeId)) {
            if (nodeRole(nodeId) === 'bridge') return { exit: nodeId, edge, geo, hops, relays };
            visited.add(nodeId);
            if (outboundTag === undefined) {
                const route = policy(profiles, nodeId, edge);
                if (edge && nodeRole(nodeId) === 'relay') relays.push({ edge, route });
                geo ||= hasGeoExit(route);
                outboundTag = route.defaultTag;
            }
            if (outboundTag === 'block') return { exit: null, geo, hops, relays };
            edge = edgeFor(nodeId, outboundTag);
            if (edge) hops.push(edge);
            nodeId = edge?.target;
            outboundTag = undefined;
        }
        // Legacy/manual/unmapped isn't an observed blackhole.
        return { exit: undefined, geo, hops, relays };
    }

    function portalPolicy(profiles, nodeId) {
        const root = policy(profiles, nodeId);
        const fromRule = outboundTag => {
            const edge = edgeFor(nodeId, outboundTag);
            const path = defaultPath(profiles, nodeId, undefined, outboundTag);
            return { edge, path, relay: path.relays[0]?.route };
        };
        const resolveRelayGeo = ({ path }) => {
            const seen = { domain: new Set(), ip: new Set() };
            return path.relays.flatMap(({ edge, route }, index) => route.geo.flatMap(({ match, selectors, outboundTag }) => {
                const effective = multiHop ? selectors.filter(value => !seen[match].has(value)) : selectors;
                if (multiHop) effective.forEach(value => seen[match].add(value));
                if (!effective.length) return [];
                const branch = defaultPath(profiles, edge.target, edge, outboundTag);
                branch.hops.unshift(...path.hops.slice(0, index + 1));
                return [{ match, selectors: effective, path: branch }];
            }));
        };
        return { root, primary: fromRule(root.defaultTag), geo: root.geo.map(rule => ({ ...rule, ...fromRule(rule.outboundTag) })),
            resolveRelayGeo };
    }
    return { portalPolicy, hasGeoExit };
}

const channel = edge => edge && [edge.target, edge.id];
const destination = ({ exit, edge }) => [exit, channel(edge)];
function compareGeo(previous, next, multiHop) {
    const routeSignature = path => [...destination(path), ...(multiHop ? [path.hops.map(edge => [edge.target, edge.mode, edge.id.slice(-8)])] : [])];
    const geoSignature = ({ match, selectors, path }) => [match, selectors, routeSignature(path)];
    // Don't infer geo policy from a legacy or unreadable root. Include portal
    // geo rules themselves, and at a relay only add detail for a portal that
    // uses (or used) the dedicated policy on this reachable ingress.
    if (previous.root.defaultTag === undefined || next.root.defaultTag === undefined) return;
    const scoped = new Set([...previous.geo, ...next.geo].filter(branch => branch.relay?.scoped).map(branch => branch.edge.id));
    const portalGeo = side => side.geo.map(branch => {
        const dedicated = scoped.has(branch.edge?.id);
        const relayGeo = dedicated ? side.resolveRelayGeo(branch) : [];
        return {
            signature: [branch.match, branch.selectors, channel(branch.edge), routeSignature(branch.path), relayGeo.map(geoSignature)],
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

function addExitImpacts(report, links, observedMain, candidates, nodeRole, nodeName, remove = false, transit = {}) {
    const { after = [] } = transit;
    const before = transit.before ?? observedChannels(links, observedMain, nodeRole);
    const scoped = transit.multiHop === true || hasObservedScopedTransit(observedMain);
    const channelRows = rows => rows.map(({ id, source, target }) => ({
        _id: id, portalNode: source, bridgeNode: target, scoped: true,
    }));
    const observed = routeGraphs([...links, ...channelRows(before)], nodeRole, scoped);
    const proposed = routeGraphs([...links, ...channelRows(after)], nodeRole, scoped);
    const { hasGeoExit } = proposed;
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
        const locate = channels => new Map(channels.flatMap(row => {
            if ((row.mode === 'reverse' ? row.source : row.target) !== node.nodeId) return [];
            const suffix = row.id.slice(-8);
            return [[suffix, { id: row.id, tag: listenerTag(row.mode, suffix) }]];
        }));
        const delta = [];
        const oldRows = locate(before), newRows = locate(after);
        for (const suffix of new Set([...oldRows.keys(), ...newRows.keys()])) {
            const get = (profiles, row) => row && profiles.get(node.nodeId)?.inbounds?.find(i => i.tag === row.tag);
            const old = get(observedMain, oldRows.get(suffix)), next = get(proposedMain, newRows.get(suffix));
            if (isDeepStrictEqual(old, next)) continue;
            if ([old, next].filter(Boolean).every(validTcpListener)) {
                const channelId = objectId(newRows.get(suffix)?.id ?? oldRows.get(suffix)?.id);
                delta.push({ ...(channelId ? { channelId } : { channelRef: suffix }), before: old?.port ?? null, after: next?.port ?? null });
            }
        }
        if (delta.length) node.transitListeners = delta;
        const role = nodeRole(node.nodeId);
        if (remove && ['portal', 'relay', 'bridge'].includes(role)) node.role = role;
        if (role !== 'portal') continue;
        const previous = observed.portalPolicy(observedMain, node.nodeId), next = proposed.portalPolicy(proposedMain, node.nodeId);
        const fromPath = previous.primary.path, toPath = next.primary.path;
        const multiHop = path => path.hops.filter(edge => nodeRole(edge.target) === 'relay').length > 1;
        const path = ({ hops, exit }) => exit === undefined ? null : [...hops.map(edge => ({
            nodeId: edge.target, name: plainName(nodeName?.(edge.target)) || edge.target,
            ...(objectId(edge.id) ? { linkId: edge.id } : { channelRef: edge.id }), ...(edge.name && { linkName: edge.name }),
        })), ...(exit === null ? [null] : [])];
        if (scoped && (multiHop(fromPath) || multiHop(toPath))) {
            node.portalExitPath = { before: path(fromPath), after: path(toPath) };
        }
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
        const geo = compareGeo(previous, next, scoped);
        if (geo) {
            // Selectors, rule tags and raw MAIN data never enter the report.
            const publish = paths => paths.map(path => path.exit === null ? null : publicExit(path, true) ?? {});
            const before = publish(geo.before), after = publish(geo.after);
            if ([...before, ...after].some(exit => exit?.nodeId)) node.portalExitGeoChange = { before, after };
            if (scoped && [...geo.before, ...geo.after].some(multiHop)) {
                node.portalExitGeoPaths = { before: geo.before.map(path), after: geo.after.map(path) };
            }
        }
    }
}

function addRemoveExitImpacts(report, links, observedMain, candidates, nodeRole) {
    return addExitImpacts(report, links, observedMain, candidates, nodeRole, undefined, true);
}

module.exports = { addExitImpacts, addRemoveExitImpacts, hasObservedScopedTransit };
