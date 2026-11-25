'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { compileRebuildGraph } = require('../modules/relay-l2tp/domain/rebuildTopologyCompiler');
const { buildTransitChannels } = require('../modules/relay-l2tp/services/rebuildTransitChannels');
const { composeRebuildProfiles, ingressTag, egressTag } = require('../modules/relay-l2tp/services/rebuildTopologyComposer');
const { xrayListenerProtocols } = require('../utils/cascadeTransport');

const requirePlan = (ok, reason) => {
    if (!ok) throw Object.assign(new Error('REBUILD_SCOPE_STAGE_UNPROVED'), { code: 'REBUILD_SCOPE_STAGE_UNPROVED', reason });
};
const key = (id, profile) => `${id}:${profile}`;
const hint = id => id.slice(-8);

function collect(profiles, graph) {
    requirePlan(Array.isArray(profiles), 'profile_roster');
    const map = new Map();
    for (const { nodeId, profile, config } of profiles) {
        const k = key(nodeId, profile);
        requirePlan(graph.byNodeId.has(nodeId) && ['main', 'bridge'].includes(profile) && !map.has(k)
            && Array.isArray(config?.inbounds) && Array.isArray(config?.outbounds)
            && Array.isArray(config?.routing?.rules), 'profile_roster');
        map.set(k, config);
    }
    requirePlan(map.size === 2 * graph.nodeIds.length, 'profile_roster');
    return map;
}

function ownedSocket(inbound) {
    // Don't stage beside units whose actual bind shape isn't a known generated
    // singleton. Legacy profiles/ranges require another planner, not guessing.
    const protocols = xrayListenerProtocols(inbound);
    requirePlan(Number.isInteger(inbound.port) && inbound.port > 0 && inbound.port <= 65535 && protocols.length
        && [undefined, '0.0.0.0', '127.0.0.1', '::', '::1'].includes(inbound.listen), 'listener_shape');
    return protocols.map(protocol => `${protocol}:${inbound.port}`);
}

function find(rows, match, reason) {
    const found = rows.filter(match);
    requirePlan(found.length === 1, reason);
    return found[0];
}

// An additive plan, not an execution receipt. The executor must pin the exact
// live and boot images and hold the writers' fence. Reject changes that would
// need decommissioning, an existing listener replacement, or a MAIN restart.
function planAdditiveScopedTransition({ before, after, composition }) {
    const { nodes, links, affectedNodeIds } = composition;
    const graph = compileRebuildGraph({ nodes, links, affectedNodeIds });
    const channels = buildTransitChannels(graph).artifacts;
    requirePlan(channels.length > 0, 'no_new_channels');
    const live = collect(before, graph), final = collect(after, graph);
    // Match the full desired image, including users, transport trust and PPP.
    const composed = collect(composeRebuildProfiles(composition), graph);
    const stage = new Map(graph.nodeIds.map(id => [id, structuredClone(live.get(key(id, 'main')))]));
    const downstreamFirst = [...graph.nodeIds].reverse();
    const rank = new Map(downstreamFirst.map((id, i) => [id, i]));
    const listeners = [], dialers = [], transit = [], ingress = [];
    const orderedChannels = [...channels].sort((a, b) => rank.get(a.target) - rank.get(b.target)
        || rank.get(a.source) - rank.get(b.source) || a.id.localeCompare(b.id));
    const used = (config, tag) => config.inbounds.some(row => row.tag === tag || row.settings?.clients?.some(c => c.reverse?.tag === tag))
        || config.outbounds.some(row => row.tag === tag || row.settings?.reverse?.tag === tag)
        || config.routing.rules.some(row => row.outboundTag === tag || row.inboundTag?.includes(tag));
    for (const ch of orderedChannels) {
        const { id, source, target, mode, link } = ch;
        const reverse = mode === 'reverse', suffix = hint(id);
        const listenerId = reverse ? source : target, dialerId = reverse ? target : source;
        const incoming = ingressTag(ch), outgoing = egressTag(ch);
        const listenerTag = reverse ? `rebuild-rp-conn-${suffix}` : incoming;
        const dialerTag = reverse ? `rebuild-rp-dial-${suffix}` : outgoing;
        const listener = find(final.get(key(listenerId, 'main')).inbounds, row => row?.tag === listenerTag, 'listener');
        const dialer = find(final.get(key(dialerId, 'main')).outbounds, row => row?.tag === dialerTag, 'dialer');
        const accounts = listener.settings?.clients;
        const dial = reverse ? dialer.settings : find(dialer.settings?.vnext ?? [], () => true, 'dial_endpoint');
        const users = reverse ? [dial] : dial?.users;
        requirePlan(listener.listen === '0.0.0.0' && listener.port === link.tunnelPort && dial?.port === link.tunnelPort
            && dial.address === graph.byNodeId.get(listenerId).node.ip
            && listener.protocol === ch.protocol && dialer.protocol === ch.protocol
            && listener.streamSettings?.network === 'tcp' && dialer.streamSettings?.network === 'tcp'
            && Array.isArray(accounts) && accounts.length === 1 && accounts[0]?.id === link.tunnelUuid
            && Array.isArray(users) && users.length === 1 && users[0]?.id === link.tunnelUuid
            && (!reverse || accounts[0]?.reverse?.tag === outgoing && dial.reverse?.tag === incoming), 'channel_pair');
        const bind = stage.get(listenerId), call = stage.get(dialerId);
        const both = [...bind.inbounds, ...live.get(key(listenerId, 'bridge')).inbounds];
        const sockets = new Set(both.flatMap(ownedSocket));

        requirePlan(!used(bind, listenerTag) && !used(call, dialerTag) && !used(stage.get(source), outgoing)
            && !used(stage.get(target), incoming) && !ownedSocket(listener).some(socket => sockets.has(socket)), 'channel_conflict');
        // Add all pairs before inserting any inter-channel routing reference.
        bind.inbounds.push(structuredClone(listener));
        call.outbounds.push(structuredClone(dialer));
        listeners.push({ nodeId: listenerId, channelId: id, tag: listenerTag, config: listener });
        dialers.push({ nodeId: dialerId, channelId: id, tag: dialerTag, config: dialer });
    }
    const portalSelectors = new Map();
    for (const edge of graph.byLinkId.values()) {
        if (!edge.portalExit) continue;
        if (!portalSelectors.has(edge.target)) portalSelectors.set(edge.target, new Map());
        portalSelectors.get(edge.target).set(ingressTag(edge), hint(edge.id));
    }
    // Additions may be stored in a different order, but no original inbounds
    // or outbounds may move relative to one another; the first outbound is
    // the implicit default even in the absence of every routing rule.
    const sameHandlers = (staged, desired, additions) => {
        const tags = new Set(additions.map(item => item.tag));
        return new Set(desired.map(item => item.tag)).size === desired.length
            && equal(staged.filter(item => !tags.has(item.tag)), desired.filter(item => !tags.has(item.tag)))
            && equal(staged[0], desired[0]);
    };
    for (const id of downstreamFirst) {
        const dst = stage.get(id), target = final.get(key(id, 'main'));
        const { routing: original, inbounds, outbounds, ...oldFields } = dst;
        const { routing: policy, inbounds: nextInbounds, outbounds: nextOutbounds, ...nextFields } = target;
        requirePlan(equal(live.get(key(id, 'bridge')), final.get(key(id, 'bridge'))), 'bridge_changed');
        requirePlan(equal(oldFields, nextFields), 'main_settings_changed');
        requirePlan(sameHandlers(inbounds, nextInbounds, listeners.filter(step => step.nodeId === id)), 'existing_inbounds_changed');
        requirePlan(sameHandlers(outbounds, nextOutbounds, dialers.filter(step => step.nodeId === id)), 'existing_outbounds_changed');
        const { rules: oldRules, ...oldRouter } = original;
        const { rules: finalRules, ...newRouter } = policy;
        requirePlan(equal(oldRouter, newRouter), 'routing_strategy');
        const incoming = new Map(channels.filter(ch => ch.target === id).map(ch => [ingressTag(ch), hint(ch.id)]));
        const portals = portalSelectors.get(id);
        const transitRules = new Set(), portalRules = new Set(), ruleTags = new Set();
        for (const rule of finalRules) {
            const tag = rule.ruleTag;
            requirePlan(!tag || !ruleTags.has(tag), 'rule_collision');
            if (tag) ruleTags.add(tag);
            const transitSuffix = rule.inboundTag?.length === 1 && incoming.get(rule.inboundTag[0]);
            const portalSuffix = rule.inboundTag?.length === 1 && portals?.get(rule.inboundTag[0]);
            if (typeof tag === 'string' && tag.startsWith('rebuild-policy-transit-')) {
                requirePlan(transitSuffix && tag.startsWith(`rebuild-policy-transit-${transitSuffix}-`), 'transit_policy');
                transitRules.add(rule);
            } else if (typeof tag === 'string' && tag.startsWith('rebuild-policy-portal-')) {
                requirePlan(portalSuffix && tag.startsWith(`rebuild-policy-portal-${portalSuffix}-`), 'portal_policy');
                portalRules.add(rule);
            } else {
                requirePlan(!rule.inboundTag?.some(v => incoming.has(v)), 'overlapping_transit');
            }
        }
        for (const [kind, entries, rules] of [['transit', incoming, transitRules], ['portal', portals ?? [], portalRules]]) {
            for (const [tag, suffix] of entries) find([...rules], row => row.inboundTag[0] === tag
                && row.ruleTag === `rebuild-policy-${kind}-${suffix}-default`, `${kind}_default`);
        }
        requirePlan(equal(oldRules, finalRules.filter(rule => !transitRules.has(rule) && !portalRules.has(rule))), 'existing_rules_changed');
        const stageRules = finalRules.filter(rule => !portalRules.has(rule));
        for (const [ordered, added] of [[stageRules, transitRules], [finalRules, portalRules]]) {
            for (const rule of added) {
                const earlier = ordered.slice(0, ordered.indexOf(rule));
                requirePlan(earlier.every(item => added.has(item) || (Array.isArray(item.inboundTag)
                    && item.inboundTag.length && !item.inboundTag.includes(rule.inboundTag[0]))), 'scoped_rule_shadowed');
            }
        }
        const staged = { ...original, rules: stageRules };
        if (transitRules.size) {
            // Appending the new policy must be equivalent to its canonical
            // boot placement. An old rule may not match any new transit
            // ingress, even if it originally followed the inserted group.
            requirePlan(oldRules.every(rule => Array.isArray(rule.inboundTag) && rule.inboundTag.length
                && !rule.inboundTag.some(tag => incoming.has(tag))), 'transit_append_not_disjoint');
            transit.push({ nodeId: id, before: original, after: staged, append: [...transitRules] });
        }
        if (portalRules.size) ingress.push({ nodeId: id, before: staged, after: policy });
    }
    requirePlan(equal(final, composed), 'desired_image_mismatch');
    return structuredClone({ listeners, dialers, transit, ingress });
}

module.exports = { planAdditiveScopedTransition };
