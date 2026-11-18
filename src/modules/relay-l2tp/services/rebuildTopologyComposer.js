'use strict';

const generator = require('../../../services/configGenerator');
const { composeXrayConfig } = require('./xrayConfigComposer');
const { compileRebuildGraph, rebuildId, requireRebuild } = require('../domain/rebuildTopologyCompiler');

const REBUILD_POLICY_RULE_PREFIX = 'rebuild-policy-';
const short = entry => entry.id.slice(-8); // same tags/domains as the classic tunnel helpers
const ingressTag = entry => `${entry.mode === 'reverse' ? 'bridge' : 'fwd-hop'}-${short(entry)}`;
const egressTag = entry => `${entry.mode === 'reverse' ? 'portal' : 'fwd'}-${short(entry)}`;
const validPort = port => Number.isSafeInteger(port) && port > 0 && port <= 65535;
const address = node => typeof node.ip === 'string' && /^\S+$/.test(node.ip);

function projectLinks(graph) {
    const shortIds = new Set();
    const result = new Map();
    for (const entry of graph.byLinkId.values()) {
        const link = entry.link;
        const source = graph.byNodeId.get(entry.source).node;
        const target = graph.byNodeId.get(entry.target).node;
        requireRebuild(address(entry.mode === 'reverse' ? source : target), 'REBUILD_INVALID_NODE_ADDRESS');
        requireRebuild(validPort(link.tunnelPort) && typeof link.tunnelUuid === 'string' && /^\S+$/.test(link.tunnelUuid)
            && (!link.tunnelDomain || typeof link.tunnelDomain === 'string' && /^[a-z0-9.-]+$/i.test(link.tunnelDomain))
            && ['vless', 'vmess'].includes(link.tunnelProtocol ?? 'vless')
            && ['none', 'tls', 'reality'].includes(link.tunnelSecurity ?? 'none')
            && ['tcp', 'ws', 'grpc', 'xhttp', 'splithttp'].includes(link.tunnelTransport ?? 'tcp'), 'REBUILD_INVALID_TUNNEL');
        if (link.tunnelSecurity === 'reality') {
            requireRebuild(typeof link.realityPrivateKey === 'string' && link.realityPrivateKey.length > 0
                && typeof link.realityPublicKey === 'string' && link.realityPublicKey.length > 0, 'REBUILD_INVALID_TUNNEL');
        }
        requireRebuild(!shortIds.has(short(entry)), 'REBUILD_TUNNEL_TAG_COLLISION');
        shortIds.add(short(entry));
        result.set(entry.id, { ...link, _id: entry.id, portalNode: source, bridgeNode: target });
    }
    return result;
}

function collectUsers(usersByNode) {
    requireRebuild(usersByNode instanceof Map || (usersByNode && typeof usersByNode === 'object'
        && !Array.isArray(usersByNode)), 'REBUILD_INVALID_USERS');
    const users = new Map();
    for (const [key, list] of usersByNode instanceof Map ? usersByNode : Object.entries(usersByNode)) {
        const nodeId = rebuildId(key);
        requireRebuild(!users.has(nodeId), 'REBUILD_INVALID_USERS');
        users.set(nodeId, list);
    }
    return users;
}

function blackholeProfile() {
    return {
        log: { loglevel: 'warning', access: 'none' }, inbounds: [],
        outbounds: [{ tag: 'block', protocol: 'blackhole' }],
        routing: { domainStrategy: 'IPIfNonMatch', rules: [] },
    };
}

function mainProfile(node, users, options) {
    requireRebuild(node.type === 'xray' && (node.port === undefined || validPort(node.port))
        && (node.xray?.apiPort === undefined || validPort(node.xray.apiPort)), 'REBUILD_INVALID_NODE_CONFIG');
    requireRebuild(Array.isArray(users) && users.every(user => typeof user?.xrayUuid === 'string' && /^\S+$/.test(user.xrayUuid)
        && typeof user.userId === 'string' && user.userId.length > 0), 'REBUILD_INVALID_USERS');
    // Only deny rules carry over. A classic direct/custom ACL can bypass the
    // rebuild graph; do not even give the profile those outbound objects.
    const aclRules = (node.aclRules ?? []).filter(rule => typeof rule === 'string' && /^reject\(.+\)$/.test(rule));
    const config = JSON.parse(generator.generateXrayConfig({ ...node, aclRules, outbounds: [] }, users, options));
    config.outbounds = config.outbounds.filter(outbound => outbound.tag === 'block');
    const tags = config.inbounds.map(inbound => inbound.tag);
    requireRebuild(tags.every(tag => typeof tag === 'string' && tag.trim() === tag && tag.length > 0), 'REBUILD_INVALID_INBOUND_TAG');
    for (const rule of config.routing.rules) rule.inboundTag = tags.slice();
    // Keep references to the subscriber ACLs only, before API/tunnel rules are added.
    const subscriberDenies = [...config.routing.rules];
    generator.applyXrayApi(config, node.xray?.apiPort ?? 61000);
    return { config, tags, subscriberDenies };
}

function addLinkArtifacts(config, entry, projected, options) {
    const find = mode => entry.incoming.filter(link => link.mode === mode).map(link => projected.get(link.id));
    generator.applyForwardHopInbound(config, find('forward'), { ...options, transitOnly: true });
    generator.applyReverseBridge(config, find('reverse'), null, { ...options, scopeControl: true });
    for (const edge of entry.outgoing) {
        const link = projected.get(edge.id);
        if (edge.mode === 'reverse') generator.applyReversePortal(config, [link], [], options);
        else generator.applyForwardChain(config, [link], [], [], [], options);
    }
    // Xray uses its FIRST outbound for unmatched traffic. The reverse bridge
    // helper prepends dialers in classic profiles; restore fail-closed ordering.
    const block = config.outbounds.findIndex(outbound => outbound.tag === 'block');
    config.outbounds.unshift(...config.outbounds.splice(block, 1));
}

function addSharedPolicy(config, tags, entry, graph) {
    function add(suffix, outboundTag, selector) {
        config.routing.rules.push({ type: 'field', ruleTag: `${REBUILD_POLICY_RULE_PREFIX}${suffix}`,
            inboundTag: tags.slice(), outboundTag, ...selector });
    }
    // In an entirely closed component there is no reason to enable geo DNS
    // resolution. If other exits exist, a dead geo edge blocks its matches.
    if (entry.hasExit) {
        for (const [index, link] of entry.geoLinks.entries()) {
            const tag = graph.byNodeId.get(link.target).hasExit ? egressTag(link) : 'block';
            if (link.domains.length) add(`geo-${index}-domain`, tag, { domain: link.domains });
            if (link.geoip.length) {
                add(`geo-${index}-ip`, tag, { ip: link.geoip });
                config.routing.domainStrategy = 'IPOnDemand';
            }
        }
    }
    add('default', entry.defaultLink ? egressTag(entry.defaultLink) : 'block');
}

function assertListeners(main, bridge) {
    const ports = new Set();
    // The generators use only TCP listeners, either wildcard or loopback.
    // A wildcard also owns the corresponding loopback port across profiles.
    for (const { port } of [...main.inbounds, ...bridge.inbounds]) {
        requireRebuild(validPort(port), 'REBUILD_INVALID_LISTENER');
        requireRebuild(!ports.has(port), 'REBUILD_LISTENER_COLLISION');
        ports.add(port);
    }
    for (const config of [main, bridge]) {
        const inbounds = new Set(config.inbounds.map(inbound => inbound.tag));
        const outbounds = new Set(config.outbounds.map(outbound => outbound.tag));
        requireRebuild(config.reverse?.bridges?.every(bridge => !inbounds.has(bridge.tag)) !== false
            && config.reverse?.portals?.every(portal => !outbounds.has(portal.tag)) !== false, 'REBUILD_TUNNEL_TAG_COLLISION');
    }
}

/** Build owned MAIN/BRIDGE replacements from an explicit desired graph. No I/O. */
function composeRebuildProfiles({ nodes, links, usersByNode = {}, affectedNodeIds, panelTls = {}, followRelayStates = [], controlPlaneAddresses = [] }) {
    requireRebuild(panelTls && typeof panelTls === 'object' && !Array.isArray(panelTls)
        && (panelTls.serverName === undefined || typeof panelTls.serverName === 'string'), 'REBUILD_INVALID_PANEL_TLS');
    const options = { panelTls };
    const graph = compileRebuildGraph({ nodes, links, affectedNodeIds });
    const projected = projectLinks(graph);
    const users = collectUsers(usersByNode);
    const profiles = [];
    for (const [nodeId, entry] of graph.byNodeId) {
        const { config: main, tags, subscriberDenies } = mainProfile(entry.node, users.has(nodeId) ? users.get(nodeId) : [], options);
        const bridge = blackholeProfile();
        const transit = entry.incoming.map(ingressTag);
        if (entry.isExit) {
            bridge.log = generator.buildXrayLogSection(entry.node);
            addLinkArtifacts(bridge, entry, projected, options);
            bridge.outbounds.push({ tag: 'freedom', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' } });
            bridge.routing.rules.push({ type: 'field', ip: ['geoip:private'], inboundTag: transit.slice(), outboundTag: 'block' },
                { type: 'field', inboundTag: transit, outboundTag: 'freedom' });
        } else {
            addLinkArtifacts(main, entry, projected, options);
            // Only generated client and forward-hop inbounds have sniffing.
            // Leave reverse connectors and non-transit client settings alone.
            if (entry.carryDomain) {
                for (const inbound of main.inbounds) {
                    if (inbound.sniffing?.enabled) inbound.sniffing.routeOnly = false;
                }
            }
            addSharedPolicy(main, [...tags, ...transit], entry, graph);
        }
        const installed = followRelayStates.filter(state => rebuildId(state.node) === nodeId);
        if (installed.length) {
            requireRebuild(entry.role === 'relay' && installed.length === 1, 'REBUILD_L2TP_STATE_AMBIGUOUS');
            require('./l2tpFollowRelay').attachLocalFollowRelay({ nodeId, state: installed[0], main, bridge,
                controlPlaneAddresses, carryDomain: entry.carryDomain,
                policy: [...subscriberDenies, ...main.routing.rules.filter(rule => rule.ruleTag?.startsWith(REBUILD_POLICY_RULE_PREFIX))] });
        }
        assertListeners(main, bridge);
        profiles.push({ nodeId, profile: 'main', config: composeXrayConfig(main, []) },
            { nodeId, profile: 'bridge', config: composeXrayConfig(bridge, []) });
    }
    return profiles;
}

module.exports = { composeRebuildProfiles, REBUILD_POLICY_RULE_PREFIX };
