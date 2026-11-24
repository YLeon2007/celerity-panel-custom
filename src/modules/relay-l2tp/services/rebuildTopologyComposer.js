'use strict';

const generator = require('../../../services/configGenerator');
const { tunnelSettings } = require('../../../services/rebuildLinkKeys');
const { tunnelName } = require('../../../services/rebuildTunnelTls');
const { assertRealityFingerprint } = require('../../../services/rebuildRealityFingerprint');
const { reverseObservationEmail } = require('../../../services/rebuildReverseIdentity');
const { CASCADE_TRANSPORTS, isKcpTransport, isKcpSecurity, xrayListenerProtocols } = require('../../../utils/cascadeTransport');
const { compileRebuildGraph, rebuildId, requireRebuild } = require('../domain/rebuildTopologyCompiler');

const REBUILD_POLICY_RULE_PREFIX = 'rebuild-policy-';
const short = entry => entry.id.slice(-8);
const ingressTag = entry => `${entry.mode === 'reverse' ? 'rebuild-rp-ingress' : 'fwd-hop'}-${short(entry)}`;
const egressTag = entry => `${entry.mode === 'reverse' ? 'rebuild-rp-egress' : 'fwd'}-${short(entry)}`;
const validPort = port => Number.isSafeInteger(port) && port > 0 && port <= 65535;
const address = node => typeof node.ip === 'string' && /^\S+$/.test(node.ip);
const encrypted = key => typeof key === 'string' && key.length > 0 && key !== 'none' && !/\s/.test(key);

function projectLinks(graph, options, dialerVersions) {
    const shortIds = new Set();
    const result = new Map();
    for (const entry of graph.byLinkId.values()) {
        const { link, protocol } = entry;
        const reverse = entry.mode === 'reverse';
        const server = graph.byNodeId.get(reverse ? entry.source : entry.target).node;
        const security = link.tunnelSecurity ?? 'none';
        const transport = link.tunnelTransport ?? 'tcp';
        const { tunnelEncryption = 'vless-enc' } = link;
        const port = link.tunnelPort;
        const id = link.tunnelUuid;
        let wire = security === 'tls' ? { ...link, tlsServerName: tunnelName(link) } : link;
        requireRebuild(address(server), 'REBUILD_INVALID_NODE_ADDRESS');
        requireRebuild(validPort(port) && typeof id === 'string' && /^\S+$/.test(id)
            && ['none', 'tls', 'reality'].includes(security)
            && ['vless-enc', 'none'].includes(tunnelEncryption)
            && CASCADE_TRANSPORTS.includes(transport)
            && (!isKcpTransport(transport) || isKcpSecurity(security)), 'REBUILD_INVALID_TUNNEL');
        if (security === 'reality') {
            const dialerVersion = dialerVersions?.get(reverse ? entry.target : entry.source);
            const fingerprint = assertRealityFingerprint({ mode: entry.mode, portalNode: entry.source,
                bridgeNode: entry.target, realityFingerprint: link.realityFingerprint }, dialerVersion);
            wire = { ...link, realityFingerprint: fingerprint };
            requireRebuild(typeof link.realityPrivateKey === 'string' && link.realityPrivateKey.length > 0
                && typeof link.realityPublicKey === 'string' && link.realityPublicKey.length > 0, 'REBUILD_INVALID_TUNNEL');
        }
        requireRebuild(!shortIds.has(short(entry)), 'REBUILD_TUNNEL_TAG_COLLISION');
        shortIds.add(short(entry));

        let decryption = 'none';
        let encryption = 'none';
        if (protocol === 'vless' && security === 'none' && tunnelEncryption === 'vless-enc') {
            const keys = tunnelSettings(link);
            decryption = keys?.decryption;
            encryption = keys?.encryption;
            requireRebuild(encrypted(decryption) && encrypted(encryption), 'REBUILD_INVALID_TUNNEL_KEY_SETTINGS');
        }

        // Xray creates the source-side outbound and the target-side inbound
        // from these reverse tags. There is no legacy control-domain route.
        const client = { id, ...(reverse ? { reverse: { tag: egressTag(entry) } } : {}) };
        if (reverse && protocol === 'vless' && security === 'reality' && (link.tunnelTransport ?? 'tcp') === 'tcp') {
            const email = reverseObservationEmail(entry.id, id);
            if (email) client.email = email;
        }
        const endpoint = { address: server.ip, port };
        const dialUser = protocol === 'vmess' ? { id, alterId: 0, security: 'auto' } : { id, encryption };
        const dialSettings = reverse
            ? { ...endpoint, ...dialUser, reverse: { tag: ingressTag(entry) } }
            : { vnext: [{ ...endpoint, users: [dialUser] }] };
        result.set(entry.id, {
            listener: {
                tag: reverse ? `rebuild-rp-conn-${short(entry)}` : ingressTag(entry),
                listen: '0.0.0.0', port, protocol,
                settings: { clients: [client], ...(protocol === 'vless' ? { decryption } : {}) },
                streamSettings: generator.buildCascadeTunnelStreamSettings(wire, { ...options, server: true }),
                ...(!reverse ? { sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true } } : {}),
            },
            dialer: {
                tag: reverse ? `rebuild-rp-dial-${short(entry)}` : egressTag(entry),
                protocol, settings: dialSettings,
                streamSettings: generator.buildCascadeTunnelStreamSettings(wire, { ...options, rebuildTunnel: true }),
                ...(!reverse && link.muxEnabled ? { mux: { enabled: true, concurrency: link.muxConcurrency || 8 } } : {}),
            },
        });
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

function mainProfile({ node, role }, users, options, hasClientInbound) {
    requireRebuild(node.type === 'xray' && (node.port === undefined || validPort(node.port))
        && (node.xray?.apiPort === undefined || validPort(node.xray.apiPort)), 'REBUILD_INVALID_NODE_CONFIG');
    requireRebuild(Array.isArray(users) && users.every(user => typeof user?.xrayUuid === 'string' && /^\S+$/.test(user.xrayUuid)
        && typeof user.userId === 'string' && user.userId.length > 0), 'REBUILD_INVALID_USERS');
    const apiPort = node.xray?.apiPort ?? 61000;
    // Classic exit-only setup does not provision client inbounds or REALITY keys.
    // Keep MAIN available for local management without opening a subscriber port.
    if (role === 'bridge' && users.length === 0 && !hasClientInbound) {
        const config = blackholeProfile();
        config.log = generator.buildXrayLogSection(node);
        generator.applyXrayApi(config, apiPort);
        return { config, tags: [], subscriberDenies: [] };
    }
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
    generator.applyXrayApi(config, apiPort, { statsUserOnline: generator.hasXrayMainClientRole(node, role) });
    return { config, tags, subscriberDenies };
}

function addLinkArtifacts(config, entry, projected) {
    // A reverse edge switches which endpoint dials, not the payload direction.
    // Append only: Xray falls back to the first outbound (blackhole).
    for (const edge of entry.incoming) {
        const { listener, dialer } = projected.get(edge.id);
        if (edge.mode === 'reverse') config.outbounds.push(dialer);
        else config.inbounds.push(listener);
    }
    for (const edge of entry.outgoing) {
        const { listener, dialer } = projected.get(edge.id);
        if (edge.mode === 'reverse') config.inbounds.push(listener);
        else config.outbounds.push(dialer);
    }
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

function assertProfileOwnership(main, bridge) {
    const sockets = new Set();
    // Generated listeners are wildcard or loopback, so the wildcard owns the
    // corresponding loopback socket even across MAIN and BRIDGE processes.
    for (const inbound of [...main.inbounds, ...bridge.inbounds]) {
        const protocols = xrayListenerProtocols(inbound);
        requireRebuild(validPort(inbound.port) && protocols.length, 'REBUILD_INVALID_LISTENER');
        for (const protocol of protocols) {
            const socket = `${protocol}:${inbound.port}`;
            requireRebuild(!sockets.has(socket), 'REBUILD_LISTENER_COLLISION');
            sockets.add(socket);
        }
    }
    for (const config of [main, bridge]) {
        const inbounds = new Set(config.inbounds.map(inbound => inbound.tag));
        const outbounds = new Set(config.outbounds.map(outbound => outbound.tag));
        const reverseIngress = config.outbounds.map(outbound => outbound.settings?.reverse?.tag).filter(Boolean);
        const reverseEgress = config.inbounds.flatMap(inbound => (inbound.settings?.clients ?? [])
            .map(client => client.reverse?.tag).filter(Boolean));
        requireRebuild(reverseIngress.every(tag => !inbounds.has(tag))
            && reverseEgress.every(tag => !outbounds.has(tag)), 'REBUILD_TUNNEL_TAG_COLLISION');
        requireRebuild(inbounds.size === config.inbounds.length, 'DUPLICATE_INBOUND_TAG');
        requireRebuild(outbounds.size === config.outbounds.length, 'DUPLICATE_OUTBOUND_TAG');
    }
}

/** Build owned MAIN/BRIDGE replacements from an explicit desired graph. No I/O. */
function composeRebuildProfiles({ nodes, links, dialerVersions, usersByNode = {}, bridgesWithClientInbound = new Set(), affectedNodeIds, panelTls = {}, followRelayStates = [], controlPlaneAddresses = [] }) {
    requireRebuild(panelTls && typeof panelTls === 'object' && !Array.isArray(panelTls)
        && (panelTls.serverName === undefined || typeof panelTls.serverName === 'string'), 'REBUILD_INVALID_PANEL_TLS');
    const options = { panelTls };
    const graph = compileRebuildGraph({ nodes, links, affectedNodeIds });
    const projected = projectLinks(graph, options, dialerVersions);
    const users = collectUsers(usersByNode);
    const profiles = [];
    for (const [nodeId, entry] of graph.byNodeId) {
        const { config: main, tags, subscriberDenies } = mainProfile(entry, users.has(nodeId) ? users.get(nodeId) : [], options, bridgesWithClientInbound.has(nodeId));
        const bridge = blackholeProfile();
        const transit = entry.incoming.map(ingressTag);
        if (entry.isExit) {
            bridge.log = generator.buildXrayLogSection(entry.node);
            addLinkArtifacts(bridge, entry, projected);
            // Native VLESS reverse defaults to deny-all at the final dial on newer Xray cores.
            bridge.outbounds.push({ tag: 'freedom', protocol: 'freedom', settings: {
                domainStrategy: 'UseIPv4',
                finalRules: [{ action: 'block', ip: ['geoip:private'] }, { action: 'allow' }],
            } });
            bridge.routing.rules.push({ type: 'field', ip: ['geoip:private'], inboundTag: transit.slice(), outboundTag: 'block' },
                { type: 'field', inboundTag: transit, outboundTag: 'freedom' });
        } else {
            addLinkArtifacts(main, entry, projected);
            // Only generated client and forward-hop inbounds have sniffing.
            // Leave reverse connectors and non-transit client settings alone.
            if (entry.carryDomain) {
                for (const inbound of main.inbounds) {
                    if (inbound.sniffing?.enabled) inbound.sniffing.routeOnly = false;
                }
            }
            if (tags.length || transit.length) addSharedPolicy(main, [...tags, ...transit], entry, graph);
        }
        const installed = followRelayStates.filter(state => rebuildId(state.node) === nodeId);
        if (installed.length) {
            requireRebuild(entry.role === 'relay' && installed.length === 1, 'REBUILD_L2TP_STATE_AMBIGUOUS');
            require('./l2tpFollowRelay').attachLocalFollowRelay({ nodeId, state: installed[0], main, bridge,
                controlPlaneAddresses, carryDomain: entry.carryDomain,
                policy: [...subscriberDenies, ...main.routing.rules.filter(rule => rule.ruleTag?.startsWith(REBUILD_POLICY_RULE_PREFIX))] });
        }
        assertProfileOwnership(main, bridge);
        // These are complete generated profiles, not fragment merges. Their
        // ownership check above knows the socket protocol, unlike the classic
        // fragment composer's address/port-only duplicate check.
        profiles.push({ nodeId, profile: 'main', config: structuredClone(main) },
            { nodeId, profile: 'bridge', config: structuredClone(bridge) });
    }
    return profiles;
}

module.exports = { composeRebuildProfiles, REBUILD_POLICY_RULE_PREFIX, egressTag };
