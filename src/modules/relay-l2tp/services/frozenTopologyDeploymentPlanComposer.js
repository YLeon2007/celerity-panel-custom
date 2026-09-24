'use strict';

const { createHash } = require('node:crypto');
const configGenerator = require('../../../services/configGenerator');
const { composeXrayConfig } = require('./xrayConfigComposer');
const {
    cascadePathIngressPort,
} = require('../domain/cascadePathIngress');

const XRAY_CONFIG_FIELDS = Object.freeze([
    'apiPort',
    'inboundTag',
    'transport',
    'security',
    'flow',
    'alpn',
    'realityDest',
    'realitySni',
    'realityPrivateKey',
    'realityShortIds',
    'realitySpiderX',
    'wsPath',
    'wsHost',
    'grpcServiceName',
    'xhttpPath',
    'xhttpHost',
    'xhttpMode',
    'fallbackDest',
    'tlsSource',
    'manualCert',
    'manualKey',
]);
const EXTRA_INBOUND_FIELDS = Object.freeze([
    'id',
    'label',
    'uniqueName',
    'port',
    'inboundTag',
    'transport',
    'security',
    'flow',
    'alpn',
    'realityDest',
    'realitySni',
    'realityPrivateKey',
    'realityShortIds',
    'realitySpiderX',
    'wsPath',
    'wsHost',
    'grpcServiceName',
    'xhttpPath',
    'xhttpHost',
    'xhttpMode',
    'fallbackDest',
]);
const LINK_CONFIG_FIELDS = Object.freeze([
    'tunnelDomain',
    'tunnelProtocol',
    'tunnelSecurity',
    'tunnelTransport',
    'tcpFastOpen',
    'tcpKeepAlive',
    'tcpNoDelay',
    'wsPath',
    'wsHost',
    'grpcServiceName',
    'xhttpPath',
    'xhttpHost',
    'xhttpMode',
    'tlsServerName',
    'muxEnabled',
    'muxConcurrency',
    'realityDest',
    'realitySni',
    'realityPrivateKey',
    'realityPublicKey',
    'realityShortIds',
    'realityFingerprint',
]);

const TARGETS_BY_ROLE = Object.freeze({
    portal: Object.freeze({
        targetProfile: 'xray-main',
        serviceUnit: 'xray.service',
        serviceUnitPath: '/etc/systemd/system/xray.service',
        configPath: '/usr/local/etc/xray/config.json',
    }),
    relay: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
    bridge: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
});

class FrozenTopologyDeploymentPlanError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'FrozenTopologyDeploymentPlanError';
        this.code = code;
        Object.assign(this, details);
    }
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity.id ?? entity._id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
}

function uniqueById(items, kind) {
    const byId = new Map();
    for (const item of items || []) {
        const id = entityId(item);
        if (!id) {
            throw new FrozenTopologyDeploymentPlanError(
                `MISSING_${kind}_ID`,
                `${kind.toLowerCase()} metadata requires an id`,
            );
        }
        if (byId.has(id)) {
            throw new FrozenTopologyDeploymentPlanError(
                `DUPLICATE_${kind}_ID`,
                `${kind.toLowerCase()} metadata ids must be unique`,
            );
        }
        byId.set(id, item);
    }
    return byId;
}

function orderedChain(snapshot, geoLeafLinkIds = new Set()) {
    if (!snapshot || !Array.isArray(snapshot.nodes) || !Array.isArray(snapshot.links)) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_TOPOLOGY_SNAPSHOT',
            'A validated topology snapshot with nodes and links is required',
        );
    }

    const nodesById = uniqueById(snapshot.nodes, 'NODE');
    const linksById = uniqueById(snapshot.links, 'LINK');
    const roles = { portal: [], relay: [], bridge: [] };
    for (const [id, node] of nodesById) {
        if (!Object.hasOwn(TARGETS_BY_ROLE, node.role)) {
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_NODE_ROLE',
                'Every topology node requires a supported role',
            );
        }
        roles[node.role].push(id);
    }
    if (roles.portal.length !== 1 || roles.bridge.length < 1) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_TOPOLOGY_ROLES',
            'Topology requires exactly one portal and at least one bridge',
        );
    }

    const outgoing = new Map();
    const incoming = new Map();
    const geoOutgoing = new Map();
    const geoIncoming = new Map();
    let mode = null;
    for (const [id, link] of linksById) {
        const source = entityId(link.source ?? link.portalNode);
        const target = entityId(link.target ?? link.bridgeNode);
        if (!source || !target || !nodesById.has(source) || !nodesById.has(target)) {
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_TOPOLOGY_LINK_ENDPOINT',
                'Every topology link requires known source and target nodes',
            );
        }
        if (link.mode !== 'forward' && link.mode !== 'reverse') {
            throw new FrozenTopologyDeploymentPlanError(
                'UNSUPPORTED_TOPOLOGY_MODE',
                'Topology v1 supports only forward or reverse links',
            );
        }
        if (mode !== null && mode !== link.mode) {
            throw new FrozenTopologyDeploymentPlanError(
                'MIXED_TOPOLOGY_MODES',
                'Topology v1 does not support mixed link modes',
            );
        }
        mode = link.mode;
        const entry = { id, link, source, target };
        if (geoLeafLinkIds.has(id)) {
            // Geo-routing leaf: must hang off a main-chain node and terminate
            // at a dedicated bridge that carries no other link.
            if (geoOutgoing.has(source) && geoOutgoing.get(source).has(id)) {
                throw new FrozenTopologyDeploymentPlanError(
                    'NON_LINEAR_TOPOLOGY',
                    'Duplicate geo-routing branch link',
                );
            }
            if (!geoOutgoing.has(source)) geoOutgoing.set(source, new Map());
            geoOutgoing.get(source).set(id, entry);
            if (geoIncoming.has(target) || incoming.has(target)) {
                throw new FrozenTopologyDeploymentPlanError(
                    'GEO_LEAF_TARGET_CONFLICT',
                    'A geo-routing branch must terminate at its own dedicated bridge',
                );
            }
            geoIncoming.set(target, entry);
            continue;
        }
        if (outgoing.has(source) || incoming.has(target)) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Topology allows one linear main chain; additional bridges require geoRouting',
            );
        }
        outgoing.set(source, entry);
        incoming.set(target, entry);
    }

    const orderedNodes = [];
    const orderedLinks = [];
    const visited = new Set();
    let currentId = roles.portal[0];
    while (currentId) {
        if (visited.has(currentId)) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Topology v1 requires an acyclic linear chain',
            );
        }
        visited.add(currentId);
        orderedNodes.push({ id: currentId, node: nodesById.get(currentId) });
        const next = outgoing.get(currentId);
        if (!next) break;
        orderedLinks.push(next);
        currentId = next.target;
    }

    const mainNodeIds = new Set(orderedNodes.map(entry => entry.id));
    if (orderedNodes.length === 0 || orderedLinks.length !== outgoing.size) {
        throw new FrozenTopologyDeploymentPlanError(
            'MISSING_TOPOLOGY_LINK',
            'Topology requires one link between every adjacent main-chain node',
        );
    }
    if (
        orderedNodes.at(-1).node.role !== 'bridge'
        || orderedNodes[0].node.role !== 'portal'
        || orderedNodes.slice(1, -1).some(entry => entry.node.role !== 'relay')
    ) {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'Topology must form a linear Portal to Relay to Bridge main chain',
        );
    }

    // Every remaining node must be a dedicated geo-bridge leaf; every geo leaf
    // must be attached to the main chain and terminate at such a node.
    const geoLeafNodes = [];
    for (const [id, node] of nodesById) {
        if (mainNodeIds.has(id)) continue;
        if (node.role !== 'bridge') {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Nodes outside the main chain must be geo-routing bridges',
            );
        }
        const leaf = geoIncoming.get(id);
        if (!leaf) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Every bridge outside the main chain requires an incoming geoRouting link',
            );
        }
        if (!mainNodeIds.has(leaf.source)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_SOURCE_OUTSIDE_CHAIN',
                'A geo-routing branch must start from a main-chain node',
            );
        }
        if (outgoing.has(id) || geoOutgoing.has(id)) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'A geo-routing bridge must be a leaf (no outgoing links)',
            );
        }
        geoLeafNodes.push({ id, node, link: leaf });
    }
    for (const [id, entry] of geoIncoming) {
        if (!mainNodeIds.has(entry.source)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_SOURCE_OUTSIDE_CHAIN',
                'A geo-routing branch must start from a main-chain node',
            );
        }
        if (mainNodeIds.has(id)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_TARGET_CONFLICT',
                'A geo-routing branch cannot terminate inside the main chain',
            );
        }
    }
    // Multiple default bridges: a bridge inside the main chain is unique by
    // construction (incoming/outgoing uniqueness), so no extra check needed.
    geoLeafNodes.sort((left, right) => left.id.localeCompare(right.id, 'en'));

    return { mode, orderedNodes, orderedLinks, geoLeafNodes };
}

function topologyRefs(orderedNodes, geoLeafNodes = []) {
    let relayIndex = 0;
    const refs = new Map(orderedNodes.map(({ id, node }) => {
        let ref = node.role;
        if (node.role === 'relay') ref = `relay-${++relayIndex}`;
        return [id, ref];
    }));
    // Geo-routing bridges get deterministic suffixed refs; the main-chain
    // (default) bridge keeps the plain 'bridge' ref.
    let bridgeIndex = 1;
    for (const { id } of geoLeafNodes) {
        refs.set(id, `bridge-${++bridgeIndex}`);
    }
    return refs;
}

function assertPort(value) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 65535) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_TUNNEL_PORT',
            'Every hydrated topology link requires a valid tunnel port',
        );
    }
    return value;
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cloneAllowed(source, fields) {
    const projected = {};
    if (!isPlainObject(source)) return projected;
    for (const field of fields) {
        if (source[field] !== undefined) projected[field] = structuredClone(source[field]);
    }
    return projected;
}

function projectXrayConfig(metadata) {
    const source = isPlainObject(metadata?.xray) ? metadata.xray : {};
    const xray = cloneAllowed(source, XRAY_CONFIG_FIELDS);
    xray.accessLogs = { enabled: source.accessLogs?.enabled === true };
    xray.extraInbounds = Array.isArray(source.extraInbounds)
        ? source.extraInbounds.map(inbound => cloneAllowed(inbound, EXTRA_INBOUND_FIELDS))
        : [];
    return xray;
}

function projectNodeConfig(metadata, node, nodeRef) {
    if (metadata?.type !== 'xray' || metadata?.active !== true) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_NODE_CONFIG',
            'Every topology node requires active Xray server configuration',
        );
    }
    if (typeof metadata.ip !== 'string' || metadata.ip.length === 0 || /\s/.test(metadata.ip)) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_NODE_CONFIG',
            'Every topology node requires a valid Xray server address',
        );
    }
    return {
        _id: nodeRef,
        type: 'xray',
        active: true,
        cascadeRole: node.role,
        ip: metadata.ip,
        ...(typeof metadata.domain === 'string' ? { domain: metadata.domain } : {}),
        ...(typeof metadata.sni === 'string' ? { sni: metadata.sni } : {}),
        ...(metadata.port === undefined ? {} : { port: assertPort(metadata.port) }),
        xray: projectXrayConfig(metadata),
    };
}

function deterministicTunnelUuid(linkIdentity) {
    // Stored tunnel credentials are deliberately not materialized. Both ends
    // instead receive the same candidate-local UUID derived from the frozen
    // link identity, so the complete config remains restart-deterministic.
    const hex = createHash('sha256')
        .update(`celerity-topology-v1:${linkIdentity}`)
        .digest('hex')
        .slice(0, 32)
        .split('');
    hex[12] = '5';
    hex[16] = ['8', '9', 'a', 'b'][Number.parseInt(hex[16], 16) % 4];
    return [
        hex.slice(0, 8).join(''),
        hex.slice(8, 12).join(''),
        hex.slice(12, 16).join(''),
        hex.slice(16, 20).join(''),
        hex.slice(20).join(''),
    ].join('-');
}

const GEOIP_TAG_RE = /^[a-z0-9-]+$/;

function sanitizeGeoipTag(value) {
    const tag = String(value).trim().toLowerCase();
    return GEOIP_TAG_RE.test(tag) ? tag : null;
}

function projectGeoRouting(metadata) {
    const source = metadata?.geoRouting;
    if (!isPlainObject(source)) return undefined;
    return {
        enabled: source.enabled === true,
        domains: Array.isArray(source.domains)
            ? source.domains.filter(value => typeof value === 'string')
            : [],
        // Drop tags Xray cannot resolve (e.g. Cyrillic "рф") instead of
        // poisoning the generated config with an unknown geoip file lookup.
        geoip: Array.isArray(source.geoip)
            ? source.geoip.map(sanitizeGeoipTag).filter(Boolean)
            : [],
    };
}

function projectCascadeLink(entry, index, metadata, nodeConfigsById) {
    const linkRef = `link-${index + 1}`;
    const projected = {
        _id: linkRef,
        portalNode: nodeConfigsById.get(entry.source),
        bridgeNode: nodeConfigsById.get(entry.target),
        tunnelUuid: deterministicTunnelUuid(entry.id),
        tunnelPort: assertPort(metadata.tunnelPort),
        ...cloneAllowed(metadata, LINK_CONFIG_FIELDS),
    };
    const geoRouting = projectGeoRouting(metadata);
    if (geoRouting) projected.geoRouting = geoRouting;
    return projected;
}

function parseGeneratedConfig(generated) {
    const config = typeof generated === 'string' ? JSON.parse(generated) : structuredClone(generated);
    if (!isPlainObject(config)
        || !Array.isArray(config.inbounds)
        || !Array.isArray(config.outbounds)
        || !isPlainObject(config.routing)
        || !Array.isArray(config.routing.rules)) {
        throw new TypeError('Invalid generated Xray configuration');
    }
    return config;
}

function clientInboundTags(nodeConfig) {
    return [
        nodeConfig.xray.inboundTag || 'vless-in',
        ...nodeConfig.xray.extraInbounds.map(inbound => inbound.inboundTag).filter(Boolean),
    ];
}

function composeBaselineWithCascade(baseline, cascade) {
    const config = composeXrayConfig(baseline, [{
        id: 'topology-cascade',
        inbounds: cascade.inbounds || [],
        outbounds: cascade.outbounds || [],
        routingRules: cascade.routing.rules,
    }]);
    if (cascade.reverse !== undefined) config.reverse = structuredClone(cascade.reverse);
    if (cascade.routing.balancers !== undefined) {
        config.routing.balancers = structuredClone(cascade.routing.balancers);
    }
    return config;
}

// Every enabled path of every route group whose subchain crosses this relay's
// downstream link gets a deterministic loopback socks ingress on the relay.
// Disabled paths stay without ingress; ordering is normalized so frozen
// candidates are permutation-stable.
function relayPathIngress(groups, downstreamLinkId, egressTag) {
    const entries = [];
    for (const group of groups || []) {
        const groupId = entityId(group);
        if (!groupId || !Array.isArray(group.paths)) continue;
        for (const path of group.paths) {
            if (path?.enabled === false) continue;
            if (typeof path?.pathKey !== 'string' || path.pathKey.length === 0) continue;
            const linkIds = (Array.isArray(path.linkIds) ? path.linkIds : []).map(entityId);
            if (!linkIds.includes(downstreamLinkId)) continue;
            entries.push({
                pathKey: path.pathKey,
                port: cascadePathIngressPort(groupId, path.pathKey),
                ...(egressTag === undefined ? {} : { egressTag }),
            });
        }
    }
    entries.sort((left, right) => (
        left.pathKey.localeCompare(right.pathKey, 'en') || left.port - right.port
    ));
    return entries;
}

function buildCandidateConfigs({ chain, refs, nodeMetadataById, linkMetadataById, groups = [] }) {
    const geoLeafNodes = chain.geoLeafNodes || [];
    const geoLeavesBySource = new Map();
    for (const leaf of geoLeafNodes) {
        const list = geoLeavesBySource.get(leaf.link.source) || [];
        list.push(leaf);
        geoLeavesBySource.set(leaf.link.source, list);
    }
    const allChainNodes = [...chain.orderedNodes, ...geoLeafNodes];
    const nodeConfigsById = new Map(allChainNodes.map(({ id, node }) => [
        id,
        projectNodeConfig(nodeMetadataById.get(id), node, refs.get(id)),
    ]));
    const links = chain.orderedLinks.map((entry, index) => projectCascadeLink(
        entry,
        index,
        linkMetadataById.get(entry.id),
        nodeConfigsById,
    ));
    const geoLinks = geoLeafNodes.map((leaf, index) => projectCascadeLink(
        leaf.link,
        chain.orderedLinks.length + index,
        linkMetadataById.get(leaf.link.id),
        nodeConfigsById,
    ));
    const geoLinksBySource = new Map();
    for (let index = 0; index < geoLeafNodes.length; index += 1) {
        const source = geoLeafNodes[index].link.source;
        const list = geoLinksBySource.get(source) || [];
        list.push(geoLinks[index]);
        geoLinksBySource.set(source, list);
    }
    const configs = new Map();
    const ingressByNodeId = new Map();

    for (let index = 0; index < chain.orderedNodes.length; index += 1) {
        const { id, node } = chain.orderedNodes[index];
        const nodeConfig = nodeConfigsById.get(id);
        let config = parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, []));

        if (node.role === 'portal') {
            // The portal keeps the panel management API on its xray-main profile.
            configGenerator.applyXrayApi(config, nodeConfig.xray.apiPort || 61000);
        }

        // Forward chains originate every outbound at the portal (geo branches
        // included); reverse chains attach geo branches at their source node.
        const geoBranches = chain.mode === 'forward'
            ? (node.role === 'portal' ? geoLinks : [])
            : (geoLinksBySource.get(id) || []);

        if (chain.mode === 'forward') {
            if (node.role === 'portal') {
                // Geo branches chain through the main-chain prefix up to their
                // source node: the outbound targeting that node acts as the
                // transport-layer proxy for the geo-leaf outbound.
                const branches = geoBranches.map(geoLink => {
                    const leaf = geoLeafNodes[geoLinks.indexOf(geoLink)];
                    const prefixIndex = chain.orderedLinks.findIndex(
                        entry => entry.target === leaf.link.source,
                    );
                    return {
                        link: geoLink,
                        viaTag: prefixIndex >= 0
                            ? `fwd-${String(links[prefixIndex]._id).slice(-8)}`
                            : null,
                    };
                });
                configGenerator.applyForwardChain(config, links, clientInboundTags(nodeConfig), [], branches);
            } else {
                configGenerator.applyForwardHopInbound(config, [links[index - 1]]);
                if (node.role === 'relay') {
                    const ingress = relayPathIngress(groups, chain.orderedLinks[index].id);
                    if (ingress.length > 0) {
                        // Chain the per-path socks ingress to the suffix exit.
                        configGenerator.applyForwardChain(config, links.slice(index), [], ingress);
                        ingressByNodeId.set(id, ingress);
                    }
                }
            }
        } else if (node.role === 'portal') {
            configGenerator.applyReversePortal(config, [links[index], ...geoBranches], clientInboundTags(nodeConfig));
        } else if (node.role === 'relay') {
            // Relay reverse candidates are pure cascade configs: the baseline
            // is intentionally not composed in, so the bridge profile never
            // binds the panel API port alongside the relay xray-main instance.
            const ingress = relayPathIngress(
                groups,
                chain.orderedLinks[index].id,
                `portal-down-${String(links[index]._id).slice(-8)}`,
            );
            if (ingress.length > 0) ingressByNodeId.set(id, ingress);
            config = parseGeneratedConfig(configGenerator.generateRelayConfigWithIngress(
                links[index - 1],
                links[index - 1].portalNode,
                [links[index], ...geoBranches],
                ingress,
            ));
        } else {
            const cascade = JSON.parse(configGenerator.generateCombinedBridgeConfig([links[index - 1]]));
            cascade.inbounds = cascade.inbounds || [];
            config = composeBaselineWithCascade(config, parseGeneratedConfig(cascade));
        }
        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(id, config);
    }

    // Geo-routing bridges are configured exactly like the default bridge,
    // each with its single upstream geo link.
    for (let index = 0; index < geoLeafNodes.length; index += 1) {
        const { id, node } = geoLeafNodes[index];
        const nodeConfig = nodeConfigsById.get(id);
        let config = parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, []));
        if (chain.mode === 'forward') {
            configGenerator.applyForwardHopInbound(config, [geoLinks[index]]);
        } else {
            const cascade = JSON.parse(configGenerator.generateCombinedBridgeConfig([geoLinks[index]]));
            cascade.inbounds = cascade.inbounds || [];
            config = composeBaselineWithCascade(config, parseGeneratedConfig(cascade));
        }
        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(id, config);
    }
    return { configs, ingressByNodeId };
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!isPlainObject(value)) return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalize(value[key])]),
    );
}

function candidateForNode({ mode, nodeId, node, nodeRef, orderedLinks, linkMetadataById, config, ingressPorts = [] }) {
    const target = TARGETS_BY_ROLE[node.role];
    const listeningPorts = [...new Set([
        ...orderedLinks
            .filter(entry => (mode === 'reverse' ? entry.source : entry.target) === nodeId)
            .map(entry => assertPort(linkMetadataById.get(entry.id).tunnelPort)),
        ...ingressPorts,
    ])].sort((left, right) => left - right);
    const checks = [
        { type: 'service', serviceUnit: target.serviceUnit, expectedState: 'active' },
        ...listeningPorts.map(port => ({
            type: 'port',
            protocol: 'tcp',
            port,
            expectedState: 'listening',
        })),
    ];
    const bytes = Buffer.from(`${JSON.stringify(canonicalize(config))}\n`, 'utf8');

    return {
        nodeRef,
        role: node.role,
        ...target,
        candidate: {
            mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
            bytes: [...bytes],
            sha256: createHash('sha256').update(bytes).digest('hex'),
        },
        checks,
    };
}

function composeFrozenTopologyDeploymentPlan({
    snapshot,
    nodeMetadata = [],
    linkMetadata = [],
    compiledTopology,
} = {}) {
    if (compiledTopology?.valid !== true || !Array.isArray(compiledTopology.relays)) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_COMPILED_TOPOLOGY',
            'A valid compiled topology is required',
        );
    }
    const nodeMetadataById = uniqueById(nodeMetadata, 'NODE_METADATA');
    const linkMetadataById = uniqueById(linkMetadata, 'LINK_METADATA');

    // Classify geo-routing leaf links BEFORE walking the chain: a link with
    // enabled geoRouting and at least one valid rule branches off the main
    // chain towards its own dedicated bridge. Links on the main chain must
    // not carry geo rules.
    const geoLeafLinkIds = new Set();
    const geoRuleOwner = new Map();
    for (const link of snapshot.links) {
        const linkId = entityId(link);
        const metadata = linkMetadataById.get(linkId);
        if (!metadata) {
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_LINK_METADATA',
                'Every topology link requires hydrated metadata',
            );
        }
        const geo = projectGeoRouting(metadata);
        if (!geo || geo.enabled !== true) continue;
        if (geo.domains.length === 0 && geo.geoip.length === 0) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_WITHOUT_RULES',
                'A geo-routing link requires at least one valid domain or geoip rule',
            );
        }
        for (const rule of [
            ...geo.domains.map(value => `domain:${value}`),
            ...geo.geoip.map(value => `geoip:${value}`),
        ]) {
            const owner = geoRuleOwner.get(rule);
            if (owner && owner !== linkId) {
                throw new FrozenTopologyDeploymentPlanError(
                    'DUPLICATE_GEO_RULE',
                    'Geo-routing rules must be unique across links',
                );
            }
            geoRuleOwner.set(rule, linkId);
        }
        geoLeafLinkIds.add(linkId);
    }

    const chain = orderedChain(snapshot, geoLeafLinkIds);
    const roleByNodeId = new Map(
        [...chain.orderedNodes, ...chain.geoLeafNodes].map(({ id, node }) => [id, node.role]),
    );
    const compiledRelayIds = new Set();
    for (const relay of compiledTopology.relays) {
        const relayId = entityId(relay?.nodeId);
        if (!relayId || roleByNodeId.get(relayId) !== 'relay' || compiledRelayIds.has(relayId)) {
            throw new FrozenTopologyDeploymentPlanError(
                'COMPILED_TOPOLOGY_MISMATCH',
                'Compiled relay data must belong to the frozen topology',
            );
        }
        compiledRelayIds.add(relayId);
    }

    for (const { id, node } of [...chain.orderedNodes, ...chain.geoLeafNodes]) {
        const metadata = nodeMetadataById.get(id);
        if (!metadata) {
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_NODE_METADATA',
                'Every topology node requires hydrated metadata',
            );
        }
        if (metadata.role !== undefined && metadata.role !== node.role) {
            throw new FrozenTopologyDeploymentPlanError(
                'NODE_ROLE_MISMATCH',
                'Hydrated node role must match the validated topology snapshot',
            );
        }
    }
    const allLinkEntries = [
        ...chain.orderedLinks,
        ...chain.geoLeafNodes.map(leaf => leaf.link),
    ];
    for (const { id, link, source, target } of allLinkEntries) {
        const metadata = linkMetadataById.get(id);
        const metadataSource = metadata.source === undefined && metadata.portalNode === undefined
            ? source
            : entityId(metadata.source ?? metadata.portalNode);
        const metadataTarget = metadata.target === undefined && metadata.bridgeNode === undefined
            ? target
            : entityId(metadata.target ?? metadata.bridgeNode);
        const metadataMode = metadata.mode === undefined ? link.mode : metadata.mode;
        if (metadataSource !== source || metadataTarget !== target || metadataMode !== link.mode) {
            throw new FrozenTopologyDeploymentPlanError(
                'LINK_METADATA_MISMATCH',
                'Hydrated link metadata must match the validated topology snapshot',
            );
        }
    }
    // Main-chain links must not carry geo rules: branching is allowed only
    // from a chain node towards a dedicated geo bridge.
    for (const entry of chain.orderedLinks) {
        if (geoLeafLinkIds.has(entry.id)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_RULES_ON_MAIN_CHAIN',
                'Geo-routing rules are allowed only on branch links to dedicated bridges',
            );
        }
    }

    const refs = topologyRefs(chain.orderedNodes, chain.geoLeafNodes);
    let candidateConfigsById;
    let ingressByNodeId;
    try {
        ({ configs: candidateConfigsById, ingressByNodeId } = buildCandidateConfigs({
            chain,
            refs,
            nodeMetadataById,
            linkMetadataById,
            groups: snapshot.groups,
        }));
    } catch (error) {
        if (error instanceof FrozenTopologyDeploymentPlanError) throw error;
        throw new FrozenTopologyDeploymentPlanError(
            'XRAY_CONFIG_GENERATION_FAILED',
            'Failed to generate a frozen Xray topology candidate',
        );
    }
    // Deployment order keeps endpoints first for forward chains (bridges
    // before their upstream) and source-first for reverse chains; geo bridges
    // deploy alongside the default bridge.
    const deploymentOrder = chain.mode === 'forward'
        ? [...chain.geoLeafNodes, ...[...chain.orderedNodes].reverse()]
        : [...chain.orderedNodes, ...chain.geoLeafNodes];
    const nodes = deploymentOrder.map(({ id, node }) => candidateForNode({
        mode: chain.mode,
        nodeId: id,
        node,
        nodeRef: refs.get(id),
        orderedLinks: allLinkEntries,
        linkMetadataById,
        config: candidateConfigsById.get(id),
        ingressPorts: (ingressByNodeId.get(id) || []).map(entry => entry.port),
    }));

    return deepFreeze({
        schemaVersion: 1,
        mode: chain.mode,
        nodes,
    });
}

module.exports = {
    FrozenTopologyDeploymentPlanError,
    TARGETS_BY_ROLE,
    composeFrozenTopologyDeploymentPlan,
};
