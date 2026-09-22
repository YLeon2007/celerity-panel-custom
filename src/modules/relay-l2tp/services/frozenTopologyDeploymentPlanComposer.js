'use strict';

const { createHash } = require('node:crypto');
const configGenerator = require('../../../services/configGenerator');
const { composeXrayConfig } = require('./xrayConfigComposer');

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

function orderedChain(snapshot) {
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
    if (roles.portal.length !== 1 || roles.bridge.length !== 1) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_TOPOLOGY_ROLES',
            'Topology v1 requires exactly one portal and one bridge',
        );
    }
    if (linksById.size !== nodesById.size - 1) {
        throw new FrozenTopologyDeploymentPlanError(
            'MISSING_TOPOLOGY_LINK',
            'Topology v1 requires one link between every adjacent node',
        );
    }

    const outgoing = new Map();
    const incoming = new Map();
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
        if (outgoing.has(source) || incoming.has(target)) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Topology v1 requires a linear chain',
            );
        }
        mode = link.mode;
        outgoing.set(source, { id, link, source, target });
        incoming.set(target, { id, link, source });
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

    if (
        visited.size !== nodesById.size
        || currentId !== roles.bridge[0]
        || orderedLinks.length !== linksById.size
    ) {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'Topology v1 must form Portal to Relay to Bridge',
        );
    }
    const orderedRoles = orderedNodes.map(entry => entry.node.role);
    if (
        orderedRoles[0] !== 'portal'
        || orderedRoles.at(-1) !== 'bridge'
        || orderedRoles.slice(1, -1).some(role => role !== 'relay')
    ) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_TOPOLOGY_ROLES',
            'Topology v1 must form Portal to Relay to Bridge',
        );
    }

    return { mode, orderedNodes, orderedLinks };
}

function topologyRefs(orderedNodes) {
    let relayIndex = 0;
    return new Map(orderedNodes.map(({ id, node }) => {
        let ref = node.role;
        if (node.role === 'relay') ref = `relay-${++relayIndex}`;
        return [id, ref];
    }));
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

function projectGeoRouting(metadata) {
    const source = metadata?.geoRouting;
    if (!isPlainObject(source)) return undefined;
    return {
        enabled: source.enabled === true,
        domains: Array.isArray(source.domains)
            ? source.domains.filter(value => typeof value === 'string')
            : [],
        geoip: Array.isArray(source.geoip)
            ? source.geoip.filter(value => typeof value === 'string')
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

function buildCandidateConfigs({ chain, refs, nodeMetadataById, linkMetadataById }) {
    const nodeConfigsById = new Map(chain.orderedNodes.map(({ id, node }) => [
        id,
        projectNodeConfig(nodeMetadataById.get(id), node, refs.get(id)),
    ]));
    const links = chain.orderedLinks.map((entry, index) => projectCascadeLink(
        entry,
        index,
        linkMetadataById.get(entry.id),
        nodeConfigsById,
    ));
    const configs = new Map();

    for (let index = 0; index < chain.orderedNodes.length; index += 1) {
        const { id, node } = chain.orderedNodes[index];
        const nodeConfig = nodeConfigsById.get(id);
        let config = parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, []));

        if (chain.mode === 'forward') {
            if (node.role === 'portal') {
                configGenerator.applyForwardChain(config, links, clientInboundTags(nodeConfig));
            } else {
                configGenerator.applyForwardHopInbound(config, [links[index - 1]]);
            }
        } else if (node.role === 'portal') {
            configGenerator.applyReversePortal(config, [links[index]], clientInboundTags(nodeConfig));
        } else if (node.role === 'relay') {
            const cascade = parseGeneratedConfig(configGenerator.generateRelayConfig(
                links[index - 1],
                links[index - 1].portalNode,
                [links[index]],
            ));
            config = composeBaselineWithCascade(config, cascade);
        } else {
            const cascade = JSON.parse(configGenerator.generateCombinedBridgeConfig([links[index - 1]]));
            cascade.inbounds = cascade.inbounds || [];
            config = composeBaselineWithCascade(config, parseGeneratedConfig(cascade));
        }
        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(id, config);
    }
    return configs;
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!isPlainObject(value)) return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalize(value[key])]),
    );
}

function candidateForNode({ mode, nodeId, node, nodeRef, orderedLinks, linkMetadataById, config }) {
    const target = TARGETS_BY_ROLE[node.role];
    const listeningPorts = orderedLinks
        .filter(entry => (mode === 'reverse' ? entry.source : entry.target) === nodeId)
        .map(entry => assertPort(linkMetadataById.get(entry.id).tunnelPort))
        .sort((left, right) => left - right);
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
    const chain = orderedChain(snapshot);
    const roleByNodeId = new Map(
        chain.orderedNodes.map(({ id, node }) => [id, node.role]),
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
    const nodeMetadataById = uniqueById(nodeMetadata, 'NODE_METADATA');
    const linkMetadataById = uniqueById(linkMetadata, 'LINK_METADATA');

    for (const { id, node } of chain.orderedNodes) {
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
    for (const { id, link, source, target } of chain.orderedLinks) {
        const metadata = linkMetadataById.get(id);
        if (!metadata) {
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_LINK_METADATA',
                'Every topology link requires hydrated metadata',
            );
        }
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
        if (metadata.tunnelSecurity === 'reality') {
            throw new FrozenTopologyDeploymentPlanError(
                'UNSUPPORTED_TOPOLOGY_TUNNEL_SECURITY',
                'Reality topology tunnel security is unsupported',
            );
        }
    }

    const refs = topologyRefs(chain.orderedNodes);
    let candidateConfigsById;
    try {
        candidateConfigsById = buildCandidateConfigs({
            chain,
            refs,
            nodeMetadataById,
            linkMetadataById,
        });
    } catch (error) {
        if (error instanceof FrozenTopologyDeploymentPlanError) throw error;
        throw new FrozenTopologyDeploymentPlanError(
            'XRAY_CONFIG_GENERATION_FAILED',
            'Failed to generate a frozen Xray topology candidate',
        );
    }
    const deploymentOrder = chain.mode === 'forward'
        ? [...chain.orderedNodes].reverse()
        : chain.orderedNodes;
    const nodes = deploymentOrder.map(({ id, node }) => candidateForNode({
        mode: chain.mode,
        nodeId: id,
        node,
        nodeRef: refs.get(id),
        orderedLinks: chain.orderedLinks,
        linkMetadataById,
        config: candidateConfigsById.get(id),
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
