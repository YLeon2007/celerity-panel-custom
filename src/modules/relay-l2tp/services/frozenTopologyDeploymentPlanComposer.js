'use strict';

const { createHash } = require('node:crypto');

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

function candidateForNode({ mode, nodeId, node, nodeRef, refs, orderedLinks, linkMetadataById }) {
    const target = TARGETS_BY_ROLE[node.role];
    const incidentLinks = orderedLinks
        .map((entry, index) => ({ ...entry, index }))
        .filter(entry => entry.source === nodeId || entry.target === nodeId)
        .map(entry => ({
            linkRef: `link-${entry.index + 1}`,
            direction: entry.source === nodeId ? 'outbound' : 'inbound',
            peerRef: refs.get(entry.source === nodeId ? entry.target : entry.source),
            port: assertPort(linkMetadataById.get(entry.id).tunnelPort),
        }));
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
    const candidateDocument = {
        schemaVersion: 1,
        kind: 'xray-topology-node-candidate',
        mode,
        nodeRef,
        role: node.role,
        targetProfile: target.targetProfile,
        links: incidentLinks,
        checks,
    };
    const bytes = Buffer.from(`${JSON.stringify(candidateDocument)}\n`, 'utf8');

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
    }

    const refs = topologyRefs(chain.orderedNodes);
    const deploymentOrder = chain.mode === 'forward'
        ? [...chain.orderedNodes].reverse()
        : chain.orderedNodes;
    const nodes = deploymentOrder.map(({ id, node }) => candidateForNode({
        mode: chain.mode,
        nodeId: id,
        node,
        nodeRef: refs.get(id),
        refs,
        orderedLinks: chain.orderedLinks,
        linkMetadataById,
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
