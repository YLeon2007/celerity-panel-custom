'use strict';

const { createHash } = require('node:crypto');
const configGenerator = require('../../../services/configGenerator');
const { composeXrayConfig } = require('./xrayConfigComposer');
const { compileTopology } = require('../domain/topologyCompiler');
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

function orderedChain(snapshot, geoLeafLinkIds = new Set(), staged = false) {
    if (!snapshot || !Array.isArray(snapshot.nodes) || !Array.isArray(snapshot.links)) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_TOPOLOGY_SNAPSHOT',
            'A validated topology snapshot with nodes and links is required',
        );
    }

    const nodesById = uniqueById(snapshot.nodes, 'NODE');
    const linksById = uniqueById(snapshot.links, 'LINK');

    // Roles are operator state: a node may keep portal/relay/bridge while
    // being rewired. Only nodes that actually participate in the link graph
    // belong to the topology plan; disconnected roled nodes are staged
    // assets and are left untouched (and unvalidated) by this deployment.
    const linkedNodeIds = new Set();
    for (const [, link] of linksById) {
        const source = entityId(link.source ?? link.portalNode);
        const target = entityId(link.target ?? link.bridgeNode);
        if (source) linkedNodeIds.add(source);
        if (target) linkedNodeIds.add(target);
    }
    const excludedNodeIds = [];
    for (const id of [...nodesById.keys()]) {
        if (!linkedNodeIds.has(id)) {
            nodesById.delete(id);
            excludedNodeIds.push(id);
        }
    }

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
    if ((!staged && (roles.portal.length !== 1 || roles.bridge.length < 1)) || roles.portal.length > 1) {
        if (excludedNodeIds.length > 0) {
            // The link graph is incomplete: nodes with cascade roles exist
            // but are disconnected, so the chain lost its portal/bridge.
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_TOPOLOGY_LINK',
                'A node with a cascade role is not connected by any link; complete the chain or detach the node',
            );
        }
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_TOPOLOGY_ROLES',
            'Topology requires exactly one portal and at least one bridge',
        );
    }

    const outgoing = new Map();
    const incoming = new Map();
    const geoOutgoing = new Map();
    const geoIncoming = new Map();
    const linkModes = new Set();
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
        // Link mode is per-hop: forward = source dials target, reverse =
        // target dials source. Mixed modes within one domain are supported
        // (RKN may block a forward tunnel while its reverse variant works),
        // so uniformity is deliberately NOT enforced here.
        linkModes.add(link.mode);
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
    const sources = [...nodesById.keys()].filter(id => !incoming.has(id) && !geoIncoming.has(id));
    const rootId = roles.portal[0] ?? (staged && sources.length === 1 ? sources[0] : null);
    let currentId = rootId;
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
        (orderedNodes.at(-1).node.role !== 'bridge' && !(staged && orderedNodes.at(-1).node.role === 'relay'))
        || (orderedNodes[0].node.role !== 'portal' && !(staged && orderedNodes[0].node.role === 'relay'))
        || orderedNodes.slice(1, -1).some(entry => entry.node.role !== 'relay')
    ) {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'Topology must form a linear portal/relay to relay/bridge main chain; incomplete endpoints require staging',
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

    return {
        mode: linkModes.size === 1 ? [...linkModes][0] : 'mixed',
        ...(orderedNodes[0].node.role !== 'portal' || orderedNodes.at(-1).node.role !== 'bridge'
            ? { staged: true } : {}),
        orderedNodes,
        orderedLinks,
        geoLeafNodes,
    };
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

/**
 * Multi-portal fan-in domain (forward mode only): several portal sources
 * converge into a shared relay trunk that terminates at a single default
 * bridge; geo leaves branch off nodes shared by ALL portal paths.
 *
 * Shape rules (validator):
 * - every non-geo node has at most ONE non-geo outgoing link (the default
 *   route must stay unambiguous, including for L2TP path walking);
 * - source nodes (no non-geo incoming) must be portals; fan-in (multiple
 *   non-geo incoming) is allowed on relays only;
 * - all portal paths terminate at the SAME sink, which must be a bridge;
 *   intermediate path nodes must be relays;
 * - a geo branch source must lie on every portal path (common trunk), so
 *   every portal can reach every geo bridge.
 */
function orderedFanInChain(snapshot, geoLeafLinkIds) {
    const nodesById = uniqueById(snapshot.nodes, 'NODE');
    const linksById = uniqueById(snapshot.links, 'LINK');

    // Staged assets: roled nodes without links do not participate (same
    // semantics as orderedChain).
    const linkedNodeIds = new Set();
    for (const [, link] of linksById) {
        const source = entityId(link.source ?? link.portalNode);
        const target = entityId(link.target ?? link.bridgeNode);
        if (source) linkedNodeIds.add(source);
        if (target) linkedNodeIds.add(target);
    }
    for (const id of [...nodesById.keys()]) {
        if (!linkedNodeIds.has(id)) nodesById.delete(id);
    }

    for (const [, node] of nodesById) {
        if (!Object.hasOwn(TARGETS_BY_ROLE, node.role)) {
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_NODE_ROLE',
                'Every topology node requires a supported role',
            );
        }
    }

    const outgoing = new Map(); // source -> entry (non-geo, unique per node)
    const incoming = new Map(); // target -> entry[] (non-geo, fan-in allowed)
    const geoOutgoing = new Map();
    const geoIncoming = new Map();
    const linkModes = new Set();
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
        // Per-hop link modes (mixed forward/reverse fan-in included) are
        // supported; uniformity is deliberately not enforced.
        linkModes.add(link.mode);
        const entry = { id, link, source, target };
        if (geoLeafLinkIds.has(id)) {
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
        if (outgoing.has(source)) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Each node may have only one non-geo (default) outgoing link; additional branches require geoRouting',
            );
        }
        outgoing.set(source, entry);
        if (!incoming.has(target)) incoming.set(target, []);
        incoming.get(target).push(entry);
    }

    const sources = [...outgoing.keys()]
        .filter(id => !incoming.has(id))
        .sort((left, right) => left.localeCompare(right, 'en'));
    if (sources.length < 2) {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'Fan-in composition requires at least two portal source nodes',
        );
    }
    for (const id of sources) {
        if (nodesById.get(id).role !== 'portal') {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Every fan-in source node must be a portal',
            );
        }
    }

    const portalPaths = [];
    let sinkId = null;
    for (const sourceId of sources) {
        const pathLinks = [];
        const pathNodeIds = [sourceId];
        const seen = new Set([sourceId]);
        let current = sourceId;
        while (outgoing.has(current)) {
            const entry = outgoing.get(current);
            pathLinks.push(entry);
            current = entry.target;
            if (seen.has(current)) {
                throw new FrozenTopologyDeploymentPlanError(
                    'NON_LINEAR_TOPOLOGY',
                    'Topology v1 requires an acyclic graph',
                );
            }
            seen.add(current);
            pathNodeIds.push(current);
        }
        if (sinkId === null) sinkId = current;
        else if (sinkId !== current) {
            throw new FrozenTopologyDeploymentPlanError(
                'MULTIPLE_DEFAULT_EGRESS',
                'All portal paths must terminate at the same default bridge',
            );
        }
        portalPaths.push({ portalId: sourceId, nodeIds: pathNodeIds, links: pathLinks });
    }

    if (nodesById.get(sinkId).role !== 'bridge') {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'The single non-geo chain end must be a bridge',
        );
    }
    for (const id of incoming.keys()) {
        if (!outgoing.has(id) && id !== sinkId) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Only the default bridge may terminate a non-geo path',
            );
        }
    }
    for (const { nodeIds } of portalPaths) {
        for (const id of nodeIds.slice(1, -1)) {
            if (nodesById.get(id).role !== 'relay') {
                throw new FrozenTopologyDeploymentPlanError(
                    'NON_LINEAR_TOPOLOGY',
                    'Intermediate fan-in path nodes must be relays',
                );
            }
        }
    }

    const coveredNodeIds = new Set(portalPaths.flatMap(path => path.nodeIds));
    const commonNodeIds = new Set(portalPaths[0].nodeIds);
    for (const path of portalPaths.slice(1)) {
        const pathNodes = new Set(path.nodeIds);
        for (const id of [...commonNodeIds]) {
            if (!pathNodes.has(id)) commonNodeIds.delete(id);
        }
    }

    const geoLeafNodes = [];
    for (const [id, node] of nodesById) {
        if (coveredNodeIds.has(id)) continue;
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
        if (!coveredNodeIds.has(leaf.source)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_SOURCE_OUTSIDE_CHAIN',
                'A geo-routing branch must start from a main-chain node',
            );
        }
        if (!commonNodeIds.has(leaf.source)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_SOURCE_NOT_COMMON_TRUNK',
                'A geo-routing branch must start from a node shared by all portal paths',
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
        if (!coveredNodeIds.has(entry.source)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_SOURCE_OUTSIDE_CHAIN',
                'A geo-routing branch must start from a main-chain node',
            );
        }
        if (coveredNodeIds.has(id)) {
            throw new FrozenTopologyDeploymentPlanError(
                'GEO_LEAF_TARGET_CONFLICT',
                'A geo-routing branch cannot terminate inside the main chain',
            );
        }
    }
    geoLeafNodes.sort((left, right) => left.id.localeCompare(right.id, 'en'));

    // Deterministic ordering: portals sorted by id, relays in first-seen
    // path order, sink last; links unique in first-seen path order.
    const orderedNodes = [];
    const seenNodes = new Set();
    for (const { portalId } of portalPaths) {
        orderedNodes.push({ id: portalId, node: nodesById.get(portalId) });
        seenNodes.add(portalId);
    }
    for (const { nodeIds } of portalPaths) {
        for (const id of nodeIds.slice(1)) {
            if (seenNodes.has(id) || id === sinkId) continue;
            seenNodes.add(id);
            orderedNodes.push({ id, node: nodesById.get(id) });
        }
    }
    orderedNodes.push({ id: sinkId, node: nodesById.get(sinkId) });

    const orderedLinks = [];
    const seenLinks = new Set();
    for (const { links } of portalPaths) {
        for (const entry of links) {
            if (seenLinks.has(entry.id)) continue;
            seenLinks.add(entry.id);
            orderedLinks.push(entry);
        }
    }

    // Distance to sink (single non-geo outgoing per node makes this
    // well-defined); used for downstream-first deployment ordering.
    const distToSink = new Map([[sinkId, 0]]);
    let changed = true;
    while (changed) {
        changed = false;
        for (const { nodeIds } of portalPaths) {
            for (let index = 0; index < nodeIds.length - 1; index += 1) {
                const id = nodeIds[index];
                const next = nodeIds[index + 1];
                if (distToSink.has(id) || !distToSink.has(next)) continue;
                distToSink.set(id, distToSink.get(next) + 1);
                changed = true;
            }
        }
    }

    return {
        mode: linkModes.size === 1 ? [...linkModes][0] : 'mixed',
        fanIn: true,
        portalPaths,
        orderedNodes,
        orderedLinks,
        geoLeafNodes,
        incoming,
        outgoing,
        distToSink,
    };
}

/** Decide between the classic linear chain and the fan-in domain shape. */
function selectChainShape(snapshot, geoLeafLinkIds, staged = false) {
    const nonGeoTargets = new Set();
    const nonGeoSources = new Set();
    for (const link of snapshot.links) {
        if (geoLeafLinkIds.has(entityId(link))) continue;
        const source = entityId(link.source ?? link.portalNode);
        const target = entityId(link.target ?? link.bridgeNode);
        if (source) nonGeoSources.add(source);
        if (target) nonGeoTargets.add(target);
    }
    const rootCount = [...nonGeoSources].filter(id => !nonGeoTargets.has(id)).length;
    const linkedIds = new Set([...nonGeoSources, ...nonGeoTargets]);
    const hasBridge = snapshot.nodes.some(node => linkedIds.has(entityId(node)) && node.role === 'bridge');
    return rootCount > 1
        ? (staged && !hasBridge
            ? orderedStagedChain(snapshot, geoLeafLinkIds)
            : orderedFanInChain(snapshot, geoLeafLinkIds))
        : orderedChain(snapshot, geoLeafLinkIds, staged);
}

/**
 * Staged scoped chain (link.apply on an incomplete component): a single
 * portal source followed by one linear run of relays that never reaches a
 * bridge. The terminal relay is a dead end by definition — candidate
 * builders must route its transit to `block` (fail closed), never `direct`.
 *
 * Deliberately stricter than the complete-chain walkers:
 * - one or more portal sources may converge on the same terminal relay;
 *   separate dead ends remain invalid (no implicit split egress);
 * - no geo-routing leaf links (a geo branch requires a dedicated bridge,
 *   which a bridge-less graph cannot have);
 * - every linked node must lie on the single portal path, and every node
 *   after the portal must be a relay (including the terminal node).
 */
function orderedStagedChain(snapshot, geoLeafLinkIds) {
    const nodesById = uniqueById(snapshot.nodes, 'NODE');
    const linksById = uniqueById(snapshot.links, 'LINK');

    if (geoLeafLinkIds.size > 0) {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'A geo-routing branch requires a dedicated bridge; staged chains cannot carry geo rules',
        );
    }

    // Staged assets: roled nodes without links do not participate (same
    // semantics as orderedChain / orderedFanInChain).
    const linkedNodeIds = new Set();
    for (const [, link] of linksById) {
        const source = entityId(link.source ?? link.portalNode);
        const target = entityId(link.target ?? link.bridgeNode);
        if (source) linkedNodeIds.add(source);
        if (target) linkedNodeIds.add(target);
    }
    for (const id of [...nodesById.keys()]) {
        if (!linkedNodeIds.has(id)) nodesById.delete(id);
    }

    const outgoing = new Map();
    const incoming = new Map();
    const linkModes = new Set();
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
        linkModes.add(link.mode);
        const entry = { id, link, source, target };
        if (outgoing.has(source)) {
            throw new FrozenTopologyDeploymentPlanError(
                'NON_LINEAR_TOPOLOGY',
                'Each node may have only one non-geo (default) outgoing link; additional branches require geoRouting',
            );
        }
        outgoing.set(source, entry);
        if (!incoming.has(target)) incoming.set(target, []);
        incoming.get(target).push(entry);
    }

    for (const [id, node] of nodesById) {
        if (!Object.hasOwn(TARGETS_BY_ROLE, node.role)) {
            throw new FrozenTopologyDeploymentPlanError(
                'MISSING_NODE_ROLE',
                'Every topology node requires a supported role',
            );
        }
        if (node.role === 'bridge') {
            throw new FrozenTopologyDeploymentPlanError(
                'INVALID_TOPOLOGY_ROLES',
                'A staged chain must not contain a bridge node',
            );
        }
    }

    // Every linked node must lie on a portal-rooted path to the SAME terminal
    // relay. A multi-portal fan-in is staged safely: transit is blocked at
    // that terminal until a confirmed downstream bridge joins the scope.
    const sources = [...outgoing.keys()]
        .filter(id => !incoming.has(id))
        .sort((left, right) => left.localeCompare(right, 'en'));
    if (sources.length === 0 || sources.some(id => nodesById.get(id)?.role !== 'portal')) {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'A staged chain requires portal sources reaching one terminal relay',
        );
    }
    const portalPaths = [];
    let terminalId = null;
    const coveredNodes = new Set();
    const coveredLinks = new Set();
    for (const portalId of sources) {
        const nodeIds = [portalId];
        const links = [];
        const seen = new Set([portalId]);
        let currentId = portalId;
        while (outgoing.has(currentId)) {
            const next = outgoing.get(currentId);
            links.push(next);
            coveredLinks.add(next.id);
            currentId = next.target;
            if (seen.has(currentId)) {
                throw new FrozenTopologyDeploymentPlanError(
                    'NON_LINEAR_TOPOLOGY', 'A staged chain must be acyclic',
                );
            }
            seen.add(currentId);
            nodeIds.push(currentId);
        }
        if (terminalId === null) terminalId = currentId;
        else if (terminalId !== currentId) {
            throw new FrozenTopologyDeploymentPlanError(
                'MULTIPLE_DEFAULT_EGRESS',
                'All staged portal paths must end at the same relay',
            );
        }
        nodeIds.forEach(id => coveredNodes.add(id));
        portalPaths.push({ portalId, nodeIds, links });
    }
    if (coveredNodes.size !== nodesById.size || coveredLinks.size !== linksById.size
        || nodesById.get(terminalId)?.role !== 'relay'
        || portalPaths.some(path => path.nodeIds.slice(1)
            .some(id => nodesById.get(id)?.role !== 'relay'))) {
        throw new FrozenTopologyDeploymentPlanError(
            'NON_LINEAR_TOPOLOGY',
            'A staged chain requires every linked node on portal paths to one terminal relay',
        );
    }
    const orderedNodes = [];
    const orderedLinks = [];
    const emittedNodes = new Set();
    const emittedLinks = new Set();
    for (const portalId of sources) {
        orderedNodes.push({ id: portalId, node: nodesById.get(portalId) });
        emittedNodes.add(portalId);
    }
    for (const path of portalPaths) {
        for (const id of path.nodeIds.slice(1)) {
            if (id === terminalId || emittedNodes.has(id)) continue;
            orderedNodes.push({ id, node: nodesById.get(id) });
            emittedNodes.add(id);
        }
        for (const link of path.links) {
            if (emittedLinks.has(link.id)) continue;
            orderedLinks.push(link);
            emittedLinks.add(link.id);
        }
    }
    orderedNodes.push({ id: terminalId, node: nodesById.get(terminalId) });
    return {
        mode: linkModes.size === 1 ? [...linkModes][0] : 'mixed',
        staged: true,
        ...(sources.length > 1 ? { fanIn: true } : {}),
        portalPaths,
        orderedNodes,
        orderedLinks,
        geoLeafNodes: [],
        incoming,
        outgoing,
    };
}

function topologyFanInRefs(chain) {
    const refs = new Map();
    let portalIndex = 0;
    let relayIndex = 0;
    for (const { id, node } of chain.orderedNodes) {
        if (node.role === 'portal') refs.set(id, `portal-${++portalIndex}`);
        else if (node.role === 'relay') refs.set(id, `relay-${++relayIndex}`);
        else refs.set(id, 'bridge'); // the default-bridge sink
    }
    let bridgeIndex = 1;
    for (const { id } of chain.geoLeafNodes) {
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
    // Legacy identity-only snapshots deliberately omit stored credentials.
    // Both ends then use this restart-deterministic UUID; trusted complete
    // descriptors may instead carry the exact already-applied tunnelUuid.
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

// geoip.dat codes are ISO-3166 alpha-2 (plus a few specials like 'private');
// this also rejects punycode artifacts such as 'xn--p1ai' (from 'рф').
const GEOIP_TAG_RE = /^[a-z]{2}$|^private$/;

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

function projectCascadeLink(entry, index, metadata, nodeConfigsById, linkRefsById) {
    const linkRef = linkRefsById?.get(entry.id) ?? `link-${index + 1}`;
    const projected = {
        _id: linkRef,
        portalNode: nodeConfigsById.get(entry.source),
        bridgeNode: nodeConfigsById.get(entry.target),
        tunnelUuid: entry.link.tunnelUuid ?? deterministicTunnelUuid(entry.id),
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

// xray-bridge profile candidates must not bind the node's xray-main client
// inbounds: on hosts running both services (e.g. a panel host doubling as a
// relay) the ports would collide and the bridge service would fail to start.
function stripServerInbounds(config, nodeConfig) {
    const tags = new Set(clientInboundTags(nodeConfig));
    config.inbounds = (config.inbounds || []).filter(inbound => !tags.has(inbound.tag));
    if (Array.isArray(config.routing?.rules)) {
        config.routing.rules = config.routing.rules.filter(rule =>
            !Array.isArray(rule.inboundTag)
            || !rule.inboundTag.some(tag => tags.has(tag)));
    }
    return config;
}

// --- Scoped mixed-mode primitives -------------------------------------------
// The hop-by-hop mixed builder needs reverse-bridge artifacts on an existing
// config and forward hop inbounds whose unconditional `-> direct` exit rule
// is suppressed (the builder emits exit rules itself, after geo-branch
// rules). Baseline configGenerator (b97900e) does not export these; commit
// 3471f52 adds them as applyReverseBridge / applyForwardHopInbound(_, _, tag)
// upstream. Until the mode-generator owner ports that part, keep local
// mirrors here so this module stays scoped. Behavior must match 3471f52
// exactly — deduplicate once configGenerator exports the shared helpers.
function tunnelDomainOf(link) {
    const baseDomain = link.tunnelDomain || 'reverse.tunnel.internal';
    return `${String(link._id).slice(-8)}.${baseDomain}`;
}

function outboundUserOf(uuid, protocol) {
    if (protocol === 'vmess') return { id: uuid, alterId: 0, security: 'auto' };
    return { id: uuid, encryption: 'none' };
}

/**
 * Mirror of configGenerator.applyReverseBridge(config, links, egressTag)
 * from 3471f52: for every reverse link this node dials (it is the target /
 * bridgeNode), install the reverse bridge control block, the tunnel outbound
 * and the full-domain control-channel rule; route tunnel-exit traffic to
 * egressTag unless it is null.
 */
function applyReverseBridgeArtifacts(config, links, egressTag = 'freedom') {
    if (!links || links.length === 0) return;

    config.reverse = config.reverse || {};
    config.reverse.bridges = config.reverse.bridges || [];
    config.outbounds = config.outbounds || [];
    config.routing = config.routing || { rules: [] };
    config.routing.rules = config.routing.rules || [];

    for (const link of links) {
        const portalNode = link.portalNode;
        if (!portalNode || !portalNode.ip) {
            throw new FrozenTopologyDeploymentPlanError(
                'XRAY_CONFIG_GENERATION_FAILED',
                `Portal node is not populated for cascade link ${link.name || link._id}`,
            );
        }

        const tunnelDomain = tunnelDomainOf(link);
        const protocol = link.tunnelProtocol || 'vless';
        const linkIdShort = String(link._id).slice(-8);
        const bridgeTag = `bridge-${linkIdShort}`;
        const tunnelTag = `tunnel-${linkIdShort}`;

        const tunnelOutbound = {
            tag: tunnelTag,
            protocol,
            settings: {
                vnext: [{
                    address: portalNode.ip,
                    port: link.tunnelPort || 10086,
                    users: [outboundUserOf(link.tunnelUuid, protocol)],
                }],
            },
            streamSettings: configGenerator.buildCascadeTunnelStreamSettings(link),
        };
        if (link.muxEnabled) {
            tunnelOutbound.mux = { enabled: true, concurrency: link.muxConcurrency || 8 };
        }

        config.reverse.bridges.push({ tag: bridgeTag, domain: tunnelDomain });
        config.outbounds.unshift(tunnelOutbound);

        config.routing.rules.push({
            type: 'field',
            domain: [`full:${tunnelDomain}`],
            outboundTag: tunnelTag,
        });
        if (egressTag !== null) {
            config.routing.rules.push({
                type: 'field',
                inboundTag: [bridgeTag],
                outboundTag: egressTag,
            });
        }
    }
}

/**
 * Equivalent of configGenerator.applyForwardHopInbound(config, links, null)
 * from 3471f52: bind the hop inbounds but suppress the per-link
 * `inboundTag -> direct` exit rule the baseline helper appends
 * unconditionally — mixed composition places exit rules after geo branches.
 */
function applyForwardHopInboundNoEgress(config, links) {
    if (!links || links.length === 0) return;
    config.routing = config.routing || { rules: [] };
    config.routing.rules = config.routing.rules || [];
    const ruleCount = config.routing.rules.length;
    configGenerator.applyForwardHopInbound(config, links);
    config.routing.rules = config.routing.rules.filter((rule, index) => index < ruleCount
        || !(rule.type === 'field' && rule.outboundTag === 'direct' && Array.isArray(rule.inboundTag)));
}
// --- End scoped mixed-mode primitives ---------------------------------------

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

function buildCandidateConfigs({ chain, refs, nodeMetadataById, linkMetadataById, groups = [], linkRefsById }) {
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
        linkRefsById,
    ));
    const geoLinks = geoLeafNodes.map((leaf, index) => projectCascadeLink(
        leaf.link,
        chain.orderedLinks.length + index,
        linkMetadataById.get(leaf.link.id),
        nodeConfigsById,
        linkRefsById,
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
                if (node.role === 'relay') {
                    config = stripServerInbounds(config, nodeConfig);
                }
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

/**
 * Fan-in (multi-portal, forward-only) candidate configs.
 * - each portal originates the full forward chain along its own path plus
 *   every geo branch (chained through its own path prefix);
 * - a merge relay binds one hop inbound per upstream link and keeps the
 *   per-path socks ingress chained to its single downstream link;
 * - the default bridge terminates ALL upstream links.
 */
function buildFanInCandidateConfigs({ chain, refs, nodeMetadataById, linkMetadataById, groups = [], linkRefsById }) {
    const geoLeafNodes = chain.geoLeafNodes || [];
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
        linkRefsById,
    ));
    const geoLinks = geoLeafNodes.map((leaf, index) => projectCascadeLink(
        leaf.link,
        chain.orderedLinks.length + index,
        linkMetadataById.get(leaf.link.id),
        nodeConfigsById,
        linkRefsById,
    ));
    const projectedByEntryId = new Map(chain.orderedLinks.map((entry, index) => [entry.id, links[index]]));
    const geoProjectedByEntryId = new Map(geoLeafNodes.map((leaf, index) => [leaf.link.id, geoLinks[index]]));

    const configs = new Map();
    const ingressByNodeId = new Map();

    // Portals: full forward chain along the own path + all geo branches.
    for (const path of chain.portalPaths) {
        const id = path.portalId;
        const nodeConfig = nodeConfigsById.get(id);
        let config = parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, []));
        configGenerator.applyXrayApi(config, nodeConfig.xray.apiPort || 61000);
        const branches = geoLeafNodes.map(leaf => {
            const prefixEntry = path.links.find(entry => entry.target === leaf.link.source);
            return {
                link: geoProjectedByEntryId.get(leaf.link.id),
                viaTag: prefixEntry
                    ? `fwd-${String(projectedByEntryId.get(prefixEntry.id)._id).slice(-8)}`
                    : null,
            };
        });
        configGenerator.applyForwardChain(
            config,
            path.links.map(entry => projectedByEntryId.get(entry.id)),
            clientInboundTags(nodeConfig),
            [],
            branches,
        );
        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(id, config);
    }

    // Relays: one hop inbound per upstream link; per-path socks ingress
    // chained along the single downstream suffix.
    for (const { id, node } of chain.orderedNodes) {
        if (node.role !== 'relay') continue;
        const nodeConfig = nodeConfigsById.get(id);
        let config = stripServerInbounds(
            parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, [])),
            nodeConfig,
        );
        const upstream = (chain.incoming.get(id) || [])
            .slice()
            .sort((left, right) => left.id.localeCompare(right.id, 'en'));
        configGenerator.applyForwardHopInbound(
            config,
            upstream.map(entry => projectedByEntryId.get(entry.id)),
        );
        const downstream = chain.outgoing.get(id);
        if (downstream) {
            const suffixEntries = [];
            let current = id;
            const seen = new Set([id]);
            while (chain.outgoing.has(current)) {
                const entry = chain.outgoing.get(current);
                suffixEntries.push(entry);
                current = entry.target;
                if (seen.has(current)) break; // validator rejects cycles already
                seen.add(current);
            }
            const ingress = relayPathIngress(groups, downstream.id);
            if (ingress.length > 0) {
                configGenerator.applyForwardChain(
                    config,
                    suffixEntries.map(entry => projectedByEntryId.get(entry.id)),
                    [],
                    ingress,
                );
                ingressByNodeId.set(id, ingress);
            }
        }
        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(id, config);
    }

    // Default bridge sink: terminates every upstream link. In forward mode the
    // sink is a transport hop (like a geo leaf): it binds one fwd-hop inbound
    // per upstream link and forwards the decoded stream directly. The reverse
    // combined-bridge generator builds a reverse-tunnel (outbounds only, no
    // listening hop port), which never satisfies the forward verify port check.
    const sinkId = chain.orderedNodes.at(-1).id;
    {
        const nodeConfig = nodeConfigsById.get(sinkId);
        let config = parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, []));
        const upstream = (chain.incoming.get(sinkId) || [])
            .slice()
            .sort((left, right) => left.id.localeCompare(right.id, 'en'));
        if (chain.mode === 'forward') {
            configGenerator.applyForwardHopInbound(
                config,
                upstream.map(entry => projectedByEntryId.get(entry.id)),
            );
        } else {
            const cascade = JSON.parse(configGenerator.generateCombinedBridgeConfig(
                upstream.map(entry => projectedByEntryId.get(entry.id)),
            ));
            cascade.inbounds = cascade.inbounds || [];
            config = composeBaselineWithCascade(config, parseGeneratedConfig(cascade));
        }
        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(sinkId, config);
    }

    // Geo-routing bridges: same as the linear path (single upstream link).
    for (let index = 0; index < geoLeafNodes.length; index += 1) {
        const { id } = geoLeafNodes[index];
        const nodeConfig = nodeConfigsById.get(id);
        let config = parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, []));
        configGenerator.applyForwardHopInbound(config, [geoLinks[index]]);
        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(id, config);
    }

    return { configs, ingressByNodeId };
}

/**
 * Hop-by-hop candidate builder for domains whose links mix forward and
 * reverse modes, and for non-forward fan-in domains. Unlike the uniform
 * forward builders there is no proxySettings nesting here: every hop
 * terminates the upstream tunnel and re-originates traffic into its
 * downstream link.
 *
 * Per link L = (source S, target T, mode M) traffic always flows S -> T:
 * - forward: S originates outbound fwd-<ref8> towards T; T binds hop inbound
 *   fwd-hop-<ref8>.
 * - reverse: S binds the reverse portal (portal-<ref8> control block plus
 *   bridge-conn-<ref8> connector inbound); T dials S (reverse bridge
 *   bridge-<ref8> control block plus tunnel-<ref8> outbound).
 *
 * Routing per node: portal routes client inbound tags, relay routes upstream
 * tunnel exit tags (plus loopback L2TP path ingress) into the default
 * downstream artifact; geo-branch rules are placed before the default rule;
 * terminal nodes (default sink, geo leaves) route exits to `terminalEgressTag`
 * ('block' for a staged relay dead end). An explicit bridge remains an
 * allowed exit, including a geo leaf beside a missing default path.
 */
function buildMixedCandidateConfigs({ chain, refs, nodeMetadataById, linkMetadataById, groups = [], terminalEgressTag = 'direct', linkRefsById }) {
    const byEntryId = (left, right) => left.id.localeCompare(right.id, 'en');
    const geoLeafNodes = chain.geoLeafNodes || [];
    const allChainNodes = [...chain.orderedNodes, ...geoLeafNodes];
    const nodeConfigsById = new Map(allChainNodes.map(({ id, node }) => [
        id,
        projectNodeConfig(nodeMetadataById.get(id), node, refs.get(id)),
    ]));
    const allEntries = [
        ...chain.orderedLinks,
        ...geoLeafNodes.map(leaf => leaf.link),
    ];
    const projectedByEntryId = new Map(allEntries.map((entry, index) => [
        entry.id,
        projectCascadeLink(entry, index, linkMetadataById.get(entry.id), nodeConfigsById, linkRefsById),
    ]));

    const geoLeafLinkIds = new Set(geoLeafNodes.map(leaf => leaf.link.id));
    const incoming = new Map(); // target -> entry[] (non-geo)
    const outgoing = new Map(); // source -> entry (non-geo)
    const geoIncoming = new Map(); // geo leaf node id -> entry
    const geoBySource = new Map(); // branch source node id -> entry[]
    for (const entry of allEntries) {
        if (geoLeafLinkIds.has(entry.id)) {
            geoIncoming.set(entry.target, entry);
            const list = geoBySource.get(entry.source) || [];
            list.push(entry);
            geoBySource.set(entry.source, list);
            continue;
        }
        outgoing.set(entry.source, entry);
        if (!incoming.has(entry.target)) incoming.set(entry.target, []);
        incoming.get(entry.target).push(entry);
    }

    const ref8 = entry => String(projectedByEntryId.get(entry.id)._id).slice(-8);
    const egressTagOf = entry => entry.link.mode === 'reverse'
        ? `portal-${ref8(entry)}`
        : `fwd-${ref8(entry)}`;
    const exitTagOf = entry => entry.link.mode === 'reverse'
        ? `bridge-${ref8(entry)}`
        : `fwd-hop-${ref8(entry)}`;

    const configs = new Map();
    const ingressByNodeId = new Map();

    for (const { id, node } of allChainNodes) {
        const nodeConfig = nodeConfigsById.get(id);
        let config = parseGeneratedConfig(configGenerator.generateXrayConfig(nodeConfig, []));
        if (node.role === 'portal') {
            configGenerator.applyXrayApi(config, nodeConfig.xray.apiPort || 61000);
        } else if (node.role === 'relay') {
            config = stripServerInbounds(config, nodeConfig);
        }

        const ups = (incoming.get(id) || []).slice().sort(byEntryId);
        const geoLeafEntry = geoIncoming.get(id) || null;
        const downstream = outgoing.get(id) || null;
        const branches = (geoBySource.get(id) || []).slice().sort(byEntryId);
        const isTerminal = !downstream; // default sink or geo leaf

        // Upstream tunnel artifacts (listener or dialer side per link mode).
        // Exit routing rules are emitted below, after geo-branch rules.
        const forwardUps = ups.filter(entry => entry.link.mode === 'forward');
        const reverseUps = ups.filter(entry => entry.link.mode === 'reverse');
        if (geoLeafEntry) {
            (geoLeafEntry.link.mode === 'forward' ? forwardUps : reverseUps).push(geoLeafEntry);
        }
        if (forwardUps.length > 0) {
            applyForwardHopInboundNoEgress(
                config,
                forwardUps.map(entry => projectedByEntryId.get(entry.id)),
            );
        }
        if (reverseUps.length > 0) {
            applyReverseBridgeArtifacts(
                config,
                reverseUps.map(entry => projectedByEntryId.get(entry.id)),
                null,
            );
        }

        // Downstream tunnel artifacts: default link plus geo branches.
        const downstreamArtifacts = [...(downstream ? [downstream] : []), ...branches];
        for (const entry of downstreamArtifacts) {
            const projected = projectedByEntryId.get(entry.id);
            if (entry.link.mode === 'reverse') {
                configGenerator.applyReversePortal(config, [projected], []);
            } else {
                configGenerator.applyForwardChain(config, [projected], [], []);
            }
        }

        // Ingress tags this node routes onwards: portals route client
        // inbounds; relays and terminal nodes route upstream tunnel exits.
        const transitTags = [
            ...ups.map(exitTagOf),
            ...(geoLeafEntry ? [exitTagOf(geoLeafEntry)] : []),
        ];
        const ingressTags = node.role === 'portal' ? clientInboundTags(nodeConfig) : transitTags;

        // Loopback L2TP path ingress follows the same geo/default policy as
        // upstream transit. Install listeners only: an immediate per-path
        // catch-all here would bypass the geo rules emitted below.
        if (node.role === 'relay' && downstream) {
            const ingress = relayPathIngress(groups, downstream.id);
            if (ingress.length > 0) {
                configGenerator.applyCascadePathIngress(config, ingress);
                ingressTags.push(...ingress.map(entry => `cascade-${entry.pathKey}`));
                ingressByNodeId.set(id, ingress);
            }
        }

        // Geo-branch rules first, so branch matches win over the default rule.
        for (const entry of branches) {
            if (ingressTags.length === 0) continue;
            const geo = projectGeoRouting(linkMetadataById.get(entry.id)) || {};
            const tag = egressTagOf(entry);
            if (Array.isArray(geo.domains) && geo.domains.length > 0) {
                config.routing.rules.push({
                    type: 'field',
                    inboundTag: ingressTags,
                    domain: geo.domains.map(item => (item.includes(':') ? item : `geosite:${item}`)),
                    outboundTag: tag,
                });
            }
            if (Array.isArray(geo.geoip) && geo.geoip.length > 0) {
                config.routing.rules.push({
                    type: 'field',
                    inboundTag: ingressTags,
                    ip: geo.geoip.map(item => (item.includes(':') ? item : `geoip:${item}`)),
                    outboundTag: tag,
                });
                // Domain targets skip ip-only rules under IPIfNonMatch and
                // fall into the default route; IPOnDemand resolves them.
                config.routing.domainStrategy = 'IPOnDemand';
            }
        }
        if (isTerminal) {
            for (const tag of ingressTags) {
                config.routing.rules.push({
                    type: 'field',
                    inboundTag: [tag],
                    outboundTag: node.role === 'bridge' ? 'direct' : terminalEgressTag,
                });
            }
        } else if (ingressTags.length > 0) {
            config.routing.rules.push({
                type: 'field',
                inboundTag: ingressTags,
                outboundTag: egressTagOf(downstream),
            });
        }

        configGenerator.ensurePrivateIpBlock(config);
        config = composeXrayConfig(config, []);
        configs.set(id, config);
    }

    return { configs, ingressByNodeId };
}

/**
 * Deployment order with per-hop listener-first guarantees: for every link,
 * the node hosting the tunnel listener (forward: target; reverse: source)
 * is deployed before the node that dials it. Deterministic (id-ascending)
 * tie-break. Uniform-mode chains keep their legacy downstream-first order.
 */
function mixedDeploymentOrder(chain) {
    const geoLeafNodes = chain.geoLeafNodes || [];
    const allChainNodes = [...chain.orderedNodes, ...geoLeafNodes];
    const nodeIds = allChainNodes.map(({ id }) => id);
    const allEntries = [...chain.orderedLinks, ...geoLeafNodes.map(leaf => leaf.link)];
    const deps = new Map(nodeIds.map(id => [id, new Set()])); // node -> nodes deployed earlier
    for (const entry of allEntries) {
        const listener = entry.link.mode === 'reverse' ? entry.source : entry.target;
        const dialer = entry.link.mode === 'reverse' ? entry.target : entry.source;
        if (listener !== dialer) deps.get(dialer)?.add(listener);
    }
    const order = [];
    const placed = new Set();
    while (order.length < nodeIds.length) {
        const ready = nodeIds
            .filter(id => !placed.has(id) && [...deps.get(id)].every(dep => placed.has(dep)))
            .sort((left, right) => left.localeCompare(right, 'en'));
        if (ready.length === 0) {
            // Defensive: topological graphs should never cycle; fall back to
            // remaining ids so the plan stays complete rather than dropping nodes.
            ready.push(...nodeIds.filter(id => !placed.has(id)).sort((a, b) => a.localeCompare(b, 'en')));
        }
        for (const id of ready) {
            placed.add(id);
            order.push(id);
        }
    }
    return order;
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!isPlainObject(value)) return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalize(value[key])]),
    );
}

function candidateForNode({ nodeId, node, nodeRef, orderedLinks, linkMetadataById, config, ingressPorts = [], previousListeningPorts = [] }) {
    const target = TARGETS_BY_ROLE[node.role];
    // Tunnel listeners live on the target of forward links and on the source
    // of reverse links (the dialer connects to them).
    const listeningPorts = [...new Set([
        ...orderedLinks
            .filter(entry => (entry.link.mode === 'reverse' ? entry.source : entry.target) === nodeId)
            .map(entry => assertPort(linkMetadataById.get(entry.id).tunnelPort)),
        ...ingressPorts,
        // A shared owner/blocked PPP input can deliberately keep the port.
        ...previousListeningPorts.filter(port => config.inbounds.some(inbound => inbound.port === port)),
    ])].sort((left, right) => left - right);
    const removedPorts = [...new Set(previousListeningPorts)]
        .filter(port => !config.inbounds.some(inbound => inbound.port === port))
        .sort((left, right) => left - right);
    const checks = [
        { type: 'service', serviceUnit: target.serviceUnit, expectedState: 'active' },
        ...listeningPorts.map(port => ({
            type: 'port',
            protocol: 'tcp',
            port,
            expectedState: 'listening',
        })),
        ...removedPorts.map(port => ({ type: 'port', protocol: 'tcp', port, expectedState: 'absent' })),
    ];
    const bytes = Buffer.from(`${JSON.stringify(canonicalize(config))}\n`, 'utf8');

    return {
        node: nodeId,
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

// A route group may preserve independently owned disconnected paths. They are
// separate routing domains, not competing defaults of one fan-in domain.
function connectedSnapshots(snapshot) {
    const nodesById = uniqueById(snapshot.nodes, 'NODE');
    uniqueById(snapshot.links, 'LINK');
    const neighbors = new Map();
    for (const link of snapshot.links) {
        const from = entityId(link.source ?? link.portalNode);
        const to = entityId(link.target ?? link.bridgeNode);
        if (!nodesById.has(from) || !nodesById.has(to)) {
            throw new FrozenTopologyDeploymentPlanError('MISSING_TOPOLOGY_LINK_ENDPOINT', 'Link endpoints must exist');
        }
        if (!neighbors.has(from)) neighbors.set(from, new Set());
        if (!neighbors.has(to)) neighbors.set(to, new Set());
        neighbors.get(from).add(to);
        neighbors.get(to).add(from);
    }
    const remaining = new Set([...neighbors.keys()].sort());
    const components = [];
    while (remaining.size) {
        const pending = [remaining.values().next().value];
        const included = new Set();
        while (pending.length) {
            const id = pending.pop();
            if (included.has(id)) continue;
            included.add(id);
            remaining.delete(id);
            pending.push(...neighbors.get(id));
        }
        const links = snapshot.links.filter(link => included.has(entityId(link.source ?? link.portalNode)));
        const ids = new Set(links.map(entityId));
        const groups = (snapshot.groups || []).map(group => ({ ...group,
            paths: (group.paths || []).filter(path => {
                const inside = path.linkIds.some(id => ids.has(entityId(id)));
                if (inside && path.linkIds.some(id => !ids.has(entityId(id)))) {
                    throw new FrozenTopologyDeploymentPlanError('DISCONTINUOUS_PATH', 'A route path crosses disconnected components');
                }
                return inside;
            }),
        })).filter(group => group.paths.length);
        components.push({ nodes: snapshot.nodes.filter(node => included.has(entityId(node))), links, groups });
    }
    return components;
}

function componentRefs(snapshot) {
    const refs = new Map();
    for (const role of Object.keys(TARGETS_BY_ROLE)) {
        const nodes = snapshot.nodes.filter(node => node.role === role).sort((a, b) => entityId(a).localeCompare(entityId(b), 'en'));
        nodes.forEach((node, index) => refs.set(entityId(node), role === 'relay' || nodes.length > 1
            ? `${role}-${index + 1}` : role));
    }
    return refs;
}

// A verified node.profileConfig is the role-target profile's last readback,
// never another profile or caller-supplied config. Replace only generated
// members; leave unrelated fragments and runtime client identities intact.
function preserveProfileConfig(profile, previous, next, clientTags) {
    const current = parseGeneratedConfig(profile);
    const before = previous || { inbounds: [], outbounds: [], routing: { rules: [] } };
    const mergeTagged = (existing, oldItems, newItems) => {
        const owned = new Set(oldItems.map(item => item.tag));
        const replacements = new Map(newItems.map(item => [item.tag, structuredClone(item)]));
        const result = [];
        for (const item of existing) {
            if (!owned.has(item.tag)) { result.push(structuredClone(item)); continue; }
            const replacement = replacements.get(item.tag);
            if (replacement) {
                if (clientTags.includes(item.tag) && Array.isArray(item.settings?.clients)) {
                    replacement.settings.clients = structuredClone(item.settings.clients);
                }
                result.push(replacement);
                replacements.delete(item.tag);
            }
        }
        return [...result, ...replacements.values()];
    };
    current.inbounds = mergeTagged(current.inbounds, before.inbounds, next.inbounds);
    current.outbounds = mergeTagged(current.outbounds, before.outbounds, next.outbounds);
    const key = item => JSON.stringify(canonicalize(item));
    const oldRules = new Set(before.routing.rules.map(key));
    const foreignRules = current.routing.rules.filter(rule => !oldRules.has(key(rule)));
    current.routing = { ...current.routing, ...next.routing,
        rules: [...structuredClone(next.routing.rules), ...foreignRules] };
    for (const kind of ['portals', 'bridges']) {
        const values = mergeTagged(current.reverse?.[kind] || [], before.reverse?.[kind] || [], next.reverse?.[kind] || []);
        if (values.length || current.reverse?.[kind] || next.reverse?.[kind]) {
            current.reverse ||= {};
            current.reverse[kind] = values;
        }
    }
    return composeXrayConfig(current, []);
}

function isolatedProfileConfig(node, nodeRef) {
    const metadata = projectNodeConfig(node, node, nodeRef);
    let config = parseGeneratedConfig(configGenerator.generateXrayConfig(metadata, []));
    if (node.role === 'portal') {
        configGenerator.applyXrayApi(config, metadata.xray.apiPort || 61000);
        config.routing.rules.push({ type: 'field', inboundTag: clientInboundTags(metadata), outboundTag: 'block' });
    } else config = stripServerInbounds(config, metadata);
    configGenerator.ensurePrivateIpBlock(config);
    return config;
}

// An empty installed path can retain the previously generated blocked ingress.
// Recognize only the exact loopback listener AND block rule in the verified
// role-profile readback, bound to an existing group/key/port descriptor.
function includeBlockedPathReadback(topology, node, config) {
    if (node.role !== 'relay' || node.profileConfig === undefined) return;
    const profile = parseGeneratedConfig(node.profileConfig);
    const key = item => JSON.stringify(canonicalize(item));
    for (const group of topology.groups || []) {
        for (const path of group.paths || []) {
            if (path.enabled === false || path.linkIds.length !== 0) continue;
            const fragment = { inbounds: [], routing: { rules: [] } };
            configGenerator.applyCascadePathIngress(fragment, [{ pathKey: path.pathKey,
                port: cascadePathIngressPort(entityId(group), path.pathKey), egressTag: 'block' }]);
            const inbound = fragment.inbounds[0];
            const rule = fragment.routing.rules[0];
            if (!config.inbounds.some(current => current.tag === inbound.tag)
                && profile.inbounds.some(current => key(current) === key(inbound))
                && profile.routing.rules.some(current => key(current) === key(rule))) {
                config.inbounds.push(inbound);
                config.routing.rules.push(rule);
            }
        }
    }
}

// Generate both sides with the existing generators. Stable private link refs
// keep a surviving tunnel's tags/domain independent of removed siblings.
function composeDescriptorTransition(before, after) {
    const beforeNodes = uniqueById(before.nodes, 'NODE');
    const afterNodes = uniqueById(after.nodes, 'NODE');
    const nodesById = new Map([...beforeNodes, ...afterNodes]);
    for (const [id, node] of beforeNodes) {
        if (afterNodes.has(id) && afterNodes.get(id).role !== node.role) {
            throw new FrozenTopologyDeploymentPlanError('NODE_ROLE_MISMATCH', 'A descriptor transition may not change profile roles');
        }
    }
    const unionLinks = new Map([...before.links, ...after.links].map(link => [entityId(link), link]));
    const usedIds = new Set(nodesById.keys());
    const refs = componentRefs({ nodes: [...nodesById.values()] });
    const linkRefs = new Map([...unionLinks.keys()].map(id => [id,
        `link-${createHash('sha256').update(`celerity-topology-link:${id}`).digest('hex').slice(0, 8)}`]));
    if (new Set(linkRefs.values()).size !== linkRefs.size) {
        throw new FrozenTopologyDeploymentPlanError('DUPLICATE_LINK_REF', 'Frozen link artifact identities collide');
    }
    const generate = topology => {
        if (topology.links.length === 0) return null;
        return composeFrozenTopologyDeploymentPlan({ snapshot: topology,
            nodeMetadata: topology.nodes, linkMetadata: topology.links,
            compiledTopology: compileTopology(topology), staged: true,
            nodeRefsById: refs, linkRefsById: linkRefs, hopByHop: true });
    };
    const oldPlan = generate(before);
    const newPlan = generate(after);
    const configMap = plan => new Map((plan?.nodes || []).map(node => [node.node,
        parseGeneratedConfig(Buffer.from(node.candidate.bytes).toString('utf8'))]));
    const oldConfigs = configMap(oldPlan);
    const newConfigs = configMap(newPlan);
    for (const [id, node] of beforeNodes) {
        if (!oldConfigs.has(id)) oldConfigs.set(id, isolatedProfileConfig(node, refs.get(id)));
        includeBlockedPathReadback(before, node, oldConfigs.get(id));
        if (node.profileConfig !== undefined) {
            const profile = parseGeneratedConfig(node.profileConfig);
            const key = value => JSON.stringify(canonicalize(value));
            for (const link of before.links.filter(link => (link.mode === 'reverse' ? link.source : link.target) === id)) {
                const expected = oldConfigs.get(id).inbounds.find(inbound => inbound.port === link.tunnelPort);
                if (!expected || !profile.inbounds.some(inbound => key(inbound) === key(expected))) {
                    throw new FrozenTopologyDeploymentPlanError('TOPOLOGY_PROFILE_BASELINE_MISMATCH',
                        'The verified profile does not match its owned tunnel descriptors; import is required');
                }
            }
        }
    }
    const order = [...(newPlan?.nodes || []).map(node => node.node),
        ...[...usedIds].filter(id => !newConfigs.has(id)).sort()];
    const entries = after.links.map(link => ({ id: link.id, link, source: link.source, target: link.target }));
    const linkMetadataById = uniqueById(after.links, 'LINK_METADATA');
    const nodes = order.map(id => {
        const node = nodesById.get(id);
        const nodeConfig = projectNodeConfig(node, node, refs.get(id));
        let config = newConfigs.get(id);
        if (!config) config = isolatedProfileConfig(node, refs.get(id));
        if (node.role !== 'portal') config = stripServerInbounds(config, nodeConfig);
        // A removed final egress must still accept the installed loopback PPP
        // path and block it. Removing that listener can expose a default path
        // in a separately preserved PPP fragment and is not a no-route plan.
        const missingIngress = (oldConfigs.get(id)?.inbounds || [])
            .filter(inbound => inbound.tag?.startsWith('cascade-')
                && !config.inbounds.some(current => current.tag === inbound.tag));
        config.inbounds.push(...structuredClone(missingIngress));
        // Explicit no-exit PPP must win even for reverse-handshake domains.
        // Keep this block scoped to the retired ingress; transit and other
        // owners still follow the existing handshake/geo/default rule order.
        config.routing.rules.unshift(...missingIngress.map(inbound => ({
            type: 'field', inboundTag: [inbound.tag], outboundTag: 'block',
        })));
        configGenerator.ensurePrivateIpBlock(config);
        const profileConfig = beforeNodes.get(id)?.profileConfig;
        if (profileConfig !== undefined) {
            config = preserveProfileConfig(profileConfig, oldConfigs.get(id), config,
                node.role === 'portal' ? clientInboundTags(nodeConfig) : []);
        }
        return candidateForNode({ nodeId: id, node, nodeRef: refs.get(id), orderedLinks: entries,
            linkMetadataById, config: composeXrayConfig(config, []),
            previousListeningPorts: before.links
                .filter(link => (link.mode === 'reverse' ? link.source : link.target) === id)
                .map(link => assertPort(link.tunnelPort)),
            ingressPorts: config.inbounds.filter(inbound => inbound.tag?.startsWith('cascade-')).map(inbound => inbound.port) });
    });
    return deepFreeze({ schemaVersion: 1, mode: newPlan?.mode ?? oldPlan?.mode ?? 'mixed',
        ...(newPlan?.staged === true || after.links.length === 0 ? { staged: true } : {}), nodes });
}

function composeFrozenTopologyDeploymentPlan({
    snapshot,
    nodeMetadata = [],
    linkMetadata = [],
    compiledTopology,
    staged = false,
    nodeRefsById,
    linkRefsById,
    baselineTopology,
    hopByHop = false,
} = {}) {
    if (compiledTopology?.valid !== true || !Array.isArray(compiledTopology.relays)) {
        throw new FrozenTopologyDeploymentPlanError(
            'INVALID_COMPILED_TOPOLOGY',
            'A valid compiled topology is required',
        );
    }
    if (baselineTopology !== undefined) return composeDescriptorTransition(baselineTopology, snapshot);
    const nodeMetadataById = uniqueById(nodeMetadata, 'NODE_METADATA');
    const linkMetadataById = uniqueById(linkMetadata, 'LINK_METADATA');
    const components = staged === true ? connectedSnapshots(snapshot) : [];
    if (components.length > 1) {
        const nodeRoles = new Map(snapshot.nodes.map(node => [entityId(node), node.role]));
        const linkedIds = new Set(snapshot.links.flatMap(link => [entityId(link.source), entityId(link.target)]));
        const relayIds = new Set();
        for (const relay of compiledTopology.relays) {
            const id = entityId(relay.nodeId);
            if (nodeRoles.get(id) !== 'relay' || !linkedIds.has(id) || relayIds.has(id)) {
                throw new FrozenTopologyDeploymentPlanError('COMPILED_TOPOLOGY_MISMATCH',
                    'Compiled relay data must belong to the frozen topology');
            }
            relayIds.add(id);
        }
        const refs = nodeRefsById ?? componentRefs(snapshot);
        const linkRefs = linkRefsById ?? new Map([...snapshot.links].sort((a, b) => entityId(a).localeCompare(entityId(b), 'en'))
            .map((link, index) => [entityId(link), `link-${index + 1}`]));
        const plans = components.map(component => composeFrozenTopologyDeploymentPlan({
            snapshot: component, nodeMetadata, linkMetadata, staged,
            compiledTopology: { valid: true, relays: compiledTopology.relays.filter(relay =>
                component.nodes.some(node => entityId(node) === entityId(relay.nodeId))) },
            nodeRefsById: refs, linkRefsById: linkRefs,
            hopByHop,
        }));
        return deepFreeze({ schemaVersion: 1,
            mode: new Set(plans.map(plan => plan.mode)).size === 1 ? plans[0].mode : 'mixed',
            ...(plans.some(plan => plan.staged === true) ? { staged: true } : {}),
            nodes: plans.flatMap(plan => plan.nodes) });
    }

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
        // Fail closed at compose time: a reality link with incomplete
        // parameters would produce an xray config that cannot start,
        // triggering a node-side rollout and rollback mid-deploy.
        if (metadata.tunnelSecurity === 'reality') {
            const missing = [];
            if (typeof metadata.realityDest !== 'string' || metadata.realityDest.length === 0) missing.push('realityDest');
            if (typeof metadata.realityPrivateKey !== 'string' || metadata.realityPrivateKey.length === 0) missing.push('realityPrivateKey');
            if (typeof metadata.realityPublicKey !== 'string' || metadata.realityPublicKey.length === 0) missing.push('realityPublicKey');
            // realityShortIds may legitimately be empty (server accepts any
            // short id), so it is not part of the fail-closed guard.
            if (missing.length > 0) {
                throw new FrozenTopologyDeploymentPlanError(
                    'INCOMPLETE_REALITY_PARAMETERS',
                    `Reality link is missing required parameters: ${missing.join(', ')}`,
                );
            }
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

    // Staging is an explicit scoped-mutation permission, not readiness. Walk
    // linked nodes only: a detached portal/bridge cannot complete a path, and
    // a geo bridge is not an implicit default exit. Complete graphs keep
    // their existing builders; incomplete endpoints use hop-by-hop routing.
    const chain = selectChainShape(snapshot, geoLeafLinkIds, staged === true);
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

    const refs = nodeRefsById ?? (chain.fanIn === true
        ? topologyFanInRefs(chain)
        : topologyRefs(chain.orderedNodes, chain.geoLeafNodes));
    // Mixed-mode domains (and fan-in domains with any reverse link) are built
    // hop-by-hop; uniform domains keep their legacy builders. Staged chains
    // are always built hop-by-hop with terminal relays routing unmatched
    // transit to `block`, while explicitly permitted bridges remain exits.
    const useMixedBuilder = hopByHop === true || chain.staged === true
        || chain.mode === 'mixed'
        || (chain.fanIn === true && chain.mode !== 'forward');
    let candidateConfigsById;
    let ingressByNodeId;
    try {
        ({ configs: candidateConfigsById, ingressByNodeId } = (useMixedBuilder
            ? buildMixedCandidateConfigs
            : chain.fanIn === true
                ? buildFanInCandidateConfigs
                : buildCandidateConfigs)({
            chain,
            refs,
            nodeMetadataById,
            linkMetadataById,
            linkRefsById,
            groups: snapshot.groups,
            ...(chain.staged === true ? { terminalEgressTag: 'block' } : {}),
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
    // deploy alongside the default bridge. Fan-in domains order chain nodes
    // by distance to the sink instead of a linear reverse. Mixed domains use
    // a per-link listener-first topological order instead.
    let deploymentOrder;
    if (useMixedBuilder) {
        const orderIds = mixedDeploymentOrder(chain);
        const byId = new Map(
            [...chain.orderedNodes, ...chain.geoLeafNodes].map(entry => [entry.id, entry]),
        );
        deploymentOrder = orderIds.map(id => byId.get(id));
    } else {
        const chainDeploymentNodes = chain.fanIn === true
            ? [...chain.orderedNodes].sort((left, right) => (
                (chain.distToSink.get(left.id) - chain.distToSink.get(right.id))
                || left.id.localeCompare(right.id, 'en')
            ))
            : [...chain.orderedNodes].reverse();
        deploymentOrder = chain.mode === 'forward'
            ? [...chain.geoLeafNodes, ...chainDeploymentNodes]
            : [...chain.orderedNodes, ...chain.geoLeafNodes];
    }
    const nodes = deploymentOrder.map(({ id, node }) => candidateForNode({
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
        ...(chain.staged === true ? { staged: true } : {}),
        nodes,
    });
}

module.exports = {
    FrozenTopologyDeploymentPlanError,
    TARGETS_BY_ROLE,
    composeFrozenTopologyDeploymentPlan,
};
