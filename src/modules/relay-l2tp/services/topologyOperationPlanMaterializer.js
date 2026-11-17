'use strict';

const {
    composeFrozenTopologyDeploymentPlan,
    projectXrayConfig,
} = require('./frozenTopologyDeploymentPlanComposer');
const { projectGroups } = require('../domain/topologyDraft');
const { isDeepStrictEqual } = require('node:util');
const { installedPrimaryReserve } = require('../domain/primaryReservePolicy');

const { topologyExecutionContext, TOPOLOGY_EXECUTION_CONTEXTS } = require('../domain/topologyExecutionContext');
const TEST_TOPOLOGY_TARGET = 'test';
const TEST_TOPOLOGY_HOST_IDENTITY = 'test.infograd.online';
const SUPPORTED_ROLES = Object.freeze(['portal', 'relay', 'bridge']);
const SUPPORTED_MODES = Object.freeze(['forward', 'reverse']);
const STAGED_OPERATION_KINDS = new Set(['link.apply', 'link.attach', 'link.replace', 'link.delete', 'domain.reconcile']);
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NODE_METADATA_FILTER = Object.freeze({
    type: 'xray',
    active: true,
    cascadeRole: Object.freeze({ $in: SUPPORTED_ROLES }),
});
const LINK_METADATA_FILTER = Object.freeze({ active: true });
const NODE_METADATA_SELECT = Object.freeze([
    '_id',
    'type',
    'active',
    'cascadeRole',
    'ip',
    'domain',
    'sni',
    'port',
    'xray.accessLogs.enabled',
    'xray.apiPort',
    'xray.inboundTag',
    'xray.transport',
    'xray.security',
    'xray.flow',
    'xray.alpn',
    'xray.realityDest',
    'xray.realitySni',
    'xray.realityPrivateKey',
    'xray.realityPublicKey',
    'xray.fingerprint',
    'xray.fingerprintPool',
    'xray.realityShortIds',
    'xray.realitySpiderX',
    'xray.wsPath',
    'xray.wsHost',
    'xray.grpcServiceName',
    'xray.xhttpPath',
    'xray.xhttpHost',
    'xray.xhttpMode',
    'xray.fallbackDest',
    'xray.extraInbounds',
    'xray.tlsSource',
    'xray.manualCert',
    '+xray.manualKey',
].join(' '));
const LINK_METADATA_SELECT = Object.freeze([
    '_id',
    'portalNode',
    'bridgeNode',
    'mode',
    'tunnelPort',
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
    'geoRouting',
    'realityDest',
    'realitySni',
    'realityPrivateKey',
    'realityPublicKey',
    'realityShortIds',
    'realityFingerprint',
].join(' '));
const LINK_CONFIG_FIELDS = Object.freeze([
    'tunnelPort',
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
    'geoRouting',
    'realityDest',
    'realitySni',
    'realityPrivateKey',
    'realityPublicKey',
    'realityShortIds',
    'realityFingerprint',
]);

class TopologyOperationPlanMaterializerError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'TopologyOperationPlanMaterializerError';
        this.code = code;
    }
}

function fail(code, message) {
    throw new TopologyOperationPlanMaterializerError(code, message);
}

function assertSafeId(value, code) {
    if (typeof value !== 'string' || !SAFE_ID_PATTERN.test(value)) {
        fail(code, 'The pinned topology contains an unsafe identity');
    }
    return value;
}

function rowId(row, code) {
    const value = row?._id ?? row?.id;
    if (value === undefined || value === null) fail(code, 'Pinned topology metadata is incomplete');
    return assertSafeId(String(value), code);
}

function snapshotNode(node) {
    const id = assertSafeId(node?.id, 'UNSAFE_TOPOLOGY_NODE_IDENTITY');
    if (!SUPPORTED_ROLES.includes(node?.role)) {
        fail('UNSAFE_TOPOLOGY_NODE_ROLE', 'Every pinned topology node requires a supported role');
    }
    return { id, role: node.role };
}

function snapshotLink(link) {
    const id = assertSafeId(link?.id, 'UNSAFE_TOPOLOGY_LINK_IDENTITY');
    const source = assertSafeId(link?.source, 'UNSAFE_TOPOLOGY_LINK_ENDPOINT');
    const target = assertSafeId(link?.target, 'UNSAFE_TOPOLOGY_LINK_ENDPOINT');
    if (!SUPPORTED_MODES.includes(link?.mode)) {
        fail('UNSAFE_TOPOLOGY_LINK_MODE', 'Every pinned topology link requires a supported mode');
    }
    return { id, source, target, mode: link.mode };
}

function projectPinnedGroups(groups) {
    return projectGroups(groups).map(group => {
        const id = assertSafeId(group._id, 'UNSAFE_TOPOLOGY_GROUP_IDENTITY');
        return {
            ...group,
            _id: id,
            paths: group.paths.map(path => ({
                ...path,
                pathKey: assertSafeId(path.pathKey, 'UNSAFE_TOPOLOGY_GROUP_IDENTITY'),
                linkIds: path.linkIds.map(linkId => (
                    assertSafeId(linkId, 'UNSAFE_TOPOLOGY_GROUP_IDENTITY')
                )),
            })),
        };
    }).sort((left, right) => left._id.localeCompare(right._id, 'en'));
}

function projectPinnedSnapshot(pinnedSnapshot, operationKind) {
    const topology = pinnedSnapshot?.topology;
    const compiled = pinnedSnapshot?.compiled;
    if (!topology || !Array.isArray(topology.nodes) || !Array.isArray(topology.links)) {
        fail('INVALID_PINNED_TOPOLOGY', 'A pinned topology snapshot is required');
    }
    if (!compiled || compiled.valid !== true || !Array.isArray(compiled.relays)) {
        fail('INVALID_PINNED_TOPOLOGY', 'A compiled pinned topology snapshot is required');
    }

    const nodes = topology.nodes.map(snapshotNode)
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    // Fan-in domains legitimately contain multiple portals; the composer
    // (orderedChain / orderedFanInChain) performs the authoritative shape
    // validation. Here we only require the graph to be deployable at all.
    const portalCount = nodes.filter(node => node.role === 'portal').length;

    // Only an explicit scoped mutation may compose incomplete endpoints. Pass
    // permission, not a readiness inference from all roled assets: the
    // composer checks linked nodes and the actual default path itself.
    const incomplete = portalCount === 0 || !nodes.some(node => node.role === 'bridge');
    if (incomplete && !STAGED_OPERATION_KINDS.has(operationKind)) {
        fail('INVALID_TOPOLOGY_ROLES', 'Only an explicit scoped mutation may stage an incomplete chain');
    }
    const links = topology.links.map(snapshotLink)
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    const groups = projectPinnedGroups(topology.groups);
    const relays = compiled.relays.map(relay => ({
        nodeId: assertSafeId(relay?.nodeId, 'UNSAFE_COMPILED_RELAY_IDENTITY'),
        ...(relay.routeGroups ? { routeGroups: structuredClone(relay.routeGroups) } : {}),
    })).sort((left, right) => left.nodeId.localeCompare(right.nodeId, 'en'));

    return {
        snapshot: { nodes, links, groups },
        compiledTopology: { valid: true, relays },
        staged: STAGED_OPERATION_KINDS.has(operationKind),
    };
}

function projectNodeMetadata(rows) {
    return (rows || []).map(row => {
        const id = rowId(row, 'UNSAFE_NODE_METADATA_IDENTITY');
        const role = row?.cascadeRole ?? row?.role;
        if (!SUPPORTED_ROLES.includes(role)) {
            fail('UNSAFE_NODE_METADATA_ROLE', 'Hydrated topology node metadata requires a supported role');
        }
        return {
            id,
            role,
            type: row?.type,
            active: row?.active,
            ip: row?.ip,
            domain: row?.domain,
            sni: row?.sni,
            port: row?.port,
            xray: row?.xray === undefined ? undefined : structuredClone(row.xray),
        };
    }).sort((left, right) => left.id.localeCompare(right.id, 'en'));
}

function projectLinkMetadata(rows) {
    return (rows || []).map(row => {
        const id = rowId(row, 'UNSAFE_LINK_METADATA_IDENTITY');
        const source = row?.portalNode ?? row?.source;
        const target = row?.bridgeNode ?? row?.target;
        if (source === undefined || source === null || target === undefined || target === null) {
            fail('UNSAFE_LINK_METADATA_ENDPOINT', 'Hydrated topology link metadata is incomplete');
        }
        const mode = row?.mode;
        if (!SUPPORTED_MODES.includes(mode)) {
            fail('UNSAFE_LINK_METADATA_MODE', 'Hydrated topology link metadata requires a supported mode');
        }
        const projected = {
            id,
            source: assertSafeId(String(source), 'UNSAFE_LINK_METADATA_ENDPOINT'),
            target: assertSafeId(String(target), 'UNSAFE_LINK_METADATA_ENDPOINT'),
            mode,
        };
        for (const field of LINK_CONFIG_FIELDS) {
            if (row[field] !== undefined) projected[field] = structuredClone(row[field]);
        }
        return projected;
    }).sort((left, right) => left.id.localeCompare(right.id, 'en'));
}

// Internal admission input only. These are complete, verified applied/effective
// descriptors, not HTTP authority and not IDs to hydrate from mutable desired.
function descriptorTopology(value) {
    function assertJson(item) {
        if (item === null || typeof item === 'string' || typeof item === 'boolean') return;
        if (typeof item === 'number' && Number.isFinite(item)) return;
        if (Array.isArray(item)) { item.forEach(assertJson); return; }
        if (item && Object.getPrototypeOf(item) === Object.prototype) {
            Object.values(item).forEach(assertJson);
            return;
        }
        fail('INVALID_TOPOLOGY_DESCRIPTORS', 'Topology descriptors must be complete JSON snapshots');
    }
    try { assertJson(value); } catch {
        fail('INVALID_TOPOLOGY_DESCRIPTORS', 'Topology descriptors must be complete JSON snapshots');
    }
    if (!value || !['nodes', 'links', 'groups'].every(key => Array.isArray(value[key]))) {
        fail('INVALID_TOPOLOGY_DESCRIPTORS', 'Both topology descriptor snapshots are required');
    }
    const snapshot = structuredClone(value);
    const nodeIds = new Set();
    const linkIds = new Set();
    for (const node of snapshot.nodes) {
        snapshotNode(node);
        if (nodeIds.has(node.id)) fail('INVALID_TOPOLOGY_DESCRIPTORS', 'Descriptor identities must be unique');
        nodeIds.add(node.id);
    }
    for (const link of snapshot.links) {
        snapshotLink(link);
        if (linkIds.has(link.id) || !nodeIds.has(link.source) || !nodeIds.has(link.target)) {
            fail('INVALID_TOPOLOGY_DESCRIPTORS', 'Descriptor links require unique known endpoints');
        }
        linkIds.add(link.id);
    }
    projectPinnedGroups(snapshot.groups);
    return snapshot;
}

function descriptorInstalledPath(value, before, after) {
    if (value === undefined) return undefined;
    const groupId = assertSafeId(value?.groupId, 'TOPOLOGY_INSTALLED_PATH_MISMATCH');
    const pathKey = assertSafeId(value?.pathKey, 'TOPOLOGY_INSTALLED_PATH_MISMATCH');
    const ownerNodeId = assertSafeId(value?.ownerNodeId, 'TOPOLOGY_INSTALLED_PATH_MISMATCH');
    const owner = after.nodes.find(node => node.id === ownerNodeId) || before.nodes.find(node => node.id === ownerNodeId);
    if (value.preserveGroupPaths === true) {
        const policy = installedPrimaryReserve(after, value);
        const old = before.groups.find(group => String(group.id ?? group._id) === groupId)
            ?.paths.find(path => path.pathKey === pathKey);
        if (owner?.role !== 'relay' || !old || !isDeepStrictEqual(old.linkIds, value.oldPathLinkIds)
            || !isDeepStrictEqual(policy.selected?.path.linkIds || [], value.newPathLinkIds)) {
            fail('TOPOLOGY_INSTALLED_PATH_MISMATCH', 'Installed policy must match the frozen descriptors');
        }
        return { groupId, pathKey, ownerNodeId };
    }
    const path = topology => topology.groups.find(group => String(group.id ?? group._id) === groupId)
        ?.paths.find(path => path.pathKey === pathKey);
    const beforeGroup = before.groups.find(group => String(group.id ?? group._id) === groupId);
    const oldPath = path(before), newPath = path(after);
    // readSelected explicitly supports an installed owner whose path has not
    // yet been inserted. Preserve that actual absent before-descriptor; it is
    // not a kept-empty path and must not acquire fabricated old membership.
    if (owner?.role !== 'relay' || !beforeGroup || !newPath || oldPath?.enabled === false || newPath.enabled === false
        || !isDeepStrictEqual(oldPath?.linkIds || [], value.oldPathLinkIds)
        || !isDeepStrictEqual(newPath.linkIds, value.newPathLinkIds)) {
        fail('TOPOLOGY_INSTALLED_PATH_MISMATCH', 'Installed owner/path must match the trusted before and after descriptors');
    }
    return { groupId, pathKey, ownerNodeId };
}

function descriptorIdentity(topology) {
    return {
        nodes: topology.nodes.map(snapshotNode).sort((a, b) => a.id.localeCompare(b.id, 'en')),
        links: topology.links.map(snapshotLink).sort((a, b) => a.id.localeCompare(b.id, 'en')),
        groups: projectPinnedGroups(topology.groups),
    };
}

class TopologyOperationPlanMaterializer {
    #HyNode;

    #CascadeLink;

    constructor({ HyNode, CascadeLink } = {}) {
        if (!HyNode || typeof HyNode.find !== 'function') {
            throw new TypeError('Topology operation plan materializer requires HyNode.find');
        }
        if (!CascadeLink || typeof CascadeLink.find !== 'function') {
            throw new TypeError('Topology operation plan materializer requires CascadeLink.find');
        }
        this.#HyNode = HyNode;
        this.#CascadeLink = CascadeLink;
    }

    async materialize({ target, hostIdentity, pinnedSnapshot, operationKind, session,
        baselineTopology, effectiveTopology, installedPath, selectedOwnerPins } = {}) {
        if (!TOPOLOGY_EXECUTION_CONTEXTS.some(context => context.target === target)) {
            fail('UNSAFE_TOPOLOGY_TARGET', 'Topology operations require an allowlisted server target');
        }
        if (!topologyExecutionContext(target, hostIdentity)) {
            fail(
                'UNSAFE_TOPOLOGY_HOST_IDENTITY',
                'Topology operations require an exact allowlisted server host identity',
            );
        }

        if (operationKind === 'link.delete' && (baselineTopology === undefined || effectiveTopology === undefined)) {
            fail('TOPOLOGY_DELETE_BASELINE_REQUIRED', 'Deletion requires trusted before and after descriptors');
        }
        const input = projectPinnedSnapshot(pinnedSnapshot, operationKind);
        if (baselineTopology !== undefined || effectiveTopology !== undefined) {
            const before = descriptorTopology(baselineTopology);
            const after = descriptorTopology(effectiveTopology);
            if (!isDeepStrictEqual(descriptorIdentity(after), input.snapshot)) {
                fail('TOPOLOGY_DESCRIPTOR_MISMATCH', 'Effective descriptors must match the pinned topology');
            }
            return composeFrozenTopologyDeploymentPlan({
                ...input,
                executionContext: topologyExecutionContext(target, hostIdentity),
                snapshot: after,
                nodeMetadata: after.nodes,
                linkMetadata: after.links,
                baselineTopology: before,
                installedPath: descriptorInstalledPath(installedPath, before, after),
                selectedOwnerPins,
            });
        }
        if (selectedOwnerPins?.some(pin => Object.hasOwn(pin, 'profileTargetPin'))) {
            fail('TOPOLOGY_PROFILE_TARGET_INVALID', 'Imported targets require trusted before and after descriptors');
        }
        const nodeIds = input.snapshot.nodes.map(node => node.id);
        const linkIds = input.snapshot.links.map(link => link.id);
        let nodeRows;
        let linkRows;
        try {
            if (session !== undefined && (
                typeof session?.inTransaction !== 'function' || session.inTransaction() !== true
            )) {
                throw new TypeError('An active transaction is required for session-bound metadata reads');
            }
            const nodeQuery = this.#HyNode.find({
                ...NODE_METADATA_FILTER,
                _id: { $in: nodeIds },
            }).select(NODE_METADATA_SELECT);
            const linkQuery = this.#CascadeLink.find({
                ...LINK_METADATA_FILTER,
                _id: { $in: linkIds },
            }).select(LINK_METADATA_SELECT);
            if (session !== undefined) {
                // MongoDB sessions cannot execute concurrent operations. Require
                // both injected queries to support session binding before reading.
                if (typeof nodeQuery.session !== 'function'
                    || typeof linkQuery.session !== 'function') {
                    throw new TypeError('Session-bound topology metadata reads are unavailable');
                }
                const sessionNodeQuery = nodeQuery.session(session);
                const sessionLinkQuery = linkQuery.session(session);
                nodeRows = await sessionNodeQuery.lean();
                linkRows = await sessionLinkQuery.lean();
            } else {
                [nodeRows, linkRows] = await Promise.all([
                    nodeQuery.lean(),
                    linkQuery.lean(),
                ]);
            }
        } catch {
            fail(
                'TOPOLOGY_METADATA_READ_FAILED',
                'Pinned topology metadata could not be loaded',
            );
        }

        const nodeMetadata = projectNodeMetadata(nodeRows);
        const linkMetadata = projectLinkMetadata(linkRows);
        const plan = composeFrozenTopologyDeploymentPlan({
            ...input,
            executionContext: topologyExecutionContext(target, hostIdentity),
            nodeMetadata,
            linkMetadata,
        });
        if (operationKind !== undefined && operationKind !== 'domain.reconcile') return plan;
        // Capture the exact same-session descriptors used above, BEFORE any
        // dispatch. Full sync must not later reconstruct applied geometry from
        // mutable desired rows or require a prior selected operation.
        const fullTopology = JSON.parse(JSON.stringify({
            nodes: nodeMetadata.map(node => ({ ...node, xray: projectXrayConfig(node) })),
            links: linkMetadata.map(link => Object.fromEntries(Object.entries(link)
                .filter(([key]) => link.tunnelSecurity === 'reality' || !key.startsWith('reality')))),
            groups: input.snapshot.groups,
        }));
        return require('../models/topologyExecutionBindingContract').freeze({ ...plan, fullTopology });
    }
}

module.exports = {
    LINK_METADATA_FILTER,
    LINK_METADATA_SELECT,
    NODE_METADATA_FILTER,
    NODE_METADATA_SELECT,
    TEST_TOPOLOGY_HOST_IDENTITY,
    TEST_TOPOLOGY_TARGET,
    TopologyOperationPlanMaterializer,
    TopologyOperationPlanMaterializerError,
};
