'use strict';

const {
    composeFrozenTopologyDeploymentPlan,
} = require('./frozenTopologyDeploymentPlanComposer');

const TEST_TOPOLOGY_TARGET = 'test';
const TEST_TOPOLOGY_HOST_IDENTITY = 'test.infograd.online';
const SUPPORTED_ROLES = Object.freeze(['portal', 'relay', 'bridge']);
const SUPPORTED_MODES = Object.freeze(['forward', 'reverse']);
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

function projectPinnedSnapshot(pinnedSnapshot) {
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
    const portalCount = nodes.filter(node => node.role === 'portal').length;
    const bridgeCount = nodes.filter(node => node.role === 'bridge').length;
    if (portalCount !== 1 || bridgeCount !== 1) {
        fail(
            'INVALID_TOPOLOGY_ROLES',
            'Pinned topology requires exactly one portal and one bridge',
        );
    }
    const links = topology.links.map(snapshotLink)
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    const relays = compiled.relays.map(relay => ({
        nodeId: assertSafeId(relay?.nodeId, 'UNSAFE_COMPILED_RELAY_IDENTITY'),
    })).sort((left, right) => left.nodeId.localeCompare(right.nodeId, 'en'));

    return {
        snapshot: { nodes, links },
        compiledTopology: { valid: true, relays },
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

    async materialize({ target, hostIdentity, pinnedSnapshot } = {}) {
        if (target !== TEST_TOPOLOGY_TARGET) {
            fail('UNSAFE_TOPOLOGY_TARGET', 'Topology operations are restricted to the test target');
        }
        if (hostIdentity !== TEST_TOPOLOGY_HOST_IDENTITY) {
            fail(
                'UNSAFE_TOPOLOGY_HOST_IDENTITY',
                'Topology operations are restricted to the fixed test host identity',
            );
        }

        const input = projectPinnedSnapshot(pinnedSnapshot);
        const nodeIds = input.snapshot.nodes.map(node => node.id);
        const linkIds = input.snapshot.links.map(link => link.id);
        let nodeRows;
        let linkRows;
        try {
            [nodeRows, linkRows] = await Promise.all([
                this.#HyNode.find({
                    ...NODE_METADATA_FILTER,
                    _id: { $in: nodeIds },
                }).select(NODE_METADATA_SELECT).lean(),
                this.#CascadeLink.find({
                    ...LINK_METADATA_FILTER,
                    _id: { $in: linkIds },
                }).select(LINK_METADATA_SELECT).lean(),
            ]);
        } catch {
            fail(
                'TOPOLOGY_METADATA_READ_FAILED',
                'Pinned topology metadata could not be loaded',
            );
        }

        return composeFrozenTopologyDeploymentPlan({
            ...input,
            nodeMetadata: projectNodeMetadata(nodeRows),
            linkMetadata: projectLinkMetadata(linkRows),
        });
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
