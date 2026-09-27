'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    LINK_METADATA_FILTER,
    LINK_METADATA_SELECT,
    NODE_METADATA_FILTER,
    NODE_METADATA_SELECT,
    TEST_TOPOLOGY_HOST_IDENTITY,
    TEST_TOPOLOGY_TARGET,
    TopologyOperationPlanMaterializer,
} = require('../services/topologyOperationPlanMaterializer');
const {
    cascadePathIngressPort,
} = require('../domain/cascadePathIngress');

const SECRET_CANARIES = Object.freeze([
    'node-ssh-password-canary',
    'node-private-key-canary',
    'node-config-secret-canary',
    'link-tunnel-uuid-canary',
    'link-private-key-canary',
    'raw-command-canary',
]);

function createReadModel(rows, label) {
    const calls = [];
    const writes = [];
    const rejectWrite = method => async (...args) => {
        writes.push({ method, args });
        assert.fail(`${label}.${method} must not be called`);
    };
    return {
        calls,
        writes,
        find(filter) {
            calls.push({ method: 'find', filter });
            return {
                select(paths) {
                    calls.push({ method: 'select', paths });
                    return this;
                },
                async lean() {
                    calls.push({ method: 'lean' });
                    return structuredClone(rows);
                },
            };
        },
        create: rejectWrite('create'),
        updateOne: rejectWrite('updateOne'),
        findOneAndUpdate: rejectWrite('findOneAndUpdate'),
        deleteOne: rejectWrite('deleteOne'),
    };
}

function pinnedSnapshot() {
    return {
        revision: 17,
        topology: {
            nodes: [
                { id: 'relay-1', role: 'relay', password: SECRET_CANARIES[0] },
                { id: 'bridge-1', role: 'bridge', command: SECRET_CANARIES[5] },
                { id: 'portal-1', role: 'portal', privateKey: SECRET_CANARIES[1] },
            ],
            links: [
                {
                    id: 'relay-bridge',
                    source: 'relay-1',
                    target: 'bridge-1',
                    mode: 'reverse',
                    tunnelUuid: SECRET_CANARIES[3],
                },
                {
                    id: 'portal-relay',
                    source: 'portal-1',
                    target: 'relay-1',
                    mode: 'reverse',
                    rawCommand: SECRET_CANARIES[5],
                },
            ],
            groups: [{
                _id: 'group-1',
                mode: 'reverse',
                strategy: 'priority-failover',
                secret: SECRET_CANARIES[2],
                shell: SECRET_CANARIES[5],
                paths: [{
                    pathKey: 'main',
                    linkIds: ['portal-relay', 'relay-bridge'],
                    priority: 1,
                    enabled: true,
                    password: SECRET_CANARIES[0],
                }],
            }],
        },
        compiled: {
            valid: true,
            errors: [],
            relays: [{
                nodeId: 'relay-1',
                routeGroups: [{ secret: SECRET_CANARIES[2], command: SECRET_CANARIES[5] }],
            }],
            generatedConfig: SECRET_CANARIES[2],
        },
        ssh: { password: SECRET_CANARIES[0] },
    };
}

function metadataRows() {
    return {
        nodes: [
            {
                _id: 'bridge-1',
                type: 'xray',
                active: true,
                cascadeRole: 'bridge',
                ip: '192.0.2.30',
                domain: 'bridge.example.test',
                port: 24443,
                xray: {
                    apiPort: 61003,
                    inboundTag: 'client-bridge',
                    transport: 'tcp',
                    security: 'none',
                },
                ssh: { privateKey: SECRET_CANARIES[1], password: SECRET_CANARIES[0] },
            },
            {
                _id: 'portal-1',
                type: 'xray',
                active: true,
                cascadeRole: 'portal',
                ip: '192.0.2.10',
                domain: 'portal.example.test',
                port: 20443,
                xray: {
                    accessLogs: { enabled: true },
                    apiPort: 61001,
                    inboundTag: 'client-portal',
                    transport: 'tcp',
                    security: 'none',
                    extraInbounds: [{
                        id: 'portal-extra',
                        label: 'Portal extra',
                        port: 21443,
                        inboundTag: 'client-portal-extra',
                        transport: 'ws',
                        security: 'none',
                        wsPath: '/extra',
                        rawCommand: SECRET_CANARIES[5],
                    }],
                    agentToken: SECRET_CANARIES[2],
                },
                customConfig: SECRET_CANARIES[2],
            },
            {
                _id: 'relay-1',
                type: 'xray',
                active: true,
                cascadeRole: 'relay',
                ip: '192.0.2.20',
                domain: 'relay.example.test',
                port: 22443,
                xray: {
                    apiPort: 61002,
                    inboundTag: 'client-relay',
                    transport: 'tcp',
                    security: 'none',
                },
                initScript: SECRET_CANARIES[5],
            },
        ],
        links: [
            {
                _id: 'portal-relay',
                portalNode: 'portal-1',
                bridgeNode: 'relay-1',
                mode: 'reverse',
                tunnelPort: 12001,
                tunnelDomain: 'reverse.example.test',
                tunnelProtocol: 'vless',
                tunnelSecurity: 'none',
                tunnelTransport: 'tcp',
                tunnelUuid: SECRET_CANARIES[3],
            },
            {
                _id: 'relay-bridge',
                portalNode: 'relay-1',
                bridgeNode: 'bridge-1',
                mode: 'reverse',
                tunnelPort: 12002,
                tunnelDomain: 'reverse.example.test',
                tunnelProtocol: 'vless',
                tunnelSecurity: 'none',
                tunnelTransport: 'tcp',
                realityPrivateKey: SECRET_CANARIES[4],
            },
        ],
    };
}

function createMaterializer(rows = metadataRows()) {
    const HyNode = createReadModel(rows.nodes, 'HyNode');
    const CascadeLink = createReadModel(rows.links, 'CascadeLink');
    return {
        HyNode,
        CascadeLink,
        materializer: new TopologyOperationPlanMaterializer({ HyNode, CascadeLink }),
    };
}

function isDeepFrozen(value) {
    if (value === null || typeof value !== 'object') return true;
    return Object.isFrozen(value) && Object.values(value).every(isDeepFrozen);
}

test('materializes one deterministic frozen test plan from allowlisted snapshot reads', async () => {
    const { HyNode, CascadeLink, materializer } = createMaterializer();

    const plan = await materializer.materialize({
        target: 'test',
        hostIdentity: 'test.infograd.online',
        pinnedSnapshot: pinnedSnapshot(),
    });

    assert.equal(TEST_TOPOLOGY_TARGET, 'test');
    assert.equal(TEST_TOPOLOGY_HOST_IDENTITY, 'test.infograd.online');
    assert.equal(isDeepFrozen(plan), true);
    assert.deepEqual(Object.keys(plan).sort(), ['mode', 'nodes', 'schemaVersion']);
    assert.deepEqual(plan.nodes.map(node => node.nodeRef), ['portal', 'relay-1', 'bridge']);
    assert.deepEqual(plan.nodes.map(node => node.role), ['portal', 'relay', 'bridge']);
    for (const node of plan.nodes) {
        const bytes = Buffer.from(node.candidate.bytes);
        assert.equal(node.candidate.sha256, createHash('sha256').update(bytes).digest('hex'));
        const config = JSON.parse(bytes.toString('utf8'));
        assert.ok(Array.isArray(config.inbounds));
        assert.ok(Array.isArray(config.outbounds));
        assert.ok(config.routing && Array.isArray(config.routing.rules));
    }
    const portal = JSON.parse(Buffer.from(plan.nodes[0].candidate.bytes).toString('utf8'));
    const relay = JSON.parse(Buffer.from(plan.nodes[1].candidate.bytes).toString('utf8'));
    const bridge = JSON.parse(Buffer.from(plan.nodes[2].candidate.bytes).toString('utf8'));
    assert(portal.inbounds.some(inbound => inbound.tag === 'API_INBOUND'));
    assert.equal(relay.inbounds.some(inbound => inbound.tag === 'API_INBOUND'), false);
    assert.equal(bridge.inbounds.some(inbound => inbound.tag === 'API_INBOUND'), false);
    // Route groups survive projection: the relay candidate carries a per-path
    // socks ingress for the enabled path routed through its downstream link.
    const socksIngress = relay.inbounds.find(inbound => inbound.tag === 'cascade-main');
    assert.deepEqual(socksIngress, {
        tag: 'cascade-main',
        listen: '127.0.0.1',
        port: cascadePathIngressPort('group-1', 'main'),
        protocol: 'socks',
        settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' },
    });
    assert(relay.routing.rules.some(rule => (
        rule.inboundTag?.includes('cascade-main') && rule.outboundTag === 'portal-down-link-2'
    )));
    assert.equal(portal.inbounds.some(inbound => inbound.protocol === 'socks'), false);
    assert.equal(bridge.inbounds.some(inbound => inbound.protocol === 'socks'), false);
    assert(portal.inbounds.some(inbound => (
        inbound.tag === 'client-portal' && inbound.port === 20443
    )));
    assert(portal.inbounds.some(inbound => (
        inbound.tag === 'client-portal-extra' && inbound.port === 21443
    )));
    assert(portal.inbounds.some(inbound => inbound.tag === 'bridge-conn-link-1'));
    assert.equal(portal.reverse.portals[0].domain, 'link-1.reverse.example.test');

    const serialized = JSON.stringify(plan);
    for (const secret of SECRET_CANARIES) assert.equal(serialized.includes(secret), false);
    assert.doesNotMatch(
        serialized,
        /password|privateKey|configSecret|tunnelUuid|rawCommand|command|shell|ssh/i,
    );

    assert.deepEqual(HyNode.calls, [
        {
            method: 'find',
            filter: {
                ...NODE_METADATA_FILTER,
                _id: { $in: ['bridge-1', 'portal-1', 'relay-1'] },
            },
        },
        { method: 'select', paths: NODE_METADATA_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(CascadeLink.calls, [
        {
            method: 'find',
            filter: {
                ...LINK_METADATA_FILTER,
                _id: { $in: ['portal-relay', 'relay-bridge'] },
            },
        },
        { method: 'select', paths: LINK_METADATA_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(HyNode.writes, []);
    assert.deepEqual(CascadeLink.writes, []);
    assert.doesNotMatch(NODE_METADATA_SELECT, /ssh|customConfig|initScript|agentToken/i);
    assert.doesNotMatch(LINK_METADATA_SELECT, /tunnelUuid|rawCommand/i);

    await Promise.resolve();
    assert.equal(HyNode.calls.filter(call => call.method === 'find').length, 1);
    assert.equal(CascadeLink.calls.filter(call => call.method === 'find').length, 1);
});

test('hydrates Reality tunnel security through the allowlisted projection', async () => {
    const rows = metadataRows();
    rows.links[0].tunnelSecurity = 'reality';
    rows.links[0].realityPrivateKey = SECRET_CANARIES[4];
    rows.links[0].realityPublicKey = 'reality-public-key';
    rows.links[0].realityDest = 'dl.google.com:443';
    rows.links[0].realitySni = ['dl.google.com'];
    const { HyNode, CascadeLink, materializer } = createMaterializer(rows);

    const plan = await materializer.materialize({
        target: TEST_TOPOLOGY_TARGET,
        hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
        pinnedSnapshot: pinnedSnapshot(),
    });

    // The portal candidate needs the reality private key to terminate the
    // tunnel — it is hydrated only through the allowlisted link fields.
    const portalNode = plan.nodes.find(node => node.role === 'portal');
    const portalConfig = JSON.parse(Buffer.from(portalNode.candidate.bytes).toString('utf8'));
    const realityInbound = portalConfig.inbounds.find(inbound =>
        inbound.streamSettings?.security === 'reality');
    assert.ok(realityInbound, 'portal candidate terminates the reality tunnel');
    assert.equal(
        realityInbound.streamSettings.realitySettings.privateKey,
        SECRET_CANARIES[4],
    );
    assert.equal(CascadeLink.calls.some(call => call.method === 'lean'), true);
    assert.deepEqual(HyNode.writes, []);
    assert.deepEqual(CascadeLink.writes, []);
});

test('sanitizes metadata read failures without returning database or secret details', async () => {
    const secret = 'database-password-canary';
    const HyNode = createReadModel(metadataRows().nodes, 'HyNode');
    const CascadeLink = {
        find() {
            return {
                select() {
                    return this;
                },
                async lean() {
                    throw new Error(`database unavailable: ${secret}`);
                },
            };
        },
    };
    const materializer = new TopologyOperationPlanMaterializer({ HyNode, CascadeLink });

    await assert.rejects(
        materializer.materialize({
            target: TEST_TOPOLOGY_TARGET,
            hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
            pinnedSnapshot: pinnedSnapshot(),
        }),
        error => {
            assert.equal(error.name, 'TopologyOperationPlanMaterializerError');
            assert.equal(error.code, 'TOPOLOGY_METADATA_READ_FAILED');
            assert.equal(error.message, 'Pinned topology metadata could not be loaded');
            assert.equal(Object.hasOwn(error, 'cause'), false);
            assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
            return true;
        },
    );
    assert.deepEqual(HyNode.writes, []);
});

test('rejects missing, unsafe, non-test, and invalid role identities before metadata reads', async () => {
    const cases = [
        {
            name: 'missing target',
            input: { target: undefined, hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            code: 'UNSAFE_TOPOLOGY_TARGET',
        },
        {
            name: 'non-test target',
            input: { target: 'production', hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            code: 'UNSAFE_TOPOLOGY_TARGET',
        },
        {
            name: 'missing host identity',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: undefined },
            code: 'UNSAFE_TOPOLOGY_HOST_IDENTITY',
        },
        {
            name: 'coercible host identity',
            input: {
                target: TEST_TOPOLOGY_TARGET,
                hostIdentity: { toString: () => TEST_TOPOLOGY_HOST_IDENTITY },
            },
            code: 'UNSAFE_TOPOLOGY_HOST_IDENTITY',
        },
        {
            name: 'non-test host identity',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: 'panel.infograd.online' },
            code: 'UNSAFE_TOPOLOGY_HOST_IDENTITY',
        },
        {
            name: 'missing node role',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            mutate(snapshot) {
                delete snapshot.topology.nodes[0].role;
            },
            code: 'UNSAFE_TOPOLOGY_NODE_ROLE',
        },
        {
            name: 'non-topology node role',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            mutate(snapshot) {
                snapshot.topology.nodes[0].role = 'standalone';
            },
            code: 'UNSAFE_TOPOLOGY_NODE_ROLE',
        },
        // NOTE: multi-portal topologies are legitimate (fan-in domains) — the
        // materializer no longer rejects them; shape validation lives in the
        // composer (covered by frozenTopologyDeploymentPlanComposer tests).
        {
            name: 'unsafe route group identity',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            mutate(snapshot) {
                snapshot.topology.groups[0]._id = 'group with spaces';
            },
            code: 'UNSAFE_TOPOLOGY_GROUP_IDENTITY',
        },
        {
            name: 'missing route group identity',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            mutate(snapshot) {
                delete snapshot.topology.groups[0]._id;
            },
            code: 'UNSAFE_TOPOLOGY_GROUP_IDENTITY',
        },
        {
            name: 'unsafe route group path key',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            mutate(snapshot) {
                snapshot.topology.groups[0].paths[0].pathKey = 'main; rm -rf /';
            },
            code: 'UNSAFE_TOPOLOGY_GROUP_IDENTITY',
        },
        {
            name: 'unsafe route group path link id',
            input: { target: TEST_TOPOLOGY_TARGET, hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY },
            mutate(snapshot) {
                snapshot.topology.groups[0].paths[0].linkIds = ['relay-bridge', ''];
            },
            code: 'UNSAFE_TOPOLOGY_GROUP_IDENTITY',
        },
    ];

    for (const testCase of cases) {
        const snapshot = pinnedSnapshot();
        testCase.mutate?.(snapshot);
        const { HyNode, CascadeLink, materializer } = createMaterializer();
        await assert.rejects(
            materializer.materialize({ ...testCase.input, pinnedSnapshot: snapshot }),
            error => {
                assert.equal(error.code, testCase.code, testCase.name);
                assert.doesNotMatch(error.message, /production|panel\.infograd|standalone/i);
                return true;
            },
        );
        assert.deepEqual(HyNode.calls, [], testCase.name);
        assert.deepEqual(CascadeLink.calls, [], testCase.name);
    }
});

test('normalizes pinned and hydrated row order into identical composer inputs and plan hashes', async () => {
    const firstRows = metadataRows();
    const secondRows = metadataRows();
    secondRows.nodes.reverse();
    secondRows.links.reverse();
    const first = createMaterializer(firstRows);
    const second = createMaterializer(secondRows);
    const firstSnapshot = pinnedSnapshot();
    const secondSnapshot = pinnedSnapshot();
    secondSnapshot.topology.nodes.reverse();
    secondSnapshot.topology.links.reverse();
    secondSnapshot.compiled.relays.reverse();

    const [firstPlan, secondPlan] = await Promise.all([
        first.materializer.materialize({
            target: TEST_TOPOLOGY_TARGET,
            hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
            pinnedSnapshot: firstSnapshot,
        }),
        second.materializer.materialize({
            target: TEST_TOPOLOGY_TARGET,
            hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
            pinnedSnapshot: secondSnapshot,
        }),
    ]);

    assert.deepEqual(secondPlan, firstPlan);
    assert.deepEqual(
        secondPlan.nodes.map(node => node.candidate.sha256),
        firstPlan.nodes.map(node => node.candidate.sha256),
    );
    assert.deepEqual(second.HyNode.calls, first.HyNode.calls);
    assert.deepEqual(second.CascadeLink.calls, first.CascadeLink.calls);
});
