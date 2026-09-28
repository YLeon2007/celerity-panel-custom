'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'admin@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret';

const assert = require('node:assert/strict');
const test = require('node:test');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const TopologyOperation = require('../models/topologyOperationModel');
const { durablePlan } = require('../workers/topologyOperationWorker');

const ids = Object.fromEntries(['pa', 'pb', 'ra', 'rm', 'bd', 'bg'].map((name, i) => [name, (i + 1).toString(16).padStart(24, '0')]));
const edges = [
    ['pa', 'ra', 'forward'],
    ['ra', 'rm', 'forward'],
    ['pb', 'rm', 'reverse'],
    ['rm', 'bd', 'forward'],
    ['rm', 'bg', 'forward'],
];
const roles = { pa: 'portal', pb: 'portal', ra: 'relay', rm: 'relay', bd: 'bridge', bg: 'bridge' };
const links = edges.map(([source, target, mode], index) => ({
    _id: (index + 11).toString(16).padStart(24, '0'),
    portalNode: ids[source], bridgeNode: ids[target], mode, active: true,
    status: 'deployed',
    ...(index === 4 ? { geoRouting: { enabled: true, geoip: ['ru'], domains: [] } } : {}),
}));
const nodes = Object.entries(roles).map(([name, role]) => ({
    _id: ids[name], cascadeRole: role,
}));
const nodeMetadata = Object.entries(roles).map(([name, role], index) => ({
    id: ids[name], role, type: 'xray', active: true,
    ip: `192.0.2.${index + 1}`, port: 24001 + index,
    xray: { accessLogs: { enabled: false }, apiPort: 61001 + index,
        inboundTag: `client-${name}`, transport: 'tcp', security: 'none', extraInbounds: [] },
}));
const linkMetadata = links.map((link, index) => ({
    id: String(link._id), tunnelPort: 10101 + index,
    ...(index === 4 ? { geoRouting: { enabled: true, geoip: ['ru'], domains: [] } } : {}),
}));

function setup(mutatePlan = plan => plan) {
    const saved = [];
    const model = {
        async create(input, options) {
            assert.ok(Array.isArray(input));
            assert.equal(input.length, 1);
            assert.equal(options?.session?.inTransaction(), true);
            assert.equal(input[0].heldTopologyAdmission, true);
            assert.match(input[0].admissionFingerprint, /^[a-f0-9]{64}$/);
            const document = new TopologyOperation(input[0]);
            await document.validate();
            saved.push(document);
            return [document];
        },
        findOneAndUpdate() {}, updateOne() {},
    };
    const repository = new TopologyOperationRepository({ model });
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async admitTopology({ expectedRevision, prepare, admit }) {
                const snapshot = { revision: 7, deployedRevision: 5, nodes, links, groups: [] };
                assert.equal(expectedRevision, snapshot.revision);
                const session = { inTransaction: () => true };
                const pinned = { ...snapshot, ...await prepare(snapshot, session) };
                await admit(pinned, session);
                return pinned;
            },
        },
        planMaterializer: {
            async materialize({ pinnedSnapshot }) {
                return mutatePlan(composeFrozenTopologyDeploymentPlan({
                    snapshot: pinnedSnapshot.topology,
                    nodeMetadata,
                    linkMetadata,
                    compiledTopology: pinnedSnapshot.compiled,
                }));
            },
        },
        operationRepository: repository,
        validator: () => ({ valid: true }),
        compiler: () => ({ valid: true, relays: [ids.ra, ids.rm].map(nodeId => ({ nodeId })) }),
    });
    return { coordinator, saved };
}

test('mixed unequal-depth fan-in plan binds every ref to its own node through durable repository and worker', async () => {
    const { coordinator, saved } = setup();
    const result = await coordinator.queue({ expectedTopologyRevision: 7 });
    assert.equal(result.status, 'queued');
    assert.equal(saved.length, 1);
    const document = saved[0];
    const mapping = Object.fromEntries(document.nodes.map(({ nodeRef, node }) => [nodeRef, String(node)]));
    assert.deepEqual(mapping, {
        'bridge-2': ids.bg, bridge: ids.bd,
        'portal-2': ids.pb, 'relay-2': ids.rm, 'relay-1': ids.ra, 'portal-1': ids.pa,
    });
    const claimed = document.toObject();
    claimed.status = 'preparing';
    claimed.nodes = claimed.nodes.map(node => ({ ...node, node: String(node.node) }));
    const work = durablePlan(claimed, result.operationId);
    assert.deepEqual(Object.fromEntries(work.nodes.map(node => [node.nodeRef, node.node])), mapping);
});

test('coordinator fails closed on foreign and ambiguous refs before persistence', async () => {
    const { nodeIdsByRef } = require('../services/topologyOperationCoordinator');
    const topology = {
        nodes: Object.entries(roles).map(([name, role]) => ({ id: ids[name], role })),
        links: links.map(link => ({ source: link.portalNode, target: link.bridgeNode,
            geo: link._id === links[4]._id })),
    };
    const mapping = nodeIdsByRef(topology);
    assert.equal(mapping.get('portal-2'), ids.pb);
    assert.equal(mapping.get('relay-2'), ids.rm);
    assert.equal(mapping.has('portal-3'), false);
    // A second non-geo outgoing edge cannot silently pick the last target.
    topology.links.push({ source: ids.pa, target: ids.bd, geo: false });
    assert.throws(() => nodeIdsByRef(topology), /ambiguous|invalid/i);
});

test('coordinator rejects foreign, spoofed, duplicate and role-swapped refs before persistence', async () => {
    const edits = [
        nodes => { nodes[0].nodeRef = 'portal-3'; },
        nodes => { nodes[0].node = ids.pa; },
        nodes => { nodes[0].nodeRef = nodes[1].nodeRef; },
        nodes => { nodes[0].role = 'bridge'; },
    ];
    for (const [index, edit] of edits.entries()) {
        const { coordinator, saved } = setup(plan => {
            const copy = structuredClone(plan);
            edit(copy.nodes);
            return copy;
        });
        await assert.rejects(coordinator.queue({ expectedTopologyRevision: 7 }),
            error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT', `edit ${index}`);
        assert.equal(saved.length, 0);
    }
});

test('worker rejects malformed persisted portal refs and role swaps', async () => {
    const { coordinator, saved } = setup();
    const result = await coordinator.queue({ expectedTopologyRevision: 7 });
    for (const ref of ['portal-0', 'portal-01', 'bridge-2']) {
        const operation = saved[0].toObject();
        operation.status = 'preparing';
        operation.nodes.find(node => node.role === 'portal').nodeRef = ref;
        assert.throws(() => durablePlan(operation, result.operationId), /Invalid durable topology candidate/);
    }
});

test('persisted model rejects role/ref mismatches and malformed numbered portals', async () => {
    const { coordinator, saved } = setup();
    await coordinator.queue({ expectedTopologyRevision: 7 });
    for (const ref of ['portal-0', 'portal-01', 'portal-999x', 'bridge-2', 'relay-1']) {
        const document = new TopologyOperation(saved[0].toObject());
        document.nodes.find(node => node.role === 'portal').nodeRef = ref;
        await assert.rejects(document.validate(), /nodeRef/);
    }
});
