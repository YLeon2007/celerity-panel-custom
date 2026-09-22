'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { TopologyTransferDraftService } = require('../services/topologyTransferDraftService');

const IDS = Object.freeze({
    relay: '64a1b2c3d4e5f6a7b8c9d001',
    bridge: '64a1b2c3d4e5f6a7b8c9d002',
    link: '64a1b2c3d4e5f6a7b8c9d003',
    group: '64a1b2c3d4e5f6a7b8c9d004',
});

function currentTopology() {
    return {
        nodes: [
            {
                _id: IDS.relay,
                name: 'Relay west',
                cascadeRole: 'relay',
                ssh: { password: 'node-secret', rawCommand: 'rm -rf /' },
            },
            { _id: IDS.bridge, name: 'Bridge east', cascadeRole: 'bridge' },
        ],
        links: [{
            _id: IDS.link,
            name: 'Relay to bridge',
            portalNode: IDS.relay,
            bridgeNode: IDS.bridge,
            mode: 'reverse',
            active: true,
            tunnelUuid: 'link-secret',
        }],
        routeGroups: [{
            _id: IDS.group,
            name: 'Primary route',
            mode: 'reverse',
            strategy: 'priority-failover',
            paths: [{ pathKey: 'primary', linkIds: [IDS.link], priority: 1 }],
        }],
        relayStates: [{
            node: IDS.relay,
            desiredState: 'installed',
            clientCidr: '10.66.0.0/24',
            routeGroup: IDS.group,
            pskEncrypted: 'encrypted-secret',
        }],
    };
}

test('exports current topology as a canonical portable document without persisting', async () => {
    const calls = [];
    const repository = {
        async loadCurrentTopology() {
            calls.push('loadCurrentTopology');
            return currentTopology();
        },
        async createDraft() {
            calls.push('createDraft');
            throw new Error('read-only export must not persist');
        },
    };
    const service = new TopologyTransferDraftService({ repository });

    const document = await service.exportCurrentTopology();

    assert.deepEqual(calls, ['loadCurrentTopology']);
    assert.equal(document.kind, 'relay-l2tp-topology-transfer');
    assert.deepEqual(document.topology.nodes.map(node => node.key), ['node-001', 'node-002']);
    const serialized = JSON.stringify(document);
    assert.doesNotMatch(serialized, /\b[a-f0-9]{24}\b/i);
    assert.doesNotMatch(serialized, /password|rawCommand|node-secret|link-secret|encrypted-secret|psk/i);
});

test('creates an immutable export DRAFT without exposing database internals', async () => {
    const calls = [];
    const repository = {
        async loadCurrentTopology() {
            calls.push({ method: 'loadCurrentTopology' });
            return currentTopology();
        },
        async createDraft(draft) {
            calls.push({ method: 'createDraft', draft });
            return {
                _id: IDS.group,
                ...draft,
                createdAt: new Date('2026-09-22T12:00:00.000Z'),
                internal: 'must-not-leak',
            };
        },
    };
    const service = new TopologyTransferDraftService({
        repository,
        idFactory: () => '4ac7d68f-5c40-47e7-a329-6daf108b09dd',
    });

    const result = await service.createExportDraft({ name: ' Before migration ' });

    assert.equal(calls[0].method, 'loadCurrentTopology');
    assert.deepEqual(calls[1].draft, {
        draftId: '4ac7d68f-5c40-47e7-a329-6daf108b09dd',
        status: 'DRAFT',
        source: 'export',
        name: 'Before migration',
        document: result.document,
        counts: { nodes: 2, links: 1, routeGroups: 1, relayStates: 1 },
    });
    assert.deepEqual(result, {
        ...calls[1].draft,
        createdAt: new Date('2026-09-22T12:00:00.000Z'),
    });
    assert.doesNotMatch(JSON.stringify(result), /must-not-leak|\b[a-f0-9]{24}\b/i);
});

test('imports a transfer by canonicalizing and persisting an isolated DRAFT only', async () => {
    const calls = [];
    const repository = {
        async createDraft(draft) {
            calls.push({ method: 'createDraft', draft });
            return {
                ...draft,
                createdAt: new Date('2026-09-22T12:05:00.000Z'),
            };
        },
        async loadCurrentTopology() {
            throw new Error('import must not read current topology');
        },
        async applyDraft() {
            throw new Error('import must never apply topology state');
        },
        async deploy() {
            throw new Error('import must never deploy nodes');
        },
    };
    const service = new TopologyTransferDraftService({
        repository,
        idFactory: () => '19ff16e6-2f6d-482a-aa52-90fb1dc618de',
    });
    const transfer = {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind: 'relay-l2tp-topology-transfer',
        credentials: { token: 'must-be-discarded' },
        topology: {
            nodes: [
                {
                    key: 'node-001',
                    name: 'Relay west',
                    role: 'relay',
                    password: 'must-be-discarded',
                },
                { key: 'node-002', name: 'Bridge east', role: 'bridge' },
            ],
            links: [{
                key: 'link-001',
                name: 'Relay to bridge',
                source: 'node-001',
                target: 'node-002',
                mode: 'reverse',
                rawShell: 'must-be-discarded',
            }],
            routeGroups: [{
                key: 'group-001',
                name: 'Primary route',
                mode: 'reverse',
                strategy: 'priority-failover',
                paths: [{ pathKey: 'primary', links: ['link-001'], priority: 1 }],
            }],
            relayStates: [{
                node: 'node-001',
                desiredState: 'installed',
                routeGroup: 'group-001',
                psk: 'must-be-discarded',
            }],
        },
    };

    const result = await service.importTopologyDraft({
        name: ' Imported topology ',
        document: transfer,
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, 'createDraft');
    assert.equal(calls[0].draft.draftId, '19ff16e6-2f6d-482a-aa52-90fb1dc618de');
    assert.equal(calls[0].draft.status, 'DRAFT');
    assert.equal(calls[0].draft.source, 'import');
    assert.equal(calls[0].draft.name, 'Imported topology');
    assert.equal(calls[0].draft.document.kind, 'relay-l2tp-topology-import-draft');
    assert.deepEqual(calls[0].draft.counts, {
        nodes: 2,
        links: 1,
        routeGroups: 1,
        relayStates: 1,
    });
    assert.deepEqual(result, { ...calls[0].draft, createdAt: result.createdAt });
    const serialized = JSON.stringify({ calls, result });
    assert.doesNotMatch(serialized, /password|credential|token|rawShell|psk|must-be-discarded/i);
    assert.doesNotMatch(serialized, /\b[a-f0-9]{24}\b/i);
    assert.equal(service.applyDraft, undefined);
    assert.equal(service.deploy, undefined);
});

test('lists metadata and reads a full DRAFT by public UUID only', async () => {
    const draftId = '19ff16e6-2f6d-482a-aa52-90fb1dc618de';
    const createdAt = new Date('2026-09-22T12:05:00.000Z');
    const document = {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind: 'relay-l2tp-topology-import-draft',
        topology: { nodes: [], links: [], routeGroups: [], relayStates: [] },
    };
    const stored = {
        _id: IDS.group,
        draftId,
        status: 'DRAFT',
        source: 'import',
        name: 'Imported topology',
        document,
        counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
        createdAt,
        internal: 'must-not-leak',
    };
    const calls = [];
    const service = new TopologyTransferDraftService({
        repository: {
            async listDrafts() {
                calls.push({ method: 'listDrafts' });
                return [stored];
            },
            async findDraftById(value) {
                calls.push({ method: 'findDraftById', value });
                return stored;
            },
        },
    });

    assert.deepEqual(await service.listDrafts(), [{
        draftId,
        status: 'DRAFT',
        source: 'import',
        name: 'Imported topology',
        counts: stored.counts,
        createdAt,
    }]);
    assert.deepEqual(await service.getDraft(draftId), {
        draftId,
        status: 'DRAFT',
        source: 'import',
        name: 'Imported topology',
        document,
        counts: stored.counts,
        createdAt,
    });
    assert.deepEqual(calls, [
        { method: 'listDrafts' },
        { method: 'findDraftById', value: draftId },
    ]);
});

test('rejects relay state bound to a non-relay node before draft persistence', async () => {
    let createCalls = 0;
    const service = new TopologyTransferDraftService({
        repository: {
            async createDraft() {
                createCalls += 1;
            },
        },
    });
    const transfer = {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind: 'relay-l2tp-topology-transfer',
        topology: {
            nodes: [{ key: 'node-001', name: 'Bridge', role: 'bridge' }],
            links: [],
            routeGroups: [],
            relayStates: [{ node: 'node-001', desiredState: 'absent' }],
        },
    };

    await assert.rejects(
        service.importTopologyDraft({ document: transfer }),
        error => error?.code === 'INVALID_TOPOLOGY_TRANSFER_DRAFT'
            && error.details.some(detail => detail.code === 'RELAY_STATE_NODE_NOT_RELAY'),
    );
    assert.equal(createCalls, 0);
});
