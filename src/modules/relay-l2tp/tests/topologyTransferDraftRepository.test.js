'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    CURRENT_LINK_SELECT,
    CURRENT_NODE_FILTER,
    CURRENT_NODE_SELECT,
    CURRENT_RELAY_STATE_SELECT,
    CURRENT_ROUTE_GROUP_SELECT,
    TopologyTransferDraftRepository,
} = require('../repositories/topologyTransferDraftRepository');

function createFindModel(rows) {
    const calls = [];
    return {
        calls,
        find(filter) {
            calls.push({ method: 'find', filter });
            return {
                select(fields) {
                    calls.push({ method: 'select', fields });
                    return this;
                },
                sort(value) {
                    calls.push({ method: 'sort', value });
                    return this;
                },
                async lean() {
                    calls.push({ method: 'lean' });
                    return rows;
                },
            };
        },
    };
}

test('loads current topology through stable positive projections only', async () => {
    const nodes = [{ _id: 'node-a', name: 'Relay', cascadeRole: 'relay' }];
    const links = [{
        _id: 'link-a',
        name: 'Relay to bridge',
        portalNode: 'node-a',
        bridgeNode: 'node-b',
        mode: 'reverse',
        active: true,
    }];
    const routeGroups = [{
        _id: 'group-a',
        name: 'Primary',
        mode: 'reverse',
        strategy: 'priority-failover',
        paths: [{ pathKey: 'primary', linkIds: ['link-a'], priority: 1, enabled: true }],
    }];
    const relayStates = [{
        node: 'node-a',
        desiredState: 'installed',
        clientCidr: '10.66.0.0/24',
        routeGroup: 'group-a',
    }];
    const HyNode = createFindModel(nodes);
    const CascadeLink = createFindModel(links);
    const CascadeRouteGroup = createFindModel(routeGroups);
    const RelayL2tpState = createFindModel(relayStates);
    const repository = new TopologyTransferDraftRepository({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        RelayL2tpState,
        RelayL2tpTopologyTransferDraft: {},
    });

    assert.deepEqual(await repository.loadCurrentTopology(), {
        nodes,
        links,
        routeGroups,
        relayStates,
    });
    assert.deepEqual(HyNode.calls, [
        { method: 'find', filter: CURRENT_NODE_FILTER },
        { method: 'select', fields: CURRENT_NODE_SELECT },
        { method: 'sort', value: { _id: 1 } },
        { method: 'lean' },
    ]);
    for (const [model, select, sort] of [
        [CascadeLink, CURRENT_LINK_SELECT, { _id: 1 }],
        [CascadeRouteGroup, CURRENT_ROUTE_GROUP_SELECT, { _id: 1 }],
        [RelayL2tpState, CURRENT_RELAY_STATE_SELECT, { node: 1 }],
    ]) {
        assert.deepEqual(model.calls, [
            { method: 'find', filter: {} },
            { method: 'select', fields: select },
            { method: 'sort', value: sort },
            { method: 'lean' },
        ]);
    }
    assert.doesNotMatch(
        JSON.stringify([HyNode.calls, CascadeLink.calls, CascadeRouteGroup.calls, RelayL2tpState.calls]),
        /password|privateKey|token|secret|psk|rawCommand|tunnelUuid|ssh/i,
    );
});

test('creates only allowlisted immutable DRAFT fields and hides database internals', async () => {
    const calls = [];
    const createdAt = new Date('2026-09-22T12:00:00.000Z');
    const document = {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind: 'relay-l2tp-topology-import-draft',
        topology: { nodes: [], links: [], routeGroups: [], relayStates: [] },
    };
    const DraftModel = {
        async create(value) {
            calls.push(value);
            return {
                toObject() {
                    return {
                        _id: '64a1b2c3d4e5f6a7b8c9d001',
                        ...value,
                        createdAt,
                        internal: 'must-not-leak',
                    };
                },
            };
        },
    };
    const repository = new TopologyTransferDraftRepository({
        HyNode: {},
        CascadeLink: {},
        CascadeRouteGroup: {},
        RelayL2tpState: {},
        RelayL2tpTopologyTransferDraft: DraftModel,
    });

    const result = await repository.createDraft({
        draftId: '4ac7d68f-5c40-47e7-a329-6daf108b09dd',
        status: 'APPLIED',
        source: 'import',
        name: 'Imported topology',
        document,
        counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
        rawCommand: 'must-not-be-written',
        secret: 'must-not-be-written',
    });

    const expectedWrite = {
        draftId: '4ac7d68f-5c40-47e7-a329-6daf108b09dd',
        status: 'DRAFT',
        source: 'import',
        name: 'Imported topology',
        document,
        counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
    };
    assert.deepEqual(calls, [expectedWrite]);
    assert.deepEqual(result, { ...expectedWrite, createdAt });
    assert.equal(repository.updateDraft, undefined);
    assert.equal(repository.applyDraft, undefined);
    assert.equal(repository.deleteDraft, undefined);
    assert.doesNotMatch(JSON.stringify({ calls, result }), /rawCommand|must-not|internal/i);
});

test('lists and reads DRAFT records through positive public projections', async () => {
    const calls = [];
    const summary = {
        draftId: '4ac7d68f-5c40-47e7-a329-6daf108b09dd',
        status: 'DRAFT',
        source: 'import',
        name: 'Imported topology',
        counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
        createdAt: new Date('2026-09-22T12:00:00.000Z'),
    };
    const full = {
        ...summary,
        document: {
            schemaVersion: 1,
            module: 'relay-l2tp',
            kind: 'relay-l2tp-topology-import-draft',
            topology: { nodes: [], links: [], routeGroups: [], relayStates: [] },
        },
    };
    function query(result) {
        return {
            select(fields) {
                calls.push({ method: 'select', fields });
                return this;
            },
            sort(value) {
                calls.push({ method: 'sort', value });
                return this;
            },
            async lean() {
                calls.push({ method: 'lean' });
                return result;
            },
        };
    }
    const DraftModel = {
        find(filter) {
            calls.push({ method: 'find', filter });
            return query([{ _id: 'must-not-leak', ...summary, internal: 'must-not-leak' }]);
        },
        findOne(filter) {
            calls.push({ method: 'findOne', filter });
            return query({ _id: 'must-not-leak', ...full, internal: 'must-not-leak' });
        },
    };
    const repository = new TopologyTransferDraftRepository({
        HyNode: {},
        CascadeLink: {},
        CascadeRouteGroup: {},
        RelayL2tpState: {},
        RelayL2tpTopologyTransferDraft: DraftModel,
    });

    assert.deepEqual(await repository.listDrafts(), [summary]);
    assert.deepEqual(await repository.findDraftById(summary.draftId), full);
    assert.deepEqual(calls, [
        { method: 'find', filter: { status: 'DRAFT' } },
        { method: 'select', fields: 'draftId status source name counts createdAt' },
        { method: 'sort', value: { createdAt: -1, draftId: 1 } },
        { method: 'lean' },
        { method: 'findOne', filter: { draftId: summary.draftId, status: 'DRAFT' } },
        { method: 'select', fields: 'draftId status source name document counts createdAt' },
        { method: 'lean' },
    ]);
});
