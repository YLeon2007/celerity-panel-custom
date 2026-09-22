'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { compileTopology } = require('../domain/topologyCompiler');
const {
    GROUP_TOPOLOGY_FILTER,
    GROUP_TOPOLOGY_SELECT,
    LINK_TOPOLOGY_FILTER,
    LINK_TOPOLOGY_SELECT,
    NODE_TOPOLOGY_FILTER,
    NODE_TOPOLOGY_SELECT,
    TopologyRuntimeService,
} = require('../services/topologyRuntimeService');

function createReadModel(rows) {
    const calls = [];
    const writes = [];
    const recordWrite = method => (...args) => {
        writes.push({ method, args });
        throw new Error(`${method} must not be called by the read-only topology runtime`);
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
                lean() {
                    calls.push({ method: 'lean' });
                    return Promise.resolve(rows);
                },
            };
        },
        create: recordWrite('create'),
        updateOne: recordWrite('updateOne'),
        findOneAndUpdate: recordWrite('findOneAndUpdate'),
        deleteMany: recordWrite('deleteMany'),
    };
}

function createTopologyRuntime({ healthByPathKey } = {}) {
    return new TopologyRuntimeService({
        HyNode: createReadModel([
            { _id: 'portal-1', cascadeRole: 'portal' },
            { _id: 'relay-1', cascadeRole: 'relay' },
            { _id: 'bridge-1', cascadeRole: 'bridge' },
        ]),
        CascadeLink: createReadModel([
            {
                _id: 'link-portal-relay',
                portalNode: 'portal-1',
                bridgeNode: 'relay-1',
                mode: 'forward',
            },
            {
                _id: 'link-relay-bridge',
                portalNode: 'relay-1',
                bridgeNode: 'bridge-1',
                mode: 'forward',
            },
        ]),
        CascadeRouteGroup: createReadModel([{
            _id: 'group-a',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: ['link-portal-relay', 'link-relay-bridge'],
                priority: 10,
            }],
        }]),
        compiler: compileTopology,
        healthByPathKey,
    });
}

test('unknown path health blocks rather than assuming the path is healthy', async () => {
    const runtime = createTopologyRuntime();

    const plan = await runtime.getRelayGroupPlan('relay-1', 'group-a');

    assert.equal(plan.groupId, 'group-a');
    assert.deepEqual(plan.decision, {
        decision: 'block',
        error: { code: 'NO_HEALTHY_PATH' },
    });
});

test('opt-in health provider selects a path whose downstream nodes are currently online', async () => {
    const now = new Date('2026-09-22T12:00:00.000Z');
    const HyNode = createReadModel([
        {
            _id: 'portal-1',
            cascadeRole: 'portal',
            active: true,
            status: 'online',
            agentStatus: 'online',
            agentLastSeen: now,
        },
        {
            _id: 'relay-1',
            cascadeRole: 'relay',
            active: true,
            status: 'online',
            agentStatus: 'online',
            agentLastSeen: now,
        },
        {
            _id: 'bridge-1',
            cascadeRole: 'bridge',
            active: true,
            status: 'online',
            agentStatus: 'online',
            agentLastSeen: now,
        },
    ]);
    const CascadeLink = createReadModel([
        {
            _id: 'entry',
            active: true,
            portalNode: 'portal-1',
            bridgeNode: 'relay-1',
            mode: 'forward',
        },
        {
            _id: 'exit',
            active: true,
            portalNode: 'relay-1',
            bridgeNode: 'bridge-1',
            mode: 'forward',
        },
    ]);
    const CascadeRouteGroup = createReadModel([{
        _id: 'group-a',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{ pathKey: 'primary', linkIds: ['entry', 'exit'], priority: 10 }],
    }]);
    const runtime = new TopologyRuntimeService({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        compiler: compileTopology,
        enableHealthProvider: true,
        clock: { now: () => now },
        healthMaxStalenessMs: 30_000,
    });

    const plan = await runtime.getRelayGroupPlan('relay-1', 'group-a');

    assert.deepEqual(plan.decision, {
        decision: 'select',
        groupId: 'group-a',
        pathKey: 'primary',
        nextHopNodeId: 'bridge-1',
    });
});

test('same-named paths in multiple groups remain isolated', async () => {
    const runtime = new TopologyRuntimeService({
        HyNode: createReadModel([
            { _id: 'portal-1', cascadeRole: 'portal' },
            { _id: 'relay-1', cascadeRole: 'relay' },
            { _id: 'bridge-a', cascadeRole: 'bridge' },
            { _id: 'bridge-b', cascadeRole: 'bridge' },
        ]),
        CascadeLink: createReadModel([
            { _id: 'entry', portalNode: 'portal-1', bridgeNode: 'relay-1', mode: 'forward' },
            { _id: 'exit-a', portalNode: 'relay-1', bridgeNode: 'bridge-a', mode: 'forward' },
            { _id: 'exit-b', portalNode: 'relay-1', bridgeNode: 'bridge-b', mode: 'forward' },
        ]),
        CascadeRouteGroup: createReadModel([
            {
                _id: 'group-b',
                mode: 'forward',
                strategy: 'priority-failover',
                paths: [{ pathKey: 'primary', linkIds: ['entry', 'exit-b'], priority: 10 }],
            },
            {
                _id: 'group-a',
                mode: 'forward',
                strategy: 'priority-failover',
                paths: [{ pathKey: 'primary', linkIds: ['entry', 'exit-a'], priority: 10 }],
            },
        ]),
        compiler: compileTopology,
        healthByPathKey: {
            'group-a:primary': true,
            'group-b:primary': false,
        },
    });

    const selected = await runtime.getRelayGroupPlan('relay-1', 'group-a');
    const blocked = await runtime.getRelayGroupPlan('relay-1', 'group-b');

    assert.equal(selected.groupId, 'group-a');
    assert.deepEqual(selected.decision, {
        decision: 'select',
        groupId: 'group-a',
        pathKey: 'primary',
        nextHopNodeId: 'bridge-a',
    });
    assert.equal(blocked.groupId, 'group-b');
    assert.deepEqual(blocked.decision, {
        decision: 'block',
        error: { code: 'NO_HEALTHY_PATH' },
    });
});

test('selects the lowest-priority candidate whose injected health is explicitly true', async () => {
    const HyNode = createReadModel([
        { _id: 'portal-1', cascadeRole: 'portal' },
        { _id: 'relay-1', cascadeRole: 'relay' },
        { _id: 'bridge-primary', cascadeRole: 'bridge' },
        { _id: 'bridge-secondary', cascadeRole: 'bridge' },
    ]);
    const CascadeLink = createReadModel([
        { _id: 'entry', portalNode: 'portal-1', bridgeNode: 'relay-1', mode: 'forward' },
        { _id: 'primary-exit', portalNode: 'relay-1', bridgeNode: 'bridge-primary', mode: 'forward' },
        { _id: 'secondary-exit', portalNode: 'relay-1', bridgeNode: 'bridge-secondary', mode: 'forward' },
    ]);
    const CascadeRouteGroup = createReadModel([{
        _id: 'group-a',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [
            { pathKey: 'secondary', linkIds: ['entry', 'secondary-exit'], priority: 20 },
            { pathKey: 'primary', linkIds: ['entry', 'primary-exit'], priority: 10 },
        ],
    }]);
    const runtime = new TopologyRuntimeService({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        compiler: compileTopology,
        healthByPathKey: async () => ({
            'group-a:primary': false,
            'group-a:secondary': true,
        }),
    });

    const plan = await runtime.getRelayGroupPlan('relay-1', 'group-a');

    assert.deepEqual(plan.decision, {
        decision: 'select',
        groupId: 'group-a',
        pathKey: 'secondary',
        nextHopNodeId: 'bridge-secondary',
    });
});

test('preserves disabled paths from the runtime query through compiler selection', async () => {
    const HyNode = createReadModel([
        { _id: 'portal-1', cascadeRole: 'portal' },
        { _id: 'relay-1', cascadeRole: 'relay' },
        { _id: 'bridge-primary', cascadeRole: 'bridge' },
        { _id: 'bridge-secondary', cascadeRole: 'bridge' },
    ]);
    const CascadeLink = createReadModel([
        { _id: 'entry', portalNode: 'portal-1', bridgeNode: 'relay-1', mode: 'forward' },
        { _id: 'primary-exit', portalNode: 'relay-1', bridgeNode: 'bridge-primary', mode: 'forward' },
        { _id: 'secondary-exit', portalNode: 'relay-1', bridgeNode: 'bridge-secondary', mode: 'forward' },
    ]);
    const CascadeRouteGroup = createReadModel([{
        _id: 'group-a',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [
            {
                pathKey: 'primary',
                linkIds: ['entry', 'primary-exit'],
                priority: 10,
                enabled: false,
            },
            {
                pathKey: 'secondary',
                linkIds: ['entry', 'secondary-exit'],
                priority: 20,
                enabled: true,
            },
        ],
    }]);
    const runtime = new TopologyRuntimeService({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        compiler: compileTopology,
        healthByPathKey: {
            'group-a:primary': true,
            'group-a:secondary': true,
        },
    });

    const plan = await runtime.getRelayGroupPlan('relay-1', 'group-a');

    assert.ok(GROUP_TOPOLOGY_SELECT.split(/\s+/).includes('paths.enabled'));
    assert.deepEqual(
        plan.candidates.map(({ pathKey, enabled }) => ({ pathKey, enabled })),
        [
            { pathKey: 'primary', enabled: false },
            { pathKey: 'secondary', enabled: true },
        ],
    );
    assert.deepEqual(plan.decision, {
        decision: 'select',
        groupId: 'group-a',
        pathKey: 'secondary',
        nextHopNodeId: 'bridge-secondary',
    });
});

test('queries lean allowlisted fields, performs no writes, and compiles a deterministic secret-free snapshot', async () => {
    const HyNode = createReadModel([
        {
            _id: 'relay-1',
            cascadeRole: 'relay',
            ssh: { password: 'node-password', privateKey: 'node-private-key' },
        },
        { _id: 'portal-1', cascadeRole: 'portal' },
        { _id: 'bridge-1', cascadeRole: 'bridge' },
    ]);
    const CascadeLink = createReadModel([
        {
            _id: 'link-b',
            portalNode: 'relay-1',
            bridgeNode: 'bridge-1',
            mode: 'forward',
            tunnelUuid: 'link-secret',
        },
        {
            _id: 'link-a',
            portalNode: 'portal-1',
            bridgeNode: 'relay-1',
            mode: 'forward',
            realityPrivateKey: 'link-private-key',
        },
    ]);
    const CascadeRouteGroup = createReadModel([{
        _id: 'group-a',
        name: 'group name excluded from compiler input',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{
            pathKey: 'primary',
            linkIds: ['link-a', 'link-b'],
            priority: 10,
            psk: 'group-path-psk',
        }],
    }]);
    const expectedPlan = {
        groupId: 'group-a',
        candidates: [],
        decision: { decision: 'block', error: { code: 'NO_HEALTHY_PATH' } },
    };
    const compileCalls = [];
    const runtime = new TopologyRuntimeService({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        compiler(input) {
            compileCalls.push(input);
            return {
                relays: [{
                    nodeId: 'relay-1',
                    routeGroups: [
                        { groupId: 'other-group' },
                        expectedPlan,
                    ],
                }],
            };
        },
        healthByPathKey: {
            'group-a:primary': true,
            'unknown-group:unknown-path': true,
        },
    });

    const plan = await runtime.getRelayGroupPlan('relay-1', 'group-a');

    assert.strictEqual(plan, expectedPlan);
    assert.deepEqual(compileCalls, [{
        nodes: [
            { id: 'bridge-1', role: 'bridge' },
            { id: 'portal-1', role: 'portal' },
            { id: 'relay-1', role: 'relay' },
        ],
        links: [
            { id: 'link-a', source: 'portal-1', target: 'relay-1', mode: 'forward' },
            { id: 'link-b', source: 'relay-1', target: 'bridge-1', mode: 'forward' },
        ],
        groups: [{
            _id: 'group-a',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: ['link-a', 'link-b'],
                priority: 10,
                enabled: true,
            }],
        }],
        healthByPathKey: { 'group-a:primary': true },
    }]);
    assert.doesNotMatch(JSON.stringify(compileCalls), /password|privateKey|psk|tunnelUuid/i);
    assert.deepEqual(HyNode.calls, [
        { method: 'find', filter: NODE_TOPOLOGY_FILTER },
        { method: 'select', paths: NODE_TOPOLOGY_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(CascadeLink.calls, [
        { method: 'find', filter: LINK_TOPOLOGY_FILTER },
        { method: 'select', paths: LINK_TOPOLOGY_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(CascadeRouteGroup.calls, [
        { method: 'find', filter: GROUP_TOPOLOGY_FILTER },
        { method: 'select', paths: GROUP_TOPOLOGY_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(HyNode.writes, []);
    assert.deepEqual(CascadeLink.writes, []);
    assert.deepEqual(CascadeRouteGroup.writes, []);
});
