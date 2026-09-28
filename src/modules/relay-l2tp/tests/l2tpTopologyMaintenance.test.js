'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { buildDefaultChainLinkIds, buildDefaultChainPath } = require('../domain/defaultChainPath');
const { maintainAutoL2tpPaths } = require('../services/autoL2tpPathMaintenance');
const { mergePreservedL2tpConfig } = require('../domain/l2tpXrayConfigMerge');

const NODES = [
    { _id: 'portal-1', cascadeRole: 'portal' },
    { _id: 'relay-1', cascadeRole: 'relay' },
    { _id: 'bridge-1', cascadeRole: 'bridge' },
    { _id: 'bridge-2', cascadeRole: 'bridge' },
];
const nodesById = new Map(NODES.map(node => [node._id, node]));

test('default chain walk follows the non-geo hop past a geo branch', () => {
    const links = [
        { _id: 'l1', portalNode: 'portal-1', bridgeNode: 'relay-1' },
        { _id: 'l2', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
        { _id: 'l3', portalNode: 'relay-1', bridgeNode: 'bridge-2', geoRouting: { enabled: true } },
    ];
    assert.deepEqual(buildDefaultChainLinkIds({ links, nodesById, startNodeId: 'relay-1' }), ['l2']);
});

test('default chain walk rejects two non-geo branches', () => {
    const links = [
        { _id: 'l2', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
        { _id: 'l3', portalNode: 'relay-1', bridgeNode: 'bridge-2' },
    ];
    assert.throws(
        () => buildDefaultChainLinkIds({ links, nodesById, startNodeId: 'relay-1' }),
        error => error.code === 'ROUTE_GROUP_AMBIGUOUS',
    );
});

test('default chain walk detects loops', () => {
    const links = [
        { _id: 'l1', portalNode: 'relay-1', bridgeNode: 'portal-1' },
        { _id: 'l2', portalNode: 'portal-1', bridgeNode: 'relay-1' },
    ];
    assert.throws(
        () => buildDefaultChainLinkIds({ links, nodesById, startNodeId: 'relay-1' }),
        error => error.code === 'ROUTE_GROUP_AMBIGUOUS',
    );
});

test('default chain walk handles bson ObjectId-shaped ids without recursion', () => {
    const oid = hex => ({
        _id: undefined,
        toHexString: () => hex,
        toString: () => hex,
    });
    const links = [{ _id: oid('l1'), portalNode: oid('relay-1'), bridgeNode: oid('bridge-1') }];
    const byId = new Map(NODES.map(node => [node._id, node]));
    const result = buildDefaultChainLinkIds({ links, nodesById: byId, startNodeId: 'relay-1' });
    assert.deepEqual(result.map(String), ['l1']);
});

test('default chain path is complete only when the walk reaches a bridge role', () => {
    const links = [
        { _id: 'l1', portalNode: 'portal-1', bridgeNode: 'relay-1' },
        { _id: 'l2', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
    ];
    const result = buildDefaultChainPath({ links, nodesById, startNodeId: 'relay-1' });
    assert.equal(result.complete, true);
    assert.deepEqual(result.linkIds, ['l2']);
    assert.equal(result.endNodeId, 'bridge-1');
});

test('default chain path reports a suffix that stops short of any bridge as incomplete', () => {
    const withRelay2 = new Map([...NODES, { _id: 'relay-2', cascadeRole: 'relay' }]
        .map(node => [node._id, node]));
    const links = [{ _id: 'l1', portalNode: 'relay-1', bridgeNode: 'relay-2' }];
    const result = buildDefaultChainPath({ links, nodesById: withRelay2, startNodeId: 'relay-1' });
    assert.equal(result.complete, false);
    assert.deepEqual(result.linkIds, ['l1']);
    assert.equal(result.endNodeId, 'relay-2');
});

test('default chain walk never follows a geo-only branch as the main path', () => {
    const links = [
        { _id: 'l-geo', portalNode: 'relay-1', bridgeNode: 'bridge-2', geoRouting: { enabled: true } },
    ];
    const result = buildDefaultChainPath({ links, nodesById, startNodeId: 'relay-1' });
    assert.equal(result.complete, false);
    assert.deepEqual(result.linkIds, []);
    // The legacy wrapper agrees: geo links are side branches, never the
    // automatic L2TP path.
    assert.deepEqual(buildDefaultChainLinkIds({ links, nodesById, startNodeId: 'relay-1' }), []);
});

function maintenanceModels({ links, groupPaths }) {
    return maintenanceHarness({
        links, nodes: NODES,
        states: [{ node: 'relay-1', desiredState: 'installed', routeGroup: 'group-a' }],
        groups: { 'group-a': { _id: 'group-a', paths: groupPaths } },
    });
}

test('maintenance rebuilds the auto-l2tp path after link topology changed', async () => {
    const links = [{ _id: 'l-new', portalNode: 'relay-1', bridgeNode: 'bridge-1' }];
    const models = maintenanceModels({ links, groupPaths: [] });

    const result = await maintainAutoL2tpPaths(models);

    assert.equal(result.updated, 1);
    assert.equal(models.writes.length, 1);
    assert.deepEqual(models.writes[0].update.$set.paths, [
        { pathKey: 'main', linkIds: ['l-new'], priority: 1, enabled: true },
    ]);
});

test('maintenance leaves an already-correct path untouched', async () => {
    const links = [{ _id: 'l-new', portalNode: 'relay-1', bridgeNode: 'bridge-1' }];
    const models = maintenanceModels({
        links,
        groupPaths: [{ pathKey: 'main', linkIds: ['l-new'], priority: 1, enabled: true }],
    });

    const result = await maintainAutoL2tpPaths(models);

    assert.equal(result.updated, 0);
    assert.equal(models.writes.length, 0);
});

test('maintenance skips ambiguous graphs without touching the group', async () => {
    const links = [
        { _id: 'l2', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
        { _id: 'l3', portalNode: 'relay-1', bridgeNode: 'bridge-2' },
    ];
    const models = maintenanceModels({ links, groupPaths: [] });
    const warnings = [];

    const result = await maintainAutoL2tpPaths({
        ...models,
        logger: { warn: msg => warnings.push(msg) },
    });

    assert.equal(result.updated, 0);
    assert.equal(models.writes.length, 0);
    assert.equal(warnings.length, 1);
});

const NODES_MULTI = [
    { _id: 'portal-1', cascadeRole: 'portal' },
    { _id: 'relay-1', cascadeRole: 'relay' },
    { _id: 'relay-2', cascadeRole: 'relay' },
    { _id: 'bridge-1', cascadeRole: 'bridge' },
    { _id: 'bridge-2', cascadeRole: 'bridge' },
];

// In-memory model stubs for the multi-relay / gap / recreate scenarios.
// `groups` is a map of groupId -> group document the stub mutates in place,
// so tests can assert the exact published state after each invocation.
function maintenanceHarness({ links, nodes = NODES_MULTI, states, groups }) {
    const groupStore = new Map(Object.entries(groups));
    const writes = [];
    const topologyUpdates = [];
    const topology = { _id: 'singleton', revision: 112 };
    const session = {};
    let staged = new Map();
    const query = value => ({
        session(received) { assert.equal(received, session); return this; },
        select() { return this; },
        async lean() { return value; },
    });
    const models = {
        writes,
        topologyUpdates,
        transactionRunner: async work => {
            staged = new Map();
            const result = await work(session);
            for (const [id, paths] of staged) groupStore.get(id).paths = paths;
            return result;
        },
        HyNode: { find: () => query(nodes) },
        CascadeLink: { find: () => query(links) },
        CascadeRouteGroup: {
            findById: id => query(groupStore.has(id)
                ? { ...groupStore.get(id), paths: staged.get(id) ?? groupStore.get(id).paths }
                : null),
            updateOne: async (filter, update, options) => {
                assert.equal(options.session, session);
                assert.equal(options.runValidators, true);
                writes.push({ id: filter._id, update });
                if (!groupStore.has(filter._id)) return { matchedCount: 0 };
                staged.set(filter._id, update.$set.paths);
                return { matchedCount: 1 };
            },
        },
        RelayL2tpState: { find: () => query(states) },
        CascadeTopologyState: {
            findById: () => query({ ...topology }),
            findOneAndUpdate: (filter, update, options) => {
                assert.equal(options.session, session);
                topologyUpdates.push({ filter, update, options });
                assert.deepEqual(filter.replacementReservation, { $exists: false });
                assert.equal(filter.revision, topology.revision);
                topology.revision += update.$inc.revision;
                return query({ ...topology });
            },
        },
    };
    return models;
}

function installedState(node, routeGroup, activePathKey = 'main') {
    return { node, desiredState: 'installed', routeGroup, activePathKey };
}

test('maintenance never publishes an empty path during a delete/recreate gap', async () => {
    const group = { _id: 'group-a', paths: [] };
    const states = [installedState('relay-1', 'group-a')];
    const warnings = [];
    const logger = { warn: msg => warnings.push(msg), info: () => {} };

    // Gap: the only downstream link was deleted and the draft stripped the
    // group path. The old behaviour wrote paths: [] — an explicit empty
    // publish. The maintenance hook must instead defer and leave the group
    // untouched until a complete replacement suffix exists.
    const gap = maintenanceHarness({ links: [], states, groups: { 'group-a': group } });
    const gapResult = await maintainAutoL2tpPaths({ ...gap, logger });
    assert.equal(gapResult.updated, 0);
    assert.equal(gap.writes.length, 0, 'no empty path array may be published');
    assert.deepEqual(group.paths, []);
    assert.equal(gapResult.deferred.length, 1);
    assert.equal(gapResult.deferred[0].relayNode, 'relay-1');
    assert.equal(gapResult.deferred[0].reason, 'CHAIN_INCOMPLETE');
    assert.equal(gap.topologyUpdates.length, 0, 'no topology revision bump without a write');

    // Recreate: a fresh link with a new id completes the suffix to a bridge.
    const links = [{ _id: 'l-new', portalNode: 'relay-1', bridgeNode: 'bridge-1' }];
    const healed = maintenanceHarness({ links, states, groups: { 'group-a': group } });
    const healedResult = await maintainAutoL2tpPaths({ ...healed, logger });
    assert.equal(healedResult.updated, 1);
    assert.equal(healedResult.deferred.length, 0);
    assert.deepEqual(group.paths, [
        { pathKey: 'main', linkIds: ['l-new'], priority: 1, enabled: true },
    ]);
    assert.equal(healedResult.revision, 113, 'post-maintenance topology revision is returned');
    assert.equal(healed.topologyUpdates[0].options?.new, true);

    // Idempotent: a second pass over the same desired state changes nothing.
    const again = maintenanceHarness({ links, states, groups: { 'group-a': group } });
    const againResult = await maintainAutoL2tpPaths({ ...again, logger });
    assert.equal(againResult.updated, 0);
    assert.equal(again.writes.length, 0);
    assert.equal(againResult.revision, null);
});

test('maintenance never publishes a partial path that stops short of a bridge', async () => {
    const group = {
        _id: 'group-a',
        paths: [{ pathKey: 'main', linkIds: ['l-old'], priority: 1, enabled: true }],
    };
    // relay-1 -> relay-2 exists, but nothing continues relay-2 to a bridge.
    const links = [{ _id: 'l1', portalNode: 'relay-1', bridgeNode: 'relay-2' }];
    const models = maintenanceHarness({
        links,
        states: [installedState('relay-1', 'group-a')],
        groups: { 'group-a': group },
    });

    const result = await maintainAutoL2tpPaths({ ...models, logger: { warn: () => {}, info: () => {} } });

    assert.equal(result.updated, 0);
    assert.equal(models.writes.length, 0, 'a partial suffix must not replace the last working path');
    assert.deepEqual(group.paths[0].linkIds, ['l-old']);
    assert.equal(result.deferred[0]?.reason, 'CHAIN_INCOMPLETE');
});

test('maintenance replaces a stale main path after a link changes relay ownership', async () => {
    const links = [
        { _id: 'l-old', portalNode: 'relay-2', bridgeNode: 'bridge-2' },
        { _id: 'l-new', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
    ];
    const group = { _id: 'group-a', paths: [
        { pathKey: 'main', linkIds: ['l-old'], priority: 1, enabled: true },
    ] };
    const models = maintenanceHarness({ links, states: [installedState('relay-1', 'group-a')], groups: { 'group-a': group } });
    const result = await maintainAutoL2tpPaths(models);
    assert.equal(result.updated, 1);
    assert.deepEqual(group.paths, [
        { pathKey: 'main', linkIds: ['l-new'], priority: 1, enabled: true },
    ]);
});

test('maintenance rebuilds only the relay-owned path and preserves other relays in a shared group', async () => {
    // Two installed L2TP relays share one route group; relay-2's path is
    // already correct while relay-1 needs a rebuild after a link recreate.
    // Link ids are listed in adverse order (relay-2's link first).
    const links = [
        { _id: 'l2', portalNode: 'relay-2', bridgeNode: 'bridge-2' },
        { _id: 'l1', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
    ];
    const group = {
        _id: 'group-shared',
        paths: [{ pathKey: 'main-relay-2', linkIds: ['l2'], priority: 1, enabled: true }],
    };
    const states = [
        installedState('relay-1', 'group-shared', 'main-relay-1'),
        installedState('relay-2', 'group-shared', 'main-relay-2'),
    ];
    const models = maintenanceHarness({ links, states, groups: { 'group-shared': group } });

    const result = await maintainAutoL2tpPaths({ ...models, logger: { warn: () => {}, info: () => {} } });

    assert.equal(result.updated, 1, 'only relay-1 needed a path write');
    assert.equal(models.writes.length, 1);
    assert.deepEqual(group.paths, [
        { pathKey: 'main-relay-2', linkIds: ['l2'], priority: 1, enabled: true },
        { pathKey: 'main-relay-1', linkIds: ['l1'], priority: 1, enabled: true },
    ], 'the foreign relay path must survive the rebuild');
});

test('maintenance refuses a shared route group with duplicate relay path keys', async () => {
    const links = [
        { _id: 'l1', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
        { _id: 'l2', portalNode: 'relay-2', bridgeNode: 'bridge-2' },
    ];
    const group = { _id: 'group-shared', paths: [
        { pathKey: 'main', linkIds: ['l2'], priority: 1, enabled: true },
    ] };
    const models = maintenanceHarness({
        links,
        states: [installedState('relay-1', 'group-shared'), installedState('relay-2', 'group-shared')],
        groups: { 'group-shared': group },
    });
    const result = await maintainAutoL2tpPaths(models);
    assert.equal(result.updated, 0);
    assert.equal(models.writes.length, 0);
    assert.ok(result.deferred.some(item => item.reason === 'AMBIGUOUS_ROUTE_GROUP_OWNERSHIP'));
    assert.deepEqual(group.paths, [{ pathKey: 'main', linkIds: ['l2'], priority: 1, enabled: true }]);
});

test('maintenance keeps geo branch links out of the published default path', async () => {
    const links = [
        { _id: 'l-geo', portalNode: 'relay-1', bridgeNode: 'bridge-2', geoRouting: { enabled: true } },
        { _id: 'l-main', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
    ];
    const group = { _id: 'group-a', paths: [] };
    const models = maintenanceHarness({
        links,
        states: [installedState('relay-1', 'group-a')],
        groups: { 'group-a': group },
    });

    const result = await maintainAutoL2tpPaths({ ...models, logger: { warn: () => {}, info: () => {} } });

    assert.equal(result.updated, 1);
    assert.deepEqual(group.paths[0].linkIds, ['l-main']);
});

test('maintenance with a geo-only downstream defers instead of publishing the geo path', async () => {
    const links = [
        { _id: 'l-geo', portalNode: 'relay-1', bridgeNode: 'bridge-2', geoRouting: { enabled: true } },
    ];
    const group = {
        _id: 'group-a',
        paths: [{ pathKey: 'main', linkIds: ['l-old'], priority: 1, enabled: true }],
    };
    const models = maintenanceHarness({
        links,
        states: [installedState('relay-1', 'group-a')],
        groups: { 'group-a': group },
    });

    const result = await maintainAutoL2tpPaths({ ...models, logger: { warn: () => {}, info: () => {} } });

    assert.equal(result.updated, 0);
    assert.equal(models.writes.length, 0, 'a geo branch is never published as the default path');
    assert.deepEqual(group.paths[0].linkIds, ['l-old']);
    assert.equal(result.deferred[0]?.reason, 'CHAIN_INCOMPLETE');
});

test('maintenance never mutates relay L2TP state or credentials', async () => {
    const links = [{ _id: 'l-new', portalNode: 'relay-1', bridgeNode: 'bridge-1' }];
    const models = maintenanceHarness({
        links,
        states: [installedState('relay-1', 'group-a')],
        groups: { 'group-a': { _id: 'group-a', paths: [] } },
    });
    // Any write attempt against the relay state model must explode: installed
    // state, PSK, CIDR and PPP credentials survive link maintenance.
    models.RelayL2tpState.updateOne = async () => {
        throw new Error('RelayL2tpState must stay read-only during path maintenance');
    };
    models.RelayL2tpState.findByIdAndUpdate = async () => {
        throw new Error('RelayL2tpState must stay read-only during path maintenance');
    };

    const result = await maintainAutoL2tpPaths({ ...models, logger: { warn: () => {}, info: () => {} } });

    assert.equal(result.updated, 1);
    assert.equal(models.writes.length, 1);
    assert.deepEqual(
        Object.keys(models.writes[0].update.$set),
        ['paths'],
        'the route group write touches only paths — name/mode/strategy stay stable',
    );
});

const L2TP_INBOUND = {
    tag: 'relay-l2tp-group-a',
    protocol: 'dokodemo-door',
    listen: '0.0.0.0',
    port: 12345,
    settings: { address: '127.0.0.1', port: 0, network: 'tcp,udp' },
    sniffing: { enabled: true, destOverride: ['fido'] },
};
const L2TP_OUTBOUND = { tag: 'cascade-main', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: 19357 }] } };
const L2TP_RULE = { type: 'field', inboundTag: ['relay-l2tp-group-a'], outboundTag: 'cascade-main' };

test('merge re-attaches L2TP sections dropped by a regenerated base config', () => {
    const generated = JSON.stringify({
        inbounds: [{ tag: 'vless-in', protocol: 'vless' }],
        outbounds: [{ tag: 'direct' }, { tag: 'block' }],
        routing: { rules: [{ type: 'field', ip: ['geoip:private'], outboundTag: 'block' }] },
    });
    const current = JSON.stringify({
        inbounds: [{ tag: 'vless-in' }, L2TP_INBOUND],
        outbounds: [{ tag: 'direct' }, { tag: 'block' }, L2TP_OUTBOUND],
        routing: { rules: [L2TP_RULE, { type: 'field', ip: ['geoip:private'], outboundTag: 'block' }] },
    });

    const merged = JSON.parse(mergePreservedL2tpConfig(generated, current));

    assert.ok(merged.inbounds.some(inbound => inbound.tag === 'relay-l2tp-group-a'));
    assert.ok(merged.outbounds.some(outbound => outbound.tag === 'cascade-main'));
    assert.ok(merged.routing.rules.some(rule => (rule.inboundTag || []).includes('relay-l2tp-group-a')));
});

test('merge is a no-op when the live config has no L2TP sections', () => {
    const generated = JSON.stringify({ inbounds: [{ tag: 'vless-in' }], outbounds: [], routing: { rules: [] } });
    const current = JSON.stringify({ inbounds: [{ tag: 'vless-in' }], outbounds: [], routing: { rules: [] } });

    assert.equal(mergePreservedL2tpConfig(generated, current), JSON.stringify({
        inbounds: [{ tag: 'vless-in' }], outbounds: [], routing: { rules: [] },
    }, null, 2));
});

test('merge survives garbage on the wire', () => {
    assert.equal(mergePreservedL2tpConfig('{broken', '{}'), '{broken');
    assert.equal(mergePreservedL2tpConfig('{}', 'not json'), '{}');
});
