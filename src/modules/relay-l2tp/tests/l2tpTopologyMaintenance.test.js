'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { buildDefaultChainLinkIds } = require('../domain/defaultChainPath');
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

function maintenanceModels({ links, groupPaths }) {
    const group = { _id: 'group-a', paths: groupPaths };
    const writes = [];
    return {
        writes,
        HyNode: {
            find: () => ({ select: () => ({ lean: async () => NODES }) }),
        },
        CascadeLink: { find: () => ({ lean: async () => links }) },
        CascadeRouteGroup: {
            findById: () => ({ lean: async () => group }),
            findByIdAndUpdate: async (id, update) => { writes.push({ id, update }); },
        },
        RelayL2tpState: {
            find: () => ({
                lean: async () => [{ node: 'relay-1', desiredState: 'installed', routeGroup: 'group-a' }],
            }),
        },
        CascadeTopologyState: {
            findByIdAndUpdate: async () => ({}),
        },
    };
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
