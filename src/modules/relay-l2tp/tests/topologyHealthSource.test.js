'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    DEFAULT_MAX_STALENESS_MS,
    GROUP_HEALTH_FILTER,
    GROUP_HEALTH_SELECT,
    LINK_HEALTH_FILTER,
    LINK_HEALTH_SELECT,
    NODE_HEALTH_FILTER,
    NODE_HEALTH_SELECT,
    TopologyHealthSource,
} = require('../services/topologyHealthSource');

function createReadModel(rows) {
    const calls = [];
    const writes = [];
    const recordWrite = method => (...args) => {
        writes.push({ method, args });
        throw new Error(`${method} must not be called by the topology health source`);
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

const NOW = new Date('2026-09-22T12:00:00.000Z');

function onlineNode(id) {
    return {
        _id: id,
        active: true,
        status: 'online',
        agentStatus: 'online',
        agentLastSeen: new Date(NOW.getTime() - 1_000),
    };
}

test('marks a path healthy when every link and downstream node is currently online', async () => {
    const source = new TopologyHealthSource({
        HyNode: createReadModel([
            onlineNode('portal-1'),
            onlineNode('relay-1'),
            onlineNode('bridge-1'),
        ]),
        CascadeLink: createReadModel([
            {
                _id: 'entry',
                active: true,
                portalNode: 'portal-1',
                bridgeNode: 'relay-1',
            },
            {
                _id: 'exit',
                active: true,
                portalNode: 'relay-1',
                bridgeNode: 'bridge-1',
            },
        ]),
        CascadeRouteGroup: createReadModel([{
            _id: 'group-a',
            paths: [{ pathKey: 'primary', linkIds: ['entry', 'exit'] }],
        }]),
        clock: { now: () => NOW },
        maxStalenessMs: 30_000,
    });

    assert.deepEqual(await source.getHealthByPathKey(), {
        'group-a:primary': true,
    });
});

test('uses the current time when no clock is injected', async () => {
    const justSeen = new Date();
    const source = new TopologyHealthSource({
        HyNode: createReadModel([
            { ...onlineNode('portal-1'), agentLastSeen: justSeen },
            { ...onlineNode('bridge-1'), agentLastSeen: justSeen },
        ]),
        CascadeLink: createReadModel([{
            _id: 'link-1',
            active: true,
            portalNode: 'portal-1',
            bridgeNode: 'bridge-1',
        }]),
        CascadeRouteGroup: createReadModel([{
            _id: 'group-a',
            paths: [{ pathKey: 'primary', linkIds: ['link-1'] }],
        }]),
    });

    assert.deepEqual(await source.getHealthByPathKey(), {
        'group-a:primary': true,
    });
});

test('default staleness bound blocks stale downstream nodes', async () => {
    const freshNode = onlineNode('bridge-fresh');
    freshNode.agentLastSeen = new Date(NOW.getTime() - DEFAULT_MAX_STALENESS_MS);
    const staleNode = onlineNode('bridge-stale');
    staleNode.agentLastSeen = new Date(NOW.getTime() - DEFAULT_MAX_STALENESS_MS - 1);
    const source = new TopologyHealthSource({
        HyNode: createReadModel([
            onlineNode('portal-1'),
            freshNode,
            staleNode,
        ]),
        CascadeLink: createReadModel([
            {
                _id: 'fresh-link',
                active: true,
                portalNode: 'portal-1',
                bridgeNode: 'bridge-fresh',
            },
            {
                _id: 'stale-link',
                active: true,
                portalNode: 'portal-1',
                bridgeNode: 'bridge-stale',
            },
        ]),
        CascadeRouteGroup: createReadModel([{
            _id: 'group-a',
            paths: [
                { pathKey: 'fresh', linkIds: ['fresh-link'] },
                { pathKey: 'stale', linkIds: ['stale-link'] },
            ],
        }]),
        clock: { now: () => NOW },
    });

    assert.deepEqual(await source.getHealthByPathKey(), {
        'group-a:fresh': true,
        'group-a:stale': false,
    });
});

test('rejects an unbounded staleness window', () => {
    assert.throws(() => new TopologyHealthSource({
        HyNode: createReadModel([]),
        CascadeLink: createReadModel([]),
        CascadeRouteGroup: createReadModel([]),
        clock: { now: () => NOW },
        maxStalenessMs: Number.POSITIVE_INFINITY,
    }), {
        name: 'RangeError',
        message: 'maxStalenessMs must be a positive finite number',
    });
});

test('offline or unknown downstream state blocks paths', async () => {
    const offlineNode = onlineNode('bridge-offline');
    offlineNode.status = 'offline';
    const unknownAgentNode = onlineNode('bridge-unknown-agent');
    unknownAgentNode.agentStatus = 'unknown';
    const unseenNode = onlineNode('bridge-unseen');
    delete unseenNode.agentLastSeen;
    const source = new TopologyHealthSource({
        HyNode: createReadModel([
            onlineNode('portal-1'),
            offlineNode,
            unknownAgentNode,
            unseenNode,
        ]),
        CascadeLink: createReadModel([
            { _id: 'offline', active: true, portalNode: 'portal-1', bridgeNode: 'bridge-offline' },
            { _id: 'unknown-agent', active: true, portalNode: 'portal-1', bridgeNode: 'bridge-unknown-agent' },
            { _id: 'unseen', active: true, portalNode: 'portal-1', bridgeNode: 'bridge-unseen' },
            { _id: 'missing', active: true, portalNode: 'portal-1', bridgeNode: 'missing-node' },
        ]),
        CascadeRouteGroup: createReadModel([{
            _id: 'group-a',
            paths: [
                { pathKey: 'offline', linkIds: ['offline'] },
                { pathKey: 'unknown-agent', linkIds: ['unknown-agent'] },
                { pathKey: 'unseen', linkIds: ['unseen'] },
                { pathKey: 'missing', linkIds: ['missing'] },
                { pathKey: 'missing-link', linkIds: ['not-found'] },
            ],
        }]),
        clock: { now: () => NOW },
    });

    assert.deepEqual(await source.getHealthByPathKey(), {
        'group-a:offline': false,
        'group-a:unknown-agent': false,
        'group-a:unseen': false,
        'group-a:missing': false,
        'group-a:missing-link': false,
    });
});

test('inactive links or endpoints block paths', async () => {
    const inactivePortal = onlineNode('portal-inactive');
    inactivePortal.active = false;
    const inactiveBridge = onlineNode('bridge-inactive');
    inactiveBridge.active = false;
    const source = new TopologyHealthSource({
        HyNode: createReadModel([
            onlineNode('portal-1'),
            inactivePortal,
            onlineNode('bridge-1'),
            inactiveBridge,
        ]),
        CascadeLink: createReadModel([
            { _id: 'inactive-link', active: false, portalNode: 'portal-1', bridgeNode: 'bridge-1' },
            { _id: 'inactive-portal', active: true, portalNode: 'portal-inactive', bridgeNode: 'bridge-1' },
            { _id: 'inactive-bridge', active: true, portalNode: 'portal-1', bridgeNode: 'bridge-inactive' },
        ]),
        CascadeRouteGroup: createReadModel([{
            _id: 'group-a',
            paths: [
                { pathKey: 'inactive-link', linkIds: ['inactive-link'] },
                { pathKey: 'inactive-portal', linkIds: ['inactive-portal'] },
                { pathKey: 'inactive-bridge', linkIds: ['inactive-bridge'] },
            ],
        }]),
        clock: { now: () => NOW },
    });

    assert.deepEqual(await source.getHealthByPathKey(), {
        'group-a:inactive-link': false,
        'group-a:inactive-portal': false,
        'group-a:inactive-bridge': false,
    });
});

test('same-named paths remain isolated by route group', async () => {
    const source = new TopologyHealthSource({
        HyNode: createReadModel([
            onlineNode('portal-1'),
            onlineNode('bridge-online'),
            { ...onlineNode('bridge-offline'), status: 'offline' },
        ]),
        CascadeLink: createReadModel([
            { _id: 'healthy-link', active: true, portalNode: 'portal-1', bridgeNode: 'bridge-online' },
            { _id: 'blocked-link', active: true, portalNode: 'portal-1', bridgeNode: 'bridge-offline' },
        ]),
        CascadeRouteGroup: createReadModel([
            { _id: 'group-a', paths: [{ pathKey: 'primary', linkIds: ['healthy-link'] }] },
            { _id: 'group-b', paths: [{ pathKey: 'primary', linkIds: ['blocked-link'] }] },
        ]),
        clock: { now: () => NOW },
    });

    assert.deepEqual(await source.getHealthByPathKey(), {
        'group-a:primary': true,
        'group-b:primary': false,
    });
});

test('queries lean allowlisted fields and performs no writes or secret reads', async () => {
    const HyNode = createReadModel([{
        ...onlineNode('bridge-1'),
        ssh: { password: 'node-password', privateKey: 'node-private-key' },
    }, onlineNode('portal-1')]);
    const CascadeLink = createReadModel([{
        _id: 'link-1',
        active: true,
        portalNode: 'portal-1',
        bridgeNode: 'bridge-1',
        tunnelUuid: 'link-secret',
        realityPrivateKey: 'reality-secret',
    }]);
    const CascadeRouteGroup = createReadModel([{
        _id: 'group-a',
        name: 'not selected',
        paths: [{
            pathKey: 'primary',
            linkIds: ['link-1'],
            psk: 'path-secret',
        }],
    }]);
    const source = new TopologyHealthSource({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        clock: { now: () => NOW },
    });

    const health = await source.getHealthByPathKey();

    assert.deepEqual(health, { 'group-a:primary': true });
    assert.doesNotMatch(JSON.stringify(health), /password|privateKey|secret|psk|tunnelUuid/i);
    assert.deepEqual(HyNode.calls, [
        { method: 'find', filter: NODE_HEALTH_FILTER },
        { method: 'select', paths: NODE_HEALTH_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(CascadeLink.calls, [
        { method: 'find', filter: LINK_HEALTH_FILTER },
        { method: 'select', paths: LINK_HEALTH_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(CascadeRouteGroup.calls, [
        { method: 'find', filter: GROUP_HEALTH_FILTER },
        { method: 'select', paths: GROUP_HEALTH_SELECT },
        { method: 'lean' },
    ]);
    assert.deepEqual(HyNode.writes, []);
    assert.deepEqual(CascadeLink.writes, []);
    assert.deepEqual(CascadeRouteGroup.writes, []);
});
