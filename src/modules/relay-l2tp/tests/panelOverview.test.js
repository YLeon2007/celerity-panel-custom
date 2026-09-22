'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createPanelOverviewLoader,
    NODE_PANEL_SELECT,
    OPERATION_PANEL_SELECT,
    ROUTE_GROUP_PANEL_SELECT,
    STATE_PANEL_SELECT,
    TOPOLOGY_PANEL_SELECT,
} = require('../routes/panelOverview');

function query(result, calls, model) {
    const chain = {
        select(fields) {
            calls.push({ model, method: 'select', fields });
            return chain;
        },
        sort(value) {
            calls.push({ model, method: 'sort', value });
            return chain;
        },
        limit(value) {
            calls.push({ model, method: 'limit', value });
            return chain;
        },
        lean() {
            calls.push({ model, method: 'lean' });
            return Promise.resolve(result);
        },
    };
    return chain;
}

test('panel overview queries and returns only allowlisted operational fields', async () => {
    const calls = [];
    const secret = 'must-never-reach-the-panel';
    const models = {
        HyNode: {
            find(filter) {
                calls.push({ model: 'HyNode', method: 'find', filter });
                return query([{
                    _id: 'relay-1',
                    name: 'Relay One',
                    active: true,
                    status: 'online',
                    cascadeRole: 'relay',
                    ssh: { password: secret, privateKey: secret },
                }], calls, 'HyNode');
            },
        },
        RelayL2tpState: {
            find(filter) {
                calls.push({ model: 'RelayL2tpState', method: 'find', filter });
                return query([{
                    node: 'relay-1',
                    desiredState: 'installed',
                    status: 'installed',
                    clientCidr: '10.66.0.0/24',
                    localAddress: '10.66.0.1',
                    poolStart: '10.66.0.10',
                    poolEnd: '10.66.0.200',
                    dnsServers: ['9.9.9.9'],
                    tproxyPort: 12345,
                    fwmark: 77,
                    routeTable: 177,
                    routeGroup: 'group-1',
                    appliedTopologyRevision: 16,
                    activePathKey: 'primary',
                    lastVerifiedAt: '2026-09-22T08:00:00.000Z',
                    pskEncrypted: secret,
                    psk: secret,
                    lastError: secret,
                }], calls, 'RelayL2tpState');
            },
        },
        CascadeTopologyState: {
            findById(id) {
                calls.push({ model: 'CascadeTopologyState', method: 'findById', id });
                return query({ revision: 17, encryptedValue: secret }, calls, 'CascadeTopologyState');
            },
        },
        CascadeRouteGroup: {
            find(filter) {
                calls.push({ model: 'CascadeRouteGroup', method: 'find', filter });
                return query([{
                    _id: 'group-1',
                    name: 'Primary route',
                    mode: 'reverse',
                    strategy: 'priority-failover',
                    paths: [{ pathKey: 'primary', priority: 1, rawArgs: secret }],
                    secret,
                }], calls, 'CascadeRouteGroup');
            },
        },
        L2tpOperation: {
            find(filter) {
                calls.push({ model: 'L2tpOperation', method: 'find', filter });
                return query([{
                    _id: 'operation-1',
                    node: 'relay-1',
                    kind: 'install',
                    status: 'running',
                    step: 'apply',
                    progress: 60,
                    errorCode: '',
                    topologyRevision: 17,
                    routeGroupId: 'group-1',
                    createdAt: '2026-09-22T08:01:00.000Z',
                    updatedAt: '2026-09-22T08:02:00.000Z',
                    logs: [{ message: secret }],
                    plan: { rawCommand: secret },
                    errorMessage: secret,
                }], calls, 'L2tpOperation');
            },
        },
    };

    const loadPanelOverview = createPanelOverviewLoader(models);
    const overview = await loadPanelOverview();

    assert.deepEqual(overview, {
        topologyRevision: 17,
        relays: [{
            id: 'relay-1',
            name: 'Relay One',
            active: true,
            nodeStatus: 'online',
            l2tpStatus: 'installed',
            desiredState: 'installed',
            clientCidr: '10.66.0.0/24',
            localAddress: '10.66.0.1',
            poolStart: '10.66.0.10',
            poolEnd: '10.66.0.200',
            dnsServers: ['9.9.9.9'],
            tproxyPort: 12345,
            fwmark: 77,
            routeTable: 177,
            routeGroupId: 'group-1',
            appliedTopologyRevision: 16,
            activePathKey: 'primary',
            lastVerifiedAt: '2026-09-22T08:00:00.000Z',
        }],
        routeGroups: [{
            id: 'group-1',
            name: 'Primary route',
            mode: 'reverse',
            strategy: 'priority-failover',
            paths: [{ pathKey: 'primary', priority: 1 }],
        }],
        operations: [{
            id: 'operation-1',
            nodeId: 'relay-1',
            kind: 'install',
            status: 'running',
            step: 'apply',
            progress: 60,
            errorCode: '',
            topologyRevision: 17,
            routeGroupId: 'group-1',
            createdAt: '2026-09-22T08:01:00.000Z',
            updatedAt: '2026-09-22T08:02:00.000Z',
        }],
    });
    assert.doesNotMatch(JSON.stringify(overview), new RegExp(secret));
    assert.deepEqual(calls, [
        { model: 'HyNode', method: 'find', filter: { cascadeRole: 'relay' } },
        { model: 'HyNode', method: 'select', fields: NODE_PANEL_SELECT },
        { model: 'HyNode', method: 'lean' },
        { model: 'RelayL2tpState', method: 'find', filter: {} },
        { model: 'RelayL2tpState', method: 'select', fields: STATE_PANEL_SELECT },
        { model: 'RelayL2tpState', method: 'lean' },
        { model: 'CascadeTopologyState', method: 'findById', id: 'singleton' },
        { model: 'CascadeTopologyState', method: 'select', fields: TOPOLOGY_PANEL_SELECT },
        { model: 'CascadeTopologyState', method: 'lean' },
        { model: 'CascadeRouteGroup', method: 'find', filter: {} },
        { model: 'CascadeRouteGroup', method: 'select', fields: ROUTE_GROUP_PANEL_SELECT },
        { model: 'CascadeRouteGroup', method: 'lean' },
        { model: 'L2tpOperation', method: 'find', filter: {} },
        { model: 'L2tpOperation', method: 'select', fields: OPERATION_PANEL_SELECT },
        { model: 'L2tpOperation', method: 'sort', value: { createdAt: -1 } },
        { model: 'L2tpOperation', method: 'limit', value: 25 },
        { model: 'L2tpOperation', method: 'lean' },
    ]);

    const selectors = [
        NODE_PANEL_SELECT,
        STATE_PANEL_SELECT,
        TOPOLOGY_PANEL_SELECT,
        ROUTE_GROUP_PANEL_SELECT,
        OPERATION_PANEL_SELECT,
    ].join(' ');
    assert.doesNotMatch(selectors, /password|psk|encrypted|ssh|privateKey|rawArgs|command/i);
});
