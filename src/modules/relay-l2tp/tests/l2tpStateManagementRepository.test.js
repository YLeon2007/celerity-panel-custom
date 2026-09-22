'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    EXECUTION_SECRET_SELECT,
    L2tpStateManagementRepository,
    STATE_MANAGEMENT_SAFE_SELECT,
} = require('../repositories/l2tpStateManagementRepository');

function createQueryModel(result = null) {
    const calls = [];
    const query = () => ({
        select(paths) {
            calls.push({ method: 'select', paths });
            return this;
        },
        lean(options) {
            calls.push({ method: 'lean', options });
            return Promise.resolve(result);
        },
    });

    return {
        calls,
        findById(id) {
            calls.push({ method: 'findById', id });
            return query();
        },
        findOne(filter) {
            calls.push({ method: 'findOne', filter });
            return query();
        },
        findOneAndUpdate(filter, update, options) {
            calls.push({ method: 'findOneAndUpdate', filter, update, options });
            return query();
        },
    };
}

test('repository adapter writes an encrypted select:false PSK and returns only safe state', async () => {
    const HyNode = createQueryModel({ _id: 'relay-1', cascadeRole: 'relay' });
    const CascadeRouteGroup = createQueryModel({ _id: 'group-a' });
    const RelayL2tpState = createQueryModel({
        _id: 'state-1',
        node: 'relay-1',
        desiredState: 'installed',
        status: 'not_installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        secretRevision: 1,
        pskEncrypted: 'v1:must-not-be-returned',
        psk: 'raw-must-not-be-returned',
        unknown: 'must-not-be-returned',
    });
    const repository = new L2tpStateManagementRepository({
        HyNode,
        RelayL2tpState,
        CascadeRouteGroup,
    });

    assert.deepEqual(await repository.findNodeById('relay-1'), {
        _id: 'relay-1',
        cascadeRole: 'relay',
    });
    assert.deepEqual(await repository.findRouteGroupById('group-a'), { _id: 'group-a' });

    const result = await repository.configureRelay({
        node: 'relay-1',
        desiredState: 'installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        pskEncrypted: 'v1:encrypted-envelope',
        psk: 'raw-must-not-be-written',
        secretRevision: 999,
        status: 'installed',
        unknown: 'must-not-be-written',
    });

    assert.deepEqual(HyNode.calls, [
        { method: 'findById', id: 'relay-1' },
        { method: 'select', paths: '_id cascadeRole' },
        { method: 'lean', options: undefined },
    ]);
    assert.deepEqual(CascadeRouteGroup.calls, [
        { method: 'findById', id: 'group-a' },
        { method: 'select', paths: '_id' },
        { method: 'lean', options: undefined },
    ]);
    assert.deepEqual(RelayL2tpState.calls, [
        {
            method: 'findOneAndUpdate',
            filter: { node: 'relay-1' },
            update: {
                $set: {
                    node: 'relay-1',
                    desiredState: 'installed',
                    routeGroup: 'group-a',
                    clientCidr: '10.77.0.0/24',
                    localAddress: '10.77.0.1',
                    poolStart: '10.77.0.10',
                    poolEnd: '10.77.0.200',
                    dnsServers: ['1.1.1.1'],
                    tproxyPort: 12345,
                    fwmark: 77,
                    routeTable: 177,
                    routingMode: 'route-group',
                    pskEncrypted: 'v1:encrypted-envelope',
                },
                $inc: { secretRevision: 1 },
                $setOnInsert: { status: 'not_installed' },
            },
            options: {
                new: true,
                runValidators: true,
                setDefaultsOnInsert: false,
                upsert: true,
            },
        },
        { method: 'select', paths: STATE_MANAGEMENT_SAFE_SELECT },
        { method: 'lean', options: undefined },
    ]);
    assert.deepEqual(result, {
        _id: 'state-1',
        node: 'relay-1',
        desiredState: 'installed',
        status: 'not_installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        secretRevision: 1,
    });
    assert.doesNotMatch(JSON.stringify(result), /psk|must-not-be-returned/i);
});

test('execution lookup selects only matching state identity, revision, and encrypted PSK', async () => {
    const executionState = {
        node: 'relay-1',
        desiredState: 'installed',
        secretRevision: 7,
        pskEncrypted: 'v1:execution-only',
    };
    const RelayL2tpState = createQueryModel(executionState);
    const repository = new L2tpStateManagementRepository({
        HyNode: createQueryModel(),
        RelayL2tpState,
        CascadeRouteGroup: createQueryModel(),
    });

    assert.strictEqual(
        await repository.findExecutionStateByNodeId('relay-1'),
        executionState,
    );
    assert.equal(EXECUTION_SECRET_SELECT, 'node desiredState secretRevision +pskEncrypted');
    assert.deepEqual(RelayL2tpState.calls, [
        { method: 'findOne', filter: { node: 'relay-1' } },
        { method: 'select', paths: EXECUTION_SECRET_SELECT },
        { method: 'lean', options: undefined },
    ]);
});
