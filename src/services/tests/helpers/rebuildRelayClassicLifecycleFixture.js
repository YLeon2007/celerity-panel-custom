'use strict';

const { Types: { ObjectId } } = require('mongoose');

const operations = 'l2tpoperations';

function inactiveClassicRelay(nodeId, prefix, status = 'succeeded') {
    const node = new ObjectId(String(nodeId));
    const operation = {
        _id: new ObjectId('e'.repeat(24)), node, kind: 'install', status,
        ...(status === 'succeeded' && { finishedAt: new Date(1) }),
    };
    // Historical persisted shape: the current model's desiredState enum would
    // reject this value on new writes. Seed it through the raw collection.
    const state = {
        _id: new ObjectId('f'.repeat(24)), node,
        status: 'not_installed', desiredState: 'not_installed', routingMode: 'route-group',
        operationId: operation._id, routeGroup: new ObjectId('d'.repeat(24)), activePathKey: 'fixture-classic-path',
        clientCidr: `${prefix}.0/24`, localAddress: `${prefix}.10`, poolStart: `${prefix}.50`, poolEnd: `${prefix}.99`,
        pskEncrypted: 'fixture-classic-psk-envelope', secretRevision: 1,
    };
    return { state, operation };
}

module.exports = { inactiveClassicRelay, operations };
