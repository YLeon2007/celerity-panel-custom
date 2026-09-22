'use strict';

const { L2tpNodeTransport } = require('./l2tpNodeTransport');

function createL2tpNodeTransportFactory({
    nodeSSHFactory,
    NodeTransport = L2tpNodeTransport,
} = {}) {
    if (typeof nodeSSHFactory !== 'function') {
        throw new TypeError('createL2tpNodeTransportFactory requires nodeSSHFactory');
    }
    if (typeof NodeTransport !== 'function') {
        throw new TypeError('createL2tpNodeTransportFactory requires NodeTransport');
    }

    return node => new NodeTransport({
        nodeSSH: nodeSSHFactory(node),
    });
}

function createL2tpNodeTransportResolver({
    nodeExecutionResolver,
    NodeTransport = L2tpNodeTransport,
} = {}) {
    if (!nodeExecutionResolver || typeof nodeExecutionResolver.resolve !== 'function') {
        throw new TypeError('createL2tpNodeTransportResolver requires nodeExecutionResolver.resolve');
    }
    if (typeof NodeTransport !== 'function') {
        throw new TypeError('createL2tpNodeTransportResolver requires NodeTransport');
    }

    return async ({ nodeId }) => new NodeTransport({
        nodeSSH: await nodeExecutionResolver.resolve(nodeId),
    });
}

module.exports = {
    createL2tpNodeTransportFactory,
    createL2tpNodeTransportResolver,
};
