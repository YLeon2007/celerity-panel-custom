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

module.exports = {
    createL2tpNodeTransportFactory,
};
