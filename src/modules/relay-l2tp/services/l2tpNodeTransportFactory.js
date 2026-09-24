'use strict';

const { createHash } = require('node:crypto');

const { L2tpNodeTransport } = require('./l2tpNodeTransport');
const { createL2tpArtifactBootstrapper } = require('./l2tpArtifactBootstrapper');

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

function defaultArtifactBootstrapper(nodeSSH) {
    try {
        return createL2tpArtifactBootstrapper({ nodeSSH, createHash });
    } catch {
        return null;
    }
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

    return async ({ nodeId }) => {
        const nodeSSH = await nodeExecutionResolver.resolve(nodeId);
        return new NodeTransport({
            nodeSSH,
            artifactBootstrapper: defaultArtifactBootstrapper(nodeSSH),
        });
    };
}

module.exports = {
    createL2tpNodeTransportFactory,
    createL2tpNodeTransportResolver,
};
