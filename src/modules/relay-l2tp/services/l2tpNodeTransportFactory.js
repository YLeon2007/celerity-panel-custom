'use strict';

const { bindExecutionAuthorization, assertExecutionAuthorized, assertExecutionBinding } = require('../domain/l2tpExecutionAuthorization');

const { createHash } = require('node:crypto');

const { L2tpNodeTransport } = require('./l2tpNodeTransport');
const { createL2tpArtifactBootstrapper } = require('./l2tpArtifactBootstrapper');

function createL2tpNodeTransportFactory({
    executionContext,
    enableProductionExecution = false,
    nodeSSHFactory,
    NodeTransport = L2tpNodeTransport,
} = {}) {
    if (typeof nodeSSHFactory !== 'function') {
        throw new TypeError('createL2tpNodeTransportFactory requires nodeSSHFactory');
    }
    if (typeof NodeTransport !== 'function') {
        throw new TypeError('createL2tpNodeTransportFactory requires NodeTransport');
    }

    const authorization = {};
    bindExecutionAuthorization(authorization, { executionContext, enableProductionExecution });
    return node => {
        assertExecutionAuthorized(authorization);
        return new NodeTransport({
            executionContext: authorization.executionContext,
            enableProductionExecution: authorization.enableProductionExecution,
            nodeSSH: nodeSSHFactory(node),
        });
    };
}

function defaultArtifactBootstrapper(nodeSSH) {
    try {
        return createL2tpArtifactBootstrapper({ nodeSSH, createHash });
    } catch {
        return null;
    }
}

function createL2tpNodeTransportResolver({
    executionContext,
    enableProductionExecution = false,
    nodeExecutionResolver,
    NodeTransport = L2tpNodeTransport,
} = {}) {
    if (!nodeExecutionResolver || typeof nodeExecutionResolver.resolve !== 'function') {
        throw new TypeError('createL2tpNodeTransportResolver requires nodeExecutionResolver.resolve');
    }
    if (typeof NodeTransport !== 'function') {
        throw new TypeError('createL2tpNodeTransportResolver requires NodeTransport');
    }

    const authorization = {};
    bindExecutionAuthorization(authorization, { executionContext, enableProductionExecution });
    return async ({ nodeId, executionContext: binding }) => {
        assertExecutionBinding(authorization, binding);
        const nodeSSH = await nodeExecutionResolver.resolve(nodeId, authorization.executionContext);
        return new NodeTransport({
            nodeSSH,
            executionContext: authorization.executionContext,
            enableProductionExecution: authorization.enableProductionExecution,
            artifactBootstrapper: defaultArtifactBootstrapper(nodeSSH),
        });
    };
}

module.exports = {
    createL2tpNodeTransportFactory,
    createL2tpNodeTransportResolver,
};
