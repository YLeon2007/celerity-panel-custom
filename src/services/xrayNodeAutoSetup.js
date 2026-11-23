'use strict';

function isXrayBridge(node) {
    return node.type === 'xray' && node.cascadeRole === 'bridge';
}

// A bridge only stages Xray. Its runtime config belongs to cascade deployment.
async function setupXrayForRole(node, { restartService = true } = {}) {
    const nodeSetup = require('./nodeSetup');
    if (!isXrayBridge(node)) return nodeSetup.setupXrayNodeWithAgent(node, { restartService });

    const result = await nodeSetup.setupXrayNode(node, { restartService: false, exitOnly: true });
    if (result.success) {
        result.logs = result.logs || [];
        result.logs.push('[Bridge] Xray installed. Create a cascade link to deploy bridge config.');
    }
    return result;
}

module.exports = { isXrayBridge, setupXrayForRole };
