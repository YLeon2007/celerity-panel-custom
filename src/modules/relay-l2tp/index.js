'use strict';

const manifest = require('./manifest.json');

function validateHost(hostCapabilities, candidateManifest = manifest) {
    return candidateManifest;
}

function registerModels({ modelRegistry } = {}) {
    const models = {
        RelayL2tpState: require('./models/relayL2tpStateModel'),
        L2tpUser: require('./models/l2tpUserModel'),
        CascadeRouteGroup: require('./models/cascadeRouteGroupModel'),
        CascadeTopologyState: require('./models/cascadeTopologyStateModel'),
        L2tpOperation: require('./models/l2tpOperationModel'),
        TopologyOperation: require('./models/topologyOperationModel'),
        NodeOperationLock: require('./models/nodeOperationLockModel'),
    };

    if (modelRegistry) {
        for (const [modelName, modelConstructor] of Object.entries(models)) {
            modelRegistry.register(modelName, modelConstructor);
        }
    }

    return models;
}

function registerConfigFragments({ configFragmentRegistry }) {
    const { buildL2tpXrayFragment } = require('./services/l2tpXrayFragmentProvider');

    configFragmentRegistry.register(manifest.id, buildL2tpXrayFragment);
    return buildL2tpXrayFragment;
}

module.exports = {
    manifest,
    validateHost,
    registerModels,
    registerConfigFragments,
};
