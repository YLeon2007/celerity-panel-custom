'use strict';

const MODULE_INDEX_MODEL_NAMES = Object.freeze([
    'RelayL2tpState',
    'L2tpUser',
    'CascadeRouteGroup',
    'CascadeTopologyState',
    'L2tpOperation',
    'TopologyOperation',
    'NodeOperationLock',
]);

const ensureModuleIndexes = Object.freeze({
    id: '001-ensure-module-indexes',
    version: 1,
    steps: Object.freeze(MODULE_INDEX_MODEL_NAMES.map(modelName => Object.freeze({
        action: 'createIndexes',
        modelName,
    }))),
});

const migrations = Object.freeze([ensureModuleIndexes]);

module.exports = {
    migrations,
    MODULE_INDEX_MODEL_NAMES,
};
