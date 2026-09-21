'use strict';

const { loadModules } = require('./loadModules');
const relayL2tpManifest = require('./relay-l2tp/manifest.json');
const relayL2tpEntry = require('./relay-l2tp');

const modules = [{
    manifest: relayL2tpManifest,
    entry: relayL2tpEntry,
}];

function bootstrapModules(hostCapabilities) {
    const registry = loadModules({
        hostCapabilities,
        modules,
    });

    return { registry, modules };
}

module.exports = {
    bootstrapModules,
};
