'use strict';

const { createModuleRegistry } = require('./moduleRegistry');

class ModuleLoaderError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'ModuleLoaderError';
        this.code = code;
        Object.assign(this, details);
    }
}

function loadModules({ hostCapabilities, modules }) {
    const registry = createModuleRegistry(hostCapabilities);

    for (const [descriptorIndex, descriptor] of modules.entries()) {
        const manifest = descriptor?.manifest;
        const entry = descriptor?.entry;

        if (entry === undefined || entry === null) {
            throw new ModuleLoaderError(
                'MODULE_ENTRY_REQUIRED',
                `Module entry is required for descriptor: ${manifest?.id ?? descriptorIndex}`,
                { moduleId: manifest?.id, descriptorIndex },
            );
        }

        registry.validate(manifest);
        if (typeof entry.validateHost === 'function') {
            entry.validateHost(hostCapabilities, manifest);
        }
        registry.register(manifest, entry);
    }

    return registry;
}

module.exports = {
    ModuleLoaderError,
    loadModules,
};
