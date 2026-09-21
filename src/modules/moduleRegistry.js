'use strict';

const SUPPORTED_MODULE_API_VERSION = 1;

function createModuleRegistry(hostCapabilities = []) {
    const capabilities = new Set(hostCapabilities);
    const entries = [];

    function validate(manifest) {
        if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
            throw new TypeError('manifest must be an object');
        }

        for (const field of ['id', 'version', 'moduleApiVersion', 'requiredCapabilities']) {
            if (manifest[field] === undefined || manifest[field] === null) {
                throw new TypeError(`manifest.${field} is required`);
            }
        }

        if (typeof manifest.id !== 'string' || manifest.id.trim() === '') {
            throw new TypeError('manifest.id must be a non-empty string');
        }

        if (typeof manifest.version !== 'string' || manifest.version.trim() === '') {
            throw new TypeError('manifest.version must be a non-empty string');
        }

        if (!Array.isArray(manifest.requiredCapabilities)
            || manifest.requiredCapabilities.some(capability => (
                typeof capability !== 'string' || capability.trim() === ''
            ))) {
            throw new TypeError('manifest.requiredCapabilities must be an array of non-empty strings');
        }

        if (manifest.moduleApiVersion !== SUPPORTED_MODULE_API_VERSION) {
            throw new Error(`Unsupported module API version: ${manifest.moduleApiVersion}`);
        }

        const missingCapabilities = manifest.requiredCapabilities
            .filter(capability => !capabilities.has(capability));

        if (missingCapabilities.length > 0) {
            throw new Error(`Missing required capabilities: ${missingCapabilities.join(', ')}`);
        }

        return manifest;
    }

    return {
        validate,

        register(manifest, moduleImplementation) {
            validate(manifest);

            if (entries.some(entry => entry.manifest.id === manifest.id)) {
                throw new Error(`Module id already registered: ${manifest.id}`);
            }

            entries.push({ manifest, moduleImplementation });
        },

        list() {
            return entries.map(entry => entry.manifest);
        },
    };
}

module.exports = {
    createModuleRegistry,
};
