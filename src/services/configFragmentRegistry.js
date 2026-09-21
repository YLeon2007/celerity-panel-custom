'use strict';

class ConfigFragmentRegistryError extends Error {
    constructor(code, providerId, message, details = {}) {
        super(message);
        this.name = 'ConfigFragmentRegistryError';
        this.code = code;
        this.providerId = providerId;
        Object.assign(this, details);
    }
}

function deepFreeze(value, seen = new WeakSet()) {
    if (value === null || typeof value !== 'object' || seen.has(value)) return value;

    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
        deepFreeze(value[key], seen);
    }
    return Object.freeze(value);
}

function createConfigFragmentRegistry(knownProviderIds = []) {
    const knownProviders = new Set(knownProviderIds);
    const providers = new Map();

    return {
        register(providerId, provider) {
            if (!knownProviders.has(providerId)) {
                throw new ConfigFragmentRegistryError(
                    'UNKNOWN_CONFIG_FRAGMENT_PROVIDER',
                    providerId,
                    `Unknown config fragment provider: ${providerId}`,
                );
            }
            if (providers.has(providerId)) {
                throw new ConfigFragmentRegistryError(
                    'DUPLICATE_CONFIG_FRAGMENT_PROVIDER',
                    providerId,
                    `Config fragment provider already registered: ${providerId}`,
                );
            }
            providers.set(providerId, provider);
        },

        compose(snapshot) {
            const frozenSnapshot = deepFreeze(snapshot);
            return [...providers.entries()]
                .sort(([leftId], [rightId]) => (
                    leftId < rightId ? -1 : leftId > rightId ? 1 : 0
                ))
                .map(([providerId, provider]) => {
                    const fragment = provider(frozenSnapshot);
                    const fragmentId = fragment?.id;
                    if (fragmentId !== providerId) {
                        throw new ConfigFragmentRegistryError(
                            'CONFIG_FRAGMENT_PROVIDER_ID_MISMATCH',
                            providerId,
                            `Config fragment id must match provider id: ${providerId}`,
                            { fragmentId },
                        );
                    }
                    return fragment;
                });
        },
    };
}

module.exports = {
    ConfigFragmentRegistryError,
    createConfigFragmentRegistry,
};
