'use strict';

class XrayConfigComposerError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'XrayConfigComposerError';
        this.code = code;
        Object.assign(this, details);
    }
}

function compareIds(left, right) {
    return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

function assertBaseConfig(baseConfig) {
    let field;
    if (baseConfig === null || typeof baseConfig !== 'object' || Array.isArray(baseConfig)) {
        field = 'baseConfig';
    } else if (!Array.isArray(baseConfig.inbounds)) {
        field = 'inbounds';
    } else if (!Array.isArray(baseConfig.outbounds)) {
        field = 'outbounds';
    } else if (
        baseConfig.routing === null
        || typeof baseConfig.routing !== 'object'
        || Array.isArray(baseConfig.routing)
    ) {
        field = 'routing';
    } else if (!Array.isArray(baseConfig.routing.rules)) {
        field = 'routing.rules';
    }

    if (field) {
        throw new XrayConfigComposerError(
            'INVALID_BASE_XRAY_CONFIG',
            `Invalid base Xray config field: ${field}`,
            { field },
        );
    }
}

function assertCanonicalFragment(fragment, fragmentIndex) {
    let field;
    if (fragment === null || typeof fragment !== 'object' || Array.isArray(fragment)) {
        field = 'fragment';
    } else if (typeof fragment.id !== 'string' || fragment.id.length === 0) {
        field = 'id';
    } else {
        field = ['inbounds', 'outbounds', 'routingRules']
            .find(candidate => !Array.isArray(fragment[candidate]));
    }

    if (field) {
        throw new XrayConfigComposerError(
            'INVALID_XRAY_CONFIG_FRAGMENT',
            `Invalid Xray config fragment field: ${field}`,
            {
                fragmentIndex,
                fragmentId: fragment?.id,
                field,
            },
        );
    }
}

function assertUniqueFragmentIds(fragments) {
    const fragmentIds = new Set();
    for (const fragment of fragments) {
        if (fragmentIds.has(fragment.id)) {
            throw new XrayConfigComposerError(
                'DUPLICATE_XRAY_CONFIG_FRAGMENT_ID',
                `Duplicate Xray config fragment id: ${fragment.id}`,
                { fragmentId: fragment.id },
            );
        }
        fragmentIds.add(fragment.id);
    }
}

function assertUniqueTags(items, code) {
    const tags = new Set();
    for (const item of items) {
        if (item.tag === undefined) continue;
        if (tags.has(item.tag)) {
            throw new XrayConfigComposerError(code, `Duplicate Xray tag: ${item.tag}`, {
                tag: item.tag,
            });
        }
        tags.add(item.tag);
    }
}

function assertUniqueListeners(inbounds) {
    const listeners = new Set();
    for (const inbound of inbounds) {
        if (inbound.port === undefined) continue;
        const listen = inbound.listen ?? '0.0.0.0';
        const key = JSON.stringify([listen, String(inbound.port)]);
        if (listeners.has(key)) {
            throw new XrayConfigComposerError(
                'DUPLICATE_INBOUND_LISTENER',
                `Duplicate Xray inbound listener: ${listen}:${inbound.port}`,
                { listen, port: inbound.port },
            );
        }
        listeners.add(key);
    }
}

function composeXrayConfig(baseConfig, fragments) {
    assertBaseConfig(baseConfig);
    if (!Array.isArray(fragments)) {
        throw new XrayConfigComposerError(
            'INVALID_XRAY_CONFIG_FRAGMENTS',
            'Xray config fragments must be an array',
            { field: 'fragments' },
        );
    }
    fragments.forEach(assertCanonicalFragment);
    assertUniqueFragmentIds(fragments);
    const sortedFragments = [...fragments].sort(compareIds);
    const inbounds = [
        baseConfig.inbounds,
        ...sortedFragments.map(fragment => fragment.inbounds),
    ].flat();
    assertUniqueTags(inbounds, 'DUPLICATE_INBOUND_TAG');
    assertUniqueListeners(inbounds);
    assertUniqueTags(
        [baseConfig.outbounds, ...sortedFragments.map(fragment => fragment.outbounds)].flat(),
        'DUPLICATE_OUTBOUND_TAG',
    );

    const config = structuredClone(baseConfig);

    for (const fragment of sortedFragments) {
        config.inbounds.push(...structuredClone(fragment.inbounds));
        config.outbounds.push(...structuredClone(fragment.outbounds));
        config.routing.rules.push(...structuredClone(fragment.routingRules));
    }

    return config;
}

module.exports = { composeXrayConfig };
