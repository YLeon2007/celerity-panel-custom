'use strict';

const { KCP_INPUT_FIELDS, sanitizeKcpInput } = require('../utils/cascadeTransport');

const INVALID_KCP_LINK_SETTINGS = 'INVALID_KCP_LINK_SETTINGS';
const invalidKcp = message => Object.assign(new Error(message), { code: INVALID_KCP_LINK_SETTINGS });

function readKcpFields(input = {}) {
    for (const key of KCP_INPUT_FIELDS) {
        if (!Object.hasOwn(input, key)) continue;
        const value = input[key];
        // An empty optional control is an omission, not a reset. Reject
        // structured JSON and booleans before the upstream numeric coercion.
        if (value == null || value === '') continue;
        if (typeof value !== 'string' && (key === 'kcpHeader' || typeof value !== 'number')) {
            throw invalidKcp(`${key} has an invalid type`);
        }
    }
    const { fields, error } = sanitizeKcpInput(input);
    if (error) throw invalidKcp(error);
    return fields;
}

function assertKcpSecurity(transport, security) {
    if (transport === 'kcp' && security !== 'none' && security !== 'tls') {
        throw invalidKcp('mKCP requires none or TLS security');
    }
}

function publicCascadeLink(link) {
    if (!link) return link;
    const { kcpPassword: _serverOwned, ...fields } = typeof link.toJSON === 'function' ? link.toJSON() : link;
    return fields;
}

module.exports = { INVALID_KCP_LINK_SETTINGS, readKcpFields, assertKcpSecurity, publicCascadeLink };
