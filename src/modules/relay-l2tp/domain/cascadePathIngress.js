'use strict';

const { createHash } = require('node:crypto');

// Reserved loopback port range for per-path cascade socks ingress listeners on
// relay nodes. Kept clear of tunnel defaults (10086/10087) and the Xray API
// port (61000) so listeners never collide with existing services.
const INGRESS_PORT_BASE = 18000;
const INGRESS_PORT_SPAN = 2000;

function assertIdentity(value, name) {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`cascade path ingress requires a non-empty string ${name}`);
    }
    return value;
}

function cascadePathIngressPort(groupId, pathKey) {
    assertIdentity(groupId, 'groupId');
    assertIdentity(pathKey, 'pathKey');
    const digest = createHash('sha256')
        .update(`cascade-path-ingress:${groupId}:${pathKey}`)
        .digest();
    return INGRESS_PORT_BASE + (digest.readUInt32BE(0) % INGRESS_PORT_SPAN);
}

function cascadePathIngressTag(pathKey) {
    assertIdentity(pathKey, 'pathKey');
    return `cascade-${pathKey}`;
}

module.exports = {
    INGRESS_PORT_BASE,
    INGRESS_PORT_SPAN,
    cascadePathIngressPort,
    cascadePathIngressTag,
};
