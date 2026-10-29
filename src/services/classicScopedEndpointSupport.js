'use strict';
const net = require('node:net');
function sourceHost(value) {
    if (typeof value !== 'string') return false;
    if (net.isIP(value)) return true;
    const labels = value.split('.');
    return value.length <= 253 && labels.length > 1 && /[A-Za-z]/.test(labels.at(-1))
        && labels.every(label => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}
// Shared preclaim and held-core capability contract. Not authorization: callers
// must separately validate grants, graph/ownership, revision and physical state.
function scopedClassicEndpointsSupported(source, bridge) {
    return source?.type === 'xray' && ['portal', 'relay'].includes(source.cascadeRole)
        && source.active === true && bridge?.active === true
        && sourceHost(source.ip) && !!net.isIP(bridge.ip || '')
        && [source, bridge].every(node => !!(node.ssh?.password || node.ssh?.privateKey));
}
module.exports = { scopedClassicEndpointsSupported };
