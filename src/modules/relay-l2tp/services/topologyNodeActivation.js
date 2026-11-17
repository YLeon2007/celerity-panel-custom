'use strict';
const { createHash } = require('node:crypto');
// Deliberately not a generic node deployment API. Client security on an
// already-owned portal MAIN only; ports, transport, users and placement stay applied.
const SECURITY_FIELDS = Object.freeze(['security', 'flow', 'alpn', 'realityDest', 'realitySni',
    'realityPrivateKey', 'realityPublicKey', 'realityShortIds', 'realitySpiderX', 'fingerprint', 'fingerprintPool']);
const fail = () => { throw Object.assign(new Error('Invalid explicit node activation'), { code: 'INVALID_TOPOLOGY_INTENT' }); };
function nodeActivation(value) {
    if (!value || Object.getPrototypeOf(value) !== Object.prototype
        || Object.keys(value).sort().join() !== 'nodeId,targetProfile'
        || typeof value.nodeId !== 'string' || !/^[a-f0-9]{24}$/.test(value.nodeId)
        || value.targetProfile !== 'xray-main') fail();
    return { nodeId: value.nodeId, targetProfile: value.targetProfile };
}
function nodeSecurityPayload(node, activation) {
    activation = nodeActivation(activation);
    if (String(node?._id ?? node?.id) !== activation.nodeId || node.type !== 'xray' || node.active !== true
        || (node.cascadeRole ?? node.role) !== 'portal') fail();
    const xray = node.xray || {};
    if (!['none', 'reality'].includes(xray.security || 'none')) fail();
    return JSON.parse(JSON.stringify(Object.fromEntries(SECURITY_FIELDS
        .filter(key => xray[key] !== undefined).map(key => [key, xray[key]]))));
}
function nodeDesiredVersion(node, activation) {
    const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
        ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
    return createHash('sha256').update(JSON.stringify(canonical({ nodeActivation: nodeActivation(activation),
        security: nodeSecurityPayload(node, activation) }))).digest('hex');
}
async function selectedDesiredVersion(dependencies, link, activation, session) {
    if (!activation) return require('./topologyIntentService').linkDesiredVersion(link);
    const normalized = nodeActivation(activation);
    const node = await dependencies.HyNode.findById(normalized.nodeId)
        .select(`type active cascadeRole ${SECURITY_FIELDS.map(key => `xray.${key}`).join(' ')}`).session(session).lean();
    return nodeDesiredVersion(node, normalized);
}
function overlayNodeSecurity(before, desired, activation) {
    const patch = nodeSecurityPayload(desired, activation);
    nodeSecurityPayload(before, activation);
    const xray = { ...before.xray };
    for (const key of SECURITY_FIELDS) delete xray[key];
    return { ...before, xray: { ...xray, ...patch } };
}
module.exports = { SECURITY_FIELDS, nodeActivation, nodeSecurityPayload, nodeDesiredVersion, selectedDesiredVersion, overlayNodeSecurity };
