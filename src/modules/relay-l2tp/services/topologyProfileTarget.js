'use strict';

// Shape/digest helpers only: a pin is NOT remote authority. Dispatch still
// requires an independently read owner, enrollment/binding and held authority.
const { createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const mongoose = require('mongoose');
const { topologyExecutionContext, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const ID = /^[a-f0-9]{24}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const PIN_KEYS = Object.freeze(['version', 'layout', 'nodeId', 'role', 'targetProfile',
    'ownerGeneration', 'descriptorSha256', 'ownerEvidenceSha256']);
const TARGETS = Object.freeze({
    'xray-main': Object.freeze({ targetProfile: 'xray-main', configPath: '/usr/local/etc/xray/config.json',
        serviceUnit: 'xray.service', serviceUnitPath: '/etc/systemd/system/xray.service' }),
    'xray-bridge': Object.freeze({ targetProfile: 'xray-bridge', configPath: '/usr/local/etc/xray-bridge/config.json',
        serviceUnit: 'xray-bridge.service', serviceUnitPath: '/etc/systemd/system/xray-bridge.service' }),
});
function failure(suffix = 'INVALID') {
    const code = `TOPOLOGY_PROFILE_TARGET_${suffix}`;
    return Object.assign(new Error(code), { code });
}
function requireValid(condition) { if (!condition) throw failure(); }
function plain(value) {
    return value instanceof mongoose.Document
        ? value.toObject({ depopulate: true, getters: false, virtuals: false, transform: false }) : value;
}
function object(value) { return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) {
    return object(value) && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function matches(value, pattern) { return typeof value === 'string' && pattern.test(value); }
function freeze(value) {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
}
function nodeHex(value) {
    // Deliberate BSON serialization, not duck typing or ID repair.
    const id = value instanceof mongoose.Types.ObjectId ? value.toHexString() : value;
    requireValid(matches(id, ID));
    return id;
}
function assertProfileTargetPin(input) {
    const value = plain(input);
    requireValid(exact(value, PIN_KEYS) && value.version === 1 && value.layout === 'legacy-forward-main'
        && matches(value.nodeId, ID) && ['portal', 'bridge'].includes(value.role)
        && value.targetProfile === 'xray-main' && matches(value.ownerGeneration, UUID)
        && matches(value.descriptorSha256, SHA) && matches(value.ownerEvidenceSha256, SHA));
    return freeze(Object.fromEntries(PIN_KEYS.map(key => [key, value[key]])));
}

// JSON objects sort recursively; arrays and embedded profileConfig strings do
// not. No toJSON/coercion hooks, BSON, Dates, undefined or sparse arrays here.
function canonicalProfileTargetJSON(value) {
    const active = new Set();
    function canonical(item) {
        if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
        if (typeof item === 'number') { requireValid(Number.isFinite(item)); return item; }
        requireValid(item && typeof item === 'object' && !active.has(item));
        active.add(item);
        let result;
        if (Array.isArray(item)) {
            requireValid(Reflect.ownKeys(item).length === item.length + 1);
            result = Array.from({ length: item.length }, (_, i) => {
                requireValid(Object.hasOwn(item, i)); return canonical(item[i]);
            });
        } else {
            requireValid(object(item) && Reflect.ownKeys(item).length === Object.keys(item).length);
            result = Object.fromEntries(Object.keys(item).sort().map(key => [key, canonical(item[key])]));
        }
        active.delete(item);
        return result;
    }
    return JSON.stringify(canonical(value));
}
const digest = value => createHash('sha256').update(canonicalProfileTargetJSON(value), 'utf8').digest('hex');
function receiptProjection(input) {
    requireValid(exact(input, ['proofId', 'maintenanceId', 'fromGeneration', 'toGeneration',
        'oldBackendInstanceId', 'oldPid', 'oldProcessStartTime', 'verifiedAt']));
    const value = { ...input };
    if (value.verifiedAt instanceof Date) {
        requireValid(Number.isFinite(value.verifiedAt.getTime()));
        value.verifiedAt = value.verifiedAt.toISOString();
    }
    requireValid(['proofId', 'maintenanceId', 'fromGeneration', 'toGeneration'].every(key => matches(value[key], UUID))
        && value.fromGeneration !== value.toGeneration
        && typeof value.oldBackendInstanceId === 'string' && value.oldBackendInstanceId.length > 0
        && Number.isSafeInteger(value.oldPid) && value.oldPid > 0
        && typeof value.oldProcessStartTime === 'string' && value.oldProcessStartTime.length > 0
        && typeof value.verifiedAt === 'string' && Number.isFinite(Date.parse(value.verifiedAt))
        && new Date(value.verifiedAt).toISOString() === value.verifiedAt);
    return value;
}
function ownerEvidence(input) {
    const owner = plain(input);
    requireValid(object(owner));
    const context = topologyExecutionContext(owner.executionContext?.target, owner.executionContext?.hostIdentity);
    requireValid(matchesTopologyExecutionContext(owner.executionContext, context)
        && owner.owner === 'topology' && owner.profile === 'xray-main' && matches(owner.generation, UUID)
        && !Object.hasOwn(owner, 'handbackReceipt')
        && exact(owner.nodeIdentity, ['machineId', 'sshHostKeySha256'])
        && matches(owner.nodeIdentity.machineId, /^[a-f0-9]{32}$/) && matches(owner.nodeIdentity.sshHostKeySha256, SHA)
        && exact(owner.originalSnapshot, ['configSha256', 'unitSha256', 'serviceActive', 'serviceEnabled'])
        && matches(owner.originalSnapshot.configSha256, SHA) && matches(owner.originalSnapshot.unitSha256, SHA)
        && ['active', 'inactive'].includes(owner.originalSnapshot.serviceActive)
        && ['enabled', 'disabled', 'masked'].includes(owner.originalSnapshot.serviceEnabled)
        && exact(owner.legacyAppliedTopology, ['nodes', 'links', 'groups']));
    const receipt = receiptProjection(owner.adoptionReceipt);
    requireValid(receipt.toGeneration === owner.generation);
    return { executionContext: { ...context }, node: nodeHex(owner.node), profile: owner.profile, owner: 'topology',
        generation: owner.generation, nodeIdentity: { ...owner.nodeIdentity }, originalSnapshot: { ...owner.originalSnapshot },
        adoptionReceipt: receipt, descriptorSha256: digest(owner.legacyAppliedTopology) };
}

// Pure deterministic mechanics, NOT root qualification. Exported separately so
// BSON/JSON and settlement invariance can be tested without a fake verifier.
function importedProfileTargetDigests(owner) {
    const evidence = ownerEvidence(owner);
    return freeze({ descriptorSha256: evidence.descriptorSha256, ownerEvidenceSha256: digest(evidence) });
}
function nativeClientShape(node) {
    const xray = node.xray;
    const supported = value => object(value)
        && (value.security === undefined || ['none', 'reality'].includes(value.security))
        && (value.transport === undefined || value.transport === 'tcp')
        && (value.protocol === undefined || value.protocol === 'vless');
    return (xray === undefined || supported(xray))
        && (xray?.extraInbounds === undefined || Array.isArray(xray.extraInbounds) && xray.extraInbounds.every(supported));
}
function boundedTopology(topology, { empty = false } = {}) {
    requireValid(exact(topology, ['nodes', 'links', 'groups']) && Array.isArray(topology.nodes)
        && Array.isArray(topology.links) && topology.nodes.every(object) && topology.links.every(object)
        && Array.isArray(topology.groups) && topology.groups.length === 0
        && (topology.nodes.length === 2 || empty && topology.nodes.length === 0)
        && (topology.links.length === 1 || empty && topology.links.length === 0));
    canonicalProfileTargetJSON(topology);
    if (!topology.nodes.length) { requireValid(!topology.links.length); return; }
    const [portal] = topology.nodes.filter(node => node.role === 'portal');
    const [bridge] = topology.nodes.filter(node => node.role === 'bridge');
    requireValid(portal && bridge && portal.id !== bridge.id
        && topology.nodes.every(node => matches(node.id, ID) && node.type === 'xray' && node.active === true && nativeClientShape(node)));
    if (!topology.links.length) return;
    const [link] = topology.links;
    requireValid(matches(link.id, ID) && link.source === portal.id && link.target === bridge.id
        && link.mode === 'forward' && link.active === true && matches(link.tunnelUuid, UUID)
        && Number.isSafeInteger(link.tunnelPort) && link.tunnelPort >= 1 && link.tunnelPort <= 65535
        && (link.tunnelProtocol === undefined || link.tunnelProtocol === 'vless')
        && (link.tunnelTransport === undefined || link.tunnelTransport === 'tcp')
        && (link.tunnelSecurity === undefined || ['none', 'reality'].includes(link.tunnelSecurity))
        && !Object.hasOwn(link, 'lifecycle'));
}
function projectImportedProfileTargetPin(input) {
    const owner = plain(input), evidence = ownerEvidence(owner);
    boundedTopology(owner.legacyAppliedTopology);
    const descriptor = owner.legacyAppliedTopology.nodes.find(node => node.id === evidence.node);
    requireValid(descriptor && typeof descriptor.profileConfig === 'string'
        && createHash('sha256').update(descriptor.profileConfig, 'utf8').digest('hex') === evidence.originalSnapshot.configSha256);
    // Lazy, fixed dependency avoids transfer -> repository/composer -> helper
    // import cycles when B1 uses this projector during adoption. No injectable
    // verifier/caller permit. A0 intentionally retains the real verifier's
    // CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED for forward. B1 must extend that
    // private recognizer/readback contract only after all consumers are ready.
    const { verifyLegacyAppliedProfile } = require('../../../services/topologyConfigTransfer');
    const verified = verifyLegacyAppliedProfile(owner.legacyAppliedTopology, {
        node: evidence.node, profile: evidence.profile, originalSnapshot: evidence.originalSnapshot });
    requireValid(same(verified, owner.legacyAppliedTopology));
    return assertProfileTargetPin({ version: 1, layout: 'legacy-forward-main', nodeId: evidence.node,
        role: descriptor.role, targetProfile: evidence.profile, ownerGeneration: evidence.generation,
        descriptorSha256: evidence.descriptorSha256, ownerEvidenceSha256: digest(evidence) });
}
function verifyImportedProfileTargetPin({ owner: input, profileTargetPin, executionContext } = {}) {
    const pin = assertProfileTargetPin(profileTargetPin), owner = plain(input);
    const context = topologyExecutionContext(executionContext?.target, executionContext?.hostIdentity);
    if (!owner || !matchesTopologyExecutionContext(executionContext, context)
        || !matchesTopologyExecutionContext(owner.executionContext, context)
        || !Object.hasOwn(owner, 'profileTargetPin')) throw failure('STALE');
    const saved = assertProfileTargetPin(owner.profileTargetPin);
    if (!same(saved, pin)) throw failure('STALE');
    // Detect changed root bytes before recognition. Equal shape/digests still
    // cannot skip the real legacy verifier below (nor supply remote authority).
    let evidence;
    try { evidence = ownerEvidence(owner); }
    catch { throw failure('STALE'); }
    if (evidence.node !== pin.nodeId || evidence.profile !== pin.targetProfile
        || evidence.generation !== pin.ownerGeneration || evidence.descriptorSha256 !== pin.descriptorSha256
        || digest(evidence) !== pin.ownerEvidenceSha256) throw failure('STALE');
    const projected = projectImportedProfileTargetPin(owner);
    if (!same(projected, pin)) throw failure('STALE');
    return projected;
}
function resolveTopologyProfileTarget(input = {}) {
    requireValid(object(input));
    const { nodeId, role, targetProfile } = input;
    requireValid(matches(nodeId, ID) && ['portal', 'relay', 'bridge'].includes(role));
    if (Object.hasOwn(input, 'profileTargetPin')) {
        const pin = assertProfileTargetPin(input.profileTargetPin);
        requireValid(pin.nodeId === nodeId && pin.role === role && targetProfile === pin.targetProfile);
        return TARGETS[pin.targetProfile];
    }
    const native = role === 'portal' ? 'xray-main' : 'xray-bridge';
    requireValid(targetProfile === undefined || targetProfile === native);
    return TARGETS[native];
}
function assertSelectedProfileTargets(input) {
    const operation = plain(input);
    const nodes = operation?.nodes, owners = operation?.selectedOwnerPins;
    const present = values => Array.isArray(values) && values.some(value => value && Object.hasOwn(value, 'profileTargetPin'));
    if (!present(nodes) && !present(owners)) return; // Native inputs remain untouched.
    requireValid(operation.admissionScope === 'selected' && ['link.apply', 'link.delete'].includes(operation.kind)
        && operation.installedPath === undefined && operation.groupId === undefined && operation.pathKey === undefined
        && Array.isArray(nodes) && nodes.length === 2 && nodes.every(object)
        && Array.isArray(owners) && owners.length === 2 && owners.every(object)
        && Array.isArray(operation.resourceNodeIds) && operation.resourceNodeIds.length === 2);
    const pins = nodes.map(node => {
        requireValid(Object.hasOwn(node, 'profileTargetPin'));
        const pin = assertProfileTargetPin(node.profileTargetPin);
        resolveTopologyProfileTarget({ nodeId: nodeHex(node.node), role: node.role, targetProfile: node.targetProfile, profileTargetPin: pin });
        const matching = owners.filter(owner => nodeHex(owner.node) === pin.nodeId);
        requireValid(matching.length === 1);
        const owner = matching[0];
        requireValid(Object.hasOwn(owner, 'profileTargetPin') && same(assertProfileTargetPin(owner.profileTargetPin), pin)
            && owner.owner === 'topology' && owner.profile === pin.targetProfile && owner.generation === pin.ownerGeneration
            && !Object.hasOwn(owner, 'handbackReceipt')
            && matchesTopologyExecutionContext(owner.executionContext,
                topologyExecutionContext(operation.executionContext?.target, operation.executionContext?.hostIdentity))
            && same(owner.executionContext, operation.executionContext));
        return pin;
    });
    requireValid(new Set(pins.map(pin => pin.nodeId)).size === 2 && new Set(pins.map(pin => pin.role)).size === 2
        && pins[0].descriptorSha256 === pins[1].descriptorSha256
        && new Set(operation.resourceNodeIds).size === 2
        && operation.resourceNodeIds.every(id => pins.some(pin => pin.nodeId === id)));
    const union = new Set();
    for (const topology of [operation.baselineTopology, operation.effectiveTopology]) {
        boundedTopology(topology, { empty: true });
        for (const node of topology.nodes) {
            requireValid(pins.some(pin => pin.nodeId === node.id && pin.role === node.role)); union.add(node.id);
        }
    }
    requireValid(union.size === 2 && matches(operation.linkId, ID)
        && Array.isArray(operation.linkIds) && operation.linkIds.length === operation.effectiveTopology.links.length
        && operation.linkIds.every(id => operation.effectiveTopology.links.some(link => link.id === id)));
    if (operation.kind === 'link.apply') requireValid(operation.effectiveTopology.links.length === 1
        && operation.effectiveTopology.links[0].id === operation.linkId);
    else requireValid(operation.baselineTopology.links.length === 1 && operation.baselineTopology.links[0].id === operation.linkId
        && operation.effectiveTopology.links.length === 0);
}
module.exports = { assertProfileTargetPin, canonicalProfileTargetJSON, importedProfileTargetDigests,
    projectImportedProfileTargetPin, verifyImportedProfileTargetPin, resolveTopologyProfileTarget, assertSelectedProfileTargets };
