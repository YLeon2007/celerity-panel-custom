#!/usr/bin/env node
'use strict';

/**
 * OFFLINE, READ-ONLY preflight. No runtime imports, deployment, discovery or Sync.
 * API: buildTransferManifest(records, {linkIds, linkFingerprints, inputSha256?}).
 * CLI (stdin only): node scripts/production-transfer-inventory.js < export.json
 * Input envelope: {records, expected}. Exit 0 = inventory proven; 2 = not ready.
 *
 * records v1: snapshotId, serverIdentity='prod', capturedAt (ISO), completeness
 * {links,nodes,profiles,listeners}:true, and arrays described by the direct tests.
 * Completeness covers all active links and all profiles/listeners on affected
 * execution hosts. linkIds must equal the full active+online set; any additional
 * possibly-active link sharing a selected node also blocks the preflight.
 * links/nodes retain server _id, portalNode/bridgeNode, mode, active/status and
 * cascadeRole. Missing legacy mode is UNKNOWN here, never defaulted to reverse.
 * Supplemental node evidence: executionHostId and exact profileIds. Profiles
 * bind nodeId, targetProfile, ownedLinkIds, config {path,sha256}, unit
 * {name,sha256,configPath}, serviceState {loadState,activeState,subState,
 * configSha256,unitSha256}, egress {kind,configSha256,linkIds?}. Listeners bind
 * linkId/nodeId/profileId, port/network/bindAddress, configSha256/unitSha256.
 * All evidence must come from one server export; completeness is a server
 * attestation, NOT something this offline utility can independently establish.
 *
 * Pin linkFingerprints from a separately accepted immutable baseline. IDs alone
 * cannot prove records unchanged. No pin-generation/adopt-all CLI is provided.
 * Hashes bind the complete JSON export, including unprojected fields. SHA-256
 * uses sorted object keys, canonical record-array order and sorted known ID
 * sets (profileIds, ownedLinkIds, egress.linkIds); other arrays retain order.
 * These are semantic JSON fingerprints, not raw-file byte hashes. The output
 * contains only allowlisted identifiers, paths, units and hashes, never configs,
 * credentials, addresses, arbitrary source/error strings. Export stays in memory.
 * A ready inventory is NOT maintenance authorization, freshness, live listener
 * verification, writer quiescence, rollback proof or end-to-end client proof.
 */
const { createHash } = require('node:crypto');

function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    }
    return value;
}
function sha(value) {
    return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}
function assertJson(value, seen = new Set(), depth = 0) {
    if (depth > 64) throw new Error('JSON input required');
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
    if (typeof value === 'number' && Number.isFinite(value)) return;
    if (typeof value !== 'object' || seen.has(value)) throw new Error('JSON input required');
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null && prototype !== Array.prototype) throw new Error('JSON input required');
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
        if (typeof key !== 'string') throw new Error('JSON input required');
        if (Array.isArray(value) && key === 'length') continue;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw new Error('JSON input required');
        assertJson(descriptor.value, seen, depth + 1);
    }
    if (Array.isArray(value) && Object.keys(value).length !== value.length) throw new Error('JSON input required');
    seen.delete(value);
}
function fingerprintLink(link) { assertJson(link); return sha(link); }
function freeze(value) {
    if (value && typeof value === 'object') {
        Object.values(value).forEach(freeze);
        Object.freeze(value);
    }
    return value;
}
function sorted(values) { return [...values].sort(); }
function components(links, nodesById) {
    const neighbors = new Map();
    for (const link of links) {
        for (const [a, b] of [[link.portalNode, link.bridgeNode], [link.bridgeNode, link.portalNode]]) {
            if (!neighbors.has(a)) neighbors.set(a, new Set());
            neighbors.get(a).add(b);
        }
    }
    const seen = new Set();
    const result = [];
    for (const root of sorted(neighbors.keys())) {
        if (seen.has(root)) continue;
        const queue = [root];
        const nodeIds = [];
        seen.add(root);
        while (queue.length) {
            const id = queue.shift();
            nodeIds.push(id);
            for (const next of sorted(neighbors.get(id))) {
                if (!seen.has(next)) { seen.add(next); queue.push(next); }
            }
        }
        nodeIds.sort();
        const members = new Set(nodeIds);
        const bridgeNodeIds = nodeIds.filter(id => nodesById.get(id).cascadeRole === 'bridge');
        const staged = nodeIds.some(id => !links.some(link => link.portalNode === id)
            && nodesById.get(id).cascadeRole !== 'bridge');
        result.push({ nodeIds, linkIds: links.filter(link => members.has(link.portalNode)).map(link => link._id),
            bridgeNodeIds, staged });
    }
    return result;
}
function refusal(reasons, inputSha256 = null) {
    return freeze({ inventoryReady: false, reasons: sorted(new Set(reasons)).map(code => ({ code })),
        clientReady: false, executionAuthorized: false, inputSha256, manifestSha256: null, manifest: null });
}
function orderedRecords(source) {
    const records = JSON.parse(JSON.stringify(source));
    for (const node of records.nodes ?? []) node.profileIds?.sort();
    for (const profile of records.profiles ?? []) {
        profile.ownedLinkIds?.sort();
        profile.egress?.linkIds?.sort();
    }
    // Normalize known set-valued evidence. All other arrays (notably route /
    // config arrays) retain their meaningful original ordering.
    for (const key of ['nodes', 'links', 'profiles', 'listeners']) {
        records[key]?.sort((a, b) => {
            const left = JSON.stringify(canonical(a));
            const right = JSON.stringify(canonical(b));
            return left < right ? -1 : left > right ? 1 : 0;
        });
    }
    return records;
}
const { isIP } = require('node:net');
const hashValue = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const identifier = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(value)
    && !['__proto__', 'constructor', 'prototype'].includes(value);
const idSet = value => Array.isArray(value) && value.every(identifier) && new Set(value).size === value.length;
const sameSet = (left, right) => idSet(left) && idSet(right)
    && JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
const configPath = value => typeof value === 'string' && /^\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+$/.test(value)
    && !value.split('/').some(part => part === '.' || part === '..');

function validateEvidence(records, links, affectedNodeIds, nodesById, profiles) {
    const reasons = [];
    const add = code => reasons.push(code);
    for (const [key, code] of [['nodes', 'DUPLICATE_NODE'], ['profiles', 'DUPLICATE_PROFILE']]) {
        if (new Set(records[key].map(item => item._id)).size !== records[key].length) add(code);
    }
    for (const link of links) {
        if (!['reverse', 'forward'].includes(link.mode) || !identifier(link.portalNode)
            || !identifier(link.bridgeNode) || link.portalNode === link.bridgeNode
            || !Number.isInteger(link.tunnelPort) || link.tunnelPort < 1 || link.tunnelPort > 65535) {
            add('LINK_DIRECTION_UNRESOLVED');
        }
    }
    for (const id of affectedNodeIds) {
        const node = nodesById.get(id);
        if (!node) { add('NODE_MISSING'); continue; }
        if (!['portal', 'relay', 'bridge'].includes(node.cascadeRole)) add('UNKNOWN_NODE_ROLE');
        if (node.type !== 'xray' || node.active !== true || node.status !== 'online') add('NODE_NOT_ACTIVE_ONLINE_XRAY');
        if (!identifier(node.executionHostId)) add('NODE_EXECUTION_HOST_REQUIRED');
        if (!idSet(node.profileIds) || !node.profileIds.length) add('NODE_PROFILES_UNKNOWN');
        else if (!sameSet(node.profileIds, profiles.filter(profile => profile.nodeId === id).map(profile => profile._id))) {
            add('PROFILE_SET_MISMATCH');
        }
    }
    for (const link of records.links.filter(item => !links.includes(item) && item.active !== false)) {
        if ([link.portalNode, link.bridgeNode].some(id => affectedNodeIds.includes(id))) add('ACTIVE_LINK_OUTSIDE_EXPLICIT_SCOPE');
    }
    for (const profile of profiles) {
        if (!identifier(profile.targetProfile)) add('PROFILE_EVIDENCE_REQUIRED');
        if (!configPath(profile.config?.path) || !hashValue(profile.config?.sha256)) add('CONFIG_EVIDENCE_REQUIRED');
        if (typeof profile.unit?.name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.@-]*\.service$/.test(profile.unit.name)
            || !hashValue(profile.unit?.sha256)) add('UNIT_EVIDENCE_REQUIRED');
        if (profile.unit?.configPath !== profile.config?.path) add('UNIT_CONFIG_MISMATCH');
        const state = profile.serviceState;
        if (state?.loadState !== 'loaded' || state?.activeState !== 'active' || state?.subState !== 'running'
            || !hashValue(state.configSha256) || state.configSha256 !== profile.config?.sha256
            || !hashValue(state.unitSha256) || state.unitSha256 !== profile.unit?.sha256) add('SERVICE_STATE_UNPROVEN');
        const incident = links.filter(link => [link.portalNode, link.bridgeNode].includes(profile.nodeId)).map(link => link._id);
        if (!idSet(profile.ownedLinkIds) || profile.ownedLinkIds.some(id => !incident.includes(id))) {
            add('PROFILE_LINK_OWNERSHIP_UNPROVEN');
        }
        if (!profile.ownedLinkIds?.some(id => incident.includes(id))) continue;
        const outgoing = links.filter(link => link.portalNode === profile.nodeId
            && profile.ownedLinkIds.includes(link._id)).map(link => link._id);
        const role = nodesById.get(profile.nodeId)?.cascadeRole;
        const egress = profile.egress;
        const proven = egress?.configSha256 === profile.config?.sha256 && hashValue(egress?.configSha256);
        if (!proven || (outgoing.length
            ? egress.kind !== 'links' || !sameSet(egress.linkIds, outgoing) || role === 'bridge'
            : role === 'bridge' ? egress.kind !== 'direct' : role !== 'relay' || egress.kind !== 'staged')) {
            add('EGRESS_UNPROVEN');
        }
    }
    for (const link of links) {
        for (const nodeId of [link.portalNode, link.bridgeNode]) {
            if (profiles.filter(profile => profile.nodeId === nodeId && profile.ownedLinkIds?.includes(link._id)).length !== 1) {
                add('PROFILE_LINK_OWNERSHIP_UNPROVEN');
            }
        }
        const rows = records.listeners.filter(item => item.linkId === link._id);
        const row = rows[0];
        const profile = profiles.find(item => item._id === row?.profileId);
        const listenerNode = link.mode === 'reverse' ? link.portalNode : link.bridgeNode;
        if (rows.length !== 1 || row.nodeId !== listenerNode || profile?.nodeId !== listenerNode
            || !profile.ownedLinkIds?.includes(link._id) || row.port !== link.tunnelPort
            || row.network !== 'tcp' || !isIP(row.bindAddress ?? '')
            || row.configSha256 !== profile.config?.sha256 || row.unitSha256 !== profile.unit?.sha256) {
            add('LISTENER_OWNERSHIP_UNPROVEN');
        }
    }
    for (const row of records.listeners) {
        const profile = profiles.find(item => item._id === row.profileId);
        if (profile?.ownedLinkIds?.some(id => links.some(link => link._id === id))
            && (!links.some(link => link._id === row.linkId) || row.nodeId !== profile.nodeId)) {
            add('LISTENER_SCOPE_UNPROVEN');
        }
    }
    // Physical host identity, not IP or graph-node identity, owns listeners and
    // service/config writers. Distinct bind addresses alone do not prove safety.
    const affectedHosts = new Set(affectedNodeIds.map(id => nodesById.get(id)?.executionHostId));
    const hostProfiles = records.profiles.filter(profile => affectedHosts.has(nodesById.get(profile.nodeId)?.executionHostId));
    for (let i = 0; i < hostProfiles.length; i += 1) {
        for (const other of hostProfiles.slice(i + 1)) {
            const profile = hostProfiles[i];
            if (nodesById.get(profile.nodeId)?.executionHostId !== nodesById.get(other.nodeId)?.executionHostId) continue;
            if (!profile.config?.path || !other.config?.path || !profile.unit?.name || !other.unit?.name
                || profile.config.path === other.config.path || profile.unit.name === other.unit.name) {
                add('PROFILE_WRITER_ALIAS_UNPROVEN');
            }
        }
    }
    const hostListeners = records.listeners.filter(row => affectedHosts.has(nodesById.get(row.nodeId)?.executionHostId));
    for (let i = 0; i < hostListeners.length; i += 1) {
        for (const other of hostListeners.slice(i + 1)) {
            const row = hostListeners[i];
            if (nodesById.get(row.nodeId)?.executionHostId === nodesById.get(other.nodeId)?.executionHostId
                && row.port === other.port && row.network === other.network) add('LISTENER_COLLISION_UNPROVEN');
        }
    }
    const incoming = new Map(affectedNodeIds.map(id => [id, 0]));
    const outgoing = new Map(affectedNodeIds.map(id => [id, []]));
    for (const link of links) {
        incoming.set(link.bridgeNode, incoming.get(link.bridgeNode) + 1);
        outgoing.get(link.portalNode).push(link.bridgeNode);
    }
    const roots = affectedNodeIds.filter(id => incoming.get(id) === 0);
    let visited = 0;
    while (roots.length) {
        const nodeId = roots.shift();
        visited += 1;
        for (const next of outgoing.get(nodeId)) {
            incoming.set(next, incoming.get(next) - 1);
            if (incoming.get(next) === 0) roots.push(next);
        }
    }
    if (visited !== affectedNodeIds.length) add('GRAPH_CYCLE_UNPROVEN');
    return reasons;
}
function buildValidatedManifest(source, expected) {
    // Clone immediately: later caller edits cannot alter a frozen result.
    const records = orderedRecords(source);
    const inputSha256 = sha(records);
    const reasons = [];
    if (records.schemaVersion !== 1 || records.serverIdentity !== 'prod' || !identifier(records.snapshotId)
        || typeof records.capturedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(records.capturedAt)
        || !['links', 'nodes', 'profiles', 'listeners'].every(key => records.completeness?.[key] === true)) {
        return refusal(['EXPORT_EVIDENCE_REQUIRED'], inputSha256);
    }
    if (!Array.isArray(expected?.linkIds) || !expected.linkIds.length) {
        return refusal(['EXPECTED_LINK_IDS_REQUIRED'], inputSha256);
    }
    if (!expected.linkIds.every(identifier) || ['links', 'nodes', 'profiles'].some(key =>
        records[key].some(item => !identifier(item._id)))) return refusal(['INVALID_IDENTIFIER'], inputSha256);
    if (expected.inputSha256 !== undefined && (!hashValue(expected.inputSha256) || expected.inputSha256 !== inputSha256)) {
        reasons.push('SNAPSHOT_CHANGED');
    }
    if (new Set(expected.linkIds).size !== expected.linkIds.length) reasons.push('DUPLICATE_EXPECTED_LINK');
    if (expected.linkFingerprints && !sameSet(Object.keys(expected.linkFingerprints), expected.linkIds)) {
        reasons.push('LINK_BASELINE_SCOPE_MISMATCH');
    }
    const seen = new Set();
    for (const link of records.links) {
        if (!expected.linkIds.includes(link._id) && link.active === true && link.status === 'online') {
            reasons.push('UNEXPECTED_ACTIVE_ONLINE_LINK');
        }
        if (seen.has(link._id)) reasons.push('DUPLICATE_LINK');
        seen.add(link._id);
    }
    for (const id of expected.linkIds) {
        const link = records.links.find(item => item._id === id);
        if (!link) { reasons.push('EXPECTED_LINK_MISSING'); continue; }
        if (link.active !== true || link.status !== 'online') reasons.push('LINK_NOT_ACTIVE_ONLINE');
        const pin = expected.linkFingerprints?.[id];
        if (!/^[a-f0-9]{64}$/.test(pin ?? '')) reasons.push('LINK_BASELINE_REQUIRED');
        else if (pin !== fingerprintLink(link)) reasons.push('LINK_CHANGED');
    }
    if (reasons.length) return refusal(reasons, inputSha256);
    const links = records.links.filter(link => expected.linkIds.includes(link._id))
        .sort((a, b) => a._id < b._id ? -1 : a._id > b._id ? 1 : 0);
    const affectedNodeIds = sorted(new Set(links.flatMap(link => [link.portalNode, link.bridgeNode])));
    const nodesById = new Map(records.nodes.map(node => [node._id, node]));
    const profileCatalog = records.profiles.filter(profile => affectedNodeIds.includes(profile.nodeId))
        .sort((a, b) => a._id < b._id ? -1 : a._id > b._id ? 1 : 0);
    reasons.push(...validateEvidence(records, links, affectedNodeIds, nodesById, profileCatalog));
    if (reasons.length) return refusal(reasons, inputSha256);
    const profiles = profileCatalog.filter(profile => profile.ownedLinkIds.some(id => expected.linkIds.includes(id)));
    const listenerTransfers = links.map(link => {
        const listener = records.listeners.find(item => item.linkId === link._id);
        const profile = profiles.find(item => item._id === listener.profileId);
        const dialerNodeId = link.mode === 'reverse' ? link.bridgeNode : link.portalNode;
        const dialer = profiles.find(item => item.nodeId === dialerNodeId && item.ownedLinkIds.includes(link._id));
        return { linkId: link._id, mode: link.mode, listenerNodeId: listener.nodeId,
            dialerNodeId, dialerProfileId: dialer._id,
            trafficSourceNodeId: link.portalNode, trafficTargetNodeId: link.bridgeNode,
            profileId: profile._id, port: listener.port, network: listener.network,
            listenerFingerprint: sha(listener),
            configPath: profile.config.path, configSha256: profile.config.sha256,
            serviceUnit: profile.unit.name, unitSha256: profile.unit.sha256,
            action: 'preserve-exact-listener' };
    });
    const manifest = { schemaVersion: 1, kind: 'production-transfer-inventory', inputSha256,
        affectedNodeIds, affectedProfileIds: profiles.map(profile => profile._id),
        profiles: profiles.map(profile => ({ profileId: profile._id, nodeId: profile.nodeId,
            executionHostId: nodesById.get(profile.nodeId).executionHostId,
            targetProfile: profile.targetProfile, configPath: profile.config.path,
            configSha256: profile.config.sha256, serviceUnit: profile.unit.name,
            unitSha256: profile.unit.sha256, ownedLinkIds: profile.ownedLinkIds,
            egressKind: profile.egress.kind })),
        linkIds: links.map(link => link._id),
        linkFingerprints: Object.fromEntries(links.map(link => [link._id, fingerprintLink(link)])),
        components: components(links, nodesById), listenerTransfers };
    const nonReadyReasons = ['MAINTENANCE_AUTHORIZATION_NOT_PROVEN', 'CLIENT_PATH_NOT_PROVEN_FROM_RECORDS'];
    if (manifest.components.some(component => component.staged)) {
        nonReadyReasons.push('BRIDGELESS_OR_INCOMPLETE_COMPONENT_STAGING_ONLY');
    }
    return freeze({ inventoryReady: true, reasons: [], nonReadyReasons: sorted(nonReadyReasons), clientReady: false,
        executionAuthorized: false, inputSha256,
        manifestSha256: sha(manifest), manifest });
}
function buildTransferManifest(records, expected) {
    try { assertJson(records); if (expected !== undefined) assertJson(expected); }
    catch { return refusal(['INVALID_JSON_INPUT']); }
    if (!records || Array.isArray(records) || typeof records !== 'object'
        || !['nodes', 'links', 'profiles', 'listeners'].every(key => Array.isArray(records[key])
            && records[key].every(row => row && typeof row === 'object' && !Array.isArray(row)))) {
        return refusal(['EXPORT_EVIDENCE_REQUIRED']);
    }
    try { return buildValidatedManifest(records, expected); }
    catch { return refusal(['MALFORMED_EVIDENCE']); }
}
module.exports = { buildTransferManifest, fingerprintLink };

if (require.main === module) {
    let result;
    if (process.argv.length !== 2) result = refusal(['CLI_ARGUMENTS_NOT_ALLOWED']);
    else {
        try {
            const fs = require('node:fs');
            const chunks = [];
            let total = 0;
            while (true) {
                const buffer = Buffer.alloc(65536);
                const count = fs.readSync(0, buffer, 0, buffer.length, null);
                if (!count) break;
                total += count;
                if (total > 16 * 1024 * 1024) throw new Error('input limit');
                chunks.push(buffer.subarray(0, count));
            }
            const envelope = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            result = buildTransferManifest(envelope?.records, envelope?.expected);
        } catch {
            // Parser/OS exceptions can contain credentials or raw input: never echo.
            result = refusal(['INVALID_OR_OVERSIZED_STDIN_JSON']);
        }
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.inventoryReady ? 0 : 2;
}
