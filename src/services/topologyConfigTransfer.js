'use strict';
const { randomUUID, createHash } = require('node:crypto');
const {
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD,
    TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST,
    matchesTopologyExecutionContext,
} = require('../modules/relay-l2tp/domain/topologyExecutionContext');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const PROFILES = Object.freeze({
    'xray-main': Object.freeze({ configPath: '/usr/local/etc/xray/config.json', unitPath: '/etc/systemd/system/xray.service', service: 'xray' }),
    'xray-bridge': Object.freeze({ configPath: '/usr/local/etc/xray-bridge/config.json', unitPath: '/etc/systemd/system/xray-bridge.service', service: 'xray-bridge' }),
});
function failure(code) { return Object.assign(new Error(code), { code }); }
function snapshot(readback) {
    if (readback?.source !== 'node-readback'
        || !/^[a-f0-9]{64}$/.test(readback.configSha256)
        || !/^[a-f0-9]{64}$/.test(readback.unitSha256)
        || !['active', 'inactive'].includes(readback.serviceActive)
        || !['enabled', 'disabled', 'masked'].includes(readback.serviceEnabled)) {
        throw failure('CONFIG_TRANSFER_PROOF_INVALID');
    }
    const { configSha256, unitSha256, serviceActive, serviceEnabled } = readback;
    return { configSha256, unitSha256, serviceActive, serviceEnabled };
}
const { isDeepStrictEqual } = require('node:util');

// This is observed ingress recognition only. Installed-owner/epoch joining is
// a separate mandatory selected-admission boundary, not authority minted here.
function supportedLegacyGroup(topology) {
    const [group] = topology.groups;
    const portal = topology.nodes.filter(node => node.role === 'portal');
    const relay = topology.nodes.filter(node => node.role === 'relay');
    const bridge = topology.nodes.filter(node => node.role === 'bridge');
    if (topology.groups.length !== 1 || topology.nodes.length !== 3 || topology.links.length !== 2
        || portal.length !== 1 || relay.length !== 1 || bridge.length !== 1
        || group.mode !== 'reverse' || group.strategy !== 'priority-failover' || group.paths.length !== 1) return false;
    const [path] = group.paths;
    const upstream = topology.links.find(link => link.source === portal[0].id && link.target === relay[0].id);
    const downstream = topology.links.find(link => link.source === relay[0].id && link.target === bridge[0].id);
    const supportedClient = client => client && typeof client === 'object' && !Array.isArray(client)
        && client.security === 'none' && (client.protocol === undefined || client.protocol === 'vless')
        && (client.transport === undefined || client.transport === 'tcp');
    if (!upstream || !downstream || path.enabled !== true
        || typeof path.pathKey !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(path.pathKey)
        || !Number.isFinite(path.priority) || path.priority <= 0
        || path.linkIds.length !== 1 || path.linkIds[0] !== downstream.id
        || topology.links.some(link => link.mode !== 'reverse' || link.geo === true || link.geoRouting?.enabled
            || (link.tunnelProtocol !== undefined && link.tunnelProtocol !== 'vless')
            || (link.tunnelTransport !== undefined && link.tunnelTransport !== 'tcp')
            || (link.tunnelSecurity !== undefined && link.tunnelSecurity !== 'none'))
        || topology.nodes.some(node => !supportedClient(node.xray)
            || (node.xray.extraInbounds !== undefined && (!Array.isArray(node.xray.extraInbounds)
                || !node.xray.extraInbounds.every(supportedClient))))) return false;
    // Compare, never normalize an incorrect ID/tag/port or silently add defaults.
    const { projectGroups } = require('../modules/relay-l2tp/domain/topologyDraft');
    return isDeepStrictEqual(topology.groups, projectGroups(topology.groups));
}

// An import is an accepted descriptor inventory PLUS exact existing profile
// bytes. The existing adoption readback binds those bytes; status/desired data
// alone never supplies authority. No config is generated onto a node here.
function legacyAppliedTopology(input) {
    const invalid = code => { throw failure(code || 'CONFIG_LEGACY_IMPORT_INVALID'); };
    let topology;
    try {
        topology = require('../modules/relay-l2tp/repositories/topologyOperationRepository').durableSelectedTopology(input);
    } catch { invalid(); }
    if (!topology.nodes.length || topology.nodes.length > 32 || !topology.links.length || topology.links.length > 64
        || Buffer.byteLength(JSON.stringify(topology)) > 4 * 1024 * 1024) invalid();
    // Forward MAIN is a bounded, checked imported layout, never a global
    // role-to-profile exception. Reverse imports retain their historical path.
    const forward = topology.links.some(link => link.mode === 'forward');
    if (forward) {
        const [link] = topology.links;
        const portal = topology.nodes.find(node => node.role === 'portal');
        const bridge = topology.nodes.find(node => node.role === 'bridge');
        const supportedClient = value => value && typeof value === 'object' && !Array.isArray(value)
            && (value.security === undefined || ['none', 'reality'].includes(value.security))
            && (value.protocol === undefined || value.protocol === 'vless')
            && (value.transport === undefined || value.transport === 'tcp');
        if (topology.groups.length || topology.nodes.length !== 2 || topology.links.length !== 1
            || !portal || !bridge || portal.id === bridge.id || link.source !== portal.id || link.target !== bridge.id
            || link.mode !== 'forward' || !Number.isSafeInteger(link.tunnelPort) || link.tunnelPort < 1 || link.tunnelPort > 65535
            || (link.tunnelProtocol !== undefined && link.tunnelProtocol !== 'vless')
            || (link.tunnelTransport !== undefined && link.tunnelTransport !== 'tcp')
            || (link.tunnelSecurity !== undefined && !['none', 'reality'].includes(link.tunnelSecurity))
            || topology.nodes.some(node => node.type !== 'xray' || node.active !== true || !supportedClient(node.xray === undefined ? {} : node.xray)
                || (node.xray?.extraInbounds !== undefined && (!Array.isArray(node.xray.extraInbounds)
                    || !node.xray.extraInbounds.every(supportedClient))))) invalid('CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED');
        if (link.tunnelSecurity === 'reality' && ['realityPrivateKey', 'realityPublicKey', 'realityDest']
            .some(key => typeof link[key] !== 'string' || !link[key])) invalid('CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH');
        // MAIN's actual generator default is REALITY. Its empty-key fallback
        // cannot qualify an observed client listener as a supported profile.
        if (topology.nodes.some(node => [node.xray || {}, ...(node.xray?.extraInbounds || [])].some(inbound =>
            inbound.security !== 'none' && (typeof inbound.realityPrivateKey !== 'string' || !inbound.realityPrivateKey)))) {
            invalid('CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH');
        }
    }
    // Only a portal's descriptor-backed manual client TLS is observation-only.
    // Extras inherit the NODE source, exactly as the existing generator does;
    // a per-extra source cannot authorize panel/default or file-backed TLS.
    const supportedReverseClient = (node, security) => ['none', 'reality'].includes(security)
        || (security === 'tls' && node.role === 'portal' && node.type === 'xray' && node.active === true
            && node.xray?.tlsSource === 'manual'
            && ['manualCert', 'manualKey'].every(key => typeof node.xray[key] === 'string' && node.xray[key].trim()));
    // Nonempty groups have exactly one bounded reverse G2 allowlist. Existing
    // groupless none/REALITY/manual-client-TLS behavior remains unchanged.
    if (topology.groups.length && !supportedLegacyGroup(topology)) invalid('CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED');
    if (!forward && (topology.links.some(link => link.mode !== 'reverse'
        || !['none', 'reality'].includes(link.tunnelSecurity || 'none'))
        || topology.nodes.some(node => !supportedReverseClient(node, node.xray?.security || 'none')
            || node.xray?.extraInbounds?.some(inbound => !supportedReverseClient(node, inbound.security || 'reality'))))) {
        invalid('CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED');
    }
    for (const node of topology.nodes) {
        if (typeof node.profileConfig !== 'string' || Buffer.byteLength(node.profileConfig) > 1024 * 1024
            || typeof node.ip !== 'string' || !node.ip || /\s/.test(node.ip)) invalid();
        let profile;
        try { profile = JSON.parse(node.profileConfig); } catch { invalid(); }
        if (!profile || Array.isArray(profile) || !Array.isArray(profile.outbounds)
            || !Array.isArray(profile.routing?.rules)
            || (profile.inbounds !== undefined && !Array.isArray(profile.inbounds))) invalid();
        const incoming = topology.links.filter(link => link.target === node.id);
        const outgoing = topology.links.filter(link => link.source === node.id);
        if ((node.role === 'portal' && (incoming.length || outgoing.length !== 1))
            || (node.role === 'relay' && incoming.length !== 1)
            || (node.role === 'bridge' && (!incoming.length || outgoing.length))) invalid('CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED');
    }
    for (const link of topology.links) {
        if (link.active !== true || typeof link.tunnelUuid !== 'string' || !UUID.test(link.tunnelUuid)
            || (link.status !== undefined && !['online', 'deployed'].includes(link.status))) invalid();
        // Lifecycle is mutable desired state, not imported applied authority.
        if (link.lifecycle !== undefined) invalid();
        if (!forward) delete link.status;
    }
    const reached = new Set([topology.nodes[0].id]);
    for (let changed = true; changed;) {
        changed = false;
        for (const link of topology.links) if (reached.has(link.source) || reached.has(link.target)) {
            if (!reached.has(link.source) || !reached.has(link.target)) changed = true;
            reached.add(link.source); reached.add(link.target);
        }
    }
    if (reached.size !== topology.nodes.length) invalid();
    // Retain caller policy order: old relay/geo rule order is observable state.
    return topology;
}

// Exported for the existing descriptor composer to convert these *observed*
// artifacts rather than mistaking classic tag/domain identities for new ones.
// This function never reads desired metadata, transport or certificate files.
function legacyProfileArtifacts(input, nodeId) {
    const topology = legacyAppliedTopology(input);
    const node = topology.nodes.find(item => item.id === nodeId);
    if (!node) throw failure('CONFIG_LEGACY_IMPORT_INVALID');
    const generator = require('./configGenerator');
    const metadata = value => ({ ...value, _id: value.id, cascadeRole: value.role });
    const links = topology.links.map(link => ({ ...link, _id: link.id,
        portalNode: metadata(topology.nodes.find(item => item.id === link.source)),
        bridgeNode: metadata(topology.nodes.find(item => item.id === link.target)) }));
    const incoming = links.filter(link => link.target === nodeId), outgoing = links.filter(link => link.source === nodeId);
    const current = JSON.parse(node.profileConfig);
    const generated = [];
    const forward = topology.links[0].mode === 'forward';
    const groupedRelay = topology.groups.length === 1 && node.role === 'relay';
    if (node.role === 'portal' || forward) {
        // Verify client listener/transport/key metadata too, without claiming
        // current runtime clients were generated from a mutable user catalog.
        const baseline = JSON.parse(generator.generateXrayConfig(metadata(node), []));
        for (const expected of baseline.inbounds) {
            const actual = (current.inbounds || []).filter(item => item.tag === expected.tag);
            const withoutClients = item => {
                const copy = structuredClone(item);
                if (Array.isArray(copy.settings?.clients)) copy.settings.clients = [];
                return copy;
            };
            if (actual.length !== 1 || !isDeepStrictEqual(withoutClients(actual[0]), withoutClients(expected))) {
                throw failure('CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH');
            }
        }
        const delta = { inbounds: [], outbounds: [], routing: { rules: [] } };
        const clientTags = [node.xray?.inboundTag || 'vless-in',
            ...(node.xray?.extraInbounds || []).map(item => item.inboundTag).filter(Boolean)];
        if (forward) {
            if (node.role === 'portal') generator.applyForwardChain(delta, outgoing, clientTags);
            else generator.applyForwardHopInbound(delta, incoming);
        } else generator.applyReversePortal(delta, outgoing, clientTags);
        generated.push(delta);
    } else if (node.role === 'relay') {
        const relay = JSON.parse(generator.generateRelayConfig(incoming[0], incoming[0].portalNode, outgoing));
        if (groupedRelay) {
            const [path] = topology.groups[0].paths;
            // The fourth generateRelayConfig argument changes guard order.
            // Reproduce the observed classic writer sequence, not that variant.
            generator.applyCascadePathIngress(relay, [{ pathKey: path.pathKey, port: path.cascadePathIngress.port,
                egressTag: `portal-down-${outgoing[0].id.slice(-8)}` }]);
            require('./classicL2tpConfigComposition').finishClassicConfigRouting(relay);
        }
        generated.push(relay);
    } else {
        const combined = JSON.parse(generator.generateCombinedBridgeConfig(incoming));
        generated.push(combined);
        // The scoped classic writer seeds the idle bridge with the generated
        // global safety tail, then inserts tunnel rules before geoip:private
        // (cascadeService, bootstrap composition). This leaves the IPv6 guard
        // FIRST, unlike the full generator. Recognize that exact writer output,
        // not arbitrary observed rule permutations or a desired-as-applied map.
        const scoped = structuredClone(combined);
        const tunnelRules = scoped.routing.rules.filter(row => row.domain || row.inboundTag);
        scoped.routing.rules = scoped.routing.rules.filter(row => !row.domain && !row.inboundTag);
        const privateGuard = scoped.routing.rules.findIndex(row => row.ip?.includes('geoip:private'));
        scoped.routing.rules.splice(privateGuard < 0 ? scoped.routing.rules.length : privateGuard, 0, ...tunnelRules);
        generated.push(scoped);
        if (incoming.length === 1) {
            const single = JSON.parse(generator.generateBridgeConfig(incoming[0], incoming[0].portalNode));
            generated.push(single);
            // Existing classic shared-profile writes preserve the historical
            // generic bridge/tunnel tag pair with the combined writer's guard
            // order. Accept only that exact single-link alias, not arbitrary
            // tag/rule normalization or a rearrangement of observed globals.
            const generic = JSON.parse(generator.generateCombinedBridgeConfig(incoming));
            const suffix = incoming[0].id.slice(-8);
            const aliases = new Map([[`bridge-${suffix}`,'bridge'],[`tunnel-${suffix}`,'tunnel']]);
            const alias = tag => aliases.get(tag) || tag;
            generic.reverse.bridges.forEach(row => { row.tag = alias(row.tag); });
            generic.outbounds.forEach(row => { row.tag = alias(row.tag); });
            generic.routing.rules.forEach(row => {
                if (row.outboundTag) row.outboundTag = alias(row.outboundTag);
                if (row.inboundTag) row.inboundTag = row.inboundTag.map(alias);
            });
            generated.push(generic);
        }
    }
    const reserved = forward || topology.groups.length ? /^(?:bridge-conn-|portal-|bridge-|tunnel-|conn-down-|fwd-|cascade-)/
        : /^(?:bridge-conn-|portal-|bridge-|tunnel-|conn-down-|fwd-|cascade-in-)/;
    if (groupedRelay) {
        const inbounds = current.inbounds || [];
        if (new Set(inbounds.map(row => row.tag)).size !== inbounds.length
            || new Set(inbounds.map(row => row.port)).size !== inbounds.length) {
            throw failure('CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH');
        }
    }
    const sections = config => [config.inbounds || [], config.outbounds || [], config.reverse?.portals || [],
        config.reverse?.bridges || [], config.routing.rules];
    const matched = generated.find(expected => {
        const actualSections = sections(current), expectedSections = sections(expected);
        const tags = new Set(expectedSections.slice(0, 4).flat().map(item => item.tag));
        const owns = item => reserved.test(item.tag || '') || tags.has(item.tag);
        const ownsRule = item => (groupedRelay && (!Array.isArray(item.inboundTag) || !item.inboundTag.length))
            || tags.has(item.outboundTag) || tags.has(item.balancerTag)
            || item.inboundTag?.some(tag => tags.has(tag) || reserved.test(tag))
            || reserved.test(item.outboundTag || '') || (forward && reserved.test(item.balancerTag || ''));
        for (let i = 0; i < 4; i++) {
            // A whole shared reverse profile must be represented, including
            // older generic bridge/tunnel tags; unknown reverse entries cannot
            // be classified as unrelated merely because their names differ.
            const actual = i >= 2 ? actualSections[i] : actualSections[i].filter(owns), wanted = expectedSections[i];
            if (forward && !isDeepStrictEqual(actual, wanted)) return false;
            if (actual.length !== wanted.length
                || wanted.some(item => actual.filter(value => isDeepStrictEqual(value, item)).length !== 1)) return false;
        }
        // Rules have precedence: compare owned rules in their actual order.
        const actualRules = current.routing.rules.filter(ownsRule);
        const expectedRules = expected.routing.rules.filter(ownsRule);
        if (!isDeepStrictEqual(actualRules, expectedRules)) return false;
        // Independent MAIN balancers are not tunnel artifacts. Reserved or
        // tunnel-referencing ones cannot be reclassified as unrelated.
        if (forward) return !(current.routing.balancers || []).some(item => reserved.test(item.tag || '')
            || item.selector?.some(tag => reserved.test(tag) || tags.has(tag)));
        return isDeepStrictEqual(current.routing.balancers || [], expected.routing.balancers || []);
    });
    if (!matched) throw failure('CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH');
    return matched;
}

function verifyLegacyAppliedProfile(input, { node, profile, originalSnapshot }) {
    const topology = legacyAppliedTopology(input);
    const descriptor = topology.nodes.find(item => item.id === node);
    const forward = topology.links[0].mode === 'forward';
    if (!descriptor || (forward || descriptor.role === 'portal' ? 'xray-main' : 'xray-bridge') !== profile
        || createHash('sha256').update(descriptor.profileConfig).digest('hex') !== originalSnapshot?.configSha256) {
        throw failure('CONFIG_LEGACY_IMPORT_READBACK_MISMATCH');
    }
    // A locally matching half never blesses an incomplete/forged peer inventory.
    // Each peer's physical bytes still need its own independent public adoption.
    for (const member of forward ? topology.nodes : [descriptor]) legacyProfileArtifacts(topology, member.id);
    return topology;
}

// Dormant internal contract: no HTTP/MCP entry point or runtime wiring.
// See topologyConfigTransfer.md: classic writers do NOT yet hold a shared
// durable remote scope; PROD must stay QUIESCENCE_UNPROVEN, even with a row.
// withVerifiedMaintenance is an EXTERNAL authority, not a flag/DB marker. It
// must hold dispatch exclusion across callback + majority confirmation, including
// old backend PID/process-tree exit and revocation of its future dispatch.
class TopologyConfigTransfer {
    constructor({ executionContext, withVerifiedMaintenance, TopologyConfigOwner } = {}) {
        const context = [TEST, PROD].find(candidate => matchesTopologyExecutionContext(executionContext, candidate));
        if (!context) {
            throw new TypeError('Explicit server-owned TEST or production context required');
        }
        if (typeof withVerifiedMaintenance !== 'function') {
            throw new TypeError('External maintenance authority required');
        }
        Object.defineProperty(this, 'executionContext', { value: context, enumerable: true });
        this.withVerifiedMaintenance = withVerifiedMaintenance;
        this.Model = TopologyConfigOwner || require('../models/topologyConfigOwnerModel');
    }

    async #requireUniqueIndex() {
        // Index provisioning belongs to future startup/migration wiring. Do not
        // silently create a production adoption namespace from a request.
        let indexes;
        try { indexes = await this.Model.collection.indexes({ maxTimeMS: 5000 }); }
        catch { throw failure('CONFIG_OWNERSHIP_INDEX_REQUIRED'); }
        if (!indexes.some(index => isDeepStrictEqual(index.key, { node: 1, profile: 1 })
            && index.unique === true && !index.sparse && !index.partialFilterExpression)) {
            throw failure('CONFIG_OWNERSHIP_INDEX_REQUIRED');
        }
    }

    async initializeClassic({ node, profile, nodeIdentity }) {
        if (!Object.hasOwn(PROFILES, profile)) throw new TypeError('Unknown config profile');
        if (!/^[a-f0-9]{24}$/.test(node)) throw failure('CONFIG_TRANSFER_BINDING_INVALID');
        await this.#requireUniqueIndex();
        const generation = randomUUID();
        // Internal server inventory only; this never changes an existing owner.
        await this.Model.create([{ executionContext: this.executionContext, node, profile, nodeIdentity,
            owner: 'classic', generation }], { writeConcern: { w: 'majority' } });
        const confirmed = await this.Model.findOne({ executionContext: this.executionContext, node, profile, generation, owner: 'classic' })
            .read('primary').readConcern('majority').maxTimeMS(5000).lean();
        if (!confirmed) throw failure('CONFIG_TRANSFER_UNCONFIRMED');
        return confirmed;
    }

    async adopt(input) { return this.#transfer('adopt', input); }
    async handback(input) { return this.#transfer('handback', input); }

    async #transfer(action, { node, profile, generation, proofRef, legacyTopology: proposedLegacy } = {}) {
        // Freeze/copy before the first await. This is not a flag that blesses
        // mutable desired: each member's exact profile must match adoption.
        const imported = proposedLegacy === undefined ? undefined : legacyAppliedTopology(proposedLegacy);
        if (imported !== undefined && action !== 'adopt') throw failure('CONFIG_LEGACY_IMPORT_INVALID');
        if (!/^[a-f0-9]{24}$/.test(node) || !Object.hasOwn(PROFILES, profile) || !UUID.test(generation)) {
            throw failure('CONFIG_TRANSFER_BINDING_INVALID');
        }
        if (typeof proofRef !== 'string' || !proofRef.trim() || proofRef.length > 1024) {
            throw failure('CONFIG_TRANSFER_PROOF_INVALID');
        }
        await this.#requireUniqueIndex();
        const nextOwner = action === 'adopt' ? 'topology' : 'classic';
        const query = { node, profile, executionContext: this.executionContext,
            owner: action === 'adopt' ? 'classic' : 'topology', generation };
        const row = await this.Model.findOne(query, '+executionEnrollment').read('primary').readConcern('majority').maxTimeMS(5000).lean();
        if (!row || !/^[a-f0-9]{32}$/.test(row.nodeIdentity?.machineId)
            || !/^[a-f0-9]{64}$/.test(row.nodeIdentity?.sshHostKeySha256)) {
            throw failure('CONFIG_OWNERSHIP_CONFLICT');
        }
        const binding = Object.freeze({ executionContext: this.executionContext, node, profile,
            nodeIdentity: Object.freeze({ ...row.nodeIdentity }), generation, nextGeneration: randomUUID(),
            action, paths: PROFILES[profile] });
        let invoked = false;
        let scopeOpen = true;
        let confirmed;
        const work = async proof => {
            if (!scopeOpen || invoked) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
            invoked = true;
            if (proof?.status !== 'verified' || proof.authority !== 'external-maintenance-v1'
                || !UUID.test(proof.proofId) || !UUID.test(proof.maintenanceId)
                || !isDeepStrictEqual(proof.binding, binding)
                || proof.maintenance !== 'held' || proof.allWriters !== 'drained'
                || proof.oldBackend?.processTree !== 'stopped' || proof.oldBackend?.dispatch !== 'disabled'
                || typeof proof.oldBackend.instanceId !== 'string' || !proof.oldBackend.instanceId
                || !Number.isSafeInteger(proof.oldBackend.pid) || proof.oldBackend.pid < 1
                || typeof proof.oldBackend.processStartTime !== 'string' || !proof.oldBackend.processStartTime) {
                throw failure('CONFIG_TRANSFER_PROOF_INVALID');
            }
            const readback = snapshot(proof.readback);
            const legacy = imported === undefined ? undefined
                : verifyLegacyAppliedProfile(imported, { node, profile, originalSnapshot: readback });
            if (action === 'handback' && (!row.adoptionReceipt
                || row.adoptionReceipt.toGeneration !== generation
                || !isDeepStrictEqual(row.originalSnapshot, readback))) {
                throw failure('CONFIG_RESTORATION_MISMATCH');
            }
            const receipt = { proofId: proof.proofId, maintenanceId: proof.maintenanceId,
                fromGeneration: generation, toGeneration: binding.nextGeneration,
                oldBackendInstanceId: proof.oldBackend.instanceId, oldPid: proof.oldBackend.pid,
                oldProcessStartTime: proof.oldBackend.processStartTime, verifiedAt: new Date() };
            const profileTargetPin = legacy?.links[0].mode === 'forward'
                ? require('../modules/relay-l2tp/services/topologyProfileTarget').projectImportedProfileTargetPin({
                    executionContext: this.executionContext, node, profile, nodeIdentity: row.nodeIdentity,
                    owner: nextOwner, generation: binding.nextGeneration, originalSnapshot: readback,
                    adoptionReceipt: receipt, legacyAppliedTopology: legacy,
                }) : undefined;
            const reentry = action === 'adopt' && this.executionContext === PROD && row.handbackReceipt !== undefined;
            const executionEnrollment = reentry ? { kind: 'public-handback-reentry-v1',
                previousAdoptionReceipt: row.adoptionReceipt, previousHandbackReceipt: row.handbackReceipt,
                ...(row.executionEnrollment?.enrollment === undefined ? {} : { previousEnrollment: row.executionEnrollment.enrollment }) } : undefined;
            // External verification/remote reads NEVER run inside Mongo retry.
            await this.Model.db.transaction(async session => {
                if (!scopeOpen) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
                const fence = { ...query, nodeIdentity: row.nodeIdentity,
                    ...(action === 'handback' || reentry ? { originalSnapshot: row.originalSnapshot, adoptionReceipt: row.adoptionReceipt } : {}),
                    ...(reentry ? { handbackReceipt: row.handbackReceipt } : {}),
                    ...(reentry || row.executionEnrollment !== undefined
                        ? { executionEnrollment: row.executionEnrollment ?? { $exists: false } } : {}) };
                const fields = action === 'adopt'
                    ? { originalSnapshot: readback, adoptionReceipt: receipt,
                        ...(reentry ? { executionEnrollment } : {}),
                        ...(legacy === undefined ? {} : { legacyAppliedTopology: legacy }),
                        ...(profileTargetPin === undefined ? {} : { profileTargetPin }) }
                    : { handbackReceipt: receipt };
                const updated = await this.Model.findOneAndUpdate(fence,
                    { $set: { owner: nextOwner, generation: binding.nextGeneration, ...fields },
                        ...(action === 'adopt' ? { $unset: { handbackReceipt: 1,
                            ...(legacy === undefined ? { legacyAppliedTopology: 1 } : {}),
                            ...(profileTargetPin === undefined ? { profileTargetPin: 1 } : {}) } } : {}) },
                    { session, new: true, runValidators: true });
                if (!scopeOpen) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
                if (!updated) throw failure('CONFIG_OWNERSHIP_CONFLICT');
            }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            let confirmation = this.Model.findOne({ ...query, owner: nextOwner, generation: binding.nextGeneration });
            // Preserve the old transfer projection/return protocol unless this
            // adoption is explicitly importing private profile descriptors.
            if (legacy !== undefined) confirmation = confirmation.select('+legacyAppliedTopology');
            if (profileTargetPin !== undefined) confirmation = confirmation.select('+profileTargetPin');
            confirmed = await confirmation.read('primary').readConcern('majority').maxTimeMS(5000).lean();
            if (!confirmed || (legacy !== undefined && !isDeepStrictEqual(confirmed.legacyAppliedTopology, legacy))) {
                throw failure('CONFIG_TRANSFER_UNCONFIRMED');
            }
            if (profileTargetPin !== undefined) {
                try {
                    const verified = require('../modules/relay-l2tp/services/topologyProfileTarget').verifyImportedProfileTargetPin({
                        owner: confirmed, profileTargetPin, executionContext: this.executionContext,
                    });
                    if (!isDeepStrictEqual(verified, profileTargetPin)) throw failure('CONFIG_TRANSFER_UNCONFIRMED');
                } catch { throw failure('CONFIG_TRANSFER_UNCONFIRMED'); }
            }
        };
        try {
            await this.withVerifiedMaintenance({ binding, proofRef }, work);
        } finally { scopeOpen = false; }
        // An authority returning a boolean/row without executing the held scope
        // cannot manufacture a verified transition.
        if (!invoked || !confirmed) throw failure('CONFIG_TRANSFER_PROOF_INVALID');
        return confirmed;
    }
}
module.exports = { TopologyConfigTransfer, verifyLegacyAppliedProfile, legacyProfileArtifacts };
