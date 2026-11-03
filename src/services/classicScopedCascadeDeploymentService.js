'use strict';

const { randomUUID } = require('node:crypto');
const { hasClassicLifecycleGrant } = require('./classicLifecycleAuthorization');
const { resolveL2tpExecutionAuthorization } = require('../modules/relay-l2tp/domain/l2tpExecutionAuthorization');
const ID = /^[0-9a-f]{24}$/i;
// Health-offline is not evidence that an established physical tunnel is absent.
const APPLIED = new Set(['deployed', 'online', 'staged', 'offline']);
const READ = Object.freeze({ readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000 });
const MESSAGES = Object.freeze({
    CLASSIC_DEPLOY_UNSUPPORTED: 'Classic deployment supports only an existing active reverse link.apply',
    CLASSIC_DEPLOY_BUSY: 'Classic deployment requires an initialized, quiescent topology',
    CLASSIC_DEPLOY_NODE_BUSY: 'A node in this Portal-to-Bridge component is busy; retry when its operation completes',
    CLASSIC_DEPLOY_PREFLIGHT_FAILED: 'Portal-to-Bridge preflight failed before any remote write; correct the prerequisite and retry',
    CLASSIC_DEPLOY_SCOPE_CHANGED: 'Classic deployment scope no longer matches the confirmed baseline',
    CLASSIC_DEPLOY_IN_USE: 'Classic deployment is blocked by L2TP or route-group use',
    CLASSIC_DEPLOY_OWNER_VETO: 'Classic deployment is blocked by configuration ownership',
    CLASSIC_DEPLOY_PORT_CONFLICT: 'The requested tunnel port is already in use on the source node; edit the port and retry',
    CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE: 'Source port inspection could not be completed; no deployment was started',
    CLASSIC_DEPLOY_UNCERTAIN: 'Classic deployment completion is unproved; ownership retained for recovery',
    CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED: 'Configuration was applied and verified, but the tunnel has no confirmed connection. Check connectivity between nodes; retry and checked deletion remain available.',
    CLASSIC_DEPLOY_FENCE_LOST: 'Classic deployment ownership could not be confirmed or released',
    TOPOLOGY_DEPLOYMENT_UNAVAILABLE: 'Classic deployment capabilities are unavailable',
    STALE_TOPOLOGY_REVISION: 'Topology revision changed; reload before applying',
    INVALID_REQUEST: 'Invalid scoped classic deployment request',
    INVALID_TOPOLOGY_DRAFT: 'Classic deletion would leave an invalid topology draft',
});
function failure(code) { return Object.assign(new Error(MESSAGES[code]), { code }); }
const validId = value => typeof value === 'string' && ID.test(value);
const entityId = value => String(value?._id ?? value);
const MAIN_PROFILE = '/usr/local/etc/xray/config.json';
const BRIDGE_PROFILE = '/usr/local/etc/xray-bridge/config.json';
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const sameList = (actual, expected) => Array.isArray(actual)
    && actual.length === expected.length && expected.every((value, i) => Object.hasOwn(actual, i) && actual[i] === value);
function immutablePin(value) {
    const stable = item => {
        if (item && typeof item.toJSON === 'function') return stable(item.toJSON());
        if (Array.isArray(item)) return item.map(stable);
        if (item && typeof item === 'object') return Object.fromEntries(Object.keys(item).sort().map(k => [k, stable(item[k])]));
        return item;
    };
    return JSON.stringify(stable(value));
}
function independentPins(links, nodes, nodeIds) {
    const pinnedLinks = links.filter(link => nodeIds.includes(entityId(link.portalNode)) || nodeIds.includes(entityId(link.bridgeNode)))
        .map(link => {
            const pin = { ...link, _id: entityId(link._id), portalNode: entityId(link.portalNode), bridgeNode: entityId(link.bridgeNode) };
            for (const key of ['status', 'lastHealthCheck', 'latencyMs', 'lastError', 'updatedAt', 'createdAt']) delete pin[key];
            return pin;
        }).sort((a, b) => a._id.localeCompare(b._id));
    const pinnedNodes = nodes.filter(node => nodeIds.includes(entityId(node._id))).map(node => ({
        _id: entityId(node._id), ip: node.ip, active: node.active, type: node.type, cascadeRole: node.cascadeRole,
        ssh: node.ssh, xray: node.xray,
    })).sort((a, b) => a._id.localeCompare(b._id));
    return immutablePin({ links: pinnedLinks, nodes: pinnedNodes });
}
function classicLinkAllowlist(env) {
    const value = env.CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS;
    if (typeof value !== 'string' || value.length > 1599) return null;
    const ids = value.split(',');
    return ids.length <= 64 && ids.every(id => /^[0-9a-f]{24}$/.test(id))
        && new Set(ids).size === ids.length ? ids : null;
}

// This is a private completion protocol, not a native operation/queued receipt.
// Account for every main/transit profile on the two endpoints exactly once.
function checkedCompletion(result, { linkId, expectedTopologyRevision, baselineLinkIds, endpoints }) {
    const receipt = result?.receipt;
    if (result?.success !== true || result?.remoteQuiescent !== true
        || Object.keys(result).sort().join(',') !== 'receipt,remoteQuiescent,success'
        || !receipt || Object.keys(receipt).sort().join(',') !== 'kind,linkId,nodeIds,preservedLinkIds,preservedProfiles,profiles,topologyRevision,tunnelEstablished'
        || receipt.kind !== 'classic-scoped-reverse' || receipt.linkId !== linkId
        || receipt.topologyRevision !== expectedTopologyRevision || receipt.tunnelEstablished !== true
        || !sameList(receipt.nodeIds, [...endpoints].sort())
        || !sameList(receipt.preservedLinkIds, baselineLinkIds)
        || !Array.isArray(receipt.profiles) || !Array.isArray(receipt.preservedProfiles)) return false;
    return checkedApplyProfiles(receipt, endpoints);
}

// Known configuration completion, NOT a connected-tunnel success. Only this
// distinct full four-profile proof may settle ownership before a public warning.
function checkedUnconnectedCompletion(result, { linkId, expectedTopologyRevision, baselineLinkIds, endpoints }) {
    const receipt = result?.receipt;
    if (result?.success !== true || result?.remoteQuiescent !== true
        || Object.keys(result).sort().join(',') !== 'receipt,remoteQuiescent,success'
        || !receipt || Object.keys(receipt).sort().join(',') !== 'configurationVerified,kind,linkId,nodeIds,preservedLinkIds,preservedProfiles,profiles,topologyRevision,tunnelEstablished'
        || receipt.kind !== 'classic-scoped-reverse-unconnected' || receipt.configurationVerified !== true
        || receipt.tunnelEstablished !== false || receipt.linkId !== linkId
        || receipt.topologyRevision !== expectedTopologyRevision
        || !sameList(receipt.nodeIds, [...endpoints].sort())
        || !sameList(receipt.preservedLinkIds, baselineLinkIds)
        || !Array.isArray(receipt.profiles) || !Array.isArray(receipt.preservedProfiles)) return false;
    return checkedApplyProfiles(receipt, endpoints);
}

function checkedApplyProfiles(receipt, endpoints) {
    const [source, target] = endpoints;
    const key = (node, path) => `${node}:${path}`;
    const requiredChanges = [key(source, MAIN_PROFILE), key(target, BRIDGE_PROFILE)];
    const optionalChange = key(target, MAIN_PROFILE);
    const changed = new Set();
    for (const profile of receipt.profiles) {
        if (!profile || Object.keys(profile).sort().join(',') !== 'beforeSha256,nodeId,path,sha256'
            || typeof profile.nodeId !== 'string' || typeof profile.path !== 'string'
            || !digest(profile.beforeSha256) || !digest(profile.sha256)) return false;
        const id = key(profile.nodeId, profile.path);
        if ((!requiredChanges.includes(id) && id !== optionalChange) || changed.has(id)) return false;
        changed.add(id);
    }
    if (!requiredChanges.every(id => changed.has(id))) return false;
    const expectedPreserved = [key(source, BRIDGE_PROFILE), ...(!changed.has(optionalChange) ? [optionalChange] : [])];
    const preserved = new Set();
    for (const profile of receipt.preservedProfiles) {
        if (!profile || Object.keys(profile).sort().join(',') !== 'nodeId,path,sha256'
            || typeof profile.nodeId !== 'string' || typeof profile.path !== 'string'
            || (profile.sha256 !== null && !digest(profile.sha256))) return false;
        const id = key(profile.nodeId, profile.path);
        if (!expectedPreserved.includes(id) || preserved.has(id)) return false;
        preserved.add(id);
    }
    return preserved.size === expectedPreserved.length;
}

// Removal accounts for all four endpoint profiles, including unchanged/absent
// files. A status string or a generic SSH success is never an absence proof.
function checkedRemoval(result, context) {
    const r = result?.receipt;
    if (result?.success !== true || result?.remoteQuiescent !== true
        || Object.keys(result).sort().join(',') !== 'receipt,remoteQuiescent,success'
        || !r || Object.keys(r).sort().join(',') !== 'kind,linkId,nodeIds,preservedLinkIds,preservedProfiles,profiles,targetAbsent,topologyRevision'
        || r.kind !== 'classic-scoped-reverse-removal' || r.linkId !== context.linkId
        || r.topologyRevision !== context.expectedTopologyRevision || r.targetAbsent !== true
        || !sameList(r.nodeIds, [...context.endpoints].sort())
        || !sameList(r.preservedLinkIds, context.baselineLinkIds)
        || !Array.isArray(r.profiles) || !Array.isArray(r.preservedProfiles)) return false;
    const [source, target] = context.endpoints;
    const key = p => `${p.nodeId}:${p.path}`;
    const required = [`${source}:${MAIN_PROFILE}`, `${target}:${BRIDGE_PROFILE}`];
    const optional = `${target}:${MAIN_PROFILE}`;
    const changed = new Set();
    const validProfile = p => p && Object.keys(p).sort().join(',') === 'beforeSha256,changed,nodeId,path,sha256'
        && typeof p.nodeId === 'string' && typeof p.path === 'string'
        && (p.beforeSha256 === null || digest(p.beforeSha256)) && (p.sha256 === null || digest(p.sha256))
        && typeof p.changed === 'boolean' && p.changed === (p.beforeSha256 !== p.sha256);
    for (const p of r.profiles) {
        if (!validProfile(p) || (!required.includes(key(p)) && key(p) !== optional) || changed.has(key(p))) return false;
        changed.add(key(p));
    }
    if (!required.every(k => changed.has(k))) return false;
    const expectedPreserved = [`${source}:${BRIDGE_PROFILE}`, ...(!changed.has(optional) ? [optional] : [])];
    const preserved = new Set();
    for (const p of r.preservedProfiles) {
        if (!validProfile(p) || p.changed !== false || !expectedPreserved.includes(key(p)) || preserved.has(key(p))) return false;
        preserved.add(key(p));
    }
    return preserved.size === expectedPreserved.length;
}

function inactiveRelay(state) {
    // Include the observed legacy desiredState spelling without adopting any
    // missing/unknown status as evidence of a completed uninstall.
    return state?.status === 'not_installed' && ['absent', 'not_installed'].includes(state.desiredState)
        && state.installedRouteGroup == null;
}

function routeGroupUseVeto(groups, relays, touching) {
    if (!Array.isArray(groups) || !Array.isArray(relays)) return true;
    for (const group of groups) {
        if (!group || !validId(entityId(group._id)) || !Array.isArray(group.paths)) return true;
        let touches = false;
        for (const path of group.paths) {
            if (!path || !Array.isArray(path.linkIds) || !path.linkIds.every(id => validId(entityId(id)))
                || (path.enabled !== undefined && typeof path.enabled !== 'boolean')) return true;
            if (path.enabled !== false && path.linkIds.some(id => touching.has(entityId(id)))) touches = true;
        }
        if (!touches) continue;
        const id = entityId(group._id);
        const references = relays.filter(state => entityId(state?.routeGroup) === id
            || entityId(state?.installedRouteGroup) === id);
        // Retained paths are configuration, not installed authority, only when
        // every reference is positively attributable to a completed uninstall.
        if (!references.length || !references.every(inactiveRelay)) return true;
    }
    return false;
}

function isClassicProductionDeploymentConfigured(env) {
    const auth = resolveL2tpExecutionAuthorization(env);
    return auth.enableProductionExecution === true && env.PANEL_DOMAIN === 'lm1.infograd.online'
        && env.CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true'
        && env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'false'
        && env.TOPOLOGY_TEST_EXECUTION_ENABLED === 'false';
}

function isClassicProductionDeploymentEnabled(env) {
    const lifecycle = env.CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED === 'true';
    const validLifecycle = lifecycle && typeof env.CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY === 'string'
        && /^[a-f0-9]{64}$/.test(env.CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY);
    return isClassicProductionDeploymentConfigured(env)
        && (lifecycle ? validLifecycle : classicLinkAllowlist(env) !== null);
}

// Same endpoint-connected, confirmed-applied selection as the HTTP contract.
// Recompute from fresh persistence: a caller's list is a pin, not authority.
function baselineIds(links, selected) {
    const nodes = new Set([entityId(selected.portalNode), entityId(selected.bridgeNode)]);
    const baseline = new Set();
    let changed = true;
    while (changed) {
        changed = false;
        for (const link of links) {
            if (entityId(link._id) === entityId(selected._id) || link.active === false
                || !APPLIED.has(link.status) || baseline.has(entityId(link._id))) continue;
            const source = entityId(link.portalNode);
            const target = entityId(link.bridgeNode);
            if (nodes.has(source) || nodes.has(target)) {
                baseline.add(entityId(link._id)); nodes.add(source); nodes.add(target); changed = true;
            }
        }
    }
    return [...baseline].sort();
}

function createClassicScopedCascadeDeploymentService(dependencies = {}) {
    const env = Object.freeze({ ...(dependencies.env ?? process.env) });
    const creationCapabilities = new Map();
    const CAPABILITY_TTL_MS = 5 * 60 * 1000;
    const purgeCreationCapabilities = () => {
        const now = Date.now();
        for (const [token, record] of creationCapabilities) {
            if (record.expiresAt <= now) creationCapabilities.delete(token);
        }
    };
    const capabilityToken = capability => typeof capability?.token === 'string'
        && /^[0-9a-f-]{36}$/.test(capability.token) ? capability.token : null;
    function beginCreatedLinkCapability({ linkId } = {}) {
        purgeCreationCapabilities();
        if (!validId(linkId)) throw failure('INVALID_REQUEST');
        const token = randomUUID();
        creationCapabilities.set(token, {
            linkId,
            expectedTopologyRevision: null,
            confirmed: false,
            expiresAt: Date.now() + CAPABILITY_TTL_MS,
        });
        return Object.freeze({ token });
    }
    function confirmCreatedLinkCapability(capability, { linkId, expectedTopologyRevision } = {}) {
        purgeCreationCapabilities();
        const token = capabilityToken(capability);
        const record = token && creationCapabilities.get(token);
        if (!record || record.confirmed || record.linkId !== linkId
            || !Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) {
            throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
        }
        record.expectedTopologyRevision = expectedTopologyRevision;
        record.confirmed = true;
        return capability;
    }
    // Resolve lazily: selecting the mode must not construct native workers, SSH,
    // optional models or index/collection DDL during dormant router import.
    function resolve() {
        const models = {};
        for (const [name, file] of Object.entries({
            CascadeTopologyState: 'cascadeTopologyStateModel', TopologyOperation: 'topologyOperationModel',
            TopologyCreateIntent: 'topologyCreateIntentModel', TopologyIntentQueueState: 'topologyIntentQueueStateModel',
            NodeOperationLock: 'nodeOperationLockModel', RelayL2tpState: 'relayL2tpStateModel',
            CascadeRouteGroup: 'cascadeRouteGroupModel',
        })) models[name] = dependencies[name] ?? require(`../modules/relay-l2tp/models/${file}`);
        models.CascadeLink = dependencies.CascadeLink ?? require('../models/cascadeLinkModel');
        models.HyNode = dependencies.HyNode ?? require('../models/hyNodeModel');
        const connection = models.CascadeTopologyState.db;
        if (typeof connection?.transaction !== 'function'
            || Object.values(models).some(model => model.db !== connection)) {
            throw failure('TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
        }
        return { ...models, connection };
    }

    async function runQueue(input, { creationCapability = null, action = 'link.apply' } = {}) {
        const isDelete = action === 'link.delete';
        const allowUnlistedPending = creationCapability !== null;
        if (!isClassicProductionDeploymentEnabled(env)) throw failure('TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
        if (!input || typeof input !== 'object' || Array.isArray(input)
            || Object.keys(input).some(key => !['expectedTopologyRevision', 'scope'].includes(key))
            || !Number.isSafeInteger(input.expectedTopologyRevision) || input.expectedTopologyRevision < 0) {
            throw failure('INVALID_REQUEST');
        }
        const { expectedTopologyRevision, scope } = input;
        if (!scope || scope.kind !== 'link.apply') throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
        if (Object.keys(scope).some(key => !['kind', 'linkId', 'linkIds'].includes(key))
            || !validId(scope.linkId) || !Array.isArray(scope.linkIds) || !scope.linkIds.every(validId)
            || new Set(scope.linkIds).size !== scope.linkIds.length || !scope.linkIds.includes(scope.linkId)) {
            throw failure('INVALID_REQUEST');
        }
        // Copy before the first await; external callers cannot change the pin.
        const linkId = scope.linkId;
        const allowlisted = (classicLinkAllowlist(env) ?? []).includes(linkId);
        if (!allowUnlistedPending && !allowlisted && env.CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED !== 'true') {
            throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
        }
        const requestedIds = isDelete ? null : [...scope.linkIds].sort();
        const m = resolve();
        const stateModel = m.CascadeTopologyState;
        const operationId = randomUUID();
        const ownerToken = `classic-deploy:${operationId}`;
        let repository;
        if (isDelete) {
            const { TopologyDraftRepository } = require('../modules/relay-l2tp/repositories/topologyDraftRepository');
            repository = new TopologyDraftRepository(m);
        }
        async function prepareDeletion(session, checkRevision = true, heldNodeIds = null) {
            const snapshot = await repository.readDraft(session);
            if (checkRevision && snapshot.revision !== expectedTopologyRevision) throw failure('STALE_TOPOLOGY_REVISION');
            const { buildCandidate } = require('../modules/relay-l2tp/domain/topologyDraft');
            const { validateTopology } = require('../modules/relay-l2tp/domain/topologyValidator');
            const { compileTopology } = require('../modules/relay-l2tp/domain/topologyCompiler');
            const { mutationNodeIds, isStandaloneClassicMutation } = require('../modules/relay-l2tp/repositories/topologyDraftRepository');
            const request = { kind: 'link.delete', id: linkId };
            let standaloneClassicDraft = false;
            let candidateSnapshot = snapshot;
            if (heldNodeIds) {
                // Classification needs complete relay inventory, not just installed groups.
                const query = m.RelayL2tpState.find({});
                snapshot.relayReferences = await (session ? query.session(session) : query.setOptions(READ)).lean();
                standaloneClassicDraft = isStandaloneClassicMutation(snapshot, request);
                if (standaloneClassicDraft) {
                    // No groups reference this proven standalone component. Build
                    // locally too: the global builder also prunes unrelated empty groups.
                    candidateSnapshot = { ...snapshot,
                        nodes: snapshot.nodes.filter(node => heldNodeIds.includes(entityId(node))),
                        links: snapshot.links.filter(link => heldNodeIds.includes(entityId(link.portalNode))
                            && heldNodeIds.includes(entityId(link.bridgeNode))),
                        groups: [], activeRouteGroupIds: [], installedRouteGroupIds: [] };
                }
            }
            const prepared = buildCandidate(candidateSnapshot, request);
            if (heldNodeIds && mutationNodeIds(snapshot, prepared.mutation).some(id => !heldNodeIds.includes(id))) {
                throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            }
            if (!validateTopology(prepared.candidate)?.valid
                || !compileTopology({ ...prepared.candidate, healthByPathKey: {} })?.valid) {
                throw failure('INVALID_TOPOLOGY_DRAFT');
            }
            return { mutation: prepared.mutation, standaloneClassicDraft };
        }
        async function assertNoCompetingWork(session) {
            const read = query => session ? query.session(session) : query.setOptions(READ);
            if (await read(m.TopologyOperation.exists({ $or: [
                { status: { $nin: ['succeeded', 'failed', 'rolled_back'] } }, { heldTopologyAdmission: true },
            ] }))
                || await read(m.TopologyCreateIntent.exists({ status: { $nin: ['succeeded', 'failed'] } }))
                || await read(m.TopologyIntentQueueState.exists({ outstanding: { $ne: 0 } }))
                || await read(m.NodeOperationLock.exists({}))) throw failure('CLASSIC_DEPLOY_BUSY');
        }
        async function admission(session, independent = false, requireCreatedPending = allowUnlistedPending) {
            const read = query => session ? query.session(session) : query.setOptions(READ);
            const links = await read(m.CascadeLink.find({}).select('+classicLifecycleGrant')).lean();
            if (!Array.isArray(links) || new Set(links.map(link => entityId(link._id))).size !== links.length) {
                throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            }
            const selected = links.find(link => entityId(link._id) === linkId);
            if (!selected || selected.active !== true || selected.mode !== 'reverse') throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            if (!allowlisted && !(allowUnlistedPending && env.CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED !== 'true')
                && !hasClassicLifecycleGrant(selected, env)) throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            if (!['pending', 'error', ...APPLIED].includes(selected.status)
                || (requireCreatedPending && selected.status !== 'pending')) {
                throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            }
            const baselineLinkIds = baselineIds(links, selected);
            if (links.some(link => baselineLinkIds.includes(entityId(link._id))
                && (link.mode ?? 'reverse') !== 'reverse')) throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            if (requestedIds && !sameList([...baselineLinkIds, linkId].sort(), requestedIds)) {
                throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            }
            const endpoints = [entityId(selected.portalNode), entityId(selected.bridgeNode)];
            if (!endpoints.every(validId) || endpoints[0] === endpoints[1]) throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            const nodes = await read(m.HyNode.find({})).lean();
            const componentNodeIds = independent ? [...new Set([...endpoints, ...links
                .filter(link => baselineLinkIds.includes(entityId(link._id)))
                .flatMap(link => [entityId(link.portalNode), entityId(link.bridgeNode)])])].sort() : endpoints;
            for (const id of componentNodeIds) {
                const matches = nodes.filter(node => entityId(node._id) === id);
                if (matches.length !== 1) throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
                const owns = dependencies.topologyManagesNodeConfig ?? require('./topologyConfigOwnership').topologyManagesNodeConfig;
                try {
                    if (await owns(matches[0], env)) throw failure('CLASSIC_DEPLOY_OWNER_VETO');
                } catch { throw failure('CLASSIC_DEPLOY_OWNER_VETO'); }
            }
            const relays = await read(m.RelayL2tpState.find({})).lean();
            if (!Array.isArray(relays) || relays.some(state => componentNodeIds.includes(entityId(state?.node))
                && !inactiveRelay(state))) throw failure('CLASSIC_DEPLOY_IN_USE');
            const touching = new Set(links.filter(link => componentNodeIds.includes(entityId(link.portalNode))
                || componentNodeIds.includes(entityId(link.bridgeNode))).map(link => entityId(link._id)));
            const groups = await read(m.CascadeRouteGroup.find({})).lean();
            if (routeGroupUseVeto(groups, relays, touching)) throw failure('CLASSIC_DEPLOY_IN_USE');
            const source = nodes.find(node => entityId(node._id) === endpoints[0]);
            const destination = nodes.find(node => entityId(node._id) === endpoints[1]);
            // Capability refusal is DB-only: do it before preview, reservation
            // and node locks, and recheck it in the held core before dispatch.
            const { scopedClassicEndpointsSupported } = require('./classicScopedEndpointSupport');
            if (!scopedClassicEndpointsSupported(source, destination)) throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            const standalone = source.cascadeRole === 'portal' && destination.cascadeRole === 'bridge'
                && !links.some(link => link !== selected && link.active !== false && APPLIED.has(link.status)
                    && (entityId(link.bridgeNode) === endpoints[0] || entityId(link.portalNode) === endpoints[0]
                        || entityId(link.portalNode) === endpoints[1]));
            if (independent && !standalone) throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            return { baselineLinkIds, endpoints, componentNodeIds, standalone,
                pin: independent ? independentPins(links, nodes, componentNodeIds) : null,
                portPreview: { node: source, port: selected.tunnelPort,
                target: { ...selected, portalNode: source, bridgeNode: destination } } };
        }
        const diagnose = (error, phase) => {
            const internalCode = typeof error?.code === 'string' && error.code.length <= 96
                && (Object.hasOwn(MESSAGES, error.code)
                    || /^(CLASSIC_SCOPED_[A-Z_]+|CLASSIC_CONFIG_WRITE_[A-Z_]+|NODE_OPERATION_LOCK_CONFLICT)$/.test(error.code))
                ? error.code : 'UNKNOWN';
            try { (dependencies.logger ?? require('../utils/logger')).warn(JSON.stringify({
                event: 'classic-scoped-refusal', internalCode, phase, operationId, linkId,
            })); } catch { /* diagnostics cannot change ownership semantics */ }
        };
        async function checkedAdmission(session) {
            const state = await stateModel.findById('singleton').session(session).lean();
            if (!state || !Number.isSafeInteger(state.revision) || state.revision < 0
                || !Number.isSafeInteger(state.deployedRevision) || state.deployedRevision < 0
                || !Number.isSafeInteger(state.replacementEpoch) || state.replacementEpoch < 0
                || state.replacementEpoch >= Number.MAX_SAFE_INTEGER
                || state.topologyAdmissionCount !== 0 || state.remoteAdmissionCount !== 0
                || state.replacementReservation !== undefined || state.remoteDrain !== undefined
                || state.classicLifecycleAttempt !== undefined || (isDelete && state.revision >= Number.MAX_SAFE_INTEGER)) {
                throw failure('CLASSIC_DEPLOY_BUSY');
            }
            if (state.revision !== expectedTopologyRevision) throw failure('STALE_TOPOLOGY_REVISION');
            await assertNoCompetingWork(session);
            const admitted = await admission(session);
            if (isDelete) await prepareDeletion(session);
            return { state, admitted };
        }
        const transactionOptions = { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' };
        // Only standalone root Portal -> terminal Bridge operations use
        // independent admission, including a consumed server creation capability.
        // Relay/forward/full-sync retain their reservation protocol below.
        {
            const candidates = await m.CascadeLink.find({ _id: linkId }).setOptions(READ).lean();
            const candidate = candidates[0];
            const candidateNodes = candidate ? await m.HyNode.find({ _id: { $in: [candidate.portalNode, candidate.bridgeNode] } }).setOptions(READ).lean() : [];
            if (candidateNodes.find(node => entityId(node._id) === entityId(candidate?.portalNode))?.cascadeRole === 'portal'
                && candidateNodes.find(node => entityId(node._id) === entityId(candidate?.bridgeNode))?.cascadeRole === 'bridge') {
                try {
                const { withScopedClassicNodeLocks, createScopedClassicExecutionContext } = require('./classicPortalBridgeAdmission');
                const initial = await m.connection.transaction(async session => {
                    const state = await stateModel.findById('singleton').session(session).lean();
                    if (!state || state.revision !== expectedTopologyRevision) throw failure('STALE_TOPOLOGY_REVISION');
                    const admitted = await admission(session, true);
                    if (isDelete) await prepareDeletion(session, true, admitted.componentNodeIds);
                    return admitted;
                }, transactionOptions);
                let warning = false;
                const result = await withScopedClassicNodeLocks({ nodeIds: initial.componentNodeIds,
                    operationId: `classic-deploy:${operationId}`, lockService: dependencies.lockService }, async held => {
                    const pinned = await admission(undefined, true);
                    if (!sameList(pinned.componentNodeIds, initial.componentNodeIds) || pinned.pin !== initial.pin
                        || !sameList(pinned.baselineLinkIds, initial.baselineLinkIds)) throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
                    const verifyPins = async session => {
                        await held.verify();
                        const fresh = await admission(session, true, false);
                        if (fresh.pin !== pinned.pin || !sameList(fresh.componentNodeIds, pinned.componentNodeIds)
                            || !sameList(fresh.baselineLinkIds, pinned.baselineLinkIds)) throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
                        if (isDelete) await prepareDeletion(session, false, pinned.componentNodeIds);
                        await held.verify();
                    };
                    if (!isDelete) {
                        const { preflightTunnelPort } = require('./classicScopedPortPreflight');
                        try { await preflightTunnelPort(pinned.portPreview, { NodeSSH: dependencies.NodeSSH }); }
                        catch (error) { throw failure(error?.code === 'TUNNEL_PORT_IN_USE'
                            ? 'CLASSIC_DEPLOY_PORT_CONFLICT' : 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE'); }
                    }
                    await verifyPins();
                    const scopedExecutionContext = createScopedClassicExecutionContext({ nodeIds: pinned.componentNodeIds, verify: verifyPins });
                    const core = dependencies.cascadeService ?? require('./cascadeService');
                    const method = isDelete ? 'removeScopedClassicLink' : 'deployScopedClassicLink';
                    if (typeof core[method] !== 'function') throw failure('TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
                    const completion = await held.runWithHeldConfigWrites(() => core[method]({ linkId, expectedTopologyRevision,
                        baselineLinkIds: pinned.baselineLinkIds, scopedExecutionContext, beforeRemoteMutation: held.beforeRemoteMutation }));
                    const context = { linkId, expectedTopologyRevision, baselineLinkIds: pinned.baselineLinkIds, endpoints: pinned.endpoints };
                    warning = !isDelete && checkedUnconnectedCompletion(completion, context);
                    if (!warning && !(isDelete ? checkedRemoval : checkedCompletion)(completion, context)) {
                        // A malformed receipt cannot authorize releasing possible effects.
                        await held.beforeRemoteMutation({ nodeId: pinned.endpoints[0], phase: 'unproved-completion' });
                        throw failure('CLASSIC_DEPLOY_UNCERTAIN');
                    }
                    await verifyPins();
                    // Full four-profile receipt establishes known remote completion.
                    // A later status/draft DB failure must not poison a safe retry.
                    await held.settleVerified();
                    if (isDelete) {
                        const removed = await m.connection.transaction(async session => {
                            await verifyPins(session);
                            const { mutation, standaloneClassicDraft } = await prepareDeletion(session, false, pinned.componentNodeIds);
                            const state = await stateModel.findById('singleton').session(session).lean();
                            if (!Number.isSafeInteger(state?.revision) || state.revision >= Number.MAX_SAFE_INTEGER) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                            await repository.persistMutation(mutation, session);
                            const updated = await stateModel.findOneAndUpdate({ _id: 'singleton', revision: state.revision },
                                { $inc: { revision: 1 } }, { session, new: true, upsert: false, runValidators: true }).lean();
                            if (updated?.revision !== state.revision + 1) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                            return { revision: updated.revision, deployedRevision: updated.deployedRevision,
                                ...(standaloneClassicDraft ? { standaloneClassicDraft: true } : {}) };
                        }, transactionOptions);
                        if (await m.CascadeLink.exists({ _id: linkId }).setOptions(READ)) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                        const state = await stateModel.findById('singleton').setOptions(READ).lean();
                        if (!state || state.revision < removed.revision) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                        return removed;
                    }
                    const status = warning ? 'offline' : 'deployed';
                    const updated = await m.CascadeLink.updateOne({ _id: linkId, active: true }, { $set: { status,
                        lastError: warning ? 'CLASSIC_SCOPED_TUNNEL_UNCONFIRMED' : '', lastHealthCheck: new Date() } },
                    { writeConcern: { w: 'majority' }, maxTimeMS: 5000 });
                    if (updated?.matchedCount !== 1) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                    const saved = await m.CascadeLink.find({ _id: linkId }).setOptions(READ).lean();
                    if (saved.length !== 1 || saved[0].status !== status) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                    await verifyPins();
                    return { status: 'succeeded', executionMode: 'classic', topologyRevision: expectedTopologyRevision };
                });
                if (warning) throw failure('CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED');
                return result;
                } catch (error) {
                    diagnose(error, 'independent-portal-bridge');
                    if (error?.remoteOutcomeUncertain === true) throw failure('CLASSIC_DEPLOY_UNCERTAIN');
                    if (error?.code === 'NODE_OPERATION_LOCK_CONFLICT') throw failure('CLASSIC_DEPLOY_NODE_BUSY');
                    if (require('./classicPortalBridgePhase').isClassicPortalBridgePreflightError(error)) {
                        throw failure('CLASSIC_DEPLOY_PREFLIGHT_FAILED');
                    }
                    if (error?.code === 'CLASSIC_DEPLOY_PREFLIGHT_FAILED') throw failure('CLASSIC_DEPLOY_UNCERTAIN');
                    if (Object.hasOwn(MESSAGES, error?.code)) throw failure(error.code);
                    throw failure(/^CLASSIC_CONFIG_WRITE_/.test(error?.code ?? '')
                        ? 'CLASSIC_DEPLOY_FENCE_LOST' : 'CLASSIC_DEPLOY_UNCERTAIN');
                }
            }
        }
        if (!isDelete) {
            // A retried DB-only authorization/ownership snapshot, then bounded
            // read-only SSH OUTSIDE Mongo transactions and BEFORE any claim.
            // This preview never licenses release; the held core still rechecks.
            try {
                const { admitted } = await m.connection.transaction(checkedAdmission, transactionOptions);
                const { preflightTunnelPort } = require('./classicScopedPortPreflight');
                try { await preflightTunnelPort(admitted.portPreview, { NodeSSH: dependencies.NodeSSH }); }
                catch (error) { throw failure(error?.code === 'TUNNEL_PORT_IN_USE'
                    ? 'CLASSIC_DEPLOY_PORT_CONFLICT' : 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE'); }
            } catch (error) {
                diagnose(error, 'port-preflight');
                throw failure(Object.hasOwn(MESSAGES, error?.code) ? error.code : 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
            }
        }
        let claimed;
        try {
            claimed = await m.connection.transaction(async session => {
                const { state, admitted } = await checkedAdmission(session);
                const epoch = state.replacementEpoch + 1;
                const attempt = { operationId, action, linkId, epoch, nodeIds: admitted.endpoints,
                    topologyRevision: expectedTopologyRevision, deployedRevision: state.deployedRevision,
                    baselineLinkIds: admitted.baselineLinkIds, phase: 'dispatching' };
                const row = await stateModel.findOneAndUpdate({
                    _id: 'singleton', revision: expectedTopologyRevision, deployedRevision: state.deployedRevision,
                    replacementEpoch: state.replacementEpoch, topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                    replacementReservation: { $exists: false }, remoteDrain: { $exists: false },
                    classicLifecycleAttempt: { $exists: false },
                }, { $set: { replacementReservation: { ownerToken, epoch }, classicLifecycleAttempt: attempt },
                    $inc: { replacementEpoch: 1 } },
                { session, new: true, upsert: false, runValidators: true }).lean();
                if (!row || row.revision !== expectedTopologyRevision || row.replacementEpoch !== epoch
                    || row.replacementReservation?.ownerToken !== ownerToken
                    || row.replacementReservation?.epoch !== epoch
                    || row.classicLifecycleAttempt?.operationId !== operationId) throw failure('CLASSIC_DEPLOY_BUSY');
                return Object.freeze({ epoch, deployedRevision: state.deployedRevision, ...admitted });
            }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
        } catch (error) {
            // Unknown commit never dispatches and never attempts speculative release.
            diagnose(error, 'claim');
            throw failure(Object.hasOwn(MESSAGES, error?.code) ? error.code : 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
        }
        const fence = Object.freeze({ _id: 'singleton', revision: expectedTopologyRevision,
            deployedRevision: claimed.deployedRevision, replacementEpoch: claimed.epoch,
            topologyAdmissionCount: 0, remoteAdmissionCount: 0, remoteDrain: { $exists: false },
            'replacementReservation.ownerToken': ownerToken, 'replacementReservation.epoch': claimed.epoch,
            'classicLifecycleAttempt.operationId': operationId, 'classicLifecycleAttempt.action': action,
            'classicLifecycleAttempt.linkId': linkId, 'classicLifecycleAttempt.epoch': claimed.epoch,
            'classicLifecycleAttempt.topologyRevision': expectedTopologyRevision,
            'classicLifecycleAttempt.deployedRevision': claimed.deployedRevision,
            'classicLifecycleAttempt.nodeIds': claimed.endpoints,
            'classicLifecycleAttempt.baselineLinkIds': claimed.baselineLinkIds,
            'classicLifecycleAttempt.phase': 'dispatching' });
        async function verifyFence(session) {
            const query = stateModel.findOne(fence);
            const row = await (session ? query.session(session) : query.setOptions(READ)).lean();
            if (!row || row._id !== 'singleton' || row.revision !== expectedTopologyRevision
                || row.deployedRevision !== claimed.deployedRevision || row.replacementEpoch !== claimed.epoch
                || row.topologyAdmissionCount !== 0 || row.remoteAdmissionCount !== 0
                || row.remoteDrain !== undefined || row.replacementReservation?.ownerToken !== ownerToken
                || row.replacementReservation?.epoch !== claimed.epoch
                || row.classicLifecycleAttempt?.operationId !== operationId
                || row.classicLifecycleAttempt?.action !== action || row.classicLifecycleAttempt?.linkId !== linkId
                || row.classicLifecycleAttempt?.epoch !== claimed.epoch
                || row.classicLifecycleAttempt?.topologyRevision !== expectedTopologyRevision
                || row.classicLifecycleAttempt?.deployedRevision !== claimed.deployedRevision
                || row.classicLifecycleAttempt?.phase !== 'dispatching'
                || !sameList(row.classicLifecycleAttempt?.nodeIds, claimed.endpoints)
                || !sameList(row.classicLifecycleAttempt?.baselineLinkIds, claimed.baselineLinkIds)) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
        }
        // Everything below is AFTER acquisition. Errors/timeouts/partial proofs
        // keep ownership. A full verified-unconnected receipt is separately
        // settled before warning; it does not claim a connected tunnel.
        let unconnectedSettled = false;
        try {
            await verifyFence();
            await assertNoCompetingWork();
            const { baselineLinkIds, endpoints } = await admission();
            if (!sameList(endpoints, claimed.endpoints) || !sameList(baselineLinkIds, claimed.baselineLinkIds)) {
                throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            }
            if (isDelete) await prepareDeletion();
            await verifyFence();
            const core = dependencies.cascadeService ?? require('./cascadeService');
            const method = isDelete ? 'removeScopedClassicLink' : 'deployScopedClassicLink';
            if (typeof core[method] !== 'function') throw failure('TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
            const result = await core[method]({ linkId, expectedTopologyRevision, baselineLinkIds });
            const context = { linkId, expectedTopologyRevision, baselineLinkIds, endpoints };
            const unconnected = !isDelete && checkedUnconnectedCompletion(result, context);
            if (!unconnected && !(isDelete ? checkedRemoval : checkedCompletion)(result, context)) {
                throw failure('CLASSIC_DEPLOY_UNCERTAIN');
            }
            await verifyFence();
            const revision = expectedTopologyRevision + (isDelete ? 1 : 0);
            const settlement = { operationId, action, linkId, epoch: claimed.epoch, nodeIds: endpoints,
                topologyRevision: expectedTopologyRevision, deployedRevision: claimed.deployedRevision,
                baselineLinkIds, revision, phase: 'succeeded' };
            const exactSettlement = actual => actual && Object.entries(settlement).every(([key, expected]) =>
                Array.isArray(expected) ? sameList(actual[key], expected) : actual[key] === expected);
            const update = { $set: { classicLifecycleLastSettlement: settlement },
                $unset: { replacementReservation: '', classicLifecycleAttempt: '' },
                ...(isDelete ? { $inc: { revision: 1 } } : {}) };
            let released;
            if (isDelete) {
                released = await m.connection.transaction(async session => {
                    await verifyFence(session);
                    await assertNoCompetingWork(session);
                    const fresh = await admission(session);
                    if (!sameList(fresh.endpoints, endpoints) || !sameList(fresh.baselineLinkIds, baselineLinkIds)) {
                        throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
                    }
                    const { mutation } = await prepareDeletion(session);
                    await repository.persistMutation(mutation, session);
                    const row = await stateModel.findOneAndUpdate(fence, update,
                        { session, new: true, upsert: false, runValidators: true }).lean();
                    if (!row || row.revision !== revision || row.replacementReservation !== undefined
                        || row.classicLifecycleAttempt !== undefined
                        || !exactSettlement(row.classicLifecycleLastSettlement)) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                    return row;
                }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
            } else {
                released = await stateModel.findOneAndUpdate(fence, update,
                    { new: true, upsert: false, runValidators: true, writeConcern: { w: 'majority' }, maxTimeMS: 5000 }).lean();
            }
            if (!released || released.replacementReservation !== undefined || released.classicLifecycleAttempt !== undefined
                || released.revision !== revision || released.replacementEpoch !== claimed.epoch
                || released.deployedRevision !== claimed.deployedRevision
                || !exactSettlement(released.classicLifecycleLastSettlement)) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
            // A write acknowledgement alone is not completion. Read back this
            // operation's exact settlement; unknown settlement never re-dispatches.
            const confirmed = await stateModel.findOne({ _id: 'singleton', revision,
                deployedRevision: claimed.deployedRevision, replacementEpoch: claimed.epoch,
                replacementReservation: { $exists: false }, classicLifecycleAttempt: { $exists: false },
                'classicLifecycleLastSettlement.operationId': operationId }).setOptions(READ).lean();
            if (!confirmed || confirmed.revision !== revision || confirmed.replacementEpoch !== claimed.epoch
                || confirmed.deployedRevision !== claimed.deployedRevision || confirmed.replacementReservation !== undefined
                || confirmed.classicLifecycleAttempt !== undefined
                || !exactSettlement(confirmed.classicLifecycleLastSettlement)) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
            if (isDelete) {
                if (await m.CascadeLink.exists({ _id: linkId }).setOptions(READ)) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
                return { revision, deployedRevision: claimed.deployedRevision };
            }
            if (unconnected) {
                unconnectedSettled = true;
                throw failure('CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED');
            }
            return { status: 'succeeded', executionMode: 'classic', topologyRevision: expectedTopologyRevision };
        } catch (error) {
            diagnose(error, 'held-dispatch-or-settlement');
            // A code from a held callback cannot certify a pre-dispatch refusal.
            const safeCode = !(error?.code === 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED' && !unconnectedSettled)
                && !['CLASSIC_DEPLOY_PORT_CONFLICT', 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE'].includes(error?.code)
                && Object.hasOwn(MESSAGES, error?.code) ? error.code : 'CLASSIC_DEPLOY_UNCERTAIN';
            throw failure(safeCode);
        }
    }
    const queue = input => runQueue(input);
    const queueCreatedLink = async (input, capability) => {
        purgeCreationCapabilities();
        const token = capabilityToken(capability);
        const record = token && creationCapabilities.get(token);
        const linkId = input?.scope?.linkId;
        if (!record || !record.confirmed || record.linkId !== linkId
            || input?.expectedTopologyRevision !== record.expectedTopologyRevision) {
            throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
        }
        // Consume before any await: a retry or concurrent caller cannot dispatch
        // the same newly-created link twice with one creation receipt.
        creationCapabilities.delete(token);
        return runQueue(input, { creationCapability: record });
    };
    return Object.freeze({
        queue,
        async deleteLink(input) {
            if (!input || typeof input !== 'object' || Array.isArray(input)
                || Object.keys(input).some(key => !['expectedTopologyRevision', 'linkId'].includes(key))
                || !validId(input.linkId)) throw failure('INVALID_REQUEST');
            return runQueue({ expectedTopologyRevision: input.expectedTopologyRevision,
                scope: { kind: 'link.apply', linkId: input.linkId, linkIds: [input.linkId] } }, { action: 'link.delete' });
        },
        beginCreatedLinkCapability,
        confirmCreatedLinkCapability,
        // This service never prepares L2TP ingress. Only checked DELETE applies
        // the draft builder's retained-group cleanup, in its settlement transaction.
        get requiresL2tpIngressPreparation() { return false; },
        selectBaselineLinkIds({ links, linkId }) {
            const selected = links.find(link => entityId(link._id) === entityId(linkId));
            if (!selected) throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            return baselineIds(links, selected);
        },
        // Internal create-and-apply path: the caller must have just persisted
        // the pending link in the same request. Public Deploy requires an exact
        // production ID or a verified server-issued durable lifecycle grant.
        queueCreatedLink,
        async deploy() { throw failure('CLASSIC_DEPLOY_UNSUPPORTED'); },
    });
}

function isCompletedClassicDeploymentResult(result, revision) {
    return !!result && result.status === 'succeeded' && result.executionMode === 'classic'
        && Number.isSafeInteger(revision) && revision >= 0 && result.topologyRevision === revision
        && Object.keys(result).sort().join(',') === 'executionMode,status,topologyRevision';
}

module.exports = { createClassicScopedCascadeDeploymentService, isClassicProductionDeploymentEnabled,
    isClassicProductionDeploymentConfigured, isCompletedClassicDeploymentResult };
