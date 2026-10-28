'use strict';

const { randomUUID } = require('node:crypto');
const { resolveL2tpExecutionAuthorization } = require('../modules/relay-l2tp/domain/l2tpExecutionAuthorization');
const ID = /^[0-9a-f]{24}$/i;
const APPLIED = new Set(['deployed', 'online', 'staged']);
const READ = Object.freeze({ readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000 });
const MESSAGES = Object.freeze({
    CLASSIC_DEPLOY_UNSUPPORTED: 'Classic deployment supports only an existing active reverse link.apply',
    CLASSIC_DEPLOY_BUSY: 'Classic deployment requires an initialized, quiescent topology',
    CLASSIC_DEPLOY_SCOPE_CHANGED: 'Classic deployment scope no longer matches the confirmed baseline',
    CLASSIC_DEPLOY_IN_USE: 'Classic deployment is blocked by L2TP or route-group use',
    CLASSIC_DEPLOY_OWNER_VETO: 'Classic deployment is blocked by configuration ownership',
    CLASSIC_DEPLOY_UNCERTAIN: 'Classic deployment completion is unproved; ownership retained for recovery',
    CLASSIC_DEPLOY_FENCE_LOST: 'Classic deployment ownership could not be confirmed or released',
    TOPOLOGY_DEPLOYMENT_UNAVAILABLE: 'Classic deployment capabilities are unavailable',
    STALE_TOPOLOGY_REVISION: 'Topology revision changed; reload before applying',
    INVALID_REQUEST: 'Invalid scoped classic deployment request',
});
function failure(code) { return Object.assign(new Error(MESSAGES[code]), { code }); }
const validId = value => typeof value === 'string' && ID.test(value);
const entityId = value => String(value?._id ?? value);

function isClassicProductionDeploymentEnabled(env) {
    const auth = resolveL2tpExecutionAuthorization(env);
    return auth.enableProductionExecution === true && env.PANEL_DOMAIN === 'lm1.infograd.online'
        && env.CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true'
        && env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'false'
        && env.TOPOLOGY_TEST_EXECUTION_ENABLED === 'false';
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

    async function queue(input) {
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
        const requestedIds = [...scope.linkIds].sort();
        const m = resolve();
        const stateModel = m.CascadeTopologyState;
        const ownerToken = `classic-deploy:${randomUUID()}`;
        let claimed;
        try {
            claimed = await m.connection.transaction(async session => {
                const state = await stateModel.findById('singleton').session(session).lean();
                if (!state || !Number.isSafeInteger(state.revision) || state.revision < 0
                    || !Number.isSafeInteger(state.deployedRevision) || state.deployedRevision < 0
                    || !Number.isSafeInteger(state.replacementEpoch) || state.replacementEpoch < 0
                    || state.replacementEpoch >= Number.MAX_SAFE_INTEGER
                    || state.topologyAdmissionCount !== 0 || state.remoteAdmissionCount !== 0
                    || state.replacementReservation !== undefined || state.remoteDrain !== undefined) {
                    throw failure('CLASSIC_DEPLOY_BUSY');
                }
                if (state.revision !== expectedTopologyRevision) throw failure('STALE_TOPOLOGY_REVISION');
                if (await m.TopologyOperation.exists({ $or: [
                    { status: { $nin: ['succeeded', 'failed', 'rolled_back'] } }, { heldTopologyAdmission: true },
                ] }).session(session)
                    || await m.TopologyCreateIntent.exists({ status: { $nin: ['succeeded', 'failed'] } }).session(session)
                    || await m.TopologyIntentQueueState.exists({ outstanding: { $ne: 0 } }).session(session)
                    || await m.NodeOperationLock.exists({}).session(session)) throw failure('CLASSIC_DEPLOY_BUSY');
                const epoch = state.replacementEpoch + 1;
                const row = await stateModel.findOneAndUpdate({
                    _id: 'singleton', revision: expectedTopologyRevision, deployedRevision: state.deployedRevision,
                    replacementEpoch: state.replacementEpoch, topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                    replacementReservation: { $exists: false }, remoteDrain: { $exists: false },
                }, { $set: { replacementReservation: { ownerToken, epoch } }, $inc: { replacementEpoch: 1 } },
                { session, new: true, upsert: false, runValidators: true }).lean();
                if (!row || row.revision !== expectedTopologyRevision || row.replacementEpoch !== epoch
                    || row.replacementReservation?.ownerToken !== ownerToken
                    || row.replacementReservation?.epoch !== epoch) throw failure('CLASSIC_DEPLOY_BUSY');
                return Object.freeze({ epoch, deployedRevision: state.deployedRevision });
            }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
        } catch (error) {
            // Unknown commit never dispatches and never attempts speculative release.
            throw failure(Object.hasOwn(MESSAGES, error?.code) ? error.code : 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
        }
        const fence = Object.freeze({ _id: 'singleton', revision: expectedTopologyRevision,
            deployedRevision: claimed.deployedRevision, replacementEpoch: claimed.epoch,
            topologyAdmissionCount: 0, remoteAdmissionCount: 0, remoteDrain: { $exists: false },
            'replacementReservation.ownerToken': ownerToken, 'replacementReservation.epoch': claimed.epoch });
        async function verifyFence() {
            const row = await stateModel.findOne(fence).setOptions(READ).lean();
            if (!row || row._id !== 'singleton' || row.revision !== expectedTopologyRevision
                || row.deployedRevision !== claimed.deployedRevision || row.replacementEpoch !== claimed.epoch
                || row.topologyAdmissionCount !== 0 || row.remoteAdmissionCount !== 0
                || row.remoteDrain !== undefined || row.replacementReservation?.ownerToken !== ownerToken
                || row.replacementReservation?.epoch !== claimed.epoch) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
        }
        // Everything below is AFTER acquisition. Every refusal keeps ownership;
        // no error/timeout/partial completion can authorize a successor writer.
        try {
            await verifyFence();
            const links = await m.CascadeLink.find({}).setOptions(READ).lean();
            if (!Array.isArray(links) || new Set(links.map(link => entityId(link._id))).size !== links.length) {
                throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            }
            const selected = links.find(link => entityId(link._id) === linkId);
            if (!selected || selected.active !== true || selected.mode !== 'reverse') throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            const baselineLinkIds = baselineIds(links, selected);
            if (links.some(link => baselineLinkIds.includes(entityId(link._id))
                && (link.mode ?? 'reverse') !== 'reverse')) throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
            if (JSON.stringify([...baselineLinkIds, linkId].sort()) !== JSON.stringify(requestedIds)) {
                throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            }
            const endpoints = [entityId(selected.portalNode), entityId(selected.bridgeNode)];
            if (!endpoints.every(validId) || endpoints[0] === endpoints[1]) throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
            const nodes = await m.HyNode.find({}).setOptions(READ).lean();
            for (const id of endpoints) {
                const matches = nodes.filter(node => entityId(node._id) === id);
                if (matches.length !== 1) throw failure('CLASSIC_DEPLOY_SCOPE_CHANGED');
                const owns = dependencies.topologyManagesNodeConfig ?? require('./topologyConfigOwnership').topologyManagesNodeConfig;
                if (await owns(matches[0], env)) throw failure('CLASSIC_DEPLOY_OWNER_VETO');
            }
            const relays = await m.RelayL2tpState.find({}).setOptions(READ).lean();
            if (relays.some(state => endpoints.includes(entityId(state.node))
                && (['installed', 'installing'].includes(state.status)
                    || ['installed', 'installing'].includes(state.desiredState)))) throw failure('CLASSIC_DEPLOY_IN_USE');
            const touching = new Set(links.filter(link => endpoints.includes(entityId(link.portalNode))
                || endpoints.includes(entityId(link.bridgeNode))).map(link => entityId(link._id)));
            const groups = await m.CascadeRouteGroup.find({}).setOptions(READ).lean();
            if (groups.some(group => group.paths.some(path => path.enabled !== false
                && path.linkIds.some(id => touching.has(entityId(id)))))) throw failure('CLASSIC_DEPLOY_IN_USE');
            await verifyFence();
            const core = dependencies.cascadeService ?? require('./cascadeService');
            if (typeof core.deployScopedClassicLink !== 'function') throw failure('TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
            const result = await core.deployScopedClassicLink({ linkId, expectedTopologyRevision, baselineLinkIds });
            if (result?.success !== true || result?.remoteQuiescent !== true
                || Object.keys(result).sort().join(',') !== 'remoteQuiescent,success') throw failure('CLASSIC_DEPLOY_UNCERTAIN');
            await verifyFence();
            const released = await stateModel.findOneAndUpdate(fence,
                { $unset: { replacementReservation: '' } },
                { new: true, upsert: false, writeConcern: { w: 'majority' }, maxTimeMS: 5000 }).lean();
            if (!released || released.replacementReservation !== undefined
                || released.revision !== expectedTopologyRevision || released.replacementEpoch !== claimed.epoch
                || released.deployedRevision !== claimed.deployedRevision) throw failure('CLASSIC_DEPLOY_FENCE_LOST');
            return { status: 'succeeded', executionMode: 'classic', topologyRevision: expectedTopologyRevision };
        } catch (error) {
            throw failure(Object.hasOwn(MESSAGES, error?.code) ? error.code : 'CLASSIC_DEPLOY_UNCERTAIN');
        }
    }
    return Object.freeze({ queue, async deploy() { throw failure('CLASSIC_DEPLOY_UNSUPPORTED'); } });
}

function isCompletedClassicDeploymentResult(result, revision) {
    return !!result && result.status === 'succeeded' && result.executionMode === 'classic'
        && Number.isSafeInteger(revision) && revision >= 0 && result.topologyRevision === revision
        && Object.keys(result).sort().join(',') === 'executionMode,status,topologyRevision';
}

module.exports = { createClassicScopedCascadeDeploymentService, isClassicProductionDeploymentEnabled,
    isCompletedClassicDeploymentResult };
