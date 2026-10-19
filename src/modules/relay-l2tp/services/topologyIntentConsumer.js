'use strict';
const { randomUUID } = require('node:crypto');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { TopologyDraftWriteService } = require('./topologyDraftWriteService');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyOperationCoordinator } = require('./topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('./topologyOperationPlanMaterializer');
const { maintainAutoL2tpPaths } = require('./autoL2tpPathMaintenance');
const { QUEUE_ID, intentError } = require('./topologyIntentService');
const TERMINAL = new Set(['succeeded', 'failed', 'rolled_back']);
function baselineIds(links, link) {
    const touched = new Set([String(link.portalNode), String(link.bridgeNode)]);
    const result = new Set();
    let added;
    do {
        added = false;
        for (const candidate of links) {
            const id = String(candidate._id);
            const source = String(candidate.portalNode), target = String(candidate.bridgeNode);
            if (id === String(link._id) || result.has(id) || candidate.active === false
                || !['deployed', 'online', 'staged'].includes(candidate.status)
                || (!touched.has(source) && !touched.has(target))) continue;
            result.add(id); touched.add(source); touched.add(target); added = true;
        }
    } while (added);
    return [...result].sort();
}
class TopologyIntentConsumer {
    constructor(dependencies) {
        this.dependencies = dependencies;
        const { CascadeTopologyState, TopologyCreateIntent, TopologyIntentQueueState, TopologyOperation,
            clock = { now: () => new Date() }, owner = `intent-${randomUUID()}`, leaseMs = 30000,
            maxAttempts = 3, backoffMs = 1000, transactionRunner } = dependencies;
        if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10
            || !Number.isSafeInteger(leaseMs) || leaseMs < 1
            || !Number.isSafeInteger(backoffMs) || backoffMs < 0) throw new TypeError('Invalid intent processing bounds');
        const connection = CascadeTopologyState.db;
        const models = ['TopologyCreateIntent', 'TopologyIntentQueueState', 'TopologyOperation', 'HyNode', 'CascadeLink', 'CascadeRouteGroup', 'RelayL2tpState'];
        if (models.some(name => dependencies[name]?.db !== connection)) throw new TypeError('Intent consumption requires one Mongo connection');
        Object.assign(this, { CascadeTopologyState, TopologyCreateIntent, TopologyIntentQueueState, TopologyOperation, clock, owner, leaseMs, maxAttempts, backoffMs });
        this.transactionRunner = transactionRunner || (work => connection.transaction(work, {
            readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary',
        }));
    }
    fence(row, status = row.status) {
        return { _id: row._id, status, generation: row.generation, leaseOwner: row.leaseOwner, leaseUntil: row.leaseUntil };
    }
    async releaseOutstanding(session) {
        const released = await this.TopologyIntentQueueState.updateOne(
            { _id: QUEUE_ID, outstanding: { $gt: 0 } }, { $inc: { outstanding: -1 } }, { session },
        );
        if (released.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_COUNTER_MISMATCH');
    }
    async claim() {
        return this.transactionRunner(async session => {
            const row = await this.TopologyCreateIntent.findOne({ status: { $in: ['waiting', 'claimed', 'admitted', 'blocked'] } })
                .sort({ ordinal: 1 }).session(session).lean();
            if (!row) return null;
            if (row.operationId || row.status === 'blocked') return row;
            const now = this.clock.now();
            if ((row.status === 'claimed' && row.leaseUntil > now)
                || (row.nextAttemptAt && row.nextAttemptAt > now)) return null;
            const safe = await this.CascadeTopologyState.findOneAndUpdate({
                _id: 'singleton', topologyAdmissionCount: 0,
                replacementReservation: { $exists: false }, remoteDrain: { $exists: false },
            }, { $inc: { stateTransitionRevision: 1 } }, { session, new: true }).lean();
            if (!safe) return null;
            if (row.attempts >= this.maxAttempts) {
                const result = await this.TopologyCreateIntent.updateOne({ _id: row._id, status: row.status, generation: row.generation },
                    { $set: { status: 'failed', errorCode: 'TOPOLOGY_INTENT_ATTEMPTS_EXHAUSTED' }, $unset: { leaseOwner: '', leaseUntil: '' } }, { session });
                if (result.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
                await this.releaseOutstanding(session); return null;
            }
            return this.TopologyCreateIntent.findOneAndUpdate({ _id: row._id, status: row.status, generation: row.generation }, {
                $set: { status: 'claimed', leaseOwner: this.owner, leaseUntil: new Date(now.getTime() + this.leaseMs) },
                $inc: { generation: 1, attempts: 1 }, $unset: { nextAttemptAt: '', errorCode: '' },
            }, { new: true, session }).select('+payload').lean();
        });
    }
    async settle(row) {
        return this.transactionRunner(async session => {
            const intent = await this.TopologyCreateIntent.findById(row._id).session(session).lean();
            if (!intent || !['admitted', 'blocked'].includes(intent.status) || !intent.operationId) return false;
            const operation = await this.TopologyOperation.findById(intent.operationId).session(session).lean();
            const exact = operation && String(operation._id) === String(intent.operationId)
                && operation.topologyRevision === intent.topologyRevision
                && operation.priorDeployedRevision === intent.priorDeployedRevision
                && operation.admissionFingerprint === intent.admissionFingerprint;
            if (!exact || (TERMINAL.has(operation.status) && operation.heldTopologyAdmission !== false)) {
                await this.TopologyCreateIntent.updateOne({ _id: intent._id, operationId: intent.operationId, generation: intent.generation },
                    { $set: { status: 'blocked', errorCode: 'TOPOLOGY_INTENT_OPERATION_UNCERTAIN' } }, { session });
                return false;
            }
            if (!TERMINAL.has(operation.status)) return false;
            const safe = await this.CascadeTopologyState.findOneAndUpdate({ _id: 'singleton', topologyAdmissionCount: 0 },
                { $inc: { stateTransitionRevision: 1 } }, { new: true, session }).lean();
            if (!safe) return false;
            const updated = await this.TopologyCreateIntent.updateOne({ _id: intent._id, status: intent.status, operationId: intent.operationId, generation: intent.generation }, {
                $set: { status: operation.status === 'succeeded' ? 'succeeded' : 'failed',
                    ...(operation.status === 'succeeded' ? {} : { errorCode: 'TOPOLOGY_INTENT_OPERATION_FAILED' }) },
                $unset: { leaseOwner: '', leaseUntil: '', ...(operation.status === 'succeeded' ? { errorCode: '' } : {}) },
            }, { session });
            if (updated.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            await this.releaseOutstanding(session); return true;
        });
    }
    async consume(row) {
        return this.transactionRunner(async session => {
            const intent = await this.TopologyCreateIntent.findOne({ ...this.fence(row, 'claimed'), leaseUntil: { $eq: row.leaseUntil, $gt: this.clock.now() } })
                .select('+payload').session(session).lean();
            if (!intent) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            const transactionRunner = async work => work(session);
            const dependencies = { ...this.dependencies, transactionRunner };
            const draft = new TopologyDraftRepository(dependencies);
            const current = await this.CascadeTopologyState.findOne({ _id: 'singleton', topologyAdmissionCount: 0,
                replacementReservation: { $exists: false }, remoteDrain: { $exists: false } }).session(session).lean();
            if (!current) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            const link = intent.payload;
            // Compare actual listeners: forward on bridge, reverse (the legacy default) on portal.
            // Recheck at the queue head against each existing link's own mode.
            const listenerNode = link.mode === 'forward' ? link.bridgeNode : link.portalNode;
            if (await this.dependencies.CascadeLink.exists({
                active: true, tunnelPort: link.tunnelPort,
                $or: [{ mode: 'forward', bridgeNode: listenerNode }, { mode: { $ne: 'forward' }, portalNode: listenerNode }],
            }).session(session)) {
                throw intentError('TOPOLOGY_INTENT_PORT_CONFLICT');
            }
            const writeService = new TopologyDraftWriteService({ repository: draft });
            let revision = (await writeService.createLink({ expectedTopologyRevision: current.revision, link })).revision;
            const maintenance = await (this.dependencies.maintainPaths || maintainAutoL2tpPaths)(dependencies);
            if (Number.isSafeInteger(maintenance?.revision)) revision = maintenance.revision;
            const links = await this.dependencies.CascadeLink.find({}).session(session).lean();
            const linkIds = [String(link._id), ...baselineIds(links, link)];
            if (this.dependencies.prepareIngress) {
                const prepared = await this.dependencies.prepareIngress({ link, linkId: String(link._id), linkIds, expectedTopologyRevision: revision, session });
                if (!Number.isSafeInteger(prepared?.revision) || prepared.revision < revision) throw intentError('TOPOLOGY_INTENT_INGRESS_REVISION_INVALID');
                revision = prepared.revision;
            } else if (await this.dependencies.RelayL2tpState.exists({ routeGroup: { $ne: null } }).session(session)) {
                throw intentError('TOPOLOGY_INTENT_INGRESS_UNAVAILABLE');
            }
            const coordinator = new TopologyOperationCoordinator({
                topologyRepository: new TopologyDeploymentRepository({ snapshotReader: draft, ...dependencies }),
                planMaterializer: this.dependencies.planMaterializer || new TopologyOperationPlanMaterializer(dependencies),
                operationRepository: new TopologyOperationRepository({ model: this.TopologyOperation }),
                // Never launch remote execution inside (or on an ambiguous response from) this transaction.
            });
            const queued = await coordinator.queue({ expectedTopologyRevision: revision, scope: { kind: 'link.apply', linkId: String(link._id), linkIds } });
            const operation = await this.TopologyOperation.findById(queued.operationId).session(session).lean();
            if (!operation || operation.heldTopologyAdmission !== true || operation.topologyRevision !== revision
                || !/^[a-f0-9]{64}$/.test(operation.admissionFingerprint)) throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
            const updated = await this.TopologyCreateIntent.updateOne({ ...this.fence(row, 'claimed'), leaseUntil: { $eq: row.leaseUntil, $gt: this.clock.now() } }, {
                $set: { status: 'admitted', operationId: operation._id, topologyRevision: revision,
                    priorDeployedRevision: operation.priorDeployedRevision, admissionFingerprint: operation.admissionFingerprint,
                    createdLinkId: link._id }, $unset: { leaseOwner: '', leaseUntil: '', errorCode: '' },
            }, { session });
            if (updated.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            return queued;
        });
    }
    async failedAttempt(row, error) {
        if (error?.hasErrorLabel?.('UnknownTransactionCommitResult') || error?.code === 'TOPOLOGY_INTENT_FENCE_LOST') return;
        // This transaction callback never executes remotely. A known abort rolled back
        // link/maintenance/admission/binding together, so bounded local preparation retry is safe.
        await this.transactionRunner(async session => {
            const exhausted = row.attempts >= this.maxAttempts;
            const updated = await this.TopologyCreateIntent.updateOne(this.fence(row, 'claimed'), {
                $set: { status: exhausted ? 'failed' : 'waiting',
                    errorCode: exhausted ? 'TOPOLOGY_INTENT_ATTEMPTS_EXHAUSTED' : 'TOPOLOGY_INTENT_PREPARE_FAILED',
                    ...(!exhausted ? { nextAttemptAt: new Date(this.clock.now().getTime() + this.backoffMs * row.attempts) } : {}) },
                $unset: { leaseOwner: '', leaseUntil: '' },
            }, { session });
            if (updated.matchedCount === 1 && exhausted) await this.releaseOutstanding(session);
        });
    }
    async runOnce() {
        let head = await this.claim();
        // Settle bounded completed heads, but admit at most one new operation per tick.
        for (let i = 0; head?.operationId && i < 128; i++) {
            if (!await this.settle(head)) return;
            head = await this.claim();
        }
        if (!head || head.status !== 'claimed' || head.leaseOwner !== this.owner) return;
        try { return await this.consume(head); }
        catch (error) { await this.failedAttempt(head, error); }
    }
}
module.exports = { TopologyIntentConsumer, baselineIds };
