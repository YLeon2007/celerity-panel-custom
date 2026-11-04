'use strict';
const { randomUUID } = require('node:crypto');
const { QUEUE_ID, intentError, INTENT_KINDS, resourceIds, linkDesiredVersion } = require('./topologyIntentService');
const { matchesTopologyOperationExecutionContext, matchesTopologyExecutionContext, topologyExecutionContext } = require('../domain/topologyExecutionContext');
const TERMINAL = new Set(['succeeded', 'failed', 'rolled_back']);
const RESOURCE_BUSY = new Set(['TOPOLOGY_DEPLOY_BUSY', 'TOPOLOGY_ADMISSION_UNAVAILABLE',
    'CLASSIC_DEPLOY_NODE_BUSY', 'NODE_OPERATION_LOCK_CONFLICT']);
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
    #executionContext;
    constructor(dependencies) {
        const context = dependencies.executionContext;
        this.#executionContext = topologyExecutionContext(context?.target, context?.hostIdentity);
        if (!this.#executionContext) throw new TypeError('Intent consumption requires an exact server execution context');
        this.dependencies = { ...dependencies, executionContext: this.#executionContext };
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
    assertContext(row) {
        if (!matchesTopologyExecutionContext(row?.executionContext, this.#executionContext)) {
            throw intentError('TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH');
        }
    }
    assertOperationContext(operation) {
        this.assertContext(operation);
        if (!matchesTopologyOperationExecutionContext(operation, this.#executionContext)) {
            throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
        }
    }
    assertBinding(row) {
        if (row.version === 2 && (!INTENT_KINDS.has(row.kind)
            || !/^[a-f0-9]{24}$/.test(String(row.linkId))
            || typeof row.desiredVersion !== 'string' || !/^[a-f0-9]{64}$/.test(row.desiredVersion)
            || JSON.stringify(resourceIds(row.resourceNodeIds)) !== JSON.stringify(row.resourceNodeIds)
            || (row.kind === 'link.create' && String(row.createdLinkId) !== String(row.linkId)))) {
            throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
        }
        if (![1, 2].includes(row.version)) throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
        if ((['admitted', 'blocked'].includes(row.status)
                && !(row.version === 2 && row.status === 'blocked' && row.errorCode === 'TOPOLOGY_INTENT_PREPARE_UNCERTAIN')) !== Boolean(row.operationId)
            || (row.operationId && (!Number.isSafeInteger(row.topologyRevision) || row.topologyRevision < 0
                || !Number.isSafeInteger(row.priorDeployedRevision) || row.priorDeployedRevision < 0
                || !/^[a-f0-9]{64}$/.test(row.admissionFingerprint)
                || !matchesTopologyOperationExecutionContext({ ...row, idempotencyKey: row.operationIdempotencyKey }, this.#executionContext)))) {
            throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
        }
    }
    fence(row, status = row.status) {
        return { _id: row._id, status, generation: row.generation, leaseOwner: row.leaseOwner, leaseUntil: row.leaseUntil,
            'executionContext.target': this.#executionContext.target,
            'executionContext.hostIdentity': this.#executionContext.hostIdentity };
    }
    async releaseOutstanding(session) {
        const released = await this.TopologyIntentQueueState.updateOne(
            { _id: QUEUE_ID, outstanding: { $gt: 0 } }, { $inc: { outstanding: -1 } }, { session },
        );
        if (released.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_COUNTER_MISMATCH');
    }
    async claim(excludedIds = new Set()) {
        return this.transactionRunner(async session => {
            const rows = await this.TopologyCreateIntent.find({ status: { $in: ['waiting', 'claimed', 'admitted', 'blocked'] } })
                .sort({ ordinal: 1 }).limit(128).session(session).lean();
            // Refresh only unbound, undispatched mutations. Resolve every candidate
            // before eligibility so a newly expanded earlier union still wins FIFO.
            for (const row of rows) {
                this.assertContext(row); this.assertBinding(row);
                if (row.version !== 2 || row.operationId || row.status === 'blocked'
                    || (row.status === 'claimed' && row.leaseUntil > this.clock.now())) continue;
                const link = await this.dependencies.CascadeLink.findById(row.linkId).session(session).lean();
                if (!link || linkDesiredVersion(link) !== row.desiredVersion) continue;
                if (typeof this.dependencies.resolveIntentResources !== 'function') throw intentError('TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE');
                const fresh = resourceIds(await this.dependencies.resolveIntentResources({
                    kind: row.kind, link, desiredVersion: row.desiredVersion, session,
                }));
                if (JSON.stringify(fresh) !== JSON.stringify(row.resourceNodeIds)) {
                    const updated = await this.TopologyCreateIntent.updateOne(this.fence(row), { $set: { resourceNodeIds: fresh } }, { session });
                    if (updated.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
                    row.resourceNodeIds = fresh;
                }
            }
            const predecessors = [];
            for (const row of rows) {
                this.assertContext(row); this.assertBinding(row);
                const overlaps = predecessors.some(prior => prior.version !== 2 || row.version !== 2
                    || prior.resourceNodeIds.some(id => row.resourceNodeIds.includes(id)));
                predecessors.push(row);
                if (row.operationId || row.status === 'blocked' || excludedIds.has(String(row._id))) continue;
                if (overlaps) {
                    if (row.version === 2) await this.TopologyCreateIntent.updateOne(this.fence(row),
                        { $set: { waitingReason: 'TOPOLOGY_INTENT_RESOURCE_BUSY' } }, { session });
                    continue;
                }
                const now = this.clock.now();
                if ((row.status === 'claimed' && row.leaseUntil > now)
                    || (row.nextAttemptAt && row.nextAttemptAt > now)) continue;
                const safe = await this.CascadeTopologyState.findOneAndUpdate({
                    _id: 'singleton', ...(row.version === 2 ? {} : { topologyAdmissionCount: 0 }),
                    replacementReservation: { $exists: false }, remoteDrain: { $exists: false },
                }, { $inc: { stateTransitionRevision: 1 } }, { session, new: true }).lean();
                if (!safe) continue;
                if (row.attempts >= this.maxAttempts) {
                    const result = await this.TopologyCreateIntent.updateOne(this.fence(row),
                        { $set: { status: 'failed', errorCode: 'TOPOLOGY_INTENT_ATTEMPTS_EXHAUSTED' }, $unset: { leaseOwner: '', leaseUntil: '' } }, { session });
                    if (result.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
                    await this.releaseOutstanding(session);
                    predecessors.pop();
                    continue;
                }
                return this.TopologyCreateIntent.findOneAndUpdate(this.fence(row), {
                    $set: { status: 'claimed', leaseOwner: this.owner, leaseUntil: new Date(now.getTime() + this.leaseMs) },
                    $inc: { generation: 1, ...(row.version === 2 ? {} : { attempts: 1 }) },
                    $unset: { nextAttemptAt: '', errorCode: '', waitingReason: '' },
                }, { new: true, session }).select('+payload').lean();
            }
            return null;
        });
    }
    async settle(row) {
        return this.transactionRunner(async session => {
            const intent = await this.TopologyCreateIntent.findById(row._id).session(session).lean();
            if (!intent) return false;
            this.assertContext(intent);
            this.assertBinding(intent);
            if (!['admitted', 'blocked'].includes(intent.status) || !intent.operationId) return false;
            const operation = await this.TopologyOperation.findById(intent.operationId)
                .select('+admissionScope +resourceNodeIds +desiredVersion').session(session).lean();
            if (operation) {
                this.assertOperationContext(operation);
                if (intent.version === 2) this.assertSelectedOperation(intent, operation);
                if (operation.idempotencyKey !== intent.operationIdempotencyKey) throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
            }
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
            if (intent.version !== 2) {
                const safe = await this.CascadeTopologyState.findOneAndUpdate({ _id: 'singleton', topologyAdmissionCount: 0 },
                    { $inc: { stateTransitionRevision: 1 } }, { new: true, session }).lean();
                if (!safe) return false;
            }
            const updated = await this.TopologyCreateIntent.updateOne({ _id: intent._id, status: intent.status, operationId: intent.operationId, generation: intent.generation }, {
                $set: { status: operation.status === 'succeeded' ? 'succeeded' : 'failed',
                    ...(operation.status === 'succeeded' ? {} : { errorCode: 'TOPOLOGY_INTENT_OPERATION_FAILED' }) },
                $unset: { leaseOwner: '', leaseUntil: '', ...(operation.status === 'succeeded' ? { errorCode: '' } : {}) },
            }, { session });
            if (updated.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            await this.releaseOutstanding(session); return true;
        });
    }
    assertSelectedOperation(intent, operation) {
        this.assertOperationContext(operation);
        if (operation.admissionScope !== 'selected'
            || operation.kind !== (intent.kind === 'link.delete' ? 'link.delete' : 'link.apply')
            || String(operation.linkId) !== String(intent.linkId)
            || operation.desiredVersion !== intent.desiredVersion
            || JSON.stringify(resourceIds(operation.resourceNodeIds)) !== JSON.stringify(intent.resourceNodeIds)) {
            throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
        }
    }
    async consumeVersioned(row) {
        return this.transactionRunner(async session => {
            const intent = await this.TopologyCreateIntent.findOne({ ...this.fence(row, 'claimed'),
                leaseUntil: { $eq: row.leaseUntil, $gt: this.clock.now() } }).session(session).lean();
            if (!intent) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            this.assertContext(intent); this.assertBinding(intent);
            const link = await this.dependencies.CascadeLink.findById(intent.linkId).session(session).lean();
            if (!link || linkDesiredVersion(link) !== intent.desiredVersion) throw intentError('TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT');
            if (typeof this.dependencies.resolveIntentResources !== 'function') throw intentError('TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE');
            const freshResources = resourceIds(await this.dependencies.resolveIntentResources({
                kind: intent.kind, link, desiredVersion: intent.desiredVersion, session,
            }));
            if (JSON.stringify(freshResources) !== JSON.stringify(intent.resourceNodeIds)) throw intentError('TOPOLOGY_INTENT_RESOURCE_SCOPE_CHANGED');
            const current = await this.CascadeTopologyState.findOne({ _id: 'singleton',
                replacementReservation: { $exists: false }, remoteDrain: { $exists: false } }).session(session).lean();
            if (!current) throw intentError('TOPOLOGY_DEPLOY_BUSY');
            const admission = this.dependencies.intentOperationAdmission;
            if (admission?.db !== this.CascadeTopologyState.db || typeof admission?.queue !== 'function') throw intentError('TOPOLOGY_INTENT_ADMISSION_UNAVAILABLE');
            // Required integration capability: reuse selected coordinator/repository
            // admission in this exact session; it MUST NOT start a worker or do I/O.
            // It owns effective/baseline selection, never this legacy baselineIds().
            const queued = await admission.queue({ session, transactionRunner: work => work(session),
                executionContext: this.#executionContext, intentId: String(intent._id),
                mutation: { kind: intent.kind === 'link.delete' ? 'link.delete' : 'link.apply',
                    linkId: String(intent.linkId), desiredVersion: intent.desiredVersion },
                expectedTopologyRevision: current.revision, resourceNodeIds: freshResources,
            });
            const operation = await this.TopologyOperation.findById(queued?.operationId)
                .select('+admissionScope +resourceNodeIds +desiredVersion').session(session).lean();
            if (!operation) throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
            this.assertSelectedOperation(intent, operation);
            if (operation.heldTopologyAdmission !== true || operation.topologyRevision !== current.revision
                || !/^[a-f0-9]{64}$/.test(operation.admissionFingerprint)) throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
            const updated = await this.TopologyCreateIntent.updateOne({ ...this.fence(row, 'claimed'),
                leaseUntil: { $eq: row.leaseUntil, $gt: this.clock.now() } }, {
                $set: { status: 'admitted', operationId: operation._id, topologyRevision: operation.topologyRevision,
                    operationIdempotencyKey: operation.idempotencyKey,
                    priorDeployedRevision: operation.priorDeployedRevision, admissionFingerprint: operation.admissionFingerprint },
                $inc: { attempts: 1 }, $unset: { leaseOwner: '', leaseUntil: '', errorCode: '', waitingReason: '' },
            }, { session });
            if (updated.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            return queued;
        });
    }
    async consume(row) {
        if (row.version === 2) return this.consumeVersioned(row);
        return this.transactionRunner(async session => {
            const intent = await this.TopologyCreateIntent.findOne({ ...this.fence(row, 'claimed'), leaseUntil: { $eq: row.leaseUntil, $gt: this.clock.now() } })
                .select('+payload').session(session).lean();
            if (!intent) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            this.assertContext(intent);
            this.assertBinding(intent);
            const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
            const { TopologyDraftWriteService } = require('./topologyDraftWriteService');
            const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
            const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
            const { TopologyOperationCoordinator } = require('./topologyOperationCoordinator');
            const { TopologyOperationPlanMaterializer } = require('./topologyOperationPlanMaterializer');
            const { maintainAutoL2tpPaths } = require('./autoL2tpPathMaintenance');
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
                executionContext: this.#executionContext,
                topologyRepository: new TopologyDeploymentRepository({ snapshotReader: draft, ...dependencies }),
                planMaterializer: this.dependencies.planMaterializer || new TopologyOperationPlanMaterializer(dependencies),
                operationRepository: new TopologyOperationRepository({ model: this.TopologyOperation }),
                // Never launch remote execution inside (or on an ambiguous response from) this transaction.
            });
            const queued = await coordinator.queue({ expectedTopologyRevision: revision, scope: { kind: 'link.apply', linkId: String(link._id), linkIds } });
            const operation = await this.TopologyOperation.findById(queued.operationId).session(session).lean();
            if (operation) this.assertOperationContext(operation);
            if (!operation || operation.heldTopologyAdmission !== true || operation.topologyRevision !== revision
                || !/^[a-f0-9]{64}$/.test(operation.admissionFingerprint)) throw intentError('TOPOLOGY_INTENT_BINDING_INVALID');
            const updated = await this.TopologyCreateIntent.updateOne({ ...this.fence(row, 'claimed'), leaseUntil: { $eq: row.leaseUntil, $gt: this.clock.now() } }, {
                $set: { status: 'admitted', operationId: operation._id, topologyRevision: revision,
                    operationIdempotencyKey: operation.idempotencyKey,
                    priorDeployedRevision: operation.priorDeployedRevision, admissionFingerprint: operation.admissionFingerprint,
                    createdLinkId: link._id }, $unset: { leaseOwner: '', leaseUntil: '', errorCode: '' },
            }, { session });
            if (updated.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_FENCE_LOST');
            return queued;
        });
    }
    async failedAttempt(row, error) {
        if (error?.hasErrorLabel?.('UnknownTransactionCommitResult')
            || ['TOPOLOGY_INTENT_FENCE_LOST', 'TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH', 'TOPOLOGY_INTENT_BINDING_INVALID'].includes(error?.code)) return;
        if (row.version === 2) {
            const busy = RESOURCE_BUSY.has(error?.code);
            const retryable = !busy && (error?.hasErrorLabel?.('TransientTransactionError')
                || ['STALE_TOPOLOGY_REVISION', 'TOPOLOGY_INTENT_RESOURCE_SCOPE_CHANGED'].includes(error?.code));
            const rejected = new Set(['TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT',
                'TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE', 'TOPOLOGY_INTENT_ADMISSION_UNAVAILABLE']);
            const attempts = row.attempts + (busy ? 0 : 1);
            const exhausted = retryable && attempts >= this.maxAttempts;
            const failed = rejected.has(error?.code) || exhausted;
            const status = busy || (retryable && !exhausted) ? 'waiting' : failed ? 'failed' : 'blocked';
            await this.transactionRunner(async session => {
                const updated = await this.TopologyCreateIntent.updateOne(this.fence(row, 'claimed'), {
                    $set: { status, attempts,
                        ...(busy ? { waitingReason: 'TOPOLOGY_INTENT_RESOURCE_BUSY' }
                            : { errorCode: exhausted ? 'TOPOLOGY_INTENT_ATTEMPTS_EXHAUSTED'
                                : failed ? error.code : retryable ? 'TOPOLOGY_INTENT_PREPARE_FAILED' : 'TOPOLOGY_INTENT_PREPARE_UNCERTAIN' }),
                        ...(status === 'waiting' ? { nextAttemptAt: new Date(this.clock.now().getTime() + this.backoffMs * Math.max(1, attempts)) } : {}) },
                    $unset: { leaseOwner: '', leaseUntil: '', ...(busy ? { errorCode: '' } : { waitingReason: '' }) },
                }, { session });
                if (updated.matchedCount === 1 && failed) await this.releaseOutstanding(session);
            });
            return;
        }
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
        // Bounded scan of the existing queue. An uncertain selected operation
        // retains its own resources, not the head of every independent component.
        const admitted = await this.TopologyCreateIntent.find({ status: { $in: ['admitted', 'blocked'] } })
            .sort({ ordinal: 1 }).limit(128).lean();
        for (const row of admitted) {
            this.assertContext(row); this.assertBinding(row);
            await this.settle(row);
        }
        const excludedIds = new Set();
        for (let i = 0; i < 128; i++) {
            const head = await this.claim(excludedIds);
            if (!head || head.status !== 'claimed' || head.leaseOwner !== this.owner) return;
            try { return await this.consume(head); }
            catch (error) {
                await this.failedAttempt(head, error);
                if (head.version !== 2 || !RESOURCE_BUSY.has(error?.code)) return;
                excludedIds.add(String(head._id));
            }
        }
    }
}
module.exports = { TopologyIntentConsumer, baselineIds };
