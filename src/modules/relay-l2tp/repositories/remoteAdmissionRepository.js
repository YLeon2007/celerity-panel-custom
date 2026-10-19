'use strict';

const { randomUUID } = require('node:crypto');

function admissionError(code) {
    const error = new Error(code);
    error.code = code;
    return error;
}

const CLAIM_CAS_MISS = new Error('Queued install claim CAS miss');
function installAttemptKey(nodeId, revision, operationId) {
    return `install:${nodeId}:revision-${revision}:attempt-${operationId}`;
}

const SYNC_CLAIM_CAS_MISS = new Error('Queued sync_users claim CAS miss');
const PRE_REMOTE_FAILURES = new Set([
    'INSTALL_PLAN_REJECTED', 'INVALID_INSTALL_PLAN', 'INVALID_SYNC_USERS_PLAN',
    'VERIFY_STEP_REQUIRED', 'XRAY_CANDIDATE_FAILED',
    'NODE_OPERATION_LOCK_CONFLICT', 'NODE_LOCK_UNAVAILABLE',
    'SECRET_RESOLUTION_FAILED', 'USER_SNAPSHOT_RESOLUTION_FAILED',
]);

// The readback is returned to the install service for exact comparison, never
// to logs. Reject unexpected plan fields instead of copying possible secrets.
const PLAN_FIELDS = new Set(['ok', 'operationId', 'topologyRevision', 'relayId',
    'routeGroupId', 'selectedPathKey', 'nextHopNodeId', 'desired', 'steps']);
const DESIRED_FIELDS = new Set(['clientCidr', 'localAddress', 'poolStart', 'poolEnd',
    'dnsServers', 'tproxyPort', 'fwmark', 'routeTable', 'credentialRevision']);
const STEP_FIELDS = new Set(['type', 'artifacts']);
const ARTIFACT_FIELDS = new Set(['type', 'path']);

function safePlanObject(value, fields) {
    return value && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).every(key => fields.has(key));
}

function safeScalar(value) {
    return typeof value === 'string' || typeof value === 'boolean'
        || typeof value === 'number' && Number.isFinite(value);
}

function normalizedInstallPlan(plan) {
    if (!safePlanObject(plan, PLAN_FIELDS) || plan.ok !== true
        || typeof plan.operationId !== 'string' || typeof plan.relayId !== 'string'
        || !Number.isSafeInteger(plan.topologyRevision) || plan.topologyRevision < 0
        || !['routeGroupId', 'selectedPathKey', 'nextHopNodeId'].every(key =>
            plan[key] === undefined || typeof plan[key] === 'string')
        || plan.desired !== undefined && (!safePlanObject(plan.desired, DESIRED_FIELDS)
            || Object.entries(plan.desired).some(([key, value]) =>
                key === 'dnsServers' ? !Array.isArray(value)
                    || !value.every(item => typeof item === 'string') : !safeScalar(value)))
        || !Array.isArray(plan.steps) || !plan.steps.every(step =>
            safePlanObject(step, STEP_FIELDS) && typeof step.type === 'string'
            && (step.artifacts === undefined || Array.isArray(step.artifacts)
                && step.artifacts.every(artifact => safePlanObject(artifact, ARTIFACT_FIELDS)
                    && typeof artifact.type === 'string' && typeof artifact.path === 'string')))) {
        return null;
    }
    // Safe shape is fully bounded above. JSON cloning strips prototypes from
    // lean/Mongoose values without propagating metadata or credential fields.
    return JSON.parse(JSON.stringify(plan));
}

function transactionRunnerFor(CascadeTopologyState, RemoteAdmission) {
    const connection = CascadeTopologyState?.db;
    if (!connection || RemoteAdmission?.db !== connection || typeof connection.startSession !== 'function') {
        throw new TypeError('Remote admission requires both models on one transactional Mongo connection');
    }
    return async work => {
        const session = await connection.startSession();
        try {
            let value;
            await session.withTransaction(async () => { value = await work(session); });
            return value;
        } finally {
            await session.endSession();
        }
    };
}

// withTransaction may retry a callback or an uncertain commit. A counted
// first claim must make one attempt with one stable admission identity.
function oneShotTransactionRunnerFor(connection) {
    return async work => {
        const session = await connection.startSession();
        let commitStarted = false;
        try {
            session.startTransaction();
            const value = await work(session);
            commitStarted = true;
            await session.commitTransaction();
            return value;
        } catch (error) {
            if (!commitStarted) {
                try { await session.abortTransaction(); } catch { /* preserve original failure */ }
            }
            throw error;
        } finally {
            await session.endSession();
        }
    };
}

class RemoteAdmissionRepository {
    constructor({ CascadeTopologyState, RemoteAdmission, L2tpOperation, NodeOperationLock,
        transactionRunner } = {}) {
        if (typeof CascadeTopologyState?.updateOne !== 'function'
            || typeof RemoteAdmission?.create !== 'function'
            || typeof RemoteAdmission?.updateOne !== 'function') {
            throw new TypeError('Remote admission requires topology and admission models');
        }
        // No non-transaction fallback: even injected test runners must be explicit.
        this.transactionRunner = transactionRunner ?? transactionRunnerFor(CascadeTopologyState, RemoteAdmission);
        this.syncClaimRunner = transactionRunner ?? (CascadeTopologyState?.db?.startSession
            ? oneShotTransactionRunnerFor(CascadeTopologyState.db) : null);
        if (typeof this.transactionRunner !== 'function') throw new TypeError('Remote admission requires transactions');
        this.CascadeTopologyState = CascadeTopologyState;
        this.RemoteAdmission = RemoteAdmission;
        // Optional until the install handoff is explicitly wired by a caller.
        this.L2tpOperation = L2tpOperation;
        this.NodeOperationLock = NodeOperationLock;
    }

    /** Exact counted, still-queued readback for an uncertain queue commit. */
    async findInstallHandoff({ admissionId, operationId } = {}) {
        if (typeof admissionId !== 'string' || !admissionId
            || typeof operationId !== 'string' || !operationId) return null;
        const connection = this.CascadeTopologyState.db;
        if (!connection || typeof connection.startSession !== 'function'
            || this.RemoteAdmission.db !== connection || this.L2tpOperation?.db !== connection
            || typeof this.CascadeTopologyState.findOne !== 'function'
            || typeof this.RemoteAdmission.findOne !== 'function'
            || typeof this.L2tpOperation?.findOne !== 'function') return null;

        const session = await connection.startSession();
        try {
            let handoff;
            await session.withTransaction(async () => {
                handoff = await this._readInstallHandoff({ admissionId, operationId, session });
            }, { readConcern: { level: 'snapshot' } });
            return handoff;
        } finally {
            await session.endSession();
        }
    }

    async _readInstallHandoff({ admissionId, operationId, session }) {
        const gate = await this.CascadeTopologyState.findOne({
            _id: 'singleton', remoteAdmissionCount: { $gt: 0 },
            remoteDrain: { $exists: false }, replacementReservation: { $exists: false },
        }).session(session).lean();
        if (gate?._id !== 'singleton' || typeof gate.remoteAdmissionCount !== 'number'
            || !Number.isSafeInteger(gate.remoteAdmissionCount) || gate.remoteAdmissionCount <= 0
            || gate.remoteDrain !== undefined || gate.replacementReservation !== undefined) return null;

        const admission = await this.RemoteAdmission.findOne({ _id: admissionId,
            kind: 'install', phase: 'queued', operationId }).session(session).lean();
        if (admission?._id !== admissionId || admission.kind !== 'install'
            || admission.phase !== 'queued' || admission.operationId !== operationId
            || admission.leaseOwner !== undefined
            || typeof admission.nodeId !== 'string' || !admission.nodeId) return null;

        const operation = await this.L2tpOperation.findOne({ _id: operationId,
            admissionId, kind: 'install', status: 'queued' }).session(session).lean();
        if (!operation || String(operation._id) !== operationId
            || String(operation.node) !== admission.nodeId
            || operation.kind !== 'install' || operation.status !== 'queued'
            || operation.ownerGeneration !== undefined || operation.attempts !== 0
            || operation.admissionId !== admissionId
            || operation.idempotencyKey !== installAttemptKey(
                admission.nodeId, operation.plan?.topologyRevision, operationId)) {
            return null;
        }
        const plan = normalizedInstallPlan(operation.plan);
        if (!plan || plan.operationId !== operationId || plan.relayId !== admission.nodeId) return null;
        return {
            admission: { _id: admissionId, nodeId: admission.nodeId, kind: 'install',
                phase: 'queued', operationId },
            operation: { _id: operationId, node: admission.nodeId, kind: 'install',
                status: 'queued', admissionId, idempotencyKey: operation.idempotencyKey, plan },
        };
    }

    async queueInstall({ admissionId, operationDocument } = {}) {
        const connection = this.CascadeTopologyState.db;
        if (!connection || typeof connection.startSession !== 'function'
            || this.RemoteAdmission.db !== connection
            || this.L2tpOperation?.db !== connection
            || typeof this.CascadeTopologyState.findOne !== 'function'
            || typeof this.L2tpOperation?.create !== 'function') {
            throw new TypeError('Install handoff requires three models on one transactional Mongo connection');
        }
        const operationId = operationDocument?._id;
        const nodeId = operationDocument?.node;
        if (!admissionId || !operationId || !nodeId
            || operationDocument.kind !== 'install' || operationDocument.status !== 'queued'
            || String(operationDocument.plan?.operationId) !== String(operationId)
            || String(operationDocument.plan?.relayId) !== String(nodeId)
            || !Number.isSafeInteger(operationDocument.plan?.topologyRevision)
            || operationDocument.plan.topologyRevision < 0
            || operationDocument.idempotencyKey !== installAttemptKey(
                nodeId, operationDocument.plan.topologyRevision, operationId)) {
            throw admissionError('REMOTE_ADMISSION_INVALID_INSTALL');
        }

        await this.transactionRunner(async session => {
            // Already counted before preflight: this handoff neither increments nor
            // decrements the gate. A drain can only begin after the count reaches 0.
            const gate = await this.CascadeTopologyState.findOne({
                _id: 'singleton', remoteAdmissionCount: { $gt: 0 },
                remoteDrain: { $exists: false }, replacementReservation: { $exists: false },
            }).session(session).lean();
            if (!gate) throw admissionError('REMOTE_ADMISSION_BLOCKED');

            // The unique _id and idempotencyKey indexes reject duplicates; never
            // reinterpret a duplicate as a successful handoff or delete a prior op.
            try {
                await this.L2tpOperation.create([{
                    ...operationDocument, admissionId,
                }], { session });
            } catch (error) {
                // Duplicate key is rejected before handoff; the transaction
                // will abort, so the caller may release only its unlinked claim.
                if (error.code === 11000) error.installQueuePreCommitAbort = true;
                throw error;
            }
            const changed = await this.RemoteAdmission.updateOne({
                _id: admissionId, nodeId: String(nodeId), kind: 'install',
                phase: 'running', operationId: { $exists: false },
            }, { $set: { phase: 'queued', operationId: String(operationId) } }, { session });
            if (changed.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_NOT_ACTIVE');
        });
        return String(operationId);
    }

    /** Dormant DB-only claim: the worker is deliberately not wired to this path. */
    async claimQueuedInstall({ owner, leaseMs, now } = {}) {
        if (typeof owner !== 'string' || !owner.trim()
            || !Number.isSafeInteger(leaseMs) || leaseMs <= 0
            || !(now instanceof Date) || !Number.isFinite(now.getTime())
            || !Number.isFinite(now.getTime() + leaseMs)) {
            throw new TypeError('Invalid queued install claim');
        }
        const connection = this.CascadeTopologyState.db;
        if (!connection || typeof connection.startSession !== 'function'
            || this.RemoteAdmission.db !== connection || this.L2tpOperation?.db !== connection
            || typeof this.CascadeTopologyState.findOne !== 'function'
            || typeof this.RemoteAdmission.findOne !== 'function'
            || typeof this.L2tpOperation?.findOne !== 'function'
            || typeof this.L2tpOperation?.updateOne !== 'function') {
            throw new TypeError('Queued install claim requires three models on one transactional Mongo connection');
        }

        const leaseUntil = new Date(now.getTime() + leaseMs);
        try {
            return await this.transactionRunner(async session => {
                // Queued admissions are already counted. Neither this claim nor a
                // failed CAS changes the gate; only a queued operation is eligible.
                const gate = await this.CascadeTopologyState.findOne({
                    _id: 'singleton', remoteAdmissionCount: { $gt: 0 },
                    remoteDrain: { $exists: false }, replacementReservation: { $exists: false },
                }).session(session).lean();
                if (!gate) return null;
                const candidate = await this.L2tpOperation.findOne({
                    status: 'queued', kind: 'install', admissionId: { $type: 'string', $ne: '' },
                }).sort({ createdAt: 1, _id: 1 }).session(session).lean();
                if (!candidate) return null;
                if (!Number.isSafeInteger(candidate.attempts) || candidate.attempts < 0
                    || candidate.attempts >= Number.MAX_SAFE_INTEGER
                    || candidate.ownerGeneration !== undefined) return null;
                const admission = await this.RemoteAdmission.findOne({
                    _id: candidate.admissionId, nodeId: String(candidate.node), kind: 'install',
                    phase: 'queued', operationId: String(candidate._id),
                    leaseOwner: { $exists: false },
                }).session(session).lean();
                if (!admission || !Number.isSafeInteger(admission.ownerGeneration)
                    || admission.ownerGeneration < 1
                    || admission.ownerGeneration >= Number.MAX_SAFE_INTEGER) return null;

                const ownerGeneration = admission.ownerGeneration + 1;
                const changed = await this.L2tpOperation.updateOne({
                    _id: candidate._id, node: candidate.node, kind: 'install', status: 'queued',
                    admissionId: candidate.admissionId, attempts: candidate.attempts,
                    ownerGeneration: { $exists: false },
                }, { $set: { status: 'running', leaseOwner: owner, leaseUntil, ownerGeneration },
                    $inc: { attempts: 1 } }, { session, runValidators: true });
                if (changed.matchedCount !== 1) throw CLAIM_CAS_MISS;
                const handedOff = await this.RemoteAdmission.updateOne({
                    _id: admission._id, nodeId: String(candidate.node), kind: 'install',
                    phase: 'queued', operationId: String(candidate._id),
                    leaseOwner: { $exists: false },
                    ownerGeneration: admission.ownerGeneration,
                }, { $set: { phase: 'running', leaseOwner: owner }, $inc: { ownerGeneration: 1 } },
                { session, runValidators: true });
                if (handedOff.matchedCount !== 1) throw CLAIM_CAS_MISS;
                return { ...candidate, status: 'running', leaseOwner: owner, leaseUntil,
                    attempts: candidate.attempts + 1, ownerGeneration };
            });
        } catch (error) {
            // Throwing inside the transaction (rather than returning null) is
            // essential: an admission CAS miss must roll back the operation write.
            if (error === CLAIM_CAS_MISS) return null;
            throw error;
        }
    }

    /** Dormant DB-only first claim; no worker or release path uses this yet. */
    async claimQueuedSyncUsers({ owner, leaseMs, now } = {}) {
        if (typeof owner !== 'string' || !owner.trim()
            || !Number.isSafeInteger(leaseMs) || leaseMs <= 0
            || !(now instanceof Date) || !Number.isFinite(now.getTime())
            || !Number.isFinite(now.getTime() + leaseMs)) {
            throw new TypeError('Invalid queued sync_users claim');
        }
        const connection = this.CascadeTopologyState.db;
        if (!connection || typeof connection.startSession !== 'function'
            || this.RemoteAdmission.db !== connection || this.L2tpOperation?.db !== connection
            || typeof this.L2tpOperation.findOne !== 'function'
            || typeof this.L2tpOperation.updateOne !== 'function'
            || typeof this.RemoteAdmission.create !== 'function'
            || typeof this.CascadeTopologyState.updateOne !== 'function') {
            throw new TypeError('Queued sync_users claim requires three models on one transactional Mongo connection');
        }

        const admissionId = randomUUID();
        const leaseUntil = new Date(now.getTime() + leaseMs);
        try {
            return await this.syncClaimRunner(async session => {
                const candidate = await this.L2tpOperation.findOne({
                    status: 'queued', kind: 'sync_users', admissionId: { $exists: false },
                    ownerGeneration: { $exists: false },
                }).sort({ createdAt: 1, _id: 1 }).session(session).lean();
                if (!candidate) return null;
                if (!Number.isSafeInteger(candidate.attempts) || candidate.attempts < 0
                    || candidate.attempts >= Number.MAX_SAFE_INTEGER) return null;
                const unresolved = await this.RemoteAdmission.findOne({
                    nodeId: String(candidate.node),
                    kind: { $in: ['install', 'standalone_preflight', 'sync_users'] },
                    phase: { $in: ['running', 'queued', 'recovery_required'] },
                }).session(session).lean();
                if (unresolved) return null;

                // The singleton CAS serializes concurrent admissions and excludes
                // drain/reservation. A later CAS/insert failure aborts the count.
                const gate = await this.CascadeTopologyState.updateOne({
                    _id: 'singleton', remoteDrain: { $exists: false },
                    replacementReservation: { $exists: false },
                    remoteAdmissionCount: { $gte: 0 },
                }, { $inc: { remoteAdmissionCount: 1 } }, { session });
                if (gate.matchedCount !== 1) return null;
                const changed = await this.L2tpOperation.updateOne({
                    _id: candidate._id, node: candidate.node, kind: 'sync_users',
                    status: 'queued', admissionId: { $exists: false },
                    ownerGeneration: { $exists: false }, attempts: candidate.attempts,
                }, { $set: { status: 'running', admissionId, leaseOwner: owner,
                    leaseUntil, ownerGeneration: 1 }, $inc: { attempts: 1 } },
                { session, runValidators: true });
                if (changed.matchedCount !== 1) throw SYNC_CLAIM_CAS_MISS;
                await this.RemoteAdmission.create([{
                    _id: admissionId, kind: 'sync_users', phase: 'running',
                    operationId: String(candidate._id), nodeId: String(candidate.node),
                    ownerGeneration: 1, leaseOwner: owner,
                }], { session });
                return { ...candidate, status: 'running', admissionId,
                    leaseOwner: owner, leaseUntil, attempts: candidate.attempts + 1,
                    ownerGeneration: 1 };
            });
        } catch (error) {
            if (error === SYNC_CLAIM_CAS_MISS) return null;
            // An ambiguous commit may already have persisted the admission.
            // Expose its identity; never retry or release on the caller's behalf.
            if (error && typeof error === 'object') error.admissionId = admissionId;
            throw error;
        }
    }

    async acquireInstall({ nodeId } = {}) {
        if (!nodeId) throw new TypeError('Invalid install admission');
        const connection = this.CascadeTopologyState.db;
        if (!connection || typeof connection.startSession !== 'function'
            || this.RemoteAdmission.db !== connection
            || typeof this.RemoteAdmission.findOne !== 'function'
            || this.NodeOperationLock?.db !== connection
            || typeof this.NodeOperationLock?.findOne !== 'function') {
            throw new TypeError('Install admission requires admission and node lock models on one transactional Mongo connection');
        }
        const id = randomUUID();
        try {
            await this.transactionRunner(async session => {
                // This snapshot rejects an already-held (even expired) fence.
                // It cannot prevent a later insert: the service must still claim
                // its own exact node lock before invoking remote preflight.
                const lock = await this.NodeOperationLock.findOne({ node: String(nodeId) })
                    .session(session).lean();
                if (lock) throw admissionError('NODE_OPERATION_LOCK_CONFLICT');
                const unresolved = await this.RemoteAdmission.findOne({
                    nodeId: String(nodeId), kind: { $in: ['install', 'standalone_preflight', 'sync_users'] },
                    phase: { $in: ['running', 'queued', 'recovery_required'] },
                }).session(session).lean();
                if (unresolved) throw admissionError('REMOTE_INSTALL_ALREADY_ACTIVE');
                const gate = await this.CascadeTopologyState.updateOne({
                    _id: 'singleton', remoteDrain: { $exists: false },
                    replacementReservation: { $exists: false },
                    // An active topology operation owns deployment, even before
                    // its worker has inserted the exact relay node lock.
                    topologyAdmissionCount: 0,
                    remoteAdmissionCount: { $gte: 0 },
                }, { $inc: { remoteAdmissionCount: 1 } }, { session });
                if (gate.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_BLOCKED');
                await this.RemoteAdmission.create([{
                    _id: id, nodeId: String(nodeId), kind: 'install', phase: 'running', ownerGeneration: 1,
                }], { session });
            });
        } catch (error) {
            // An uncertain commit can already own the gate. Never retry or release
            // on behalf of the caller; expose the one identity for reconciliation.
            if (error && typeof error === 'object') error.admissionId = id;
            throw error;
        }
        return id;
    }

    async acquire({ nodeId, kind = 'standalone_preflight' }) {
        if (!nodeId || kind !== 'standalone_preflight') throw new TypeError('Invalid standalone admission');
        const connection = this.CascadeTopologyState.db;
        if (!connection || typeof connection.startSession !== 'function'
            || this.RemoteAdmission.db !== connection
            || typeof this.RemoteAdmission.findOne !== 'function') {
            throw new TypeError('Standalone admission requires both models on one transactional Mongo connection');
        }
        const id = randomUUID();
        try {
            await this.transactionRunner(async session => {
                const unresolved = await this.RemoteAdmission.findOne({
                    nodeId: String(nodeId), kind: { $in: ['install', 'standalone_preflight', 'sync_users'] },
                    phase: { $in: ['running', 'queued', 'recovery_required'] },
                }).session(session).lean();
                if (unresolved) throw admissionError('REMOTE_INSTALL_ALREADY_ACTIVE');
                const gate = await this.CascadeTopologyState.updateOne({
                    _id: 'singleton', remoteDrain: { $exists: false },
                    replacementReservation: { $exists: false },
                    remoteAdmissionCount: { $gte: 0 },
                }, { $inc: { remoteAdmissionCount: 1 } }, { session });
                if (gate.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_BLOCKED');
                await this.RemoteAdmission.create([{
                    _id: id, nodeId: String(nodeId), kind, phase: 'running', ownerGeneration: 1,
                }], { session });
            });
        } catch (error) {
            // An uncertain commit may have counted the record. Do not retry or
            // authorize transport; retain its stable id for later reconciliation.
            if (error && typeof error === 'object') error.admissionId = id;
            throw error;
        }
        return id;
    }

    async completeVerifiedOperation({ admissionId, operationId, nodeId, owner,
        ownerGeneration, kind } = {}) {
        if (!admissionId || !operationId || !nodeId || !owner
            || !Number.isSafeInteger(ownerGeneration) || ownerGeneration < 1
            || !['install', 'sync_users'].includes(kind)
            || this.L2tpOperation?.db !== this.CascadeTopologyState.db
            || this.RemoteAdmission.db !== this.CascadeTopologyState.db
            || this.NodeOperationLock?.db !== this.CascadeTopologyState.db
            || typeof this.NodeOperationLock?.findOne !== 'function'
            || typeof this.L2tpOperation?.findOne !== 'function') {
            throw admissionError('REMOTE_ADMISSION_INVALID_COMPLETION');
        }
        return this.transactionRunner(async session => {
            const succeeded = await this.L2tpOperation.findOne({
                _id: operationId, node: nodeId, kind, status: 'succeeded',
                admissionId, leaseOwner: owner, ownerGeneration,
            }).session(session).lean();
            if (!succeeded) throw admissionError('REMOTE_ADMISSION_NOT_VERIFIED');
            const lock = await this.NodeOperationLock.findOne({
                node: nodeId, operationId,
            }).session(session).lean();
            if (lock) throw admissionError('REMOTE_ADMISSION_LOCK_HELD');
            const changed = await this.RemoteAdmission.updateOne({
                _id: admissionId, nodeId, kind,
                phase: { $in: ['running', 'recovery_required'] }, operationId,
                leaseOwner: owner, ownerGeneration,
            }, { $set: { phase: 'completed' } }, { session });
            if (changed.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_NOT_ACTIVE');
            const gate = await this.CascadeTopologyState.updateOne({
                _id: 'singleton', remoteAdmissionCount: { $gt: 0 },
            }, { $inc: { remoteAdmissionCount: -1 } }, { session });
            if (gate.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_GATE_MISSING');
            return true;
        });
    }

    async markRecoveryRequired(id) {
        await this.transactionRunner(async session => {
            const changed = await this.RemoteAdmission.updateOne(
                { _id: id, phase: 'running' },
                { $set: { phase: 'recovery_required' } }, { session },
            );
            if (changed.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_NOT_ACTIVE');
        });
    }

    /**
     * Close a counted worker admission only after the operation reached a
     * terminal state whose remote work is known to be quiescent. This is the
     * rollback/pre-SSH counterpart of completeVerifiedOperation.
     */
    async completeTerminalOperation({ admissionId, operationId, nodeId, owner,
        ownerGeneration, kind } = {}) {
        if (!admissionId || !operationId || !nodeId || !owner
            || !Number.isSafeInteger(ownerGeneration) || ownerGeneration < 1
            || !['install', 'sync_users'].includes(kind)
            || this.L2tpOperation?.db !== this.CascadeTopologyState.db
            || this.RemoteAdmission.db !== this.CascadeTopologyState.db
            || this.NodeOperationLock?.db !== this.CascadeTopologyState.db
            || typeof this.NodeOperationLock?.findOne !== 'function'
            || typeof this.L2tpOperation?.findOne !== 'function') {
            throw admissionError('REMOTE_ADMISSION_INVALID_COMPLETION');
        }
        return this.transactionRunner(async session => {
            const terminal = await this.L2tpOperation.findOne({
                _id: operationId, node: nodeId, kind,
                status: { $in: ['failed', 'rolled_back'] },
                admissionId, leaseOwner: owner, ownerGeneration,
            }).session(session).lean();
            if (!terminal || terminal.status === 'failed'
                && (terminal.progress !== 0 || !PRE_REMOTE_FAILURES.has(terminal.errorCode))) {
                throw admissionError('REMOTE_ADMISSION_NOT_TERMINAL');
            }
            const lock = await this.NodeOperationLock.findOne({
                node: nodeId, operationId,
            }).session(session).lean();
            if (lock) throw admissionError('REMOTE_ADMISSION_LOCK_HELD');
            const changed = await this.RemoteAdmission.updateOne({
                _id: admissionId, nodeId, kind,
                phase: { $in: ['running', 'recovery_required'] }, operationId,
                leaseOwner: owner, ownerGeneration,
            }, { $set: { phase: 'completed' } }, { session });
            if (changed.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_NOT_ACTIVE');
            const gate = await this.CascadeTopologyState.updateOne({
                _id: 'singleton', remoteAdmissionCount: { $gt: 0 },
            }, { $inc: { remoteAdmissionCount: -1 } }, { session });
            if (gate.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_GATE_MISSING');
            return true;
        });
    }

    /** Keep the count and mark the linked worker admission for authoritative recovery. */
    async markOperationRecoveryRequired({ admissionId, operationId, nodeId, owner,
        ownerGeneration, kind } = {}) {
        if (!admissionId || !operationId || !nodeId || !owner
            || !Number.isSafeInteger(ownerGeneration) || ownerGeneration < 1
            || !['install', 'sync_users'].includes(kind)) {
            throw admissionError('REMOTE_ADMISSION_INVALID_RECOVERY');
        }
        return this.transactionRunner(async session => {
            const changed = await this.RemoteAdmission.updateOne({
                _id: admissionId, nodeId, kind, phase: 'running', operationId,
                leaseOwner: owner, ownerGeneration,
            }, { $set: { phase: 'recovery_required' } }, { session });
            if (changed.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_NOT_ACTIVE');
            return true;
        });
    }

    /**
     * Repair only counted admissions with a durable terminal operation and no
     * remaining node lock. Running/rolling-back work and failed rollback stay
     * fenced; a restart is not evidence that SSH has stopped.
     */
    async recoverSettledAdmissions({ limit = 25 } = {}) {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100
            || typeof this.RemoteAdmission.find !== 'function'
            || typeof this.L2tpOperation?.findOne !== 'function'
            || this.NodeOperationLock?.db !== this.CascadeTopologyState.db) {
            throw admissionError('REMOTE_ADMISSION_RECOVERY_UNAVAILABLE');
        }
        const candidates = await this.RemoteAdmission.find({
            kind: { $in: ['install', 'sync_users'] },
            phase: { $in: ['running', 'recovery_required'] },
            operationId: { $exists: true },
        }).sort({ _id: 1 }).limit(limit).lean();
        let recovered = 0;
        for (const record of candidates) {
            if (!record.operationId || !record.leaseOwner
                || !Number.isSafeInteger(record.ownerGeneration)) continue;
            const operation = await this.L2tpOperation.findOne({
                _id: record.operationId,
            }).lean();
            if (!operation || !['succeeded', 'rolled_back', 'failed'].includes(operation.status)) {
                continue;
            }
            const input = {
                admissionId: record._id, operationId: record.operationId,
                nodeId: record.nodeId, owner: record.leaseOwner,
                ownerGeneration: record.ownerGeneration, kind: record.kind,
            };
            try {
                if (operation.status === 'succeeded') {
                    await this.completeVerifiedOperation(input);
                } else {
                    await this.completeTerminalOperation(input);
                }
                recovered += 1;
            } catch (error) {
                if (!['REMOTE_ADMISSION_NOT_ACTIVE', 'REMOTE_ADMISSION_NOT_VERIFIED',
                    'REMOTE_ADMISSION_NOT_TERMINAL', 'REMOTE_ADMISSION_LOCK_HELD'].includes(error.code)) {
                    throw error;
                }
            }
        }
        return { scanned: candidates.length, recovered };
    }

    async release(id) {
        await this.transactionRunner(async session => {
            // Only the unlinked prequeue owner may release. A worker's counted
            // admission remains fenced even when its operation appears terminal.
            // The record is the idempotency key: a second release cannot decrement twice.
            const changed = await this.RemoteAdmission.updateOne(
                { _id: id, phase: 'running', kind: { $in: ['standalone_preflight', 'install'] },
                    operationId: { $exists: false }, leaseOwner: { $exists: false },
                    ownerGeneration: 1 },
                { $set: { phase: 'completed' } }, { session },
            );
            if (changed.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_NOT_ACTIVE');
            const gate = await this.CascadeTopologyState.updateOne(
                { _id: 'singleton', remoteAdmissionCount: { $gt: 0 } },
                { $inc: { remoteAdmissionCount: -1 } }, { session },
            );
            if (gate.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_GATE_MISSING');
        });
    }
}

module.exports = { RemoteAdmissionRepository };
