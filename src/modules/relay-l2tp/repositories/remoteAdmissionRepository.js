'use strict';

const { randomUUID } = require('node:crypto');

function admissionError(code) {
    const error = new Error(code);
    error.code = code;
    return error;
}

const CLAIM_CAS_MISS = new Error('Queued install claim CAS miss');

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

class RemoteAdmissionRepository {
    constructor({ CascadeTopologyState, RemoteAdmission, L2tpOperation, transactionRunner } = {}) {
        if (typeof CascadeTopologyState?.updateOne !== 'function'
            || typeof RemoteAdmission?.create !== 'function'
            || typeof RemoteAdmission?.updateOne !== 'function') {
            throw new TypeError('Remote admission requires topology and admission models');
        }
        // No non-transaction fallback: even injected test runners must be explicit.
        this.transactionRunner = transactionRunner ?? transactionRunnerFor(CascadeTopologyState, RemoteAdmission);
        if (typeof this.transactionRunner !== 'function') throw new TypeError('Remote admission requires transactions');
        this.CascadeTopologyState = CascadeTopologyState;
        this.RemoteAdmission = RemoteAdmission;
        // Optional until the install handoff is explicitly wired by a caller.
        this.L2tpOperation = L2tpOperation;
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
            || operationDocument.idempotencyKey
                !== `install:${nodeId}:revision-${operationDocument.plan.topologyRevision}`) {
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
            await this.L2tpOperation.create([{
                ...operationDocument, admissionId,
            }], { session });
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

    async acquireInstall({ nodeId } = {}) {
        if (!nodeId) throw new TypeError('Invalid install admission');
        const connection = this.CascadeTopologyState.db;
        if (!connection || typeof connection.startSession !== 'function'
            || this.RemoteAdmission.db !== connection) {
            throw new TypeError('Install admission requires both models on one transactional Mongo connection');
        }
        const id = randomUUID();
        try {
            await this.transactionRunner(async session => {
                const gate = await this.CascadeTopologyState.updateOne({
                    _id: 'singleton', remoteDrain: { $exists: false },
                    replacementReservation: { $exists: false },
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
        const id = randomUUID();
        try {
            await this.transactionRunner(async session => {
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

    async markRecoveryRequired(id) {
        await this.transactionRunner(async session => {
            const changed = await this.RemoteAdmission.updateOne(
                { _id: id, phase: 'running' },
                { $set: { phase: 'recovery_required' } }, { session },
            );
            if (changed.matchedCount !== 1) throw admissionError('REMOTE_ADMISSION_NOT_ACTIVE');
        });
    }

    async release(id) {
        await this.transactionRunner(async session => {
            // The record is the idempotency key. A second release cannot decrement twice.
            const changed = await this.RemoteAdmission.updateOne(
                { _id: id, phase: 'running' },
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
