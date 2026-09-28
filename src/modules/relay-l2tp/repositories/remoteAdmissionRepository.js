'use strict';

const { randomUUID } = require('node:crypto');

function admissionError(code) {
    const error = new Error(code);
    error.code = code;
    return error;
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

class RemoteAdmissionRepository {
    constructor({ CascadeTopologyState, RemoteAdmission, transactionRunner } = {}) {
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
