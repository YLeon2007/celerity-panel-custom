'use strict';

const { randomBytes } = require('node:crypto');

const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_RETRY_INTERVAL_MS = 30000;
const OBJECT_ID = /^[a-f\d]{24}$/i;

function syncPlan(operationId, relayNode, credentialRevision) {
    return {
        ok: true,
        operationId,
        relayId: relayNode,
        desired: { credentialRevision },
        steps: [
            { type: 'backup' },
            { type: 'sync_users', artifacts: [{ type: 'desired', path: 'desired.json' }] },
            { type: 'verify_users' },
        ],
    };
}

class L2tpPppDriftSyncRepository {
    constructor({ RelayL2tpState, L2tpOperation,
        operationIdFactory = () => randomBytes(12).toString('hex') } = {}) {
        if (typeof RelayL2tpState?.findOne !== 'function'
            || typeof L2tpOperation?.findOne !== 'function'
            || typeof L2tpOperation?.countDocuments !== 'function'
            || typeof L2tpOperation?.create !== 'function'
            || typeof operationIdFactory !== 'function') {
            throw new TypeError('PPP drift SYNC requires state and operation models');
        }
        this.RelayL2tpState = RelayL2tpState;
        this.L2tpOperation = L2tpOperation;
        this.operationIdFactory = operationIdFactory;
    }

    /**
     * Persist one bounded attempt for a relay credential revision. This is a
     * queue primitive, not a PPP-readiness assertion: the caller establishes
     * revision or on-node drift before invoking it.
     */
    async enqueue({ relayNode, now, maxAttempts = DEFAULT_MAX_ATTEMPTS,
        retryIntervalMs = DEFAULT_RETRY_INTERVAL_MS } = {}) {
        if (typeof relayNode !== 'string' || !OBJECT_ID.test(relayNode)
            || !(now instanceof Date) || !Number.isFinite(now.getTime())
            || !Number.isSafeInteger(maxAttempts) || maxAttempts < 1
            || !Number.isSafeInteger(retryIntervalMs) || retryIntervalMs < 0) {
            throw new TypeError('Invalid PPP drift SYNC request');
        }
        const state = await this.RelayL2tpState.findOne({ node: relayNode })
            .select('node status desiredState secretRevision').lean();
        const revision = state?.secretRevision;
        if (state?.status !== 'installed' || state.desiredState !== 'installed'
            || !Number.isSafeInteger(revision) || revision < 1) {
            return { status: 'unavailable' };
        }

        // Never pile a drift attempt on top of a user edit's queued SYNC, or
        // another in-flight drift attempt. All SYNC producers share this query.
        const active = await this.L2tpOperation.findOne({
            node: relayNode, kind: 'sync_users',
            status: { $in: ['queued', 'running', 'rolling_back'] },
        }).select('_id').lean();
        if (active) return { status: 'active', operationId: String(active._id) };

        // Attempt numbers are encoded in durable unique idempotency keys, not
        // memory or worker's per-operation `attempts` (a separate retry budget).
        const prefix = `ppp-drift-sync:${relayNode}:revision-${revision}:attempt-`;
        const attemptKey = new RegExp(`^${prefix}[1-9][0-9]*$`);
        const attempts = await this.L2tpOperation.countDocuments({
            node: relayNode, kind: 'sync_users', idempotencyKey: attemptKey,
        });
        if (!Number.isSafeInteger(attempts) || attempts < 0) {
            throw new Error('Invalid persisted PPP drift SYNC attempt count');
        }
        if (attempts >= maxAttempts) return { status: 'exhausted', attempts };
        if (attempts > 0) {
            const previous = await this.L2tpOperation.findOne({
                node: relayNode, kind: 'sync_users', idempotencyKey: `${prefix}${attempts}`,
            }).select('status finishedAt createdAt').lean();
            // Missing, active, or malformed prior history is never permission
            // to bypass the bound/cooldown. Failed retries require a terminal op.
            if (!previous || !['failed', 'rolled_back', 'cancelled', 'succeeded'].includes(previous.status)) {
                return { status: 'active', attempts };
            }
            const completedAt = previous.finishedAt;
            if (!(completedAt instanceof Date) || !Number.isFinite(completedAt.getTime())
                || now.getTime() - completedAt.getTime() < retryIntervalMs) {
                return { status: 'cooldown', attempts };
            }
        }
        // Refuse a snapshot already superseded while reading durable history.
        // This does not replace a transaction fence against subsequent edits.
        const current = await this.RelayL2tpState.findOne({ node: relayNode })
            .select('status desiredState secretRevision').lean();
        if (current?.status !== 'installed' || current.desiredState !== 'installed'
            || current.secretRevision !== revision) return { status: 'unavailable' };
        const operationId = this.operationIdFactory();
        const idempotencyKey = `${prefix}${attempts + 1}`;
        try {
            await this.L2tpOperation.create([{
                _id: operationId,
                node: relayNode,
                kind: 'sync_users',
                status: 'queued',
                idempotencyKey,
                progress: 0,
                attempts: 0,
                plan: syncPlan(operationId, relayNode, revision),
            }]);
        } catch (error) {
            // The unique idempotency index is the cross-process CAS. Only a
            // duplicate of *our* key is an idempotent race; other errors fail.
            if (error?.code !== 11000 || !error.keyPattern?.idempotencyKey) throw error;
            const winner = await this.L2tpOperation.findOne({
                node: relayNode, kind: 'sync_users', idempotencyKey,
            }).select('_id').lean();
            if (!winner) throw error;
            return { status: 'active', operationId: String(winner._id), attempts: attempts + 1 };
        }
        return { status: 'queued', operationId, attempts: attempts + 1 };
    }
}

module.exports = { L2tpPppDriftSyncRepository, DEFAULT_MAX_ATTEMPTS, DEFAULT_RETRY_INTERVAL_MS };
