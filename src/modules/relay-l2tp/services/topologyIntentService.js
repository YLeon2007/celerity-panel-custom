'use strict';
const { createHash, randomUUID } = require('node:crypto');
const QUEUE_ID = 'create-v1';
function intentError(code) { return Object.assign(new Error(code), { code }); }
function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    return value;
}
function digest(value) { return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex'); }
function publicIntent(row) {
    if (!row) return null;
    return {
        jobId: String(row._id), status: row.status, acceptanceRevision: row.acceptanceRevision,
        ordinal: row.ordinal, attempts: row.attempts,
        ...(row.operationId ? { operationId: String(row.operationId), topologyRevision: row.topologyRevision } : {}),
        ...(row.createdLinkId ? { createdLinkId: String(row.createdLinkId) } : {}),
        ...(row.errorCode ? { errorCode: row.errorCode } : {}),
    };
}
class TopologyIntentService {
    constructor(dependencies = {}) {
        const { TopologyCreateIntent, TopologyIntentQueueState, CascadeTopologyState, CascadeLink, capacity = 32, transactionRunner } = dependencies;
        this.dependencies = dependencies;
        const models = { TopologyCreateIntent, TopologyIntentQueueState, CascadeTopologyState, CascadeLink };
        const connection = CascadeTopologyState?.db;
        if (!connection || Object.values(models).some(model => model?.db !== connection)) throw new TypeError('Intent admission requires one Mongo connection');
        if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 128) throw new TypeError('Intent capacity must be 1..128');
        Object.assign(this, models, { capacity });
        this.transactionRunner = transactionRunner || (work => connection.transaction(work, {
            readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary',
        }));
    }
    runOnce() {
        if (!this.consumer) {
            const { TopologyIntentConsumer } = require('./topologyIntentConsumer');
            this.consumer = new TopologyIntentConsumer(this.dependencies);
        }
        return this.consumer.runOnce();
    }
    get(id) { return this.TopologyCreateIntent.findById(id).lean().then(publicIntent); }
    async accept({ expectedTopologyRevision, requestKey = randomUUID(), link, payloadHash } = {}) {
        if (!Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) throw intentError('INVALID_TOPOLOGY_REVISION');
        if (typeof requestKey !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(requestKey)) throw intentError('INVALID_IDEMPOTENCY_KEY');
        const document = new this.CascadeLink({ ...link, active: true, status: 'pending', autoDeploy: true });
        await document.validate();
        const payload = JSON.parse(JSON.stringify(document.toObject()));
        delete payload.createdAt; delete payload.updatedAt; delete payload.__v;
        if (Buffer.byteLength(JSON.stringify(payload)) > 32768) throw intentError('TOPOLOGY_INTENT_PAYLOAD_TOO_LARGE');
        const { _id, ...comparable } = payload;
        const fingerprint = payloadHash || digest(comparable);
        if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw intentError('INVALID_REQUEST');
        const findExisting = async (session, confirmDurable = false) => {
            const query = this.TopologyCreateIntent.findOne({ requestKey }).session(session);
            if (confirmDurable) query.readConcern('majority').read('primary').maxTimeMS(5000);
            const found = await query.lean();
            if (found && found.payloadHash !== fingerprint) throw intentError('TOPOLOGY_INTENT_KEY_CONFLICT');
            return found;
        };
        try {
            return await this.transactionRunner(async session => {
                const existing = await findExisting(session);
                if (existing) return publicIntent(existing);
                let queue = await this.TopologyIntentQueueState.findById(QUEUE_ID).session(session).lean();
                if (!queue) {
                    // New namespace only; a missing counter alongside prior intents is corruption, not zero.
                    if (await this.TopologyCreateIntent.exists({}).session(session)) throw intentError('TOPOLOGY_INTENT_STATE_MISSING');
                    [queue] = await this.TopologyIntentQueueState.create([{ _id: QUEUE_ID, ordinal: 0, outstanding: 0 }], { session });
                }
                const state = await this.CascadeTopologyState.findOneAndUpdate(
                    { _id: 'singleton', revision: expectedTopologyRevision },
                    { $inc: { stateTransitionRevision: 1 } }, { new: true, session, upsert: false },
                ).lean();
                if (!state) throw intentError('STALE_TOPOLOGY_REVISION');
                const counted = await this.TopologyIntentQueueState.findOneAndUpdate(
                    { _id: QUEUE_ID, outstanding: { $lt: this.capacity } },
                    { $inc: { outstanding: 1, ordinal: 1 } }, { new: true, session, runValidators: true },
                ).lean();
                if (!counted) throw intentError('TOPOLOGY_INTENT_BACKLOG_FULL');
                const [row] = await this.TopologyCreateIntent.create([{
                    requestKey, version: 1, payload, payloadHash: fingerprint, ordinal: counted.ordinal,
                    acceptanceRevision: expectedTopologyRevision, status: 'waiting', attempts: 0, generation: 0,
                }], { session });
                return publicIntent(row);
            });
        } catch (error) {
            // Local visibility is not durable confirmation after an ambiguous commit.
            // Bound the primary majority read; absence/failure must never acknowledge acceptance.
            if (error?.code === 11000 || error?.hasErrorLabel?.('UnknownTransactionCommitResult')) {
                const existing = await findExisting(null, true);
                if (existing) return publicIntent(existing);
            }
            throw error;
        }
    }
}
function createTopologyIntentService(dependencies) { return new TopologyIntentService(dependencies); }
module.exports = { TopologyIntentService, createTopologyIntentService, publicIntent, digest, intentError, QUEUE_ID };
