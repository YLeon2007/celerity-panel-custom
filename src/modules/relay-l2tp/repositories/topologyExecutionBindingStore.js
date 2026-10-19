'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { topologyOperationClaimBindingFilter } = require('../domain/topologyOperationClaimBinding');
const { projectCanonicalXrayCandidate } = require('../services/topologyXrayCandidate');
const { UUID, ID, TOKEN, COMMANDS, EXPECTED_KEYS, RECORD_KEYS, exact, freeze, failure } = require('../models/topologyExecutionBindingContract');
const TIMEOUT_MS = 5000;
const ENROLLMENT_KEYS = ['nodeId', 'targetProfile', 'nodeIdentity', 'ownerGeneration', 'predecessorGeneration', 'bootId'];
const ENROLLMENT_ROW_KEYS = ['_id', 'executionContext', 'proofId', 'maintenanceId', ...ENROLLMENT_KEYS];
const BINDING_ROW_KEYS = [...new Set([...ENROLLMENT_ROW_KEYS, ...RECORD_KEYS, 'enrollmentId', 'commandTokens'])];
const PROFILES = ['xray-main', 'xray-bridge'];
const OPTIONS = { maxTimeMS: TIMEOUT_MS, timeoutMS: TIMEOUT_MS };
function token(value) { return typeof value === 'string' && TOKEN.test(value); }
function validIdentity(identity) {
    return exact(identity, ['machineId', 'sshHostKeySha256'])
        && /^[a-f0-9]{32}$/.test(identity.machineId) && /^[a-f0-9]{64}$/.test(identity.sshHostKeySha256);
}
function validEnrollment(value) {
    return exact(value, ENROLLMENT_KEYS) && ID.test(value.nodeId) && PROFILES.includes(value.targetProfile)
        && validIdentity(value.nodeIdentity) && UUID.test(value.ownerGeneration)
        && UUID.test(value.predecessorGeneration) && UUID.test(value.bootId);
}
function enrollmentProjection(row) {
    return Object.fromEntries(ENROLLMENT_KEYS.map(key => [key, row[key]]));
}
function validExpected(value) {
    return exact(value, EXPECTED_KEYS) && Object.isFrozen(value)
        && value.executionContext === PROD.hostIdentity && ID.test(value.operationId) && ID.test(value.nodeId)
        && /^sha256:[a-f0-9]{64}$/.test(value.candidateHash) && token(value.backupId)
        && token(value.owner) && PROFILES.includes(value.targetProfile)
        && Number.isSafeInteger(value.attempt) && value.attempt > 0 && UUID.test(value.generation)
        && Number.isSafeInteger(value.topologyRevision) && value.topologyRevision >= 0
        && Number.isSafeInteger(value.priorDeployedRevision) && value.priorDeployedRevision >= 0;
}
function recordProjection(row) {
    return freeze(Object.fromEntries(RECORD_KEYS.map(key => [key, key === 'commandIds' ? { ...row[key] } : row[key]])));
}

// DORMANT: no routes, host/worker wiring, flag or production authority implementation.
// The trusted authority MUST hold old-PID/dispatch/bootstrap/alias exclusion across
// the awaited callback, including commit + primary-majority readback. A DB row,
// local shutdown, or request-provided proof is never a replacement for that scope.
// That exclusion MUST also be sustained externally across the subsequent remote
// lifecycle; this store owns only validation/commit/readback, never that lifetime.
class TopologyExecutionBindingStore {
    #models;
    #authority;
    constructor({ executionContext, withVerifiedAuthority, Operation, Lock, Owner, Enrollment, Binding } = {}) {
        if (!matchesTopologyExecutionContext(executionContext, PROD)) {
            throw new TypeError('Exact server-owned production context required');
        }
        if (typeof withVerifiedAuthority !== 'function') throw new TypeError('Scoped external authority required');
        const models = { Operation, Lock, Owner, Enrollment, Binding };
        if (Object.values(models).some(model => !model?.db || typeof model.findOne !== 'function')
            || new Set(Object.values(models).map(model => model.db)).size !== 1) {
            throw new TypeError('Binding store requires actual models on one Mongo connection');
        }
        const client = Binding.db.getClient();
        if (client.options.directConnection || client.topology?.description?.type !== 'ReplicaSetWithPrimary') {
            throw new TypeError('Binding store requires a connected discovered replica set with a primary');
        }
        this.#models = Object.freeze(models);
        this.#authority = withVerifiedAuthority;
    }

    async #indexes() {
        const requirements = {
            Owner: [{ node: 1, profile: 1 }], Lock: [{ node: 1 }],
            Enrollment: [{ nodeId: 1, targetProfile: 1 }, { 'nodeIdentity.machineId': 1, targetProfile: 1 },
                { 'nodeIdentity.sshHostKeySha256': 1, targetProfile: 1 }],
            Binding: [{ operationId: 1, nodeId: 1, targetProfile: 1 }, { enrollmentId: 1 }, { attemptId: 1 }, { commandTokens: 1 }],
        };
        for (const [name, keys] of Object.entries(requirements)) {
            let indexes;
            try { indexes = await this.#models[name].collection.indexes({ ...OPTIONS, readPreference: 'primary' }); }
            catch { throw failure('INDEX_REQUIRED'); }
            if (keys.some(key => !indexes.some(index => isDeepStrictEqual(index.key, key)
                && index.unique === true && !index.sparse && !index.partialFilterExpression))) throw failure('INDEX_REQUIRED');
        }
    }

    #ownerFilter(enrollment) {
        return { executionContext: { ...PROD }, node: enrollment.nodeId, profile: enrollment.targetProfile,
            nodeIdentity: enrollment.nodeIdentity, owner: 'topology', generation: enrollment.ownerGeneration,
            'adoptionReceipt.toGeneration': enrollment.ownerGeneration, originalSnapshot: { $exists: true },
            handbackReceipt: { $exists: false } };
    }
    #operationFilter(expected, now) {
        return { _id: expected.operationId, ...topologyOperationClaimBindingFilter(PROD),
            topologyRevision: expected.topologyRevision, priorDeployedRevision: expected.priorDeployedRevision,
            heldTopologyAdmission: true, leaseOwner: expected.owner, attempts: expected.attempt,
            leaseUntil: { $gt: now }, status: { $in: ['preparing', 'committing', 'rolling_back'] },
            pppWait: { $exists: false }, nodes: { $elemMatch: { node: expected.nodeId,
                targetProfile: expected.targetProfile, candidateHash: expected.candidateHash.slice(7) } } };
    }
    #lockFilter(expected, now) {
        return { node: expected.nodeId, owner: expected.owner, operationId: expected.operationId,
            generation: expected.generation, remoteUncertain: true, leaseUntil: { $gt: now } };
    }
    #majority(Model, filter, deadline = Date.now() + TIMEOUT_MS) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw failure('UNCONFIRMED');
        return Model.findOne(filter).read('primary').readConcern('majority')
            .setOptions({ maxTimeMS: remaining, timeoutMS: remaining }).lean();
    }

    async #scope(action, enrollment, expected, work) {
        const challenge = freeze({ action, nonce: randomUUID(), executionContext: { ...PROD },
            enrollment: structuredClone(enrollment), ...(expected ? { expected: { ...expected } } : {}) });
        let open = true, invoked = false, finished = false, pending, result;
        const ensureOpen = () => { if (!open) throw failure(); };
        const callback = proof => {
            ensureOpen();
            if (invoked) throw failure();
            invoked = true;
            pending = (async () => {
                if (proof?.authority !== 'external-execution-maintenance-v1' || proof.status !== 'verified'
                    || !isDeepStrictEqual(proof.challenge, challenge) || !UUID.test(proof.proofId) || !UUID.test(proof.maintenanceId)
                    || proof.maintenance !== 'held' || proof.allWriters !== 'drained' || proof.bootstrapWriters !== 'excluded'
                    || proof.owner !== 'topology' || !isDeepStrictEqual(proof.physicalIdentity, enrollment.nodeIdentity)
                    || !isDeepStrictEqual(proof.predecessor, { generation: enrollment.predecessorGeneration,
                        bootId: enrollment.bootId, status: 'pre-enrolled' })
                    || proof.oldBackend?.processTree !== 'stopped' || proof.oldBackend?.dispatch !== 'disabled'
                    || !token(proof.oldBackend.instanceId) || !Number.isSafeInteger(proof.oldBackend.pid)
                    || proof.oldBackend.pid < 1 || typeof proof.oldBackend.processStartTime !== 'string'
                    || !proof.oldBackend.processStartTime) throw failure();
                // Copy authority metadata before awaits; never retain its mutable proof object.
                const receipt = freeze({ proofId: proof.proofId, maintenanceId: proof.maintenanceId });
                result = await work(receipt, ensureOpen);
                ensureOpen();
                finished = true;
                return result;
            })();
            pending.catch(() => {}); // A broken authority must not leak unhandled work.
            return pending;
        };
        try {
            await this.#authority(challenge, callback);
            if (!invoked || !finished) throw failure();
            return result;
        } finally {
            open = false;
            if (pending) await pending.catch(() => {});
        }
    }

    async #transaction(work, confirm, ensureOpen) {
        const session = await this.#models.Binding.db.startSession();
        let commitAttempted = false;
        try {
            session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' },
                readPreference: 'primary', maxCommitTimeMS: TIMEOUT_MS });
            await work(session);
            ensureOpen();
            commitAttempted = true;
            try { await session.commitTransaction({ timeoutMS: TIMEOUT_MS }); }
            catch (error) {
                // One bounded confirmation, never retry the transaction or mint new IDs.
                if (!error.hasErrorLabel?.('UnknownTransactionCommitResult')) throw error;
            }
            ensureOpen();
            const result = await confirm(Date.now() + TIMEOUT_MS);
            ensureOpen();
            return result;
        } catch (error) {
            if (!commitAttempted && session.inTransaction()) await session.abortTransaction({ timeoutMS: TIMEOUT_MS }).catch(() => {});
            if (error?.code === 11000) throw failure('CONFLICT');
            if (error?.code?.startsWith?.('TOPOLOGY_EXECUTION_BINDING_')) throw error;
            throw failure(commitAttempted ? 'UNCONFIRMED' : 'UNPROVEN');
        } finally { await session.endSession(); }
    }
    async #cas(Model, filter, nonce, session) {
        const result = await Model.updateOne(filter, { $set: { executionBindingCheck: nonce } },
            { session, ...OPTIONS, runValidators: true });
        if (result.matchedCount !== 1) throw failure();
    }

    async preEnroll(input) {
        if (!validEnrollment(input)) throw failure();
        const enrollment = freeze(structuredClone(input));
        await this.#indexes();
        const row = { _id: randomUUID(), executionContext: PROD.hostIdentity, ...enrollment };
        return this.#scope('enroll', enrollment, null, async (receipt, ensureOpen) => {
            const nonce = randomUUID();
            const filter = this.#ownerFilter(enrollment);
            return this.#transaction(async session => {
                ensureOpen();
                await this.#cas(this.#models.Owner, filter, nonce, session);
                await this.#models.Enrollment.create([{ ...row, ...receipt }], { session, ...OPTIONS });
            }, async deadline => {
                const confirmed = await this.#majority(this.#models.Enrollment, { ...row, ...receipt }, deadline);
                const owner = await this.#majority(this.#models.Owner, { ...filter, executionBindingCheck: nonce }, deadline);
                if (!confirmed || !owner || !isDeepStrictEqual(confirmed, { ...row, ...receipt })) throw failure('UNCONFIRMED');
                return freeze({ enrollmentId: confirmed._id, ...enrollmentProjection(confirmed) });
            }, ensureOpen);
        });
    }

    async #enrollment(expected) {
        const row = await this.#majority(this.#models.Enrollment, { executionContext: PROD.hostIdentity,
            nodeId: expected.nodeId, targetProfile: expected.targetProfile });
        if (!exact(row, ENROLLMENT_ROW_KEYS) || !UUID.test(row._id)
            || !UUID.test(row.proofId) || !UUID.test(row.maintenanceId)
            || !validEnrollment(enrollmentProjection(row))) throw failure();
        return freeze(structuredClone(row));
    }
    #checkRow(row, enrollment, expected) {
        if (!exact(row, BINDING_ROW_KEYS) || !UUID.test(row.proofId) || !UUID.test(row.maintenanceId)
            || row.enrollmentId !== enrollment._id || row.executionContext !== PROD.hostIdentity
            || !isDeepStrictEqual(enrollmentProjection(row), enrollmentProjection(enrollment))
            || EXPECTED_KEYS.some(key => row[key] !== expected[key]) || !UUID.test(row._id) || !UUID.test(row.attemptId)
            || row.generation === row.predecessorGeneration || !exact(row.commandIds, COMMANDS)
            || !COMMANDS.every(key => UUID.test(row.commandIds[key]))
            || new Set(Object.values(row.commandIds)).size !== COMMANDS.length
            || !isDeepStrictEqual(row.commandTokens, COMMANDS.map(key => row.commandIds[key]))) throw failure();
    }
    async #checkOperation(expected, session) {
        const row = await this.#models.Operation.findOne(this.#operationFilter(expected, new Date()))
            .session(session).setOptions(OPTIONS).lean();
        const nodes = row?.nodes?.filter(node => String(node.node) === expected.nodeId);
        if (nodes?.length !== 1) throw failure();
        const node = nodes[0];
        if ((node.role === 'portal' ? 'xray-main' : ['relay', 'bridge'].includes(node.role) ? 'xray-bridge' : null) !== expected.targetProfile
            || !['', expected.backupId].includes(node.backupId)) throw failure();
        try { projectCanonicalXrayCandidate(node.candidate, expected.candidateHash.slice(7)); }
        catch { throw failure(); }
        const backupId = `topology-${createHash('sha256').update([
            expected.operationId, expected.nodeId, expected.candidateHash, expected.targetProfile,
        ].join('\0')).digest('hex')}`;
        if (backupId !== expected.backupId) throw failure();
    }
    async #binding(action, input, work) {
        if (!validExpected(input)) throw failure();
        const expected = freeze({ ...input });
        await this.#indexes();
        const enrollment = await this.#enrollment(expected);
        return this.#scope(action, enrollmentProjection(enrollment), expected, async (receipt, ensureOpen) => {
            if (receipt.maintenanceId !== enrollment.maintenanceId) throw failure();
            const nonce = randomUUID();
            let row = action === 'create' ? { ...expected, ...enrollmentProjection(enrollment),
                _id: randomUUID(), enrollmentId: enrollment._id, attemptId: randomUUID(), ...receipt,
                commandIds: Object.fromEntries(COMMANDS.map(command => [command, randomUUID()])) } : null;
            if (row) row.commandTokens = COMMANDS.map(command => row.commandIds[command]);
            const ownerFilter = this.#ownerFilter(enrollment);
            const check = () => this.#transaction(async session => {
                ensureOpen();
                await this.#checkOperation(expected, session);
                await this.#cas(this.#models.Operation, this.#operationFilter(expected, new Date()), nonce, session);
                await this.#cas(this.#models.Lock, this.#lockFilter(expected, new Date()), nonce, session);
                await this.#cas(this.#models.Owner, ownerFilter, nonce, session);
                const enrolled = await this.#models.Enrollment.findOne({ _id: enrollment._id }).session(session).setOptions(OPTIONS).lean();
                if (!isDeepStrictEqual(enrolled, enrollment)) throw failure();
                if (action === 'create') {
                    this.#checkRow(row, enrollment, expected);
                    await this.#models.Binding.create([row], { session, ...OPTIONS });
                } else {
                    row = await this.#models.Binding.findOne({ enrollmentId: enrollment._id }).session(session).setOptions(OPTIONS).lean();
                    this.#checkRow(row, enrollment, expected);
                    if (row.maintenanceId !== receipt.maintenanceId) throw failure();
                }
            }, async deadline => {
                const confirmed = await this.#majority(this.#models.Binding, { _id: row._id }, deadline);
                this.#checkRow(confirmed, enrollment, expected);
                if (!isDeepStrictEqual(confirmed, row)) throw failure('UNCONFIRMED');
                for (const [Model, filter] of [[this.#models.Operation, this.#operationFilter(expected, new Date())],
                    [this.#models.Lock, this.#lockFilter(expected, new Date())], [this.#models.Owner, ownerFilter]]) {
                    if (!await this.#majority(Model, { ...filter, executionBindingCheck: nonce }, deadline)) throw failure('UNCONFIRMED');
                }
                return recordProjection(confirmed);
            }, ensureOpen);
            const record = await check();
            if (!work) return record;
            const assertCurrent = async () => {
                ensureOpen();
                if (!isDeepStrictEqual(await check(), record)) throw failure();
                ensureOpen();
            };
            ensureOpen();
            const result = await work(record, assertCurrent);
            await assertCurrent();
            return result;
        });
    }
    // No caller-selected attempt/command/predecessor IDs, no update/adopt/release API.
    async createBinding(expected) { return this.#binding('create', expected); }
    async readVerified(expected) { return this.#binding('read', expected); }
    // Hold external exclusion through close, fresh status and final exact DB readback.
    async withVerifiedBinding(expected, work) {
        if (typeof work !== 'function') throw failure();
        return this.#binding('terminal', expected, work);
    }
}
module.exports = { TopologyExecutionBindingStore };
