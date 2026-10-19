'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { Types: { ObjectId } } = require('mongoose');
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
const NUMBER_TYPES = ['double', 'int', 'long'];
// Aggregation $type checks the field itself, unlike query $type/equality which
// can match array elements. $literal also prevents values becoming expressions.
function exactFields(filter, fields) {
    const checks = Object.entries(fields).flatMap(([field, [type, ...value]]) => [
        { $in: [{ $type: `$${field}` }, Array.isArray(type) ? type : [type]] },
        ...(value.length ? [{ $eq: [`$${field}`, { $literal: value[0] }] }] : []),
    ]);
    return { ...filter, $expr: { $and: [...(filter.$expr ? [filter.$expr] : []), ...checks] } };
}
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
        return exactFields({ executionContext: { ...PROD }, node: enrollment.nodeId, profile: enrollment.targetProfile,
            nodeIdentity: enrollment.nodeIdentity, owner: 'topology', generation: enrollment.ownerGeneration,
            'adoptionReceipt.toGeneration': enrollment.ownerGeneration, originalSnapshot: { $exists: true },
            handbackReceipt: { $exists: false } }, {
            executionContext: ['object', { ...PROD }], node: ['objectId', new ObjectId(enrollment.nodeId)],
            profile: ['string', enrollment.targetProfile], nodeIdentity: ['object', enrollment.nodeIdentity],
            owner: ['string', 'topology'], generation: ['string', enrollment.ownerGeneration],
            originalSnapshot: ['object'], adoptionReceipt: ['object'],
            'adoptionReceipt.toGeneration': ['string', enrollment.ownerGeneration],
        });
    }
    #ownerEvidence(row) {
        const snapshot = row?.originalSnapshot;
        const receipt = row?.adoptionReceipt;
        const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
        const uuid = value => typeof value === 'string' && UUID.test(value);
        const nonempty = value => typeof value === 'string' && value.trim().length > 0;
        if (!exact(snapshot, ['configSha256', 'unitSha256', 'serviceActive', 'serviceEnabled'])
            || !digest(snapshot.configSha256) || !digest(snapshot.unitSha256)
            || !['active', 'inactive'].includes(snapshot.serviceActive)
            || !['enabled', 'disabled', 'masked'].includes(snapshot.serviceEnabled)
            || !exact(receipt, ['proofId', 'maintenanceId', 'fromGeneration', 'toGeneration',
                'oldBackendInstanceId', 'oldPid', 'oldProcessStartTime', 'verifiedAt'])
            || !uuid(receipt.proofId) || !uuid(receipt.maintenanceId) || !uuid(receipt.fromGeneration)
            || !uuid(receipt.toGeneration) || receipt.toGeneration !== row.generation
            || receipt.fromGeneration === receipt.toGeneration || !nonempty(receipt.oldBackendInstanceId)
            || !Number.isSafeInteger(receipt.oldPid) || receipt.oldPid < 1 || !nonempty(receipt.oldProcessStartTime)
            || !(receipt.verifiedAt instanceof Date) || !Number.isFinite(receipt.verifiedAt.getTime())
            || receipt.verifiedAt.getTime() > Date.now()) throw failure();
        return { originalSnapshot: snapshot, adoptionReceipt: receipt };
    }
    async #ownerInTransaction(filter, session) {
        const row = await this.#models.Owner.findOne(filter).session(session).setOptions(OPTIONS).lean();
        return this.#ownerEvidence(row);
    }
    #operationFilter(expected, now) {
        return exactFields({ _id: expected.operationId, ...topologyOperationClaimBindingFilter(PROD),
            topologyRevision: expected.topologyRevision, priorDeployedRevision: expected.priorDeployedRevision,
            heldTopologyAdmission: true, leaseOwner: expected.owner, attempts: expected.attempt,
            leaseUntil: { $gt: now }, status: { $in: ['preparing', 'committing', 'rolling_back'] },
            pppWait: { $exists: false }, nodes: { $elemMatch: { node: expected.nodeId,
                targetProfile: expected.targetProfile, candidateHash: expected.candidateHash.slice(7) } } }, {
            _id: ['objectId', new ObjectId(expected.operationId)], idempotencyKey: ['string'],
            topologyRevision: [NUMBER_TYPES, expected.topologyRevision],
            priorDeployedRevision: [NUMBER_TYPES, expected.priorDeployedRevision],
            heldTopologyAdmission: ['bool', true], leaseOwner: ['string', expected.owner],
            attempts: [NUMBER_TYPES, expected.attempt], leaseUntil: ['date'], status: ['string'], nodes: ['array'],
        });
    }
    #lockFilter(expected, now) {
        return exactFields({ node: expected.nodeId, owner: expected.owner, operationId: expected.operationId,
            generation: expected.generation, remoteUncertain: true, leaseUntil: { $gt: now } }, {
            node: ['objectId', new ObjectId(expected.nodeId)], owner: ['string', expected.owner],
            operationId: ['string', expected.operationId], generation: ['string', expected.generation],
            remoteUncertain: ['bool', true], leaseUntil: ['date'],
        });
    }
    async #majority(Model, filter, deadline = Date.now() + TIMEOUT_MS) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw failure('UNCONFIRMED');
        const exactFilter = Object.hasOwn(filter, 'executionBindingCheck')
            ? exactFields(filter, { executionBindingCheck: ['string', filter.executionBindingCheck] }) : filter;
        const row = await Model.findOne(exactFilter).read('primary').readConcern('majority')
            .setOptions({ maxTimeMS: remaining, timeoutMS: remaining }).lean();
        if (Date.now() >= deadline) throw failure('UNCONFIRMED');
        return row;
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
            let ownerEvidence;
            return this.#transaction(async session => {
                ensureOpen();
                ownerEvidence = await this.#ownerInTransaction(filter, session);
                await this.#cas(this.#models.Owner, filter, nonce, session);
                // Model.create/save drops timeoutMS in Mongoose 8. insertMany validates
                // the schema and forwards the bounded driver options unchanged.
                await this.#models.Enrollment.insertMany([{ ...row, ...receipt }], { session, ...OPTIONS });
            }, async deadline => {
                const confirmed = await this.#majority(this.#models.Enrollment, { ...row, ...receipt }, deadline);
                const owner = await this.#majority(this.#models.Owner, { ...filter, executionBindingCheck: nonce }, deadline);
                if (!confirmed || !owner || !isDeepStrictEqual(confirmed, { ...row, ...receipt })
                    || !isDeepStrictEqual(this.#ownerEvidence(owner), ownerEvidence)) throw failure('UNCONFIRMED');
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
        this.#checkOperationRow(row, expected);
    }
    #checkOperationRow(row, expected) {
        const nodes = Array.isArray(row?.nodes) ? row.nodes.filter(node =>
            node?.node instanceof ObjectId && node.node.toHexString() === expected.nodeId) : [];
        if (nodes.length !== 1) throw failure();
        const node = nodes[0];
        if (node.targetProfile !== expected.targetProfile || node.candidateHash !== expected.candidateHash.slice(7)
            || (node.role === 'portal' ? 'xray-main' : ['relay', 'bridge'].includes(node.role) ? 'xray-bridge' : null) !== expected.targetProfile
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
        let validUntil = 0;
        const assertFresh = () => {
            if (Date.now() >= validUntil) throw failure('UNCONFIRMED');
        };
        const result = await this.#scope(action, enrollmentProjection(enrollment), expected, async (receipt, ensureOpen) => {
            if (receipt.maintenanceId !== enrollment.maintenanceId) throw failure();
            const nonce = randomUUID();
            let row = action === 'create' ? { ...expected, ...enrollmentProjection(enrollment),
                _id: randomUUID(), enrollmentId: enrollment._id, attemptId: randomUUID(), ...receipt,
                commandIds: Object.fromEntries(COMMANDS.map(command => [command, randomUUID()])) } : null;
            if (row) row.commandTokens = COMMANDS.map(command => row.commandIds[command]);
            const ownerFilter = this.#ownerFilter(enrollment);
            const check = async () => {
                let ownerEvidence;
                const confirmedRecord = await this.#transaction(async session => {
                    ensureOpen();
                    await this.#checkOperation(expected, session);
                    await this.#cas(this.#models.Operation, this.#operationFilter(expected, new Date()), nonce, session);
                    await this.#cas(this.#models.Lock, this.#lockFilter(expected, new Date()), nonce, session);
                    ownerEvidence = await this.#ownerInTransaction(ownerFilter, session);
                    await this.#cas(this.#models.Owner, ownerFilter, nonce, session);
                    const enrolled = await this.#models.Enrollment.findOne({ _id: enrollment._id }).session(session).setOptions(OPTIONS).lean();
                    if (!isDeepStrictEqual(enrolled, enrollment)) throw failure();
                    if (action === 'create') {
                        this.#checkRow(row, enrollment, expected);
                        await this.#models.Binding.insertMany([row], { session, ...OPTIONS });
                    } else {
                        row = await this.#models.Binding.findOne({ enrollmentId: enrollment._id }).session(session).setOptions(OPTIONS).lean();
                        this.#checkRow(row, enrollment, expected);
                        if (row.maintenanceId !== receipt.maintenanceId) throw failure();
                    }
                }, async deadline => {
                    const confirmed = await this.#majority(this.#models.Binding, { _id: row._id }, deadline);
                    this.#checkRow(confirmed, enrollment, expected);
                    if (!isDeepStrictEqual(confirmed, row)) throw failure('UNCONFIRMED');
                    // Each filter is built immediately before its read, not before
                    // another awaited confirmation. Retain both exact expiration dates
                    // and bound all remaining readback by the earliest observed lease.
                    for (const [Model, filter] of [[this.#models.Operation, () => this.#operationFilter(expected, new Date())],
                        [this.#models.Lock, () => this.#lockFilter(expected, new Date())], [this.#models.Owner, () => ownerFilter]]) {
                        const current = await this.#majority(Model, { ...filter(), executionBindingCheck: nonce }, deadline);
                        if (!current) throw failure('UNCONFIRMED');
                        if (Model === this.#models.Owner) {
                            if (!isDeepStrictEqual(this.#ownerEvidence(current), ownerEvidence)) throw failure('UNCONFIRMED');
                        } else {
                            if (Model === this.#models.Operation) this.#checkOperationRow(current, expected);
                            if (!(current.leaseUntil instanceof Date) || !Number.isFinite(current.leaseUntil.getTime())) throw failure('UNCONFIRMED');
                            deadline = Math.min(deadline, current.leaseUntil.getTime());
                        }
                    }
                    validUntil = deadline;
                    assertFresh();
                    return recordProjection(confirmed);
                }, ensureOpen);
                // Session cleanup is awaited by #transaction's finally block.
                assertFresh();
                return confirmedRecord;
            };
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
        // The authority itself can await cleanup after its callback completes.
        assertFresh();
        return result;
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
