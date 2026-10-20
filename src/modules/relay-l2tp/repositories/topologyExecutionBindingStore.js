'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { isIP } = require('node:net');
const { isDeepStrictEqual } = require('node:util');
const { Types: { ObjectId } } = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { topologyOperationClaimBindingFilter } = require('../domain/topologyOperationClaimBinding');
const { projectCanonicalXrayCandidate } = require('../services/topologyXrayCandidate');
const { UUID, ID, TOKEN, COMMANDS, EXPECTED_KEYS, RECORD_KEYS, exact, freeze, failure, validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const TIMEOUT_MS = 5000;
const ENROLLMENT_KEYS = ['nodeId', 'targetProfile', 'endpoint', 'nodeIdentity', 'ownerGeneration', 'predecessorGeneration', 'bootId'];
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
function matches(value, pattern) { return typeof value === 'string' && pattern.test(value); }
function validEndpoint(endpoint) {
    return exact(endpoint, ['ip', 'port', 'username'])
        && typeof endpoint.ip === 'string' && isIP(endpoint.ip) !== 0
        && Number.isSafeInteger(endpoint.port) && endpoint.port >= 1 && endpoint.port <= 65535
        && typeof endpoint.username === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}[$]?$/.test(endpoint.username);
}
function validIdentity(identity) {
    return exact(identity, ['machineId', 'sshHostKeySha256'])
        && matches(identity.machineId, /^[a-f0-9]{32}$/) && matches(identity.sshHostKeySha256, /^[a-f0-9]{64}$/);
}
function validEnrollment(value) {
    return exact(value, ENROLLMENT_KEYS) && matches(value.nodeId, ID) && PROFILES.includes(value.targetProfile)
        && validEndpoint(value.endpoint) && validIdentity(value.nodeIdentity) && matches(value.ownerGeneration, UUID)
        && (value.predecessorGeneration === 'none' || matches(value.predecessorGeneration, UUID)) && matches(value.bootId, UUID);
}
function emptyHead(enrollment) {
    return { generation: 'none', bootId: enrollment.bootId, status: 'empty', protocolVersion: 2,
        journal: 'absent', legacyState: 'absent', writers: 'excluded' };
}
function enrollmentProjection(row) {
    return Object.fromEntries(ENROLLMENT_KEYS.map(key => [key, row[key]]));
}
function validExpected(value) {
    return exact(value, EXPECTED_KEYS) && Object.isFrozen(value)
        && value.executionContext === PROD.hostIdentity && matches(value.operationId, ID) && matches(value.nodeId, ID)
        && matches(value.candidateHash, /^sha256:[a-f0-9]{64}$/) && token(value.backupId)
        && token(value.owner) && PROFILES.includes(value.targetProfile)
        && Number.isSafeInteger(value.attempt) && value.attempt > 0 && matches(value.generation, UUID)
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
    #held = new AsyncLocalStorage();
    constructor({ executionContext, withVerifiedAuthority, Operation, Lock, Owner, Enrollment, Binding, HyNode } = {}) {
        if (!matchesTopologyExecutionContext(executionContext, PROD)) {
            throw new TypeError('Exact server-owned production context required');
        }
        if (typeof withVerifiedAuthority !== 'function') throw new TypeError('Scoped external authority required');
        const models = { Operation, Lock, Owner, Enrollment, Binding, HyNode };
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
                { 'nodeIdentity.sshHostKeySha256': 1, targetProfile: 1 },
                { 'nodeIdentity.machineId': 1 }, { 'nodeIdentity.sshHostKeySha256': 1 },
                { 'endpoint.ip': 1, 'endpoint.port': 1 }],
            Binding: [{ operationId: 1, nodeId: 1, targetProfile: 1 }, { enrollmentId: 1, predecessorGeneration: 1 }, { enrollmentId: 1, generation: 1 }, { attemptId: 1 }, { commandTokens: 1 }],
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
    #nodeFilter(enrollment) {
        return exactFields({ _id: enrollment.nodeId, active: true, type: 'xray',
            cascadeRole: { $in: enrollment.targetProfile === 'xray-main' ? ['portal'] : ['relay', 'bridge'] } }, {
            _id: ['objectId', new ObjectId(enrollment.nodeId)], active: ['bool', true], type: ['string', 'xray'],
            cascadeRole: ['string'], ssh: ['object'], ip: ['string', enrollment.endpoint.ip],
            'ssh.port': [NUMBER_TYPES, enrollment.endpoint.port], 'ssh.username': ['string', enrollment.endpoint.username],
        });
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
        const query = Model.findOne(exactFilter).read('primary').readConcern('majority')
            .setOptions({ maxTimeMS: remaining, timeoutMS: remaining });
        if (Model === this.#models.HyNode) query.select('_id ip type active cascadeRole ssh.port ssh.username');
        const row = await query.lean();
        if (Date.now() >= deadline) throw failure('UNCONFIRMED');
        return row;
    }

    async #scope(action, enrollment, expected, work, predecessor = null) {
        const challenge = freeze({ action, nonce: randomUUID(), executionContext: { ...PROD },
            enrollment: structuredClone(enrollment), ...(expected ? { expected: { ...expected } } : {}),
            ...(predecessor ? { predecessor: { bindingId: predecessor._id, binding: recordProjection(predecessor) } } : {}) });
        let open = true, invoked = false, finished = false, pending, result;
        const ensureOpen = () => { if (!open) throw failure(); };
        const callback = proof => {
            ensureOpen();
            if (invoked) throw failure();
            invoked = true;
            pending = (async () => {
                if (proof?.authority !== 'external-execution-maintenance-v1' || proof.status !== 'verified'
                    || !isDeepStrictEqual(proof.challenge, challenge) || !matches(proof.proofId, UUID) || !matches(proof.maintenanceId, UUID)
                    || proof.maintenance !== 'held' || proof.allWriters !== 'drained' || proof.bootstrapWriters !== 'excluded'
                    || proof.owner !== 'topology' || !isDeepStrictEqual(proof.physicalIdentity, enrollment.nodeIdentity)
                    || !exact(proof.connectionAttestation, ['authority', 'endpoint', 'physicalIdentity', 'maintenanceId', 'aliases', 'hostKeyDigest', 'endpointReassignment'])
                    || proof.connectionAttestation.authority !== 'server-physical-ssh-endpoint-v1'
                    || proof.connectionAttestation.hostKeyDigest !== 'raw-ssh-public-key-sha256'
                    || proof.connectionAttestation.aliases !== 'excluded'
                    || proof.connectionAttestation.endpointReassignment !== 'excluded'
                    || proof.connectionAttestation.maintenanceId !== proof.maintenanceId
                    || !isDeepStrictEqual(proof.connectionAttestation.endpoint, enrollment.endpoint)
                    || !isDeepStrictEqual(proof.connectionAttestation.physicalIdentity, enrollment.nodeIdentity)
                    || (predecessor ? !exact(proof.predecessor, ['bindingId', 'generation', 'headGeneration', 'bootId', 'status', 'receipt'])
                        || proof.predecessor.bindingId !== predecessor._id
                        || proof.predecessor.generation !== predecessor.generation || proof.predecessor.bootId !== predecessor.bootId
                        || !(action === 'successor' ? [predecessor.generation] : [predecessor.generation, expected.generation])
                            .includes(proof.predecessor.headGeneration)
                        || proof.predecessor.status !== 'terminal' || !validTerminalReceipt(proof.predecessor.receipt, predecessor)
                        : !isDeepStrictEqual(proof.predecessor, action === 'enroll' && enrollment.predecessorGeneration === 'none'
                        ? emptyHead(enrollment) : { generation: enrollment.predecessorGeneration,
                            bootId: enrollment.bootId, status: 'pre-enrolled' }))
                    || proof.oldBackend?.processTree !== 'stopped' || proof.oldBackend?.dispatch !== 'disabled'
                    || !token(proof.oldBackend.instanceId) || !Number.isSafeInteger(proof.oldBackend.pid)
                    || proof.oldBackend.pid < 1 || typeof proof.oldBackend.processStartTime !== 'string'
                    || !proof.oldBackend.processStartTime) throw failure();
                // Copy authority metadata before awaits; never retain its mutable proof object.
                const receipt = freeze({ proofId: proof.proofId, maintenanceId: proof.maintenanceId,
                    ...(predecessor ? { predecessorBindingId: predecessor._id,
                        predecessorReceipt: structuredClone(proof.predecessor.receipt) } : {}),
                    ...(action === 'enroll' && enrollment.predecessorGeneration === 'none'
                        ? { provisioningReceipt: structuredClone(proof.predecessor) } : {}) });
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
            const nodeFilter = this.#nodeFilter(enrollment);
            let ownerEvidence;
            return this.#transaction(async session => {
                ensureOpen();
                ownerEvidence = await this.#ownerInTransaction(filter, session);
                await this.#cas(this.#models.Owner, filter, nonce, session);
                await this.#cas(this.#models.HyNode, nodeFilter, nonce, session);
                // Model.create/save drops timeoutMS in Mongoose 8. insertMany validates
                // the schema and forwards the bounded driver options unchanged.
                await this.#models.Enrollment.insertMany([{ ...row, ...receipt }], { session, ...OPTIONS });
            }, async deadline => {
                const confirmed = await this.#majority(this.#models.Enrollment, { ...row, ...receipt }, deadline);
                const owner = await this.#majority(this.#models.Owner, { ...filter, executionBindingCheck: nonce }, deadline);
                const node = await this.#majority(this.#models.HyNode, { ...nodeFilter, executionBindingCheck: nonce }, deadline);
                if (!confirmed || !owner || !node || !isDeepStrictEqual(confirmed, { ...row, ...receipt })
                    || !isDeepStrictEqual(this.#ownerEvidence(owner), ownerEvidence)) throw failure('UNCONFIRMED');
                return freeze({ enrollmentId: confirmed._id, ...enrollmentProjection(confirmed) });
            }, ensureOpen);
        });
    }

    async #enrollment(expected) {
        const row = await this.#majority(this.#models.Enrollment, { executionContext: PROD.hostIdentity,
            nodeId: expected.nodeId, targetProfile: expected.targetProfile });
        if (!exact(row, [...ENROLLMENT_ROW_KEYS, ...(row?.predecessorGeneration === 'none' ? ['provisioningReceipt'] : [])])
            || (row.predecessorGeneration === 'none' && !isDeepStrictEqual(row.provisioningReceipt, emptyHead(row)))
            || !matches(row._id, UUID)
            || !matches(row.proofId, UUID) || !matches(row.maintenanceId, UUID)
            || !validEnrollment(enrollmentProjection(row))) throw failure();
        return freeze(structuredClone(row));
    }
    #checkRow(row, enrollment, expected) {
        if (!exact(row, [...BINDING_ROW_KEYS, ...(row?.predecessorBindingId ? ['predecessorBindingId', 'predecessorReceipt'] : [])])
            || !matches(row.proofId, UUID) || !matches(row.maintenanceId, UUID)
            || row.enrollmentId !== enrollment._id || row.executionContext !== PROD.hostIdentity
            || !isDeepStrictEqual(enrollmentProjection(row), { ...enrollmentProjection(enrollment),
                ...(row.predecessorBindingId ? { predecessorGeneration: row.predecessorGeneration } : {}) })
            || (row.predecessorBindingId && (!matches(row.predecessorBindingId, UUID)
                || !matches(row.predecessorGeneration, UUID)
                || !validTerminalReceipt(row.predecessorReceipt, { ...row.predecessorReceipt,
                    commandIds: { close: row.predecessorReceipt?.commandId }, bootId: enrollment.bootId })
                || row.predecessorReceipt.generation !== row.predecessorGeneration
                || ['nodeId', 'targetProfile', 'executionContext'].some(key => row.predecessorReceipt[key] !== row[key])
                || row.predecessorReceipt.operationId === row.operationId))
            || EXPECTED_KEYS.some(key => row[key] !== expected[key]) || !matches(row._id, UUID) || !matches(row.attemptId, UUID)
            || row.generation === row.predecessorGeneration || !exact(row.commandIds, COMMANDS)
            || !COMMANDS.every(key => matches(row.commandIds[key], UUID))
            || new Set(Object.values(row.commandIds)).size !== COMMANDS.length
            || !isDeepStrictEqual(row.commandTokens, COMMANDS.map(key => row.commandIds[key]))) throw failure();
    }
    #terminalOperationFilter(prior) {
        return exactFields({ _id: prior.operationId, ...topologyOperationClaimBindingFilter(PROD),
            status: { $in: ['succeeded', 'failed'] }, heldTopologyAdmission: false, attempts: prior.attempt,
            topologyRevision: prior.topologyRevision, priorDeployedRevision: prior.priorDeployedRevision,
            nodes: { $elemMatch: { node: prior.nodeId, targetProfile: prior.targetProfile,
                candidateHash: prior.candidateHash.slice(7) } } }, {
            _id: ['objectId', new ObjectId(prior.operationId)], status: ['string'], heldTopologyAdmission: ['bool', false],
            attempts: [NUMBER_TYPES, prior.attempt],
            topologyRevision: [NUMBER_TYPES, prior.topologyRevision],
            priorDeployedRevision: [NUMBER_TYPES, prior.priorDeployedRevision], nodes: ['array'],
        });
    }
    async #predecessor(enrollment, id) {
        if (!id) return null;
        if (!matches(id, UUID)) throw failure();
        const prior = await this.#majority(this.#models.Binding, { _id: id });
        const expected = prior && freeze(Object.fromEntries(EXPECTED_KEYS.map(key => [key, prior[key]])));
        if (!validExpected(expected)) throw failure();
        this.#checkRow(prior, enrollment, expected);
        if (prior.maintenanceId !== enrollment.maintenanceId) throw failure();
        return freeze(structuredClone(prior));
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
    async #binding(action, input, work, predecessorId = null) {
        if (!validExpected(input)) throw failure();
        const expected = freeze({ ...input });
        await this.#indexes();
        const enrollment = await this.#enrollment(expected);
        const creating = action === 'create' || action === 'successor';
        const selected = creating ? null : await this.#majority(this.#models.Binding, { operationId: expected.operationId,
            nodeId: expected.nodeId, targetProfile: expected.targetProfile });
        if (selected) this.#checkRow(selected, enrollment, expected);
        if (!creating && !selected) throw failure();
        const predecessor = await this.#predecessor(enrollment, predecessorId || selected?.predecessorBindingId);
        if (action === 'successor' && !predecessor) throw failure();
        if (predecessor && (predecessor.operationId === expected.operationId
            || predecessor.generation === expected.generation)) throw failure();
        let validUntil = 0;
        const assertFresh = () => {
            if (Date.now() >= validUntil) throw failure('UNCONFIRMED');
        };
        const result = await this.#scope(action, enrollmentProjection(enrollment), expected, async (receipt, ensureOpen) => {
            if (receipt.maintenanceId !== enrollment.maintenanceId) throw failure();
            const nonce = randomUUID();
            let row = creating ? { ...expected, ...enrollmentProjection(enrollment),
                ...(predecessor ? { predecessorGeneration: predecessor.generation } : {}),
                _id: randomUUID(), enrollmentId: enrollment._id, attemptId: randomUUID(), ...receipt,
                commandIds: Object.fromEntries(COMMANDS.map(command => [command, randomUUID()])) } : null;
            if (row) row.commandTokens = COMMANDS.map(command => row.commandIds[command]);
            const ownerFilter = this.#ownerFilter(enrollment);
            const nodeFilter = this.#nodeFilter(enrollment);
            const check = async () => {
                let ownerEvidence;
                const confirmedRecord = await this.#transaction(async session => {
                    ensureOpen();
                    await this.#checkOperation(expected, session);
                    await this.#cas(this.#models.Operation, this.#operationFilter(expected, new Date()), nonce, session);
                    await this.#cas(this.#models.Lock, this.#lockFilter(expected, new Date()), nonce, session);
                    ownerEvidence = await this.#ownerInTransaction(ownerFilter, session);
                    await this.#cas(this.#models.Owner, ownerFilter, nonce, session);
                    await this.#cas(this.#models.HyNode, nodeFilter, nonce, session);
                    const enrolled = await this.#models.Enrollment.findOne({ _id: enrollment._id }).session(session).setOptions(OPTIONS).lean();
                    if (!isDeepStrictEqual(enrolled, enrollment)) throw failure();
                    if (predecessor) {
                        const previous = await this.#models.Binding.findOne({ _id: predecessor._id }).session(session).setOptions(OPTIONS).lean();
                        if (!isDeepStrictEqual(previous, predecessor)) throw failure();
                        const terminalFilter = this.#terminalOperationFilter(predecessor);
                        const terminalOperation = await this.#models.Operation.findOne(terminalFilter)
                            .session(session).setOptions(OPTIONS).lean();
                        this.#checkOperationRow(terminalOperation, predecessor);
                        await this.#cas(this.#models.Operation, terminalFilter, nonce, session);
                    }
                    if (creating) {
                        this.#checkRow(row, enrollment, expected);
                        await this.#models.Binding.insertMany([row], { session, ...OPTIONS });
                    } else {
                        row = await this.#models.Binding.findOne({ _id: selected._id }).session(session).setOptions(OPTIONS).lean();
                        this.#checkRow(row, enrollment, expected);
                        if (row.maintenanceId !== receipt.maintenanceId) throw failure();
                        if (predecessor && !isDeepStrictEqual(row.predecessorReceipt, receipt.predecessorReceipt)) throw failure();
                    }
                }, async deadline => {
                    if (predecessor) {
                        const previous = await this.#majority(this.#models.Binding, { _id: predecessor._id }, deadline);
                        const operation = await this.#majority(this.#models.Operation,
                            { ...this.#terminalOperationFilter(predecessor), executionBindingCheck: nonce }, deadline);
                        if (!isDeepStrictEqual(previous, predecessor) || !operation) throw failure('UNCONFIRMED');
                        this.#checkOperationRow(operation, predecessor);
                    }
                    const confirmed = await this.#majority(this.#models.Binding, { _id: row._id }, deadline);
                    this.#checkRow(confirmed, enrollment, expected);
                    if (!isDeepStrictEqual(confirmed, row)) throw failure('UNCONFIRMED');
                    // Each filter is built immediately before its read, not before
                    // another awaited confirmation. Retain both exact expiration dates
                    // and bound all remaining readback by the earliest observed lease.
                    for (const [Model, filter] of [[this.#models.Operation, () => this.#operationFilter(expected, new Date())],
                        [this.#models.Lock, () => this.#lockFilter(expected, new Date())], [this.#models.Owner, () => ownerFilter],
                        [this.#models.HyNode, () => nodeFilter]]) {
                        const current = await this.#majority(Model, { ...filter(), executionBindingCheck: nonce }, deadline);
                        if (!current) throw failure('UNCONFIRMED');
                        if (Model === this.#models.Owner) {
                            if (!isDeepStrictEqual(this.#ownerEvidence(current), ownerEvidence)) throw failure('UNCONFIRMED');
                        } else if (Model !== this.#models.HyNode) {
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
            // Reuse the same held authority for executor connection checks inside
            // terminal callbacks; reacquiring a non-reentrant authority can release
            // exclusion or deadlock. Async-local scope is private and cannot be
            // reused after ensureOpen closes it, even by escaped async work.
            return this.#held.run({ expected, record, assertCurrent, connection: freeze({
                expectedEndpoint: { ...enrollment.endpoint },
                expectedHostKeySha256: enrollment.nodeIdentity.sshHostKeySha256,
            }) }, async () => {
                const result = await work(record, assertCurrent);
                await assertCurrent();
                return result;
            });
        }, predecessor);
        // The authority itself can await cleanup after its callback completes.
        assertFresh();
        return result;
    }
    // Worker-followup interface (DORMANT; this store never settles/releases):
    // 1. Independently settle the predecessor operation and acquire the successor's
    //    exact claim + uncertain node lock; the paired config-owner generation stays.
    // 2. createSuccessor(expected, predecessorBindingId) selects only a persisted
    //    immutable row ID, never a caller-provided generation or terminal receipt.
    // 3. The held external authority must independently supply proof.predecessor:
    //    { bindingId, generation, headGeneration, bootId, status: 'terminal', receipt }.
    //    On mint, headGeneration MUST equal that predecessor's persisted generation.
    //    receipt is the exact fresh V2 `status` of its persisted commandIds.close,
    //    checked by validTerminalReceipt; a historical close/status alone is NOT
    //    current-head, writer-quiescence, endpoint or maintenance authority.
    // 4. Reads permit only that head or the admitted successor's own generation.
    //    Authority must sustain endpoint/alias/bootstrap/old-writer exclusion over
    //    the entire lifecycle, not merely echo a challenge or perform a DB scan.
    // Unknown commit/readback never releases anything; readVerified(expected)
    // recovers a durably committed exact row without retrying or minting new IDs.
    async createSuccessor(expected, predecessorBindingId) {
        if (!matches(predecessorBindingId, UUID)) throw failure();
        return this.#binding('successor', expected, null, predecessorBindingId);
    }
    // No caller-selected attempt/command IDs, no update/adopt/release API.
    async createBinding(expected) { return this.#binding('create', expected); }
    async readVerified(expected) { return this.#binding('read', expected); }
    // Return only immutable enrolled evidence; the mutable node selects a
    // connection to compare, never the authority for that connection or SSH key.
    async readVerifiedConnection(expected, verifiedBinding) {
        if (!validExpected(expected) || !exact(verifiedBinding, RECORD_KEYS) || !Object.isFrozen(verifiedBinding)
            || !Object.isFrozen(verifiedBinding.commandIds)) throw failure();
        const current = this.#held.getStore();
        if (current) {
            if (!isDeepStrictEqual(expected, current.expected) || !isDeepStrictEqual(verifiedBinding, current.record)) throw failure();
            await current.assertCurrent();
            return freeze({ binding: current.record, connection: current.connection });
        }
        return this.#binding('connection', expected, async record => {
            if (!isDeepStrictEqual(record, verifiedBinding)) throw failure();
            return freeze({ binding: record, connection: this.#held.getStore().connection });
        });
    }
    // Hold external exclusion through close, fresh status and final exact DB readback.
    async withVerifiedBinding(expected, work) {
        if (typeof work !== 'function') throw failure();
        return this.#binding('terminal', expected, work);
    }
}
module.exports = { TopologyExecutionBindingStore };
