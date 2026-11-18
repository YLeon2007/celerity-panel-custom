'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { isIP } = require('node:net');
const { isDeepStrictEqual } = require('node:util');
const { Types: { ObjectId } } = require('mongoose');
const { topologyExecutionContext, matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { topologyOperationClaimBindingFilter } = require('../domain/topologyOperationClaimBinding');
const { projectCanonicalXrayCandidate } = require('../services/topologyXrayCandidate');
const { UUID, ID, TOKEN, COMMANDS, RECORD_KEYS, expectedKeysFor, recordKeysFor, exact, freeze, failure, validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const { assertProfileTargetPin, verifyImportedProfileTargetPin, resolveTopologyProfileTarget, assertSelectedProfileTargets } = require('../services/topologyProfileTarget');
const { selectedAdmissionFingerprint } = require('./topologyOperationRepository');
const TIMEOUT_MS = 5000;
const ENROLLMENT_KEYS = ['nodeId', 'targetProfile', 'endpoint', 'nodeIdentity', 'ownerGeneration', 'predecessorGeneration', 'bootId'];
const ENROLLMENT_ROW_KEYS = ['_id', 'executionContext', 'proofId', 'maintenanceId', ...ENROLLMENT_KEYS];
const BINDING_ROW_KEYS = [...new Set([...ENROLLMENT_ROW_KEYS, ...RECORD_KEYS, 'enrollmentId', 'commandTokens'])];
const PROFILES = ['xray-main', 'xray-bridge'];
// Only the store may open this scope, after the three-lease transaction and its
// majority readback. It preserves the creator of P; it never changes a lease filter.
const reclaimedReservation = new AsyncLocalStorage();
function partialReservationMember(expected) {
    const scope = reclaimedReservation.getStore();
    if (!scope) return null;
    if (!scope.open) throw failure();
    const member = scope.members.find(m => m.expected.nodeId === expected.nodeId);
    if (!member || !samePin(member.expected, expected)
        || expectedKeys(member.expected).some(k => !isDeepStrictEqual(member.expected[k], expected[k]))) throw failure();
    return member;
}
const OPTIONS = { maxTimeMS: TIMEOUT_MS, timeoutMS: TIMEOUT_MS };
const NUMBER_TYPES = ['double', 'int', 'long'];
const OWNER_PRIVATE_FIELDS = '+legacyAppliedTopology +profileTargetPin +executionEnrollment';
const OPERATION_PRIVATE_FIELDS = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath +reservationHandoff';
function executionAttemptFilter(context,attempt){
    if(context.target!=='test')return {attempts:attempt};
    return {$or:[{attempts:attempt},{
        'retainedVerifyContinuation.kind':'verified-before-closure-reclaimed-claim-v1',
        'retainedVerifyContinuation.originalBindingAttempt':attempt,
        $expr:{$eq:['$attempts','$retainedVerifyContinuation.originalAttempts']},
    }]};
}
function pinKeys(value) {
    if (!value || !Object.hasOwn(value, 'profileTargetPin')) return [];
    try {
        const pin = assertProfileTargetPin(value.profileTargetPin);
        if (pin.nodeId !== value.nodeId || pin.targetProfile !== value.targetProfile
            || (Object.hasOwn(value, 'ownerGeneration') && pin.ownerGeneration !== value.ownerGeneration)) throw failure();
        return ['profileTargetPin'];
    } catch { throw failure(); }
}
function expectedKeys(value) { try { return expectedKeysFor(value); } catch { throw failure(); } }
function recordKeys(value) { try { return recordKeysFor(value); } catch { throw failure(); } }
function samePin(left, right) {
    return Object.hasOwn(left, 'profileTargetPin') === Object.hasOwn(right, 'profileTargetPin')
        && isDeepStrictEqual(left.profileTargetPin, right.profileTargetPin);
}
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
function validEnrollment(value, internal = false) {
    return exact(value, [...ENROLLMENT_KEYS, ...(internal ? pinKeys(value) : [])]) && matches(value.nodeId, ID) && PROFILES.includes(value.targetProfile)
        && validEndpoint(value.endpoint) && validIdentity(value.nodeIdentity) && matches(value.ownerGeneration, UUID)
        && (value.predecessorGeneration === 'none' || matches(value.predecessorGeneration, UUID)) && matches(value.bootId, UUID);
}
function emptyHead(enrollment) {
    return { generation: 'none', bootId: enrollment.bootId, status: 'empty', protocolVersion: 2,
        journal: 'absent', legacyState: 'absent', writers: 'excluded' };
}
function liveBoot(row) {
    const r = row.pristineBootResume;
    if (r === undefined) return row.bootId;
    if (row.executionContext !== 'test.infograd.online' || row.predecessorGeneration !== 'none'
        || !exact(r, ['initialBootId', 'bootId', 'proofId', 'maintenanceId', 'verifiedAt', 'previousBootIds'])
        || r.initialBootId !== row.bootId || !UUID.test(r.bootId) || !UUID.test(r.proofId)
        || r.maintenanceId !== row.maintenanceId || !(r.verifiedAt instanceof Date)
        || !Number.isFinite(r.verifiedAt.getTime()) || r.verifiedAt.getTime() > Date.now()
        || !Array.isArray(r.previousBootIds) || r.previousBootIds.length < 1 || r.previousBootIds.length > 8
        || r.previousBootIds[0] !== row.bootId || r.previousBootIds.some(b => !UUID.test(b))
        || new Set([...r.previousBootIds, r.bootId]).size !== r.previousBootIds.length + 1) throw failure();
    return r.bootId;
}
function enrollmentProjection(row) {
    return Object.fromEntries([...ENROLLMENT_KEYS, ...pinKeys(row)].map(key => [key,
        key === 'bootId' ? liveBoot(row) : key === 'profileTargetPin' ? assertProfileTargetPin(row[key]) : row[key]]));
}
function checkedEnrollment(row) {
    if (!exact(row, [...ENROLLMENT_ROW_KEYS, ...pinKeys(row), ...(row?.predecessorGeneration === 'none' ? ['provisioningReceipt'] : []), ...(row?.pristineBootResume !== undefined ? ['pristineBootResume'] : [])])
        || (row.predecessorGeneration === 'none' && !isDeepStrictEqual(row.provisioningReceipt, emptyHead(row)))
        || !matches(row._id, UUID) || !matches(row.proofId, UUID) || !matches(row.maintenanceId, UUID)
        || !validEnrollment(enrollmentProjection(row), true)) throw failure();
    return row;
}
function ownershipReceipt(r) {
    return exact(r, ['proofId', 'maintenanceId', 'fromGeneration', 'toGeneration', 'oldBackendInstanceId', 'oldPid', 'oldProcessStartTime', 'verifiedAt'])
        && ['proofId', 'maintenanceId', 'fromGeneration', 'toGeneration'].every(k => matches(r[k], UUID))
        && r.fromGeneration !== r.toGeneration && token(r.oldBackendInstanceId)
        && Number.isSafeInteger(r.oldPid) && r.oldPid > 0 && typeof r.oldProcessStartTime === 'string' && r.oldProcessStartTime.length > 0
        && r.verifiedAt instanceof Date && Number.isFinite(r.verifiedAt.getTime()) && r.verifiedAt.getTime() <= Date.now();
}
function sameAlias(a, b) {
    return ['_id', 'executionContext', 'nodeId', 'targetProfile', 'endpoint', 'nodeIdentity'].every(k => isDeepStrictEqual(a[k], b[k]));
}
function aliasContext(alias) {
    const context = topologyExecutionContext(alias.executionContext === 'lm1.infograd.online' ? 'production' : 'test', alias.executionContext);
    if (!context) throw failure();
    return context;
}
function reentryEvidence(alias, owner) {
    checkedEnrollment(alias);
    const e = owner?.executionEnrollment;
    if (!isDeepStrictEqual(owner?.executionContext, aliasContext(alias)) || !e
        || !exact(e, ['kind', 'previousAdoptionReceipt', 'previousHandbackReceipt',
            ...(e.previousEnrollment !== undefined ? ['previousEnrollment'] : []), ...(e.enrollment !== undefined ? ['enrollment'] : [])])
        || e.kind !== 'public-handback-reentry-v1' || !ownershipReceipt(e.previousAdoptionReceipt) || !ownershipReceipt(e.previousHandbackReceipt)
        || !ownershipReceipt(owner.adoptionReceipt)
        || e.previousAdoptionReceipt.toGeneration !== e.previousHandbackReceipt.fromGeneration
        || e.previousHandbackReceipt.toGeneration !== owner.adoptionReceipt.fromGeneration
        || e.previousHandbackReceipt.verifiedAt < e.previousAdoptionReceipt.verifiedAt
        || owner.adoptionReceipt.verifiedAt < e.previousHandbackReceipt.verifiedAt) throw failure();
    const prior = checkedEnrollment(Object.hasOwn(e, 'previousEnrollment') ? e.previousEnrollment : alias);
    if (!sameAlias(prior, alias) || prior.ownerGeneration !== e.previousAdoptionReceipt.toGeneration) throw failure();
    return e;
}
// Permanent aliases never become fresh execution authority by themselves. Only
// the current owner's held preEnroll CAS may install this private epoch record.
function acceptedExecutionEnrollment(alias, owner) {
    if (owner?.executionEnrollment === undefined) return alias;
    const e = reentryEvidence(alias, owner), current = checkedEnrollment(e.enrollment);
    if (!sameAlias(alias, current) || current.predecessorGeneration !== 'none'
        || current.ownerGeneration !== owner.adoptionReceipt.toGeneration
        || current.ownerGeneration === e.previousAdoptionReceipt.toGeneration
        || !isDeepStrictEqual(owner.executionContext, aliasContext(alias))
        || String(owner.node) !== alias.nodeId || owner.profile !== alias.targetProfile
        || !isDeepStrictEqual(owner.nodeIdentity, alias.nodeIdentity)) throw failure();
    return current;
}
function handbackReentryEvidence(alias, owner) {
    checkedEnrollment(alias);
    const prior = acceptedExecutionEnrollment(alias, owner);
    if (owner?.owner !== 'classic'
        || !isDeepStrictEqual(owner.executionContext, aliasContext(alias))
        || String(owner.node) !== alias.nodeId || owner.profile !== alias.targetProfile || !isDeepStrictEqual(owner.nodeIdentity, alias.nodeIdentity)
        || !ownershipReceipt(owner.adoptionReceipt) || !ownershipReceipt(owner.handbackReceipt)
        || owner.adoptionReceipt.toGeneration !== prior.ownerGeneration
        || owner.handbackReceipt.fromGeneration !== prior.ownerGeneration || owner.handbackReceipt.toGeneration !== owner.generation
        || owner.handbackReceipt.verifiedAt < owner.adoptionReceipt.verifiedAt
        || ['lastSettledOperation', 'lastSettledGeneration', 'lastSettledRevision', 'lastSettledCloseId'].some(k => Object.hasOwn(owner, k))) throw failure();
    return prior;
}
function validExpected(value, context) {
    let keys;
    try { keys = expectedKeys(value); } catch { return false; }
    return exact(value, keys) && Object.isFrozen(value)
        && value.executionContext === context.hostIdentity && matches(value.operationId, ID) && matches(value.nodeId, ID)
        && matches(value.candidateHash, /^sha256:[a-f0-9]{64}$/) && token(value.backupId)
        && token(value.owner) && PROFILES.includes(value.targetProfile)
        && Number.isSafeInteger(value.attempt) && value.attempt > 0 && matches(value.generation, UUID)
        && Number.isSafeInteger(value.topologyRevision) && value.topologyRevision >= 0
        && Number.isSafeInteger(value.priorDeployedRevision) && value.priorDeployedRevision >= 0;
}
function recordProjection(row) {
    return freeze(Object.fromEntries(recordKeys(row).map(key => [key, key === 'commandIds' ? { ...row[key] }
        : key === 'profileTargetPin' ? assertProfileTargetPin(row[key]) : row[key]])));
}

// TEST host wiring requires an explicit externally held controller capability.
// No production activation or operational authority implementation is supplied.
// The trusted authority MUST hold old-PID/dispatch/bootstrap/alias exclusion across
// the awaited callback, including commit + primary-majority readback. A DB row,
// local shutdown, or request-provided proof is never a replacement for that scope.
// That exclusion MUST also be sustained externally across the subsequent remote
// lifecycle; this store owns only validation/commit/readback, never that lifetime.
class TopologyExecutionBindingStore {
    #context;
    #models;
    #authority;
    #assertAuthorityHeld;
    #checkPristinePair;
    #held = new AsyncLocalStorage();
    constructor({ executionContext, withVerifiedAuthority, assertAuthorityHeld, checkPristinePair, Operation, Lock, Owner, Enrollment, Binding, HyNode } = {}) {
        this.#checkPristinePair = checkPristinePair;
        const selected = topologyExecutionContext(executionContext?.target, executionContext?.hostIdentity);
        if (!matchesTopologyExecutionContext(executionContext, selected)) {
            throw new TypeError('Exact server-owned production context or canonical TEST context required');
        }
        this.#context = selected;
        Object.defineProperty(this, 'executionContext', {
            get: () => this.#context,
            enumerable: true,
        });
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
        if (assertAuthorityHeld !== undefined && typeof assertAuthorityHeld !== 'function') throw new TypeError('Held authority check required');
        this.#authority = withVerifiedAuthority;
        this.#assertAuthorityHeld = assertAuthorityHeld;
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

    #ownerFilter(enrollment, evidence, discover = false) {
        return exactFields({ executionContext: { ...this.#context }, node: enrollment.nodeId, profile: enrollment.targetProfile,
            nodeIdentity: enrollment.nodeIdentity, owner: 'topology', generation: enrollment.ownerGeneration,
            'adoptionReceipt.toGeneration': enrollment.ownerGeneration, originalSnapshot: { $exists: true },
            handbackReceipt: { $exists: false },
            ...(!discover ? { profileTargetPin: Object.hasOwn(enrollment, 'profileTargetPin')
                ? assertProfileTargetPin(enrollment.profileTargetPin) : { $exists: false } } : {}),
            ...(evidence ? { originalSnapshot: evidence.originalSnapshot, adoptionReceipt: evidence.adoptionReceipt,
                executionEnrollment: evidence.executionEnrollment ?? { $exists: false },
                ...(Object.hasOwn(evidence, 'profileTargetPin') ? { legacyAppliedTopology: evidence.legacyAppliedTopology } : {}) } : {}) }, {
            executionContext: ['object', { ...this.#context }], node: ['objectId', new ObjectId(enrollment.nodeId)],
            profile: ['string', enrollment.targetProfile], nodeIdentity: ['object', enrollment.nodeIdentity],
            owner: ['string', 'topology'], generation: ['string', enrollment.ownerGeneration],
            originalSnapshot: ['object'], adoptionReceipt: ['object'],
            'adoptionReceipt.toGeneration': ['string', enrollment.ownerGeneration],
            ...(!discover && Object.hasOwn(enrollment, 'profileTargetPin') ? {
                profileTargetPin: ['object', assertProfileTargetPin(enrollment.profileTargetPin)] } : {}),
            ...(evidence ? { originalSnapshot: ['object', evidence.originalSnapshot], adoptionReceipt: ['object', evidence.adoptionReceipt],
                ...(Object.hasOwn(evidence, 'profileTargetPin') ? { legacyAppliedTopology: ['object', evidence.legacyAppliedTopology] } : {}) } : {}),
        });
    }
    #ownerEvidence(row, enrollment, derive = false) {
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
        if (!row || !isDeepStrictEqual(row.executionContext, this.#context) || row.owner !== 'topology'
            || String(row.node) !== enrollment.nodeId || row.profile !== enrollment.targetProfile
            || row.generation !== enrollment.ownerGeneration || !isDeepStrictEqual(row.nodeIdentity, enrollment.nodeIdentity)
            || Object.hasOwn(row, 'handbackReceipt')) throw failure();
        let imported = {};
        if (Object.hasOwn(row, 'profileTargetPin')) {
            try {
                const profileTargetPin = verifyImportedProfileTargetPin({ owner: row,
                    profileTargetPin: row.profileTargetPin, executionContext: this.#context });
                imported = { profileTargetPin, legacyAppliedTopology: row.legacyAppliedTopology };
            } catch { throw failure(); }
        } else if (row.legacyAppliedTopology?.links?.some(link => link.mode === 'forward')) {
            // No backfill/upgrade of an unofficial forward root without its pin.
            throw failure();
        }
        if (!derive && !samePin(imported, enrollment)) throw failure();
        return { originalSnapshot: snapshot, adoptionReceipt: receipt, ...imported,
            ...(row.executionEnrollment === undefined ? {} : { executionEnrollment: row.executionEnrollment }) };
    }
    #nodeFilter(enrollment) {
        return exactFields({ _id: enrollment.nodeId, active: true, type: 'xray',
            cascadeRole: Object.hasOwn(enrollment, 'profileTargetPin') ? assertProfileTargetPin(enrollment.profileTargetPin).role
                : { $in: enrollment.targetProfile === 'xray-main' ? ['portal'] : ['relay', 'bridge'] } }, {
            _id: ['objectId', new ObjectId(enrollment.nodeId)], active: ['bool', true], type: ['string', 'xray'],
            cascadeRole: Object.hasOwn(enrollment, 'profileTargetPin') ? ['string', enrollment.profileTargetPin.role] : ['string'],
            ssh: ['object'], ip: ['string', enrollment.endpoint.ip],
            'ssh.port': [NUMBER_TYPES, enrollment.endpoint.port], 'ssh.username': ['string', enrollment.endpoint.username],
        });
    }
    async #ownerInTransaction(filter, session, enrollment) {
        const row = await this.#models.Owner.findOne(filter).select(OWNER_PRIVATE_FIELDS).session(session).setOptions(OPTIONS).lean();
        return this.#ownerEvidence(row, enrollment);
    }
    #operationFilter(expected, now) {
        return exactFields({ _id: expected.operationId, ...topologyOperationClaimBindingFilter(this.#context),
            topologyRevision: expected.topologyRevision, priorDeployedRevision: expected.priorDeployedRevision,
            heldTopologyAdmission: true, leaseOwner: expected.owner, ...executionAttemptFilter(this.#context,expected.attempt),
            leaseUntil: { $gt: now }, status: { $in: ['preparing', 'committing', 'rolling_back'] },
            pppWait: { $exists: false }, nodes: { $elemMatch: { node: expected.nodeId,
                targetProfile: expected.targetProfile, candidateHash: expected.candidateHash.slice(7) } } }, {
            _id: ['objectId', new ObjectId(expected.operationId)], idempotencyKey: ['string'],
            topologyRevision: [NUMBER_TYPES, expected.topologyRevision],
            priorDeployedRevision: [NUMBER_TYPES, expected.priorDeployedRevision],
            heldTopologyAdmission: ['bool', true], leaseOwner: ['string', expected.owner],
            attempts: [NUMBER_TYPES], leaseUntil: ['date'], status: ['string'], nodes: ['array'],
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
        if (Model === this.#models.Owner) query.select(OWNER_PRIVATE_FIELDS);
        if (Model === this.#models.Operation) query.select(OPERATION_PRIVATE_FIELDS);
        if (Model === this.#models.Lock) query.select('+reservationHandoffId');
        const row = await query.lean();
        if (Date.now() >= deadline) throw failure('UNCONFIRMED');
        return row;
    }

    async #scope(action, enrollment, expected, work, predecessor = null) {
        const challenge = freeze({ action, nonce: randomUUID(), executionContext: { ...this.#context },
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

    async #transaction(work, confirm, ensureOpen, { retryKnownAborted = false } = {}) {
        for (let attempt = 0; ; attempt++) {
            if (attempt > 0) {
                await this.#assertAuthorityHeld?.();
                ensureOpen();
            }
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
                    // One bounded confirmation, never retry a possibly committed transaction.
                    if (!error.hasErrorLabel?.('UnknownTransactionCommitResult')) throw error;
                }
                ensureOpen();
                const result = await confirm(Date.now() + TIMEOUT_MS);
                ensureOpen();
                return result;
            } catch (error) {
                if (!commitAttempted && session.inTransaction()) await session.abortTransaction({ timeoutMS: TIMEOUT_MS }).catch(() => {});
                // An ordinary same-owner lease heartbeat can win after the
                // snapshot and before Lock CAS (actual Mongo 112). Retry only
                // an explicitly aborted pre-commit revalidation, under the SAME
                // held authority and immutable IDs. Every predicate is reread.
                // No binding creation, remote command, unknown commit/readback,
                // operation attempt, or finalization is replayed here.
                if (retryKnownAborted && !commitAttempted && attempt < 2
                    && error?.code === 112 && error.hasErrorLabel?.('TransientTransactionError') === true
                    && !error.hasErrorLabel?.('UnknownTransactionCommitResult')) continue;
                if (error?.code === 11000) throw failure('CONFLICT');
                if (error?.code?.startsWith?.('TOPOLOGY_EXECUTION_BINDING_')) throw error;
                const refused = failure(commitAttempted ? 'UNCONFIRMED' : 'UNPROVEN');
                refused.cause = error;
                throw refused;
            } finally { await session.endSession(); }
        }
    }
    async #cas(Model, filter, nonce, session) {
        const result = await Model.updateOne(filter, { $set: { executionBindingCheck: nonce } },
            { session, ...OPTIONS, runValidators: true });
        if (result.matchedCount !== 1) throw failure();
    }

    async preEnroll(input) {
        if (!validEnrollment(input)) throw failure();
        // Exactly seven public keys. Only independently read owner evidence can
        // supply a pin; this preliminary read does not grant remote permission.
        const inputCopy = structuredClone(input);
        await this.#indexes();
        const initial = await this.#majority(this.#models.Owner, this.#ownerFilter(inputCopy, undefined, true));
        const initialEvidence = this.#ownerEvidence(initial, inputCopy, true);
        const enrollment = freeze({ ...inputCopy, ...(Object.hasOwn(initialEvidence, 'profileTargetPin')
            ? { profileTargetPin: assertProfileTargetPin(initialEvidence.profileTargetPin) } : {}) });
        const alias = await this.#majority(this.#models.Enrollment, { nodeId: input.nodeId, targetProfile: input.targetProfile });
        if (alias) {
            const prior = reentryEvidence(alias, initial);
            if (prior.enrollment !== undefined
                || enrollment.predecessorGeneration !== 'none' || !sameAlias(alias, { ...enrollment, _id: alias._id, executionContext: this.#context.hostIdentity })) throw failure();
        }
        const row = { _id: alias?._id ?? randomUUID(), executionContext: this.#context.hostIdentity, ...enrollment };
        return this.#scope('enroll', enrollment, null, async (receipt, ensureOpen) => {
            const nonce = randomUUID();
            const filter = this.#ownerFilter(enrollment, initialEvidence);
            const nodeFilter = this.#nodeFilter(enrollment);
            const currentEvidence = alias ? { ...initial.executionEnrollment, enrollment: { ...row, ...receipt } } : undefined;
            let ownerEvidence;
            return this.#transaction(async session => {
                ensureOpen();
                ownerEvidence = await this.#ownerInTransaction(filter, session, enrollment);
                if (!isDeepStrictEqual(ownerEvidence, initialEvidence)) throw failure();
                await this.#cas(this.#models.Owner, filter, nonce, session);
                await this.#cas(this.#models.HyNode, nodeFilter, nonce, session);
                // Model.create/save drops timeoutMS in Mongoose 8. insertMany validates
                // the schema and forwards the bounded driver options unchanged.
                if (!alias) await this.#models.Enrollment.insertMany([{ ...row, ...receipt }], { session, ...OPTIONS });
                else {
                    // Re-entry is deliberately limited to an empty previous business
                    // cycle. Retained/unknown work is not silently made a new head.
                    for (const [Model, query] of [[this.#models.Binding, { nodeId: enrollment.nodeId }],
                        [this.#models.Lock, { node: enrollment.nodeId }],
                        [this.#models.Operation, { $or: [{ 'nodes.node': enrollment.nodeId }, { resourceNodeIds: enrollment.nodeId }] }]]) {
                        if (await Model.findOne(query).session(session).setOptions(OPTIONS).lean()) throw failure();
                    }
                    if (!isDeepStrictEqual(await this.#models.Enrollment.findOne({ _id: alias._id }).session(session).setOptions(OPTIONS).lean(), alias)) throw failure();
                    const updated = await this.#models.Owner.updateOne({ ...filter, executionBindingCheck: nonce },
                        { $set: { executionEnrollment: currentEvidence } }, { session, ...OPTIONS, runValidators: true });
                    if (updated.matchedCount !== 1) throw failure();
                }
            }, async deadline => {
                const owner = await this.#majority(this.#models.Owner, { ...filter,
                    ...(alias ? { executionEnrollment: currentEvidence } : {}), executionBindingCheck: nonce }, deadline);
                const permanent = await this.#majority(this.#models.Enrollment, { _id: row._id }, deadline);
                const confirmed = alias ? acceptedExecutionEnrollment(permanent, owner) : permanent;
                const node = await this.#majority(this.#models.HyNode, { ...nodeFilter, executionBindingCheck: nonce }, deadline);
                if (!confirmed || !owner || !node || !isDeepStrictEqual(confirmed, { ...row, ...receipt })
                    || (alias && !isDeepStrictEqual(permanent, alias))
                    || !isDeepStrictEqual(this.#ownerEvidence(owner, enrollment), { ...ownerEvidence,
                        ...(alias ? { executionEnrollment: currentEvidence } : {}) })) throw failure('UNCONFIRMED');
                return freeze({ enrollmentId: confirmed._id, ...enrollmentProjection(confirmed) });
            }, ensureOpen);
        });
    }

    async verifyPristineEnrollment(input, originalSnapshot) {
        if (this.#context.target !== 'test' || !validEnrollment(input)) throw failure();
        await this.#indexes();
        const row = await this.#enrollment(input);
        const prior = enrollmentProjection(row);
        if (!isDeepStrictEqual({ ...prior, bootId: input.bootId }, input)) throw failure('ENROLLMENT_CHANGED');
        const initialOwner = await this.#majority(this.#models.Owner, this.#ownerFilter(input));
        const initialEvidence = this.#ownerEvidence(initialOwner, input);
        const permanent = await this.#majority(this.#models.Enrollment, { _id: row._id });
        return this.#scope('reconcile-pristine', input, null, async (receipt, ensureOpen) => {
            if (receipt.maintenanceId !== row.maintenanceId || row.predecessorGeneration !== 'none') throw failure();
            const ownerFilter = this.#ownerFilter(input, initialEvidence), nodeFilter = this.#nodeFilter(input);
            const absence = async session => {
                for (const [Model, filter] of [
                    [this.#models.Binding, { nodeId: input.nodeId }],
                    [this.#models.Lock, { node: input.nodeId }],
                    [this.#models.Operation, { 'nodes.node': input.nodeId }],
                ]) if (await Model.findOne(filter).session(session).setOptions(OPTIONS).lean()) throw failure('RECONCILE_REQUIRED');
            };
            const check = async () => {
                await this.#assertAuthorityHeld?.(); ensureOpen();
                const owner = await this.#majority(this.#models.Owner, ownerFilter);
                const node = await this.#majority(this.#models.HyNode, nodeFilter);
                const current = await this.#enrollment(input);
                const evidence = this.#ownerEvidence(owner, input);
                if (!node || !isDeepStrictEqual(current, row) || !isDeepStrictEqual(evidence.originalSnapshot, originalSnapshot)) throw failure();
                await absence(null); ensureOpen();
            };
            await check();
            const bootChanged = prior.bootId !== input.bootId;
            const previousBootIds = [...(row.pristineBootResume?.previousBootIds ?? []), prior.bootId];
            if (bootChanged && (previousBootIds.length > 8 || previousBootIds.includes(input.bootId))) throw failure();
            const resume = { initialBootId: row.bootId, bootId: input.bootId, proofId: receipt.proofId,
                maintenanceId: receipt.maintenanceId, verifiedAt: new Date(), previousBootIds };
            const nonce = randomUUID();
            const currentEpoch = initialEvidence.executionEnrollment;
            const resumedEpoch = currentEpoch && bootChanged
                ? { ...currentEpoch, enrollment: { ...row, pristineBootResume: resume } } : currentEpoch;
            // Narrow pristine TEST transition, not an enrollment replacement.
            // All original fields/receipt and IDs stay byte-for-byte unchanged.
            // The generic immutable model ABI is not relaxed.
            return this.#transaction(async session => {
                await absence(session);
                const owner = await this.#ownerInTransaction(ownerFilter, session, input);
                if (!isDeepStrictEqual(owner.originalSnapshot, originalSnapshot)) throw failure();
                await this.#cas(this.#models.Owner, ownerFilter, nonce, session);
                await this.#cas(this.#models.HyNode, nodeFilter, nonce, session);
                const filter = { ...row, pristineBootResume: row.pristineBootResume ?? { $exists: false } };
                if (currentEpoch) {
                    // A reentry keeps its permanent alias immutable. Resume the
                    // same current private epoch under the existing owner CAS.
                    if (!isDeepStrictEqual(await this.#models.Enrollment.findOne({ _id: row._id }).session(session).setOptions(OPTIONS).lean(), permanent)) throw failure('CONFLICT');
                    if (bootChanged && (await this.#models.Owner.updateOne({ ...ownerFilter, executionBindingCheck: nonce },
                        { $set: { executionEnrollment: resumedEpoch } }, { session, ...OPTIONS, runValidators: true })).matchedCount !== 1) throw failure('CONFLICT');
                } else if (bootChanged) {
                    const result = await this.#models.Enrollment.collection.updateOne(filter, { $set: { pristineBootResume: resume } }, { session, ...OPTIONS });
                    if (result.matchedCount !== 1) throw failure('CONFLICT');
                } else if (!await this.#models.Enrollment.findOne(filter).session(session).setOptions(OPTIONS).lean()) throw failure('CONFLICT');
            }, async () => {
                const confirmed = await this.#enrollment(input);
                if (!isDeepStrictEqual(confirmed, bootChanged ? { ...row, pristineBootResume: resume } : row)) throw failure('UNCONFIRMED');
                const owner = await this.#majority(this.#models.Owner, { ...this.#ownerFilter(input, {
                    ...initialEvidence, ...(resumedEpoch ? { executionEnrollment: resumedEpoch } : {}),
                }), executionBindingCheck: nonce });
                const node = await this.#majority(this.#models.HyNode, { ...nodeFilter, executionBindingCheck: nonce });
                if (!owner || !node || !isDeepStrictEqual(this.#ownerEvidence(owner, input).originalSnapshot, originalSnapshot)) throw failure('UNCONFIRMED');
                if (currentEpoch && !isDeepStrictEqual(await this.#majority(this.#models.Enrollment, { _id: row._id }), permanent)) throw failure('UNCONFIRMED');
                return freeze({ enrollmentId: row._id, ...enrollmentProjection(confirmed) });
            }, ensureOpen);
        });
    }

    async #enrollment(expected, session, deadline) {
        const get = (Model, filter) => session
            ? Model.findOne(filter).select(Model === this.#models.Owner ? OWNER_PRIVATE_FIELDS : '').session(session).setOptions(OPTIONS).lean()
            : this.#majority(Model, filter, deadline);
        const alias = await get(this.#models.Enrollment, { executionContext: this.#context.hostIdentity,
            nodeId: expected.nodeId, targetProfile: expected.targetProfile });
        const owner = await get(this.#models.Owner, { node: expected.nodeId, profile: expected.targetProfile });
        const row = acceptedExecutionEnrollment(checkedEnrollment(alias), owner);
        if (!samePin(row, expected)) throw failure();
        return freeze(structuredClone(row));
    }
    #checkRow(row, enrollment, expected, handoffOriginal = null) {
        const original = require('../services/topologyOperationExecutor').verifiedClosingOriginal(expected);
        if (!exact(row, [...BINDING_ROW_KEYS, ...pinKeys(row), ...(row?.predecessorBindingId ? ['predecessorBindingId', 'predecessorReceipt'] : [])])
            || !matches(row.proofId, UUID) || !matches(row.maintenanceId, UUID)
            || row.enrollmentId !== enrollment._id || row.executionContext !== this.#context.hostIdentity
            || !isDeepStrictEqual(enrollmentProjection(row), { ...enrollmentProjection(enrollment),
                ...(row.predecessorBindingId ? { predecessorGeneration: row.predecessorGeneration } : {}) })
            || (row.predecessorBindingId && (!matches(row.predecessorBindingId, UUID)
                || !matches(row.predecessorGeneration, UUID)
                || !validTerminalReceipt(row.predecessorReceipt, { ...row.predecessorReceipt,
                    commandIds: { close: row.predecessorReceipt?.commandId }, bootId: liveBoot(enrollment) })
                || row.predecessorReceipt.generation !== row.predecessorGeneration
                || ['nodeId', 'targetProfile', 'executionContext'].some(key => row.predecessorReceipt[key] !== row[key])
                || row.predecessorReceipt.operationId === row.operationId))
            || !samePin(row, expected) || (handoffOriginal ? (!isDeepStrictEqual(recordProjection(row),handoffOriginal)
                || expectedKeys(expected).some(key=>key!=='owner' && !isDeepStrictEqual(row[key],expected[key])))
                : original ? !isDeepStrictEqual(recordProjection(row), original)
                : expectedKeys(expected).some(key => !isDeepStrictEqual(row[key], expected[key])))
            || !matches(row._id, UUID) || !matches(row.attemptId, UUID)
            || row.generation === row.predecessorGeneration || !exact(row.commandIds, COMMANDS)
            || !COMMANDS.every(key => matches(row.commandIds[key], UUID))
            || new Set(Object.values(row.commandIds)).size !== COMMANDS.length
            || !isDeepStrictEqual(row.commandTokens, COMMANDS.map(key => row.commandIds[key]))) throw failure();
    }
    #terminalOperationFilter(prior) {
        return exactFields({ _id: prior.operationId, ...topologyOperationClaimBindingFilter(this.#context),
            status: { $in: ['succeeded', 'failed'] }, heldTopologyAdmission: false, ...executionAttemptFilter(this.#context,prior.attempt),
            topologyRevision: prior.topologyRevision, priorDeployedRevision: prior.priorDeployedRevision,
            nodes: { $elemMatch: { node: prior.nodeId, targetProfile: prior.targetProfile,
                candidateHash: prior.candidateHash.slice(7) } } }, {
            _id: ['objectId', new ObjectId(prior.operationId)], status: ['string'], heldTopologyAdmission: ['bool', false],
            attempts: [NUMBER_TYPES],
            topologyRevision: [NUMBER_TYPES, prior.topologyRevision],
            priorDeployedRevision: [NUMBER_TYPES, prior.priorDeployedRevision], nodes: ['array'],
        });
    }
    async #predecessor(enrollment, id) {
        if (!id) return null;
        if (!matches(id, UUID)) throw failure();
        const prior = await this.#majority(this.#models.Binding, { _id: id });
        const expected = prior && freeze(Object.fromEntries(expectedKeys(prior).map(key => [key, prior[key]])));
        if (!validExpected(expected, this.#context)) throw failure();
        this.#checkRow(prior, enrollment, expected);
        if (prior.maintenanceId !== enrollment.maintenanceId) throw failure();
        return freeze(structuredClone(prior));
    }
    async #checkOperation(expected, session) {
        const row = await this.#models.Operation.findOne(this.#operationFilter(expected, new Date()))
            .select(OPERATION_PRIVATE_FIELDS).session(session).setOptions(OPTIONS).lean();
        this.#checkOperationRow(row, expected);
    }
    #checkOperationRow(row, expected) {
        if(!row||require('./topologyRetainedVerifyContinuation').originalExecutionAttempt(row)!==expected.attempt)throw failure();
        const nodes = Array.isArray(row?.nodes) ? row.nodes.filter(node =>
            node?.node instanceof ObjectId && node.node.toHexString() === expected.nodeId) : [];
        if (nodes.length !== 1) throw failure();
        const node = nodes[0];
        if (node.targetProfile !== expected.targetProfile || node.candidateHash !== expected.candidateHash.slice(7)
            || !samePin(node, expected)
            || !['', expected.backupId].includes(node.backupId)) throw failure();
        try {
            resolveTopologyProfileTarget({ nodeId: expected.nodeId, role: node.role, targetProfile: node.targetProfile,
                ...(Object.hasOwn(node, 'profileTargetPin') ? { profileTargetPin: node.profileTargetPin } : {}) });
            assertSelectedProfileTargets(row);
            if (Object.hasOwn(expected, 'profileTargetPin') && row.admissionFingerprint !== selectedAdmissionFingerprint(row)) throw failure();
        } catch { throw failure(); }
        try { projectCanonicalXrayCandidate(node.candidate, expected.candidateHash.slice(7)); }
        catch { throw failure(); }
        const backupId = `topology-${createHash('sha256').update([
            expected.operationId, expected.nodeId, expected.candidateHash, expected.targetProfile,
        ].join('\0')).digest('hex')}`;
        if (backupId !== expected.backupId) throw failure();
    }
    async #binding(action, input, work, predecessorId = null, joinForWrite) {
        if (!validExpected(input, this.#context)) throw failure();
        const expected = freeze(structuredClone(input));
        await this.#indexes();
        const enrollment = await this.#enrollment(expected);
        const initialOwner = await this.#majority(this.#models.Owner, this.#ownerFilter(enrollment));
        const initialOwnerEvidence = this.#ownerEvidence(initialOwner, enrollment);
        const creating = action === 'create' || action === 'successor';
        const selected = creating ? null : await this.#majority(this.#models.Binding, { operationId: expected.operationId,
            nodeId: expected.nodeId, targetProfile: expected.targetProfile });
        if (selected) this.#checkRow(selected, enrollment, expected);
        if (!creating && !selected) throw failure();
        const predecessor = await this.#predecessor(enrollment, predecessorId || selected?.predecessorBindingId);
        if (action === 'successor' && !predecessor) throw failure();
        if (predecessor && (predecessor.operationId === expected.operationId
            || predecessor.generation === expected.generation)) throw failure();
        let validUntil = 0, confirmedNonce;
        // Physical checks may return after the first observed lease deadline.
        // A timer alone is not proof: require the *same* checked operation and
        // uncertain lock, both still live, with the transaction's exact nonce.
        const confirmAfterWait = async () => {
            if (joinForWrite && confirmedNonce && Date.now() >= validUntil) {
                let limit = Date.now() + TIMEOUT_MS;
                for (const [model, filter] of [[this.#models.Operation, this.#operationFilter], [this.#models.Lock, this.#lockFilter]]) {
                    const row = await this.#majority(model, { ...filter.call(this, expected, new Date()), executionBindingCheck: confirmedNonce }, limit);
                    if (!(row?.leaseUntil instanceof Date)) throw failure('UNCONFIRMED');
                    limit = Math.min(limit, row.leaseUntil.getTime());
                }
                validUntil = limit;
            }
            assertFresh();
        };
        const assertFresh = () => {
            if (Date.now() >= validUntil) throw failure('UNCONFIRMED');
        };
        const result = await this.#scope(action, enrollmentProjection(enrollment), expected, async (receipt, ensureOpen) => {
            if (receipt.maintenanceId !== enrollment.maintenanceId) throw failure();
            const nonce = action === 'probe' ? null : randomUUID();
            let row = creating ? { ...expected, ...enrollmentProjection(enrollment),
                ...(predecessor ? { predecessorGeneration: predecessor.generation } : {}),
                _id: randomUUID(), enrollmentId: enrollment._id, attemptId: randomUUID(), ...receipt,
                commandIds: Object.fromEntries(COMMANDS.map(command => [command, randomUUID()])) } : null;
            if (row) row.commandTokens = COMMANDS.map(command => row.commandIds[command]);
            const ownerFilter = this.#ownerFilter(enrollment, initialOwnerEvidence);
            const nodeFilter = this.#nodeFilter(enrollment);
            let readOnlyOwnerEvidence;
            const check = async () => {
                await this.#assertAuthorityHeld?.();
                if (action === 'probe') {
                    // Diagnostic recovery must not renew/claim, update CAS nonces,
                    // retry a transaction or allocate any execution identifiers.
                    // The independent external scope still excludes remote writers.
                    ensureOpen();
                    let deadline = Date.now() + TIMEOUT_MS;
                    const operation = await this.#majority(this.#models.Operation, this.#operationFilter(expected, new Date()), deadline);
                    this.#checkOperationRow(operation, expected);
                    if (!(operation?.leaseUntil instanceof Date)) throw failure();
                    let leaseUntil = operation.leaseUntil.getTime();
                    deadline = Math.min(deadline, operation.leaseUntil.getTime());
                    const lock = await this.#majority(this.#models.Lock, this.#lockFilter(expected, new Date()), deadline);
                    if (!(lock?.leaseUntil instanceof Date)) throw failure();
                    leaseUntil = Math.min(leaseUntil, lock.leaseUntil.getTime());
                    deadline = Math.min(deadline, lock.leaseUntil.getTime());
                    const owner = await this.#majority(this.#models.Owner, ownerFilter, deadline);
                    const evidence = this.#ownerEvidence(owner, enrollment);
                    if (!isDeepStrictEqual(evidence, initialOwnerEvidence)) throw failure();
                    if (readOnlyOwnerEvidence && !isDeepStrictEqual(evidence, readOnlyOwnerEvidence)) throw failure();
                    readOnlyOwnerEvidence = evidence;
                    if (!await this.#majority(this.#models.HyNode, nodeFilter, deadline)
                        || !isDeepStrictEqual(await this.#enrollment(expected, undefined, deadline), enrollment)) throw failure();
                    const current = await this.#majority(this.#models.Binding, { _id: selected._id }, deadline);
                    this.#checkRow(current, enrollment, expected);
                    if (!isDeepStrictEqual(current, selected) || current.maintenanceId !== receipt.maintenanceId) throw failure();
                    if (predecessor) {
                        if (!isDeepStrictEqual(await this.#majority(this.#models.Binding, { _id: predecessor._id }, deadline), predecessor)
                            || !isDeepStrictEqual(current.predecessorReceipt, receipt.predecessorReceipt)) throw failure();
                        const priorOperation = await this.#majority(this.#models.Operation, this.#terminalOperationFilter(predecessor), deadline);
                        this.#checkOperationRow(priorOperation, predecessor);
                    }
                    validUntil = leaseUntil;
                    await this.#assertAuthorityHeld?.();
                    assertFresh(); ensureOpen();
                    return recordProjection(current);
                }
                let ownerEvidence;
                const hold = await joinForWrite?.();
                let confirmedRecord;
                try { confirmedRecord = await this.#transaction(async session => {
                    ensureOpen();
                    await this.#checkOperation(expected, session);
                    await this.#cas(this.#models.Operation, this.#operationFilter(expected, new Date()), nonce, session);
                    await this.#cas(this.#models.Lock, this.#lockFilter(expected, new Date()), nonce, session);
                    ownerEvidence = await this.#ownerInTransaction(ownerFilter, session, enrollment);
                    if (!isDeepStrictEqual(ownerEvidence, initialOwnerEvidence)) throw failure();
                    await this.#cas(this.#models.Owner, ownerFilter, nonce, session);
                    await this.#cas(this.#models.HyNode, nodeFilter, nonce, session);
                    const enrolled = await this.#enrollment(expected, session);
                    if (!isDeepStrictEqual(enrolled, enrollment)) throw failure();
                    if (predecessor) {
                        const previous = await this.#models.Binding.findOne({ _id: predecessor._id }).session(session).setOptions(OPTIONS).lean();
                        if (!isDeepStrictEqual(previous, predecessor)) throw failure();
                        const terminalFilter = this.#terminalOperationFilter(predecessor);
                        const terminalOperation = await this.#models.Operation.findOne(terminalFilter)
                            .select(OPERATION_PRIVATE_FIELDS).session(session).setOptions(OPTIONS).lean();
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
                    let leaseUntil = Infinity;
                    for (const [Model, filter] of [[this.#models.Operation, () => this.#operationFilter(expected, new Date())],
                        [this.#models.Lock, () => this.#lockFilter(expected, new Date())], [this.#models.Owner, () => ownerFilter],
                        [this.#models.HyNode, () => nodeFilter]]) {
                        const current = await this.#majority(Model, { ...filter(), executionBindingCheck: nonce }, deadline);
                        if (!current) throw failure('UNCONFIRMED');
                        if (Model === this.#models.Owner) {
                            if (!isDeepStrictEqual(this.#ownerEvidence(current, enrollment), ownerEvidence)) throw failure('UNCONFIRMED');
                        } else if (Model !== this.#models.HyNode) {
                            if (Model === this.#models.Operation) this.#checkOperationRow(current, expected);
                            if (!(current.leaseUntil instanceof Date) || !Number.isFinite(current.leaseUntil.getTime())) throw failure('UNCONFIRMED');
                            leaseUntil = Math.min(leaseUntil, current.leaseUntil.getTime());
                            deadline = Math.min(deadline, current.leaseUntil.getTime());
                        }
                    }
                    // Mongo confirmation retains its cumulative I/O deadline.
                    // Awaited external checks/cleanup do not extend that budget,
                    // nor turn it into an earlier expiry of the confirmed leases.
                    validUntil = leaseUntil;
                    assertFresh();
                    return recordProjection(confirmed);
                }, ensureOpen, { retryKnownAborted: !creating && !joinForWrite });
                } finally { hold?.release(); }
                confirmedNonce = nonce;
                // Session cleanup is awaited by #transaction's finally block.
                await this.#assertAuthorityHeld?.();
                await confirmAfterWait();
                return confirmedRecord;
            };
            const record = await check();
            if (!work) return record;
            let active = true;
            const ensureActive = () => { ensureOpen(); if (!active) throw failure(); };
            const assertCurrent = async () => {
                ensureActive();
                if (!isDeepStrictEqual(await check(), record)) throw failure();
                ensureActive();
            };
            ensureActive();
            // Keep only the lexical ancestry of independently held bindings, not
            // historical or sibling scopes. Each frame retains its own authority
            // and freshness check; escaped async contexts cannot revive a frame.
            const scope = { expected, record, assertCurrent, ensureActive, parent: this.#held.getStore(), connection: freeze({
                expectedEndpoint: { ...enrollment.endpoint },
                expectedHostKeySha256: enrollment.nodeIdentity.sshHostKeySha256,
            }) };
            try {
                return await this.#held.run(scope, async () => {
                    const result = await work(record, assertCurrent);
                    await assertCurrent();
                    return result;
                });
            } finally { active = false; }
        }, predecessor);
        // The authority itself can await cleanup after its callback completes.
        await confirmAfterWait();
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
    async createSuccessor(expected, predecessorBindingId, joinForWrite) {
        if (!matches(predecessorBindingId, UUID)) throw failure();
        return this.#binding('successor', expected, null, predecessorBindingId, joinForWrite);
    }
    // The admitting worker reserves every participant before the first prepare.
    // No reservation, or exactly P and no B, distinguishes a cut from uncertain
    // delivery. Two bindings with pending DB labels do NOT establish that fact.
    async withPartialPortalClaim({ operationId, owner, leaseMs }, selected, work) {
        if (this.#context.target !== 'production' || !matches(operationId, ID) || !token(owner)
            || !Number.isSafeInteger(leaseMs) || leaseMs < 120000 || typeof work !== 'function'
            || typeof this.#checkPristinePair !== 'function' || typeof this.#assertAuthorityHeld !== 'function'
            || typeof selected?.verifySelected !== 'function') return null;
        const { Operation, Lock, Binding, Owner, HyNode } = this.#models;
        const claim = topologyOperationClaimBindingFilter(this.#context);
        const expired = { $lte: ['$leaseUntil', '$$NOW'] };
        const filter = { ...claim, _id: operationId, status: 'preparing', attempts: 1,
            admissionScope: 'selected', heldTopologyAdmission: true, kind: 'link.apply',
            installedPath: { $exists: false }, pppWait: { $exists: false }, v2Terminal: { $exists: false },
            $expr: { $and: [claim.$expr, { $eq: [{ $type: '$leaseUntil' }, 'date'] }, expired] } };
        const before = await this.#majority(Operation, filter);
        if (!before) return null;
        if (!token(before.leaseOwner) || before.nodes?.length !== 2 || before.nodes[0].role !== 'portal'
            || before.nodes[1].role !== 'bridge' || before.nodes.some(n => n.state !== 'pending' || n.backupId !== '')
            || !isDeepStrictEqual(before.resourceNodeIds?.slice().sort(), before.nodes.map(n => String(n.node)).sort())) return null;
        const reservations = await Binding.find({ operationId }).read('primary').readConcern('majority').limit(2).setOptions(OPTIONS).lean();
        if (reservations.length > 1 || (reservations.length === 1 && reservations[0].nodeId !== String(before.nodes[0].node))) return null;
        const old = before.leaseOwner, pending = [];
        const prior = before.reservationHandoff;
        // A repeat takeover is scoped to the exact acknowledged transaction.
        // Do not infer the binding's creator from the current lease holder or
        // authorize a legacy/malformed receipt. No command may have begun.
        if (prior !== undefined && (!exact(prior, ['kind','operationId','attempt','fingerprint','holder','nonce','members'])
            || prior.kind !== 'first-reservation-handoff-v1' || prior.operationId !== operationId || prior.attempt !== 1
            || prior.fingerprint !== before.admissionFingerprint || prior.holder !== old || !matches(prior.nonce,UUID)
            || !Array.isArray(prior.members) || prior.members.length !== 2)) throw failure();
        await this.#indexes();
        await selected.verifySelected(before);
        for (const [i, n] of before.nodes.entries()) {
            const nodeId = String(n.node), candidateHash = `sha256:${n.candidateHash}`;
            const backupId = `topology-${createHash('sha256').update([operationId,nodeId,candidateHash,n.targetProfile].join('\0')).digest('hex')}`;
            const lockFilter = { operationId, node: nodeId, owner: old, remoteUncertain: true, $expr: expired };
            const lock = await this.#majority(Lock, lockFilter);
            if (!lock || !(lock.leaseUntil instanceof Date) || !matches(lock.generation, UUID)
                || lock.owner !== old || lock.operationId !== operationId || String(lock.node) !== nodeId
                || lock.remoteUncertain !== true || lock.reservationHandoffId !== prior?.nonce) throw failure();
            const expected = freeze({ executionContext: this.#context.hostIdentity, operationId, nodeId, candidateHash, backupId,
                targetProfile: n.targetProfile, ...Object.hasOwn(n, 'profileTargetPin') && { profileTargetPin: assertProfileTargetPin(n.profileTargetPin) },
                topologyRevision: before.topologyRevision, priorDeployedRevision: before.priorDeployedRevision,
                owner: old, attempt: 1, generation: lock.generation });
            if (!validExpected(expected,this.#context)) throw failure();
            this.#checkOperationRow(before,expected);
            const enrollment = await this.#enrollment(expected);
            if (enrollment.predecessorGeneration !== 'none') throw failure();
            const ownerRow = await this.#majority(Owner,this.#ownerFilter(enrollment));
            if (!ownerRow || ownerRow.lastSettledOperation !== undefined || ownerRow.lastSettledGeneration !== undefined) throw failure();
            const evidence = this.#ownerEvidence(ownerRow,enrollment);
            if (!await this.#majority(HyNode,this.#nodeFilter(enrollment))) throw failure();
            const reservation = reservations[i];
            let handoffOriginal = null;
            if (prior !== undefined) {
                const m = prior.members[i];
                if (!exact(m,['nodeId','generation','original']) || m.nodeId !== nodeId || m.generation !== lock.generation) throw failure();
                if (m.original !== null) {
                    if (!reservation || !token(m.original?.owner)) throw failure();
                    handoffOriginal = m.original;
                }
                // A new P since an empty transfer must pass the normal exact
                // creator check against old (the actual outgoing holder).
            }
            if (reservation) this.#checkRow(reservation,enrollment,expected,handoffOriginal);
            pending.push({ lock, expected, handoffOriginal, enrollment, evidence, original: reservation ? recordProjection(reservation) : null });
        }
        const checkPhysical = () => this.#checkPristinePair(pending.map(({enrollment,evidence}) => ({ ...enrollmentProjection(enrollment),
            maintenanceId: enrollment.maintenanceId, originalSnapshot: evidence.originalSnapshot })));
        await checkPhysical();
        const leaseUntil = new Date(Date.now() + leaseMs), nonce = randomUUID();
        const opMatch = { ...filter, leaseOwner: old, leaseUntil: before.leaseUntil, admissionFingerprint: before.admissionFingerprint,
            reservationHandoff: prior === undefined ? {$exists:false} : prior };
        const handoff = {kind:'first-reservation-handoff-v1',operationId,attempt:1,fingerprint:before.admissionFingerprint,
            holder:owner,nonce,members:pending.map(({expected:e,original})=>({nodeId:e.nodeId,generation:e.generation,original}))};
        const transfer = { $set: { leaseUntil, executionBindingCheck: nonce } };
        let acknowledged;
        await this.#transaction(async session => {
            const opts = { ...OPTIONS, session };
            const op = await Operation.findOne(opMatch).select(OPERATION_PRIVATE_FIELDS).setOptions(opts).lean();
            if (!op || !isDeepStrictEqual(op.nodes,before.nodes) || !isDeepStrictEqual(op.resourceNodeIds,before.resourceNodeIds)
                || await Lock.countDocuments({ operationId }).setOptions(opts) !== 2
                || await Binding.countDocuments({ operationId }).setOptions(opts) !== reservations.length) throw failure();
            await selected.verifySelected(op,session);
            for (const [i, {expected,handoffOriginal,evidence,enrollment,lock}] of pending.entries()) {
                this.#checkOperationRow(op,expected);
                if (!isDeepStrictEqual(await this.#enrollment(expected,session),enrollment)
                    || await Binding.countDocuments({enrollmentId:enrollment._id}).setOptions(opts) !== (reservations[i] ? 1 : 0)) throw failure();
                if (reservations[i]) {
                    const row = await Binding.findById(reservations[i]._id).setOptions(opts).lean();
                    this.#checkRow(row,enrollment,expected,handoffOriginal);
                    if (!isDeepStrictEqual(row,reservations[i])) throw failure();
                }
                const ownerFilter = { ...this.#ownerFilter(enrollment,evidence), lastSettledOperation: {$exists:false}, lastSettledGeneration: {$exists:false} };
                await this.#cas(Owner,ownerFilter,nonce,session);
                await this.#cas(HyNode,this.#nodeFilter(enrollment),nonce,session);
                if ((await Lock.updateOne({ _id: lock._id, operationId, node:expected.nodeId, owner:old,
                    generation:lock.generation, remoteUncertain:true, leaseUntil:lock.leaseUntil, $expr:expired,
                    reservationHandoffId: prior === undefined ? {$exists:false} : prior.nonce },
                    { $set:{ ...transfer.$set, owner, reservationHandoffId:nonce } },opts)).matchedCount !== 1) throw failure();
            }
            if ((await Operation.updateOne(opMatch,{ $set:{ ...transfer.$set, leaseOwner:owner, reservationHandoff:handoff } },opts)).matchedCount !== 1) throw failure();
        }, async deadline => {
            const op = await this.#majority(Operation,{ _id:operationId, leaseOwner:owner, attempts:1, status:'preparing',
                heldTopologyAdmission:true, executionBindingCheck:nonce, leaseUntil }, deadline);
            if (!op || !isDeepStrictEqual(op.reservationHandoff,handoff) || !isDeepStrictEqual(op.nodes,before.nodes)) throw failure('UNCONFIRMED');
            for (const {expected} of pending) if (!await this.#majority(Lock,{operationId,node:expected.nodeId,
                owner,generation:expected.generation,remoteUncertain:true,executionBindingCheck:nonce,reservationHandoffId:nonce,leaseUntil},deadline)) throw failure('UNCONFIRMED');
            acknowledged = op;
        }, () => { if (Date.now() >= +leaseUntil) throw failure('UNCONFIRMED'); });
        await checkPhysical();
        if (!acknowledged || Date.now() >= +leaseUntil) throw failure('UNCONFIRMED');
        const members = freeze(pending.map(({expected,original})=>({ expected:{...expected,owner}, original })));
        const scope = { open:true, members };
        try {
            return await reclaimedReservation.run(scope, () => work(acknowledged,
                members.map(({expected:e})=>({node:e.nodeId,generation:e.generation}))));
        } finally { scope.open = false; }
    }
    // Post-claim provisioning only. Reuse an exact durable binding; never retry
    // a failed read as creation. Select successors from privately joined settlement
    // metadata, not caller-selected IDs or a mutable runner/current-state scan.
    async reserveBinding(expected, joinForWrite) {
        if (!validExpected(expected, this.#context)) throw failure();
        const enrollment = await this.#enrollment(expected);
        const existing = await this.#majority(this.#models.Binding, { executionContext: this.#context.hostIdentity,
            operationId: expected.operationId, nodeId: expected.nodeId, targetProfile: expected.targetProfile });
        if (existing) return this.readVerified(expected, joinForWrite);
        const previous = await this.#majority(this.#models.Binding, { enrollmentId: enrollment._id });
        if (!previous) return this.createBinding(expected, joinForWrite);
        const owner = await this.#majority(this.#models.Owner, this.#ownerFilter(enrollment));
        this.#ownerEvidence(owner, enrollment);
        if (!matches(owner?.lastSettledGeneration, UUID) || !matches(owner?.lastSettledCloseId, UUID)
            || !matches(owner?.lastSettledOperation, ID)) throw failure();
        const predecessor = await this.#majority(this.#models.Binding, { enrollmentId: enrollment._id,
            executionContext: this.#context.hostIdentity, generation: owner.lastSettledGeneration,
            operationId: owner.lastSettledOperation, 'commandIds.close': owner.lastSettledCloseId });
        if (!predecessor) throw failure();
        // One finite, separately proven cancelled child may occupy the immutable
        // slot without having changed the applied baseline. Follow its genuine
        // native close, never delete/rebind the slot or rewrite lastSettled*.
        const child = await this.#majority(this.#models.Binding, { enrollmentId: enrollment._id,
            predecessorGeneration: predecessor.generation });
        if (!child) return this.createSuccessor(expected, predecessor._id, joinForWrite);
        const cancelled = await this.#models.Operation.findOne({ _id: child.operationId })
            .select(OPERATION_PRIVATE_FIELDS + ' +undispatchedPreparationSettlement').read('primary').readConcern('majority').setOptions(OPTIONS).lean();
        if (this.#context.target !== 'test' || !require('./topologyCancelledReservation')
            .validateCancelledReservation(cancelled, child, predecessor)) throw failure();
        const current = await this.#majority(this.#models.Operation, this.#operationFilter(expected,new Date()));
        const continuation = current?.bindingReservationContinuation;
        if (cancelled.undispatchedPreparationSettlement.cancelledSuccessors.nextOperationId !== expected.operationId
            || continuation?.kind !== 'native-cancelled-successor-before-binding-insert-v1'
            || continuation.predecessorOperation !== child.operationId
            || !continuation.locks?.some(l => l.node === expected.nodeId && l.generation === expected.generation)
            || !continuation.predecessorProofs?.some(p => validTerminalReceipt(p,child) && p.terminalOutcome === 'cancelled')) throw failure();
        return this.createSuccessor(expected, child._id, joinForWrite);
    }
    // No caller-selected attempt/command IDs, no update/adopt/release API.
    async createBinding(expected, joinForWrite) { return this.#binding('create', expected, null, null, joinForWrite); }
    async readVerified(expected, joinForWrite) { return this.#binding('read', expected, null, null, joinForWrite); }
    // Return only immutable enrolled evidence; the mutable node selects a
    // connection to compare, never the authority for that connection or SSH key.
    async readVerifiedConnection(expected, verifiedBinding) {
        if (!validExpected(expected, this.#context) || !exact(verifiedBinding, recordKeys(verifiedBinding)) || !Object.isFrozen(verifiedBinding)
            || !Object.isFrozen(verifiedBinding.commandIds)
            || (Object.hasOwn(verifiedBinding, 'profileTargetPin') && !Object.isFrozen(verifiedBinding.profileTargetPin))) throw failure();
        const current = this.#held.getStore();
        if (current) {
            const ancestry = [];
            for (let scope = current; scope; scope = scope.parent) {
                scope.ensureActive();
                ancestry.push(scope);
                if (!isDeepStrictEqual(expected, scope.expected) || !isDeepStrictEqual(verifiedBinding, scope.record)) continue;
                await scope.assertCurrent();
                for (const held of ancestry) held.ensureActive();
                return freeze({ binding: scope.record, connection: scope.connection });
            }
            // A foreign current scope cannot acquire replacement authority.
            throw failure();
        }
        return this.#binding('connection', expected, async record => {
            if (!isDeepStrictEqual(record, verifiedBinding)) throw failure();
            return freeze({ binding: record, connection: this.#held.getStore().connection });
        });
    }
    // Read-only exact-ID status recovery; never substitutes for mutation authority.
    async withReadOnlyVerifiedBinding(expected, work) {
        if (typeof work !== 'function') throw failure();
        return this.#binding('probe', expected, work);
    }
    // Hold external exclusion through close, fresh status and final exact DB readback.
    async withVerifiedBinding(expected, work) {
        if (typeof work !== 'function') throw failure();
        return this.#binding('terminal', expected, work);
    }
}
module.exports = { TopologyExecutionBindingStore, enrollmentRuntimeBootId: liveBoot, acceptedExecutionEnrollment, handbackReentryEvidence, partialReservationMember };
