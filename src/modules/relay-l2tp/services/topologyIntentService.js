'use strict';
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { matchesTopologyExecutionContext, topologyExecutionContext } = require('../domain/topologyExecutionContext');
const QUEUE_ID = 'create-v1'; // One counter/order namespace for legacy and versioned intents.
const INTENT_KINDS = new Set(['link.create', 'link.apply', 'link.delete']);
const { nodeActivation: normalizeNodeActivation, selectedDesiredVersion } = require('./topologyNodeActivation');
// Health, timestamps, lifecycle markers and applied proofs are not desired config.
const DESIRED_LINK_FIELDS = Object.freeze(['name', 'mode', 'portalNode', 'bridgeNode',
    'tunnelUuid', 'tunnelPort', 'tunnelDomain', 'tunnelProtocol', 'tunnelSecurity', 'tunnelTransport',
    'tcpFastOpen', 'tcpKeepAlive', 'tcpNoDelay', 'wsPath', 'wsHost', 'grpcServiceName',
    'xhttpPath', 'xhttpHost', 'xhttpMode', 'realityDest', 'realitySni', 'realityPrivateKey',
    'realityPublicKey', 'realityShortIds', 'realityFingerprint', 'muxEnabled', 'muxConcurrency',
    'geoRouting', 'priority', 'active']);
function desiredLinkPayload(link) {
    return JSON.parse(JSON.stringify(Object.fromEntries(DESIRED_LINK_FIELDS
        .filter(key => link[key] !== undefined).map(key => [key, link[key]]))));
}
// Content-addressed desired version: ordinary updateOne does not increment __v.
function linkDesiredVersion(link) { return digest(desiredLinkPayload(link)); }
// A PUT fingerprint describes the requested patch, not today's desired row or
// generated secrets. Cast only explicitly supplied fields; defaults must not
// turn a partial edit into an overwrite or change a restart replay fingerprint.
function normalizedLinkChanges(Link, changes) {
    if (!changes || typeof changes !== 'object' || Array.isArray(changes)) throw intentError('INVALID_TOPOLOGY_INTENT');
    const allowed = new Set([...DESIRED_LINK_FIELDS, 'autoDeploy',
        'geoRouting.enabled', 'geoRouting.domains', 'geoRouting.geoip']);
    if (Object.keys(changes).some(key => !allowed.has(key) || changes[key] === undefined)
        || (changes.geoRouting !== undefined && Object.keys(changes).some(key => key.startsWith('geoRouting.')))) {
        throw intentError('INVALID_TOPOLOGY_INTENT');
    }
    const document = new Link({ _id: '000000000000000000000000', ...changes });
    const error = document.validateSync(Object.keys(changes).filter(key =>
        key !== 'tunnelUuid' || typeof changes[key] !== 'string' || changes[key].trim()));
    if (error) throw error;
    return JSON.parse(JSON.stringify(Object.fromEntries(Object.keys(changes).map(key => [key, document.get(key)]))));
}
function applyLinkChanges(link, changes) {
    const candidate = JSON.parse(JSON.stringify(link));
    // The preparation callback owns its candidate, never the frozen request
    // arrays/objects retained in the intent payload and fingerprint.
    for (const [key, value] of Object.entries(JSON.parse(JSON.stringify(changes)))) {
        // Empty credential controls mean preserve, not generate a new tuple.
        if (['tunnelUuid', 'realityPrivateKey', 'realityPublicKey'].includes(key)
            && typeof value === 'string' && !value.trim()) continue;
        if (key === 'realityShortIds' && !value.some(Boolean)) continue;
        const parts = key.split('.');
        if (parts.length === 1) candidate[key] = value;
        else candidate[parts[0]] = { ...candidate[parts[0]], [parts[1]]: value };
    }
    return candidate;
}
function resourceIds(ids) {
    if (!Array.isArray(ids) || !ids.length || ids.length > 128
        || ids.some(id => typeof id !== 'string' || !/^[a-f0-9]{24}$/.test(id))) {
        throw intentError('TOPOLOGY_INTENT_RESOURCES_INVALID');
    }
    return [...new Set(ids)].sort();
}
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
        ...(row.unadmittedPreparation ? { unadmittedPreparation: row.unadmittedPreparation } : {}),
        ...(row.version === 2 ? { version: 2, kind: row.kind, linkId: String(row.linkId),
            ...(row.nodeActivation ? { nodeActivation: row.nodeActivation } : {}),
            desiredVersion: row.desiredVersion, desiredSaved: true, phase: row.status === 'waiting' ? 'waiting' : row.status,
            ...(row.waitingReason ? { waitingReason: row.waitingReason } : {}) } : {}),
    };
}
class TopologyIntentService {
    #executionContext;
    constructor(dependencies = {}) {
        const { TopologyCreateIntent, TopologyIntentQueueState, CascadeTopologyState, CascadeLink, capacity = 32, transactionRunner } = dependencies;
        const executionContext = topologyExecutionContext(
            dependencies.executionContext?.target, dependencies.executionContext?.hostIdentity,
        );
        if (!executionContext) throw new TypeError('Intent admission requires an exact server execution context');
        this.#executionContext = executionContext;
        this.dependencies = { ...dependencies, executionContext };
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
    get(id) {
        return this.TopologyCreateIntent.findOne({ _id: id,
            'executionContext.target': this.#executionContext.target,
            'executionContext.hostIdentity': this.#executionContext.hostIdentity }).lean().then(publicIntent);
    }
    async settleUnadmittedPreparation({ jobId, expectedTopologyRevision } = {}) {
        const unproven = () => intentError('TOPOLOGY_INTENT_RECONCILIATION_UNPROVEN');
        const { TopologyOperation, NodeOperationLock, intentOperationAdmission } = this.dependencies;
        if (this.#executionContext.target !== 'test' || this.#executionContext.hostIdentity !== 'test.infograd.online'
            || typeof jobId !== 'string' || !/^[a-f0-9]{24}$/.test(jobId) || !Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0
            || TopologyOperation?.db !== this.CascadeTopologyState.db || NodeOperationLock?.db !== this.CascadeTopologyState.db
            || intentOperationAdmission?.db !== this.CascadeTopologyState.db
            || typeof intentOperationAdmission.inspectUnadmittedPreparation !== 'function') throw unproven();
        await this.transactionRunner(async session => {
            const row = await this.TopologyCreateIntent.findOne({ _id: jobId,
                'executionContext.target': this.#executionContext.target,
                'executionContext.hostIdentity': this.#executionContext.hostIdentity }).session(session).lean();
            if (row?.status === 'failed' && ['INVALID_TOPOLOGY_DEPLOYMENT', 'TOPOLOGY_INTENT_PREPARE_FAILED'].includes(row.errorCode)
                && row.unadmittedPreparation?.revision === expectedTopologyRevision) return;
            if (!row || row.version !== 2 || row.kind !== 'link.apply' || row.status !== 'blocked'
                || row.errorCode !== 'TOPOLOGY_INTENT_PREPARE_UNCERTAIN' || row.operationId || row.operationIdempotencyKey
                || row.leaseOwner || row.leaseUntil || !Number.isSafeInteger(row.generation) || row.generation < 1
                || row.acceptanceRevision !== expectedTopologyRevision || row.unadmittedPreparation) throw unproven();
            // The consumer atomically binds the admitted operation to this job
            // before any dispatch. Refuse ANY prior history of this new link;
            // this is not recovery of a bound or potentially running command.
            const lid = String(row.linkId);
            if (await TopologyOperation.findOne({ $or: [{ linkId: lid }, { linkIds: lid },
                { 'effectiveTopology.links.id': lid }, { 'baselineTopology.links.id': lid }] }).session(session).lean()
                || await NodeOperationLock.findOne({ node: { $in: row.resourceNodeIds } }).session(session).lean()) throw unproven();
            const stateFilter = { _id: 'singleton', revision: expectedTopologyRevision,
                topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                replacementReservation: { $exists: false }, remoteDrain: { $exists: false } };
            if (!await this.CascadeTopologyState.findOne(stateFilter).session(session).lean()) throw unproven();
            const link = await this.CascadeLink.findById(row.linkId).session(session).lean();
            if (!link || linkDesiredVersion(link) !== row.desiredVersion || link.lifecycle) throw unproven();
            const observed = await intentOperationAdmission.inspectUnadmittedPreparation({ linkId: lid,
                desiredVersion: row.desiredVersion, session });
            // A corrected, never-admitted six-node first preparation can also
            // be settled as failed. This is a fresh valid preflight, not a
            // fabricated explanation of its historical unknown error.
            const nowValid = observed?.status === 'valid' && row.attempts === 1 && row.generation === 1
                && row.resourceNodeIds?.length === 6;
            if ((!nowValid && (observed?.status !== 'refused' || observed.code !== 'INVALID_TOPOLOGY_DEPLOYMENT'
                || observed.causeCode !== 'MULTIPLE_DEFAULT_EGRESS')) || observed.revision !== expectedTopologyRevision
                || JSON.stringify(observed.resourceNodeIds) !== JSON.stringify(row.resourceNodeIds)) throw unproven();
            const terminalCode = nowValid ? 'TOPOLOGY_INTENT_PREPARE_FAILED' : observed.code;
            const proof = { originalErrorCode: row.errorCode, observedCauseCode: nowValid ? 'VALID_PREFLIGHT_NO_ADMISSION' : observed.causeCode,
                revision: expectedTopologyRevision, generation: row.generation, confirmedAt: new Date() };
            const updated = await this.TopologyCreateIntent.updateOne({ _id: row._id, status: row.status,
                generation: row.generation, errorCode: row.errorCode, operationId: { $exists: false },
                desiredVersion: row.desiredVersion }, { $set: { status: 'failed', errorCode: terminalCode,
                    unadmittedPreparation: proof } }, { session });
            if (updated.matchedCount !== 1) throw unproven();
            const counter = await this.TopologyIntentQueueState.updateOne({ _id: QUEUE_ID, outstanding: { $gt: 0 } },
                { $inc: { outstanding: -1 } }, { session });
            const state = await this.CascadeTopologyState.updateOne(stateFilter,
                { $inc: { stateTransitionRevision: 1 } }, { session });
            if (counter.matchedCount !== 1 || state.matchedCount !== 1) throw unproven();
        });
        const confirmed = await this.TopologyCreateIntent.findOne({ _id: jobId,
            'executionContext.target': this.#executionContext.target,
            'executionContext.hostIdentity': this.#executionContext.hostIdentity })
            .read('primary').readConcern('majority').maxTimeMS(5000).lean();
        if (confirmed?.status !== 'failed' || !['INVALID_TOPOLOGY_DEPLOYMENT', 'TOPOLOGY_INTENT_PREPARE_FAILED'].includes(confirmed.errorCode)
            || confirmed.unadmittedPreparation?.revision !== expectedTopologyRevision || confirmed.operationId) throw unproven();
        return publicIntent(confirmed);
    }
    accept(input = {}) {
        if (input.version === 2) return this.acceptVersioned(input);
        if (input.version !== undefined && input.version !== 1) return Promise.reject(intentError('INVALID_TOPOLOGY_INTENT_VERSION'));
        if (input.kind !== undefined && input.kind !== 'link.create') return Promise.reject(intentError('INVALID_TOPOLOGY_INTENT'));
        return this.acceptLegacy(input);
    }
    // v2 create and explicit apply+changes accept normalized user fields BEFORE
    // credential generation. Ordinary apply/delete retain their content-pin API.
    // prepareLink is an optional LOCAL credential generator, never a remote preflight.
    async acceptVersioned({ kind, expectedTopologyRevision, requestKey, link, linkId, desiredVersion, changes, payloadHash, nodeActivation } = {}) {
        if (!INTENT_KINDS.has(kind) || payloadHash !== undefined) throw intentError('INVALID_TOPOLOGY_INTENT');
        if (nodeActivation !== undefined) {
            nodeActivation = normalizeNodeActivation(nodeActivation);
            if (kind !== 'link.apply' || changes !== undefined || this.dependencies.HyNode?.db !== this.CascadeLink.db) throw intentError('INVALID_TOPOLOGY_INTENT');
        }
        if (!Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) throw intentError('INVALID_TOPOLOGY_REVISION');
        if (typeof requestKey !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(requestKey)) throw intentError('INVALID_IDEMPOTENCY_KEY');
        let normalized, normalizedChanges;
        const editing = kind === 'link.apply' && changes !== undefined;
        if (changes !== undefined && !editing) throw intentError('INVALID_TOPOLOGY_INTENT');
        if (kind === 'link.create') {
            if (!link || typeof link !== 'object' || Array.isArray(link) || linkId !== undefined || desiredVersion !== undefined) throw intentError('INVALID_TOPOLOGY_INTENT');
            // Fixed placeholder prevents even ObjectId generation before persisted-key lookup.
            normalized = desiredLinkPayload(new this.CascadeLink({ ...link,
                _id: link._id ?? '000000000000000000000000', active: true }).toObject());
            if (link._id !== undefined) normalized._id = String(link._id);
        } else {
            if (link !== undefined || typeof linkId !== 'string' || !/^[a-f0-9]{24}$/.test(linkId)
                || (editing ? desiredVersion !== undefined
                    : typeof desiredVersion !== 'string' || !/^[a-f0-9]{64}$/.test(desiredVersion))) {
                throw intentError('INVALID_TOPOLOGY_INTENT');
            }
            if (editing) normalizedChanges = normalizedLinkChanges(this.CascadeLink, changes);
        }
        const fingerprint = digest({ version: 2, kind, ...(nodeActivation ? { nodeActivation } : {}), ...(normalized ? { link: normalized }
            : editing ? { linkId, changes: normalizedChanges } : { linkId, desiredVersion }) });
        if (Buffer.byteLength(JSON.stringify(normalized || normalizedChanges || {})) > 32768) throw intentError('TOPOLOGY_INTENT_PAYLOAD_TOO_LARGE');
        const findExisting = async (session, confirmDurable = false) => {
            const query = this.TopologyCreateIntent.findOne({ requestKey }).session(session);
            if (confirmDurable) query.readConcern('majority').read('primary').maxTimeMS(5000);
            const found = await query.lean();
            if (found && !matchesTopologyExecutionContext(found.executionContext, this.#executionContext)) throw intentError('TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH');
            if (found && (found.version !== 2 || found.payloadHash !== fingerprint)) throw intentError('TOPOLOGY_INTENT_KEY_CONFLICT');
            return found;
        };
        try {
            return await this.transactionRunner(async session => {
                const existing = await findExisting(session);
                if (existing) return publicIntent(existing);
                if (kind === 'link.create' || editing) {
                    if (['HyNode', 'CascadeRouteGroup', 'RelayL2tpState'].some(name => this.dependencies[name]?.db !== this.CascadeLink.db)) {
                        throw intentError('TOPOLOGY_INTENT_DRAFT_CONNECTION_MISMATCH');
                    }
                }
                if (kind === 'link.create') {
                    // Scoped commitDraft acknowledges its own runner before returning;
                    // that wrapper cannot own an outer transaction's commit lifetime.
                    const writer = this.dependencies.intentDraftWriter;
                    if ((writer !== undefined && (writer?.db !== this.CascadeLink.db || typeof writer?.createLink !== 'function'))
                        || (this.dependencies.withScopedNodeLocks && !writer)) throw intentError('TOPOLOGY_INTENT_DRAFT_TRANSACTION_UNAVAILABLE');
                }
                if (editing && (this.dependencies.intentDraftWriter?.db !== this.CascadeLink.db
                    || typeof this.dependencies.intentDraftWriter?.updateLink !== 'function')) {
                    throw intentError('TOPOLOGY_INTENT_DRAFT_TRANSACTION_UNAVAILABLE');
                }
                if (typeof this.dependencies.resolveIntentResources !== 'function') throw intentError('TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE');
                const state = await this.CascadeTopologyState.findOneAndUpdate(
                    { _id: 'singleton', revision: expectedTopologyRevision }, { $inc: { stateTransitionRevision: 1 } },
                    { new: true, session, upsert: false }).lean();
                if (!state) throw intentError('STALE_TOPOLOGY_REVISION');
                let queue = await this.TopologyIntentQueueState.findById(QUEUE_ID).session(session).lean();
                if (!queue) {
                    if (await this.TopologyCreateIntent.exists({}).session(session)) throw intentError('TOPOLOGY_INTENT_STATE_MISSING');
                    [queue] = await this.TopologyIntentQueueState.create([{ _id: QUEUE_ID, ordinal: 0, outstanding: 0 }], { session });
                }
                const counted = await this.TopologyIntentQueueState.findOneAndUpdate(
                    { _id: QUEUE_ID, outstanding: { $lt: this.capacity } }, { $inc: { outstanding: 1, ordinal: 1 } },
                    { new: true, session, runValidators: true }).lean();
                if (!counted) throw intentError('TOPOLOGY_INTENT_BACKLOG_FULL');
                const jobId = new this.TopologyCreateIntent()._id;
                let target;
                if (kind === 'link.create') {
                    const prepared = this.dependencies.prepareLink
                        ? await this.dependencies.prepareLink({ ...normalized })
                        : { ...normalized, tunnelUuid: normalized.tunnelUuid || randomUUID() };
                    const document = new this.CascadeLink({ ...prepared, active: true, status: 'pending', autoDeploy: true });
                    await document.validate();
                    target = JSON.parse(JSON.stringify(document.toObject()));
                    let saved;
                    if (this.dependencies.intentDraftWriter) {
                        // Same contract as draftWriteService.createLink plus the
                        // already-active session. Caller must hold any locks until
                        // THIS admission transaction, not this callback, commits.
                        saved = await this.dependencies.intentDraftWriter.createLink({ expectedTopologyRevision, link: target, session });
                    } else {
                        const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
                        const { TopologyDraftWriteService } = require('./topologyDraftWriteService');
                        // The unscoped repository supports a joined transactionRunner.
                        const repository = new TopologyDraftRepository({ ...this.dependencies, transactionRunner: work => work(session) });
                        saved = await new TopologyDraftWriteService({ repository }).createLink({ expectedTopologyRevision, link: target });
                    }
                    const persisted = await this.CascadeLink.findById(target._id).session(session).lean();
                    if (saved?.revision !== expectedTopologyRevision + 1 || !persisted
                        || linkDesiredVersion(persisted) !== linkDesiredVersion(target)) throw intentError('TOPOLOGY_INTENT_DRAFT_BINDING_INVALID');
                    target = persisted;
                    linkId = String(target._id);
                    desiredVersion = linkDesiredVersion(target);
                } else {
                    target = await this.CascadeLink.findById(linkId).session(session).lean();
                    if (!target) throw intentError('CASCADE_LINK_NOT_FOUND');
                    if (editing) {
                        if (target.lifecycle?.state === 'deleting') throw intentError('CASCADE_LINK_DELETING');
                        let candidate = applyLinkChanges(target, normalizedChanges);
                        if (candidate.tunnelSecurity === 'reality' && candidate.tunnelTransport === 'ws') throw intentError('INVALID_TOPOLOGY_INTENT');
                        if (candidate.tunnelSecurity === 'reality' && typeof this.dependencies.prepareLink !== 'function') {
                            throw intentError('TOPOLOGY_INTENT_PREPARATION_UNAVAILABLE');
                        }
                        // Only a new acceptance may generate credentials. Both the
                        // lookup and the final tombstone check use this transaction.
                        if (this.dependencies.prepareLink) candidate = await this.dependencies.prepareLink(candidate);
                        const document = new this.CascadeLink(candidate);
                        await document.validate();
                        candidate = JSON.parse(JSON.stringify(document.toObject()));
                        if (!candidate.active) throw intentError('CASCADE_LINK_DISABLED');
                        if (!Number.isInteger(candidate.tunnelPort) || candidate.tunnelPort < 1 || candidate.tunnelPort > 65535) throw intentError('INVALID_TOPOLOGY_INTENT');
                        const listener = value => String(value[(value.mode || 'reverse') === 'forward' ? 'bridgeNode' : 'portalNode']);
                        const siblings = await this.CascadeLink.find({ active: true, tunnelPort: candidate.tunnelPort,
                            _id: { $ne: linkId } }).session(session).lean();
                        if (siblings.some(row => listener(row) === listener(candidate))) throw intentError('CASCADE_LINK_CONFLICT');
                        // Pass the actual delta to draft validation. Its structural
                        // snapshot intentionally omits secrets/transport defaults;
                        // an unchanged full descriptor must not look like a key or
                        // endpoint migration on an installed policy-only edit.
                        const previous = desiredLinkPayload(target);
                        const delta = Object.fromEntries(Object.entries(desiredLinkPayload(candidate))
                            .filter(([key, value]) => !isDeepStrictEqual(previous[key], value)));
                        const saved = await this.dependencies.intentDraftWriter.updateLink({
                            expectedTopologyRevision, linkId, changes: { ...delta, autoDeploy: true }, session,
                        });
                        const persisted = await this.CascadeLink.findById(linkId).session(session).lean();
                        if (saved?.revision !== expectedTopologyRevision + 1 || !persisted
                            || linkDesiredVersion(persisted) !== linkDesiredVersion(candidate)) throw intentError('TOPOLOGY_INTENT_DRAFT_BINDING_INVALID');
                        target = persisted;
                        desiredVersion = linkDesiredVersion(target);
                    } else if (await selectedDesiredVersion(this.dependencies, target, nodeActivation, session) !== desiredVersion) throw intentError('TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT');
                }
                const resourceNodeIds = resourceIds(await this.dependencies.resolveIntentResources({ kind, link: target, desiredVersion, nodeActivation, session }));
                if (kind === 'link.delete') {
                    // CascadeLink's lifecycle schema is separately owned. Never substitute
                    // draft deletion for a same-connection operation-owned tombstone.
                    const writer = this.dependencies.deleteIntentWriter;
                    if (writer?.db !== this.CascadeLink.db || typeof writer?.markDeleting !== 'function') throw intentError('TOPOLOGY_INTENT_DELETE_WRITER_UNAVAILABLE');
                    const marked = await writer.markDeleting({ session, linkId, desiredVersion, jobId: String(jobId) });
                    if (marked?.matchedCount !== 1) throw intentError('TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT');
                    const retained = await this.CascadeLink.findById(linkId).session(session).lean();
                    if (!retained || linkDesiredVersion(retained) !== desiredVersion) throw intentError('TOPOLOGY_INTENT_DELETE_BINDING_INVALID');
                }
                const [row] = await this.TopologyCreateIntent.create([{
                    _id: jobId, executionContext: this.#executionContext, requestKey, version: 2, kind,
                    linkId, desiredVersion, resourceNodeIds, payloadHash: fingerprint,
                    ...(nodeActivation ? { nodeActivation } : {}),
                    payload: { kind, linkId, desiredVersion, ...(editing ? { changes: normalizedChanges } : {}) }, ordinal: counted.ordinal,
                    ...(kind === 'link.create' ? { createdLinkId: linkId } : {}),
                    acceptanceRevision: expectedTopologyRevision, status: 'waiting', attempts: 0, generation: 0,
                }], { session });
                return publicIntent(row);
            });
        } catch (error) {
            if (error?.code === 11000 || error?.hasErrorLabel?.('UnknownTransactionCommitResult')) {
                const existing = await findExisting(null, true);
                if (existing) return publicIntent(existing);
            }
            throw error;
        }
    }
    async acceptLegacy({ expectedTopologyRevision, requestKey = randomUUID(), link, payloadHash } = {}) {
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
            if (found && !matchesTopologyExecutionContext(found.executionContext, this.#executionContext)) {
                throw intentError('TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH');
            }
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
                    executionContext: this.#executionContext,
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
module.exports = { TopologyIntentService, createTopologyIntentService, publicIntent, digest, intentError, QUEUE_ID,
    INTENT_KINDS, desiredLinkPayload, linkDesiredVersion, resourceIds };
