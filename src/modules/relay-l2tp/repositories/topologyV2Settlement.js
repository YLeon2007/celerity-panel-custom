'use strict';

const { isDeepStrictEqual: same } = require('node:util');
const { recordKeysFor, exact, UUID, validTerminalReceipt, freeze } = require('../models/topologyExecutionBindingContract');
const { assertProfileTargetPin, verifyImportedProfileTargetPin, resolveTopologyProfileTarget, assertSelectedProfileTargets } = require('../services/topologyProfileTarget');
const { selectedAdmissionFingerprint } = require('./topologyOperationRepository');
const { matchesTopologyOperationClaimBinding } = require('../domain/topologyOperationClaimBinding');
const { topologyExecutionContext } = require('../domain/topologyExecutionContext');
const { isTopologyTerminalProof } = require('../services/topologyOperationExecutor');
const OPTIONS = { maxTimeMS: 5000, timeoutMS: 5000 };
const DEADLINES = new WeakMap();
function refused() { throw Object.assign(new Error('V2 terminal settlement unconfirmed'), { code: 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED' }); }
function record(row) {
    try {
        return freeze(Object.fromEntries(recordKeysFor(row).map(key => [key, key === 'profileTargetPin'
            ? assertProfileTargetPin(row[key]) : key === 'commandIds' ? { ...row[key] } : row?.[key]])));
    } catch { refused(); }
}
function samePin(left, right) {
    return left && right && Object.hasOwn(left, 'profileTargetPin') === Object.hasOwn(right, 'profileTargetPin')
        && same(left.profileTargetPin, right.profileTargetPin);
}
function operationTargets(operation) {
    try {
        assertSelectedProfileTargets(operation);
        if (operation.nodes?.some(node => Object.hasOwn(node, 'profileTargetPin'))
            && operation.admissionFingerprint !== selectedAdmissionFingerprint(operation)) refused();
    } catch { refused(); }
}
function checkedTargets(operation, binding, row, enrolled, owner) {
    try {
        if (!exact(binding, recordKeysFor(binding))) refused();
        const nodes = operation.nodes.filter(node => String(node.node) === binding.nodeId);
        if (nodes.length !== 1 || !samePin(nodes[0], binding) || !samePin(row, binding)
            || !samePin(enrolled, binding) || !samePin(owner, binding)) refused();
        const node = nodes[0];
        resolveTopologyProfileTarget({ nodeId: binding.nodeId, role: node.role, targetProfile: node.targetProfile,
            ...(Object.hasOwn(binding, 'profileTargetPin') ? { profileTargetPin: binding.profileTargetPin } : {}) });
        if (operation.admissionScope === 'selected') {
            const pins = operation.selectedOwnerPins?.filter(pin => String(pin.node) === binding.nodeId);
            if (pins?.length !== 1 || !samePin(pins[0], binding)) refused();
        }
        if (Object.hasOwn(binding, 'profileTargetPin')) {
            verifyImportedProfileTargetPin({ owner, profileTargetPin: binding.profileTargetPin, executionContext: operation.executionContext });
            if (binding.profileTargetPin.ownerGeneration !== row.ownerGeneration
                || row.ownerGeneration !== enrolled.ownerGeneration || row.ownerGeneration !== owner.generation) refused();
        } else if (owner.legacyAppliedTopology?.links?.some(link => link.mode === 'forward')) refused();
    } catch { refused(); }
}
const OWNER_PRIVATE_FIELDS = '+legacyAppliedTopology +profileTargetPin';
const OPERATION_PRIVATE_FIELDS = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath';
function ownerFence(owner) {
    return { node: String(owner.node), profile: owner.profile, executionContext: owner.executionContext,
        owner: owner.owner, generation: owner.generation, nodeIdentity: owner.nodeIdentity,
        originalSnapshot: owner.originalSnapshot, adoptionReceipt: owner.adoptionReceipt };
}
function assertOwnerFences(terminal, rows) {
    if (!Array.isArray(terminal?.ownerFences) || !same(terminal.ownerFences, rows.map(({ owner }) => ownerFence(owner)))) refused();
}

// One attempt, including the commit command. Unknown commit/readback never runs
// the callback again, rolls back remotely, releases separately, or mints IDs.
// Driver transaction.transition is pinned compatibility, as in the initializer.
async function once(repository, work, confirm) {
    const db = repository.TopologyOperation.db;
    const session = await db.startSession();
    let attempted = false, result;
    try {
        if (typeof session.transaction?.transition !== 'function') refused();
        session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
        result = await work(session);
        if (Date.now() >= DEADLINES.get(session)) refused();
        attempted = true;
        try {
            const reply = await db.getClient().db('admin').command({ commitTransaction: 1,
                ...(session.transaction.recoveryToken ? { recoveryToken: session.transaction.recoveryToken } : {}),
                writeConcern: { w: 'majority', wtimeout: 5000 }, maxTimeMS: 5000 }, { session, ...OPTIONS });
            if (reply.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length || reply.errorLabels?.length) refused();
        } finally { session.transaction.transition('TRANSACTION_COMMITTED'); }
        await confirm(result);
    } catch (error) {
        if (!attempted && session.inTransaction()) await session.abortTransaction().catch(() => {});
        throw error;
    } finally { await session.endSession(); }
    return result;
}
function models(repository) {
    const entries = ['TopologyOperation', 'CascadeTopologyState', 'NodeOperationLock', 'TopologyConfigOwner',
        'TopologyExecutionBinding', 'TopologyExecutionEnrollment'].map(key => repository[key]);
    if (entries.some(model => !model?.db || model.db !== entries[0].db)) refused();
}
async function majority(model, filter, privateFields) {
    const query = model.findOne(filter).read('primary').readConcern('majority').setOptions(OPTIONS);
    if (privateFields) query.select(privateFields);
    return query.lean();
}
function operationFilter(request) {
    return { _id: request.operationId, status: 'committing', heldTopologyAdmission: true,
        topologyRevision: request.topologyRevision, priorDeployedRevision: request.priorDeployedRevision,
        leaseOwner: request.owner, leaseUntil: { $eq: request.leaseUntil, $gt: new Date() }, pppWait: { $exists: false } };
}
async function checked(repository, request, session, bindings) {
    models(repository);
    const operation = await repository.TopologyOperation.findOne(operationFilter(request)).select(OPERATION_PRIVATE_FIELDS).session(session).setOptions(OPTIONS).lean();
    const context = operation?.executionContext;
    if (!operation || !matchesTopologyOperationClaimBinding(operation, topologyExecutionContext(context?.target, context?.hostIdentity))
        || operation.status !== 'committing' || operation.heldTopologyAdmission !== true
        || operation.leaseOwner !== request.owner || !(operation.leaseUntil instanceof Date)
        || operation.leaseUntil.getTime() !== request.leaseUntil.getTime() || operation.leaseUntil <= new Date()
        || operation.topologyRevision !== request.topologyRevision || operation.priorDeployedRevision !== request.priorDeployedRevision
        || !Number.isSafeInteger(operation.attempts) || operation.attempts < 1
        || !Array.isArray(bindings) || bindings.length !== operation.nodes?.length || !bindings.length
        || new Set(bindings.map(binding => binding.nodeId)).size !== bindings.length) refused();
    operationTargets(operation);
    const topology = await repository.CascadeTopologyState.findById('singleton').session(session).setOptions(OPTIONS).lean();
    if (operation.admissionScope === 'selected') {
        if (!repository.selectedTopologyRepository || topology?.topologyAdmissionCount < 1
            || topology.replacementReservation !== undefined) refused();
        await repository.selectedTopologyRepository.verifySelected(operation, session);
    } else if (topology?.revision !== request.topologyRevision || topology.deployedRevision !== request.priorDeployedRevision
        || topology.topologyAdmissionCount !== 1 || topology.replacementReservation !== undefined) refused();
    const rows = [];
    let deadline = operation.leaseUntil.getTime();
    for (const binding of bindings) {
        const row = await repository.TopologyExecutionBinding.findOne({ operationId: request.operationId,
            nodeId: binding.nodeId, targetProfile: binding.targetProfile }).session(session).setOptions(OPTIONS).lean();
        if (!row || !same(record(row), binding) || binding.operationId !== request.operationId
            || binding.owner !== request.owner || binding.attempt !== operation.attempts
            || binding.executionContext !== context.hostIdentity
            || binding.topologyRevision !== request.topologyRevision || binding.priorDeployedRevision !== request.priorDeployedRevision
            || !['generation', 'attemptId', 'bootId', 'maintenanceId'].every(key => typeof binding[key] === 'string' && UUID.test(binding[key]))
            || !Object.values(binding.commandIds).every(value => typeof value === 'string' && UUID.test(value))) refused();
        const nodes = operation.nodes.filter(node => String(node.node) === binding.nodeId);
        if (nodes.length !== 1 || nodes[0].state !== 'committed'
            || nodes[0].targetProfile !== binding.targetProfile || `sha256:${nodes[0].candidateHash}` !== binding.candidateHash
            || nodes[0].backupId !== binding.backupId) refused();
        const enrolled = await repository.TopologyExecutionEnrollment.findById(row.enrollmentId).session(session).setOptions(OPTIONS).lean();
        if (!enrolled || ['nodeId', 'targetProfile', 'executionContext', 'bootId', 'maintenanceId', 'ownerGeneration'].some(key => enrolled[key] !== row[key])
            || !same(enrolled.nodeIdentity, row.nodeIdentity) || !same(enrolled.endpoint, row.endpoint)) refused();
        const lock = await repository.NodeOperationLock.findOne({ node: binding.nodeId }).session(session).setOptions(OPTIONS).lean();
        if (!lock || lock.owner !== binding.owner || lock.operationId !== binding.operationId
            || lock.generation !== binding.generation || lock.remoteUncertain !== true
            || !(lock.leaseUntil instanceof Date) || lock.leaseUntil <= new Date()) refused();
        const owner = await repository.TopologyConfigOwner.findOne({ node: binding.nodeId, profile: binding.targetProfile })
            .select(OWNER_PRIVATE_FIELDS).session(session).setOptions(OPTIONS).lean();
        if (!owner || !same(owner.executionContext, context) || owner.owner !== 'topology'
            || owner.generation !== row.ownerGeneration || !same(owner.nodeIdentity, row.nodeIdentity)
            || !owner.originalSnapshot || !owner.adoptionReceipt || owner.handbackReceipt !== undefined
            || owner.adoptionReceipt.toGeneration !== row.ownerGeneration) refused();
        checkedTargets(operation, binding, row, enrolled, owner);
        // Exact row predicates below turn snapshot checks into write conflicts;
        // never delete a replacement/foreign generation, even after lease expiry.
        deadline = Math.min(deadline, lock.leaseUntil.getTime());
        rows.push({ binding, row, owner, lock });
    }
    DEADLINES.set(session, deadline);
    if (Date.now() >= deadline) refused();
    return { operation, rows };
}
async function fence(repository, rows, session, settle) {
    for (const { binding, owner, lock } of rows) {
        const update = await repository.TopologyConfigOwner.updateOne(owner, { $set: settle ? {
            lastSettledOperation: binding.operationId, lastSettledGeneration: binding.generation,
            lastSettledRevision: binding.topologyRevision, lastSettledCloseId: binding.commandIds.close,
        } : { executionBindingCheck: binding.commandIds.close } }, { session, ...OPTIONS, runValidators: true });
        if (update.matchedCount !== 1) refused();
        if (settle) {
            if ((await repository.NodeOperationLock.deleteOne(lock, { session, ...OPTIONS })).deletedCount !== 1) refused();
        } else {
            if ((await repository.NodeOperationLock.updateOne(lock, { $set: { executionBindingCheck: binding.commandIds.close } },
                { session, ...OPTIONS })).matchedCount !== 1) refused();
        }
    }
}
async function begin(repository, request) {
    let bindings;
    try {
        if (!Array.isArray(request.bindings) || request.bindings.some(binding => !exact(binding, recordKeysFor(binding)))) refused();
        bindings = freeze(request.bindings.map(record));
    } catch { refused(); }
    return once(repository, async session => {
        const { operation, rows } = await checked(repository, request, session, bindings);
        if (operation.v2Terminal !== undefined) refused();
        await fence(repository, rows, session, false);
        const terminal = { bindings, ownerFences: rows.map(({ owner }) => ownerFence(owner)), proofs: [], state: 'closing' };
        if ((await repository.TopologyOperation.updateOne({ ...operationFilter(request), v2Terminal: { $exists: false } },
            { $set: { v2Terminal: terminal } }, { session, ...OPTIONS, runValidators: true })).matchedCount !== 1) refused();
        return terminal;
    }, async terminal => {
        const current = await majority(repository.TopologyOperation, operationFilter(request), OPERATION_PRIVATE_FIELDS);
        if (!same(current?.v2Terminal, terminal)) refused();
        await confirmRoots(repository, current, terminal);
    });
}
async function fenceSideEffects(repository, operation, effects, session) {
    if (!effects || effects.usersVerified !== true || typeof effects.attachVerified !== 'boolean'
        || effects.attachVerified !== (operation.kind === 'link.attach' || Boolean(operation.installedPath))
        || !Array.isArray(effects.pppProof)
        || new Set(effects.pppProof.map(proof => proof.relayNode)).size !== effects.pppProof.length) refused();
    const relays = operation.nodes.filter(node => node.role === 'relay').map(node => String(node.node));
    if (effects.pppProof.some(proof => !relays.includes(proof.relayNode)
        || typeof proof.relayNode !== 'string' || !Number.isSafeInteger(proof.credentialRevision) || proof.credentialRevision < 1)) refused();
    const skipped = effects.skippedPppProof ?? [];
    if (!Array.isArray(skipped) || skipped.some(proof => typeof proof?.relayNode !== 'string'
        || !relays.includes(proof.relayNode) || proof.state !== 'not_installed'
        || !['absent', 'not_installed'].includes(proof.desiredState)
        || !Number.isSafeInteger(proof.credentialRevision) || proof.credentialRevision < 0)
        || new Set([...effects.pppProof, ...skipped].map(proof => proof.relayNode)).size !== relays.length
        || effects.pppProof.length + skipped.length !== relays.length) refused();
    if (!relays.length) return;
    if (repository.RelayL2tpState?.db !== repository.TopologyOperation.db) refused();
    for (const node of relays) {
        const proof = effects.pppProof.find(item => item.relayNode === node);
        // Never reread/adopt the current epoch for an omitted PPP proof. The
        // gate's original zero-user/no-active-sync observation must survive
        // both persistence and publication; the producer writes this same row.
        const absent = skipped.find(item => item.relayNode === node);
        if (absent) {
            if (['HyNode', 'L2tpUser', 'L2tpOperation'].some(key => repository[key]?.db !== repository.TopologyOperation.db)) refused();
            const inventory = await repository.HyNode.findById(node).select('_id cascadeRole')
                .session(session).setOptions(OPTIONS).lean();
            const user = await repository.L2tpUser.findOne({ relayNode: node }).select('_id')
                .session(session).setOptions(OPTIONS).lean();
            const active = await repository.L2tpOperation.findOne({ node, status: { $in: ['queued', 'running', 'rolling_back'] } })
                .select('_id').session(session).setOptions(OPTIONS).lean();
            if (String(inventory?._id) !== node || inventory.cascadeRole !== 'relay' || user || active) refused();
            // These snapshot reads alone do not exclude a new user/queue row.
            // The exact ORIGINAL epoch write below conflicts with the actual
            // producer's reserveCredentialRevision in the same transaction.
        }
        const filter = proof
            ? { node, status: 'installed', desiredState: 'installed', secretRevision: proof.credentialRevision }
            : { node, status: 'not_installed', desiredState: absent.desiredState, secretRevision: absent.credentialRevision };
        const updated = await repository.RelayL2tpState.updateOne(filter, { $inc: { replacementFence: 1 } }, { session, ...OPTIONS });
        if (updated.matchedCount !== 1) refused();
    }
}
async function persist(repository, request) {
    return once(repository, async session => {
        const stored = await repository.TopologyOperation.findById(request.operationId).session(session).setOptions(OPTIONS).lean();
        const terminal = stored?.v2Terminal;
        const { operation, rows } = await checked(repository, request, session, terminal?.bindings);
        if (terminal.state !== 'closing' || !Array.isArray(request.proofs) || request.proofs.length !== rows.length
            || request.proofs.some((proof, index) => !isTopologyTerminalProof(proof)
                || !validTerminalReceipt(proof, rows[index].binding) || proof.terminalOutcome !== 'verified')) refused();
        assertOwnerFences(terminal, rows);
        await fenceSideEffects(repository, operation, request.sideEffects, session);
        await fence(repository, rows, session, false);
        const next = { ...terminal, proofs: request.proofs, sideEffects: request.sideEffects, state: 'proven' };
        if ((await repository.TopologyOperation.updateOne({ ...operationFilter(request), v2Terminal: terminal },
            { $set: { v2Terminal: next } }, { session, ...OPTIONS, runValidators: true })).matchedCount !== 1) refused();
        return next;
    }, async terminal => {
        const current = await majority(repository.TopologyOperation, operationFilter(request), OPERATION_PRIVATE_FIELDS);
        if (!same(current?.v2Terminal, terminal)) refused();
        await confirmRoots(repository, current, terminal);
    });
}
async function settle(repository, request, publish) {
    return once(repository, async session => {
        const stored = await repository.TopologyOperation.findById(request.operationId).session(session).setOptions(OPTIONS).lean();
        const terminal = stored?.v2Terminal;
        const { operation, rows } = await checked(repository, request, session, terminal?.bindings);
        if (terminal.state !== 'proven' || terminal.proofs.length !== rows.length
            || terminal.proofs.some((proof, index) => !validTerminalReceipt(proof, rows[index].binding)
                || proof.terminalOutcome !== 'verified')) refused();
        assertOwnerFences(terminal, rows);
        await fenceSideEffects(repository, operation, terminal.sideEffects, session);
        await fence(repository, rows, session, true);
        if (!session.inTransaction() || !DEADLINES.has(session) || typeof publish !== 'function') refused();
        const finalized = await publish(session);
        if (!finalized) refused();
        return { ...finalized, terminal, selected: operation.admissionScope === 'selected' };
    }, async result => {
        const operation = await majority(repository.TopologyOperation, { _id: request.operationId }, OPERATION_PRIVATE_FIELDS);
        const topology = await majority(repository.CascadeTopologyState, { _id: 'singleton' });
        if (operation?.status !== 'succeeded' || operation.heldTopologyAdmission !== false
            || !same(operation.v2Terminal, result.terminal)
            || !Number.isSafeInteger(topology?.topologyAdmissionCount) || topology.topologyAdmissionCount < 0
            || (!result.selected && (topology?.topologyAdmissionCount !== 0 || topology.deployedRevision !== result.deployedRevision))) refused();
        for (const binding of result.terminal.bindings) {
            if (await majority(repository.NodeOperationLock, { node: binding.nodeId, generation: binding.generation })) refused();
            const owner = await majority(repository.TopologyConfigOwner, { node: binding.nodeId, profile: binding.targetProfile }, OWNER_PRIVATE_FIELDS);
            if (owner?.owner !== 'topology' || owner.lastSettledOperation !== binding.operationId
                || owner.lastSettledGeneration !== binding.generation || owner.lastSettledCloseId !== binding.commandIds.close) refused();
        }
        await confirmRoots(repository, operation, result.terminal);
    });
}
async function probe(repository, operationId) {
    models(repository);
    const operation = await majority(repository.TopologyOperation, { _id: operationId }, OPERATION_PRIVATE_FIELDS);
    if (!operation?.v2Terminal) return null;
    const terminal = operation.v2Terminal;
    if (!Array.isArray(terminal.bindings) || !terminal.bindings.length
        || terminal.bindings.length !== operation.nodes?.length
        || new Set(terminal.bindings.map(binding => binding.nodeId)).size !== terminal.bindings.length
        || !['closing', 'proven'].includes(terminal.state)) refused();
    await confirmRoots(repository, operation, terminal);
    for (const [index, binding] of terminal.bindings.entries()) {
        const row = await majority(repository.TopologyExecutionBinding, { operationId, nodeId: binding.nodeId,
            targetProfile: binding.targetProfile });
        if (!same(record(row), binding) || binding.operationId !== operationId
            || binding.executionContext !== operation.executionContext?.hostIdentity
            || binding.attempt !== operation.attempts) refused();
        if (terminal.state === 'proven' && (!validTerminalReceipt(terminal.proofs?.[index], binding)
            || terminal.proofs[index].terminalOutcome !== 'verified')) refused();
    }
    if (operation.status === 'succeeded' && (operation.heldTopologyAdmission !== false
        || terminal.state !== 'proven' || terminal.proofs.length !== terminal.bindings.length
        || terminal.sideEffects?.usersVerified !== true || !Array.isArray(terminal.sideEffects.pppProof))) refused();
    // Read-only recovery: no lease renewal/claim, remote bootstrap, new command
    // IDs, publication retry, rollback, release or admission decrement.
    return freeze({ operationId, status: operation.status, retained: operation.heldTopologyAdmission !== false,
        terminal: structuredClone(operation.v2Terminal), nodes: operation.nodes.map(node => ({ nodeId: String(node.node), role: node.role,
            ...(Object.hasOwn(node, 'profileTargetPin') ? { profileTargetPin: assertProfileTargetPin(node.profileTargetPin) } : {}) })) });
}
async function confirmRoots(repository, operation, terminal) {
    operationTargets(operation);
    const owners = [];
    for (const binding of terminal.bindings) {
        const row = await majority(repository.TopologyExecutionBinding, { operationId: binding.operationId,
            nodeId: binding.nodeId, targetProfile: binding.targetProfile });
        if (!row || !same(record(row), binding)) refused();
        const enrolled = await majority(repository.TopologyExecutionEnrollment, { _id: row.enrollmentId });
        const owner = await majority(repository.TopologyConfigOwner, { node: binding.nodeId, profile: binding.targetProfile }, OWNER_PRIVATE_FIELDS);
        if (!owner || !enrolled || ['nodeId', 'targetProfile', 'executionContext', 'bootId', 'maintenanceId', 'ownerGeneration'].some(key => enrolled[key] !== row[key])
            || !same(enrolled.nodeIdentity, row.nodeIdentity) || !same(enrolled.endpoint, row.endpoint)
            || owner.owner !== 'topology' || owner.generation !== row.ownerGeneration
            || !same(owner.executionContext, operation.executionContext) || !same(owner.nodeIdentity, row.nodeIdentity)
            || owner.handbackReceipt !== undefined || owner.adoptionReceipt?.toGeneration !== row.ownerGeneration
            || owner.adoptionReceipt?.proofId !== row.ownerReceiptProofId) refused();
        checkedTargets(operation, binding, row, enrolled, owner);
        owners.push({ owner });
    }
    assertOwnerFences(terminal, owners);
}
module.exports = { begin, persist, settle, probe };
