'use strict';

const {
    topologyExecutionContext, matchesTopologyExecutionContext, TOPOLOGY_EXECUTION_CONTEXTS,
} = require('../modules/relay-l2tp/domain/topologyExecutionContext');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const scalarMatch = (value, pattern) => typeof value === 'string' && pattern.test(value);
const uuid = value => scalarMatch(value, UUID);
const digest = value => scalarMatch(value, /^[a-f0-9]{64}$/);
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
function uncertain() {
    throw Object.assign(new Error('CONFIG_OWNERSHIP_UNCERTAIN'), { code: 'CONFIG_OWNERSHIP_UNCERTAIN' });
}
function validReceipt(receipt) {
    return receipt && uuid(receipt.proofId) && uuid(receipt.maintenanceId)
        && uuid(receipt.fromGeneration) && uuid(receipt.toGeneration)
        && receipt.fromGeneration !== receipt.toGeneration
        && nonempty(receipt.oldBackendInstanceId) && nonempty(receipt.oldProcessStartTime)
        && Number.isSafeInteger(receipt.oldPid) && receipt.oldPid > 0
        && receipt.verifiedAt instanceof Date && Number.isFinite(receipt.verifiedAt.getTime());
}
function validSnapshot(snapshot) {
    return snapshot && digest(snapshot.configSha256) && digest(snapshot.unitSha256)
        && ['active', 'inactive'].includes(snapshot.serviceActive)
        && ['enabled', 'disabled', 'masked'].includes(snapshot.serviceEnabled);
}
function ownerVeto(rows, nodeId, context, ObjectId) {
    if (!Array.isArray(rows) || rows.length > 2) uncertain();
    const profiles = new Set();
    for (const row of rows) {
        if (!row || !(typeof row.node === 'string' || row.node instanceof ObjectId)
            || String(row.node) !== nodeId
            || !['xray-main', 'xray-bridge'].includes(row.profile) || profiles.has(row.profile)
            || !matchesTopologyExecutionContext(row.executionContext, context)
            || !['classic', 'topology'].includes(row.owner) || !uuid(row.generation)
            || !scalarMatch(row.nodeIdentity?.machineId, /^[a-f0-9]{32}$/)
            || !digest(row.nodeIdentity?.sshHostKeySha256)) uncertain();
        profiles.add(row.profile);
        if (row.owner === 'topology') continue; // A veto, never adoption authority.
        const hasHistory = ['originalSnapshot', 'adoptionReceipt', 'handbackReceipt',
            'lastSettledOperation', 'lastSettledGeneration', 'lastSettledRevision',
            'lastSettledCloseId', 'executionBindingCheck'].some(key => Object.hasOwn(row, key));
        if (hasHistory && (!validSnapshot(row.originalSnapshot)
            || !validReceipt(row.adoptionReceipt) || !validReceipt(row.handbackReceipt)
            || row.handbackReceipt.fromGeneration !== row.adoptionReceipt.toGeneration
            || row.handbackReceipt.toGeneration !== row.generation
            || row.adoptionReceipt.fromGeneration === row.generation)) uncertain();
    }
    // No precise profile is supplied by these legacy callers. Conservatively
    // veto either adopted profile; mutable roles must not choose ownership.
    return rows.some(row => row.owner === 'topology');
}

// A completed V2 settlement already carries the checked permanent-owner fence.
// Handback invalidates that generation for future binding-store dispatch. Only
// its exact settled rows become history; a classic label/receipt alone never
// retires pending, uncertain, legacy or foreign-generation execution evidence.
function handedBackHistory(operation, owners, nodeId, context) {
    const { isDeepStrictEqual: same } = require('node:util');
    const { validTerminalReceipt } = require('../modules/relay-l2tp/models/topologyExecutionBindingContract');
    const terminal = operation?.v2Terminal;
    if (operation?.status !== 'succeeded' || operation.heldTopologyAdmission !== false
        || !matchesTopologyExecutionContext(operation.executionContext, context)
        || terminal?.state !== 'proven' || terminal.sideEffects?.usersVerified !== true
        || !Array.isArray(operation.nodes) || !Array.isArray(terminal.bindings)
        || !Array.isArray(terminal.proofs) || !Array.isArray(terminal.ownerFences)
        || [terminal.bindings, terminal.proofs, terminal.ownerFences].some(rows => rows.length !== operation.nodes.length)) return false;
    const nodes = operation.nodes.filter(entry => String(entry.node) === nodeId);
    if (nodes.length !== 1) return false;
    const node = nodes[0], owner = owners.find(row => row.profile === node.targetProfile);
    if (node.state !== 'committed' || owner?.owner !== 'classic' || !owner.handbackReceipt) return false;
    const index = terminal.bindings.findIndex(binding => binding.nodeId === nodeId && binding.targetProfile === node.targetProfile);
    if (index < 0 || terminal.bindings.filter(binding => binding.nodeId === nodeId).length !== 1) return false;
    const binding = terminal.bindings[index], proof = terminal.proofs[index];
    const expectedFence = { node: nodeId, profile: owner.profile, executionContext: context, owner: 'topology',
        generation: owner.handbackReceipt.fromGeneration, nodeIdentity: owner.nodeIdentity,
        originalSnapshot: owner.originalSnapshot, adoptionReceipt: owner.adoptionReceipt };
    return same(terminal.ownerFences[index], expectedFence)
        && binding.operationId === String(operation._id) && binding.executionContext === context?.hostIdentity
        && binding.owner === operation.leaseOwner && binding.attempt === operation.attempts
        && binding.topologyRevision === operation.topologyRevision && binding.priorDeployedRevision === operation.priorDeployedRevision
        && binding.candidateHash === `sha256:${node.candidateHash}` && binding.backupId === node.backupId
        && uuid(binding.generation) && uuid(binding.attemptId) && uuid(binding.commandIds?.close)
        && validTerminalReceipt(proof, binding) && proof.terminalOutcome === 'verified';
}

const APPLIED_LINK_STATUSES = Object.freeze(['staged', 'deployed', 'online']);

// Compatibility for the already topology-managed TEST installation only.
// Production opt-in permits execution, not adoption of every legacy node/link.
function usesTestTopologyConfig(node, env = process.env) {
    return !!topologyExecutionContext('test', env.PANEL_DOMAIN)
        && ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED']
            .every(flag => env[flag] === 'true')
        && ['portal', 'relay', 'bridge'].includes(node?.cascadeRole);
}

async function topologyManagesNodeConfig(node, env = process.env) {
    const testCompatibility = usesTestTopologyConfig(node, env);
    const context = TOPOLOGY_EXECUTION_CONTEXTS.find(candidate => candidate.hostIdentity === env.PANEL_DOMAIN);
    const releaseEnv = Object.freeze({ PANEL_DOMAIN: env.PANEL_DOMAIN,
        TOPOLOGY_TEST_EXECUTION_ENABLED: env.TOPOLOGY_TEST_EXECUTION_ENABLED,
        TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED });
    let historicalVeto = false, historyQuery, TopologyOperation;
    if (node?._id) {
        TopologyOperation = require('../modules/relay-l2tp/models/topologyOperationModel');
        historyQuery = { $or: [
            { 'nodes.node': node._id, status: { $in: ['queued', 'preparing', 'committing', 'rolling_back'] } },
            { nodes: { $elemMatch: { node: node._id, state: { $in: ['prepared', 'committed', 'failed'] } } } },
            { 'nodes.node': node._id, heldTopologyAdmission: true },
        ] };
        historicalVeto = !!await TopologyOperation.exists(historyQuery);
        // Handback never waives active or retained work, including pending rows
        // with no terminal receipt. Preserve the independent finite TEST path.
        if (historicalVeto && await TopologyOperation.exists({ 'nodes.node': node._id, $or: [
            { status: { $in: ['queued', 'preparing', 'committing', 'rolling_back'] } },
            { heldTopologyAdmission: true },
        ] })) return true;
    }
    if (node?._id) {
        // Native read only: importing the owner model here would register an
        // autoCreate/autoIndex candidate on otherwise dormant installations.
        const mongoose = require('mongoose');
        const rows = await mongoose.connection.db.collection('topologyconfigowners').find({
            node: new mongoose.Types.ObjectId(String(node._id)),
        }, { readPreference: 'primary', readConcern: { level: 'majority' },
            maxTimeMS: 5000, timeoutMS: 5000, limit: 3 }).toArray();
        if (ownerVeto(rows, String(node._id), context, mongoose.Types.ObjectId)) return true;
        const handedBack = rows.some(row => row.handbackReceipt);
        if (historicalVeto || handedBack) {
            let settled = false;
            if (handedBack) {
                // A receipt is not evidence about a pending/unknown resource.
                // Check every operation touching this node, not only the older
                // prepared/committed compatibility veto. No history remains a
                // valid pre-native handback; contradictory nonempty evidence
                // must not disappear between the existence and full reads.
                const operations = await TopologyOperation.find({ 'nodes.node': node._id })
                    .read('primary').readConcern('majority').maxTimeMS(5000).lean();
                settled = Array.isArray(operations) && (!historicalVeto || operations.length > 0)
                    && operations.every(operation => handedBackHistory(operation, rows, String(node._id), context));
            }
            if (!settled) {
                if (!historicalVeto) return true;
                const { hasTestLegacyTopologyRelease } = require('./testLegacyTopologyRelease');
                if (!await hasTestLegacyTopologyRelease({ db: mongoose.connection.db,
                    nodeId: String(node._id), env: releaseEnv })) return true;
            }
        }
        // The TEST role/status heuristic predates paired ownership. It cannot
        // re-adopt a profile just restored and handed back by the public CAS.
        if (handedBack) return false;
    }
    if (!testCompatibility) return false;
    const CascadeLink = require('../models/cascadeLinkModel');
    return !!(await CascadeLink.exists({
        active: true,
        status: { $in: APPLIED_LINK_STATUSES },
        $or: [{ portalNode: node._id }, { bridgeNode: node._id }],
    }));
}

module.exports = { APPLIED_LINK_STATUSES, usesTestTopologyConfig, topologyManagesNodeConfig };
