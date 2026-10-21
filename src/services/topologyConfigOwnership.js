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
    if (node?._id) {
        const TopologyOperation = require('../modules/relay-l2tp/models/topologyOperationModel');
        // A server-persisted plan is a conservative veto of classic writes,
        // even after execution is disabled or link metadata/roles are edited.
        // This is NOT authority to adopt/mutate legacy PROD nodes: operation
        // history has no durable paired per-node adoption/handback contract.
        if (await TopologyOperation.exists({ $or: [
            { 'nodes.node': node._id, status: { $in: ['queued', 'preparing', 'committing', 'rolling_back'] } },
            { nodes: { $elemMatch: { node: node._id, state: { $in: ['prepared', 'committed', 'failed'] } } } },
            { 'nodes.node': node._id, heldTopologyAdmission: true },
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
