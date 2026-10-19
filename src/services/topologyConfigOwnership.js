'use strict';

const { topologyExecutionContext } = require('../modules/relay-l2tp/domain/topologyExecutionContext');

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
    if (!testCompatibility) return false;
    const CascadeLink = require('../models/cascadeLinkModel');
    return !!(await CascadeLink.exists({
        active: true,
        status: { $in: APPLIED_LINK_STATUSES },
        $or: [{ portalNode: node._id }, { bridgeNode: node._id }],
    }));
}

module.exports = { APPLIED_LINK_STATUSES, usesTestTopologyConfig, topologyManagesNodeConfig };
