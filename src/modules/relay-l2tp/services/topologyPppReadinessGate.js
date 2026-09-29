'use strict';

const { createL2tpNodeTransportResolver } = require('./l2tpNodeTransportFactory');
const { L2tpNodeExecutionResolver } = require('./l2tpNodeExecutionResolver');

const OPERATION_ID = /^[a-f0-9]{24}$/i;
const failed = verifiedRelayCount => ({ ok: false, verifiedRelayCount });
const id = value => value == null ? '' : String(value);

function stagedTerminalRelayRef(nodes) {
    let portalCount = 0;
    const relayNumbers = new Set();
    for (const node of nodes) {
        if (node?.role === 'portal' && node.nodeRef === 'portal') {
            portalCount += 1;
        } else if (node?.role === 'relay' && /^relay-[1-9]\d*$/.test(node.nodeRef)) {
            const number = Number(node.nodeRef.slice('relay-'.length));
            if (!Number.isSafeInteger(number) || relayNumbers.has(number)) return null;
            relayNumbers.add(number);
        } else {
            return null;
        }
    }
    if (portalCount !== 1 || relayNumbers.size === 0) return null;
    for (let number = 1; number <= relayNumbers.size; number += 1) {
        if (!relayNumbers.has(number)) return null;
    }
    return `relay-${relayNumbers.size}`;
}

class TopologyPppReadinessGate {
    constructor({ RelayL2tpState, L2tpUser, L2tpOperation, transportResolver } = {}) {
        if (typeof RelayL2tpState?.findOne !== 'function'
            || typeof L2tpUser?.find !== 'function'
            || typeof L2tpOperation?.findOne !== 'function'
            || typeof transportResolver !== 'function') {
            throw new TypeError('Topology PPP readiness requires state, users, operations and node transport');
        }
        this.RelayL2tpState = RelayL2tpState;
        this.L2tpUser = L2tpUser;
        this.L2tpOperation = L2tpOperation;
        this.transportResolver = transportResolver;
    }

    async verifyPlan(plan) {
        let verifiedRelayCount = 0;
        let skippedRelayCount = 0;
        try {
            if (!Array.isArray(plan?.nodes)) return failed(0);
            const terminalRelayRef = plan.staged === true ? stagedTerminalRelayRef(plan.nodes) : null;
            if (plan.staged === true && !terminalRelayRef) return failed(0);
            for (const node of plan.nodes) {
                if (node.role !== 'relay') continue;
                const relayNode = id(node.node);
                if (!relayNode) return failed(verifiedRelayCount);
                const state = await this.RelayL2tpState.findOne({ node: relayNode })
                    .select('node status desiredState secretRevision').lean();
                // Only an explicitly staged topology may omit PPP installation.
                // This is a skipped check, not evidence that the relay is ready.
                if (!state || state.desiredState === 'absent') {
                    if (plan.staged !== true || node.nodeRef !== terminalRelayRef) return failed(verifiedRelayCount);
                    skippedRelayCount += 1;
                    continue;
                }
                // A relay used only for transit has no PPP credentials to
                // read back. Skip it only when explicit durable non-installation,
                // zero users and no L2TP operation agree; an absent state is not
                // equivalent to this evidence.
                if (state.status === 'not_installed' && state.desiredState === 'not_installed') {
                    const users = await this.L2tpUser.find({ relayNode })
                        .select('_id').lean();
                    const activeOperation = await this.L2tpOperation.findOne({
                        node: relayNode, status: { $in: ['queued', 'running', 'rolling_back'] },
                    }).select('_id').lean();
                    const current = await this.RelayL2tpState.findOne({ node: relayNode })
                        .select('status desiredState').lean();
                    if (!Array.isArray(users) || users.length !== 0 || activeOperation
                        || current?.status !== 'not_installed'
                        || current.desiredState !== 'not_installed') {
                        return failed(verifiedRelayCount);
                    }
                    continue;
                }
                const revision = state.secretRevision;
                if (state.status !== 'installed' || state.desiredState !== 'installed'
                    || !Number.isSafeInteger(revision) || revision < 1) {
                    return failed(verifiedRelayCount);
                }
                const users = await this.L2tpUser.find({ relayNode })
                    .select('relayNode enabled desiredRevision appliedRevision syncStatus syncOperationId').lean();
                if (!Array.isArray(users)) return failed(verifiedRelayCount);
                const operation = await this.L2tpOperation.findOne({
                    node: relayNode,
                    kind: 'sync_users',
                    status: 'succeeded',
                    'plan.desired.credentialRevision': revision,
                }).sort({ finishedAt: -1, _id: -1 })
                    .select('_id node kind status plan.operationId plan.relayId plan.desired.credentialRevision').lean();
                const operationId = id(operation?._id);
                if (!OPERATION_ID.test(operationId)
                    || operation.kind !== 'sync_users'
                    || operation.status !== 'succeeded'
                    || id(operation.node) !== relayNode
                    || operation.plan?.operationId !== operationId
                    || operation.plan?.relayId !== relayNode
                    || operation.plan?.desired?.credentialRevision !== revision
                    || users.some(user => id(user.relayNode) !== relayNode
                        || typeof user.enabled !== 'boolean'
                        || !Number.isSafeInteger(user.desiredRevision)
                        || user.desiredRevision < 1
                        || user.desiredRevision > revision
                        || user.appliedRevision !== user.desiredRevision
                        || user.syncStatus !== 'synced'
                        || id(user.syncOperationId) !== operationId)) {
                    return failed(verifiedRelayCount);
                }
                const expectedEnabledUserCount = users.filter(user => user.enabled).length;
                const transport = await this.transportResolver({ nodeId: relayNode });
                const actual = await transport.runArtifactCommand({
                    operationId,
                    command: 'verify-users',
                    expectedCredentialRevision: revision,
                    expectedEnabledUserCount,
                });
                if (actual?.ok !== true || actual.code !== 'USERS_VERIFIED'
                    || actual.credentialRevision !== revision
                    || actual.enabledUserCount !== expectedEnabledUserCount
                    || actual.managedUserCount !== expectedEnabledUserCount) {
                    return failed(verifiedRelayCount);
                }
                // Concurrent user edits increment the state revision. Never accept
                // a readback against a snapshot already superseded in Mongo.
                const current = await this.RelayL2tpState.findOne({ node: relayNode })
                    .select('status desiredState secretRevision').lean();
                if (current?.status !== 'installed' || current.desiredState !== 'installed'
                    || current.secretRevision !== revision) return failed(verifiedRelayCount);
                verifiedRelayCount += 1;
            }
            return skippedRelayCount > 0
                ? { ok: true, verifiedRelayCount, skippedRelayCount }
                : { ok: true, verifiedRelayCount };
        } catch {
            // Includes SSH/runner, malformed result and database failures. Never
            // propagate stderr or credentials into topology operation logs.
            return failed(verifiedRelayCount);
        }
    }
}

function createTopologyPppReadinessGate({ RelayL2tpState, L2tpUser, L2tpOperation, HyNode, NodeSSH }) {
    const resolver = new L2tpNodeExecutionResolver({ HyNode, NodeSSH });
    return new TopologyPppReadinessGate({
        RelayL2tpState,
        L2tpUser,
        L2tpOperation,
        transportResolver: createL2tpNodeTransportResolver({ nodeExecutionResolver: resolver }),
    });
}

module.exports = { TopologyPppReadinessGate, createTopologyPppReadinessGate };
