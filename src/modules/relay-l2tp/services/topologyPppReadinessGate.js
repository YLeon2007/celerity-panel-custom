'use strict';

const { createL2tpNodeTransportResolver } = require('./l2tpNodeTransportFactory');
const { L2tpNodeExecutionResolver } = require('./l2tpNodeExecutionResolver');

const OPERATION_ID = /^[a-f0-9]{24}$/i;
// Only PPP_DRIFT is safe for a caller to use as a sync trigger.
const REASON = Object.freeze({
    DRIFT: 'PPP_DRIFT',
    UNAVAILABLE: 'PPP_UNAVAILABLE',
    NOT_INSTALLED: 'PPP_NOT_INSTALLED',
    UNKNOWN: 'PPP_UNKNOWN',
});
const SYNCABLE_USER_FAILURES = new Set([
    'MANAGED_USERS_MISSING', 'MANAGED_USERS_EXTRA', 'MANAGED_USERS_DUPLICATE',
    'MANAGED_USERS_ALTERED', 'DISABLED_USERS_PRESENT',
]);
const failed = (verifiedRelayCount, reason = REASON.UNKNOWN) => ({ ok: false, verifiedRelayCount, reason });
const drift = (verifiedRelayCount, relayNode, credentialRevision) => ({
    ...failed(verifiedRelayCount, REASON.DRIFT), relayNode, credentialRevision,
});
const id = value => value == null ? '' : String(value);

function stagedTerminalRelayRef(nodes) {
    let singlePortal = 0;
    const portalNumbers = new Set();
    const relayNumbers = new Set();
    for (const node of nodes) {
        if (node?.role === 'portal' && node.nodeRef === 'portal') {
            singlePortal += 1;
        } else if (node?.role === 'portal' && /^portal-[1-9]\d*$/.test(node.nodeRef)) {
            const number = Number(node.nodeRef.slice('portal-'.length));
            if (!Number.isSafeInteger(number) || portalNumbers.has(number)) return null;
            portalNumbers.add(number);
        } else if (node?.role === 'relay' && /^relay-[1-9]\d*$/.test(node.nodeRef)) {
            const number = Number(node.nodeRef.slice('relay-'.length));
            if (!Number.isSafeInteger(number) || relayNumbers.has(number)) return null;
            relayNumbers.add(number);
        } else {
            return null;
        }
    }
    if (!(singlePortal === 1 && portalNumbers.size === 0
        || singlePortal === 0 && portalNumbers.size >= 2)
        || relayNumbers.size === 0) return null;
    for (let number = 1; number <= portalNumbers.size; number += 1) {
        if (!portalNumbers.has(number)) return null;
    }
    for (let number = 1; number <= relayNumbers.size; number += 1) {
        if (!relayNumbers.has(number)) return null;
    }
    return `relay-${relayNumbers.size}`;
}

class TopologyPppReadinessGate {
    constructor({ RelayL2tpState, L2tpUser, L2tpOperation, transportResolver, readOnly = false } = {}) {
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
        this.readOnly = readOnly === true;
    }

    async verifyPlan(plan) {
        let verifiedRelayCount = 0;
        let skippedRelayCount = 0;
        const relayRevisions = [];
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
                // A non-PPP relay can be transit in a complete or staged
                // plan. A staged terminal with legacy explicit not_installed
                // state uses the same fenced checks, then stays blocked.
                if ((plan.staged !== true || node.nodeRef !== terminalRelayRef
                    || state?.desiredState === 'not_installed')
                    && state?.status === 'not_installed'
                    && ['absent', 'not_installed'].includes(state.desiredState)) {
                    const users = await this.L2tpUser.find({ relayNode })
                        .select('_id').lean();
                    const activeOperation = await this.L2tpOperation.findOne({
                        node: relayNode, status: { $in: ['queued', 'running', 'rolling_back'] },
                    }).select('_id').lean();
                    const current = await this.RelayL2tpState.findOne({ node: relayNode })
                        .select('status desiredState secretRevision').lean();
                    if (!Number.isSafeInteger(state.secretRevision)
                        || state.secretRevision < 0
                        || !Array.isArray(users) || users.length !== 0 || activeOperation
                        || current?.status !== 'not_installed'
                        || current.desiredState !== state.desiredState
                        || current.secretRevision !== state.secretRevision) {
                        return failed(verifiedRelayCount);
                    }
                    if (plan.staged === true && node.nodeRef === terminalRelayRef) skippedRelayCount += 1;
                    continue;
                }
                // Missing or desired-absent PPP is tolerated only at the
                // terminal relay of an explicitly staged chain.
                if (!state || state.desiredState === 'absent') {
                    if (plan.staged !== true || node.nodeRef !== terminalRelayRef) {
                        return failed(verifiedRelayCount, REASON.NOT_INSTALLED);
                    }
                    skippedRelayCount += 1;
                    continue;
                }
                const revision = state.secretRevision;
                if (state.status !== 'installed' || state.desiredState !== 'installed'
                    || !Number.isSafeInteger(revision) || revision < 1) {
                    return failed(verifiedRelayCount,
                        state.status === 'not_installed' || state.desiredState === 'not_installed'
                            ? REASON.NOT_INSTALLED : REASON.UNKNOWN);
                }
                const users = await this.L2tpUser.find({ relayNode })
                    .select('relayNode enabled desiredRevision appliedRevision syncStatus syncOperationId').lean();
                if (!Array.isArray(users)) return failed(verifiedRelayCount);
                // A typed, locally persisted desired/applied mismatch is drift;
                // malformed rows and unsynced statuses alone are not proof.
                const validUser = user => id(user.relayNode) === relayNode
                    && typeof user.enabled === 'boolean'
                    && Number.isSafeInteger(user.desiredRevision)
                    && user.desiredRevision >= 1 && user.desiredRevision <= revision
                    && Number.isSafeInteger(user.appliedRevision)
                    && user.appliedRevision >= 0;
                if (users.every(validUser)
                    && users.some(user => user.appliedRevision !== user.desiredRevision)) {
                    const current = await this.RelayL2tpState.findOne({ node: relayNode })
                        .select('status desiredState secretRevision').lean();
                    if (current?.status !== 'installed' || current.desiredState !== 'installed'
                        || current.secretRevision !== revision) return failed(verifiedRelayCount);
                    return drift(verifiedRelayCount, relayNode, revision);
                }
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
                let actual;
                try {
                    const transport = await this.transportResolver({ nodeId: relayNode });
                    const expectation = {
                        operationId,
                        expectedCredentialRevision: revision,
                        expectedEnabledUserCount,
                    };
                    actual = this.readOnly
                        ? await transport.verifyUsersReadOnly(expectation)
                        : await transport.runArtifactCommand({ ...expectation, command: 'verify-users' });
                } catch {
                    return failed(verifiedRelayCount, REASON.UNAVAILABLE);
                }
                if (actual?.ok !== true || actual.code !== 'USERS_VERIFIED'
                    || actual.credentialRevision !== revision
                    || actual.enabledUserCount !== expectedEnabledUserCount
                    || actual.managedUserCount !== expectedEnabledUserCount) {
                    const provenDrift = actual?.ok === false
                        && SYNCABLE_USER_FAILURES.has(actual.code)
                        && actual.credentialRevision === revision
                        && actual.enabledUserCount === expectedEnabledUserCount
                        && Number.isSafeInteger(actual.managedUserCount)
                        && actual.managedUserCount >= 0;
                    if (!provenDrift) return failed(verifiedRelayCount);
                    const current = await this.RelayL2tpState.findOne({ node: relayNode })
                        .select('status desiredState secretRevision').lean();
                    return current?.status === 'installed' && current.desiredState === 'installed'
                        && current.secretRevision === revision
                        ? drift(verifiedRelayCount, relayNode, revision)
                        : failed(verifiedRelayCount);
                }
                // Concurrent user edits increment the state revision. Never accept
                // a readback against a snapshot already superseded in Mongo.
                const current = await this.RelayL2tpState.findOne({ node: relayNode })
                    .select('status desiredState secretRevision').lean();
                if (current?.status !== 'installed' || current.desiredState !== 'installed'
                    || current.secretRevision !== revision) return failed(verifiedRelayCount);
                verifiedRelayCount += 1;
                relayRevisions.push({ relayNode, credentialRevision: revision });
            }
            return skippedRelayCount > 0
                ? { ok: true, verifiedRelayCount, skippedRelayCount, relayRevisions }
                : { ok: true, verifiedRelayCount, relayRevisions };
        } catch {
            // Includes SSH/runner, malformed result and database failures. Never
            // propagate stderr or credentials into topology operation logs.
            return failed(verifiedRelayCount);
        }
    }
}

function createTopologyPppReadinessGate({ RelayL2tpState, L2tpUser, L2tpOperation, HyNode, NodeSSH, readOnly = false }) {
    const resolver = new L2tpNodeExecutionResolver({ HyNode, NodeSSH });
    return new TopologyPppReadinessGate({
        RelayL2tpState,
        L2tpUser,
        L2tpOperation,
        readOnly,
        transportResolver: createL2tpNodeTransportResolver({ nodeExecutionResolver: resolver }),
    });
}

module.exports = { TopologyPppReadinessGate, createTopologyPppReadinessGate };
