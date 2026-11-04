'use strict';

const { selectExecutionContext } = require('../domain/l2tpExecutionAuthorization');
const { ownedIngressRouteState } = require('./topologyAttachIngressGate');

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

function classifyStagedRelays(nodes, topology) {
    let singlePortal = 0;
    let defaultBridge = 0;
    const portalNumbers = new Set();
    const relayNumbers = new Set();
    const geoBridgeNumbers = new Set();
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
        } else if (node?.role === 'bridge' && ['bridge', 'bridge-1'].includes(node.nodeRef)) {
            // Multi-exit composition numbers the default bridge as bridge-1;
            // it is still a real PPP exit when no portal has been added yet.
            defaultBridge += 1;
        } else if (node?.role === 'bridge' && /^bridge-[1-9]\d*$/.test(node.nodeRef)) {
            const number = Number(node.nodeRef.slice('bridge-'.length));
            if (!Number.isSafeInteger(number) || number < 2 || geoBridgeNumbers.has(number)) return null;
            geoBridgeNumbers.add(number);
        } else {
            return null;
        }
    }
    const hasPortalInput = singlePortal === 1 && portalNumbers.size === 0
        || singlePortal === 0 && portalNumbers.size >= 2;
    const noPortalInput = singlePortal === 0 && portalNumbers.size === 0;
    const sourceLessSuffix = noPortalInput && defaultBridge === 1;
    const relayOnlyFragment = noPortalInput && defaultBridge === 0 && geoBridgeNumbers.size === 0;
    if (relayNumbers.size === 0 || !(hasPortalInput && defaultBridge === 0
        || sourceLessSuffix || relayOnlyFragment)) return null;
    for (let number = 1; number <= portalNumbers.size; number += 1) {
        if (!portalNumbers.has(number)) return null;
    }
    for (let number = 1; number <= relayNumbers.size; number += 1) {
        if (!relayNumbers.has(number)) return null;
    }
    for (let number = 2; number <= geoBridgeNumbers.size + 1; number += 1) {
        if (!geoBridgeNumbers.has(number)) return null;
    }
    if (relayOnlyFragment) {
        // New source-less/bridge-less shapes need the actual pinned graph,
        // not just two role labels. Keep malformed legacy ref-only plans out.
        const ordered = [...nodes].sort((a, b) => Number(a.nodeRef.slice(6)) - Number(b.nodeRef.slice(6)));
        if (ordered.length < 2 || !Array.isArray(topology?.nodes) || !Array.isArray(topology.links)
            || topology.nodes.length !== ordered.length || topology.links.length !== ordered.length - 1
            || new Set(ordered.map(node => id(node.node))).size !== ordered.length
            || new Set(topology.nodes.map(node => node.id)).size !== ordered.length
            || topology.nodes.some(node => node.role !== 'relay'
                || ordered.filter(entry => entry.node === node.id).length !== 1)
            || ordered.slice(0, -1).some((node, index) => topology.links.filter(link =>
                link.source === node.node && link.target === ordered[index + 1].node
                && ['forward', 'reverse'].includes(link.mode) && link.geo !== true
                && link.geoRouting?.enabled !== true).length !== 1)) return null;
    }
    // Missing portal input is not missing PPP egress. R-to-B remains staged
    // for portal traffic, but every installed relay still needs its ordinary
    // credential/user/node readback. Only a bridge-less prefix has a terminal
    // relay at which legacy absent PPP can be explicitly recorded as skipped.
    return { terminalRelayRef: sourceLessSuffix ? null : `relay-${relayNumbers.size}` };
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
        const skippedRelayRevisions = [];
        try {
            if (!Array.isArray(plan?.nodes)) return failed(0);
            const ownerBound = plan.ownerCredentialRevision !== undefined;
            const blocked = plan.routeState === 'no_bridge_exit';
            // Route incompleteness is independent of PPP installation. Ordinary
            // non-PPP prefixes have no installed group/owner to bind; each relay
            // still passes its persisted user/operation/credential fences below.
            if (ownerBound && (!ownedIngressRouteState(plan)
                || !Number.isSafeInteger(plan.ownerCredentialRevision) || plan.ownerCredentialRevision < 1
                || !Number.isSafeInteger(plan.ownerTopologyRevision) || plan.ownerTopologyRevision < 0)) return failed(0);
            const stagedRelays = plan.staged === true ? classifyStagedRelays(plan.nodes, plan.effectiveTopology) : null;
            if (plan.staged === true && !stagedRelays && !(blocked && ownerBound)) return failed(0);
            const terminalRelayRef = stagedRelays?.terminalRelayRef;
            for (const node of plan.nodes) {
                if (node.role !== 'relay') continue;
                const relayNode = id(node.node);
                if (!relayNode) return failed(verifiedRelayCount);
                const state = await this.RelayL2tpState.findOne({ node: relayNode })
                    .select('node status desiredState secretRevision routeGroup activePathKey appliedTopologyRevision').lean();
                const isOwner = ownerBound && relayNode === plan.ownerNodeId;
                const ownerMatches = current => !isOwner || current?.status === 'installed'
                    && current.desiredState === 'installed' && id(current.routeGroup) === plan.groupId
                    && current.activePathKey === plan.pathKey
                    && current.appliedTopologyRevision === plan.ownerTopologyRevision
                    && current.secretRevision === plan.ownerCredentialRevision;
                if (!ownerMatches(state)) return failed(verifiedRelayCount);
                // A non-PPP relay can be transit in a complete or staged
                // plan. A staged terminal with legacy explicit not_installed
                // state uses the same fenced checks, then stays blocked.
                if (state?.status === 'not_installed'
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
                    skippedRelayRevisions.push({ relayNode, state: 'not_installed',
                        desiredState: state.desiredState, credentialRevision: state.secretRevision });
                    if (plan.staged === true && node.nodeRef === terminalRelayRef) skippedRelayCount += 1;
                    continue;
                }
                // Missing or desired-absent PPP is tolerated only at the
                // terminal relay of an explicitly staged chain.
                if (!state || state.desiredState === 'absent') {
                    if (plan.staged !== true || node.nodeRef !== terminalRelayRef) {
                        return failed(verifiedRelayCount, REASON.NOT_INSTALLED);
                    }
                    // Missing state has no serializable document fence. Record
                    // that observation, but terminal settlement must refuse it.
                    skippedRelayRevisions.push({ relayNode, state: 'unfenced' });
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
                        .select('status desiredState secretRevision routeGroup activePathKey appliedTopologyRevision').lean();
                    if (current?.status !== 'installed' || current.desiredState !== 'installed'
                        || current.secretRevision !== revision || !ownerMatches(current)) return failed(verifiedRelayCount);
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
                        .select('status desiredState secretRevision routeGroup activePathKey appliedTopologyRevision').lean();
                    return current?.status === 'installed' && current.desiredState === 'installed'
                        && current.secretRevision === revision && ownerMatches(current)
                        ? drift(verifiedRelayCount, relayNode, revision)
                        : failed(verifiedRelayCount);
                }
                // Concurrent user edits increment the state revision. Never accept
                // a readback against a snapshot already superseded in Mongo.
                const current = await this.RelayL2tpState.findOne({ node: relayNode })
                    .select('status desiredState secretRevision routeGroup activePathKey appliedTopologyRevision').lean();
                if (current?.status !== 'installed' || current.desiredState !== 'installed'
                    || current.secretRevision !== revision || !ownerMatches(current)) return failed(verifiedRelayCount);
                verifiedRelayCount += 1;
                relayRevisions.push({ relayNode, credentialRevision: revision });
            }
            return { ok: true, verifiedRelayCount, ...(skippedRelayCount > 0 ? { skippedRelayCount } : {}),
                relayRevisions, ...(skippedRelayRevisions.length ? { skippedRelayRevisions } : {}),
                ...(blocked ? { routeOutcome: { state: 'no_bridge_exit', internetProof: 'not_applicable',
                    ...(ownerBound ? { blockedOwnerNodeId: plan.ownerNodeId } : {}) } } : {}) };
        } catch {
            // Includes SSH/runner, malformed result and database failures. Never
            // propagate stderr or credentials into topology operation logs.
            return failed(verifiedRelayCount);
        }
    }
}

function createTopologyPppReadinessGate({ RelayL2tpState, L2tpUser, L2tpOperation, HyNode, NodeSSH,
    executionContext, enableProductionExecution = false, readOnly = false, restrictedRunner = false }) {
    if (restrictedRunner === true) {
        // The executor provides the exact already-pinned transport only inside
        // its held mutation scope. No independent credential/bootstrap path.
        const { invokeTopologyReadiness } = require('./topologyReadinessScope');
        return new TopologyPppReadinessGate({ RelayL2tpState, L2tpUser, L2tpOperation, readOnly: true,
            transportResolver: async ({ nodeId }) => ({ verifyUsersReadOnly: expectation =>
                invokeTopologyReadiness(nodeId, 'verify-ppp-users', expectation) }) });
    }
    const authorization = Object.freeze({ executionContext: selectExecutionContext(executionContext),
        enableProductionExecution: enableProductionExecution === true });
    const resolver = new L2tpNodeExecutionResolver({ ...authorization, HyNode, NodeSSH });
    const resolveTransport = createL2tpNodeTransportResolver({
        ...authorization, nodeExecutionResolver: resolver,
    });
    return new TopologyPppReadinessGate({
        RelayL2tpState,
        L2tpUser,
        L2tpOperation,
        readOnly,
        transportResolver: request => resolveTransport({ ...request, executionContext: authorization.executionContext }),
    });
}

module.exports = { TopologyPppReadinessGate, createTopologyPppReadinessGate };
