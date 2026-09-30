'use strict';

const {
    projectCanonicalXrayCandidate,
} = require('../services/topologyXrayCandidate');
const { validNodeRef } = require('../services/topologyNodeRef');

const ACTIVE_STATUSES = Object.freeze([
    'preparing',
    'committing',
    'rolling_back',
]);
const TERMINAL_STATUSES = new Set(['succeeded', 'failed', 'rolled_back']);
const NODE_STATES = new Set(['pending', 'prepared', 'committed', 'failed', 'rolled_back']);
const SCOPED_OPERATION_KINDS = new Set(['link.apply', 'domain.reconcile', 'link.replace', 'link.attach']);
const TARGET_BY_ROLE = Object.freeze({
    portal: Object.freeze({
        targetProfile: 'xray-main',
        serviceUnit: 'xray.service',
        serviceUnitPath: '/etc/systemd/system/xray.service',
        configPath: '/usr/local/etc/xray/config.json',
    }),
    relay: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
    bridge: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
});
const CLAIM_PROJECTION = Object.freeze({
    _id: 1,
    topologyRevision: 1,
    priorDeployedRevision: 1,
    kind: 1,
    staged: 1,
    linkId: 1,
    linkIds: 1,
    groupId: 1,
    pathKey: 1,
    ownerNodeId: 1,
    ownerTopologyRevision: 1,
    ownerCredentialRevision: 1,
    newPathLinkIds: 1,
    status: 1,
    attempts: 1,
    leaseOwner: 1,
    leaseUntil: 1,
    heldTopologyAdmission: 1,
    pppWait: 1,
    'nodes.node': 1,
    'nodes.nodeRef': 1,
    'nodes.role': 1,
    'nodes.targetProfile': 1,
    'nodes.checks': 1,
    'nodes.state': 1,
    'nodes.candidateHash': 1,
    'nodes.candidate.mediaType': 1,
    'nodes.candidate.bytes': 1,
    'nodes.candidate.sha256': 1,
    'nodes.backupId': 1,
});

function operationId(value) {
    return value === null || value === undefined ? '' : String(value);
}

function hasExactKeys(value, keys) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}

function validChecks(checks, target) {
    return Array.isArray(checks) && checks.every(check => {
        if (check?.type === 'service') {
            return hasExactKeys(check, ['expectedState', 'serviceUnit', 'type'])
                && check.serviceUnit === target.serviceUnit
                && check.expectedState === 'active';
        }
        if (check?.type === 'port') {
            return hasExactKeys(check, ['expectedState', 'port', 'protocol', 'type'])
                && check.protocol === 'tcp'
                && Number.isSafeInteger(check.port)
                && check.port >= 1
                && check.port <= 65535
                && check.expectedState === 'listening';
        }
        return false;
    });
}

function durableCandidate(candidate, candidateHash) {
    const projected = {
        mediaType: candidate?.mediaType,
        bytes: Array.isArray(candidate?.bytes) ? [...candidate.bytes] : candidate?.bytes,
        sha256: candidate?.sha256,
    };
    return projectCanonicalXrayCandidate(projected, candidateHash).candidate;
}

function durableNodeMetadata(node) {
    const target = TARGET_BY_ROLE[node?.role];
    if (!target
        || !validNodeRef(node.role, node.nodeRef)
        || node.targetProfile !== target.targetProfile
        || node.serviceUnit !== target.serviceUnit
        || node.serviceUnitPath !== target.serviceUnitPath
        || node.configPath !== target.configPath
        || !validChecks(node.checks, target)) {
        throw new TypeError('Topology operation requires bound node metadata');
    }
    return {
        node: node.node,
        nodeRef: node.nodeRef,
        role: node.role,
        targetProfile: node.targetProfile,
        checks: node.checks.map(check => ({ ...check })),
        state: 'pending',
        candidateHash: node.candidateHash,
        candidate: durableCandidate(node.candidate, node.candidateHash),
        backupId: '',
    };
}

class TopologyOperationRepository {
    constructor({ model, topologyStateModel } = {}) {
        if (!model || typeof model.create !== 'function'
            || typeof model.findOneAndUpdate !== 'function'
            || typeof model.updateOne !== 'function') {
            throw new TypeError('Topology operation repository requires a durable model');
        }
        this.model = model;
        this.topologyStateModel = topologyStateModel;
    }

    async createFrozen({
        operationId: id,
        topologyRevision,
        priorDeployedRevision,
        nodes,
        kind,
        linkId,
        linkIds,
        staged,
        oldLinkId,
        groupId,
        pathKey,
        ownerNodeId,
        oldPathLinkIds,
        newPathLinkIds,
        ownerTopologyRevision,
        ownerCredentialRevision,
        heldTopologyAdmission,
        admissionFingerprint,
        session,
    }) {
        const scoped = kind !== undefined || linkId !== undefined
            || linkIds !== undefined || staged !== undefined
            || oldLinkId !== undefined || groupId !== undefined || pathKey !== undefined
            || oldPathLinkIds !== undefined || newPathLinkIds !== undefined
            || ownerNodeId !== undefined || ownerTopologyRevision !== undefined
            || ownerCredentialRevision !== undefined;
        if (scoped && (!SCOPED_OPERATION_KINDS.has(kind)
            || typeof linkId !== 'string' || linkId.length === 0
            || !Array.isArray(linkIds) || linkIds.length === 0
            || !linkIds.every(id => typeof id === 'string' && id.length > 0)
            || new Set(linkIds).size !== linkIds.length
            || !linkIds.includes(linkId)
            || (kind === 'link.apply' ? typeof staged !== 'boolean' : staged !== undefined)
            || (kind === 'link.replace'
                ? !['oldLinkId', 'groupId', 'pathKey', 'ownerNodeId'].every(key =>
                    typeof ({ oldLinkId, groupId, pathKey, ownerNodeId })[key] === 'string'
                    && ({ oldLinkId, groupId, pathKey, ownerNodeId })[key].length > 0)
                    || oldLinkId === linkId || linkIds.includes(oldLinkId)
                    || !Array.isArray(oldPathLinkIds) || oldPathLinkIds.length < 2
                    || oldPathLinkIds.at(-1) !== oldLinkId
                    || new Set(oldPathLinkIds).size !== oldPathLinkIds.length
                : kind === 'link.attach'
                    ? oldLinkId !== undefined || oldPathLinkIds !== undefined
                        || typeof groupId !== 'string' || groupId.length === 0
                        || pathKey !== 'main'
                        || typeof ownerNodeId !== 'string' || ownerNodeId.length === 0
                        || !Number.isSafeInteger(ownerTopologyRevision) || ownerTopologyRevision < 0
                        || !Number.isSafeInteger(ownerCredentialRevision) || ownerCredentialRevision < 0
                        || !Array.isArray(newPathLinkIds) || newPathLinkIds.length < 2
                        || newPathLinkIds.length >= linkIds.length
                        || newPathLinkIds.at(-1) !== linkId
                        || new Set(newPathLinkIds).size !== newPathLinkIds.length
                        || !newPathLinkIds.every(id => linkIds.includes(id))
                    : oldLinkId !== undefined || groupId !== undefined || pathKey !== undefined
                        || oldPathLinkIds !== undefined || ownerNodeId !== undefined)
            || (kind !== 'link.attach' && (newPathLinkIds !== undefined
                || ownerTopologyRevision !== undefined || ownerCredentialRevision !== undefined)))) {
            throw new TypeError('Invalid scoped topology operation identity');
        }
        const metadata = nodes.map(durableNodeMetadata);
        if (heldTopologyAdmission === true || admissionFingerprint !== undefined) {
            if (session === undefined || heldTopologyAdmission !== true
                || !/^[a-f0-9]{64}$/.test(admissionFingerprint)) {
                throw new TypeError('Held topology admission requires an active session and fingerprint');
            }
        }
        if (session !== undefined && heldTopologyAdmission !== true) {
            throw new TypeError('Session-bound topology operation requires a held admission identity');
        }
        const document = {
            _id: id,
            topologyRevision,
            priorDeployedRevision,
            ...(scoped ? { kind, linkId, linkIds: [...linkIds],
                ...(kind === 'link.apply' ? { staged } : {}),
                ...(kind === 'link.replace' ? { oldLinkId, groupId, pathKey,
                    ownerNodeId, oldPathLinkIds: [...oldPathLinkIds] } : {}),
                ...(kind === 'link.attach' ? { groupId, pathKey, ownerNodeId,
                    ownerTopologyRevision, ownerCredentialRevision,
                    newPathLinkIds: [...newPathLinkIds] } : {}),
            } : {}),
            status: 'queued',
            clientReadiness: 'unverified',
            clientProofAttempts: 0,
            clientProofRetryAfter: null,
            clientProofLeaseOwner: '',
            clientProofLeaseUntil: null,
            clientProofState: 'active_unverified',
            ...(heldTopologyAdmission === true
                ? { heldTopologyAdmission: true, admissionFingerprint } : {}),
            attempts: 0,
            leaseOwner: '',
            leaseUntil: null,
            nodes: metadata,
        };
        if (session === undefined) {
            throw new TypeError('Topology operation requires an active Mongo session');
        }
        if (!session || typeof session !== 'object'
            || typeof session.inTransaction !== 'function' || session.inTransaction() !== true) {
            throw new TypeError('Topology operation requires an active Mongo session');
        }
        const created = await this.model.create([document], { session });
        if (!Array.isArray(created) || created.length !== 1
            || !created[0] || typeof created[0] !== 'object'
            || created[0]._id === undefined || created[0]._id === null
            || String(created[0]._id) !== String(id)) {
            throw new TypeError('Topology operation session create returned an invalid result');
        }
        return created[0];
    }

    async findAdmissionById(operationId) {
        return this.model.findById(operationId)
            .select('status topologyRevision priorDeployedRevision heldTopologyAdmission admissionFingerprint')
            .lean();
    }

    async findPublicById(operationId) {
        const operation = await this.model.findById(operationId)
            .select('status topologyRevision priorDeployedRevision kind clientReadiness clientProofRevision clientProofState clientProofReason')
            .lean();
        if (!operation) return null;
        const verified = operation.status === 'succeeded'
            && operation.clientReadiness === 'verified'
            && Number.isSafeInteger(operation.clientProofRevision)
            && operation.clientProofRevision === operation.topologyRevision
            && await this.isLiveRevision(operation);
        // A missing legacy field (or unexpected persisted value) is never a
        // client-ready claim; status:succeeded remains execution-only.
        return {
            status: operation.status,
            topologyRevision: operation.topologyRevision,
            clientReadiness: verified ? 'verified' : 'unverified',
            ...(operation.status === 'succeeded' && operation.clientProofState
                && !verified ? { clientProofState: operation.clientProofState,
                    ...(!operation.clientProofReason ? {} : { clientProofReason: operation.clientProofReason }) }
                : {}),
        };
    }

    async isLiveRevision(operation) {
        if (!Number.isSafeInteger(operation?.topologyRevision) || !this.topologyStateModel?.findById) return false;
        try {
            const live = await this.topologyStateModel.findById('singleton')
                .select('revision deployedRevision').lean();
            return live?.revision === operation.topologyRevision
                && (SCOPED_OPERATION_KINDS.has(operation.kind)
                    ? live.deployedRevision === operation.priorDeployedRevision
                    : live.deployedRevision === operation.topologyRevision);
        } catch (_) {
            return false; // Missing or unreadable state cannot attest a client path.
        }
    }

    async claimNextClientProof({ owner, now, leaseMs = 120000, maxAttempts = 3 }) {
        if (!owner || !Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 3
            || !Number.isSafeInteger(leaseMs) || leaseMs < 1000) {
            throw new TypeError('Invalid client proof claim');
        }
        const leaseUntil = new Date(now.getTime() + leaseMs);
        return this.model.findOneAndUpdate({
            status: 'succeeded',
            clientReadiness: 'unverified',
            $nor: [{ kind: 'link.apply', staged: true }],
            clientProofAttempts: { $exists: true, $gte: 0, $lt: maxAttempts },
            $and: [
                { $or: [{ clientProofRetryAfter: { $lte: now } }, { clientProofRetryAfter: null }] },
                { $or: [{ clientProofLeaseUntil: { $lte: now } }, { clientProofLeaseUntil: null }] },
            ],
        }, {
            $set: { clientProofLeaseOwner: owner,
                clientProofLeaseUntil: leaseUntil,
                // Skip leased rows in the due-time index; after a crash both
                // retry time and lease become eligible together.
                clientProofRetryAfter: leaseUntil },
            $inc: { clientProofAttempts: 1 },
        }, {
            new: true, lean: true, runValidators: true, sort: { clientProofRetryAfter: 1 },
            projection: { _id: 1, status: 1, topologyRevision: 1, priorDeployedRevision: 1, kind: 1,
                linkId: 1, linkIds: 1, clientProofAttempts: 1,
                clientProofLeaseOwner: 1, clientProofLeaseUntil: 1,
                'nodes.node': 1, 'nodes.role': 1, 'nodes.state': 1 },
        });
    }

    async completeClientProof({ operation, owner, now, passed, reason, retryMs = 60000,
        maxAttempts = 3 }) {
        if (passed !== true && !['probe_failed', 'probe_unavailable', 'revision_stale'].includes(reason)) {
            throw new TypeError('Client proof requires a safe reason code');
        }
        // Check immediately before CAS. Public reads independently recheck live state.
        const live = passed === true && await this.isLiveRevision(operation);
        const verified = passed === true && live;
        const safeReason = verified ? undefined : passed === true ? 'revision_stale' : reason;
        const exhausted = operation.clientProofAttempts >= maxAttempts;
        const result = await this.model.updateOne({
            _id: operation._id, status: 'succeeded', clientReadiness: 'unverified',
            topologyRevision: operation.topologyRevision,
            clientProofAttempts: operation.clientProofAttempts,
            clientProofLeaseOwner: owner,
            clientProofLeaseUntil: { $gt: now },
        }, verified ? { $set: {
            clientReadiness: 'verified', clientProofRevision: operation.topologyRevision,
            clientProofLeaseOwner: '', clientProofLeaseUntil: null,
            clientProofRetryAfter: null,
        }, $unset: { clientProofState: 1, clientProofReason: 1 } } : { $set: {
            clientReadiness: 'unverified', clientProofState: exhausted ? 'degraded' : 'active_unverified',
            clientProofReason: exhausted ? 'retry_exhausted' : safeReason,
            clientProofRetryAfter: new Date(now.getTime() + retryMs),
            clientProofLeaseOwner: '', clientProofLeaseUntil: null,
        } }, { runValidators: true });
        return result.matchedCount === 1 ? (verified ? 'verified' : 'unverified') : null;
    }

    async claim({ operationId: id, owner, leaseMs, now }) {
        const lease = new Date(now.getTime() + leaseMs);
        const options = {
            new: true,
            runValidators: true,
            lean: true,
            projection: CLAIM_PROJECTION,
        };
        const claimed = await this.model.findOneAndUpdate({
            _id: id,
            $or: [
                { status: 'queued' },
                {
                    status: 'preparing',
                    leaseUntil: { $lte: now },
                    nodes: {
                        $not: {
                            $elemMatch: {
                                $or: [
                                    { state: { $ne: 'pending' } },
                                    { backupId: { $ne: '' } },
                                ],
                            },
                        },
                    },
                },
            ],
        }, {
            $set: {
                status: 'preparing',
                leaseOwner: owner,
                leaseUntil: lease,
            },
            $inc: { attempts: 1 },
        }, options);
        if (claimed) return claimed;

        return this.model.findOneAndUpdate({
            _id: id,
            status: { $in: [...ACTIVE_STATUSES] },
            leaseUntil: { $lte: now },
        }, {
            $set: {
                leaseOwner: owner,
                leaseUntil: lease,
            },
            $inc: { attempts: 1 },
        }, options);
    }

    async beginPppWait({ operationId: id, owner, now, relayNode, credentialRevision, locks }) {
        if (typeof relayNode !== 'string' || !relayNode
            || !Number.isSafeInteger(credentialRevision) || credentialRevision < 1
            || !Array.isArray(locks) || !locks.length
            || new Set(locks.map(lock => lock.node)).size !== locks.length
            || locks.some(lock => typeof lock.node !== 'string' || !lock.node
                || typeof lock.generation !== 'string' || !lock.generation)) {
            throw new TypeError('Invalid PPP wait identity');
        }
        const result = await this.model.updateOne({
            _id: id, status: 'committing', heldTopologyAdmission: true,
            pppWait: { $exists: false }, leaseOwner: owner, leaseUntil: { $gt: now },
            'nodes.node': relayNode,
        }, { $set: { pppWait: { lockOwner: owner, relayNode, credentialRevision,
            locks: locks.map(lock => ({ node: lock.node, generation: lock.generation })),
            releasedNodes: [], probeLocks: [] } } }, { runValidators: true });
        return result.matchedCount === 1;
    }

    async acknowledgePppLockRelease({ operationId: id, owner, now, node, generation, lockOwner }) {
        const result = await this.model.updateOne({
            _id: id, status: 'committing', heldTopologyAdmission: true,
            leaseOwner: owner, leaseUntil: { $gt: now },
            'pppWait.lockOwner': lockOwner,
            'pppWait.locks': { $elemMatch: { node, generation } },
        }, { $addToSet: { 'pppWait.releasedNodes': node } }, { runValidators: true });
        return result.matchedCount === 1;
    }

    async recordPppProbeLock({ operationId: id, owner, now, node, generation }) {
        if (typeof generation !== 'string' || !generation) throw new TypeError('Invalid probe lock');
        const result = await this.model.updateOne({
            _id: id, status: 'committing', heldTopologyAdmission: true,
            leaseOwner: owner, leaseUntil: { $gt: now },
            'pppWait.releasedNodes': node,
            'pppWait.probeLocks.node': { $ne: node },
        }, { $push: { 'pppWait.probeLocks': { node, owner, generation } } },
        { runValidators: true });
        return result.matchedCount === 1;
    }

    async acknowledgePppProbeLockRelease({ operationId: id, owner, now,
        node, generation, lockOwner }) {
        const result = await this.model.updateOne({
            _id: id, status: 'committing', heldTopologyAdmission: true,
            leaseOwner: owner, leaseUntil: { $gt: now },
            'pppWait.probeLocks': { $elemMatch: { node, owner: lockOwner, generation } },
        }, { $pull: { 'pppWait.probeLocks': { node, owner: lockOwner, generation } } },
        { runValidators: true });
        return result.matchedCount === 1;
    }

    async renewLease({ operationId: id, owner, leaseMs, now }) {
        const result = await this.model.updateOne({
            _id: id,
            status: { $in: [...ACTIVE_STATUSES] },
            leaseOwner: owner,
            leaseUntil: { $gt: now },
        }, {
            $set: { leaseUntil: new Date(now.getTime() + leaseMs) },
        }, { runValidators: true });
        return result.matchedCount === 1;
    }

    async setPhase({ operationId: id, owner, now, from, to }) {
        if (!ACTIVE_STATUSES.includes(from) || !ACTIVE_STATUSES.includes(to)) {
            throw new TypeError('Invalid topology operation phase');
        }
        const result = await this.model.updateOne({
            _id: id,
            status: from,
            leaseOwner: owner,
            leaseUntil: { $gt: now },
        }, {
            $set: { status: to },
        }, { runValidators: true });
        return result.matchedCount === 1;
    }

    async recordNode({
        operationId: id,
        owner,
        now,
        node,
        state,
        candidateHash,
        backupId,
    }) {
        if (!NODE_STATES.has(state)) throw new TypeError('Invalid topology node state');
        const fields = { 'nodes.$.state': state };
        if (candidateHash !== undefined) fields['nodes.$.candidateHash'] = candidateHash;
        if (backupId !== undefined) fields['nodes.$.backupId'] = backupId;
        const result = await this.model.updateOne({
            _id: id,
            status: { $in: [...ACTIVE_STATUSES] },
            leaseOwner: owner,
            leaseUntil: { $gt: now },
            'nodes.node': node,
        }, { $set: fields }, { runValidators: true });
        return result.matchedCount === 1;
    }

    async finishClaimed({ operationId: id, owner, now, status }) {
        if (!TERMINAL_STATUSES.has(status)) {
            throw new TypeError('Invalid topology operation terminal status');
        }
        const result = await this.model.updateOne({
            _id: id,
            status: { $in: [...ACTIVE_STATUSES] },
            leaseOwner: owner,
            leaseUntil: { $gt: now },
        }, {
            $set: {
                status,
                finishedAt: now,
                leaseUntil: null,
            },
        }, { runValidators: true });
        return result.matchedCount === 1;
    }
}

module.exports = {
    ACTIVE_STATUSES,
    NODE_STATES,
    TERMINAL_STATUSES,
    TopologyOperationRepository,
};
