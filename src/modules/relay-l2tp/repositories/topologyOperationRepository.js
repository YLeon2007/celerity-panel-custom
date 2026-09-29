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
const SCOPED_OPERATION_KINDS = new Set(['link.apply', 'domain.reconcile', 'link.replace']);
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
    status: 1,
    attempts: 1,
    leaseOwner: 1,
    leaseUntil: 1,
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
    constructor({ model } = {}) {
        if (!model || typeof model.create !== 'function'
            || typeof model.findOneAndUpdate !== 'function'
            || typeof model.updateOne !== 'function') {
            throw new TypeError('Topology operation repository requires a durable model');
        }
        this.model = model;
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
        oldPathLinkIds,
        heldTopologyAdmission,
        admissionFingerprint,
        session,
    }) {
        const scoped = kind !== undefined || linkId !== undefined
            || linkIds !== undefined || staged !== undefined
            || oldLinkId !== undefined || groupId !== undefined || pathKey !== undefined
            || oldPathLinkIds !== undefined;
        if (scoped && (!SCOPED_OPERATION_KINDS.has(kind)
            || typeof linkId !== 'string' || linkId.length === 0
            || !Array.isArray(linkIds) || linkIds.length === 0
            || !linkIds.every(id => typeof id === 'string' && id.length > 0)
            || new Set(linkIds).size !== linkIds.length
            || !linkIds.includes(linkId)
            || (kind === 'link.apply' ? typeof staged !== 'boolean' : staged !== undefined)
            || (kind === 'link.replace'
                ? !['oldLinkId', 'groupId', 'pathKey'].every(key =>
                    typeof ({ oldLinkId, groupId, pathKey })[key] === 'string'
                    && ({ oldLinkId, groupId, pathKey })[key].length > 0)
                    || oldLinkId === linkId || linkIds.includes(oldLinkId)
                    || !Array.isArray(oldPathLinkIds) || oldPathLinkIds.length < 2
                    || oldPathLinkIds.at(-1) !== oldLinkId
                    || new Set(oldPathLinkIds).size !== oldPathLinkIds.length
                : oldLinkId !== undefined || groupId !== undefined || pathKey !== undefined
                    || oldPathLinkIds !== undefined))) {
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
                    oldPathLinkIds: [...oldPathLinkIds] } : {}),
            } : {}),
            status: 'queued',
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
        return this.model.findById(operationId)
            .select('status topologyRevision')
            .lean();
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
