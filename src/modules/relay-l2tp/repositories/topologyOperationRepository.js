'use strict';

const ACTIVE_STATUSES = Object.freeze([
    'preparing',
    'committing',
    'rolling_back',
]);
const TERMINAL_STATUSES = new Set(['succeeded', 'failed', 'rolled_back']);
const NODE_STATES = new Set(['prepared', 'committed', 'failed', 'rolled_back']);
const CLAIM_PROJECTION = Object.freeze({
    _id: 1,
    topologyRevision: 1,
    priorDeployedRevision: 1,
    status: 1,
    attempts: 1,
    leaseOwner: 1,
    leaseUntil: 1,
    'nodes.node': 1,
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

function durableCandidate(candidate) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
        || typeof candidate.mediaType !== 'string'
        || !Array.isArray(candidate.bytes)
        || typeof candidate.sha256 !== 'string') {
        throw new TypeError('Topology operation requires a durable candidate artifact');
    }
    return {
        mediaType: candidate.mediaType,
        bytes: [...candidate.bytes],
        sha256: candidate.sha256,
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
    }) {
        const metadata = nodes
            .map(node => ({
                node: node.node,
                state: 'pending',
                candidateHash: node.candidateHash,
                candidate: durableCandidate(node.candidate),
                backupId: '',
            }))
            .sort((left, right) => operationId(left.node).localeCompare(operationId(right.node)));
        return this.model.create({
            _id: id,
            topologyRevision,
            priorDeployedRevision,
            status: 'queued',
            attempts: 0,
            leaseOwner: '',
            leaseUntil: null,
            nodes: metadata,
        });
    }

    async claim({ operationId: id, owner, leaseMs, now }) {
        return this.model.findOneAndUpdate({
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
                leaseUntil: new Date(now.getTime() + leaseMs),
            },
            $inc: { attempts: 1 },
        }, {
            new: true,
            runValidators: true,
            lean: true,
            projection: CLAIM_PROJECTION,
        });
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
