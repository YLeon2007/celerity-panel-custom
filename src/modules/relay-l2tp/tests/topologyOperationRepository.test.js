'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    TopologyOperationRepository,
} = require('../repositories/topologyOperationRepository');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const CANDIDATE_MEDIA_TYPE = 'application/vnd.celerity.xray-topology-node+json;version=1';

function candidate(role, nodeRef, targetProfile) {
    const content = `${JSON.stringify({
        schemaVersion: 1,
        kind: 'xray-topology-node-candidate',
        mode: 'forward',
        nodeRef,
        role,
        targetProfile,
        links: [],
        checks: [],
    })}\n`;
    return {
        mediaType: CANDIDATE_MEDIA_TYPE,
        bytes: [...Buffer.from(content, 'utf8')],
        sha256: createHash('sha256').update(content).digest('hex'),
    };
}

function createModel() {
    const calls = [];
    return {
        calls,
        async create(document) {
            calls.push({ method: 'create', document });
            return document;
        },
        async findOneAndUpdate(query, update, options) {
            calls.push({ method: 'findOneAndUpdate', query, update, options });
            return null;
        },
        async updateOne(query, update, options) {
            calls.push({ method: 'updateOne', query, update, options });
            return { matchedCount: 1 };
        },
    };
}

test('createFrozen persists only sorted allowlisted durable candidate artifacts', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    const bridgeCandidate = candidate('bridge', 'bridge', 'xray-bridge');
    const portalCandidate = candidate('portal', 'portal', 'xray-main');

    const created = await repository.createFrozen({
        operationId: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [
            {
                node: 'node-b',
                candidateHash: bridgeCandidate.sha256,
                candidate: {
                    ...bridgeCandidate,
                    sshPassword: 'ssh-secret-canary',
                },
                rawShell: 'raw-shell-canary',
            },
            {
                node: 'node-a',
                candidateHash: portalCandidate.sha256,
                candidate: portalCandidate,
                tunnelPsk: 'tunnel-secret-canary',
            },
        ],
        secret: 'top-level secret',
    });

    const expected = {
        _id: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        status: 'queued',
        attempts: 0,
        leaseOwner: '',
        leaseUntil: null,
        nodes: [
            {
                node: 'node-a',
                state: 'pending',
                candidateHash: portalCandidate.sha256,
                candidate: portalCandidate,
                backupId: '',
            },
            {
                node: 'node-b',
                state: 'pending',
                candidateHash: bridgeCandidate.sha256,
                candidate: bridgeCandidate,
                backupId: '',
            },
        ],
    };
    assert.deepEqual(created, expected);
    assert.deepEqual(model.calls, [{ method: 'create', document: expected }]);
    assert.doesNotMatch(
        JSON.stringify(model.calls),
        /sshPassword|rawShell|tunnelPsk|secret-canary|raw-shell-canary/i,
    );
});

test('claim reads only durable candidates and never resets later active phases', async () => {
    const model = createModel();
    const claimed = { _id: 'operation-1', status: 'preparing' };
    model.findOneAndUpdate = async (query, update, options) => {
        model.calls.push({ method: 'findOneAndUpdate', query, update, options });
        return claimed;
    };
    const repository = new TopologyOperationRepository({ model });

    const result = await repository.claim({
        operationId: 'operation-1',
        owner: 'worker-1',
        leaseMs: 30_000,
        now: NOW,
    });

    assert.equal(result, claimed);
    assert.deepEqual(model.calls, [{
        method: 'findOneAndUpdate',
        query: {
            _id: 'operation-1',
            $or: [
                { status: 'queued' },
                {
                    status: 'preparing',
                    leaseUntil: { $lte: NOW },
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
        },
        update: {
            $set: {
                status: 'preparing',
                leaseOwner: 'worker-1',
                leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
            },
            $inc: { attempts: 1 },
        },
        options: {
            new: true,
            runValidators: true,
            lean: true,
            projection: {
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
            },
        },
    }]);
});

test('renewLease extends only an active unexpired lease owned by the worker', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });

    const renewed = await repository.renewLease({
        operationId: 'operation-1',
        owner: 'worker-1',
        leaseMs: 30_000,
        now: NOW,
    });

    assert.equal(renewed, true);
    assert.deepEqual(model.calls, [{
        method: 'updateOne',
        query: {
            _id: 'operation-1',
            status: { $in: ['preparing', 'committing', 'rolling_back'] },
            leaseOwner: 'worker-1',
            leaseUntil: { $gt: NOW },
        },
        update: {
            $set: { leaseUntil: new Date('2026-09-22T10:00:30.000Z') },
        },
        options: { runValidators: true },
    }]);
});

test('recordNode persists only fenced public node state and identifiers', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });

    const recorded = await repository.recordNode({
        operationId: 'operation-1',
        owner: 'worker-1',
        now: NOW,
        node: 'node-a',
        state: 'prepared',
        candidateHash: 'sha256:aaa',
        backupId: 'backup-a',
        candidate: 'must not persist',
        rawOutput: 'must not persist',
    });

    assert.equal(recorded, true);
    assert.deepEqual(model.calls, [{
        method: 'updateOne',
        query: {
            _id: 'operation-1',
            status: { $in: ['preparing', 'committing', 'rolling_back'] },
            leaseOwner: 'worker-1',
            leaseUntil: { $gt: NOW },
            'nodes.node': 'node-a',
        },
        update: {
            $set: {
                'nodes.$.state': 'prepared',
                'nodes.$.candidateHash': 'sha256:aaa',
                'nodes.$.backupId': 'backup-a',
            },
        },
        options: { runValidators: true },
    }]);
    assert.doesNotMatch(JSON.stringify(model.calls), /must not persist/);
});

test('setPhase uses the active owner lease as a compare-and-set fence', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });

    const changed = await repository.setPhase({
        operationId: 'operation-1',
        owner: 'worker-1',
        now: NOW,
        from: 'preparing',
        to: 'committing',
    });

    assert.equal(changed, true);
    assert.deepEqual(model.calls[0], {
        method: 'updateOne',
        query: {
            _id: 'operation-1',
            status: 'preparing',
            leaseOwner: 'worker-1',
            leaseUntil: { $gt: NOW },
        },
        update: { $set: { status: 'committing' } },
        options: { runValidators: true },
    });
});

test('finishClaimed terminal transition is fenced by active status owner and expiry', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });

    const finished = await repository.finishClaimed({
        operationId: 'operation-1',
        owner: 'worker-1',
        now: NOW,
        status: 'succeeded',
    });

    assert.equal(finished, true);
    assert.deepEqual(model.calls[0], {
        method: 'updateOne',
        query: {
            _id: 'operation-1',
            status: { $in: ['preparing', 'committing', 'rolling_back'] },
            leaseOwner: 'worker-1',
            leaseUntil: { $gt: NOW },
        },
        update: {
            $set: {
                status: 'succeeded',
                finishedAt: NOW,
                leaseUntil: null,
            },
        },
        options: { runValidators: true },
    });
});
