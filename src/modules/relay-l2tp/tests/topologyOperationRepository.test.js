'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    TopologyOperationRepository,
} = require('../repositories/topologyOperationRepository');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const CANDIDATE_MEDIA_TYPE = 'application/vnd.celerity.xray-topology-node+json;version=1';

const TARGET_BY_ROLE = Object.freeze({
    portal: Object.freeze({
        targetProfile: 'xray-main',
        serviceUnit: 'xray.service',
        serviceUnitPath: '/etc/systemd/system/xray.service',
        configPath: '/usr/local/etc/xray/config.json',
    }),
    bridge: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
});

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalize(value[key])]),
    );
}

function candidate(nodeRef) {
    const content = `${JSON.stringify(canonicalize({
        inbounds: [{ tag: `client-${nodeRef}` }],
        outbounds: [{ tag: 'direct' }],
        routing: { rules: [] },
    }))}\n`;
    return {
        mediaType: CANDIDATE_MEDIA_TYPE,
        bytes: [...Buffer.from(content, 'utf8')],
        sha256: createHash('sha256').update(content).digest('hex'),
    };
}

function nodePlan(node, role, nodeRef, artifact = candidate(nodeRef)) {
    const target = TARGET_BY_ROLE[role];
    return {
        node,
        nodeRef,
        role,
        ...target,
        candidateHash: artifact.sha256,
        candidate: artifact,
        checks: [{
            type: 'service',
            serviceUnit: target.serviceUnit,
            expectedState: 'active',
        }],
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

test('createFrozen durably preserves composer deployment order without sorting by node id', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    const bridgeCandidate = candidate('bridge');
    const portalCandidate = candidate('portal');
    const bridge = nodePlan('node-b', 'bridge', 'bridge', bridgeCandidate);
    const portal = nodePlan('node-a', 'portal', 'portal', portalCandidate);

    const created = await repository.createFrozen({
        operationId: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [
            {
                ...bridge,
                candidate: {
                    ...bridgeCandidate,
                    sshPassword: 'ssh-secret-canary',
                },
                rawShell: 'raw-shell-canary',
            },
            {
                ...portal,
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
                node: 'node-b',
                nodeRef: 'bridge',
                role: 'bridge',
                targetProfile: 'xray-bridge',
                checks: bridge.checks,
                state: 'pending',
                candidateHash: bridgeCandidate.sha256,
                candidate: bridgeCandidate,
                backupId: '',
            },
            {
                node: 'node-a',
                nodeRef: 'portal',
                role: 'portal',
                targetProfile: 'xray-main',
                checks: portal.checks,
                state: 'pending',
                candidateHash: portalCandidate.sha256,
                candidate: portalCandidate,
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

test('createFrozen rejects legacy, non-canonical, hash-mismatched, or unbound candidates', async () => {
    const legacyContent = `${JSON.stringify({
        schemaVersion: 1,
        kind: 'xray-topology-node-candidate',
        mode: 'forward',
        nodeRef: 'portal',
        role: 'portal',
        targetProfile: 'xray-main',
        links: [],
        checks: [],
    })}\n`;
    const legacy = {
        mediaType: CANDIDATE_MEDIA_TYPE,
        bytes: [...Buffer.from(legacyContent, 'utf8')],
        sha256: createHash('sha256').update(legacyContent).digest('hex'),
    };
    const nonCanonicalContent = `${JSON.stringify({
        outbounds: [],
        inbounds: [],
    }, null, 2)}\n`;
    const nonCanonical = {
        mediaType: CANDIDATE_MEDIA_TYPE,
        bytes: [...Buffer.from(nonCanonicalContent, 'utf8')],
        sha256: createHash('sha256').update(nonCanonicalContent).digest('hex'),
    };
    const incompleteContent = `${JSON.stringify(canonicalize({
        inbounds: [],
        outbounds: [],
    }))}\n`;
    const incomplete = {
        mediaType: CANDIDATE_MEDIA_TYPE,
        bytes: [...Buffer.from(incompleteContent, 'utf8')],
        sha256: createHash('sha256').update(incompleteContent).digest('hex'),
    };
    const valid = nodePlan('node-a', 'portal', 'portal');
    const invalidNodes = [
        nodePlan('node-a', 'portal', 'portal', legacy),
        nodePlan('node-a', 'portal', 'portal', nonCanonical),
        nodePlan('node-a', 'portal', 'portal', incomplete),
        { ...valid, candidateHash: '0'.repeat(64) },
        { ...valid, targetProfile: 'xray-bridge' },
    ];

    for (const node of invalidNodes) {
        const model = createModel();
        const repository = new TopologyOperationRepository({ model });
        await assert.rejects(
            repository.createFrozen({
                operationId: 'operation-1',
                topologyRevision: 7,
                priorDeployedRevision: 5,
                nodes: [node],
            }),
            { name: 'TypeError' },
        );
        assert.deepEqual(model.calls, []);
    }
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
