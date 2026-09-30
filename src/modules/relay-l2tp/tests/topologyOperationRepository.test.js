'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    TopologyOperationRepository,
} = require('../repositories/topologyOperationRepository');
const TopologyOperation = require('../models/topologyOperationModel');
const ADMISSION_FINGERPRINT = 'a'.repeat(64);
const PROOF_INITIAL = Object.freeze({
    clientProofAttempts: 0, clientProofRetryAfter: null,
    clientProofLeaseOwner: '', clientProofLeaseUntil: null,
    clientProofState: 'active_unverified',
});
const ATTACH_IDS = Object.freeze({
    portal: '000000000000000000000001',
    relay: '000000000000000000000002',
    bridge: '000000000000000000000003',
    group: '000000000000000000000004',
    owner: '000000000000000000000005',
    old: '000000000000000000000006',
});
const ATTACH_SCOPE = Object.freeze({
    kind: 'link.attach',
    linkId: ATTACH_IDS.bridge,
    // The scoped component is an unordered identity, not the ordered new suffix.
    linkIds: [ATTACH_IDS.bridge, ATTACH_IDS.portal, ATTACH_IDS.relay],
    groupId: ATTACH_IDS.group,
    pathKey: 'main',
    ownerNodeId: ATTACH_IDS.owner,
    ownerTopologyRevision: 5,
    ownerCredentialRevision: 11,
    newPathLinkIds: [ATTACH_IDS.relay, ATTACH_IDS.bridge],
});

test('link.attach freezes owner epochs and ordered suffix in a transactional create', async () => {
    const session = { inTransaction: () => true };
    const calls = [];
    const model = {
        async create(documents, options) {
            calls.push({ documents, options });
            return documents;
        },
        async findOneAndUpdate() {},
        async updateOne() {},
    };
    const repository = new TopologyOperationRepository({ model });
    const created = await repository.createFrozen({
        operationId: '000000000000000000000007',
        topologyRevision: 7, priorDeployedRevision: 5, nodes: [],
        ...ATTACH_SCOPE,
        heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
        session,
    });
    assert.equal(calls.length, 1);
    assert.strictEqual(calls[0].options.session, session);
    assert.deepEqual(created, calls[0].documents[0]);
    assert.deepEqual(calls[0].documents[0], {
        _id: '000000000000000000000007',
        topologyRevision: 7, priorDeployedRevision: 5,
        ...ATTACH_SCOPE,
        status: 'queued', clientReadiness: 'unverified', heldTopologyAdmission: true,
        ...PROOF_INITIAL,
        admissionFingerprint: ADMISSION_FINGERPRINT,
        attempts: 0, leaseOwner: '', leaseUntil: null, nodes: [],
    });
    assert.notStrictEqual(calls[0].documents[0].newPathLinkIds, ATTACH_SCOPE.newPathLinkIds);
    assert.notStrictEqual(calls[0].documents[0].linkIds, ATTACH_SCOPE.linkIds);
});

test('attach-only fields cannot silently disappear from an unscoped create', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    await assert.rejects(repository.createFrozen({
        operationId: 'operation-1', topologyRevision: 7, priorDeployedRevision: 5,
        nodes: [], newPathLinkIds: [ATTACH_IDS.relay, ATTACH_IDS.bridge],
        heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
        session: { inTransaction: () => true },
    }), TypeError);
    assert.deepEqual(model.calls, []);
});

test('link.attach rejects invalid ordered suffix and unrelated component links before writing', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    const invalid = [
        { newPathLinkIds: undefined },
        { newPathLinkIds: [] },
        { newPathLinkIds: [ATTACH_IDS.bridge] },
        { newPathLinkIds: [ATTACH_IDS.bridge, ATTACH_IDS.relay] },
        { newPathLinkIds: [ATTACH_IDS.relay, ATTACH_IDS.relay, ATTACH_IDS.bridge] },
        { newPathLinkIds: [ATTACH_IDS.old, ATTACH_IDS.bridge] },
        { linkIds: [ATTACH_IDS.portal, ATTACH_IDS.bridge] },
        // The suffix cannot stand in for the full scoped component (P1R1 is separate).
        { linkIds: [ATTACH_IDS.relay, ATTACH_IDS.bridge] },
    ];
    for (const fields of invalid) {
        await assert.rejects(repository.createFrozen({
            operationId: 'operation-1', topologyRevision: 7,
            priorDeployedRevision: 5, nodes: [], ...ATTACH_SCOPE, ...fields,
            heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
            session: { inTransaction: () => true },
        }), TypeError, JSON.stringify(fields));
    }
    assert.deepEqual(model.calls, []);
});

test('link.attach rejects missing or unknown owner pins and extra scoped fields', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    const invalid = [
        { groupId: undefined }, { pathKey: undefined }, { pathKey: 'alternate' },
        { ownerNodeId: undefined },
        { ownerTopologyRevision: undefined }, { ownerCredentialRevision: undefined },
        { ownerTopologyRevision: null }, { ownerCredentialRevision: null },
        { ownerTopologyRevision: -1 }, { ownerCredentialRevision: -1 },
        { ownerTopologyRevision: 1.5 }, { ownerCredentialRevision: '11' },
        { oldLinkId: ATTACH_IDS.old }, { oldPathLinkIds: [ATTACH_IDS.old] },
        { staged: false },
    ];
    for (const fields of invalid) {
        await assert.rejects(repository.createFrozen({
            operationId: 'operation-1', topologyRevision: 7,
            priorDeployedRevision: 5, nodes: [], ...ATTACH_SCOPE, ...fields,
            heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
            session: { inTransaction: () => true },
        }), TypeError, JSON.stringify(fields));
    }
    assert.deepEqual(model.calls, []);
});

test('link.attach requires a held admission in an active Mongo session', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    for (const overrides of [
        { session: undefined }, { session: null },
        { session: { inTransaction: () => false } },
        { heldTopologyAdmission: undefined }, { admissionFingerprint: undefined },
    ]) {
        await assert.rejects(repository.createFrozen({
            operationId: 'operation-1', topologyRevision: 7,
            priorDeployedRevision: 5, nodes: [], ...ATTACH_SCOPE,
            heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
            session: { inTransaction: () => true }, ...overrides,
        }), TypeError);
    }
    assert.deepEqual(model.calls, []);
});

test('scoped operation identity survives session-bound repository creation and strict Mongo schema', async () => {
    let stored;
    const session = { inTransaction: () => true };
    const model = {
        async create(documents, options) {
            assert.deepEqual(options, { session });
            stored = new TopologyOperation(documents[0]);
            await stored.validate();
            return [stored];
        },
        async findOneAndUpdate() {},
        async updateOne() {},
    };
    const repository = new TopologyOperationRepository({ model });
    await repository.createFrozen({
        operationId: '507f1f77bcf86cd799439011',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [],
        kind: 'link.apply',
        staged: true,
        linkId: '507f191e810c19729de860ea',
        linkIds: ['507f191e810c19729de860ea'],
        heldTopologyAdmission: true,
        admissionFingerprint: ADMISSION_FINGERPRINT,
        session,
    });
    const durable = stored.toObject();
    assert.equal(durable.kind, 'link.apply');
    assert.equal(durable.staged, true);
    assert.equal(durable.linkId, '507f191e810c19729de860ea');
    assert.deepEqual(durable.linkIds, ['507f191e810c19729de860ea']);
    assert.equal(durable.heldTopologyAdmission, true);
});

test('strict Mongo schema refuses partially scoped operation identity', async () => {
    for (const scope of [
        { kind: 'link.apply', linkId: '507f191e810c19729de860ea', linkIds: ['507f191e810c19729de860ea'] },
        { kind: 'link.apply' },
        { kind: 'link.apply', linkId: '507f191e810c19729de860ea', linkIds: [] },
        { linkId: '507f191e810c19729de860ea' },
    ]) {
        const operation = new TopologyOperation({
            topologyRevision: 7, priorDeployedRevision: 5,
            status: 'queued', nodes: [], ...scope,
        });
        await assert.rejects(operation.validate());
    }
});

test('client readiness is durable and separate from execution status', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    const created = await repository.createFrozen({
        operationId: '507f1f77bcf86cd799439011',
        topologyRevision: 7, priorDeployedRevision: 5, nodes: [],
        heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
        session: { inTransaction: () => true },
    });
    assert.equal(created.clientReadiness, 'unverified');
    const durable = new TopologyOperation({ ...created, status: 'succeeded' });
    await durable.validate();
    assert.equal(durable.toObject().clientReadiness, 'unverified');
    const premature = new TopologyOperation({ ...created, clientReadiness: 'verified' });
    await assert.rejects(premature.validate(), /Client readiness requires successful execution/);
    for (const invalid of ['ready', 'failed', true]) {
        const forged = new TopologyOperation({ ...created, clientReadiness: invalid });
        await assert.rejects(forged.validate(), undefined, String(invalid));
    }
});

test('legacy model defaults never synthesize proof eligibility or a verified revision', async () => {
    const legacy = new TopologyOperation({ topologyRevision: 7,
        priorDeployedRevision: 5, status: 'succeeded', nodes: [] });
    assert.equal(legacy.clientProofAttempts, undefined);
    assert.equal(legacy.clientProofRevision, undefined);
    legacy.clientReadiness = 'verified';
    await assert.rejects(legacy.validate(), /proof for frozen topology revision/);
    const [proofIndex] = TopologyOperation.schema.indexes().filter(([, options]) =>
        options.partialFilterExpression?.clientProofAttempts);
    assert.deepEqual(proofIndex[1].partialFilterExpression.clientProofAttempts, { $lt: 3 });
});

test('public operation read fails closed on legacy missing or malformed readiness', async () => {
    let projection;
    let stored;
    const repository = new TopologyOperationRepository({ model: {
        async create() {}, async findOneAndUpdate() {}, async updateOne() {},
        findById() {
            return { select(value) {
                projection = value;
                return { lean: async () => stored };
            } };
        },
    } });
    for (stored of [
        { status: 'succeeded', topologyRevision: 7 },
        { status: 'succeeded', topologyRevision: 7, clientReadiness: 'ready' },
    ]) {
        assert.deepEqual(await repository.findPublicById('operation-1'), {
            status: 'succeeded', topologyRevision: 7, clientReadiness: 'unverified',
        });
    }
    assert.equal(projection, 'status topologyRevision priorDeployedRevision kind clientReadiness clientProofRevision clientProofState clientProofReason');
    stored = { status: 'succeeded', topologyRevision: 7, clientReadiness: 'verified' };
    assert.deepEqual(await repository.findPublicById('operation-1'), {
        ...stored, clientReadiness: 'unverified',
    });
    stored = { status: 'committing', topologyRevision: 7, clientReadiness: 'verified' };
    assert.deepEqual(await repository.findPublicById('operation-1'), {
        status: 'committing', topologyRevision: 7, clientReadiness: 'unverified',
    });
    stored = null;
    assert.equal(await repository.findPublicById('operation-1'), null);
});

test('scoped operation rejects missing or inconsistent link identity before creating', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    for (const scope of [
        { kind: 'link.apply', linkId: 'a', linkIds: [] },
        { kind: 'link.apply', linkId: 'a', linkIds: ['b'] },
        { kind: 'link.apply', linkId: 'a', linkIds: ['a', 'a'] },
        { kind: 'unsupported', linkId: 'a', linkIds: ['a'] },
    ]) {
        await assert.rejects(repository.createFrozen({
            operationId: 'operation', topologyRevision: 7,
            priorDeployedRevision: 5, nodes: [], ...scope,
        }), TypeError);
    }
    assert.deepEqual(model.calls, []);
});

test('findPublicById returns only the public status projection', async () => {
    let captured;
    const model = {
        async create() {},
        async findOneAndUpdate() {},
        async updateOne() {},
        findById(id) {
            const query = {
                select(projection) {
                    captured = { id, projection };
                    return {
                        lean: async () => ({ status: 'succeeded', topologyRevision: 7 }),
                    };
                },
            };
            return query;
        },
    };
    const repository = new TopologyOperationRepository({ model });
    const result = await repository.findPublicById('operation-dup');
    assert.deepEqual(captured, { id: 'operation-dup', projection: 'status topologyRevision priorDeployedRevision kind clientReadiness clientProofRevision clientProofState clientProofReason' });
    assert.deepEqual(result, { status: 'succeeded', topologyRevision: 7, clientReadiness: 'unverified' });
});

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

test('createFrozen refuses legacy and scoped operations without a held admission session', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    for (const scope of [{}, {
        kind: 'link.apply', linkId: 'link-a', linkIds: ['link-a'], staged: false,
    }]) {
        await assert.rejects(repository.createFrozen({
            operationId: 'operation-1', topologyRevision: 7,
            priorDeployedRevision: 5, nodes: [], ...scope,
        }), TypeError);
    }
    assert.deepEqual(model.calls, []);
});

test('createFrozen refuses to claim a held admission without an active session', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    await assert.rejects(repository.createFrozen({
        operationId: 'operation-1', topologyRevision: 7,
        priorDeployedRevision: 5, nodes: [], heldTopologyAdmission: true,
        admissionFingerprint: ADMISSION_FINGERPRINT,
    }), TypeError);
    await assert.rejects(repository.createFrozen({
        operationId: 'operation-1', topologyRevision: 7,
        priorDeployedRevision: 5, nodes: [],
        admissionFingerprint: ADMISSION_FINGERPRINT,
    }), TypeError);
    assert.deepEqual(model.calls, []);
});

test('createFrozen refuses a session-bound operation without the held admission identity', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    await assert.rejects(repository.createFrozen({
        operationId: 'operation-1', topologyRevision: 7,
        priorDeployedRevision: 5, nodes: [],
        session: { inTransaction: () => true },
    }), TypeError);
    assert.deepEqual(model.calls, []);
});

test('createFrozen inserts one scoped operation with its frozen candidate on the supplied session', async () => {
    const model = createModel();
    const session = { inTransaction: () => true };
    const createdDocument = { _id: 'operation-1', persisted: true };
    model.create = async (...args) => {
        model.calls.push(args);
        return [createdDocument];
    };
    const repository = new TopologyOperationRepository({ model });
    const plan = nodePlan('node-a', 'portal', 'portal');

    const result = await repository.createFrozen({
        operationId: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [{ ...plan, rawShell: 'must-not-persist' }],
        kind: 'link.apply',
        staged: true,
        linkId: 'link-a',
        linkIds: ['link-a'],
        heldTopologyAdmission: true,
        admissionFingerprint: ADMISSION_FINGERPRINT,
        session,
    });

    assert.strictEqual(result, createdDocument);
    assert.equal(model.calls.length, 1);
    assert.deepEqual(model.calls[0], [[{
        _id: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        kind: 'link.apply',
        linkId: 'link-a',
        linkIds: ['link-a'],
        staged: true,
        status: 'queued',
        clientReadiness: 'unverified',
        ...PROOF_INITIAL,
        heldTopologyAdmission: true,
        admissionFingerprint: ADMISSION_FINGERPRINT,
        attempts: 0,
        leaseOwner: '',
        leaseUntil: null,
        nodes: [{
            node: 'node-a',
            nodeRef: 'portal',
            role: 'portal',
            targetProfile: 'xray-main',
            checks: plan.checks,
            state: 'pending',
            candidateHash: plan.candidateHash,
            candidate: plan.candidate,
            backupId: '',
        }],
    }], { session }]);
});

test('createFrozen rejects null, malformed, or inactive sessions before writing', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    for (const session of [null, false, '', {}, [], { inTransaction: true },
        { inTransaction: () => false }]) {
        await assert.rejects(repository.createFrozen({
            operationId: 'operation-1', topologyRevision: 7,
            priorDeployedRevision: 5, nodes: [], heldTopologyAdmission: true,
            admissionFingerprint: ADMISSION_FINGERPRINT, session,
        }), TypeError);
    }
    assert.deepEqual(model.calls, []);
});

test('createFrozen rejects invalid scoped identity and candidate before a session write', async () => {
    const model = createModel();
    const repository = new TopologyOperationRepository({ model });
    const session = { inTransaction: () => true };
    await assert.rejects(repository.createFrozen({
        operationId: 'operation-1', topologyRevision: 7,
        priorDeployedRevision: 5, nodes: [],
        kind: 'link.apply', linkId: 'link-a', linkIds: ['link-b'], staged: true,
        heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
        session,
    }), TypeError);
    await assert.rejects(repository.createFrozen({
        operationId: 'operation-1', topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: [{ ...nodePlan('node-a', 'portal', 'portal'), candidateHash: '0'.repeat(64) }],
        heldTopologyAdmission: true, admissionFingerprint: ADMISSION_FINGERPRINT,
        session,
    }), TypeError);
    assert.deepEqual(model.calls, []);
});

test('createFrozen propagates session insert rejection without an unscoped fallback', async () => {
    const model = createModel();
    const session = { inTransaction: () => true };
    const failure = new Error('session insert rejected');
    model.create = async (...args) => {
        model.calls.push(args);
        throw failure;
    };
    const repository = new TopologyOperationRepository({ model });
    await assert.rejects(repository.createFrozen({
        operationId: 'operation-1', topologyRevision: 7,
        priorDeployedRevision: 5, nodes: [], heldTopologyAdmission: true,
        admissionFingerprint: ADMISSION_FINGERPRINT, session,
    }), error => error === failure);
    assert.equal(model.calls.length, 1);
    assert.deepEqual(model.calls[0], [[{
        _id: 'operation-1', topologyRevision: 7, priorDeployedRevision: 5,
        status: 'queued', clientReadiness: 'unverified', heldTopologyAdmission: true,
        ...PROOF_INITIAL,
        admissionFingerprint: ADMISSION_FINGERPRINT,
        attempts: 0, leaseOwner: '', leaseUntil: null, nodes: [],
    }], { session }]);
});

test('createFrozen fails closed on malformed session create results without retrying', async () => {
    for (const result of [undefined, null, [], [{}, {}], {}, [null], [false], [{}], [{ _id: 'different' }]]) {
        const model = createModel();
        const session = { inTransaction: () => true };
        model.create = async (...args) => {
            model.calls.push(args);
            return result;
        };
        const repository = new TopologyOperationRepository({ model });
        await assert.rejects(repository.createFrozen({
            operationId: 'operation-1', topologyRevision: 7,
            priorDeployedRevision: 5, nodes: [], heldTopologyAdmission: true,
            admissionFingerprint: ADMISSION_FINGERPRINT, session,
        }), TypeError);
        assert.equal(model.calls.length, 1);
        assert.strictEqual(model.calls[0][1].session, session);
    }
});

test('createFrozen durably preserves composer deployment order without sorting by node id', async () => {
    const model = createModel();
    const session = { inTransaction: () => true };
    model.create = async (documents, options) => {
        model.calls.push({ method: 'create', documents, options });
        return documents;
    };
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
        heldTopologyAdmission: true,
        admissionFingerprint: ADMISSION_FINGERPRINT,
        session,
    });

    const expected = {
        _id: 'operation-1',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        status: 'queued',
        clientReadiness: 'unverified',
        ...PROOF_INITIAL,
        heldTopologyAdmission: true,
        admissionFingerprint: ADMISSION_FINGERPRINT,
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
    assert.deepEqual(model.calls, [{ method: 'create', documents: [expected], options: { session } }]);
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

test('claim reacquires expired committing and rolling-back phases without resetting their status', async () => {
    const model = createModel();
    let claimCall = 0;
    const recovered = {
        _id: 'operation-1',
        status: 'committing',
        nodes: [{ state: 'committed', backupId: 'backup-a' }],
    };
    model.findOneAndUpdate = async (query, update, options) => {
        model.calls.push({ method: 'findOneAndUpdate', query, update, options });
        claimCall += 1;
        return claimCall === 1 ? null : recovered;
    };
    const repository = new TopologyOperationRepository({ model });

    const result = await repository.claim({
        operationId: 'operation-1',
        owner: 'worker-1',
        leaseMs: 30_000,
        now: NOW,
    });

    assert.strictEqual(result, recovered);
    assert.deepEqual(model.calls[1], {
        method: 'findOneAndUpdate',
        query: {
            _id: 'operation-1',
            status: { $in: ['preparing', 'committing', 'rolling_back'] },
            leaseUntil: { $lte: NOW },
        },
        update: {
            $set: {
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
    });
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
