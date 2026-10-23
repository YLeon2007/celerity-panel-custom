'use strict';

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');
const Operation = require('../models/topologyOperationModel');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyClientReadinessWorker } = require('../workers/topologyClientReadinessWorker');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const NOW = new Date('2026-10-23T12:00:00Z');
const key = (context, revision = 7, scope = '') => `topology:${context.target}:revision-${revision}${scope}:host-${context.hostIdentity}:00000000-0000-0000-0000-000000000000`;
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary' };
let child, directory, repository;

before(async () => {
    if (!process.env.C3_MONGOD) return;
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'client-proof-context-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const selected = server.address().port;
            server.close(() => resolve(selected));
        });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port),
        '--bind_ip', '127.0.0.1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    await mongoose.connect(`mongodb://127.0.0.1:${port}/client_proof_context`, { serverSelectionTimeoutMS: 10000 });
    repository = new TopologyOperationRepository({ model: Operation,
        topologyStateModel: { findById() { return { select() { return { lean: async () => ({ revision: 7, deployedRevision: 7 }) }; } }; } } });
});
after(async () => {
    await mongoose.disconnect();
    if (child && child.exitCode === null) {
        const exited = new Promise(resolve => child.once('exit', resolve));
        child.kill('SIGTERM');
        await exited;
    }
    if (child) assert.equal(child.exitCode, 0, 'owned disposable MongoDB exited naturally');
    if (directory) await fs.rm(directory, { recursive: true, force: true });
});

function row(context, overrides = {}) {
    const document = { _id: new mongoose.Types.ObjectId(), executionContext: { ...context },
        idempotencyKey: key(context), topologyRevision: 7, priorDeployedRevision: 7,
        status: 'succeeded', clientReadiness: 'unverified', clientProofAttempts: 0,
        clientProofRetryAfter: null, clientProofLeaseUntil: null, clientProofLeaseOwner: '',
        heldTopologyAdmission: true, admissionFingerprint: 'a'.repeat(64), nodes: [], ...overrides };
    for (const field of Object.keys(document)) if (document[field] === undefined) delete document[field];
    return document;
}
function invalidBindings(context) {
    const foreign = context === TEST ? PROD : TEST;
    return [
        { executionContext: undefined }, { idempotencyKey: undefined },
        { executionContext: foreign, idempotencyKey: key(foreign) },
        { executionContext: { target: context.target, hostIdentity: foreign.hostIdentity } },
        { executionContext: { ...context, extra: true } },
        { executionContext: [{ ...context }] }, { executionContext: 'legacy' },
        { idempotencyKey: [key(context)] }, { idempotencyKey: key(foreign) },
        { idempotencyKey: key(context, 8) }, { idempotencyKey: key(context) + '\n' },
        { idempotencyKey: key(context, 7, ':unexpected:scope') },
        { idempotencyKey: key(context, 7, `:link.apply:${'a'.repeat(129)}`) },
        { idempotencyKey: key(context).replace(context.hostIdentity, context.hostIdentity.replaceAll('.', 'x')) },
        { topologyRevision: 7.5, idempotencyKey: key(context, 7.5) },
        { topologyRevision: '7' }, { topologyRevision: [7] },
        { topologyRevision: mongoose.Types.Decimal128.fromString('7') },
        { topologyRevision: Number.MAX_SAFE_INTEGER + 1 },
        { topologyRevision: -1, idempotencyKey: key(context, -1) },
        { topologyRevision: null }, { topologyRevision: undefined },
    ];
}

test('real Mongo worker probes only its selected identity and survives reconstruction with bounded retries', local, async () => {
    for (const context of [TEST, PROD]) {
        const foreign = context === TEST ? PROD : TEST;
        const foreignRow = row(foreign);
        const ownRow = row(context, { heldTopologyAdmission: false });
        await Operation.collection.insertMany([foreignRow, ownRow]);
        const beforeForeign = await Operation.collection.findOne({ _id: foreignRow._id });
        let current = NOW;
        let calls = 0;
        const createWorker = () => new TopologyClientReadinessWorker({ executionContext: { ...context }, repository,
            owner: 'worker', now: () => current, probeOperation: async operation => {
                calls += 1;
                assert.deepEqual(operation.executionContext, context);
                assert.equal(operation.idempotencyKey, key(context));
                assert.equal(operation.heldTopologyAdmission, false);
                return { passed: calls === 2, diagnostics: 'must-not-persist' };
            } });
        assert.equal(await createWorker().runOnce(), 'unverified');
        assert.equal(await createWorker().runOnce(), null);
        current = new Date(NOW.getTime() + 60001);
        assert.equal(await createWorker().runOnce(), 'verified');
        assert.equal(await createWorker().runOnce(), null);
        const completed = await Operation.collection.findOne({ _id: ownRow._id });
        assert.equal(completed.clientReadiness, 'verified');
        assert.equal(completed.clientProofAttempts, 2);
        assert.equal(JSON.stringify(completed).includes('must-not-persist'), false);
        assert.deepEqual(await Operation.collection.findOne({ _id: foreignRow._id }), beforeForeign);
        assert.equal(calls, 2);
        await Operation.collection.deleteMany({});
    }
});

test('real Mongo client-proof completion CAS refuses persisted binding drift on success and retry', local, async () => {
    for (const context of [TEST, PROD]) {
        for (const passed of [true, false]) {
            for (const overrides of [...invalidBindings(context),
                { idempotencyKey: key(context, 7, ':link.apply:other-valid-key') },
                { kind: 'link.apply', staged: true }]) {
                const document = row(context);
                await Operation.collection.insertOne(document);
                const claimed = await repository.claimNextClientProof({ executionContext: context, owner: 'worker', now: NOW });
                const changed = row(context, { ...overrides, _id: document._id,
                    clientProofAttempts: claimed.clientProofAttempts, clientProofLeaseOwner: 'worker',
                    clientProofLeaseUntil: claimed.clientProofLeaseUntil, clientProofRetryAfter: claimed.clientProofLeaseUntil });
                await Operation.collection.replaceOne({ _id: document._id }, changed);
                const before = await Operation.collection.findOne({ _id: document._id });
                assert.equal(await repository.completeClientProof({ operation: claimed, executionContext: context,
                    owner: 'worker', now: NOW, passed, reason: 'probe_failed' }), null, JSON.stringify(overrides));
                assert.deepEqual(await Operation.collection.findOne({ _id: document._id }), before);
                await Operation.collection.deleteMany({});
            }
            const document = row(context);
            await Operation.collection.insertOne(document);
            const claimed = await repository.claimNextClientProof({ executionContext: context, owner: 'worker', now: NOW });
            assert.equal(await repository.completeClientProof({ operation: claimed, executionContext: context,
                owner: 'worker', now: NOW, passed, reason: 'probe_failed' }), passed ? 'verified' : 'unverified');
            const completed = await Operation.collection.findOne({ _id: document._id });
            assert.equal(completed.clientReadiness, passed ? 'verified' : 'unverified');
            assert.equal(completed.clientProofLeaseUntil, null);
            await Operation.collection.deleteMany({});
        }
    }
});

test('real Mongo client-proof claim atomically excludes foreign and malformed bindings without mutation', local, async () => {
    for (const context of [TEST, PROD]) {
        for (const overrides of [...invalidBindings(context), { kind: 'link.apply', staged: true }]) {
            const document = row(context, overrides);
            await Operation.collection.insertOne(document);
            const before = await Operation.collection.findOne({ _id: document._id });
            assert.equal(await repository.claimNextClientProof({ executionContext: context,
                owner: 'worker', now: NOW }), null, JSON.stringify(overrides));
            assert.deepEqual(await Operation.collection.findOne({ _id: document._id }), before,
                'refusal must preserve attempts, lease, retry and admission');
            await Operation.collection.deleteMany({});
        }
        for (const scope of ['', ':link.apply:link-a', ':domain.reconcile:link-a',
            `:link.replace:link-a:${'a'.repeat(64)}`, `:link.attach:link-a:${'b'.repeat(64)}`]) {
            const document = row(context, { idempotencyKey: key(context, 7, scope),
                kind: 'link.apply', staged: false });
            await Operation.collection.insertOne(document);
            const claimed = await repository.claimNextClientProof({ executionContext: context, owner: 'worker', now: NOW });
            assert.ok(claimed);
            assert.deepEqual(claimed.executionContext, context);
            assert.equal(claimed.idempotencyKey, document.idempotencyKey);
            assert.equal(claimed.staged, false);
            assert.equal(claimed.clientReadiness, 'unverified');
            assert.equal(claimed.clientProofAttempts, 1);
            assert.equal(claimed.clientProofLeaseOwner, 'worker');
            assert.equal(await repository.claimNextClientProof({ executionContext: context, owner: 'second', now: NOW }), null);
            await Operation.collection.deleteMany({});
        }
    }
});
