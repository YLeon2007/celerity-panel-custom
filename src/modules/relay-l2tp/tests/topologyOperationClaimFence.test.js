'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const NOW = new Date('2026-10-19T00:00:00.000Z');
const UUID = '00000000-0000-0000-0000-000000000000';
function key(context, revision = 7, scope = '') {
    return `topology:${context.target}:revision-${revision}${scope}:host-${context.hostIdentity}:${UUID}`;
}
const request = { operationId: 'operation-1', owner: 'worker', now: NOW, leaseMs: 30000 };

test('claim rejects missing, extra, or cross-paired trusted context before any persistence call', async () => {
    const calls = [];
    const repository = new TopologyOperationRepository({ model: {
        async create() {}, async updateOne() {},
        async findOneAndUpdate(...args) { calls.push(args); return null; },
    } });
    for (const executionContext of [undefined, null, {}, { target: 'production' },
        { target: 'test', hostIdentity: PROD.hostIdentity },
        { target: 'production', hostIdentity: TEST.hostIdentity }, { ...TEST, extra: true }]) {
        await assert.rejects(repository.claim({ ...request, executionContext }), /execution context/i);
    }
    assert.deepEqual(calls, []);
});

test('atomic Mongo claim fences TEST/PROD pairs, bounded host keys and exact revision in both claim paths', {
    skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary',
}, async () => {
    const fs = require('node:fs/promises');
    const path = require('node:path');
    const net = require('node:net');
    const { spawn } = require('node:child_process');
    const mongoose = require('mongoose');
    const Operation = require('../models/topologyOperationModel');
    assert.ok(process.env.C3_MONGOD, 'Set C3_MONGOD to an isolated local MongoDB binary');
    const directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-claim-fence-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const selected = server.address().port;
            server.close(() => resolve(selected));
        });
    });
    const child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port),
        '--bind_ip', '127.0.0.1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    try {
        await mongoose.connect(`mongodb://127.0.0.1:${port}/claim_fence`, { serverSelectionTimeoutMS: 10000 });
        const repository = new TopologyOperationRepository({ model: Operation });
        for (const context of [TEST, PROD]) {
            const foreign = context === TEST ? PROD : TEST;
            for (const status of ['queued', 'preparing', 'committing', 'rolling_back']) {
                const base = { _id: new mongoose.Types.ObjectId(), executionContext: { ...context },
                    idempotencyKey: key(context), topologyRevision: 7, priorDeployedRevision: 5,
                    status, attempts: 2, leaseOwner: 'previous', leaseUntil: new Date(NOW - 1),
                    heldTopologyAdmission: true, admissionFingerprint: 'a'.repeat(64),
                    nodes: status === 'queued' ? [] : [{ state: 'prepared', backupId: 'backup' }] };
                for (const overrides of [
                    { executionContext: undefined }, { idempotencyKey: undefined },
                    { executionContext: foreign, idempotencyKey: key(foreign) },
                    { executionContext: { target: context.target, hostIdentity: foreign.hostIdentity } },
                    { executionContext: { ...context, extra: true } },
                    { executionContext: [{ ...context }] },
                    { executionContext: 'legacy' },
                    { idempotencyKey: [key(context)] },
                    { idempotencyKey: key(context).replace(context.hostIdentity, context.hostIdentity.replaceAll('.', 'x')) },
                    { idempotencyKey: key(foreign) },
                    { idempotencyKey: key(context, 8) },
                    { idempotencyKey: key(context).replace(`host-${context.hostIdentity}:`, '') },
                    { idempotencyKey: key(context) + '\n' },
                    { idempotencyKey: key(context, 7, ':unexpected:scope') },
                    { idempotencyKey: key(context, 7, `:link.apply:${'a'.repeat(129)}`) },
                    { topologyRevision: 7.5, idempotencyKey: key(context, 7.5) },
                    { topologyRevision: '7' },
                    { topologyRevision: mongoose.Types.Decimal128.fromString('7') },
                    { topologyRevision: [7] },
                    { topologyRevision: Number.MAX_SAFE_INTEGER + 1 },
                    { topologyRevision: -1, idempotencyKey: key(context, -1) },
                    { topologyRevision: null }, { topologyRevision: undefined },
                ]) {
                    const document = { ...base, ...overrides };
                    for (const field of Object.keys(document)) if (document[field] === undefined) delete document[field];
                    await Operation.collection.insertOne(document);
                    const before = await Operation.collection.findOne({ _id: base._id });
                    assert.equal(await repository.claim({ ...request, operationId: base._id, executionContext: context }), null,
                        `${context.target}/${status}/${JSON.stringify(overrides)}`);
                    assert.deepEqual(await Operation.collection.findOne({ _id: base._id }), before,
                        'Rejected historical/cloned rows must not mutate attempts, lease, nodes or admission');
                    await Operation.collection.deleteOne({ _id: base._id });
                }
                for (const scope of ['', ':link.apply:link-a', ':domain.reconcile:link-a',
                    `:link.replace:link-a:${'a'.repeat(64)}`, `:link.attach:link-a:${'b'.repeat(64)}`]) {
                    const document = { ...base, idempotencyKey: key(context, 7, scope) };
                    await Operation.collection.insertOne(document);
                    const claimed = await repository.claim({ ...request, operationId: base._id, executionContext: context });
                    assert.ok(claimed, `${context.target}/${status}/${scope}`);
                    assert.deepEqual(claimed.executionContext, context);
                    assert.equal(claimed.idempotencyKey, document.idempotencyKey);
                    assert.equal(claimed.attempts, 3);
                    assert.equal(claimed.leaseOwner, 'worker');
                    assert.equal(claimed.heldTopologyAdmission, true);
                    assert.equal(claimed.status, status === 'queued' ? 'preparing' : status);
                    await Operation.collection.deleteOne({ _id: base._id });
                }
            }
        }
    } finally {
        await mongoose.disconnect();
        if (child.exitCode === null) {
            const exited = new Promise(resolve => child.once('exit', resolve));
            child.kill('SIGTERM');
            await exited;
        }
        await fs.rm(directory, { recursive: true, force: true });
    }
});
