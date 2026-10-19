'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const NOW = new Date('2026-10-19T00:00:00.000Z');
const UUID = '00000000-0000-0000-0000-000000000000';
function key(context, revision = 7) {
    return `topology:${context.target}:revision-${revision}:host-${context.hostIdentity}:${UUID}`;
}
function fixture(executionContext = TEST, operation = null) {
    const calls = [];
    const methods = names => Object.fromEntries(names.map(method => [method, async () => {
        calls.push(method);
        assert.fail(`Unexpected side effect: ${method}`);
    }]));
    const repository = { ...methods(['renewLease', 'recordNode', 'setPhase', 'finishClaimed']),
        async claim(request) { calls.push({ claim: request }); return operation; } };
    const options = {
        executionContext, operationRepository: repository,
        executor: methods(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback']),
        finalizer: methods(['finalizeSucceeded', 'finalizeRolledBack']),
        lockService: methods(['acquire', 'renew', 'release', 'releaseVerified']),
        timer: { setInterval() { assert.fail('No heartbeat before binding validation'); }, clearInterval() {} },
        workerId: 'worker', leaseMs: 30000, clock: { now: () => NOW },
        allowUnprovenTestExecution: true,
    };
    return { options, calls };
}

test('invalid post-claim binding stops before plan validation without terminalizing, renewing or releasing', async () => {
    for (const fields of [
        {}, { executionContext: TEST }, { executionContext: PROD, idempotencyKey: key(PROD) },
        { _id: 'foreign-operation', executionContext: TEST, idempotencyKey: key(TEST) },
        { executionContext: { ...TEST, extra: true }, idempotencyKey: key(TEST) },
        { executionContext: TEST, idempotencyKey: key(TEST, 8) },
        { executionContext: TEST, idempotencyKey: key(TEST) + '\n' },
        { executionContext: TEST, idempotencyKey: key(TEST).replace('revision-7:', 'revision-7:unexpected:') },
    ]) for (const pppWait of [undefined, { locks: [], releasedNodes: [] }]) {
        const operation = { _id: 'operation-1', topologyRevision: 7, priorDeployedRevision: 5,
            status: 'preparing', heldTopologyAdmission: true, nodes: [], ...fields, ...(pppWait ? { pppWait } : {}) };
        const before = structuredClone(operation);
        const { options, calls } = fixture(TEST, operation);
        const worker = new TopologyOperationWorker(options);
        for (let attempt = 0; attempt < 2; attempt++) {
            assert.deepEqual(await worker.run({ operationId: 'operation-1', executionContext: PROD }), {
                claimed: true, operationId: 'operation-1', stopped: true,
                errorCode: 'TOPOLOGY_OPERATION_EXECUTION_CONTEXT_MISMATCH',
            });
        }
        assert.equal(calls.length, 2);
        assert.ok(calls.every(call => call.claim?.executionContext === TEST));
        assert.deepEqual(operation, before);
        assert.equal(worker.running.size, 0);
    }
});

test('worker requires and freezes an exact host-selected context; PROD cannot acquire the TEST bypass', async () => {
    for (const executionContext of [null, {}, { target: 'test', hostIdentity: PROD.hostIdentity },
        { ...TEST, extra: true }]) {
        assert.throws(() => new TopologyOperationWorker(fixture(executionContext).options), /execution context/i);
    }
    const missing = fixture();
    delete missing.options.executionContext;
    assert.throws(() => new TopologyOperationWorker(missing.options), /execution context/i);
    for (const context of [TEST, PROD]) {
        const source = { ...context };
        const { options, calls } = fixture(source);
        const worker = new TopologyOperationWorker(options);
        source.target = 'other';
        assert.deepEqual(worker.executionContext, context);
        assert.equal(Object.isFrozen(worker.executionContext), true);
        assert.throws(() => { worker.executionContext = PROD; }, TypeError);
        const result = await worker.run({ operationId: 'operation-1', executionContext: PROD });
        if (context === PROD) {
            assert.equal(result.errorCode, 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN');
            assert.deepEqual(calls, []);
        } else {
            assert.deepEqual(result, { claimed: false, operationId: 'operation-1' });
            assert.deepEqual(calls, [{ claim: { operationId: 'operation-1', executionContext: TEST,
                owner: 'worker', leaseMs: 30000, now: NOW } }]);
        }
    }
});
