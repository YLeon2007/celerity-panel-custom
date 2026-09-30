'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyOperationFinalizer,
} = require('../services/topologyOperationFinalizer');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const LEASE_UNTIL = new Date('2026-09-22T10:00:30.000Z');

function request(overrides = {}) {
    return {
        operationId: 'operation-7',
        owner: 'worker-1',
        leaseUntil: LEASE_UNTIL,
        topologyRevision: 7,
        priorDeployedRevision: 5,
        ...overrides,
    };
}

test('finalizes from fixed operation lease and revision inputs only', async () => {
    const calls = [];
    const finalizer = new TopologyOperationFinalizer({
        repository: {
            async finalizeSucceeded(input) {
                calls.push(input);
                return {
                    operationId: input.operationId,
                    topologyRevision: input.topologyRevision,
                    deployedRevision: input.topologyRevision,
                    finishedAt: input.now,
                    candidate: { bytes: [1, 2, 3] },
                    secret: 'must-not-escape',
                };
            },
        },
        clock: {
            now() {
                calls.push('clock.now');
                return NOW;
            },
        },
    });

    const result = await finalizer.finalizeSucceeded(request());

    assert.deepEqual(calls, [
        'clock.now',
        {
            operationId: 'operation-7',
            owner: 'worker-1',
            leaseUntil: LEASE_UNTIL,
            topologyRevision: 7,
            priorDeployedRevision: 5,
            now: NOW,
        },
    ]);
    assert.deepEqual(result, {
        operationId: 'operation-7',
        topologyRevision: 7,
        deployedRevision: 7,
        finishedAt: NOW,
    });
    assert.doesNotMatch(JSON.stringify(calls), /candidate|bytes|secret/i);
    assert.doesNotMatch(JSON.stringify(result), /candidate|bytes|secret/i);
});

test('scoped finalization accepts fenced prior deployed revision without claiming global Sync', async () => {
    const finalizer = new TopologyOperationFinalizer({
        repository: {
            async finalizeSucceeded(input) {
                return {
                    operationId: input.operationId,
                    topologyRevision: input.topologyRevision,
                    deployedRevision: input.priorDeployedRevision,
                    scopeKind: 'link.apply',
                    finishedAt: input.now,
                };
            },
        },
        clock: { now: () => NOW },
    });
    assert.deepEqual(await finalizer.finalizeSucceeded(request()), {
        operationId: 'operation-7', topologyRevision: 7,
        deployedRevision: 5, finishedAt: NOW,
    });
});

test('replacement finalization returns scoped success without claiming global Sync', async () => {
    const finalizer = new TopologyOperationFinalizer({
        repository: { finalizeSucceeded: async input => ({
            operationId: input.operationId, topologyRevision: input.topologyRevision,
            deployedRevision: input.priorDeployedRevision,
            scopeKind: 'link.replace', finishedAt: input.now,
        }) },
        clock: { now: () => NOW },
    });
    assert.deepEqual(await finalizer.finalizeSucceeded(request()), {
        operationId: 'operation-7', topologyRevision: 7,
        deployedRevision: 5, finishedAt: NOW,
    });
});

test('finalizer rejects a scoped result that falsely advances the global revision', async () => {
    const finalizer = new TopologyOperationFinalizer({
        repository: { finalizeSucceeded: async () => ({
            operationId: 'operation-7', topologyRevision: 7,
            deployedRevision: 7, scopeKind: 'domain.reconcile', finishedAt: NOW,
        }) },
        clock: { now: () => NOW },
    });
    assert.equal(await finalizer.finalizeSucceeded(request()), null);
});

test('durable PPP resume forwards only revision proof and obtains now from its own clock', async () => {
    const calls = [];
    const proof = [{ relayNode: 'aaaaaaaaaaaaaaaaaaaaaaaa', credentialRevision: 8 }];
    const finalizer = new TopologyOperationFinalizer({
        repository: { finalizeSucceeded: async input => {
            calls.push(input);
            return { operationId: input.operationId, topologyRevision: input.topologyRevision,
                deployedRevision: input.priorDeployedRevision, scopeKind: 'link.apply', finishedAt: input.now };
        } },
        clock: { now: () => NOW },
    });
    assert.deepEqual(await finalizer.finalizeSucceeded(request({ pppProof: proof })), {
        operationId: 'operation-7', topologyRevision: 7, deployedRevision: 5, finishedAt: NOW,
    });
    assert.deepEqual(calls, [{ ...request(), pppProof: proof, now: NOW }]);
    await assert.rejects(finalizer.finalizeSucceeded(request({ now: NOW, pppProof: proof })),
        { name: 'TypeError' });
});

test('rejects operation documents or extra candidate and secret inputs', async () => {
    const calls = [];
    const finalizer = new TopologyOperationFinalizer({
        repository: {
            async finalizeSucceeded(input) {
                calls.push(input);
                return null;
            },
        },
        clock: {
            now() {
                calls.push('clock.now');
                return NOW;
            },
        },
    });

    await assert.rejects(
        finalizer.finalizeSucceeded({
            ...request(),
            candidate: { bytes: [1, 2, 3] },
            secret: 'must-be-rejected',
        }),
        { name: 'TypeError' },
    );

    assert.deepEqual(calls, []);
});
