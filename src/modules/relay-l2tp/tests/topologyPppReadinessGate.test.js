'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');

function fixture(overrides = {}) {
    const calls = [];
    const state = { node: 'node-r', status: 'installed', desiredState: 'installed', secretRevision: 41 };
    const users = [{ relayNode: 'node-r', login: 'alice', enabled: true, desiredRevision: 41,
        appliedRevision: 41, syncStatus: 'synced', syncOperationId: 'abcdef012345abcdef012345' }];
    const operation = { _id: 'abcdef012345abcdef012345', node: 'node-r', kind: 'sync_users',
        status: 'succeeded', plan: { operationId: 'abcdef012345abcdef012345', relayId: 'node-r',
            desired: { credentialRevision: 41 } } };
    const deps = {
        RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => state }) }) },
        L2tpUser: { find: () => ({ select: () => ({ lean: async () => users }) }) },
        L2tpOperation: { findOne: () => ({ sort: () => ({ select: () => ({ lean: async () => operation }) }) }) },
        transportResolver: async ({ nodeId }) => {
            calls.push(['resolve', nodeId]);
            return { runArtifactCommand: async request => {
                calls.push(['verify', request]);
                return { ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
                    enabledUserCount: 1, managedUserCount: 1 };
            } };
        },
    };
    return { gate: new TopologyPppReadinessGate({ ...deps, ...overrides }), calls };
}

const plan = { nodes: [{ role: 'portal', node: 'node-p' }, { role: 'relay', node: 'node-r' }] };

test('installed relay is ready only after SSH artifact verification of persisted synced snapshot', async () => {
    const { gate, calls } = fixture();
    assert.deepEqual(await gate.verifyPlan(plan), { ok: true, verifiedRelayCount: 1 });
    assert.deepEqual(calls, [
        ['resolve', 'node-r'],
        ['verify', { operationId: 'abcdef012345abcdef012345', command: 'verify-users',
            expectedCredentialRevision: 41, expectedEnabledUserCount: 1 }],
    ]);
});

test('staged relay without installed PPP is skipped, never claimed node-verified', async () => {
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => null }) }) } });
    assert.deepEqual(await gate.verifyPlan({ ...plan, staged: true }),
        { ok: true, verifiedRelayCount: 0, skippedRelayCount: 1 });
    assert.deepEqual(calls, []);
});

test('non-staged relay without installed PPP fails closed rather than claiming readiness', async () => {
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => null }) }) } });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: false, verifiedRelayCount: 0 });
    assert.deepEqual(calls, []);
});

test('runner unavailable fails closed without leaking remote diagnostics', async () => {
    const { gate } = fixture({ transportResolver: async () => ({ runArtifactCommand: async () => {
        throw new Error('private-ppp-password');
    } }) });
    const result = await gate.verifyPlan(plan);
    assert.deepEqual(result, { ok: false, verifiedRelayCount: 0 });
    assert.doesNotMatch(JSON.stringify(result), /private-ppp-password/);
});

test('Mongo-only success cannot pass without a valid node response', async () => {
    const { gate } = fixture({ transportResolver: async () => ({ runArtifactCommand: async () => ({
        ok: true, code: 'USERS_VERIFIED', credentialRevision: 41, enabledUserCount: 0, managedUserCount: 0,
    }) }) });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: false, verifiedRelayCount: 0 });
});

test('unavailable or stale durable sync operation cannot pass', async () => {
    const { gate, calls } = fixture({ L2tpOperation: { findOne: () => ({ sort: () => ({ select: () => ({ lean: async () => null }) }) }) } });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: false, verifiedRelayCount: 0 });
    assert.deepEqual(calls, []);
});
