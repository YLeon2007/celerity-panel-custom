'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpUserSyncReconciler,
} = require('../services/l2tpUserSyncReconciler');

const NOW = new Date('2026-09-22T10:00:00.000Z');

function runningOperation(overrides = {}) {
    return {
        _id: 'operation-17',
        node: 'relay-1',
        kind: 'sync_users',
        status: 'running',
        leaseOwner: 'worker-1',
        leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
        plan: {
            operationId: 'operation-17',
            relayId: 'relay-1',
            desired: { credentialRevision: 9 },
        },
        ...overrides,
    };
}

function resolvedUsers() {
    return [
        {
            id: 'user-active',
            relayNode: 'relay-1',
            login: 'alice',
            ip: '10.77.0.10',
            enabled: true,
            desiredRevision: 8,
            password: 'transient-active-password',
            passwordEncrypted: 'must-not-reach-persistence',
        },
        {
            id: 'user-disabled',
            relayNode: 'relay-1',
            login: 'disabled',
            ip: '10.77.0.11',
            enabled: false,
            desiredRevision: 9,
            password: 'transient-disabled-password',
        },
    ];
}

function verifiedAttestation(overrides = {}) {
    return {
        ok: true,
        credentialRevision: 9,
        enabledUserCount: 1,
        managedUserCount: 1,
        code: 'USERS_VERIFIED',
        ...overrides,
    };
}

test('finalizeVerifiedSync passes a secret-free snapshot to atomic persistence and returns retry-safe success', async () => {
    const calls = [];
    const repository = {
        async finalizeVerifiedSync(request) {
            calls.push(request);
            return {
                operationId: request.operationId,
                reconciledUserCount: request.resolvedUsers.length,
                finalizedAt: request.now,
                password: 'repository-result-secret',
                rawCommand: 'must-not-escape',
            };
        },
    };
    const reconciler = new L2tpUserSyncReconciler({
        repository,
        clock: { now: () => NOW },
    });

    const result = await reconciler.finalizeVerifiedSync({
        operation: runningOperation(),
        resolvedUsers: resolvedUsers(),
        verification: verifiedAttestation(),
        workerId: 'worker-1',
    });

    assert.deepEqual(result, {
        ok: true,
        operationId: 'operation-17',
        reconciledUserCount: 2,
        finalizedAt: NOW,
    });
    assert.deepEqual(calls, [{
        operationId: 'operation-17',
        relayNode: 'relay-1',
        credentialRevision: 9,
        resolvedUsers: [
            {
                id: 'user-active',
                relayNode: 'relay-1',
                login: 'alice',
                ip: '10.77.0.10',
                enabled: true,
                desiredRevision: 8,
            },
            {
                id: 'user-disabled',
                relayNode: 'relay-1',
                login: 'disabled',
                ip: '10.77.0.11',
                enabled: false,
                desiredRevision: 9,
            },
        ],
        verification: {
            ok: true,
            credentialRevision: 9,
            enabledUserCount: 1,
            managedUserCount: 1,
            code: 'USERS_VERIFIED',
        },
        workerId: 'worker-1',
        now: NOW,
    }]);
    assert.doesNotMatch(
        JSON.stringify(calls),
        /transient-active-password|transient-disabled-password|must-not-reach-persistence/,
    );
});

test('claimed finalization passes explicit generation and secret-free snapshots only to the protected repository method', async () => {
    const calls = [];
    const reconciler = new L2tpUserSyncReconciler({
        repository: {
            async finalizeVerifiedSync() { throw new Error('legacy method must not run'); },
            async finalizeClaimedVerifiedSync(request) {
                calls.push(request);
                return {
                    operationId: request.operationId,
                    reconciledUserCount: request.resolvedUsers.length,
                    finalizedAt: request.now,
                    password: 'do-not-return',
                };
            },
        },
        clock: { now: () => NOW },
    });

    assert.deepEqual(await reconciler.finalizeClaimedVerifiedSync({
        operation: runningOperation({ ownerGeneration: 99, password: 'operation-secret' }),
        resolvedUsers: resolvedUsers(),
        verification: verifiedAttestation({ rawCommand: 'private-command' }),
        workerId: 'worker-1',
        ownerGeneration: 2,
    }), {
        ok: true,
        operationId: 'operation-17',
        reconciledUserCount: 2,
        finalizedAt: NOW,
    });
    assert.deepEqual(calls, [{
        operationId: 'operation-17',
        relayNode: 'relay-1',
        credentialRevision: 9,
        resolvedUsers: resolvedUsers().map(({ id, relayNode, login, ip, enabled, desiredRevision }) => ({
            id, relayNode, login, ip, enabled, desiredRevision,
        })),
        verification: verifiedAttestation(),
        workerId: 'worker-1',
        ownerGeneration: 2,
        now: NOW,
    }]);
    assert.doesNotMatch(JSON.stringify(calls), /password|private-command|operation-secret/);
});

test('claimed wrapper fails closed on missing generation, missing protected method, and legacy downgrade', async () => {
    let calls = 0;
    const repository = {
        async finalizeVerifiedSync() { calls += 1; return { operationId: 'operation-17', reconciledUserCount: 2, finalizedAt: NOW }; },
    };
    const reconciler = new L2tpUserSyncReconciler({ repository, clock: { now: () => NOW } });
    const request = {
        operation: runningOperation({ ownerGeneration: 2 }),
        resolvedUsers: resolvedUsers(),
        verification: verifiedAttestation(),
        workerId: 'worker-1',
    };
    for (const ownerGeneration of [undefined, null, 0, '2', 1.5, Number.MAX_SAFE_INTEGER + 1]) {
        const result = await reconciler.finalizeClaimedVerifiedSync({ ...request, ownerGeneration });
        assert.equal(result.error.code, 'L2TP_USER_SYNC_FINALIZE_REJECTED');
    }
    assert.equal((await reconciler.finalizeClaimedVerifiedSync({ ...request, ownerGeneration: 2 })).ok, false);
    assert.equal((await reconciler.finalizeVerifiedSync({ ...request, ownerGeneration: 2 })).ok, false);
    assert.equal(calls, 0);
});

test('legacy finalizer refuses a counted operation even if caller omits generation', async () => {
    let calls = 0;
    const reconciler = new L2tpUserSyncReconciler({
        repository: { async finalizeVerifiedSync() { calls += 1; return null; } },
        clock: { now: () => NOW },
    });
    const result = await reconciler.finalizeVerifiedSync({
        operation: runningOperation({ ownerGeneration: 2, admissionId: 'counted-admission' }),
        resolvedUsers: resolvedUsers(),
        verification: verifiedAttestation(),
        workerId: 'worker-1',
    });
    assert.equal(result.error.code, 'L2TP_USER_SYNC_FINALIZE_REJECTED');
    assert.equal(calls, 0);
});

test('returns one fixed sanitized failure for rejected or failed atomic finalization', async () => {
    const expectedFailure = {
        ok: false,
        error: {
            code: 'L2TP_USER_SYNC_FINALIZE_REJECTED',
            message: 'Verified L2TP user sync could not be finalized',
        },
    };
    const requests = {
        operation: runningOperation(),
        resolvedUsers: resolvedUsers(),
        verification: verifiedAttestation(),
        workerId: 'worker-1',
    };
    const rejected = new L2tpUserSyncReconciler({
        repository: { async finalizeVerifiedSync() { return null; } },
        clock: { now: () => NOW },
    });
    const failed = new L2tpUserSyncReconciler({
        repository: {
            async finalizeVerifiedSync() {
                throw new Error('database leaked transient-disabled-password');
            },
        },
        clock: { now: () => NOW },
    });

    const results = await Promise.all([
        rejected.finalizeVerifiedSync(requests),
        failed.finalizeVerifiedSync(requests),
    ]);

    assert.deepEqual(results, [expectedFailure, expectedFailure]);
    assert.doesNotMatch(JSON.stringify(results), /password|database|worker-1|relay-1/i);
});
