'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    CURRENT_USER_SELECT,
    L2tpUserSyncRepository,
} = require('../repositories/l2tpUserSyncRepository');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const SESSION = Object.freeze({ id: 'transaction-session' });

function queryReturning(result, trace, label) {
    return {
        select(selection) {
            trace.push({ label: `${label}.select`, selection });
            return this;
        },
        sort(sort) {
            trace.push({ label: `${label}.sort`, sort });
            return this;
        },
        async lean() {
            trace.push({ label: `${label}.lean` });
            return result;
        },
    };
}

function currentUsers() {
    return [
        {
            _id: 'user-active',
            relayNode: 'relay-1',
            login: 'alice',
            ip: '10.77.0.10',
            enabled: true,
            desiredRevision: 8,
        },
        {
            _id: 'user-disabled',
            relayNode: 'relay-1',
            login: 'disabled',
            ip: '10.77.0.11',
            enabled: false,
            desiredRevision: 9,
        },
    ];
}

function verifiedAttestationForRepository(overrides = {}) {
    return {
        ok: true,
        credentialRevision: 9,
        enabledUserCount: 1,
        managedUserCount: 1,
        code: 'USERS_VERIFIED',
        ...overrides,
    };
}

function finalizeRequest(overrides = {}) {
    return {
        operationId: 'operation-17',
        relayNode: 'relay-1',
        credentialRevision: 9,
        workerId: 'worker-1',
        now: NOW,
        resolvedUsers: currentUsers().map(user => ({
            id: user._id,
            relayNode: user.relayNode,
            login: user.login,
            ip: user.ip,
            enabled: user.enabled,
            desiredRevision: user.desiredRevision,
        })),
        verification: {
            ok: true,
            credentialRevision: 9,
            enabledUserCount: 1,
            managedUserCount: 1,
            code: 'USERS_VERIFIED',
        },
        ...overrides,
    };
}

function createHarness(overrides = {}) {
    const trace = [];
    const persistedUsers = overrides.currentUsers ?? currentUsers();
    const L2tpOperation = {
        findOneAndUpdate(filter, update, options) {
            trace.push({ label: 'operation.cas', filter, update, options });
            return queryReturning({
                _id: 'operation-17',
                node: 'relay-1',
                kind: 'sync_users',
                status: 'running',
                leaseOwner: 'worker-1',
                leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
                plan: { desired: { credentialRevision: 9 } },
            }, trace, 'operation');
        },
        ...overrides.L2tpOperation,
    };
    const RelayL2tpState = {
        findOneAndUpdate(filter, update, options) {
            trace.push({ label: 'state.cas', filter, update, options });
            return queryReturning({
                node: 'relay-1',
                desiredState: 'installed',
                status: 'installed',
                secretRevision: 9,
            }, trace, 'state');
        },
        ...overrides.RelayL2tpState,
    };
    const L2tpUser = {
        find(filter, projection, options) {
            trace.push({ label: 'users.find', filter, projection, options });
            return queryReturning(persistedUsers, trace, 'users');
        },
        async bulkWrite(operations, options) {
            trace.push({ label: 'users.bulkWrite', operations, options });
            return { matchedCount: operations.length, modifiedCount: operations.length };
        },
        ...overrides.L2tpUser,
    };
    const transactionRunner = overrides.transactionRunner ?? (async work => {
        trace.push({ label: 'transaction.begin' });
        try {
            const result = await work(SESSION);
            trace.push({ label: 'transaction.commit' });
            return result;
        } catch (error) {
            trace.push({ label: 'transaction.abort' });
            throw error;
        }
    });
    return {
        trace,
        repository: new L2tpUserSyncRepository({
            L2tpOperation,
            RelayL2tpState,
            L2tpUser,
            transactionRunner,
        }),
    };
}

test('atomically fences operation and relay state before reconciling enabled and verified-absent disabled users', async () => {
    const { repository, trace } = createHarness();

    const result = await repository.finalizeVerifiedSync(finalizeRequest());

    assert.deepEqual(result, {
        operationId: 'operation-17',
        reconciledUserCount: 2,
        finalizedAt: NOW,
    });
    assert.deepEqual(trace.map(entry => entry.label), [
        'transaction.begin',
        'operation.cas',
        'operation.select',
        'operation.lean',
        'state.cas',
        'state.select',
        'state.lean',
        'users.find',
        'users.sort',
        'users.lean',
        'users.bulkWrite',
        'transaction.commit',
    ]);

    const operationCas = trace.find(entry => entry.label === 'operation.cas');
    assert.deepEqual(operationCas.filter, {
        _id: 'operation-17',
        node: 'relay-1',
        kind: 'sync_users',
        status: 'running',
        leaseOwner: 'worker-1',
        leaseUntil: { $gt: NOW },
        'plan.operationId': 'operation-17',
        'plan.relayId': 'relay-1',
        'plan.desired.credentialRevision': 9,
    });
    assert.deepEqual(operationCas.update, {
        $set: { step: 'user_sync_reconciled' },
    });
    assert.deepEqual(operationCas.options, {
        new: true,
        runValidators: true,
        session: SESSION,
    });

    const stateCas = trace.find(entry => entry.label === 'state.cas');
    assert.deepEqual(stateCas.filter, {
        node: 'relay-1',
        desiredState: 'installed',
        status: 'installed',
        secretRevision: 9,
    });
    assert.deepEqual(stateCas.update, { $set: { lastSyncAt: NOW } });
    assert.deepEqual(stateCas.options, {
        new: true,
        runValidators: true,
        session: SESSION,
    });

    const usersFind = trace.find(entry => entry.label === 'users.find');
    assert.deepEqual(usersFind, {
        label: 'users.find',
        filter: { relayNode: 'relay-1' },
        projection: CURRENT_USER_SELECT,
        options: { session: SESSION },
    });
    assert.doesNotMatch(usersFind.projection, /password|secret/i);

    const bulk = trace.find(entry => entry.label === 'users.bulkWrite');
    assert.deepEqual(bulk.options, { ordered: true, session: SESSION });
    assert.deepEqual(bulk.operations, currentUsers().map(user => ({
        updateOne: {
            filter: {
                _id: user._id,
                relayNode: user.relayNode,
                login: user.login,
                ip: user.ip,
                enabled: user.enabled,
                desiredRevision: user.desiredRevision,
            },
            update: {
                $set: {
                    appliedRevision: user.desiredRevision,
                    syncStatus: 'synced',
                    syncOperationId: 'operation-17',
                    lastSyncedAt: NOW,
                    lastErrorCode: '',
                    lastError: '',
                },
            },
        },
    })));
});

test('accepts an idempotent retry when every guarded user still matches but no row changes', async () => {
    let attempts = 0;
    const { repository, trace } = createHarness({
        L2tpUser: {
            find(filter, projection, options) {
                trace.push({ label: 'users.find', filter, projection, options });
                return queryReturning(currentUsers(), trace, 'users');
            },
            async bulkWrite(operations, options) {
                attempts += 1;
                trace.push({ label: 'users.bulkWrite', operations, options });
                return {
                    matchedCount: operations.length,
                    modifiedCount: attempts === 1 ? operations.length : 0,
                };
            },
        },
    });

    const first = await repository.finalizeVerifiedSync(finalizeRequest());
    const retry = await repository.finalizeVerifiedSync(finalizeRequest());

    assert.deepEqual(first, retry);
    assert.equal(attempts, 2);
    assert.equal(trace.filter(entry => entry.label === 'transaction.commit').length, 2);
    assert.equal(trace.some(entry => entry.label === 'transaction.abort'), false);
});

test('aborts the transaction when any guarded user row stops matching during the bulk update', async () => {
    const { repository, trace } = createHarness({
        L2tpUser: {
            find(filter, projection, options) {
                trace.push({ label: 'users.find', filter, projection, options });
                return queryReturning(currentUsers(), trace, 'users');
            },
            async bulkWrite(operations, options) {
                trace.push({ label: 'users.bulkWrite', operations, options });
                return { matchedCount: operations.length - 1, modifiedCount: 0 };
            },
        },
    });

    const result = await repository.finalizeVerifiedSync(finalizeRequest());

    assert.equal(result, null);
    assert.equal(trace.at(-1).label, 'transaction.abort');
    assert.equal(trace.some(entry => entry.label === 'transaction.commit'), false);
});

function nullQuery() {
    return {
        select() { return this; },
        sort() { return this; },
        async lean() { return null; },
    };
}

test('missing, stale, revoked, cancelled, wrong-kind, and lease-lost operations cannot update users', async () => {
    const rejectedOperationCases = [
        'missing',
        'stale credential revision',
        'revoked',
        'cancelled',
        'wrong kind',
        'foreign worker',
        'expired lease',
    ];

    for (const label of rejectedOperationCases) {
        const { repository, trace } = createHarness({
            L2tpOperation: { findOneAndUpdate: () => nullQuery() },
        });

        const result = await repository.finalizeVerifiedSync(finalizeRequest());

        assert.equal(result, null, label);
        assert.deepEqual(trace.map(entry => entry.label), [
            'transaction.begin',
            'transaction.abort',
        ], label);
        assert.equal(trace.some(entry => entry.label === 'users.bulkWrite'), false, label);
    }
});

test('relay revocation or changed installed credential revision aborts before user reads or writes', async () => {
    const { repository, trace } = createHarness({
        RelayL2tpState: { findOneAndUpdate: () => nullQuery() },
    });

    const result = await repository.finalizeVerifiedSync(finalizeRequest());

    assert.equal(result, null);
    assert.equal(trace.at(-1).label, 'transaction.abort');
    assert.equal(trace.some(entry => entry.label === 'users.find'), false);
    assert.equal(trace.some(entry => entry.label === 'users.bulkWrite'), false);
});

test('rejects a partial snapshot that omits the disabled user and leaves every applied field untouched', async () => {
    const { repository, trace } = createHarness();
    const [active] = finalizeRequest().resolvedUsers;

    const result = await repository.finalizeVerifiedSync(finalizeRequest({
        resolvedUsers: [active],
        verification: {
            ok: true,
            credentialRevision: 9,
            enabledUserCount: 1,
            managedUserCount: 1,
            code: 'USERS_VERIFIED',
        },
    }));

    assert.equal(result, null);
    assert.equal(trace.at(-1).label, 'transaction.abort');
    assert.equal(trace.some(entry => entry.label === 'users.bulkWrite'), false);
});

test('rejects an enabled canary omitted from an otherwise count-consistent resolved snapshot', async () => {
    const canary = {
        _id: 'user-canary',
        relayNode: 'relay-1',
        login: 'canary',
        ip: '10.77.0.12',
        enabled: true,
        desiredRevision: 7,
    };
    const { repository, trace } = createHarness({
        currentUsers: [...currentUsers(), canary],
    });

    const result = await repository.finalizeVerifiedSync(finalizeRequest());

    assert.equal(result, null);
    assert.equal(trace.at(-1).label, 'transaction.abort');
    assert.equal(trace.some(entry => entry.label === 'users.bulkWrite'), false);
});

test('rejects invalid user snapshots and attestations before opening a transaction', async () => {
    const invalidRequests = [
        finalizeRequest({
            resolvedUsers: finalizeRequest().resolvedUsers.map((user, index) => (
                index === 0 ? { ...user, desiredRevision: 10 } : user
            )),
        }),
        finalizeRequest({
            verification: verifiedAttestationForRepository({ managedUserCount: 2 }),
        }),
        finalizeRequest({
            verification: verifiedAttestationForRepository({ code: 'MANAGED_USERS_EXTRA' }),
        }),
    ];

    for (const request of invalidRequests) {
        const { repository, trace } = createHarness();

        const result = await repository.finalizeVerifiedSync(request);

        assert.equal(result, null);
        assert.deepEqual(trace, []);
    }
});

test('rejects stale identity revisions and mismatched or incomplete verification attestations', async () => {
    const cases = [
        {
            label: 'current desired revision changed',
            currentUsers: currentUsers().map((user, index) => (
                index === 0 ? { ...user, desiredRevision: 9 } : user
            )),
            request: finalizeRequest(),
            expectsTransaction: true,
        },
        {
            label: 'verification revision mismatch',
            currentUsers: currentUsers(),
            request: finalizeRequest({
                verification: verifiedAttestationForRepository({ credentialRevision: 8 }),
            }),
        },
        {
            label: 'managed count mismatch',
            currentUsers: currentUsers(),
            request: finalizeRequest({
                verification: verifiedAttestationForRepository({ managedUserCount: 2 }),
            }),
        },
        {
            label: 'disabled absence not verified',
            currentUsers: currentUsers(),
            request: finalizeRequest({
                verification: verifiedAttestationForRepository({ code: 'MANAGED_USERS_EXTRA' }),
            }),
        },
    ];

    for (const { label, currentUsers: rows, request, expectsTransaction = false } of cases) {
        const { repository, trace } = createHarness({ currentUsers: rows });
        const result = await repository.finalizeVerifiedSync(request);
        assert.equal(result, null, label);
        if (expectsTransaction) {
            assert.equal(trace.at(-1).label, 'transaction.abort', label);
        } else {
            assert.deepEqual(trace, [], label);
        }
        assert.equal(trace.some(entry => entry.label === 'users.bulkWrite'), false, label);
    }
});
