'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpPppUserReadinessService,
} = require('../services/l2tpPppUserReadiness');

const NOW = new Date('2026-09-27T12:00:00.000Z');

function installedState(overrides = {}) {
    return {
        node: 'relay-1',
        desiredState: 'installed',
        status: 'installed',
        secretRevision: 41,
        ...overrides,
    };
}

function syncedUsers() {
    return [
        {
            id: 'user-1',
            relayNode: 'relay-1',
            login: 'alice',
            ip: '10.77.0.10',
            enabled: true,
            desiredRevision: 41,
            appliedRevision: 41,
            syncStatus: 'synced',
            passwordEncrypted: 'must-not-leak',
        },
    ];
}

function createService(overrides = {}) {
    const queueCalls = [];
    const service = new L2tpPppUserReadinessService({
        loadRelayState: async () => installedState(),
        loadUsers: async () => syncedUsers(),
        queueSync: async request => { queueCalls.push(request); },
        clock: { now: () => NOW },
        ...overrides,
    });
    return { service, queueCalls };
}

test('reports ready when the relay is installed and the desired/applied user snapshot matches', async () => {
    const { service, queueCalls } = createService();

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, true);
    assert.equal(result.status, 'ready');
    assert.equal(result.reason, null);
    assert.equal(result.relayNode, 'relay-1');
    assert.equal(result.userCount, 1);
    assert.equal(result.enabledUserCount, 1);
    assert.equal(result.syncQueued, false);
    assert.equal(typeof result.desiredHash, 'string');
    assert.match(result.desiredHash, /^[0-9a-f]{64}$/);
    assert.equal(queueCalls.length, 0);
    assert.equal(JSON.stringify(result).includes('must-not-leak'), false);
});

test('fails closed when the relay L2TP state is not installed', async () => {
    const { service, queueCalls } = createService({
        loadRelayState: async () => installedState({ status: 'degraded' }),
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'blocked');
    assert.equal(result.reason.code, 'L2TP_PPP_NOT_INSTALLED');
    assert.equal(typeof result.reason.message, 'string');
    assert.equal(queueCalls.length, 0);
});

test('constructor rejects missing dependencies', () => {
    assert.throws(() => new L2tpPppUserReadinessService(), TypeError);
    assert.throws(
        () => new L2tpPppUserReadinessService({
            loadRelayState: async () => null,
            loadUsers: async () => [],
            queueSync: async () => {},
        }),
        TypeError,
    );
    assert.throws(
        () => new L2tpPppUserReadinessService({
            loadRelayState: async () => null,
            loadUsers: async () => [],
            queueSync: async () => {},
            clock: { now: () => NOW },
            maxSyncAttempts: 0,
        }),
        TypeError,
    );
});

test('treats an installed relay without users as ready', async () => {
    const { service, queueCalls } = createService({
        loadUsers: async () => [],
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, true);
    assert.equal(result.userCount, 0);
    assert.equal(queueCalls.length, 0);
});

test('tracks retry budgets independently per relay', async () => {
    let now = NOW.getTime();
    const queueCalls = [];
    const service = new L2tpPppUserReadinessService({
        loadRelayState: async () => installedState(),
        loadUsers: async relay => (relay === 'relay-1' ? driftedUsers() : syncedUsers()),
        queueSync: async request => { queueCalls.push(request); },
        clock: { now: () => new Date(now) },
        maxSyncAttempts: 1,
        minRetryIntervalMs: 0,
    });

    const first = await service.assess({ relayNode: 'relay-1' });
    assert.equal(first.syncQueued, true);

    // A healthy relay is unaffected by the other relay's drift episode.
    const other = await service.assess({ relayNode: 'relay-2' });
    assert.equal(other.ready, true);
    assert.equal(other.status, 'ready');

    now += 1;
    const exhausted = await service.assess({ relayNode: 'relay-1' });
    assert.equal(exhausted.status, 'blocked');
    assert.equal(exhausted.reason.code, 'L2TP_PPP_SYNC_RETRY_EXHAUSTED');
    assert.equal(queueCalls.length, 1);
});

test('fails closed when the relay L2TP state is missing', async () => {
    const { service, queueCalls } = createService({
        loadRelayState: async () => null,
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'blocked');
    assert.equal(result.reason.code, 'L2TP_PPP_NOT_INSTALLED');
    assert.equal(queueCalls.length, 0);
});

function driftedUsers() {
    return [
        {
            id: 'user-1',
            relayNode: 'relay-1',
            login: 'alice',
            ip: '10.77.0.10',
            enabled: true,
            desiredRevision: 42,
            appliedRevision: 41,
            syncStatus: 'pending',
            passwordEncrypted: 'must-not-leak',
        },
    ];
}

test('queues the existing sync_users path once when desired and applied revisions drift', async () => {
    const { service, queueCalls } = createService({
        loadUsers: async () => driftedUsers(),
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'reconciling');
    assert.equal(result.reason.code, 'L2TP_PPP_USER_REVISION_DRIFT');
    assert.equal(result.syncQueued, true);
    assert.equal(result.syncAttempts, 1);
    assert.equal(queueCalls.length, 1);
    assert.deepEqual(Object.keys(queueCalls[0]).sort(), ['reasonCode', 'relayNode']);
    assert.equal(queueCalls[0].relayNode, 'relay-1');
    assert.equal(queueCalls[0].reasonCode, 'L2TP_PPP_USER_REVISION_DRIFT');
    assert.equal(JSON.stringify(queueCalls).includes('must-not-leak'), false);
});

test('treats an applied revision ahead of syncStatus as drift', async () => {
    const { service, queueCalls } = createService({
        loadUsers: async () => [
            { ...syncedUsers()[0], syncStatus: 'error' },
        ],
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'reconciling');
    assert.equal(result.syncQueued, true);
    assert.equal(queueCalls.length, 1);
});

test('bounds automatic resync retries and then fails closed with a reason', async () => {
    let now = NOW.getTime();
    const { service, queueCalls } = createService({
        loadUsers: async () => driftedUsers(),
        clock: { now: () => new Date(now) },
        maxSyncAttempts: 2,
        minRetryIntervalMs: 1000,
    });

    const first = await service.assess({ relayNode: 'relay-1' });
    assert.equal(first.syncQueued, true);
    assert.equal(first.syncAttempts, 1);

    // Too soon: the in-flight sync is not re-queued.
    const throttled = await service.assess({ relayNode: 'relay-1' });
    assert.equal(throttled.ready, false);
    assert.equal(throttled.status, 'reconciling');
    assert.equal(throttled.syncQueued, false);
    assert.equal(throttled.syncAttempts, 1);
    assert.equal(queueCalls.length, 1);

    now += 1000;
    const second = await service.assess({ relayNode: 'relay-1' });
    assert.equal(second.syncQueued, true);
    assert.equal(second.syncAttempts, 2);
    assert.equal(queueCalls.length, 2);

    now += 1000;
    const exhausted = await service.assess({ relayNode: 'relay-1' });
    assert.equal(exhausted.ready, false);
    assert.equal(exhausted.status, 'blocked');
    assert.equal(exhausted.reason.code, 'L2TP_PPP_SYNC_RETRY_EXHAUSTED');
    assert.equal(exhausted.syncQueued, false);
    assert.equal(queueCalls.length, 2);
});

test('resets the retry budget once the drift is reconciled', async () => {
    let drifted = true;
    let now = NOW.getTime();
    const { service, queueCalls } = createService({
        loadUsers: async () => (drifted ? driftedUsers() : syncedUsers()),
        clock: { now: () => new Date(now) },
        maxSyncAttempts: 1,
        minRetryIntervalMs: 0,
    });

    const first = await service.assess({ relayNode: 'relay-1' });
    assert.equal(first.syncAttempts, 1);

    drifted = false;
    const recovered = await service.assess({ relayNode: 'relay-1' });
    assert.equal(recovered.ready, true);
    assert.equal(recovered.status, 'ready');

    // A later, independent drift episode gets a fresh budget.
    drifted = true;
    now += 1;
    const nextEpisode = await service.assess({ relayNode: 'relay-1' });
    assert.equal(nextEpisode.syncQueued, true);
    assert.equal(nextEpisode.syncAttempts, 1);
    assert.equal(queueCalls.length, 2);
});

test('confirms readiness against the actual relay chap-secrets readback when available', async () => {
    const readbackCalls = [];
    const { service, queueCalls } = createService({
        readback: async request => {
            readbackCalls.push(request);
            return {
                ok: true,
                credentialRevision: 41,
                enabledUserCount: 1,
                managedUserCount: 1,
                code: 'USERS_VERIFIED',
            };
        },
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, true);
    assert.equal(result.status, 'ready');
    assert.equal(result.nodeVerified, true);
    assert.equal(queueCalls.length, 0);
    assert.equal(readbackCalls.length, 1);
    assert.deepEqual(Object.keys(readbackCalls[0]).sort(), ['relayNode']);
    assert.equal(readbackCalls[0].relayNode, 'relay-1');
});

test('queues resync when the relay chap-secrets readback contradicts the desired snapshot', async () => {
    const { service, queueCalls } = createService({
        readback: async () => ({
            ok: false,
            credentialRevision: 41,
            enabledUserCount: 0,
            managedUserCount: 0,
            code: 'MANAGED_USERS_MISSING',
        }),
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'reconciling');
    assert.equal(result.reason.code, 'L2TP_PPP_CHAP_SECRETS_DRIFT');
    assert.equal(result.syncQueued, true);
    assert.equal(queueCalls.length, 1);
    assert.equal(queueCalls[0].reasonCode, 'L2TP_PPP_CHAP_SECRETS_DRIFT');
});

test('fails closed when the relay chap-secrets readback fails', async () => {
    const { service, queueCalls } = createService({
        readback: async () => { throw new Error('transport down'); },
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'blocked');
    assert.equal(result.reason.code, 'L2TP_PPP_READBACK_FAILED');
    assert.equal(result.nodeVerified, false);
    assert.equal(queueCalls.length, 0);
});

test('marks database-only readiness as node-unverified when no readback is configured', async () => {
    const { service } = createService();

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, true);
    assert.equal(result.nodeVerified, false);
});

test('fails closed when the desired snapshot cannot be loaded', async () => {
    const { service, queueCalls } = createService({
        loadUsers: async () => { throw new Error('mongo down'); },
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'blocked');
    assert.equal(result.reason.code, 'L2TP_PPP_READINESS_CHECK_FAILED');
    assert.equal(queueCalls.length, 0);
});

test('fails closed when queueing the resync fails, consuming one retry', async () => {
    const { service, queueCalls } = createService({
        loadUsers: async () => driftedUsers(),
        queueSync: async () => { throw new Error('queue unavailable'); },
        maxSyncAttempts: 2,
        minRetryIntervalMs: 0,
    });

    const result = await service.assess({ relayNode: 'relay-1' });

    assert.equal(result.ready, false);
    assert.equal(result.status, 'blocked');
    assert.equal(result.reason.code, 'L2TP_PPP_SYNC_QUEUE_FAILED');
    assert.equal(result.syncAttempts, 1);
    assert.equal(queueCalls.length, 0);
});
