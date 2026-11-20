'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const { request } = require('./helpers/rebuildPanelRequest');
const { issuePanelCsrfToken } = require('../../routes/panel/csrf');

const prefix = '/rebuild/relays/l2tp/accounts';
const actions = [
    ['create', 'createRelayAccount', 'created', 201],
    ['disable', 'disableRelayAccount', 'disabled', 200],
    ['delete', 'deleteRelayAccount', 'deleted', 200],
];
const login = 'fixture-user';
const password = 'dummy-account-password';
const privateDetail = 'dummy-private-backend-detail';

// Mount the exported stock router (including its default shared limiter).
// Stub only onboarding persistence and the service behind the public handlers.
test('stock rebuild account POSTs require panel auth, onboarding, CSRF and the shared limiter; replies never echo secrets', { timeout: 5000 }, async t => {
    t.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());
    const old = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = 'true';
    t.after(() => { if (old === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = old; });
    const Settings = require('../../models/settingsModel');
    const serviceModule = require('../rebuildService');
    let completed = false, failure, invalidReceipt = false;
    const calls = [];
    t.mock.method(Settings, 'get', async () => ({ deployment: { completed } }));
    t.mock.method(serviceModule, 'createRebuildService', () => Object.fromEntries(actions.map(([action, method, status]) => [method, async input => {
        calls.push(action);
        assert.deepEqual(Object.keys(input).sort(), action === 'create' ? ['login', 'password'] : ['login']);
        assert.equal(input.login, login);
        if (action === 'create') assert.ok(input.password === password, 'must pass the supplied password only to Create');
        if (failure) throw Object.assign(new Error(`${password} ${privateDetail}`), { code: failure, password, privateDetail });
        // Even extra internal success metadata must not cross the HTTP boundary.
        return { executionMode: 'rebuild', status, login, relayCount: invalidReceipt ? privateDetail : 2,
            internal: { password, privateDetail } };
    }])));

    const panel = require('../../routes/panel');
    const { invalidateOnboardingCache } = require('../../routes/panel/helpers');
    const { routerForRebuild } = require('../../routes/cascadeRebuild');
    const apiAuth = require('../../middleware/auth');
    t.after(invalidateOnboardingCache);
    invalidateOnboardingCache();
    const app = express();
    app.use('/panel', panel);
    app.use('/api/cascade', apiAuth, routerForRebuild({ service: {} }));
    const session = { authenticated: true };
    const token = issuePanelCsrfToken({ session });
    const authorized = { session, headers: { 'x-csrf-token': token } };
    const data = action => action === 'create' ? { login, password } : { login };
    const send = async (action, opts = {}, appUnderTest = app, mount = '/panel') => {
        const response = await request(appUnderTest, `${mount}${prefix}/${action}`, { body: data(action), ...opts });
        const wire = JSON.stringify(response);
        for (const secret of [password, privateDetail, token]) assert.ok(!wire.includes(secret), 'response echoed a secret');
        return response;
    };

    for (const [action] of actions) {
        const loginRedirect = await send(action, { headers: { 'x-api-key': 'dummy-api-key' } });
        assert.equal(loginRedirect.status, 302);
        assert.equal(loginRedirect.headers.location, '/panel/login');
        const onboardingRedirect = await send(action, authorized);
        assert.equal(onboardingRedirect.status, 302);
        assert.equal(onboardingRedirect.headers.location, '/panel/wizard');
    }
    completed = true;
    invalidateOnboardingCache();
    process.env.C3_REBUILD_ENABLED = 'false';
    const classic = express();
    classic.use('/panel', panel.createPanelRouter());
    process.env.C3_REBUILD_ENABLED = 'true';
    for (const [action] of actions) {
        const noCsrf = await send(action, { session });
        const wrongSession = await send(action, { ...authorized, session: { authenticated: true } });
        const crossOrigin = await send(action, { ...authorized, headers: { ...authorized.headers, origin: 'https://other.invalid' } });
        assert.equal(noCsrf.status, 403);
        assert.equal(wrongSession.status, 403);
        assert.equal(crossOrigin.status, 403);
        for (const denied of [noCsrf, wrongSession, crossOrigin]) assert.equal(denied.headers['ratelimit-remaining'], undefined);
        assert.equal((await send(action, authorized, classic)).status, 404);
        assert.equal((await send(action, authorized, app, '/api/cascade')).status, 404);
        assert.equal((await send(action, { ...authorized, method: 'DELETE' })).status, 404);
    }
    assert.deepEqual(calls, []);

    for (const [i, [action, , status, httpStatus]] of actions.entries()) {
        const success = await send(action, { session, body: { ...data(action), _csrf: token } });
        assert.equal(success.status, httpStatus);
        assert.equal(success.headers['ratelimit-limit'], '10');
        assert.equal(success.headers['ratelimit-remaining'], String(9 - i));
        assert.deepEqual(JSON.parse(success.body), { executionMode: 'rebuild', status, login, relayCount: 2 });
    }
    // Use a separate peer for input/error cases, leaving exactly three hits on
    // the main peer's shared bucket. The invalid selectors must never dispatch.
    const alternate = { ...authorized, ip: '192.0.2.11' };
    for (const [action] of actions) {
        const extra = action === 'create' ? { nodeId: privateDetail } : { password };
        for (const invalid of [await send(action, { ...alternate, body: { ...data(action), ...extra } }),
            await send(`${action}?relay=${privateDetail}`, { ...alternate, body: data(action) })]) {
            assert.equal(invalid.status, 400);
            assert.deepEqual(JSON.parse(invalid.body), { error: { code: 'REBUILD_L2TP_ACCOUNTS_INVALID_REQUEST' } });
        }
    }
    assert.deepEqual(calls, actions.map(([action]) => action));
    for (const [action, code, status, expected] of [
        ['create', 'REBUILD_L2TP_ACCOUNTS_INTENT_UNKNOWN', 409, { code: 'REBUILD_L2TP_ACCOUNTS_INTENT_UNKNOWN', retryAllowed: false }],
        ['disable', 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE', 503, { code: 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE' }],
        ['delete', privateDetail, 409, { code: 'REBUILD_L2TP_ACCOUNTS_FAILED' }],
    ]) {
        failure = code;
        const denied = await send(action, alternate);
        assert.equal(denied.status, status);
        assert.deepEqual(JSON.parse(denied.body), { error: expected });
    }
    failure = undefined;
    invalidReceipt = true;
    const malformed = await send('delete', alternate);
    assert.equal(malformed.status, 409);
    assert.deepEqual(JSON.parse(malformed.body), { error: { code: 'REBUILD_L2TP_ACCOUNTS_FAILED' } });
    invalidReceipt = false;
    // Seven more admitted requests fill the same bucket. Install shares it.
    for (let i = 0; i < 7; i++) {
        const response = await send('disable', authorized);
        assert.equal(response.status, 200);
        assert.equal(response.headers['ratelimit-remaining'], String(6 - i));
    }
    for (const [action] of actions) assert.equal((await send(action, authorized)).status, 429);
    const install = await request(app, `/panel/rebuild/relays/${'a'.repeat(24)}/l2tp/install`, authorized);
    assert.equal(install.status, 429);
    assert.deepEqual(calls, ['create', 'disable', 'delete', 'create', 'disable', 'delete', 'delete', ...Array(7).fill('disable')]);
});
