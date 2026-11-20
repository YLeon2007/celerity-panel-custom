'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const express = require('express');
const { issuePanelCsrfToken } = require('../../routes/panel/csrf');
const { routerForRebuild } = require('../../routes/cascadeRebuild');
const serviceModule = require('../rebuildService');
const id = 'a'.repeat(24);
const route = `/rebuild/relays/${id}/l2tp`;

// Exercise the real Express mounting/middleware without opening even a loopback socket.
function request(app, url, { method = 'POST', session, headers, body = {} } = {}) {
    return new Promise((resolve, reject) => {
        const wire = [];
        const socket = new Duplex({ read() {}, write(chunk, enc, done) { wire.push(chunk.toString()); done(); } });
        const req = new IncomingMessage(socket);
        req.method = method;
        req.url = url;
        req.headers = { host: 'panel.fixture.invalid', ...headers };
        req.session = session;
        req.body = body;
        req.apiKey = { scopes: ['nodes:write'] };
        req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            const [head, ...rest] = wire.join('').split('\r\n\r\n');
            resolve({ status: res.statusCode, head, body: rest.join('\r\n\r\n') });
            socket.destroy();
        });
        app(req, res);
    });
}

test('mounted rebuild panel remove shares auth, onboarding, CSRF and install limiter; no legacy/API remove', { timeout: 5000 }, async t => {
    const previous = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = 'true';
    t.after(() => { if (previous === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = previous; });
    t.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());
    const Settings = require('../../models/settingsModel');
    let completed = false, limit = 0, deny = false;
    const calls = [];
    t.mock.method(Settings, 'get', async () => ({ deployment: { completed } }));
    t.mock.method(serviceModule, 'createRebuildService', () => ({
        async installRelay(nodeId) { calls.push(['install', nodeId]); return { status: 'installed' }; },
        async removeRelay() { assert.fail('unconfirmed service must never be called by the router'); },
        async confirmRemoveRelay() { assert.fail('no preview ticket was issued'); },
    }));
    const { createPanelRouter } = require('../../routes/panel');
    const { invalidateOnboardingCache } = require('../../routes/panel/helpers');
    invalidateOnboardingCache();
    t.after(invalidateOnboardingCache);
    const app = express();
    app.use('/panel', createPanelRouter({
        l2tpModuleEntry: { registerRoutes: () => assert.fail('legacy L2TP must not be registered') },
        l2tpRateLimiter(req, res, next) { limit++; if (deny) return res.status(429).end(); return next(); },
    }));
    app.use('/api/cascade', routerForRebuild({ service: {}, Node: {}, Link: {} }));
    const session = { authenticated: true };
    const csrf = issuePanelCsrfToken({ session });
    const authorized = { session, headers: { 'x-csrf-token': csrf } };
    const url = `/panel${route}/remove`;
    const anonymous = await request(app, url);
    assert.equal(anonymous.status, 302);
    assert.match(anonymous.head, /Location: \/panel\/login/);
    const onboarding = await request(app, url, authorized);
    assert.equal(onboarding.status, 302);
    assert.match(onboarding.head, /Location: \/panel\/wizard/);
    completed = true;
    invalidateOnboardingCache();
    assert.equal((await request(app, url, { session })).status, 403);
    assert.equal((await request(app, url, { ...authorized, headers: { ...authorized.headers, origin: 'https://other.invalid' } })).status, 403);
    assert.equal((await request(app, `/api/cascade${route}/remove`, authorized)).status, 404);
    assert.equal((await request(app, `/panel/nodes/${id}/l2tp/remove`, authorized)).status, 409);
    assert.equal((await request(app, url, { ...authorized, method: 'DELETE' })).status, 404);
    assert.equal((await request(app, `/panel${route}/uninstall`, authorized)).status, 404);
    assert.equal(limit, 0);
    assert.deepEqual(calls, []);
    assert.equal((await request(app, url, authorized)).status, 409, 'CSRF alone must not permit Remove');
    assert.deepEqual(calls, []);
    assert.equal((await request(app, `${url}?node=other`, authorized)).status, 400);
    assert.equal((await request(app, url, { ...authorized, body: { backupId: 'injection' } })).status, 400);
    assert.equal((await request(app, `/panel${route}/install`, authorized)).status, 200);
    const forged = await request(app, url, { session, body: { _csrf: csrf, decision: 'confirm', ticket: 'a'.repeat(64) } });
    assert.equal(forged.status, 409);
    assert.deepEqual(JSON.parse(forged.body), { error: { code: 'REBUILD_L2TP_REMOVE_CONFIRMATION_REQUIRED' } });
    deny = true;
    assert.equal((await request(app, url, authorized)).status, 429);
    assert.deepEqual(calls, [['install', id]]);
    deny = false;
    assert.equal((await request(app, url.replace(id, `${id}%0A`), authorized)).status, 400);
    process.env.C3_REBUILD_ENABLED = 'false';
    const classic = express();
    classic.use('/panel', createPanelRouter({ l2tpModuleEntry: { registerRoutes() {} } }));
    assert.equal((await request(classic, url, authorized)).status, 404);
});
