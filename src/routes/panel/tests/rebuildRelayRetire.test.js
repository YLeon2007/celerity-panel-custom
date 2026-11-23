'use strict';

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const { resolve: resolvePath } = require('node:path');
const { performance } = require('node:perf_hooks');
const { issuePanelCsrfToken } = require('../csrf');

const id = 'a'.repeat(24), other = 'b'.repeat(24);
const url = (action, target = id) => `/panel/rebuild/relays/${target}/retire/${action}`;
const privateValue = 'PRIVATE_FIXTURE_NEVER_FOR_HTTP';
const since = '2026-01-02T03:04:05.000Z';

after(() => require('../../../services/sshPoolService').closeAll());

function request(app, url, { method = 'POST', session, sessionID, headers, body = {}, raw = JSON.stringify(body), ip = '192.0.2.10' }) {
    return new Promise((resolve, reject) => {
        const wire = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { wire.push(chunk.toString()); done(); } });
        socket.remoteAddress = ip;
        const req = new IncomingMessage(socket);
        Object.assign(req, { method, url, session, sessionID, complete: true, headers: { host: 'fixture.invalid',
            ...headers, ...(method === 'POST' && { 'content-length': String(Buffer.byteLength(raw)) }) } });
        if (method === 'POST') req.push(Buffer.from(raw));
        req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            resolve({ status: res.statusCode, headers: res.getHeaders(), body: wire.join('').split('\r\n\r\n').slice(1).join('\r\n\r\n') });
            socket.destroy();
        });
        app(req, res);
    });
}

function mount(t, enabled = true) {
    const oldMode = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = String(enabled);
    t.after(() => { if (oldMode === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = oldMode; });
    const config = require('../../../../config');
    const whitelist = config.PANEL_IP_WHITELIST;
    config.PANEL_IP_WHITELIST = '192.0.2.10';
    t.after(() => { config.PANEL_IP_WHITELIST = whitelist; });
    const state = { completed: true, activeClients: 0, accountCount: 2, mode: 'online', allowed: true, unavailableSince: null };
    const Settings = require('../../../models/settingsModel');
    t.mock.method(Settings, 'get', async () => ({ deployment: { completed: state.completed } }));
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: async () => {
        if (state.onboardingError) throw new Error(privateValue);
        return { deployment: { completed: state.completed } };
    } }) }));
    const calls = [];
    let factory = 0;
    t.mock.method(require('../../../services/rebuildService'), 'createRebuildService', () => {
        const generation = ++factory;
        return {
            async previewRetireRelay(nodeId) {
                const estimate = Object.freeze({ nodeId, activeClients: state.activeClients, accountCount: state.accountCount,
                    mode: state.mode, allowed: state.allowed, unavailableSince: state.unavailableSince,
                    ...state.extra, unprojected: privateValue });
                calls.push({ action: 'preview', nodeId, estimate, generation });
                if (state.previewError) throw state.previewError;
                return estimate;
            },
            async confirmRetireRelay(nodeId, estimate, decision) {
                calls.push({ action: 'confirm', nodeId, estimate, decision, generation });
                if (state.confirmError) throw state.confirmError;
                if (state.barrier) await state.barrier;
                return { nodeId, status: 'deleted', secret: privateValue, ...state.result };
            },
        };
    });
    const panel = require('../index');
    const app = express();
    app.set('views', resolvePath(__dirname, '../../../../views'));
    app.set('view engine', 'ejs');
    if (enabled) app.use(require('../rebuildL2tp').rebuildL2tpIngress);
    app.use(express.json());
    app.use(require('../../../middleware/i18n').i18nMiddleware);
    app.use((_req, res, next) => { res.locals.c3Rebuild = enabled; next(); });
    app.use('/panel', panel.createPanelRouter({ l2tpRateLimiter: (_req, _res, next) => next() }));
    const session = { authenticated: true, adminUsername: 'fixture-admin' };
    const headers = { 'content-type': 'application/json', 'x-csrf-token': issuePanelCsrfToken({ session }) };
    const send = (path, opts = {}) => request(app, path, { session, sessionID: 'fixture-session', headers, ...opts });
    return { state, calls, send, session, headers };
}

function checked(response, status) {
    assert.equal(response.status, status, response.body);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.body.includes(privateValue), false);
    return response.headers['content-type']?.startsWith('application/json') ? JSON.parse(response.body) : null;
}

const getPreview = async (f, nodeId = id) => checked(await f.send(url('preview', nodeId)), 200).preview;
const submit = (f, ticket, decision, opts) => f.send(url('confirm'), { body: { ticket, decision }, ...opts });

test('the mounted node list renders a CSRF-bound relay action but does not preview on page load', async t => {
    const f = mount(t);
    const node = { _id: id, name: 'Fixture Relay', ip: '192.0.2.1', type: 'xray', cascadeRole: 'relay', active: true, status: 'online' };
    t.mock.method(require('../../../models/hyNodeModel'), 'find', () => ({ populate: () => ({ sort: async () => [node] }) }));
    t.mock.method(require('../../../models/cascadeLinkModel'), 'countDocuments', async () => 0);
    t.mock.method(require('../../../services/cacheService'), 'getGroups', async () => []);
    const page = await f.send('/panel/nodes', { method: 'GET' });
    assert.equal(page.status, 200);
    assert.match(page.body, new RegExp(`data-retire-node="${id}"`));
    assert.ok(!page.body.includes(`deleteNode('${id}')`));
    assert.deepEqual(f.calls, []);
    const dialog = page.body.match(/<dialog\b[^>]* id="relay-retire-dialog"[^>]*>/)[0];
    const token = dialog.match(/data-csrf="([A-Za-z0-9_-]+)"/)[1];
    assert.equal(token, f.headers['x-csrf-token']);
    const reply = checked(await f.send(url('preview'), { headers: { 'content-type': 'application/json', 'x-csrf-token': token } }), 200);
    assert.equal(reply.preview.nodeId, id);
});

for (const [mode, activeClients, accountCount, unavailableSince, decision] of [
    ['online', 0, 2, null, 'delete'], ['online', 5, 5, null, 'force'], ['abandon', null, null, since, 'abandon'],
]) {
    test(`${decision}: separately issued ticket passes the exact opaque estimate across service factories once`, async t => {
        const f = mount(t);
        Object.assign(f.state, { mode, activeClients, accountCount, unavailableSince });
        checked(await submit(f, 'a'.repeat(64), decision), 409);
        assert.deepEqual(f.calls, []);
        const preview = await getPreview(f);
        assert.match(preview.ticket, /^[a-f0-9]{64}$/);
        assert.deepEqual(preview, { nodeId: id, mode, activeClients, accountCount, unavailableSince, allowed: true, ticket: preview.ticket });
        assert.equal(f.calls.length, 1);
        assert.deepEqual(checked(await submit(f, preview.ticket, decision), 200), { nodeId: id, status: 'deleted' });
        assert.equal(f.calls[1].estimate, f.calls[0].estimate);
        assert.notEqual(f.calls[0].generation, f.calls[1].generation);
        assert.equal(f.calls[1].decision, decision);
        checked(await submit(f, preview.ticket, decision), 409);
        assert.equal(f.calls.length, 2);
    });
}

test('admin, whitelist, onboarding, CSRF, method and inputs are checked before service construction', async t => {
    const f = mount(t);
    const { send, headers, session } = f;
    checked(await send(url('preview'), { session: undefined }), 302);
    checked(await send(url('preview'), { session: { ...session, adminUsername: '' } }), 403);
    checked(await send(url('preview'), { sessionID: undefined }), 403);
    checked(await send(url('preview'), { ip: '192.0.2.11' }), 403);
    checked(await send(url('preview'), { headers: { 'content-type': 'application/json' } }), 403);
    checked(await send(url('preview'), { headers: { ...headers, origin: 'https://unrelated.invalid' } }), 403);
    checked(await send(url('preview'), { headers: { ...headers, 'x-csrf-token': 'é' + 'a'.repeat(42) } }), 403);
    checked(await send(url('preview'), { method: 'GET' }), 405);
    checked(await send(`${url('preview')}?`), 400);
    checked(await send(url('preview', `%61${id.slice(1)}`)), 400);
    checked(await send(url('preview'), { body: { mode: 'abandon' } }), 400);
    checked(await send(url('confirm'), { body: { ticket: 'a'.repeat(64), decision: 'force', activeClients: 0 } }), 400);
    for (const raw of ['', '{', `${' '.repeat(1024)}{}`]) checked(await send(url('preview'), { raw }), 400);
    const raw = `{"ticket":"${'a'.repeat(64)}","decision":"${privateValue}","decision":"force"}`;
    checked(await send(url('confirm'), { raw }), 400);
    f.state.completed = false;
    checked(await send(url('preview')), 302);
    f.state.onboardingError = true;
    checked(await send(url('preview')), 503);
    assert.deepEqual(f.calls, []);
});

test('wrong node or session never consumes a matching ticket; wrong or missing force decision refuses with X and consumes it', async t => {
    const f = mount(t);
    f.state.activeClients = 7;
    const preview = await getPreview(f);
    checked(await f.send(url('confirm', other), { body: { ticket: preview.ticket, decision: 'force' } }), 409);
    checked(await submit(f, preview.ticket, 'force', { sessionID: 'other-fixture-session' }), 409);
    checked(await submit(f, preview.ticket, 'force', { session: { ...f.session, adminUsername: 'other-admin' } }), 409);
    checked(await submit(f, preview.ticket, 'force', { headers: { 'content-type': 'application/json' } }), 403);
    assert.equal(f.calls.length, 1);
    for (const [ticket, decision] of [[preview.ticket, undefined], [(await getPreview(f)).ticket, 'delete'], [(await getPreview(f)).ticket, 7]]) {
        assert.deepEqual(checked(await submit(f, ticket, decision), 409), {
            error: { code: 'REBUILD_RETIRE_DECISION_REQUIRED', activeClients: 7 },
        });
        checked(await submit(f, ticket, 'force'), 409);
    }
    assert.deepEqual(f.calls.map(call => call.action), ['preview', 'preview', 'preview']);
});

test('neighbor refusal is a sanitized 409 with no ticket, including an online replacement preview', async t => {
    const f = mount(t);
    const { checkNeighborRefusal } = require('../../../services/rebuildNeighborRefusal');
    const code = 'REBUILD_RETIRE_NEIGHBOR_REFUSED';
    f.state.previewError = Object.assign(new Error(privateValue), { code, neighborName: privateValue });
    assert.deepEqual(checked(await f.send(url('preview')), 503), { error: { code: 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE' } });
    const refusal = checkNeighborRefusal(Object.assign(new Error(privateValue), {
        code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED', reason: 'RUNTIME_FOREIGN_CHANGE', nodeName: privateValue,
    }), '212\nEast');
    f.state.previewError = refusal;
    const expected = { error: { code, neighborName: '212 East', reason: 'RUNTIME_FOREIGN_CHANGE' } };
    assert.deepEqual(checked(await f.send(url('preview')), 409), expected);
    f.state.previewError = undefined;
    const preview = await getPreview(f);
    f.state.confirmError = Object.assign(new Error(privateValue), { code: 'PREVIEW_CHANGED' });
    f.state.previewError = refusal;
    assert.deepEqual(checked(await submit(f, preview.ticket, 'delete'), 409), expected);
    assert.deepEqual(f.calls.map(c => c.action), ['preview', 'preview', 'preview', 'confirm', 'preview']);
});

test('census change re-previews the same node but does not retry confirm; positive protected/neighbor refusals carry no ticket', async t => {
    const f = mount(t);
    let preview = await getPreview(f);
    f.state.activeClients = 9;
    f.state.confirmError = { code: 'PREVIEW_CHANGED', message: privateValue };
    const changed = checked(await submit(f, preview.ticket, 'delete'), 409);
    assert.equal(changed.error.code, 'PREVIEW_CHANGED');
    assert.equal(changed.preview.activeClients, 9);
    assert.notEqual(changed.preview.ticket, preview.ticket);
    assert.deepEqual(f.calls.map(({ action, nodeId }) => [action, nodeId]), [['preview', id], ['confirm', id], ['preview', id]]);
    checked(await submit(f, preview.ticket, 'delete'), 409);
    f.state.confirmError = null;
    checked(await submit(f, changed.preview.ticket, 'force'), 200);
    preview = await getPreview(f);
    f.state.confirmError = { code: 'REBUILD_NEIGHBOR_UNAVAILABLE', message: privateValue };
    assert.deepEqual(checked(await submit(f, preview.ticket, 'force'), 409), { error: { code: 'REBUILD_NEIGHBOR_UNAVAILABLE' } });
    preview = await getPreview(f);
    f.state.confirmError = { code: 'REBUILD_CLIENT_CHANGE', preview: { secret: privateValue } };
    assert.deepEqual(checked(await submit(f, preview.ticket, 'force'), 409), { error: { code: 'REBUILD_RETIRE_PROTECTED_CHANGE' } });
    f.state.allowed = false;
    const blocked = await getPreview(f);
    assert.equal(blocked.allowed, false);
    assert.equal(Object.hasOwn(blocked, 'ticket'), false);
    f.state.previewError = { code: 'REBUILD_NEIGHBOR_UNAVAILABLE', message: privateValue };
    assert.deepEqual(checked(await f.send(url('preview')), 409), { error: { code: 'REBUILD_NEIGHBOR_UNAVAILABLE' } });
});

test('first concurrent submit consumes ticket before awaiting service; uncertain outcomes are not re-previewed', async t => {
    const f = mount(t);
    const { ticket } = await getPreview(f);
    let release;
    f.state.barrier = new Promise(resolve => { release = resolve; });
    const pending = submit(f, ticket, 'delete');
    await new Promise(resolve => setImmediate(resolve));
    checked(await submit(f, ticket, 'delete'), 409);
    release();
    checked(await pending, 200);
    assert.deepEqual(f.calls.map(call => call.action), ['preview', 'confirm']);
    const next = await getPreview(f);
    f.state.confirmError = { code: 'PREVIEW_CHANGED', outcome: 'unknown', message: privateValue };
    assert.deepEqual(checked(await submit(f, next.ticket, 'delete'), 503), { error: { code: 'REBUILD_RETIRE_OUTCOME_UNCONFIRMED' } });
    checked(await submit(f, next.ticket, 'delete'), 409);
    assert.deepEqual(f.calls.map(call => call.action), ['preview', 'confirm', 'preview', 'confirm']);
});

test('tickets expire and the process-local map has a hard cap', async t => {
    const f = mount(t);
    let now = 1;
    t.mock.method(performance, 'now', () => now);
    const first = await getPreview(f);
    now += 120_000;
    checked(await submit(f, first.ticket, 'delete'), 409);
    const oldest = await getPreview(f);
    let latest;
    for (let i = 0; i < 256; i++) latest = await getPreview(f);
    checked(await submit(f, oldest.ticket, 'delete'), 409);
    checked(await submit(f, latest.ticket, 'delete'), 200);
    assert.equal(f.calls.filter(call => call.action === 'confirm').length, 1);
});

test('invalid outage time stays unknown; a preview or deletion receipt for another target is refused', async t => {
    const f = mount(t);
    Object.assign(f.state, { mode: 'abandon', activeClients: null, accountCount: null, unavailableSince: '0' });
    const preview = await getPreview(f);
    assert.equal(preview.unavailableSince, null);
    f.state.result = { nodeId: other };
    assert.deepEqual(checked(await submit(f, preview.ticket, 'abandon'), 503), { error: { code: 'REBUILD_RETIRE_OUTCOME_UNCONFIRMED' } });
    f.state.extra = { nodeId: other };
    checked(await f.send(url('preview')), 503);
});

test('classic panel does not mount the retirement API', async t => {
    const f = mount(t, false);
    assert.equal((await f.send(url('preview'))).status, 404);
    assert.deepEqual(f.calls, []);
});
