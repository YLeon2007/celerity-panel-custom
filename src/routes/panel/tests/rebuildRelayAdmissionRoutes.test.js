'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const express = require('express');
const { issuePanelCsrfToken } = require('../csrf');

const id = 'a'.repeat(24);
const challenge = 'b'.repeat(64);
const identity = { nodeId: id, host: 'relay.fixture.invalid', port: 22, username: 'root', sshHostKeySha256: 'c'.repeat(64) };
const privateValue = 'PRIVATE_FIXTURE_NOT_FOR_HTTP';
const url = action => `/panel/rebuild/relays/${id}/l2tp/admission/${action}`;
test.after(() => require('../../../services/sshPoolService').closeAll());

function request(app, path, { method = 'POST', session, sessionID, headers, body = {}, raw = JSON.stringify(body), ip = '192.0.2.10' }) {
    return new Promise((resolve, reject) => {
        const wire = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { wire.push(chunk.toString()); done(); } });
        socket.remoteAddress = ip;
        const req = new IncomingMessage(socket);
        Object.assign(req, { method, url: path, session, sessionID, complete: true, headers: { host: 'fixture.invalid',
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

function mount(t, rebuildL2tpOverview, rebuildRelayAdmission) {
    const config = require('../../../../config');
    const oldMode = process.env.C3_REBUILD_ENABLED, oldWhitelist = config.PANEL_IP_WHITELIST;
    process.env.C3_REBUILD_ENABLED = 'true';
    config.PANEL_IP_WHITELIST = '192.0.2.10';
    t.after(() => {
        if (oldMode === undefined) delete process.env.C3_REBUILD_ENABLED;
        else process.env.C3_REBUILD_ENABLED = oldMode;
        config.PANEL_IP_WHITELIST = oldWhitelist;
    });
    const settings = { completed: true, fail: false };
    t.mock.method(require('../../../models/settingsModel'), 'findById', () => ({ select: () => ({ lean: async () => {
        if (settings.fail) throw new Error(privateValue);
        return { deployment: { completed: settings.completed } };
    } }) }));
    const calls = [];
    const admission = { async perform(input) {
        calls.push(input);
        if (admission.error) throw admission.error;
        return { ...identity, password: privateValue, sessionId: privateValue, generation: privateValue,
            ...(input.action !== 'probe' && { machineId: 'd'.repeat(32) }),
            ...(input.action === 'probe' || input.action === 'verify' ? { challenge } : {}), ...admission.override };
    } };
    const app = express();
    app.use(require('../rebuildL2tp').rebuildL2tpIngress);
    app.use(require('cors')({ origin: 'http://fixture.invalid', credentials: true }));
    app.use(express.json());
    const panel = require('../index');
    panel.l2tpRateLimiter.resetKey('192.0.2.10');
    app.use('/panel', panel.createPanelRouter({ rebuildRelayAdmission: rebuildRelayAdmission ?? admission, rebuildL2tpOverview }));
    const session = { authenticated: true, adminUsername: 'admin.fixture' };
    const headers = { 'content-type': 'application/json', 'x-csrf-token': issuePanelCsrfToken({ session }) };
    const send = (path, options = {}) => request(app, path, { session, sessionID: 'admin-session-id', headers, ...options });
    return { send, calls, settings, admission, session, headers };
}

function checked({ status, headers, body }, expected) {
    assert.equal(status, expected);
    assert.equal(headers['cache-control'], 'no-store');
    assert.ok(!body.includes(privateValue));
    if (expected === 200) assert.equal(headers.etag, undefined);
    if (body && headers['content-type']?.includes('application/json')) return JSON.parse(body);
}

test('admission actions are mounted and only publish stage-scoped fields', async t => {
    const { send, calls } = mount(t);
    for (const action of ['probe', 'verify', 'confirm', 'revoke']) {
        const followup = action === 'verify' || action === 'confirm';
        const result = checked(await send(url(action), { body: followup ? { challenge } : {} }), 200);
        assert.deepEqual(result, action === 'revoke' ? { nodeId: id } : { ...identity,
            ...(action !== 'probe' && { machineId: 'd'.repeat(32) }), ...(action === 'probe' || action === 'verify' ? { challenge } : {}) });
        assert.deepEqual(calls.at(-1), { action, nodeId: id, actor: 'admin.fixture', sessionId: 'admin-session-id',
            challenge: followup ? challenge : undefined });
    }
});

test('admission refuses unauthorized and malformed inputs before executing', async t => {
    const { send, calls, settings, headers } = mount(t);
    checked(await send(url('probe'), { method: 'GET' }), 405);
    checked(await send(url('probe'), { method: 'OPTIONS', headers: { origin: 'http://fixture.invalid' } }), 204);
    checked(await send(url('probe'), { session: undefined }), 302);
    checked(await send(url('probe'), { session: { authenticated: true } }), 403);
    checked(await send(url('probe'), { sessionID: undefined }), 403);
    checked(await send(url('probe'), { ip: '192.0.2.11' }), 403);
    checked(await send(url('probe'), { headers: { ...headers, origin: 'https://elsewhere.invalid' } }), 403);
    checked(await send(url('probe'), { headers: { ...headers, 'x-csrf-token': 'a'.repeat(41) + 'é%' } }), 403);
    for (const [path, body] of [[`${url('probe')}?`, {}], [url('revoke'), { password: privateValue }],
        [url('confirm'), {}], [url('verify'), { challenge, host: privateValue }],
        [url('probe').replace(id, `a%61${id.slice(2)}`), {}]]) {
        checked(await send(path, { body }), 400);
    }
    for (const raw of [`{"challenge":"${privateValue}","challenge":"${challenge}"}`, '{', ' '.repeat(1025) + '{}', '']) {
        checked(await send(url('verify'), { raw }), 400);
    }
    settings.completed = false;
    checked(await send(url('probe')), 302);
    settings.fail = true;
    checked(await send(url('probe')), 503);
    assert.deepEqual(calls, []);
});

test('admission publishes only fixed error codes and shares a bounded action budget', async t => {
    const { send, calls, admission } = mount(t);
    admission.error = { code: 'REBUILD_L2TP_IDENTITY_CHANGED', message: privateValue, host: privateValue };
    assert.deepEqual(checked(await send(url('verify'), { body: { challenge } }), 409), { error: { code: admission.error.code } });
    admission.error = { code: privateValue, message: privateValue };
    assert.deepEqual(checked(await send(url('probe')), 503), { error: { code: 'REBUILD_L2TP_ADMISSION_UNAVAILABLE' } });
    admission.error = null;
    for (let i = 0; i < 8; i++) checked(await send(url('probe')), 200);
    checked(await send(url('revoke')), 429);
    assert.equal(calls.length, 10);
});

test('DB-only account reconciliation relies on the live service attestation, not an ENV list', async t => {
    const listKey = 'C3_REBUILD_L2TP_RELAYS_JSON';
    const previous = process.env[listKey];
    delete process.env[listKey];
    t.after(() => { if (previous !== undefined) process.env[listKey] = previous; });
    let eligible = false, pending = true, problem, fail;
    const calls = [];
    const { send } = mount(t, {
        async hasPendingAccounts() { return pending; },
        async overview() { return { canReconcileAccounts: eligible, grantProblem: problem }; },
    });
    t.mock.method(require('../../../services/rebuildService'), 'createRebuildService', () => ({
        async reconcileRelayAccounts() {
            calls.push('reconcile');
            if (fail) throw { code: fail, message: privateValue };
            pending = false;
        },
    }));
    const path = '/panel/rebuild/relays/l2tp/accounts/reconcile';
    assert.deepEqual(checked(await send(path), 409), { error: { code: 'REBUILD_L2TP_RECONCILE_DISABLED' } });
    eligible = true;
    for (const [code, status] of [['REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE', 503],
        ['REBUILD_L2TP_GRANT_ENV_INVALID', 503], ['REBUILD_L2TP_GRANT_REGISTRY_INVALID', 503],
        ['REBUILD_L2TP_GRANT_CONFLICT', 409], ['REBUILD_L2TP_GRANT_CHANGED', 409]]) {
        problem = code;
        assert.deepEqual(checked(await send(path), status), { error: { code } });
    }
    const manualBlock = { error: { code: 'REBUILD_L2TP_ACCOUNTS_MANUAL_BLOCK', retryAllowed: false } };
    problem = 'REBUILD_L2TP_IDENTITY_CHANGED';
    assert.deepEqual(checked(await send(path), 409), manualBlock);
    problem = privateValue;
    assert.deepEqual(checked(await send(path), 503), { error: { code: 'REBUILD_L2TP_RECONCILE_UNAVAILABLE' } });
    assert.deepEqual(calls, []);
    problem = null;
    fail = 'REBUILD_L2TP_ACCOUNTS_MANUAL_BLOCK';
    assert.deepEqual(checked(await send(path), 409), manualBlock);
    fail = null;
    const result = await send(path);
    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), { executionMode: 'rebuild', status: 'settled' });
    assert.deepEqual(calls, ['reconcile', 'reconcile']);
});

test('only admission publishes allowlisted conflict categories, not values or internal diagnostics', async t => {
    const { send, admission } = mount(t);
    const code = 'REBUILD_L2TP_GRANT_CONFLICT';
    for (const [error, details] of [
        [{ detail: 'sshHostKeySha256' }, { field: 'sshHostKeySha256' }],
        [{ detail: 'env-read-only' }, { sources: ['env'] }],
        [{ field: 'endpoint', sources: ['env', 'db'] }, { field: 'endpoint', sources: ['env', 'db'] }],
        [{ field: 'endpoint', sources: ['db', 'db'] }, { field: 'endpoint', sources: ['db', 'db'] }],
        [{ field: 'constructor', sources: ['env', privateValue] }],
        [{ detail: privateValue, sources: ['env', 'db', 'env'] }],
    ]) {
        admission.error = { code, ...error, message: privateValue, host: privateValue, machineId: privateValue };
        assert.deepEqual(checked(await send(url('probe')), 409), { error: { code, ...(details && { conflict: details }) } });
    }
    for (const [code, status, retryAllowed] of [
        ['REBUILD_L2TP_IDENTITY_UNAVAILABLE', 503], ['REBUILD_LOCK_LOST', 409],
        ['REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE', 503],
        ['REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN', 503, false], ['REBUILD_LOCK_RELEASE_UNCONFIRMED', 503, false],
    ]) {
        // Each route case is specifically testing translation, not the shared budget.
        require('../index').l2tpRateLimiter.resetKey('192.0.2.10');
        admission.error = { code, retryAllowed, field: 'endpoint', sources: ['env', 'db'], message: privateValue };
        assert.deepEqual(checked(await send(url('confirm'), { body: { challenge } }), status),
            { error: { code, ...(retryAllowed === false && { retryAllowed }) } });
    }
});

test('the mounted admission service passes categorical refusals without probing a host', async t => {
    const { createRebuildRelayAdmission } = require('../../../services/rebuildRelayAdmission');
    const { RelayGrantConflict } = require('../../../services/rebuildRelayAuthorization');
    const code = 'REBUILD_L2TP_GRANT_CONFLICT';
    let duplicate = false;
    const admission = createRebuildRelayAdmission({ db: {}, locks: {}, env: {
        C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
    }, store: {
        async snapshot() {
            if (duplicate) throw Object.assign(new RelayGrantConflict('endpoint', ['env', 'db']), { keyValue: privateValue });
            return { sourceFor: () => 'env' };
        },
        async audit() {},
    }, probe: { probeKey() { assert.fail('unexpected SSH probe'); } }, loadNode() { assert.fail('unexpected card read'); } });
    const { send } = mount(t, undefined, admission);
    assert.deepEqual(checked(await send(url('probe')), 409), { error: { code, conflict: { sources: ['env'] } } });
    duplicate = true;
    assert.deepEqual(checked(await send(url('probe')), 409), { error: { code, conflict: { field: 'endpoint', sources: ['env', 'db'] } } });
});

test('install, remove and accounts return stable grant errors without internal details', async t => {
    const { handler } = require('../rebuildRelayInstall');
    const { accountHandler } = require('../rebuildRelayAccounts');
    const { issueRemovalTicket, submitRemoval } = require('../rebuildRelayRemove');
    const identityCode = 'REBUILD_L2TP_IDENTITY_CHANGED';
    const registryCode = 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE';
    const refuse = code => Object.assign(new Error(privateValue), { code, nodeId: id, password: privateValue });
    const app = express();
    app.use(require('../rebuildL2tp').rebuildL2tpIngress);
    app.use(express.json());
    let error;
    const effect = async () => { if (error) throw error; return { status: 'installed', nodeId: id, password: privateValue }; };
    const factory = () => ({ installRelay: effect, disableRelayAccount: effect, confirmRemoveRelay: effect });
    t.mock.method(require('../../../services/rebuildService'), 'createRebuildService', factory);
    const installPath = `/panel/rebuild/relays/${id}/l2tp/install`;
    const removalPath = installPath.replace('install', 'remove');
    app.post('/panel/rebuild/relays/:id/l2tp/install', handler(factory));
    app.post('/panel/rebuild/relays/:id/l2tp/remove', submitRemoval);
    app.post('/panel/rebuild/relays/l2tp/accounts/disable', accountHandler('disable', factory));
    const session = { authenticated: true };
    const sessionID = 'fixture-removal-session';
    const send = (path, options) => request(app, path, { session, sessionID, headers: { 'content-type': 'application/json' }, ...options });
    const installed = await send(installPath);
    assert.equal(installed.status, 200);
    assert.deepEqual(JSON.parse(installed.body), { executionMode: 'rebuild', status: 'installed', nodeId: id });
    error = refuse(identityCode);
    assert.equal(checked(await send(installPath), 409).error.code, identityCode);
    assert.deepEqual(checked(await send('/panel/rebuild/relays/l2tp/accounts/disable', { body: { login: 'fixture' } }), 409),
        { error: { code: identityCode, outcome: 'refused', nodeId: id } });
    const mode = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = 'true';
    t.after(() => { if (mode === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = mode; });
    const preview = () => issueRemovalTicket({ method: 'GET', session, sessionID, headers: {}, params: { id } }, { nodeId: id, confirmable: true });
    const html = await send(removalPath, { headers: { 'content-type': 'application/json', accept: 'text/html' },
        body: { decision: 'confirm', ticket: preview() } });
    assert.equal(html.status, 303);
    assert.equal(html.headers.location, `/panel/l2tp?identityChanged=${id}#relay-${id}`);
    for (const phase of [{ outcome: 'unknown' }, { outcome: 'refused', retryAllowed: false }]) {
        error = Object.assign(refuse(identityCode), phase);
        const envelope = { error: { code: identityCode, outcome: 'unknown', retryAllowed: false } };
        assert.deepEqual(checked(await send(installPath), 409), envelope);
        assert.deepEqual(checked(await send('/panel/rebuild/relays/l2tp/accounts/disable', { body: { login: 'fixture' } }), 409), envelope);
        assert.deepEqual(checked(await send(removalPath, { body: { decision: 'confirm', ticket: preview() } }), 409), envelope);
        const blocked = await send(removalPath, { headers: { 'content-type': 'application/json', accept: 'text/html' },
            body: { decision: 'confirm', ticket: preview() } });
        assert.equal(blocked.status, 303);
        assert.equal(blocked.headers.location, '/panel/l2tp?view=remove-unconfirmed');
    }
    error = refuse(registryCode);
    assert.deepEqual(checked(await send(removalPath, { body: { decision: 'confirm', ticket: preview() } }), 503),
        { error: { code: registryCode } });
    error = Object.assign(refuse('REBUILD_L2TP_GRANT_CONFLICT'), { field: 'endpoint', sources: ['db', 'env'] });
    const code = error.code;
    assert.deepEqual(checked(await send(installPath), 409), { error: { code, retryAllowed: false } });
    assert.deepEqual(checked(await send('/panel/rebuild/relays/l2tp/accounts/disable', { body: { login: 'fixture' } }), 409),
        { error: { code, retryAllowed: false } });
    assert.deepEqual(checked(await send(removalPath, { body: { decision: 'confirm', ticket: preview() } }), 409), { error: { code } });
});
