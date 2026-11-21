'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { IncomingMessage, ServerResponse } = require('node:http');
const { Socket } = require('node:net');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { render } = require('../panel/helpers');
const express = require('express');
const auth = require('../../middleware/auth');
const { t } = require('../../middleware/i18n');
const { issuePanelCsrfToken } = require('../panel/csrf');
const { routerForRebuild } = require('../cascadeRebuild');

const root = path.resolve(__dirname, '../../..');
const origin = 'https://graph.example.invalid';
const hostname = new URL(origin).host;
const refreshPath = '/api/cascade/rebuild/csrf-token';
const previewPath = '/api/cascade/rebuild/preview';
const deployPath = '/api/cascade/topology/deploy';
const linkId = 'a'.repeat(24);
const previewId = 'b'.repeat(64);
const csrf = code => ({ error: 'CSRF validation failed', code });

// Real Express dispatch and auth/CSRF guards, no sockets listening or connecting.
function makeApp() {
    const browser = { authenticated: true }, other = { authenticated: true };
    const stale = issuePanelCsrfToken({ session: browser });
    const fresh = issuePanelCsrfToken({ session: other });
    const calls = [];
    const service = { execute: async input => {
        calls.push(input);
        if (input.preview) return { allowed: true, previewId, nodes: [] };
        return {};
    } };
    const app = express();
    app.set('trust proxy', 1);
    app.use(express.json());
    app.use((req, res, next) => {
        // Model the entry's CORS header and the already-resolved authentication state.
        res.set('Access-Control-Allow-Origin', 'https://cors.example.invalid');
        if (req.headers.cookie === 'fixture=session') req.session = browser;
        if (req.headers.cookie === 'fixture=api') req.apiKey = { scopes: ['nodes:read'] };
        next();
    });
    app.use('/api/cascade', (req, res, next) => req.apiKey ? next() : auth(req, res, next),
        routerForRebuild({ service, Link: {}, Node: {} }));
    const request = (url, { method = 'GET', headers = {}, body } = {}) => new Promise(resolve => {
        const req = new IncomingMessage(new Socket());
        Object.assign(req, { url, method, headers: { host: hostname, 'x-forwarded-proto': 'https',
            ...(body ? { 'content-length': String(Buffer.byteLength(body)) } : {}), ...headers } });
        if (body) req.push(body);
        req.push(null);
        const res = new ServerResponse(req);
        res.end = bytes => {
            const response = new Response(bytes, { status: res.statusCode, headers: res.getHeaders() });
            Object.defineProperty(response, 'url', { value: origin + url });
            resolve(response);
        };
        app(req, res);
    });
    return { request, stale, fresh, calls, rotate: () => { browser.panelCsrfToken = fresh; } };
}

function response(url, body, status = 200, options = {}) {
    const res = new Response(typeof body === 'string' ? body : JSON.stringify(body), { status,
        headers: { 'content-type': options.type || 'application/json' } });
    Object.defineProperties(res, { url: { value: options.url || url }, redirected: { value: !!options.redirected } });
    return res;
}

// Render the complete templates; only the DOM/Cytoscape APIs and Fetch are
// modelled. Missing rendered IDs are not filled in by the harness.
function mount(view, lang, csrfToken, rebuild, send) {
    let html;
    render({ locals: { t: key => t(key, lang), lang, csrfToken, c3Rebuild: rebuild },
        render(layout, data) { assert.equal(layout, 'layout'); html = data.content; },
    }, view, {
        nodes: [], groups: [], nodesCount: 0, linksCount: 0, ipProtocolCount: {},
        panelDomain: hostname, loadBalancingEnabled: false,
    });
    const tags = new Map(), resources = [], requests = [], confirmations = [];
    let runAsset;
    function element() {
        const children = [], classes = new Set();
        return { style: {}, children, listeners: {},
            addEventListener(event, callback) { this.listeners[event] = callback; },
            classList: { add: k => classes.add(k), remove: k => classes.delete(k), contains: k => classes.has(k) },
            querySelector: selector => selector === '.info-loading' ? children.find(child => child.className === 'info-loading') : null,
            querySelectorAll: () => [],
            appendChild(child) {
                children.push(child);
                if (child.id) tags.set(child.id, child);
                if (child.src) { runAsset(child.src); child.onload?.(); }
            },
            remove() { this.removed = true; },
        };
    }
    for (const [, id] of html.matchAll(/\bid="([\w-]+)"/g)) tags.set(id, element());
    const document = {
        readyState: 'complete', body: element(), createElement: element,
        getElementById: id => tags.get(id) ?? null,
        querySelector(selector) {
            if (selector === '.network-loading') return document.body.querySelector(selector);
            if (selector === '.info-loading') return tags.get('nodeInfoBody')?.querySelector(selector);
            return null;
        },
    };
    tags.get('btnAddLink').parentElement = element();
    const handlers = {};
    const emptyEdge = { length: 0, filter: () => emptyEdge };
    const cytoscape = () => ({
        on(event, query, cb) { handlers[event + query] = cb; },
        edges: () => emptyEdge, nodes: () => [], getElementById: () => emptyEdge,
        elements: () => ({ remove() {}, unselect() {} }),
    });
    const context = vm.createContext({ document, URL, AbortController, setTimeout() {}, clearTimeout() {}, setInterval() {},
        MutationObserver: class { observe() {} },
        location: { origin }, sessionStorage: { getItem: () => 'network', removeItem() {} }, cytoscape,
        confirm: message => { confirmations.push(message); return true; },
        fetch: async (url, init = {}) => {
            const target = new URL(url, origin);
            const call = { url: target.href, pathname: target.pathname, ...init };
            requests.push(call);
            return send(call);
        },
    });
    context.window = context;
    runAsset = src => {
        resources.push(src);
        if (src.startsWith('/js/network.js?')) {
            vm.runInContext(readFileSync(path.join(root, 'public/js/network.js'), 'utf8'), context);
        }
    };
    for (const [, src, code] of html.matchAll(/<script(?: src="([^"]+)"[^>]*)?>([\s\S]*?)<\/script>/g)) {
        if (src) runAsset(src);
        else if (code.includes('_networkCsrfToken')) vm.runInContext(code, context);
    }
    const openEdge = () => handlers.tapedge({ target: { data: () => ({ linkId, label: 'Graph fixture' }) } });
    return { context, document, requests, resources, openEdge, confirmations,
        toast: () => document.getElementById('toast')?.textContent };
}

function dispatch(app, call) {
    if (call.pathname === '/api/cascade/topology') return response(call.url, { nodes: [], edges: [] });
    if (call.pathname === '/api/cascade/links' && !call.method) return response(call.url, { links: [], topologyRevision: 7, deployedRevision: 6 });
    return app.request(call.pathname, { method: call.method, body: call.body,
        headers: { cookie: 'fixture=session', ...Object.fromEntries(new Headers(call.headers)),
            ...(call.method === 'POST' ? { origin } : {}) } });
}

for (const [view, lang, actionCopy] of [['network', 'ru', /Повторите действие вручную/], ['nodes', 'en', /Retry the action manually/]]) {
    test(`${view} (${lang}): stale session token is reread from real rebuild route, never replaying preview`, async () => {
        const app = makeApp();
        const ui = mount(view, lang, app.stale, true, call => dispatch(app, call));
        assert.ok(ui.resources.some(src => src.startsWith('/js/network.js?')));
        ui.openEdge();
        assert.match(ui.document.getElementById('nodeInfoBody').innerHTML, /window\._cascadeDeploy\('/);
        app.rotate();
        await ui.context._cascadeDeploy(linkId);
        assert.match(ui.toast(), actionCopy);
        assert.match(ui.toast(), /\(CSRF_TOKEN_INVALID\)/);
        assert.ok(!ui.toast().includes(app.fresh) && !ui.toast().includes('CSRF validation failed'));
        assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, refreshPath]);
        assert.deepEqual(app.calls, []);
        const [write, read] = ui.requests;
        assert.equal(write.headers['x-csrf-token'], app.stale);
        assert.deepEqual(JSON.parse(write.body), { expectedTopologyRevision: null, linkId });
        assert.equal(read.method, 'GET');
        assert.equal(read.cache, 'no-store');
        assert.equal(read.headers?.['x-csrf-token'], undefined);
        assert.equal(read.headers?.Authorization, undefined);
        for (const call of ui.requests) {
            assert.equal(new URL(call.url).origin, origin);
            assert.equal(call.mode, 'same-origin');
            assert.equal(call.credentials, 'same-origin');
            assert.equal(call.redirect, 'error');
        }
        // Only a new explicit operator action consumes the reread token.
        await ui.context._cascadeDeploy(linkId);
        assert.deepEqual(ui.requests.slice(2, 4).map(call => [call.pathname, call.headers['x-csrf-token'] === app.fresh]),
            [[previewPath, true], [deployPath, true]]);
        assert.deepEqual(app.calls.map(call => call.preview), [true, false]);
        assert.doesNotMatch(ui.toast(), /CSRF_/);
    });

    test(`${view}: stock still selects the minified graph without rebuild recovery`, () => {
        const ui = mount(view, lang, 'fixture', false, () => assert.fail('unexpected fetch'));
        assert.ok(ui.resources.includes('/js/network.min.js?v=8c1440573d630ba3'));
        assert.ok(!ui.resources.some(src => src.startsWith('/js/network.js?')));
    });
}

test('rebuild token route is session-only, non-cacheable and not CORS-readable', async () => {
    const app = makeApp();
    const get = headers => app.request(refreshPath, { headers });
    const a = await get({ cookie: 'fixture=session', 'sec-fetch-site': 'same-origin' });
    assert.equal(a.status, 200);
    assert.equal(a.headers.get('cache-control'), 'no-store');
    assert.equal(a.headers.get('access-control-allow-origin'), null);
    assert.deepEqual(await a.json(), { csrfRequired: true, csrfToken: app.stale });
    assert.equal((await get({})).status, 401);
    for (const headers of [{ cookie: 'fixture=api' }, { cookie: 'fixture=session', origin: 'http://' + hostname },
        { cookie: 'fixture=session', 'sec-fetch-site': 'same-site' }]) {
        const denied = await get(headers);
        assert.equal(denied.status, 403);
        assert.equal(await denied.text(), 'Forbidden');
    }
});

for (const [code, copy] of [['CSRF_AUTH_REQUIRED', /Sign in to the panel again/],
    ['CSRF_ORIGIN_INVALID', /configured address/]]) {
    test(`${code} produces actionable text but does not reread`, async () => {
        const ui = mount('nodes', 'en', 'fixture', true, ({ url }) => response(url, csrf(code), 403));
        await ui.context._cascadeDeploy(linkId);
        assert.match(ui.toast(), copy);
        assert.ok(ui.toast().endsWith(`(${code})`));
        assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath]);
    });
}

for (const [label, rejected] of [
    ['arbitrary 403', url => response(url, { error: 'restricted' }, 403)],
    ['unknown CSRF code', url => response(url, csrf('CSRF_TOKEN_EXPIRED'), 403)],
    ['nested CSRF-looking code', url => response(url, { error: { code: 'CSRF_TOKEN_INVALID' } }, 403)],
    ['conflicting outcome in error envelope', url => response(url, { ...csrf('CSRF_TOKEN_INVALID'), desiredSaved: true }, 403)],
    ['non-CSRF error discriminator', url => response(url, { error: 'another error', code: 'CSRF_TOKEN_INVALID' }, 403)],
    ['unparseable 403', url => response(url, '{', 403)],
    ['401 with CSRF-shaped JSON', url => response(url, csrf('CSRF_TOKEN_INVALID'), 401)],
    ['network failure after dispatch', () => { throw new TypeError('Failed to fetch'); }],
    ['mutating redirect', url => response(url, csrf('CSRF_TOKEN_INVALID'), 403, { redirected: true })],
]) {
    test(`${label}: do not reread or replay the failed deploy`, async () => {
        const ui = mount('nodes', 'en', 'fixture', true, ({ pathname, url }) => {
            if (pathname === previewPath) return response(url, { nodes: [], allowed: true, previewId });
            assert.equal(pathname, deployPath);
            return rejected(url);
        });
        await ui.context._cascadeDeploy(linkId);
        assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, deployPath]);
        assert.doesNotMatch(ui.toast(), /session token|Sign in to the panel|configured address/);
        assert.equal(ui.document.getElementById('toast').className, 'toast show error');
    });
}

for (const [label, rejectedRead] of [
    ['rejected response', url => response(url, { error: 'Authentication required' }, 401)],
    ['API-key mode', url => response(url, { csrfRequired: false, csrfToken: 'b'.repeat(43) })],
    ['wrong URL', url => response(url, { csrfRequired: true, csrfToken: 'b'.repeat(43) }, 200, { url: origin + '/login' })],
    ['foreign URL', url => response(url, { csrfRequired: true, csrfToken: 'b'.repeat(43) }, 200, { url: 'https://foreign.invalid/' })],
    ['redirected response', url => response(url, { csrfRequired: true, csrfToken: 'b'.repeat(43) }, 200, { redirected: true })],
    ['HTML login page', url => response(url, '<form></form>', 200, { type: 'text/html' })],
    ['same rejected token', url => response(url, { csrfRequired: true, csrfToken: 'a'.repeat(43) })],
    ['invalid token', url => response(url, { csrfRequired: true, csrfToken: 'bad token' })],
    ['transport rejection', () => { throw new TypeError('Failed to fetch'); }],
]) {
    test(`${label}: failed token reread keeps the original code and asks to reload`, async () => {
        const oldToken = 'a'.repeat(43);
        let writeCount = 0;
        const ui = mount('network', 'en', oldToken, true, ({ pathname, url }) => {
            if (pathname === refreshPath) return rejectedRead(url);
            assert.equal(pathname, previewPath);
            return response(url, writeCount++ === 0 ? csrf('CSRF_TOKEN_INVALID') : { error: 'Forbidden' }, 403);
        });
        await ui.context._cascadeDeploy(linkId);
        assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, refreshPath]);
        assert.match(ui.toast(), /Reload the topology page.*\(CSRF_TOKEN_INVALID\)/);
        await ui.context._cascadeDeploy(linkId);
        assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, refreshPath, previewPath]);
        assert.ok(ui.requests[2].headers['x-csrf-token'] === oldToken);
    });
}

test('session change between accepted preview and deploy refreshes once without resending apply', async () => {
    const app = makeApp();
    const ui = mount('nodes', 'en', app.stale, true, call => {
        if (call.pathname === deployPath) app.rotate();
        return dispatch(app, call);
    });
    await ui.context._cascadeDeploy(linkId);
    assert.match(ui.toast(), /Retry the action manually.*\(CSRF_TOKEN_INVALID\)/);
    assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, deployPath, refreshPath]);
    assert.deepEqual(app.calls.map(call => call.preview), [true]);
    assert.deepEqual(JSON.parse(ui.requests[1].body), { expectedTopologyRevision: null, linkId, expectedPreview: previewId });
});

test('a concurrent refresh cannot change the token of an already started workflow', async () => {
    const app = makeApp();
    const heldPreview = Promise.withResolvers();
    const accepted = Promise.withResolvers();
    let previews = 0;
    const ui = mount('nodes', 'en', app.stale, true, async call => {
        const result = await dispatch(app, call);
        if (call.pathname === previewPath && ++previews === 1) {
            assert.equal(result.status, 200);
            accepted.resolve();
            await heldPreview.promise;
        }
        return result;
    });
    const first = ui.context._cascadeDeploy(linkId);
    await Promise.race([accepted.promise, first.then(() => assert.fail('first preview did not reach the hold'))]);
    app.rotate();
    await ui.context._cascadeDeploy(linkId);
    assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, previewPath, refreshPath]);
    heldPreview.resolve();
    await first;
    assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, previewPath, refreshPath, deployPath]);
    assert.ok(ui.requests[3].headers['x-csrf-token'] === app.stale);
    assert.deepEqual(app.calls.map(call => call.preview), [true]);
    assert.match(ui.toast(), /\(CSRF_TOKEN_INVALID\)/);
});

test('a saved quick-create draft is not lost or saved again after the apply is refused', async () => {
    const app = makeApp();
    const ui = mount('nodes', 'en', app.stale, true, call => {
        if (call.pathname === '/api/cascade/links' && call.method === 'POST') {
            app.rotate();
            return response(call.url, { executionMode: 'rebuild', status: 'awaiting_preview', desiredSaved: true,
                linkId, preview: { nodes: [], allowed: true, previewId } });
        }
        return dispatch(app, call);
    });
    for (const [id, value] of Object.entries({ quickLinkName: 'fixture link', quickLinkMode: 'reverse',
        quickPortalId: 'c'.repeat(24), quickBridgeId: 'd'.repeat(24), quickTunnelPort: '10086', quickTunnelProtocol: 'vless' })) {
        ui.document.getElementById(id).value = value;
    }
    ui.document.getElementById('quickAutoDeploy').checked = true;
    await ui.document.getElementById('quickLinkForm').listeners.submit({ preventDefault() {} });
    assert.match(ui.toast(), /The link was saved\. Use Deploy on that link instead of saving it again\./);
    assert.match(ui.toast(), /\(CSRF_TOKEN_INVALID\)/);
    const writes = ui.requests.filter(call => call.method === 'POST');
    assert.deepEqual(writes.map(call => call.pathname), ['/api/cascade/links', deployPath]);
    assert.equal(ui.requests.filter(call => call.pathname === refreshPath).length, 1);
    assert.deepEqual(app.calls, []);
});

test('delete refusal after preview never resends DELETE or marks it accepted', async () => {
    const app = makeApp();
    const ui = mount('network', 'ru', app.stale, true, call => {
        if (call.method === 'DELETE') app.rotate();
        return dispatch(app, call);
    });
    await ui.context._cascadeDelete(linkId);
    assert.match(ui.toast(), /Повторите действие вручную.*\(CSRF_TOKEN_INVALID\)/);
    assert.deepEqual(ui.requests.map(call => call.pathname), [previewPath, '/api/cascade/links/' + linkId, refreshPath]);
    assert.deepEqual(app.calls.map(call => [call.preview, call.remove]), [[true, true]]);
    assert.equal(ui.confirmations.length, 2);
});
