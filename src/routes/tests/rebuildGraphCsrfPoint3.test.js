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
function makeApp(previewFailure, deployFailure) {
    const browser = { authenticated: true }, other = { authenticated: true };
    const stale = issuePanelCsrfToken({ session: browser });
    const fresh = issuePanelCsrfToken({ session: other });
    const calls = [];
    const service = { execute: async input => {
        calls.push(input);
        if (input.preview && previewFailure) throw previewFailure;
        if (input.preview) return { allowed: true, previewId, nodes: [] };
        if (deployFailure) throw deployFailure;
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
function mount(view, lang, csrfToken, rebuild, send, { onDialog, confirm = () => true } = {}) {
    let html;
    render({ locals: { t: key => t(key, lang), lang, csrfToken, c3Rebuild: rebuild },
        render(layout, data) { assert.equal(layout, 'layout'); html = data.content; },
    }, view, {
        nodes: [], groups: [], nodesCount: 0, linksCount: 0, ipProtocolCount: {},
        panelDomain: hostname, loadBalancingEnabled: false,
    });
    const tags = new Map(), resources = [], requests = [], confirmations = [], alerts = [];
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
    const dialog = tags.get('rebuildPreview');
    if (dialog && onDialog) {
        dialog.showModal = () => { dialog.open = true; onDialog(dialog); };
        dialog.close = () => { dialog.open = false; dialog.onclose?.(); };
    }
    const document = {
        readyState: 'complete', body: element(), createElement: element,
        addEventListener(event, callback) {
            assert.equal(event, 'visibilitychange');
            assert.equal(typeof callback, 'function');
        },
        getElementById: id => tags.get(id) ?? null,
        querySelector(selector) {
            if (selector === '.network-loading') return document.body.querySelector(selector);
            if (selector === '.info-loading') return tags.get('nodeInfoBody')?.querySelector(selector);
            return null;
        },
    };
    tags.get('btnAddLink').parentElement = element();
    const handlers = {};
    const emptyEdge = Object.assign([], { filter: () => emptyEdge });
    const cytoscape = () => ({
        on(event, query, cb) { handlers[event + query] = cb; },
        edges: () => emptyEdge, nodes: () => [], getElementById: () => emptyEdge,
        elements: () => ({ remove() {}, unselect() {} }),
        add() {}, fit() {},
    });
    const context = vm.createContext({ document, URL, AbortController, setTimeout() {}, clearTimeout() {}, setInterval() {},
        MutationObserver: class { observe() {} },
        location: { origin }, sessionStorage: { getItem: () => 'network', removeItem() {} }, cytoscape,
        confirm: message => { confirmations.push(message); return confirm(message); },
        alert: message => { alerts.push(message); },
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
        else if (code.includes('_networkCsrfToken') || code.includes('_networkRebuildPreviewI18n')) vm.runInContext(code, context);
    }
    const openEdge = () => handlers.tapedge({ target: { data: () => ({ linkId, label: 'Graph fixture' }) } });
    return { context, document, requests, resources, openEdge, confirmations, alerts, html,
        refresh: () => document.getElementById('btnRefresh').listeners.click(),
        toast: () => document.getElementById('toast')?.textContent };
}

function dispatch(app, call) {
    if (call.pathname === '/api/cascade/topology') return response(call.url, { nodes: [], edges: [] });
    if (call.pathname === '/api/cascade/links' && !call.method) return response(call.url, { links: [], topologyRevision: 7, deployedRevision: 6 });
    return app.request(call.pathname, { method: call.method, body: call.body,
        headers: { cookie: 'fixture=session', ...Object.fromEntries(new Headers(call.headers)),
            ...(call.method === 'POST' ? { origin } : {}) } });
}

test('rebuild nodes drawer keeps Delete but offers no strict Undeploy action', async () => {
    const ui = mount('nodes', 'ru', '', true, () => assert.fail('unexpected strict request'));
    ui.openEdge();
    const drawer = ui.document.getElementById('nodeInfoBody').innerHTML;
    assert.match(drawer, /id="btnDelete"/);
    assert.doesNotMatch(drawer, /id="btnUndeploy"|_cascadeUndeploy\(/);
    await ui.context._cascadeUndeploy(linkId);
    assert.deepEqual(ui.requests, []);
});

for (const [reason, copyKey] of [
    ['RUNTIME_FOREIGN_CHANGE', 'neighborRuntimeForeignChange'],
    ['NETWORK_OBSERVATION_REQUIRED', 'neighborNetworkNotReady'],
]) test(`link remove preview preserves ${reason} and never dispatches deletion`, async () => {
    const { checkNeighborRefusal } = require('../../services/rebuildNeighborRefusal');
    const previewFailure = checkNeighborRefusal(Object.assign(new Error('/private/diag'), {
        code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED', reason,
    }), '212 East');
    const app = makeApp(previewFailure);
    const req = { method: 'POST', body: JSON.stringify({ linkId, remove: true }), headers: {
        cookie: 'fixture=session', origin, 'content-type': 'application/json', 'x-csrf-token': app.stale,
    } };
    assert.equal((await app.request(previewPath, { ...req, headers: { ...req.headers, cookie: 'fixture=api' } })).status, 403);
    assert.deepEqual(app.calls, []);
    const projected = await app.request(previewPath, req);
    assert.equal(projected.status, 409);
    const body = await projected.json();
    assert.deepEqual(body, { error: {
        code: 'REBUILD_RETIRE_NEIGHBOR_REFUSED', neighborName: '212 East', reason,
    } });
    const texts = new Set();
    for (const lang of ['en', 'ru', 'zh-CN']) {
        let opened;
        const shown = new Promise(resolve => { opened = resolve; });
        const ui = mount('nodes', lang, app.stale, true, call => dispatch(app, call), { onDialog: opened });
        const action = ui.context._cascadeDelete(linkId);
        await openedBy({ opened: shown, confirmations: ui.confirmations }, action);
        assert.deepEqual(ui.requests.filter(call => call.method).map(call => call.pathname), [previewPath]);
        const copy = require(`../../locales/${lang}.json`).nodes.retireRelay;
        const warning = ui.document.getElementById('rebuildPreviewWarning');
        assert.equal(typeof copy[copyKey], 'string');
        texts.add(copy[copyKey]);
        assert.equal(warning.textContent, copy.neighborRefused.replace('{name}', '212 East') + ' ' + copy[copyKey]);
        assert.equal(warning.innerHTML, undefined);
        assert.equal(ui.document.getElementById('rebuildPreviewApply').hidden, true);
        ui.document.getElementById('rebuildPreviewCancel').onclick();
        await action;
    }
    assert.equal(texts.size, 3);
    assert.equal(app.calls.length, 4);
    assert.ok(app.calls.every(call => call.preview === true && call.remove === true));
});

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
        assert.equal(ui.document.getElementById('rebuildPreview'), null);
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
    assert.equal(ui.confirmations.length, 1);
});

test('bridge placeholder refusal: actual Deploy toast uses localized guidance only for the dedicated code', async () => {
    const bridge = 'REBUILD_L2TP_APPLY_BRIDGE_PLACEHOLDER_UNPROVED';
    for (const lang of ['en', 'ru', 'zh-CN']) {
        for (const code of [bridge, 'REBUILD_L2TP_APPLY_NETWORK_REFUSED']) {
            const app = makeApp(undefined, Object.assign(new Error('private fixture detail'), { code }));
            const ui = mount('nodes', lang, app.stale, true, call => dispatch(app, call));
            await ui.context._cascadeDeploy(linkId);
            assert.ok(ui.toast().includes(code));
            assert.equal(ui.toast().includes(t('network.bridgePlaceholderUnproved', lang)), code === bridge);
            assert.doesNotMatch(ui.toast(), /private fixture detail/);
            assert.deepEqual(app.calls.map(call => call.preview), [true, false]);
        }
    }
});

const portalId = 'c'.repeat(24), gatewayId = 'd'.repeat(24), relayId = 'e'.repeat(24), unknownId = 'f'.repeat(24);
const portalLabel = 'North <b>Harbor</b>\n$& {name}', cleanPortalLabel = 'North <b>Harbor</b> $& {name}';
const removePath = '/api/cascade/links/' + linkId;
const profile = (profile, sections, options = {}) => ({ profile, change: sections.length ? 'replace' : 'unchanged',
    sections, protectedChanged: false, ...options });

async function mountPreview(view, lang, { exitImpact, protectedChanged = false, native = true, approve = true,
    reportId = previewId } = {}) {
    const opened = Promise.withResolvers();
    const nodes = [
        { nodeId: portalId, role: 'portal', exitImpact, profiles: [profile('main', ['inbounds', 'routing'], { protectedChanged }),
            profile('bridge', ['inbounds'], { tunnelMigration: 'legacy-to-vless-reverse' })] },
        // Reports from older servers can omit role; the topology still knows it.
        { nodeId: gatewayId, profiles: [profile('main', []), profile('bridge', ['outbounds'])] },
        { nodeId: relayId, profiles: [profile('main', []), profile('bridge', [])] },
        { nodeId: unknownId, profiles: [profile('main', ['routing', 'reverse', 'dns']), profile('bridge', [])] },
    ];
    const ui = mount(view, lang, 'fixture', true, ({ pathname, url, method }) => {
        if (pathname === '/api/cascade/topology') return response(url, { edges: [], nodes: [
            [portalId, portalLabel, 'portal'], [gatewayId, 'West Exit', 'bridge'], [relayId, 'Middle', 'relay'],
        ].map(([id, label, cascadeRole]) => ({ data: { id, label, cascadeRole }, position: { x: 0, y: 0 } })) });
        if (pathname === '/api/cascade/links' && !method) return response(url, { links: [], topologyRevision: 7, deployedRevision: 6 });
        if (pathname === previewPath) return response(url, { allowed: !protectedChanged, nodes, previewId: reportId });
        assert.ok(pathname === removePath && method === 'DELETE' || pathname === deployPath && method === 'POST');
        return response(url, { executionMode: 'rebuild', deleted: linkId, status: 'succeeded' });
    }, { onDialog: native ? opened.resolve : undefined, confirm: () => approve });
    assert.equal(await ui.refresh(), true);
    const get = suffix => ui.document.getElementById('rebuildPreview' + suffix);
    return { ...ui, opened: opened.promise, get, writes: () => ui.requests.filter(call => call.method) };
}

const copy = {
    ru: {
        lost: `после удаления у портала ${cleanPortalLabel} не останется выхода — клиенты этого портала потеряют интернет`,
        partial: `После удаления у портала ${cleanPortalLabel} пропадёт выход по умолчанию — геомаршруты сохранятся.`,
        blocked: `После удаления у портала ${cleanPortalLabel} не будет выхода — у клиентов этого портала не будет интернета.`,
        portal: 'портал: меняется вход и маршруты', gateway: 'шлюз: меняется выход', unchanged: 'ретранслятор: без изменений',
        unknown: 'Узел №4 — узел: меняются маршруты, обратные туннели и DNS', settings: 'Параметры подключения клиентов не изменятся.',
        protected: 'Параметры подключения клиентов изменились бы.', refused: 'Применение запрещено. Конфигурация нод не изменена.',
    },
    en: {
        lost: `After removal, portal ${cleanPortalLabel} will have no exit — clients of this portal will lose internet access.`,
        partial: `After removal, portal ${cleanPortalLabel} will lose its default exit — geo routes will remain.`,
        blocked: `After removal, portal ${cleanPortalLabel} will have no exit — its clients will have no internet access.`,
        portal: 'portal: inbound and routing will change', gateway: 'gateway: outbound will change', unchanged: 'relay: no changes',
        unknown: 'Node #4 — node: routing, reverse tunnels, and DNS will change', settings: 'Client connection settings will not change.',
        protected: 'Client connection settings would change.', refused: 'Apply refused. Node configurations were not changed.',
    },
};

function assertSummary(text, expected, protectedChanged = false) {
    for (const label of [cleanPortalLabel, 'West Exit', 'Middle', expected.portal, expected.gateway, expected.unchanged,
        expected.unknown, expected.settings, 'VLESS Reverse Proxy']) assert.ok(text.includes(label), `Missing: ${label}\n${text}`);
    assert.equal(text.includes(expected.protected), protectedChanged);
    for (const value of [portalId, gatewayId, relayId, unknownId, 'main replace', 'inbounds', 'outbounds', 'bridge unchanged']) {
        assert.ok(!text.includes(value), `Raw preview data: ${value}`);
    }
}

async function openedBy(ui, action) {
    return Promise.race([ui.opened, action.then(() => assert.fail(
        'No rendered Preview dialog. Native prompts: ' + JSON.stringify(ui.confirmations)))]);
}

for (const view of ['nodes', 'network']) for (const [lang, expected] of Object.entries(copy)) {
    test(`${view} (${lang}): Remove highlights total exit loss before named, deduplicated details; Cancel never deletes`, async () => {
        const ui = await mountPreview(view, lang, { exitImpact: 'lost' });
        const action = ui.context._cascadeDelete(linkId);
        const dialog = await openedBy(ui, action);
        const currentAsset = require('node:crypto').createHash('sha256').update(readFileSync(path.join(root, 'public/js/network.js'))).digest('hex').slice(0, 16);
        assert.deepEqual(ui.resources.filter(src => src.startsWith('/js/network')),
            ['/js/network.js?v=' + currentAsset]);
        assert.ok(dialog.open);
        assert.match(ui.html, /<dialog[^>]*id="rebuildPreview"[^>]*aria-labelledby="rebuildPreviewTitle"[^>]*>/);
        assert.match(ui.html, /id="rebuildPreviewWarning"[\s\S]*id="rebuildPreviewDetails"[\s\S]*id="rebuildPreviewCancel"[^>]*autofocus/);
        assert.equal(ui.get('Warning').hidden, false);
        assert.equal(ui.get('Warning').textContent, expected.lost);
        assert.equal(ui.get('Warning').innerHTML, undefined);
        assertSummary(ui.get('Details').textContent, expected);
        assert.equal(ui.get('Details').innerHTML, undefined);
        assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
        assert.equal(JSON.parse(ui.writes()[0].body).remove, true);
        ui.get('Cancel').onclick();
        await action;
        assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
        assert.equal(dialog.open, false);
        assert.equal(ui.toast(), lang === 'ru' ? 'Применение отменено.' : 'Apply cancelled.');
    });

    test(`${view} (${lang}): Remove with a healthy alternative has no warning and sends the exact preview once`, async () => {
        const ui = await mountPreview(view, lang);
        const action = ui.context._cascadeDelete(linkId);
        await openedBy(ui, action);
        assert.equal(ui.get('Warning').hidden, true);
        assert.equal(ui.get('Warning').textContent, '');
        assertSummary(ui.get('Details').textContent, expected);
        assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
        ui.get('Apply').onclick();
        await action;
        assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath, removePath]);
        assert.deepEqual(JSON.parse(ui.writes()[1].body), { expectedTopologyRevision: 7, expectedPreview: previewId });
    });
}

for (const [lang, expected] of Object.entries(copy)) {
    test(`Remove (${lang}): partial and blocked exit impacts use distinct copy`, async () => {
        for (const [exitImpact, text] of [['default-lost', expected.partial], ['blocked', expected.blocked]]) {
            const ui = await mountPreview('network', lang, { exitImpact });
            const action = ui.context._cascadeDelete(linkId);
            const dialog = await openedBy(ui, action);
            assert.equal(ui.get('Warning').textContent, text);
            dialog.close(); // Like the native Escape action: close without approval.
            await action;
            assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
        }
    });

    test(`Deploy (${lang}): protected settings refuse Apply; exit warning is Remove-only`, async () => {
        const ui = await mountPreview('nodes', lang, { exitImpact: 'lost', protectedChanged: true });
        const action = ui.context._cascadeDeploy(linkId);
        await openedBy(ui, action);
        assert.equal(ui.get('Title').textContent, expected.refused);
        assert.equal(ui.get('Warning').hidden, true);
        assert.equal(ui.get('Apply').hidden, true);
        assertSummary(ui.get('Details').textContent, expected, true);
        ui.get('Apply').onclick(); // Even activation of the hidden control cannot send a write.
        assert.equal(ui.get('').open, true);
        ui.get('Cancel').onclick();
        await action;
        assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
    });

    test(`Remove (${lang}): text-only fallback puts the warning first and respects Cancel`, async () => {
        const ui = await mountPreview('nodes', lang, { exitImpact: 'lost', native: false, approve: false });
        await ui.context._cascadeDelete(linkId);
        assert.equal(ui.confirmations.length, 1);
        assert.ok(ui.confirmations[0].startsWith(expected.lost + '\n'), ui.confirmations[0]);
        assertSummary(ui.confirmations[0], expected);
        assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
    });
}

test('a missing Preview ID cannot be approved or sent', async () => {
    const ui = await mountPreview('nodes', 'en', { native: false, reportId: null });
    await ui.context._cascadeDelete(linkId);
    assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
    assert.equal(ui.confirmations.length, 0);
});

test('a concurrent preview cannot replace the warning or send a second write', async () => {
    const reportId = 'd'.repeat(128);
    const ui = await mountPreview('network', 'en', { exitImpact: 'lost', reportId });
    const removing = ui.context._cascadeDelete(linkId);
    await openedBy(ui, removing);
    await ui.context._cascadeDeploy(linkId);
    assert.equal(ui.get('Warning').textContent, copy.en.lost);
    assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath, previewPath]);
    ui.get('Apply').onclick();
    await removing;
    assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath, previewPath, removePath]);
    assert.equal(JSON.parse(ui.writes()[2].body).expectedPreview, reportId);
});

test('a refused preview without native dialog can be read but never approved', async () => {
    const ui = await mountPreview('network', 'en', { native: false, protectedChanged: true });
    await ui.context._cascadeDeploy(linkId);
    assert.equal(ui.confirmations.length, 0);
    assert.equal(ui.alerts.length, 1);
    assert.ok(ui.alerts[0].startsWith(copy.en.refused));
    assertSummary(ui.alerts[0], copy.en, true);
    assert.deepEqual(ui.writes().map(call => call.pathname), [previewPath]);
});
