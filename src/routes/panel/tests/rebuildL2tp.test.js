'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const test = require('node:test');
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { i18nMiddleware } = require('../../../middleware/i18n');
const Settings = require('../../../models/settingsModel');
const helpers = require('../helpers');
const panelRouter = require('..');
const { createPanelRouter } = panelRouter;

const page = '/panel/l2tp';
const accounts = '/panel/rebuild/relays/l2tp/accounts/reveal';
const id = 'abcdef0123456789abcdef01';
const pskPath = relay => `/panel/rebuild/relays/${relay}/l2tp/psk/reveal`;
const psk = pskPath(id);
const login = 'Fixture.Account@local';
const marker = 'FIXTURE_PRIVATE_VALUE';
const password = `${marker}_PASSWORD`;
const sharedKey = `${marker}_PSK`;

test.after(() => require('../../../services/sshPoolService').closeAll());

async function mount(t, { rebuild = true, ingress = false } = {}) {
    const originalMode = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = String(rebuild);
    t.after(() => {
        if (originalMode === undefined) delete process.env.C3_REBUILD_ENABLED;
        else process.env.C3_REBUILD_ENABLED = originalMode;
        helpers.invalidateOnboardingCache();
    });
    const config = require('../../../../config');
    const allowlist = config.PANEL_IP_WHITELIST;
    config.PANEL_IP_WHITELIST = '127.0.0.1';
    t.after(() => { config.PANEL_IP_WHITELIST = allowlist; });
    const state = { onboarded: true, calls: [] };
    const loadSettings = async () => {
        if (state.onboardingFailure) throw new Error(marker);
        return { deployment: { completed: state.onboarded } };
    };
    t.mock.method(Settings, 'get', loadSettings);
    t.mock.method(Settings, 'findById', key => {
        assert.equal(key, 'settings');
        return { select(projection) {
            assert.equal(projection, 'deployment.completed');
            return { lean: loadSettings };
        } };
    });
    helpers.invalidateOnboardingCache();

    const view = path.resolve(__dirname, '../../../../views/rebuild-l2tp.ejs');
    const read = fs.readFileSync;
    t.mock.method(fs, 'readFileSync', (filename, ...args) => filename === view
        ? '<main id="fixture-rebuild-l2tp"><%= page %>:<%= accounts.map(account => account.login).join(",") %>'
            + '<% if (typeof loadError !== "undefined" && loadError) { %><%= t("dashboard.loadError") %><% } %></main>'
        : read(filename, ...args));
    const service = {
        async overview() {
            state.calls.push(['overview']);
            if (state.overviewFailure) throw new Error(marker);
            return { relays: [], accounts: [{ login }] };
        },
        async revealPassword(value) {
            state.calls.push(['password', value]);
            if (state.revealFailure) throw Object.assign(new Error(marker), { code: marker, secret: marker });
            return state.badReveal ? { secret: marker } : value === login ? password : null;
        },
        async revealPsk(value) {
            state.calls.push(['psk', value]);
            if (state.revealFailure) throw new Error(marker);
            return value === id ? sharedKey : null;
        },
    };
    const app = express();
    app.set('view engine', 'ejs');
    app.set('views', path.dirname(view));
    if (ingress) {
        app.use(require('../rebuildL2tp').revealIngress);
        app.use(cors({ origin: 'http://fixture.invalid', credentials: true }));
    }
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(cookieParser());
    app.use(i18nMiddleware);
    app.use(session({ secret: 'fixture-session-signing', saveUninitialized: false, resave: false }));
    // Persist a fixture authenticated session via the real cookie/store machinery.
    app.get('/fixture/session', (req, res) => {
        req.session.authenticated = true;
        res.json({ csrf: require('../csrf').issuePanelCsrfToken(req) });
    });
    app.use((req, res, next) => {
        if (req.get('x-fixture-no-session-id')) delete req.sessionID;
        next();
    });
    app.use('/panel', rebuild ? createPanelRouter({ rebuildL2tpOverview: service }) : panelRouter);
    app.use((req, res) => res.status(404).send('Not found'));
    app.use((err, req, res, next) => res.status(500).send('Unexpected fixture error'));
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    async function request(url, { method = 'GET', headers = {}, auth, json, raw } = {}) {
        const response = await fetch(origin + url, {
            method, redirect: 'manual',
            headers: { ...(method === 'POST' && { Origin: origin }), ...(auth && { Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf }),
                ...(json !== undefined && { 'Content-Type': 'application/json' }), ...headers },
            body: json === undefined ? raw : JSON.stringify(json),
        });
        return { status: response.status, headers: response.headers, text: await response.text() };
    }
    async function postRaw(url, auth, raw) {
        // fetch normalizes away an empty query marker; preserve the wire URL.
        const req = http.request(origin, { path: url, method: 'POST', headers: {
            Origin: origin, Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf,
            'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(raw),
        } });
        req.end(raw);
        const [res] = await once(req, 'response');
        let text = '';
        for await (const chunk of res.setEncoding('utf8')) text += chunk;
        return { status: res.statusCode, headers: new Headers(res.headers), text };
    }
    async function signIn() {
        const { headers, text } = await request('/fixture/session');
        return { cookie: headers.get('set-cookie').split(';')[0], csrf: JSON.parse(text).csrf };
    }
    return { request, postRaw, signIn, state, origin };
}

function status(response, expected, label) {
    assert.equal(response.status, expected, label);
    assert.equal(response.headers.get('cache-control'), 'no-store', label);
}

function safe(response, expected, label) {
    status(response, expected, label);
    assert.doesNotMatch(response.text + JSON.stringify([...response.headers]), new RegExp(marker), label);
}

test('only exact authenticated, onboarded GET /panel/l2tp renders the rebuild overview', async t => {
    const { request, signIn, state } = await mount(t);
    let response = await request(page);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), '/panel/login');
    const auth = await signIn();
    state.onboarded = false;
    response = await request(page, { auth });
    assert.equal(response.headers.get('location'), '/panel/wizard');
    state.onboarded = true;
    helpers.invalidateOnboardingCache();
    assert.equal((await request(page, { auth, headers: { 'X-Forwarded-For': '192.0.2.1' } })).status, 403);
    assert.deepEqual(state.calls, []);
    response = await request(`${page}?lang=ru`, { auth });
    safe(response, 200);
    assert.match(response.text, /fixture-rebuild-l2tp">l2tp:Fixture\.Account@local/);
    assert.deepEqual(state.calls, [['overview']]);

    for (const [method, url] of [
        ['HEAD', page], ['POST', page], ['GET', `${page}/`], ['GET', '/panel/L2TP'],
        ['GET', `${page}/simple/overview`], ['POST', `${page}/simple/accounts`],
        ['GET', `/panel/nodes/${id}/l2tp/status`], ['POST', `/panel/nodes/${id}/l2tp/install`],
    ]) {
        response = await request(url, { auth, method });
        assert.equal(response.status, 409, `${method} ${url}`);
        if (method !== 'HEAD') assert.equal(JSON.parse(response.text).error.code, 'REBUILD_STRICT_DISABLED');
    }
    assert.deepEqual(state.calls, [['overview']]);
    state.overviewFailure = true;
    response = await request(`${page}?lang=ru`, { auth });
    safe(response, 503);
    assert.match(response.text, /fixture-rebuild-l2tp">l2tp:Ошибка загрузки/);
    assert.doesNotMatch(response.text, /Fixture\.Account@local/);
    assert.deepEqual(state.calls, [['overview'], ['overview']]);
});

test('both reveal POSTs enforce session, onboarding, existing same-origin CSRF and allowlist, always no-store', async t => {
    const { request, signIn, state, origin } = await mount(t);
    const auth = await signIn();
    const other = await signIn();
    for (const [url, json, secret] of [[accounts, { login }, password], [psk, {}, sharedKey]]) {
        const post = (auth, headers) => request(url, { method: 'POST', auth, json, headers });
        let response = await post(undefined, { Authorization: 'Bearer fixture-api-key' });
        safe(response, 302);
        assert.equal(response.headers.get('location'), '/panel/login');
        safe(await post(auth, { 'X-Forwarded-For': '192.0.2.1' }), 403);
        state.onboarded = false;
        response = await post(auth);
        safe(response, 302);
        assert.equal(response.headers.get('location'), '/panel/wizard');
        state.onboarded = true;
        helpers.invalidateOnboardingCache();
        state.onboardingFailure = true;
        safe(await post(auth), 503);
        state.onboardingFailure = false;
        safe(await post(auth, { 'X-Fixture-No-Session-ID': '1' }), 403);
        for (const [headers, code] of [
            [{ 'X-CSRF-Token': '' }, 'CSRF_TOKEN_INVALID'],
            [{ 'X-CSRF-Token': 'z'.repeat(43) }, 'CSRF_TOKEN_INVALID'],
            [{ 'X-CSRF-Token': 'é'.repeat(43) }, 'CSRF_TOKEN_INVALID'],
            [{ 'X-CSRF-Token': other.csrf }, 'CSRF_TOKEN_INVALID'],
            [{ Origin: 'http://foreign.invalid' }, 'CSRF_ORIGIN_INVALID'],
            [{ Origin: origin.replace('http:', 'https:') }, 'CSRF_ORIGIN_INVALID'],
        ]) {
            response = await post(auth, headers);
            safe(response, 403, code);
            assert.equal(JSON.parse(response.text).code, code);
        }
        for (const method of ['GET', 'HEAD', 'OPTIONS']) safe(await request(url, { method, auth }), 405, method);
        assert.equal(state.calls.length, url === accounts ? 0 : 1);
        response = await post(auth);
        status(response, 200);
        assert.deepEqual(JSON.parse(response.text), { secret });
        assert.equal(response.headers.get('etag'), null);
    }
    assert.deepEqual(state.calls, [['password', login], ['psk', id]]);
});

test('reveal inputs are JSON-only, with exact identifiers and no query; errors never echo input or service data', async t => {
    const { request, signIn, state } = await mount(t);
    const auth = await signIn();
    const post = (url, json, options = {}) => request(url, { method: 'POST', auth, json, ...options });
    for (const [url, json, options] of [
        [`${accounts}?login=${marker}`, { login }], [`${psk}?__proto__=x`, {}],
        [accounts, { login, secret: marker }], [accounts, { login, _csrf: auth.csrf }], [accounts, {}],
        [accounts, { login: [login] }], [accounts, [{ login }]], [accounts, { login: 7 }],
        [accounts, { login: ` ${login}` }], [accounts, { login: `${login}\n` }],
        [accounts, { login: 'a'.repeat(65) }], [accounts, { login: 'example+fixture' }],
        [psk, []], [psk, { login }], [psk, undefined],
        [psk, undefined, { raw: '', headers: { 'Content-Type': 'application/json' } }],
        [accounts, undefined, { raw: `login=${login}`, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }],
        [pskPath(id.toUpperCase()), {}], [pskPath(`%61${id.slice(1)}`), {}],
        [pskPath('%ZZ'), {}], [pskPath(`${id}%0A`), {}], [pskPath(id.slice(1)), {}],
    ]) safe(await post(url, json, options), 400, url);
    assert.deepEqual(state.calls, []);
    safe(await post(accounts, { login: login.toLowerCase() }), 404);
    safe(await post(pskPath('a'.repeat(24)), {}), 404);
    state.revealFailure = true;
    safe(await post(accounts, { login }), 503);
    safe(await post(psk, {}), 503);
    state.revealFailure = false;
    state.badReveal = true;
    safe(await post(accounts, { login }), 503);
    assert.deepEqual(state.calls, [
        ['password', login.toLowerCase()], ['psk', 'a'.repeat(24)], ['password', login], ['psk', id], ['password', login],
    ]);
});

test('pre-parser ingress refuses malformed, ambiguous and oversized requests without exposing input', async t => {
    const { postRaw, request, signIn, state } = await mount(t, { ingress: true });
    const auth = await signIn();
    for (const [url, raw] of [
        [accounts, `{"login":"${marker}`], [accounts, `{"login":"${marker}","login":"${login}"}`],
        [`${psk}?`, '{}'], [psk, ''], [psk, ' '.repeat(1025) + '{}'],
    ]) safe(await postRaw(url, auth, raw), 400);
    assert.deepEqual(state.calls, []);
    safe(await request(accounts, { method: 'OPTIONS', headers: { Origin: 'http://fixture.invalid' } }), 204);
    status(await postRaw(accounts, auth, `  { "login": "${login}" }\n`), 200);
});

test('the real reveal rate limiter shares one session budget across password and PSK', async t => {
    const { request, signIn, state } = await mount(t);
    const auth = await signIn();
    for (let i = 0; i < 10; ++i) {
        status(await request(accounts, { method: 'POST', auth, json: { login } }), 200);
    }
    const blocked = await request(psk, { method: 'POST', auth, json: {} });
    safe(blocked, 429);
    assert.ok(blocked.headers.get('retry-after'));
    assert.equal(state.calls.length, 10);
    status(await request(psk, { method: 'POST', auth: await signIn(), json: {} }), 200);
});

test('classic does not mount rebuild handlers or load the injected overview on stock routes', async t => {
    const { request, signIn, state } = await mount(t, { rebuild: false });
    const auth = await signIn();
    assert.equal((await request(page)).headers.get('location'), '/panel/login');
    const { l2tpActiveHostProvider } = require('../../../modules/l2tpActiveHostProvider');
    const unused = () => assert.fail('unexpected stock operation');
    const host = {
        loadPanelOverview: async () => ({}),
        runtime: {
            service: { getStatus: async relay => ({ node: relay, status: 'installed' }), preflight: unused, install: unused, getOperation: unused },
            stateManagementService: { configureRelay: unused },
            userManagementService: { createUser: unused, listUsers: unused, updateUser: unused, disableUser: unused },
            simpleService: { overview: async () => ({ stock: true }) },
        },
    };
    l2tpActiveHostProvider.installActiveHost(host);
    t.after(() => l2tpActiveHostProvider.clearActiveHost(host));
    const stockPage = await request(page, { auth });
    assert.equal(stockPage.status, 200);
    assert.match(stockPage.text, /\/panel\/l2tp\/simple\/overview/);
    assert.doesNotMatch(stockPage.text, /fixture-rebuild-l2tp/);
    assert.deepEqual(JSON.parse((await request(`${page}/simple/overview`, { auth })).text), { stock: true });
    const stockStatus = await request(`/panel/nodes/${id}/l2tp/status`, { auth });
    assert.equal(stockStatus.status, 200);
    assert.equal(JSON.parse(stockStatus.text).status, 'installed');
    for (const url of [accounts, psk]) {
        assert.equal((await request(url, { method: 'POST', auth, json: {} })).status, 404);
    }
    assert.deepEqual(state.calls, []);
});
