'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { readFileSync } = require('node:fs');
const { createHash } = require('node:crypto');
const vm = require('node:vm');
const { test, after } = require('node:test');
const express = require('express');
const { request } = require('../../services/tests/helpers/rebuildPanelRequest');
const nodes = require('../panel/nodes');
const { i18nMiddleware } = require('../../middleware/i18n');
const { requireAuth } = require('../panel/helpers');
const auth = require('../../middleware/auth');
const { issuePanelCsrfToken } = require('../panel/csrf');
const { routerForRebuild } = require('../cascadeRebuild');
const HyNode = require('../../models/hyNodeModel');
const Link = require('../../models/cascadeLinkModel');
const Settings = require('../../models/settingsModel');
const cache = require('../../services/cacheService');
const assetRevision = file => createHash('sha256').update(readFileSync(path.resolve(__dirname, '../../../public', file))).digest('hex').slice(0, 16);

after(() => require('../../services/sshPoolService').closeAll());

const legacyAssets = [
    'https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.4/cytoscape.min.js',
    'https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js',
    'https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js',
];

function mount(t, rebuild, customize = (_req, _res) => {}) {
    t.mock.method(HyNode, 'find', () => ({ populate: () => ({ sort: async () => [] }) }));
    t.mock.method(Link, 'countDocuments', async () => 0);
    t.mock.method(Settings, 'get', async () => ({}));
    t.mock.method(cache, 'getGroups', async () => []);
    const session = { authenticated: true };
    const app = express();
    app.set('views', path.resolve(__dirname, '../../../views'));
    app.set('view engine', 'ejs');
    app.use(i18nMiddleware);
    app.use('/panel', requireAuth, (req, res, next) => {
        res.locals.c3Rebuild = rebuild;
        res.locals.csrfToken = issuePanelCsrfToken(req);
        customize(req, res);
        next();
    }, nodes);
    return { app, session, get: url => request(app, url, { method: 'GET', session }) };
}

const tagId = (html, id) => html.match(new RegExp(`<[^>]+\\bid="${id}"[^>]*>`))?.[0] ?? '';
const mapDictionary = html => html.match(/<script type="application\/json" id="networkI18n">([^]*?)<\/script>/)?.[1];

function boot(html, { restore = false, blockedStorage = false, failAt = -1 } = {}) {
    const inline = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1])
        .find(js => js.includes('function loadNetworkScripts()'));
    assert.ok(inline, 'page contains its graph loader');
    const start = inline.indexOf('// ==================== View Tabs');
    const end = inline.indexOf('// ==================== DRAG-AND-DROP', start);
    assert.ok(end > start && start >= 0);
    const selected = [], window = {}, elements = new Map();
    const document = {
        createElement: () => ({}),
        body: { appendChild(script) {
            selected.push({ src: script.src, type: script.type });
            if (selected.length - 1 === failAt) script.onerror?.();
            else script.onload?.();
        } },
        getElementById(id) {
            const tag = tagId(html, id);
            if (!tag) return null;
            if (!elements.has(id)) elements.set(id, {
                style: { display: tag.includes('display:none') ? 'none' : '' },
                classList: new Set(tag.match(/class="([^"]+)"/)?.[1].split(' ') || []),
            });
            const node = elements.get(id);
            node.classList.remove = node.classList.delete;
            return node;
        },
    };
    const sessionStorage = {
        getItem() { if (blockedStorage) throw Error('Storage disabled'); return restore ? 'network' : null; },
        removeItem() {},
    };
    const context = vm.createContext({ window, document, sessionStorage, setTimeout: () => {} });
    vm.runInContext(inline.slice(start, end), context);
    return { selected, window, switchView: view => context.switchNodesView(view),
        mapOpen: () => document.getElementById('viewNetwork').style.display !== 'none',
        listOpen: () => document.getElementById('viewList').style.display !== 'none' };
}

for (const rebuild of [false, true]) {
    test(`${rebuild ? 'Rebuild explicit fallback' : 'Classic default'} keeps the original loader and forms`, async t => {
        const { app, session, get } = mount(t, rebuild);
        const page = await get(rebuild ? '/panel/nodes?map=classic' : '/panel/nodes');
        assert.equal(page.status, 200);
        const ui = boot(page.body);
        assert.equal(ui.mapOpen(), rebuild);
        assert.equal(ui.listOpen(), !rebuild);
        if (!rebuild) ui.switchView('network');
        assert.equal(ui.window._c3Rebuild, rebuild);
        const asset = rebuild ? 'network.js' : 'network.min.js';
        const digest = createHash('sha256').update(readFileSync(path.resolve(__dirname, '../../../public/js', asset))).digest('hex');
        const selected = [...legacyAssets, `/js/${asset}?v=${digest.slice(0, 16)}`].map(src => ({ src, type: undefined }));
        assert.deepEqual(ui.selected, selected);
        const afterFailure = boot(page.body, { failAt: 1 });
        if (!rebuild) afterFailure.switchView('network');
        assert.deepEqual(afterFailure.selected, selected, 'legacy loader continues after a failed dependency');
        assert.ok(tagId(page.body, 'btnAddLink'));
        assert.ok(tagId(page.body, 'addLinkForm'));
        assert.equal(/<option value="kcp">/.test(page.body), rebuild);
        assert.equal(/name="kcpMtu"[^>]*min="576" max="1460"/.test(page.body), rebuild);
        assert.doesNotMatch(page.body, /\/js\/network\/dist\/|\/css\/network-map\.css/);
        if (!rebuild) return;

        const service = { locks: { run: callback => callback() } };
        app.use('/api/cascade', auth, routerForRebuild({ service }));
        const post = headers => request(app, '/api/cascade/links', { session, headers, body: {} });
        const without = await post({});
        assert.equal(without.status, 403);
        assert.equal(JSON.parse(without.body).code, 'CSRF_TOKEN_INVALID');
        const withPageToken = await post({ 'x-csrf-token': ui.window._networkCsrfToken });
        assert.equal(withPageToken.status, 400);
        assert.equal(JSON.parse(withPageToken.body).error.code, 'REBUILD_INVALID_REQUEST');
    });
}

test('Rebuild defaults to modern, lazy-loads only the ES module and has a link to the fallback', async t => {
    const { get } = mount(t, true);
    const page = await get('/panel/nodes');
    assert.equal(page.status, 200);
    const ui = boot(page.body);
    assert.equal(ui.mapOpen(), false);
    assert.equal(ui.listOpen(), true);
    assert.deepEqual(ui.selected, []);
    ui.switchView('network');
    ui.switchView('list');
    ui.switchView('network');
    assert.equal(ui.mapOpen(), true);
    assert.equal(ui.listOpen(), false);
    assert.deepEqual(ui.selected, [{ src: `/js/network/dist/index.js?v=${assetRevision('js/network/dist/index.js')}`, type: 'module' }]);
    assert.equal(ui.window._networkCsrfToken, undefined);
    assert.equal(ui.window._networkI18n, undefined);
    assert.doesNotMatch(page.body, /cytoscape(?:-dagre)?\.min\.js|\/js\/network(?:\.min)?\.js|\/css\/network\.min\.css/);
    assert.ok(page.body.includes(`/css/network-map.css?v=${assetRevision('css/network-map.css')}`));
    assert.match(page.body, /href="\/panel\/nodes\?map=classic"/);
    assert.match(tagId(page.body, 'networkRoot'), /data-read-only="true"/);
    for (const part of ['nm-bar', 'nm-body', 'nm-stage', 'nm-insp', 'nm-state']) assert.match(page.body, new RegExp(`class="${part}"`));
    for (const id of ['btnAddLink', 'addLinkForm', 'addLinkModal', 'btnAutoLayout']) assert.equal(tagId(page.body, id), '');
    assert.deepEqual([...page.body.matchAll(/data-nm-view="([^"]+)"/g)].map(m => m[1]), ['chains', 'graph', 'geo']);
    assert.equal(boot(page.body, { restore: true }).mapOpen(), true);
    assert.equal(boot(page.body, { blockedStorage: true }).mapOpen(), false);
});

test('map URLs open the tab, redirects preserve accepted flags, and Classic cannot opt into modern', async t => {
    const { app, get } = mount(t, true);
    for (const [suffix, query] of [['', 'view=network'], ['?map=classic', 'map=classic'], ['?map=modern', 'map=modern'],
        ['?map[]=classic', 'view=network'], ['?map=classic&map=modern', 'view=network'], ['?map=elsewhere', 'view=network']]) {
        const redirect = await get(`/panel/network${suffix}`);
        assert.equal(redirect.status, 302);
        assert.equal(redirect.headers.location, `/panel/nodes?${query}`);
        const followed = await get(redirect.headers.location);
        assert.equal(followed.status, 200);
        const ui = boot(followed.body, { blockedStorage: true });
        assert.equal(ui.mapOpen(), true);
        assert.equal(ui.listOpen(), false);
        assert.equal(ui.selected.some(s => s.type === 'module'), query !== 'map=classic');
    }
    const fallback = await get('/panel/nodes?map=classic');
    assert.match(fallback.body, /href="\/panel\/nodes\?map=modern"/);
    assert.match(fallback.body, /href="\?map=classic&amp;lang=zh-CN"/);
    assert.equal(boot((await get('/panel/nodes?map[]=classic')).body).mapOpen(), false);
    const denied = await request(app, '/panel/nodes?map=classic', { method: 'GET' });
    assert.equal(denied.headers.location, '/panel/login');
});

test('Classic explicit map URLs never load the modern mount', async t => {
    const { get } = mount(t, false);
    for (const flag of ['modern', 'classic']) {
        const redirect = await get(`/panel/network?map=${flag}`);
        const page = await get(redirect.headers.location);
        const ui = boot(page.body, { blockedStorage: true });
        assert.equal(redirect.headers.location, `/panel/nodes?map=${flag}`);
        assert.equal(ui.mapOpen(), true);
        assert.equal(ui.selected.at(-1).src.startsWith('/js/network.min.js?v='), true);
        assert.doesNotMatch(page.body, /\/js\/network\/dist\/|id="networkRoot"/);
    }
});

test('modern locale payload is limited, translated, and safe inside an HTML script element', async t => {
    const marker = '</script><script>fixture()</script>\u2028\u2029&';
    const { get } = mount(t, true, (req, res) => {
        if (req.query.fixture !== '1') return;
        const { t: translate, locales } = res.locals;
        res.locals.t = key => key === 'network.loadingTopology' ? marker : translate(key);
        res.locals.locales = { ...locales, network: { ...locales.network, map: { ...locales.network.map, searchPlaceholder: marker } } };
    });
    for (const lang of ['en', 'ru', 'zh-CN']) {
        const page = await get(`/panel/nodes?map=modern&lang=${lang}`);
        assert.equal(page.status, 200);
        const { network: { map, mkcpAppliedUnverified } } = require(`../../locales/${lang}.json`);
        const data = JSON.parse(mapDictionary(page.body));
        assert.equal(data.map.searchPlaceholder, map.searchPlaceholder);
        assert.equal(data.map.status.deployed, map.status.deployed);
        assert.equal(data.map.status.unknown, map.status.unknown);
        assert.equal(data.mkcpAppliedUnverified, mkcpAppliedUnverified);
        assert.equal(data.tunnelUnknown, map.tunnelUnknown);
        assert.ok(page.body.includes(map.readOnlyNotice));
        assert.ok(page.body.includes(map.openClassic));
        assert.equal(data.map.create, undefined);
        assert.equal(data.confirmDeploy, undefined);
        assert.equal(data.kcpMtu, undefined);
    }
    const adversarial = await get('/panel/nodes?fixture=1');
    assert.equal(adversarial.status, 200);
    const raw = mapDictionary(adversarial.body);
    assert.doesNotMatch(raw, /[<\u2028\u2029]/u);
    const parsed = JSON.parse(raw);
    assert.equal(parsed.loadingTopology, marker);
    assert.equal(parsed.map.searchPlaceholder, marker);
    assert.doesNotMatch(adversarial.body, /<script>fixture\(\)<\/script>/);
});
