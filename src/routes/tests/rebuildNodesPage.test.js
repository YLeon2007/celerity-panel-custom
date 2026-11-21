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
const auth = require('../../middleware/auth');
const { issuePanelCsrfToken } = require('../panel/csrf');
const { routerForRebuild } = require('../cascadeRebuild');
const HyNode = require('../../models/hyNodeModel');
const Link = require('../../models/cascadeLinkModel');
const Settings = require('../../models/settingsModel');
const cache = require('../../services/cacheService');

after(() => require('../../services/sshPoolService').closeAll());

for (const rebuild of [true, false]) test(`GET /panel/nodes selects the ${rebuild ? 'rebuild' : 'classic'} graph in its rendered loader`, async t => {
    // Mock inventory reads, not the page handler, renderer, layout or token issuer.
    t.mock.method(HyNode, 'find', () => ({ populate: () => ({ sort: async () => [] }) }));
    t.mock.method(Link, 'countDocuments', async () => 0);
    t.mock.method(Settings, 'get', async () => ({}));
    t.mock.method(cache, 'getGroups', async () => []);
    const session = { authenticated: true };
    const app = express();
    app.set('views', path.resolve(__dirname, '../../../views'));
    app.set('view engine', 'ejs');
    app.use(i18nMiddleware);
    app.use('/panel', auth, (req, res, next) => {
        res.locals.c3Rebuild = rebuild;
        res.locals.csrfToken = issuePanelCsrfToken(req);
        next();
    }, nodes);
    const page = await request(app, '/panel/nodes', { method: 'GET', session });
    assert.equal(page.status, 200);
    const inline = [...page.body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1])
        .find(js => js.includes('function loadNetworkScripts()'));
    assert.ok(inline, 'page contains its graph loader');
    const start = inline.indexOf('function loadNetworkScripts()');
    const end = inline.indexOf('// Restore network view after page load', start);
    assert.ok(end > start);
    const selected = [], window = {};
    vm.runInNewContext(inline.slice(start, end) + '\nloadNetworkScripts();', { window, document: {
        createElement: () => ({}), body: { appendChild(script) { selected.push(script.src); script.onload(); } },
    } });
    assert.equal(window._c3Rebuild, rebuild);
    assert.deepEqual(selected.filter(url => url.startsWith('/js/network')), [
        rebuild ? '/js/network.js?v=' + createHash('sha256').update(readFileSync(path.join(__dirname, '../../../public/js/network.js'))).digest('hex').slice(0, 16) : '/js/network.min.js?v=8c1440573d630ba3',
    ]);
    if (rebuild) {
        const token = JSON.parse(inline.match(/window\._networkCsrfToken\s*=\s*("[A-Za-z0-9_-]+")/)[1]);
        const service = { locks: { run: callback => callback() } };
        app.use('/api/cascade', auth, routerForRebuild({ service }));
        const post = headers => request(app, '/api/cascade/links', { session, headers, body: {} });
        const without = await post({});
        assert.equal(without.status, 403);
        assert.equal(JSON.parse(without.body).code, 'CSRF_TOKEN_INVALID');
        const withPageToken = await post({ 'x-csrf-token': token });
        assert.equal(withPageToken.status, 400);
        assert.equal(JSON.parse(withPageToken.body).error.code, 'REBUILD_INVALID_REQUEST');
    }
});
