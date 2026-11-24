'use strict';

// Run in a loopback-only namespace, e.g.
// unshare -Urn sh -c 'ip link set lo up && exec node scripts/test-rebuild-fingerprint-browser.cjs'
// Use the same dummy config as rebuildNodesPage.test.js. No real DB or nodes.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { networkInterfaces } = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const express = require('express');
const { Firefox } = require('../browser-assets-wave8/firefox-bidi.cjs');

const root = path.join(__dirname, '..');
const portal = '1'.repeat(24), bridge = '2'.repeat(24), linkId = '3'.repeat(24);
const unsafeName = 'Bridge <i data-fingerprint-fixture>literal</i>';
const link = { _id: linkId, name: 'Fixture link', active: true, mode: 'reverse', status: 'pending',
    portalNode: portal, bridgeNode: bridge, tunnelProtocol: 'vless', tunnelSecurity: 'reality', realityFingerprint: 'random' };

async function main() {
    assert.deepEqual(Object.keys(networkInterfaces()), ['lo'], 'requires a loopback-only network namespace');
    assert.equal(process.env.NODE_ENV, 'test');
    assert.ok(process.env.TMPDIR, 'use a disposable scratch directory');
    const Node = require('../src/models/hyNodeModel');
    const docs = [new Node({ _id: portal, name: 'Portal', ip: '192.0.2.1', xrayVersion: '26.3.27', type: 'xray' }),
        new Node({ _id: bridge, name: unsafeName, ip: '192.0.2.2', xrayVersion: '26.11.9', type: 'xray' })];
    // Session and persistence seams only for the two real GET routes.
    Node.find = () => ({ populate: () => ({ sort: async () => docs }) });
    require('../src/models/cascadeLinkModel').countDocuments = async () => 1;
    require('../src/models/settingsModel').get = async () => ({});
    require('../src/services/cacheService').getGroups = async () => [];
    const auth = require('../src/middleware/auth');
    const { i18nMiddleware } = require('../src/middleware/i18n');
    const { issuePanelCsrfToken, requirePanelCsrf } = require('../src/routes/panel/csrf');
    const app = express(), writes = [], session = { authenticated: true };
    app.set('views', path.join(root, 'views'));
    app.set('view engine', 'ejs');
    app.use(express.json());
    app.use((req, res, next) => {
        req.session = session;
        res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:");
        next();
    });
    app.use(i18nMiddleware);
    app.use(express.static(path.join(root, 'public')));
    app.use('/panel', auth, (req, res, next) => {
        res.locals.c3Rebuild = true;
        res.locals.csrfToken = issuePanelCsrfToken(req);
        next();
    }, require('../src/routes/panel/nodes'));
    app.use('/api/nodes', auth, require('../src/routes/nodes'));
    app.get('/api/cascade/topology', (_, res) => res.json({ nodes: docs.map((node, i) => ({
        data: { id: String(node._id), label: node.name }, position: { x: 50 + i * 200, y: 100 },
    })), edges: [{ data: { ...link, id: 'link-' + linkId, linkId, source: portal, target: bridge } }] }));
    app.get('/api/cascade/links', (_, res) => res.json({ topologyRevision: 1, deployedRevision: 0, links: [link] }));
    app.get('/api/cascade/links/:id', (_, res) => res.json(link));
    app.use('/api/cascade', (req, res, next) => {
        writes.push({ method: req.method, path: req.path, body: req.body });
        next();
    }, requirePanelCsrf);
    // Contract fixture: the matching backend implementation is not in this worktree.
    app.post('/api/cascade/rebuild/preview', (_, res) => res.status(409).json({
        error: { code: 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED' },
        fingerprintIssue: { dialerId: bridge, version: '26.11.10', fingerprint: 'random', allowed: ['chrome', 'firefox', 'safari'] },
    }));
    app.use('/api', (_, res) => res.sendStatus(404));
    const scratch = mkdtempSync(path.join(process.env.TMPDIR, 'rebuild-fp-firefox-'));
    const server = app.listen(0, '127.0.0.1');
    const browser = new Firefox();
    try {
        await once(server, 'listening');
        const origin = 'http://127.0.0.1:' + server.address().port;
        const api = await fetch(origin + '/api/nodes');
        assert.equal(api.status, 200);
        assert.deepEqual((await api.json()).map(node => [node._id, node.xrayVersion]), [[portal, '26.3.27'], [bridge, '26.11.9']]);
        await browser.start(scratch);
        // Keep the real page/asset/dialog. Substitute only the graph library
        // (CDNs disabled); fire the stored edge tap as the map integration seam.
        await browser.send('script.addPreloadScript', { functionDeclaration: `() => {
            window.cytoscape = () => {
                let rows = []; const handlers = {};
                const collection = items => Object.assign(items, { toArray: () => items,
                    filter: predicate => collection(Array.prototype.filter.call(items, predicate)),
                    data: (...args) => items[0]?.data(...args) });
                window.fixtureTapEdge = () => handlers.edge({ target: rows.find(row => row.group === 'edges') });
                return { on(event, selector, handler) { if (event === 'tap' && handler) handlers[selector] = handler; },
                    resize() {}, fit() {}, zoom: () => 1, pan: () => ({x: 0, y: 0}),
                    nodes: () => collection(rows.filter(row => row.group === 'nodes')),
                    edges: () => collection(rows.filter(row => row.group === 'edges')),
                    elements: () => ({ remove() { rows = []; }, unselect() {} }),
                    getElementById: id => rows.find(row => row.id() === id) || { length: 0 },
                    add(data) { rows = data.map(({ group, data, position }) => ({ group, length: 1, id: () => data.id,
                        position: () => position, data(key, value) { if (value !== undefined) data[key] = value; return key === undefined ? data : data[key]; } })); }
                };
            };
        }` });
        for (const lang of ['en', 'ru']) {
            writes.length = 0;
            await browser.navigate(origin + '/panel/nodes?map=classic&lang=' + lang);
            const assetExpression = `Array.from(document.scripts, s => s.src).find(src => src.includes('/js/network.js?'))`;
            await browser.wait(assetExpression);
            const url = await browser.evaluate(assetExpression);
            const sha = bytes => createHash('sha256').update(bytes).digest('hex');
            const diskHash = sha(readFileSync(path.join(root, 'public/js/network.js')));
            assert.equal(new URL(url).searchParams.get('v'), diskHash.slice(0, 16));
            const asset = await fetch(url);
            assert.equal(asset.status, 200);
            assert.equal(sha(Buffer.from(await asset.arrayBuffer())), diskHash);
            const graphAssets = await browser.evaluate(`Array.from(document.scripts, s => s.src)
                .filter(src => src.includes('/js/rebuild-preview.js?') || src.includes('/js/network.js?'))`);
            const sharedHash = sha(readFileSync(path.join(root, 'public/js/rebuild-preview.js')));
            const sharedUrl = `${origin}/js/rebuild-preview.js?v=${sharedHash.slice(0, 16)}`;
            assert.deepEqual(graphAssets, [sharedUrl, url]);
            const sharedAsset = await fetch(sharedUrl);
            assert.equal(sharedAsset.status, 200);
            assert.equal(sha(Buffer.from(await sharedAsset.arrayBuffer())), sharedHash);
            assert.equal(await browser.evaluate('document.querySelectorAll("dialog#rebuildPreview").length'), 1);
            await browser.wait("typeof fixtureTapEdge === 'function' && !document.querySelector('.network-loading')");
            await browser.click('#btnAddLink');
            await browser.wait("document.getElementById('addLinkModal').classList.contains('active')");
            const options = await browser.evaluate(`Array.from(document.getElementById('selectPortal').options, o => [o.value, o.textContent])`);
            assert.equal(await browser.fill('#selectPortal', portal), portal,
                JSON.stringify(options));
            assert.equal(await browser.fill('#selectBridge', bridge), bridge);
            assert.equal(await browser.evaluate('document.getElementById("linkFingerprint").value'), 'chrome');
            assert.equal(await browser.evaluate('document.querySelector("#linkFingerprint option[value=random]").disabled'), true,
                JSON.stringify(await browser.evaluate(`(() => { const form = document.getElementById('addLinkForm'); return {
                    mode: form.mode.value, security: form.tunnelSecurity.value, bridge: form.bridgeNodeId.value,
                    hint: document.getElementById('linkFingerprintHint').textContent,
                }; })()`)) + JSON.stringify(browser.events.filter(event => event.method === 'log.entryAdded' && event.params.type === 'javascript')));
            assert.match(await browser.evaluate('document.getElementById("linkFingerprintHint").textContent'),
                lang === 'ru' ? /Исходящее соединение: Bridge .*26\.11\.9.*Допустимо: chrome, firefox, safari/ : /Dialer: Bridge .*26\.11\.9.*Allowed: chrome, firefox, safari/);
            assert.equal(await browser.evaluate('document.querySelector("[data-fingerprint-fixture]") === null'), true);
            await browser.click('#modalClose');
            // This checkout ships the quick form, but has no normal entry
            // point. Supply the endpoints at that seam and use real controls.
            await browser.evaluate(`(() => {
                document.getElementById('quickPortalId').value = ${JSON.stringify(portal)};
                document.getElementById('quickBridgeId').value = ${JSON.stringify(bridge)};
                document.getElementById('quickLinkModal').classList.add('active');
            })()`);
            const quickHint = 'document.getElementById("quickFingerprintHint").textContent';
            await browser.wait(`${quickHint}.includes('26.11.9')`);
            assert.match(await browser.evaluate(quickHint), /Bridge .*26\.11\.9.*chrome.*chrome, firefox, safari/);
            await browser.click('#quickSwapBtn');
            assert.match(await browser.evaluate(quickHint), /Portal.*26\.3\.27.*chrome/);
            await browser.click('#quickModalClose');
            await browser.evaluate('fixtureTapEdge()');
            await browser.click('#btnEdit');
            await browser.wait("document.getElementById('addLinkModal').classList.contains('active')");
            assert.equal(await browser.evaluate('document.getElementById("linkFingerprint").value'), 'random');
            assert.equal(await browser.evaluate('document.getElementById("linkModalSubmit").disabled'), true);
            await browser.evaluate('document.getElementById("addLinkForm").dispatchEvent(new Event("submit", { cancelable: true }))');
            await browser.click('#modalClose');
            await browser.evaluate('fixtureTapEdge()');
            await browser.click('#btnDeploy');
            await browser.wait('document.getElementById("rebuildPreview").open');
            const dialog = await browser.evaluate(`(() => { const get = id => document.getElementById('rebuildPreview' + id); return {
                warning: get('Warning').textContent, applyHidden: get('Apply').hidden, close: get('Cancel').textContent,
                injected: !!get('Warning').querySelector('[data-fingerprint-fixture]'),
            }; })()`);
            assert.equal(dialog.applyHidden, true);
            assert.equal(dialog.injected, false);
            assert.match(dialog.warning, lang === 'ru' ? /Исходящее соединение: Bridge .*26\.11\.10.*random.*Допустимо: chrome, firefox, safari/
                : /Dialer: Bridge .*26\.11\.10.*random.*Allowed: chrome, firefox, safari/);
            assert.ok(dialog.warning.includes(unsafeName));
            assert.equal(dialog.close, require('../src/locales/' + lang + '.json').common.close);
            await browser.click('#rebuildPreviewCancel');
            await browser.wait('!document.getElementById("rebuildPreview").open');
            assert.deepEqual(writes.map(write => [write.method, write.path]), [['POST', '/rebuild/preview']]);
            console.log(`${lang}: served source, create/edit and quick-form swap, Preview refusal; 0 edit writes, 1 Preview, 0 Apply`);
        }
    } finally {
        try { await browser.close(); }
        finally {
            await new Promise(resolve => server.close(resolve));
            await require('../src/services/sshPoolService').closeAll();
            rmSync(scratch, { recursive: true, force: true });
        }
    }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
