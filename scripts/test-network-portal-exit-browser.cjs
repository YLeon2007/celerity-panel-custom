'use strict';

// Real Firefox/native input with nodes.ejs. Use PORTAL_EXIT_SHIPPED=1 to test the shipped assets.
// Only the same-origin HTTP API is modeled; no DB, agent or external network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { test } = require('node:test');
const ejs = require('ejs');
const { t, getLocale } = require('../src/middleware/i18n');
const { Firefox } = require('./anyorder-browser-acceptance/firefox.cjs');

const root = path.resolve(__dirname, '..');
const [portal, relay, shared, selected, geo, otherRelay, otherBridge, extra, disabled, deleting] =
    '123456789a'.split('').map(c => c.repeat(24));
const [hop, defaultEdge, selectedEdge, geoEdge, unrelatedEdge, disabledEdge, deletingEdge, extraHop, extraEdge, parallelEdge] =
    'bcdef12345'.split('').map(c => ('0' + c).repeat(12));
const id = link => `link-${link}`;
const setting = (nodeId, relayGeo = true) => ({ nodeId, relayGeo });
const names = {
    [portal]: 'Portal P', [relay]: 'Relay R', [shared]: 'Shared S', [selected]: 'Chosen C', [geo]: 'Geo G',
    [otherRelay]: 'Other relay O', [otherBridge]: 'Other bridge B', [extra]: 'Alternate A',
    [disabled]: 'Disabled X', [deleting]: 'Deleting Y',
};
const nodes = Object.entries(names).map(([id, label], i) => ({
    data: { id, cascadeRole: i === 0 ? 'portal' : i === 1 || i === 5 ? 'relay' : 'bridge', type: 'xray', label, status: 'online', flag: '★' },
    position: { x: i === 0 ? 0 : i === 1 || i === 5 ? 300 : 650, y: i * 95 },
}));
nodes.push({ data: { id: 'internet', type: 'internet', status: 'online' }, position: { x: 980, y: 250 } });
const edge = (linkId, source, target, config = {}) => ({ data: {
    id: id(linkId), linkId, source, target, label: names[target], mode: 'forward', status: 'online',
    active: true, canEdit: true, rebuildApplied: true, priority: 100, geoRouting: { enabled: false }, ...config,
} });
const orgEdges = [edge(hop, portal, relay), edge(defaultEdge, relay, shared, { priority: 10 }),
    edge(selectedEdge, relay, selected, { label: 'A lower-ranked link', priority: 20 }),
    edge(parallelEdge, relay, selected, { label: 'Z best link', priority: 15 }),
    edge(geoEdge, relay, geo, { geoRouting: { enabled: true } }),
    edge(unrelatedEdge, otherRelay, otherBridge), edge(disabledEdge, relay, disabled, { active: false }),
    edge(deletingEdge, relay, deleting, { canEdit: false, applicationState: 'deleting' }),
    edge(extraHop, relay, otherRelay, { priority: 30 }), edge(extraEdge, otherRelay, extra, { priority: 200 })];
const token = 'A'.repeat(43);
const previewId = 'b'.repeat(64);
const marker = '<img src=/fixture-must-not-load>';

async function startFixture() {
    let hopConfig = {}, refusal;
    const edgeConfig = new Map();
    const mutations = [], errors = [];
    const assetDirectory = path.join(root, 'public/js/network/dist');
    // Offline fallback needs only the real Cytoscape renderer: every node has
    // stored coordinates, and the adapter fails if the fixture invokes layout.
    const cytoscape = process.env.PORTAL_EXIT_CYTOSCAPE_ESM;
    const dagreStub = '/fixture-layout-not-used.js';
    const shipped = process.env.PORTAL_EXIT_SHIPPED === '1';
    const compiled = shipped ? { outputFiles: [] } : require('esbuild').buildSync({ entryPoints: ['public/js/network/src/index.js'], absWorkingDir: root,
        outdir: assetDirectory, bundle: true, splitting: true, format: 'esm', write: false,
        external: ['d3-*', 'topojson-client', ...(cytoscape ? [dagreStub] : [])],
        ...(cytoscape ? { alias: { cytoscape, 'cytoscape-dagre': dagreStub } } : {}) });
    const assets = new Map(compiled.outputFiles.map(f => [f.path, f.contents]));
    const send = (res, body, type = 'application/json', status = 200) => {
        res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
        res.end(type === 'application/json' ? JSON.stringify(body) : body);
    };
    const server = http.createServer(async (req, res) => {
        try {
            const url = new URL(req.url, 'http://fixture.invalid'), route = url.pathname;
            const detailPath = `/api/cascade/links/${hop}`;
            if (req.method === 'GET' && route === '/panel/nodes') {
                const lang = url.searchParams.get('lang') || 'ru';
                const variant = url.searchParams.get('map') || 'modern';
                const page = await ejs.renderFile(path.join(root, 'views/nodes.ejs'), {
                    lang, t: key => t(key, lang), locales: getLocale(lang),
                    nodes: [], groups: [], linksCount: 0, loadBalancingEnabled: false,
                    useModernMap: variant === 'modern', nodesMapQuery: `map=${variant}`, c3Rebuild: variant === 'modern',
                    csrfToken: token,
                });
                res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
                return send(res, `<!doctype html><html lang="${lang}"><head><link rel="stylesheet" href="/css/style.min.css"></head><body>${page}</body></html>`, 'text/html; charset=utf-8');
            }
            if (req.method === 'GET' && route === '/api/cascade/topology') {
                const edges = structuredClone(orgEdges);
                Object.assign(edges[0].data, hopConfig);
                for (const { data } of edges) Object.assign(data, edgeConfig.get(data.linkId));
                return send(res, { nodes, edges });
            }
            if (req.method === 'GET' && route === detailPath) return send(res, {
                _id: hop, active: true, portalNode: portal, bridgeNode: relay, name: 'Portal hop', mode: 'forward',
                ...(Object.hasOwn(hopConfig, 'rebuildExit') && { rebuildExit: hopConfig.rebuildExit }),
            });
            if (req.method !== 'GET') {
                assert.equal(req.headers['x-csrf-token'], token);
                const raw = Buffer.concat(await arrayFrom(req)).toString();
                const body = JSON.parse(raw);
                mutations.push({ route, method: req.method, body });
                if ((route === detailPath && req.method === 'PUT') || (route === '/api/cascade/links' && req.method === 'POST')) {
                    if (refusal) return send(res, { error: refusal }, 'application/json', 409);
                    if (Object.hasOwn(body, 'rebuildExit')) {
                        hopConfig = { ...hopConfig, rebuildExit: body.rebuildExit, hasUnappliedChanges: true, status: 'pending' };
                    }
                    return send(res, { executionMode: 'rebuild', status: 'saved', desiredSaved: true, linkId: hop });
                }
                if (route === '/api/cascade/rebuild/preview') {
                    assert.deepEqual(body, { linkId: hop });
                    if (refusal) return send(res, { error: refusal }, 'application/json', 409);
                    return send(res, { allowed: true, previewId, nodes: [{ nodeId: portal, role: 'portal',
                        profiles: ['main', 'bridge'].map((profile, i) => ({ profile, change: i ? 'unchanged' : 'replace',
                            protectedChanged: false, sections: i ? [] : ['routing'] })),
                        portalExitChange: { before: { nodeId: shared, name: names[shared] }, after: { nodeId: selected, name: marker } },
                        portalExitRelayGeoChange: { before: true, after: false },
                        portalExitGeoChange: { before: [{ nodeId: geo, name: names[geo] }], after: [] },
                    }] });
                }
                assert.equal(route, `${detailPath}/deploy`);
                assert.deepEqual(body, { expectedPreview: previewId });
                hopConfig = { ...hopConfig, status: 'online', hasUnappliedChanges: false, appliedRebuildExit: hopConfig.rebuildExit };
                return send(res, { executionMode: 'rebuild', status: 'succeeded', allowed: true, previewId });
            }
            const file = path.resolve(root, 'public', `.${route}`);
            if (cytoscape && route === dagreStub) return send(res,
                `export default cy => cy('layout', 'dagre', function () { throw Error('Unexpected fixture layout'); });`, 'text/javascript');
            if (assets.has(file)) return send(res, assets.get(file), 'text/javascript');
            if ((shipped || !route.startsWith('/js/network/dist/')) && /^\/(?:css|js|vendor)\/[\w./-]+$/.test(route)
                && file.startsWith(`${root}/public/`) && fs.existsSync(file) && fs.statSync(file).isFile()) {
                const mime = { '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.json': 'application/json' };
                return send(res, fs.readFileSync(file), mime[path.extname(file)] || 'application/octet-stream');
            }
            if (route !== '/favicon.ico') errors.push(route);
            return send(res, '', 'text/plain', 404);
        } catch (err) {
            errors.push(String(err));
            return send(res, '', 'text/plain', 500);
        }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return { origin: `http://127.0.0.1:${server.address().port}`, mutations, errors,
        publish(config) { hopConfig = config; }, setRefusal(value) { refusal = value; },
        publishEdge(link, config) { edgeConfig.set(link, config); },
        async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}

async function arrayFrom(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return chunks;
}
const q = JSON.stringify;
const el = selector => `document.querySelector(${q(selector)})`;
const lane = `.nmc-lane[data-lane="${portal}"]`;
const exit = 'select[name="rebuildExitNodeId"]';
const geoCheck = 'input[name="relayGeo"]';
const form = '[data-nm-edit]';
const choice = (selector, value) => `${el(selector)}?.value === ${q(value)}`;
const text = selector => `${el(selector)}?.textContent.trim()`;
const card = (node, graph = false) => graph ? `.nmg-card[data-id="${node}"]` : `${lane} .nmc-card[data-node="${node}"]`;

test('portal exit choices, draft/Apply/readback and reactive routes (Firefox)', { timeout: 90000 }, async ctx => {
    assert.deepEqual(Object.keys(os.networkInterfaces()), ['lo'], 'run inside an isolated loopback-only namespace');
    const app = await startFixture();
    const browser = new Firefox();
    ctx.after(async () => { try { await browser.close(); } finally { await app.close(); } });
    await browser.start(process.env.TMPDIR || os.tmpdir());
    await browser.navigate(app.origin + '/panel/nodes?map=modern');
    await browser.wait(el(card(portal)));
    assert.ok(await browser.evaluate(`!${el(card(selected))} && !${el(card(shared))} && !${el(card(geo))}`));
    await browser.click('#btnAddLink');
    const create = '[data-nm-create]';
    await browser.wait(el(create));
    await browser.fill('select[name="portalNodeId"]', portal);
    await browser.fill('select[name="bridgeNodeId"]', relay);
    await browser.wait(`${el(exit)} && !${el(exit)}.disabled`, 2500);
    assert.deepEqual(await browser.evaluate(`Object.fromEntries(Array.from(${el(exit)}.options).slice(1).map(o => [o.value, o.textContent]))`),
        { [shared]: names[shared], [selected]: names[selected], [geo]: names[geo], [otherBridge]: names[otherBridge], [extra]: names[extra] });
    assert.equal(await browser.evaluate(`${el(exit)}.options.length`), 6, 'one option per terminal bridge, including geo targets');
    assert.match(await browser.evaluate(text(`${create} label:has(${exit})`)), /Выход этого портала/);
    assert.equal(await browser.evaluate(`${el(exit)}.options[0].textContent`), 'Общий выход релея (по умолчанию)');
    assert.equal(await browser.evaluate(`${el(geoCheck)}.disabled`), true);
    await browser.fill(exit, geo);
    assert.equal(await browser.evaluate(`${el(geoCheck)}.checked && !${el(geoCheck)}.disabled`), true);
    await browser.fill('select[name="bridgeNodeId"]', shared);
    assert.ok(await browser.evaluate(`!${el(exit)}.getClientRects().length`));
    await browser.fill('select[name="bridgeNodeId"]', relay);
    await browser.wait(choice(exit, ''));
    await browser.click(`${create} button[type=submit]`);
    await browser.wait(`${el('#rebuildPreview')}.open`);
    assert.equal(Object.hasOwn(app.mutations[0].body, 'rebuildExit'), false);
    assert.equal(Object.hasOwn(app.mutations[0].body, 'autoDeploy'), false);
    await browser.click('#rebuildPreviewCancel');
    await browser.wait(`!${el(create)}`);
    const lanePill = `${lane} .nm-pill[data-link="${id(hop)}"]`;
    async function openEdit() {
        const editButton = '.nm-insp .nm-edit-btn';
        if (!await browser.evaluate(el(editButton))) await browser.click(lanePill);
        await browser.click(editButton);
        await browser.wait(el(form));
    }
    await openEdit();
    await browser.fill(exit, selected);
    await browser.click(geoCheck);
    await browser.click(`${form} button[type=submit]`);
    await browser.wait(`${el('#rebuildPreview')}.open`);
    assert.deepEqual(app.mutations[2].body, { rebuildExit: setting(selected, false) });
    assert.equal(app.mutations.length, 4, 'no Apply before preview confirmation');
    assert.match(await browser.evaluate(text('#rebuildPreviewDetails')), /Shared S → <img src=\/fixture-must-not-load>/);
    assert.match(await browser.evaluate(text('#rebuildPreviewDetails')), /Ру-трафик больше не пойдёт через шлюз релея/);
    assert.match(await browser.evaluate(text('#rebuildPreviewDetails')), /Геомаршруты: Geo G → —/);
    assert.equal(await browser.evaluate(`Boolean(${el('#rebuildPreviewDetails img')})`), false);
    await browser.click('#rebuildPreviewCancel');
    await browser.wait(`!${el(form)}`);
    await browser.wait(`!${el(card(selected))} && !${el(card(shared))} && !${el(card(geo))}`);
    await browser.click('.nm-insp .nm-insp-head button');
    await browser.click(card(portal));
    await browser.wait(`${text('.nm-insp')}.includes('Chosen C')`);
    assert.match(await browser.evaluate(text('.nm-insp')), /Черновик/);
    assert.doesNotMatch(await browser.evaluate(text('.nm-insp .nm-chain-list')), /Chosen/);

    // An applied value outranks the draft (including a known shared exit).
    app.publish({ status: 'pending', hasUnappliedChanges: true, rebuildExit: setting(selected, false), appliedRebuildExit: null });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${el(card(shared))} && ${el(card(geo))} && !${el(card(selected))}`);
    await browser.click('.nm-insp .nm-insp-head button');
    await openEdit();
    await browser.wait(choice(exit, selected));
    await browser.fill(exit, '');
    await browser.click(`${form} button[type=submit]`);
    await browser.wait(`${el('#rebuildPreview')}.open`);
    assert.deepEqual(app.mutations[4].body, { rebuildExit: setting(null) });
    await browser.click('#rebuildPreviewApply');
    await browser.wait(`!${el(form)} && ${text('.nm-insp')}.includes(${q(names[relay])})`);
    assert.deepEqual(app.mutations[6].body, { expectedPreview: previewId });

    // No layout changes: the same graph selection must re-scope on data alone.
    await browser.click('.nm-insp .nm-insp-head button');
    await browser.click('[data-nm-view="graph"]');
    await browser.wait(el(card(portal, true)));
    const [x, y] = await browser.evaluate(`(() => { const r = ${el(card(portal, true))}.getBoundingClientRect();
        return [r.x + r.width / 2, r.y + r.height / 2]; })()`);
    await browser.pointer(x, y);
    await browser.wait(`${el(card(portal, true))}.classList.contains('sel')`);
    const faded = node => `${el(card(node, true))}?.classList.contains('faded')`;
    await browser.wait(`${faded(selected)} && !${faded(shared)} && !${faded(geo)}`);
    app.publishEdge(selectedEdge, { priority: 5 });
    app.publishEdge(geoEdge, { geoRouting: { enabled: false } });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`!${faded(selected)} && ${faded(shared)} && ${faded(geo)}`);
    app.publishEdge(geoEdge, { geoRouting: null }); // The old server omitted the routing projection.
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${faded(selected)} && ${faded(shared)} && ${faded(geo)}`);
    app.publishEdge(selectedEdge, {});
    app.publishEdge(geoEdge, {});
    // The best outlet can be a geo link even when the inherited geo policy is off.
    app.publishEdge(parallelEdge, { geoRouting: { enabled: true } });
    app.publish({ rebuildExit: setting(selected, false), appliedRebuildExit: setting(selected, false) });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`!${faded(selected)} && ${faded(shared)} && ${faded(geo)}`);
    const highlighted = edgeId => `${el(`.nmg-pills .nm-pill[data-link="${id(edgeId)}"]`)}?.classList.contains('hl')`;
    await browser.wait(`${highlighted(parallelEdge)} && !${highlighted(selectedEdge)}`);
    const unknown = `${text('.nm-insp')}.includes(${q(t('network.map.portalExit.unknown', 'ru'))})`;
    app.publishEdge(parallelEdge, { geoRouting: { enabled: true }, hasUnappliedChanges: true });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${unknown} && !${highlighted(parallelEdge)} && !${highlighted(selectedEdge)}`);
    app.publishEdge(parallelEdge, { geoRouting: { enabled: true } });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${highlighted(parallelEdge)} && !${highlighted(selectedEdge)}`);
    app.publishEdge(parallelEdge, { geoRouting: { enabled: true }, priority: 20 });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${unknown} && !${highlighted(parallelEdge)} && !${highlighted(selectedEdge)}`);
    app.publishEdge(parallelEdge, { geoRouting: { enabled: true } });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${highlighted(parallelEdge)} && !${highlighted(selectedEdge)}`);
    await browser.click('[data-nm-view="chains"]');
    const exitPill = edgeId => `${lane} .nm-pill[data-link="${id(edgeId)}"]`;
    await browser.wait(`${el(exitPill(parallelEdge))} && !${el(exitPill(selectedEdge))}`);
    app.publishEdge(parallelEdge, { canEdit: false, applicationState: 'deleting' });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${el(exitPill(selectedEdge))} && !${el(exitPill(parallelEdge))}`);
    await browser.click('.nm-insp .nm-insp-head button');
    await openEdit();
    await browser.wait(choice(exit, selected));
    await browser.click(`${form} button[type=submit]`);
    await browser.wait(`${text(`${form} [role="alert"]`)} === ${q(t('network.map.edit.noChanges', 'ru'))}`);
    assert.equal(app.mutations.length, 7, 'deleting a sibling link does not rewrite the selected node');
    await browser.click(`${form} .nm-insp-head button`);
    await browser.click(card(portal));
    await browser.click('[data-nm-view="graph"]');
    await browser.wait(`${highlighted(selectedEdge)} && !${highlighted(parallelEdge)}`);
    // An ID that is a real outgoing link is not a node selector.
    app.publish({ rebuildExit: setting(selectedEdge, false), appliedRebuildExit: setting(selectedEdge, false) });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${faded(selected)} && ${faded(shared)} && ${faded(geo)}`);
    assert.match(await browser.evaluate(text('.nm-insp')), /недоступен/i);
    // A draft, even on an online ingress, is not evidence of the applied route.
    app.publish({ rebuildExit: setting(geo, false) });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(unknown);
    assert.ok(await browser.evaluate(`${faded(selected)} && ${faded(shared)} && ${faded(geo)}`));
    // Reject old link-ID DTOs rather than interpreting them as shared policy.
    app.publish({ rebuildExit: setting(selected, false), appliedRebuildExit: { linkId: defaultEdge, relayGeo: false } });
    await browser.click('#btnNetworkRefresh');
    await browser.wait(`${text('.nm-insp')}.includes('Chosen C') && ${unknown}`);
    assert.ok(await browser.evaluate(`${faded(selected)} && ${faded(shared)} && ${faded(geo)}`));
    assert.deepEqual(app.errors, []);
});

test('localized portal exit refusals block Preview/Apply and keep the editor (Firefox)', { timeout: 90000 }, async ctx => {
    assert.deepEqual(Object.keys(os.networkInterfaces()), ['lo'], 'run inside an isolated loopback-only namespace');
    const app = await startFixture();
    const browser = new Firefox();
    ctx.after(async () => { try { await browser.close(); } finally { await app.close(); } });
    await browser.start(process.env.TMPDIR || os.tmpdir());
    const cases = [
        { lang: 'ru', error: { code: 'REBUILD_PORTAL_EXIT_INVALID' }, key: 'badExit' },
        { lang: 'ru', error: { code: 'REBUILD_PORTAL_EXIT_AMBIGUOUS' }, key: 'ambiguous' },
        { lang: 'en', error: { code: 'REBUILD_PORTAL_EXIT_UNSUPPORTED' }, key: 'unsupported' },
        { lang: 'zh-CN', error: { code: 'REBUILD_EXIT_IN_USE', portalNames: ['Portal P', 'Peer Q', 'Bad\nName', 'b'.repeat(24)] },
            key: 'inUseNamed', names: 'Portal P, Peer Q' },
    ];
    for (const { lang, error, key, names } of cases) {
        app.setRefusal({ ...error, message: 'Raw message must not appear' });
        await browser.navigate(app.origin + `/panel/nodes?map=modern&lang=${lang}`);
        const lanePill = `${lane} .nm-pill[data-link="${id(hop)}"]`;
        await browser.wait(el(lanePill));
        await browser.click(lanePill);
        await browser.click('.nm-insp .nm-edit-btn');
        await browser.wait(el(form));
        await browser.fill(exit, geo);
        await browser.click(`${form} button[type=submit]`);
        await browser.wait(`${el('#rebuildPreview')}.open`);
        assert.equal(await browser.evaluate(text('#rebuildPreviewWarning')),
            t(`network.map.portalExit.${key}`, lang).replace('{names}', names || ''));
        assert.equal(await browser.evaluate(`${el('#rebuildPreviewApply')}.hidden`), true);
        await browser.click('#rebuildPreviewCancel');
        await browser.wait(`${el(form)} && !${el(`${form} button[type=submit]`)}.disabled`);
        await browser.wait(choice(exit, geo));
    }
    const create = '[data-nm-create]';
    app.setRefusal(null);
    await browser.click(`${form} .nm-insp-head button`);
    await browser.click('#btnAddLink');
    await browser.wait(el(create));
    await browser.fill('select[name="portalNodeId"]', portal);
    await browser.fill('select[name="bridgeNodeId"]', relay);
    await browser.fill(exit, geo);
    await browser.click(`${create} button[type=submit]`);
    await browser.wait(`${el('#rebuildPreview')}.open`);
    assert.deepEqual(app.mutations.map(({ method, route }) => [method, route]), [
        ...cases.map(() => ['PUT', `/api/cascade/links/${hop}`]),
        ['POST', '/api/cascade/links'], ['POST', '/api/cascade/rebuild/preview'],
    ]);
    assert.deepEqual(app.mutations[cases.length].body.rebuildExit, setting(geo));
    assert.equal(Object.hasOwn(app.mutations[cases.length].body, 'autoDeploy'), false);
    await browser.click('#rebuildPreviewCancel');
    await browser.wait(`!${el(create)}`);
    assert.deepEqual(app.errors, []);
});
