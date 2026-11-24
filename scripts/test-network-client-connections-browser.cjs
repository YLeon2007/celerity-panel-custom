'use strict';

// Run with Node 22, installed EJS and Firefox ESR in a private loopback-only netns:
//   node --test scripts/test-network-client-connections-browser.cjs
// Real nodes.ejs/CSS/dist and native input; fixture HTTP only, no panel/DB/agent.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { createHash } = require('node:crypto');
const { test } = require('node:test');
const ejs = require('ejs');
const { t, getLocale } = require('../src/middleware/i18n');
const { Firefox, sleep } = require('./anyorder-browser-acceptance/firefox.cjs');

const root = path.resolve(__dirname, '..');
const ids = Object.fromEntries(['portal', 'relay', 'bridge', 'standalone'].map((role, i) => [role, String(i + 1).repeat(24)]));
const topology = {
    nodes: Object.entries(ids).map(([cascadeRole, id], i) => ({
        data: { id, cascadeRole, type: 'xray', label: cascadeRole, status: 'online', ip: `192.0.2.${i + 1}`, onlineUsers: [7, 8, 9, 0][i] },
        position: [{ x: 250, y: 150 }, { x: 650, y: 150 }, { x: 650, y: 450 }, { x: 250, y: 450 }][i],
    })),
    edges: ['relay', 'bridge'].map((role, i) => ({ data: {
        id: `link-${String(i + 5).repeat(24)}`, source: i ? ids.relay : ids.portal, target: ids[role], mode: 'forward', status: 'online',
    } })),
};
const marker = '<img src="/should-never-load" onerror="window.fixtureInjected=1">';
const record = { username: marker, ip: '198.51.100.4', country: 'XX', region: 'fixture-region', city: 'fixture-city', asn: 64500, isp: 'fixture-isp', lastSeen: '2026-01-01T12:00:00Z' };
const records = [record];
const clientPath = '/api/cascade/topology/clients';
const panel = '.nm-client-popover';
const chainCount = `.nmc-lane[data-lane="${ids.portal}"] .nmc-clients b`;
const standaloneCount = `.nmc-solo[data-node="${ids.standalone}"] .row2 .nm-client-count`;
const graphCount = role => `.nmg-card[data-id="${ids[role]}"] .users`;
const inspectorCount = '.nm-insp .nm-kpis .nm-kpi:first-child .v';
const sha16 = file => createHash('sha256').update(fs.readFileSync(path.join(root, 'public', file))).digest('hex').slice(0, 16);

// A completed HTTP response whose JSON promise ignores abort, to prove that
// UI invalidation is separate from the browser's actual network cancellation.
const raceScript = `{
    const realFetch = window.fetch;
    window.fixtureAllowBody = null;
    window.fixtureRaceReleased = false;
    window.fixtureAbortCount = 0;
    window.fetch = async (url, opts) => {
        const clients = String(url).startsWith(${JSON.stringify(clientPath + '?')});
        if (clients) opts.signal.addEventListener('abort', () => window.fixtureAbortCount++, { once: true });
        const res = await realFetch(url, opts);
        if (!clients || !res.headers.has('x-fixture-hold-body')) return res;
        const rows = await res.json();
        res.json = () => new Promise(resolve => { window.fixtureAllowBody = () => {
            window.fixtureRaceReleased = true;
            window.fixtureAllowBody = null;
            resolve(rows);
        }; });
        return res;
    };
}`;

async function startFixture() {
    let responseMode = 'ready';
    let live = null;
    const clientReads = [], topologyReads = [], unexpected = [], held = new Set();
    const send = (res, type, body, status = 200, headers = {}) => {
        res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...headers });
        res.end(body);
    };
    const json = (res, body, status, headers) => send(res, 'application/json', JSON.stringify(body), status, headers);
    const server = http.createServer(async (req, res) => {
        try {
            const url = new URL(req.url, 'http://fixture.invalid');
            const route = url.pathname;
            if (req.method !== 'GET') { unexpected.push(req.method); return json(res, [], 405); }
            if (route === '/panel/nodes') {
                const lang = url.searchParams.get('lang') === 'ru' ? 'ru' : 'en';
                const variant = url.searchParams.get('map') === 'classic' ? 'classic' : 'modern';
                const view = await ejs.renderFile(path.join(root, 'views/nodes.ejs'), {
                    lang, t: key => t(key, lang), locales: getLocale(lang),
                    nodes: [], groups: [], linksCount: 0, loadBalancingEnabled: false,
                    useModernMap: variant === 'modern', nodesMapQuery: `map=${variant}`, c3Rebuild: true,
                    csrfToken: url.searchParams.has('readOnly') ? '' : 'A'.repeat(43),
                });
                return send(res, 'text/html; charset=utf-8', `<!doctype html><html lang="${lang}"><head>
                    <link rel="stylesheet" href="/css/style.min.css"><script src="/fixture-race.js"></script>
                    </head><body>${view}</body></html>`, 200, {
                    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
                });
            }
            if (route === '/fixture-race.js') return send(res, 'text/javascript', raceScript);
            if (route === '/api/cascade/topology') {
                topologyReads.push(Date.now());
                if (!live) return json(res, topology);
                const snapshot = structuredClone(topology);
                snapshot.nodes[0].data.onlineUsers = live.count;
                snapshot.edges[0].data.latencyMs = topologyReads.length;
                return json(res, snapshot);
            }
            if (route === clientPath) {
                const id = url.searchParams.get('nodeId');
                assert.deepEqual([...url.searchParams.keys()], ['nodeId']);
                assert.equal(req.headers.accept, 'application/json');
                assert.equal(req.headers['sec-fetch-site'], 'same-origin');
                assert.equal(req.headers['cache-control'], 'no-cache');
                const seen = { id, closedBeforeReply: false };
                clientReads.push(seen);
                if (responseMode === 'pending') {
                    held.add(res);
                    res.on('close', () => { seen.closedBeforeReply = !res.writableEnded; held.delete(res); });
                    return;
                }
                if (responseMode === 'error') return json(res, [], 500);
                if (responseMode === 'forbidden') return json(res, records, 403, { 'x-client-connections-state': 'ready' });
                if (responseMode === 'race') return json(res, records, 200, { 'x-client-connections-state': 'ready', 'x-fixture-hold-body': 'true' });
                const state = responseMode === 'empty' ? 'ready' : responseMode;
                return json(res, responseMode === 'ready' ? live?.rows ?? records : [], 200, { 'x-client-connections-state': state });
            }
            if (route === '/favicon.ico') return send(res, 'text/plain', '', 404);
            if (/^\/(?:css|js|vendor)\/[\w./-]+$/.test(route)) {
                const file = path.resolve(root, 'public', `.${route}`);
                if (file.startsWith(`${root}/public/`) && fs.existsSync(file) && fs.statSync(file).isFile()) {
                    const mime = { '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.json': 'application/json' };
                    return send(res, mime[path.extname(file)] ?? 'application/octet-stream', fs.readFileSync(file));
                }
            }
            unexpected.push(route);
            return send(res, 'text/plain', '', 404);
        } catch (err) {
            unexpected.push(String(err));
            return send(res, 'text/plain', String(err), 500);
        }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return {
        origin: `http://127.0.0.1:${server.address().port}`, clientReads, topologyReads, unexpected,
        publish(snapshot) { live = snapshot; },
        use(mode) { responseMode = mode; },
        async close() {
            for (const res of held) res.destroy();
            server.closeAllConnections();
            await new Promise(resolve => server.close(resolve));
        },
    };
}

async function move(browser, x, y) {
    return browser.send('input.performActions', { context: browser.context, actions: [{
        type: 'pointer', id: 'mouse', parameters: { pointerType: 'mouse' }, actions: [{
            type: 'pointerMove', x, y, duration: 0, origin: 'viewport',
        }],
    }] });
}

const q = JSON.stringify;
const elem = s => `document.querySelector(${q(s)})`;
const hidden = `!${elem(panel)}`;
const hitPoint = selector => `(() => {
        const el = ${elem(selector)};
        if (!el) return null;
        const box = el.getBoundingClientRect();
        const x = Math.round(box.x + box.width / 2), y = Math.round(box.y + box.height / 2);
        const hit = document.elementFromPoint(x, y);
        return { x, y, hit: el === hit || el.contains(hit) };
    })()`;
async function hover(browser, selector) {
    // Inspector slides in; wait for the genuine hit target, not merely its text.
    await browser.wait(`${hitPoint(selector)}?.hit`, 3500);
    const point = await browser.evaluate(hitPoint(selector));
    assert.ok(point?.hit, `native pointer could not hit ${selector}: ${JSON.stringify(point)}`);
    await move(browser, point.x, point.y);
}

async function waitFor(read, message) {
    for (let i = 0; i < 80; i++) {
        if (read()) return;
        await sleep(50);
    }
    assert.fail(message);
}

test('client connections in shipped modern map (Firefox)', { timeout: 130000 }, async ctx => {
    assert.deepEqual(Object.keys(os.networkInterfaces()), ['lo'], 'run in an isolated loopback-only network namespace');
    const app = await startFixture();
    const browser = new Firefox();
    const remoteRequests = [];
    const requested = (...roles) => assert.deepEqual(app.clientReads.map(r => r.id), roles.map(role => ids[role]));
    const textIs = (s, text) => browser.wait(`${elem(s)}?.textContent.trim() === ${q(text)}`, 3500);
    const next = () => browser.keys(['\uE004']);
    async function tabTo(selector) {
        for (let i = 0; i < 60; i++) {
            if (await browser.evaluate(`document.activeElement === ${elem(selector)}`)) return;
            await next();
        }
        assert.fail(`native Tab could not reach ${selector}`);
    }
    async function open(pathname) {
        await move(browser, 1, 1);
        await browser.navigate(app.origin + pathname);
    }
    try {
        await browser.start(process.env.TMPDIR || os.tmpdir());
        await browser.send('session.subscribe', { events: ['network.beforeRequestSent'] });
        await ctx.test('RU Chains: on-demand rows, immediate count, escaping, clickable attribution', async () => {
            await open('/panel/nodes?map=modern&lang=ru');
            await browser.wait(`${elem(chainCount)}`);
            requested();
            assert.equal(await browser.evaluate(`${elem(chainCount)}.classList.contains('nm-client-count')`), true, 'admin count exposes client connections');
            const revisions = await browser.evaluate(`[
                new URL(document.querySelector('script[src*="/network/dist/"]').src).searchParams.get('v'),
                new URL(document.querySelector('link[href*="network-map.css"]').href).searchParams.get('v')
            ]`);
            assert.deepEqual(revisions, [sha16('js/network/dist/index.js'), sha16('css/network-map.css')]);
            await textIs(chainCount, '7');
            await hover(browser, chainCount);
            await textIs(`${panel} th`, 'Пользователь');
            await textIs(`${panel} th:last-child`, 'Последнее подключение');
            assert.deepEqual(await browser.evaluate(`Array.from(document.querySelectorAll(${q(`${panel} td`)}), e => e.textContent)`), Object.values(record).map(String));
            assert.equal(await browser.evaluate(`Boolean(${elem(`${panel} img`)}) || Boolean(window.fixtureInjected)`), false);
            await textIs(chainCount, '1');
            await textIs(`${panel} footer a`, 'IP Geolocation by DB-IP');
            assert.equal(await browser.evaluate(`${elem(`${panel} footer a`)}.rel`), 'noopener noreferrer');
            // Exercise server overwrite and a Chains redraw without moving the pointer.
            await browser.evaluate(`window.firstClientPanel = ${elem(panel)}`);
            await browser.evaluate(`${elem('#btnNetworkRefresh')}.click()`);
            await textIs(chainCount, '7');
            assert.equal(await browser.evaluate(`${elem(panel)} === window.firstClientPanel`), true);
            await hover(browser, `${panel} footer a`);
            await textIs(`${panel} footer a`, 'IP Geolocation by DB-IP');
            await move(browser, 1, 1);
            await browser.wait(hidden);
            requested('portal');
        });
        await ctx.test('Old agent, no-data, unavailable and HTTP error leave count alone; ready empty is distinct', async () => {
            const priorCount = await browser.evaluate(`${elem(chainCount)}.textContent.trim()`);
            const expected = {
                'old-agent': 'Нет данных о подключениях (нужен агент 1.6.0)',
                'no-data': 'Нет подключений или учёт на ноде не включён',
                empty: 'Нет активных подключений', unavailable: 'Данные о подключениях недоступны',
                error: 'Данные о подключениях недоступны',
            };
            await textIs(standaloneCount, '0');
            for (const [mode, text] of Object.entries(expected)) {
                app.use(mode);
                await hover(browser, mode === 'empty' ? standaloneCount : chainCount);
                await textIs(`${panel} [role="status"]`, text);
                if (mode !== 'empty') await textIs(chainCount, priorCount);
                await move(browser, 1, 1);
                await browser.wait(hidden);
            }
            app.use('forbidden');
            await hover(browser, chainCount);
            await waitFor(() => app.clientReads.length === Object.keys(expected).length + 2, 'HTTP 403 request not observed');
            await browser.wait(hidden);
            assert.equal(await browser.evaluate(`document.body.textContent.includes(${q(marker)})`), false);
            requested('portal', ...Object.keys(expected).map(mode => mode === 'empty' ? 'standalone' : 'portal'), 'portal');
        });
        await ctx.test('Pointer leave aborts the real outstanding GET; does not leave records or DOM', async () => {
            const prior = app.clientReads.length;
            app.use('pending');
            await move(browser, 1, 1);
            await hover(browser, chainCount);
            await waitFor(() => app.clientReads.length === prior + 1, 'hover request not received');
            await textIs(`${panel} [role="status"]`, 'Загрузка подключений…');
            await move(browser, 1, 1);
            await browser.wait(hidden);
            await waitFor(() => app.clientReads[prior].closedBeforeReply, 'outstanding HTTP request was not canceled');
        });
        await ctx.test('Graph switch invalidates a pending body; Graph and inspector exclude bridge and relay', async () => {
            const prior = app.clientReads.length;
            app.use('race');
            await hover(browser, chainCount);
            await browser.wait('Boolean(window.fixtureAllowBody)');
            const aborts = await browser.evaluate('window.fixtureAbortCount');
            // Keep the pointer at the old count: the switch must invalidate the read itself.
            await browser.evaluate(`${elem('[data-nm-view="graph"]')}.click()`);
            await browser.wait(`${elem(graphCount('portal'))} && ${elem('.nmg-cy canvas')}`);
            assert.equal(await browser.evaluate('window.fixtureAbortCount'), aborts + 1);
            await browser.evaluate(`(() => { window.fixtureStaleRendered = false;
                new MutationObserver(changes => { for (const change of changes) {
                    if ([...change.addedNodes].some(n => n.textContent?.includes(${q(marker)}))) window.fixtureStaleRendered = true;
                } }).observe(document.body, { childList: true, subtree: true }); })()`);
            await browser.evaluate('window.fixtureAllowBody()');
            await browser.wait('window.fixtureRaceReleased');
            await browser.wait(hidden);
            assert.equal(await browser.evaluate(`document.body.textContent.includes(${q(marker)})`), false);
            assert.equal(await browser.evaluate('window.fixtureStaleRendered'), false);
            app.use('ready');
            for (const role of ['bridge', 'relay']) {
                assert.equal(await browser.evaluate(`${elem(graphCount(role))}.classList.contains('nm-client-count')`), false);
                const label = `.nmg-card[data-id="${ids[role]}"] .nm`;
                // The canvas remains the pointer target outside admin count hotspots.
                const { x, y } = await browser.evaluate(`(() => { const r = ${elem(label)}.getBoundingClientRect(); return { x: Math.round(r.left + 5), y: Math.round(r.top + 5) }; })()`);
                await browser.pointer(x, y);
                await textIs('.nm-insp h3', role);
                await hover(browser, inspectorCount);
                await browser.wait(hidden);
            }
            assert.equal(app.clientReads.length, prior + 1);
            await browser.click('.nm-insp-head button');
            await hover(browser, graphCount('portal'));
            await textIs(`${panel} th`, 'Пользователь');
            await move(browser, 1, 1);
            await browser.wait(hidden);
            assert.equal(app.clientReads.at(-1).id, ids.portal);
        });
        await ctx.test('EN inspector keyboard focus; Escape clears; editor remains usable', async () => {
            const before = app.clientReads.length;
            app.use('empty');
            await open('/panel/nodes?map=modern&lang=en');
            await browser.wait(`${elem(chainCount)}`);
            await browser.click(`.nmc-card[data-node="${ids.portal}"] .row1`);
            await textIs('.nm-insp h3', 'portal');
            await browser.wait(`${hitPoint(`${inspectorCount} .nm-client-count`)}?.hit`, 3500);
            await tabTo(`${inspectorCount} .nm-client-count`);
            // In headless Firefox without a window manager, native Tab changes
            // activeElement but Gecko suppresses focus events on inactive windows.
            // Dispatch only the missing event on the actual Tab target in that case.
            const inactiveWindow = await browser.evaluate('!document.hasFocus()');
            if (inactiveWindow) await browser.evaluate("document.activeElement.dispatchEvent(new FocusEvent('focusin', { bubbles: true }))");
            await textIs(`${panel} [role="status"]`, 'No active connections');
            await textIs(inspectorCount, '0');
            await textIs(chainCount, '0');
            assert.equal(await browser.evaluate(`document.activeElement === ${elem(`${inspectorCount} .nm-client-count`)}`), true);
            await next();
            assert.equal(await browser.evaluate(`document.activeElement === ${elem(`${panel} footer a`)}`), true);
            await browser.keys(['\uE00C']);
            await browser.wait(hidden);
            assert.equal(await browser.evaluate(`Boolean(${elem('.nm-insp.open')})`), true);
            await browser.click('#btnAddLink');
            await browser.wait(`${elem('.nm-insp select')}`);
            await browser.click('.nm-insp-foot button.ghost');
            await browser.wait(`!${elem('.nm-insp select')}`);
            assert.ok(app.clientReads.length > before);
            ctx.diagnostic(inactiveWindow ? 'Native Tab; focusin dispatched on the real activeElement (inactive headless window)' : 'Native Tab and focusin');
        });
        await ctx.test('Read-only and Classic do not expose or request client records', async () => {
            const count = app.clientReads.length;
            await open('/panel/nodes?map=modern&readOnly');
            await browser.wait(`${elem(chainCount)}`);
            await hover(browser, chainCount);
            await browser.wait(hidden);
            assert.equal(await browser.evaluate(`document.querySelectorAll('.nm-client-count').length`), 0);
            await open('/panel/nodes?map=classic');
            await browser.wait(`${elem('script[src*="/js/network.js"]')}`);
            assert.equal(await browser.evaluate(`Boolean(${elem('#networkRoot[data-client-connections]')})`), false);
            assert.equal(app.clientReads.length, count);
        });
        await ctx.test('35 s native Graph hover: three topology polls, two list refreshes, same panel and viewport', async () => {
            const many = [record, { ...record, ip: '198.51.100.5' }, { ...record, username: 'fixture-two' }];
            const expanded = [...many, { ...record, username: 'fixture-three' }];
            app.use('ready');
            app.publish({ count: 7, rows: many });
            await open('/panel/nodes?map=modern&lang=ru');
            await browser.wait(`${elem(chainCount)}`);
            await browser.click('[data-nm-view="graph"]');
            await browser.wait(`${elem(graphCount('portal'))}`);
            const geometry = `(() => {
                const cy = ${elem('.nmg-cy')}._cyreg.cy;
                return { pan: cy.pan(), zoom: cy.zoom(), positions: cy.nodes().map(n => [n.id(), n.position()]) };
            })()`;
            const initial = await browser.evaluate(geometry);
            await browser.click('.nm-zoom button:first-child');
            await browser.wait(`${geometry}.zoom > ${initial.zoom} * 1.24`);
            await sleep(300);
            await hover(browser, graphCount('portal'));
            const started = Date.now();
            const polls = app.topologyReads.length;
            const reads = app.clientReads.length;
            const tableSize = n => browser.wait(`document.querySelectorAll(${q(`${panel} tbody tr`)}).length === ${n}`, 3500);
            const counts = async (n, rows) => { await textIs(graphCount('portal'), String(n)); await tableSize(rows); };
            const transforms = `Array.from(document.querySelectorAll('.nmg-card'), el => [el.dataset.id, el.style.transform])`;
            await counts(2, 3); // Two unique users, not three IP rows or server's old seven.
            const viewport = await browser.evaluate(transforms);
            const panZoom = await browser.evaluate(geometry);
            assert.notEqual(panZoom.zoom, initial.zoom);
            await browser.evaluate(`(() => {
                const panel = ${elem(panel)};
                window.fixturePanelRemoved = false;
                new MutationObserver(changes => {
                    if (changes.some(change => [...change.removedNodes].includes(panel))) window.fixturePanelRemoved = true;
                }).observe(document.body, { childList: true });
                window.fixturePanel = panel;
            })()`);
            const samePanel = async () => {
                assert.equal(await browser.evaluate(`${elem(panel)} === window.fixturePanel && !window.fixturePanelRemoved`), true);
                assert.deepEqual(await browser.evaluate(transforms), viewport);
                assert.deepEqual(await browser.evaluate(geometry), panZoom);
            };
            app.publish({ count: 2, rows: expanded });
            await browser.wait(`document.querySelectorAll(${q(`${panel} tbody tr`)}).length === 4`, 18000);
            await counts(3, 4);
            await samePanel();
            app.publish({ count: 0, rows: [] });
            await browser.wait(`${elem(`${panel} [role="status"]`)}?.textContent === 'Нет активных подключений'`, 18000);
            await counts(0, 0);
            await sleep(Math.max(0, 35000 - (Date.now() - started)));
            await counts(0, 0);
            await samePanel();
            assert.equal(app.topologyReads.length - polls, 3, 'expected three real 10 s topology polls');
            assert.equal(app.clientReads.length - reads, 2, 'expected two real 15 s client polls');
            await move(browser, 1, 1);
            await browser.wait(hidden);

        });
        await ctx.test('Hidden Firefox tab: no topology or client GET; visible again refreshes', async () => {
            app.publish({ count: 1, rows: records });
            await open('/panel/nodes?map=modern&lang=ru');
            await hover(browser, chainCount);
            await textIs(`${panel} th`, 'Пользователь');
            const primary = browser.context;
            const tab = await browser.send('browsingContext.create', { type: 'tab', background: true });
            try {
                await browser.send('browsingContext.activate', { context: tab.context });
                await browser.wait('document.hidden');
                await browser.wait(hidden);
                const polls = app.topologyReads.length, reads = app.clientReads.length;
                await sleep(16000);
                assert.equal(app.topologyReads.length, polls);
                assert.equal(app.clientReads.length, reads);
                await browser.send('browsingContext.activate', { context: primary });
                await browser.wait('!document.hidden');
                await waitFor(() => app.topologyReads.length > polls, 'visible map did not resume');
            } finally {
                await browser.send('browsingContext.close', { context: tab.context });
            }
        });
        for (const msg of browser.events.filter(e => e.method === 'network.beforeRequestSent')) {
            const url = msg.params.request.url;
            if (!url.startsWith(app.origin + '/') && !url.startsWith('data:')) remoteRequests.push(url);
        }
        assert.ok(!remoteRequests.some(url => /db-ip|should-never-load/i.test(url)), 'no automatic attribution or injected request');
        assert.deepEqual(app.unexpected, []);
    } finally {
        await browser.close();
        await app.close();
    }
});
