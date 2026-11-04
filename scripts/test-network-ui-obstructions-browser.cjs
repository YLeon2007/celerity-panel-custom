'use strict';

// Integration-owner-only native regression. Rebuild assets first, then run in
// the sole bounded heavy scope with the same sanitized fixture env as wave 8.
// Reuses frozen helpers read-only; never writes inside browser-assets-wave8.
// Usage: node scripts/test-network-ui-obstructions-browser.cjs /absolute/FRESH-OUTPUT
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
// The current wrapper supplies native form fills; the frozen base driver's
// historical fill() is a synthetic DOM setter and cannot close this gate.
const { Firefox, sleep } = require('./anyorder-browser-acceptance/firefox.cjs');

const root = path.resolve(__dirname, '..');
const CY = "document.getElementById('cy')._cyreg.cy";
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

async function main() {
    const out = process.argv[2];
    assert.ok(out && path.isAbsolute(out), 'supply a new absolute evidence directory');
    assert.ok(!path.resolve(out).startsWith(path.join(root, 'browser-assets-wave8') + path.sep),
        'wave 8 evidence is frozen');
    fs.mkdirSync(out); // exclusive: do not overwrite an earlier attempt
    const evidence = {
        scope: 'Native Firefox pointers, actual templates/built assets and loopback app; modeled DB/node execution. No remote services.',
        cases: [],
    };
    let app, browser;
    async function check(name, work) {
        try {
            const detail = await work();
            evidence.cases.push({ name, status: 'PASS', detail });
        } catch (error) {
            evidence.cases.push({ name, status: 'FAIL', error: error.stack });
            throw error;
        }
    }
    async function graph() {
        return browser.evaluate(`(()=>{const c=${CY};return {nodes:c.nodes().map(n=>({id:n.id(),position:n.position()})),pan:c.pan(),zoom:c.zoom()};})()`);
    }
    async function nativeClick(selector) {
        // Native select focus can scroll the tall form. Bring the actual
        // control into view before the mandatory hit test (as the driver does).
        await browser.evaluate(`(()=>{document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'center',behavior:'instant'});return true;})()`);
        await sleep(150);
        const hit = await browser.evaluate(`(()=>{
            const e=document.querySelector(${JSON.stringify(selector)});
            if(!e)throw Error('Missing control');
            const r=e.getBoundingClientRect(),x=Math.round(r.x+r.width/2),y=Math.round(r.y+r.height/2);
            const top=document.elementFromPoint(x,y);
            return {x,y,width:r.width,height:r.height,disabled:!!e.disabled,
                hit:!!top&&(top===e||e.contains(top)),topId:top?.id,topTag:top?.tagName};
        })()`);
        assert.ok(hit.hit && !hit.disabled && hit.width > 0 && hit.height > 0,
            'native center hit must reach ' + selector + ': ' + JSON.stringify(hit));
        // Native input.performActions via the frozen driver, never DOM .click(),
        // direct handler invocation, force click, backdrop fallback or CSS patch.
        await browser.click(selector);
        return hit;
    }
    function assertNoEdgehandles() {
        const logs = browser.events.filter(e => e.method === 'log.entryAdded');
        assert.ok(!logs.some(e => /edgehandles|memoize/i.test(JSON.stringify(e.params))),
            'the unused extension/lodash exception must not occur');
    }
    try {
        assert.equal(process.env.NODE_ENV, 'test', 'use the sanitized synthetic fixture environment');
        const cgroup = fs.readFileSync('/proc/self/cgroup', 'utf8').trim().split('::')[1];
        assert.ok(cgroup.includes('/hermes-heavy-'), 'native browser belongs to the sole bounded heavy owner');
        evidence.cgroup = cgroup;
        const { createApp } = require('../browser-assets-wave8/local-app.cjs');
        app = await createApp();
        evidence.origin = app.origin;
        browser = new Firefox();
        await browser.start(process.env.TMPDIR);
        evidence.engine = browser.session.capabilities;
        evidence.browserProfile = browser.profile;
        await browser.send('session.subscribe', { events: ['network.beforeRequestSent'] });

        await check('real nodes loader boots without unused edgehandles request or lodash exception', async () => {
            await browser.navigate(app.origin + '/panel/nodes?lang=ru');
            await nativeClick('#tabNetwork');
            await browser.wait(`${CY.replace('._cyreg.cy', '._cyreg?.cy')}?.nodes().length>=5`, 30000);
            const scripts = await browser.evaluate('Array.from(document.scripts,s=>s.src)');
            assert.ok(!scripts.some(url => /edgehandles/i.test(url)));
            assert.ok(!browser.events.some(e => e.method === 'network.beforeRequestSent'
                && /edgehandles/i.test(e.params.request.url)));
            assertNoEdgehandles();
            const layers = await browser.evaluate(`({
                wrapper:getComputedStyle(document.getElementById('viewNetwork')).zIndex,
                surface:getComputedStyle(document.querySelector('#viewNetwork > .network-page')).zIndex,
                modal:getComputedStyle(document.getElementById('nodeInfoModal')).zIndex
            })`);
            assert.deepEqual(layers, { wrapper: 'auto', surface: '1', modal: '1000' },
                'the browser must receive the rebuilt CSS, not stale generated assets');
            const assets = [];
            const loadedUrls = await browser.evaluate('Array.from(document.querySelectorAll("link[rel=stylesheet],script[src]"),e=>e.href||e.src)');
            for (const file of ['css/style.min.css', 'css/network.min.css', 'js/network.min.js']) {
                const loadedUrl = loadedUrls.find(url => new URL(url).pathname === '/' + file);
                assert.ok(loadedUrl, 'actual template must load ' + file);
                const response = await fetch(loadedUrl);
                assert.equal(response.status, 200);
                const diskSha256 = sha(fs.readFileSync(path.join(root, 'public', file)));
                const servedSha256 = sha(Buffer.from(await response.arrayBuffer()));
                const browserSha256 = await browser.evaluate(`fetch(${JSON.stringify(loadedUrl)}).then(r=>{if(r.status!==200)throw Error('Asset HTTP '+r.status);return r.arrayBuffer();}).then(b=>crypto.subtle.digest('SHA-256',b)).then(b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join(''))`);
                assert.equal(servedSha256, diskSha256);
                assert.equal(browserSha256, diskSha256);
                if (file === 'css/style.min.css') assert.equal(new URL(loadedUrl).searchParams.get('v'), diskSha256.slice(0, 16));
                assets.push({ file, loadedUrl, diskSha256, servedSha256, browserSha256 });
            }
            return { scripts, layers, assets };
        });

        await check('existing Add Link button and modal close remain natively clickable without changing map', async () => {
            const before = await graph();
            const openHit = await nativeClick('#btnAddLink');
            await browser.wait("document.getElementById('addLinkModal').classList.contains('active')");
            await browser.wait("document.querySelectorAll('#selectPortal option').length>1");
            await sleep(700); // real advisory warning can change form geometry
            const closeHit = await nativeClick('#modalClose');
            await browser.wait("!document.getElementById('addLinkModal').classList.contains('active')");
            assert.deepEqual(await graph(), before);
            assert.equal(app.f.data.CascadeLink.length, 0, 'open/close is not create or AutoDeploy');
            return { openHit, closeHit, map: before };
        });

        await check('tall staged selected-link drawer closes at its own native hit target, not Auto Layout', async () => {
            // Reproduce the same real source-less staged drawer as wave 8. The
            // actual runtime supplies its rows; do not pad DOM or fake status.
            const before = await graph();
            await nativeClick('#btnAddLink');
            await browser.wait("document.querySelectorAll('#selectPortal option').length>1");
            for (const [selector, value] of [
                ['#addLinkForm [name="name"]', 'UI obstruction R-B'],
                ['#selectPortal', app.id(2)], ['#selectBridge', app.id(3)],
                ['#addLinkForm [name="tunnelPort"]', '24509'],
            ]) await browser.fill(selector, value);
            await sleep(700);
            assert.equal(await browser.evaluate("document.querySelector('#addLinkForm [name=autoDeploy]').checked"), true);
            await nativeClick('#linkModalSubmit');
            await browser.wait("!document.getElementById('addLinkModal').classList.contains('active')");
            const link = app.f.data.CascadeLink.find(row => row.name === 'UI obstruction R-B');
            assert.ok(link, 'the actual public create route must persist the selected link');
            app.host.start();
            for (let i = 0; i < 60; i++) {
                await app.tick();
                const operation = app.f.data.TopologyOperation.find(row => row.linkId === link._id);
                if (operation && ['succeeded', 'failed', 'rolled_back'].includes(operation.status)) break;
                await sleep(50);
            }
            const operation = app.f.data.TopologyOperation.find(row => row.linkId === link._id);
            assert.equal(operation?.status, 'succeeded', JSON.stringify(app.summary()));
            assert.equal(operation.routeState, 'no_portal_input');
            assert.equal(operation.staged, true);
            assert.deepEqual(app.f.errors, []);
            await nativeClick('#btnRefresh');
            await browser.wait("!document.querySelector('.network-loading')");
            await browser.wait(`${CY}.edges().some(e=>e.data('linkId')===${JSON.stringify(link._id)})`);
            // Match the existing lifecycle's native graph viewport setup. The
            // form's focus scrolling otherwise leaves the toolbar below the
            // historical overlap band, which is not the regression under test.
            await browser.evaluate("(()=>{document.getElementById('cy').scrollIntoView({block:'center'});return true;})()");
            await sleep(350);
            const point = await browser.evaluate(`(()=>{
                const e=${CY}.edges().filter(e=>e.data('linkId')===${JSON.stringify(link._id)});
                const p=e[0].renderedMidpoint(),r=document.getElementById('cy').getBoundingClientRect();
                return {x:p.x+r.x,y:p.y+r.y};
            })()`);
            await browser.pointer(point.x, point.y);
            await browser.wait("document.getElementById('nodeInfoModal').classList.contains('active')");
            await sleep(300);
            const geometry = await browser.evaluate(`(()=>{
                const c=document.querySelector('#nodeInfoModal .modal-card').getBoundingClientRect();
                const b=document.getElementById('nodeInfoClose').getBoundingClientRect();
                const t=document.getElementById('btnAutoLayout').getBoundingClientRect();
                return {cardHeight:c.height,viewportHeight:innerHeight,closeY:b.y+b.height/2,
                    toolbarTop:t.top,toolbarBottom:t.bottom,body:document.getElementById('nodeInfoBody').innerText};
            })()`);
            assert.ok(geometry.cardHeight >= geometry.viewportHeight * 0.75,
                'must exercise the tall drawer, not a short node popup: ' + JSON.stringify(geometry));
            assert.ok(geometry.closeY >= geometry.toolbarTop && geometry.closeY <= geometry.toolbarBottom,
                'close must occupy the original toolbar-overlap band: ' + JSON.stringify(geometry));
            assert.ok(geometry.body.includes(require('../src/locales/ru.json').network.routeNoPortal),
                'the actual staged selected-link readiness rows must be visible');
            assert.ok(geometry.body.includes('PPP/L2TP') && geometry.body.toUpperCase().includes('XRAY/VLESS/REALITY'));
            const closeHit = await nativeClick('#nodeInfoClose');
            await browser.wait("!document.getElementById('nodeInfoModal').classList.contains('active')");
            assert.deepEqual(await graph(), before, 'drawer close must not accidentally run Auto Layout or fit');
            assertNoEdgehandles();
            return { linkId: link._id, operationId: operation._id, geometry, closeHit, map: before };
        });
    } catch (error) {
        evidence.error = error.stack;
        process.exitCode = 1;
    } finally {
        if (browser) {
            evidence.console = browser.events?.filter(e => e.method === 'log.entryAdded');
            evidence.nativeFills = browser.nativeFills;
            evidence.firefoxLog = browser.log;
            evidence.edgehandlesRequests = browser.events.filter(e => e.method === 'network.beforeRequestSent'
                && /edgehandles/i.test(e.params.request.url));
            try { evidence.browserCleanup = await browser.close(); }
            catch (error) { evidence.browserCleanupError = error.stack; process.exitCode = 1; }
        }
        if (app) {
            evidence.backend = app.summary();
            try { evidence.applicationCleanup = await app.close(); }
            catch (error) { evidence.applicationCleanupError = error.stack; process.exitCode = 1; }
        }
        evidence.totals = { cases: evidence.cases.length,
            pass: evidence.cases.filter(row => row.status === 'PASS').length,
            fail: evidence.cases.filter(row => row.status === 'FAIL').length };
        evidence.success = !process.exitCode && evidence.totals.cases === 3 && evidence.totals.fail === 0;
        if (!evidence.success) process.exitCode = 1;
        fs.writeFileSync(path.join(out, 'evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
        console.log(JSON.stringify({ success: evidence.success, totals: evidence.totals }));
    }
}

if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
