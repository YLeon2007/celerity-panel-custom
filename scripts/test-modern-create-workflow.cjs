'use strict';

// Offline DOM integration. Same source-bundle/jsdom pattern as test-network-modern-actions.cjs.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { JSDOM, VirtualConsole } = require('jsdom');
const { buildSync } = require('esbuild');
const { render } = require('ejs');
const i18n = require('../src/middleware/i18n');
const { MIN_KCP_XRAY_VERSION } = require('../src/utils/cascadeTransport');

const root = path.resolve(__dirname, '..');
const source = file => readFileSync(path.resolve(root, file), 'utf8');
const bundle = buildSync({ absWorkingDir: root, stdin: { resolveDir: root, contents: `
    export { createStore } from './public/js/network/src/core/store.js';
    export { createActions } from './public/js/network/src/core/actions.js';
    export { renderCreateForm } from './public/js/network/src/ui/create-form.js';
` }, bundle: true, format: 'iife', globalName: 'fixture', write: false }).outputFiles[0].text;
const sharedPreview = source('public/js/rebuild-preview.js');
const app = source('public/js/app.js');
const mapTemplate = source('views/partials/network-map.ejs');
const previewTemplate = source('views/partials/rebuild-preview.ejs');

const origin = 'https://panel.invalid';
const token = 'f'.repeat(43);
const [portal, bridge, relay, otherRelay, solo, hysteria, savedId] = '123456a'.split('').map(c => c.repeat(24));
const edgeId = `link-${savedId}`;
const previewId = 'ab'.repeat(64);
const [topology, save, preview, deploy] = ['/topology', '/links', '/rebuild/preview', `/links/${savedId}/deploy`]
    .map(p => `/api/cascade${p}`);
const name = 'Synthetic link';
const kcp = { kcpMtu: 1400, kcpTti: 30, kcpUplinkCapacity: 150, kcpDownlinkCapacity: 200, kcpHeader: 'dtls' };
const settings = { name, mode: 'reverse', portalNodeId: portal, bridgeNodeId: bridge, tunnelPort: 24444,
    tunnelProtocol: 'vless', tunnelTransport: 'kcp', tunnelSecurity: 'none' };
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

// Shape from cascadeService.getTopology(), not raw HyNode or CascadeLink rows.
function nodes() {
    const physical = [
        [portal, 'Fixture portal', 'portal', 'xray'], [bridge, 'Fixture bridge', 'bridge', 'xray'],
        [relay, 'Fixture relay A', 'relay', 'xray'], [otherRelay, 'Fixture relay B', 'relay', 'xray'],
        [solo, 'Fixture standalone', 'standalone', 'xray'], [hysteria, 'Fixture Hysteria', 'relay', 'hysteria'],
    ].map(([id, label, cascadeRole, type], i) => ({ data: {
        id, label, cascadeRole, type, ip: `192.0.2.${i + 1}`, domain: '', flag: '', country: '',
        port: i === 0 ? 10443 : 443, onlineUsers: 0, status: 'online', sshConfigured: false,
    }, position: { x: i * 150, y: 50 } }));
    return [...physical, { data: { id: 'internet', label: 'Internet', cascadeRole: 'internet', type: 'internet',
        ip: '', domain: '', flag: '🌐', country: '', port: null, onlineUsers: 0, status: 'online' } }];
}
const internetEdges = [bridge, solo].map(id => ({ data: { id: `internet-${id}`, linkId: null, source: id,
    target: 'internet', label: '', status: 'online', isInternetEdge: true, tunnelPort: null,
    latencyMs: null, tunnelProtocol: null, tunnelTransport: null } }));

async function mount(t, { lang = 'en', saveResult, previewResult, saveGate, deployGate } = {}) {
    const locales = i18n.getLocale(lang);
    const locals = { t: key => i18n.t(key, lang), lang, locales, c3Rebuild: true, csrfToken: token, canManageLinks: true, panelToken: token };
    const errors = [], virtualConsole = new VirtualConsole();
    virtualConsole.on('jsdomError', err => errors.push(err));
    const html = `${render(mapTemplate, locals)}${render(previewTemplate, locals)}<div id="toast" class="toast"></div>`;
    const { window: w } = new JSDOM(`<!doctype html><html lang="${lang}"><body>${html}</body></html>`, {
        url: `${origin}/panel/nodes?map=modern`, runScripts: 'outside-only', virtualConsole,
    });
    const doc = w.document;
    const get = suffix => doc.getElementById('rebuildPreview' + suffix);
    const dialog = get(''), apply = get('Apply'), cancel = get('Cancel');
    // jsdom may lack the native modal methods. Do not replace its application callbacks.
    if (!dialog.showModal) dialog.showModal = () => { assert.equal(dialog.open, false); dialog.open = true; };
    if (!dialog.close) dialog.close = () => {
        if (!dialog.open) return;
        dialog.open = false;
        w.queueMicrotask(() => dialog.dispatchEvent(new w.Event('close')));
    };
    for (const script of doc.querySelectorAll('script:not([src]):not([type])')) w.eval(script.textContent);
    w.eval(app);
    w.eval(sharedPreview);
    w.eval(bundle);
    const store = w.fixture.createStore({ isVisible: () => true });
    const actions = w.fixture.createActions(store);
    t.after(() => { store.destroy(); w.close(); assert.deepEqual(errors, []); });
    w.addEventListener('error', event => errors.push(event.error));
    store.on('error', err => errors.push(err));

    const calls = [], drafts = [], reads = [], events = [], createdStatuses = [];
    const snapshot = () => ({ nodes: nodes(), edges: [...internetEdges, ...drafts.map(row => ({ data: {
        id: edgeId, linkId: savedId, source: row.portalNodeId, target: row.bridgeNodeId, label: row.name,
        status: row.status, tunnelPort: row.tunnelPort, latencyMs: null, tunnelProtocol: row.tunnelProtocol,
        tunnelTransport: row.tunnelTransport, tunnelSecurity: row.tunnelSecurity, mode: row.mode, muxEnabled: false,
    } }))] });
    const report = { allowed: previewResult !== 'denied', ...(previewResult !== 'missing ID' && { previewId }),
        nodes: [portal, bridge].map(nodeId => ({ nodeId, profiles: [
            { profile: 'main', change: 'replace', sections: ['routing'], protectedChanged: previewResult === 'denied' && nodeId === portal },
            { profile: 'bridge', change: 'unchanged', sections: [], protectedChanged: false },
        ] })) };
    const version = '26.5.9';
    const kcpMessage = locales.network.rebuildKcpVersionTooOld.replace('{nodeName}', 'Fixture portal')
        .replace('{version}', version).replace('{minimumVersion}', MIN_KCP_XRAY_VERSION);
    // All effect accounting is at the fetch boundary. Envelopes mirror cascadeRebuild.js.
    w.fetch = async (input, init) => {
        const url = new URL(input, origin), method = init.method;
        const headers = new Headers(init.headers), body = init.body === undefined ? null : JSON.parse(init.body);
        calls.push({ method, path: url.pathname, body });
        const respond = (data, status = 200) => ({ ok: status < 300, status, url: url.href, redirected: false,
            headers: new Headers({ 'Content-Type': 'application/json; charset=utf-8' }), json: async () => structuredClone(data) });
        try {
            assert.equal(url.origin, origin);
            assert.equal(url.search + url.hash, '');
            assert.equal(init.credentials, 'same-origin');
            assert.equal(init.redirect, 'error');
            assert.equal(init.cache, 'no-store');
            assert.equal(headers.get('authorization'), null);
            if (method === 'GET') {
                assert.equal(url.pathname, topology);
                assert.equal(body, null);
                // The topology GET is session-authenticated; the server CSRF guard is on non-GETs only.
                const read = reads.shift();
                const view = read?.view ?? snapshot();
                await read?.gate?.promise;
                return respond(view);
            }
            assert.equal(method, 'POST');
            assert.equal(init.mode, 'same-origin');
            assert.equal(headers.get('x-csrf-token'), token);
            assert.equal(headers.get('content-type'), 'application/json');
            if (url.pathname === save) {
                if (saveResult === 'kcp conflict') return respond({ error: {
                    code: 'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED', minimumVersion: MIN_KCP_XRAY_VERSION, message: kcpMessage,
                    issues: [{ nodeId: portal, nodeName: 'Fixture portal', reason: 'too_old', version, message: kcpMessage }],
                } }, 409);
                drafts.push({ ...body, status: 'pending' });
                await saveGate?.promise;
                if (saveResult === 'lost ACK') return Promise.reject(new TypeError('Synthetic connection loss after commit'));
                return respond({ executionMode: 'rebuild', desiredSaved: true, status: 'saved',
                    linkId: saveResult === 'malformed ACK' ? null : savedId });
            }
            assert.equal(drafts.length, 1, 'one saved draft is required before preview/deploy');
            if (url.pathname === preview) {
                assert.deepEqual(body, { linkId: savedId });
                return respond(report);
            }
            assert.equal(url.pathname, deploy);
            assert.equal(report.allowed, true);
            assert.equal(report.previewId, previewId);
            assert.deepEqual(body, { expectedPreview: previewId });
            await deployGate?.promise;
            drafts[0].status = 'deployed';
            return respond({ executionMode: 'rebuild', status: 'succeeded', ...report });
        } catch (err) {
            errors.push(err); // action controller catches fetch exceptions; assertions must still fail the test
            throw err;
        }
    };
    await store.load();
    assert.deepEqual(calls.splice(0), [{ method: 'GET', path: topology, body: null }]);
    assert.equal(store.index.nodes.get(portal).port, 10443);

    const container = doc.querySelector('.nm-insp');
    w.fixture.renderCreateForm(container, { store, actions, source: portal, target: bridge,
        onCancel: () => { events.push('cancel'); container.replaceChildren(); },
        onCreated: () => {
            events.push('created');
            createdStatuses.push(store.index.links.get(edgeId)?.status);
            container.replaceChildren();
        },
        onUncertain: () => { events.push('uncertain'); },
    });
    const form = container.querySelector('form');
    assert.ok(form, 'modern create form must render for eligible endpoints');
    const field = key => {
        const control = form.elements.namedItem(key);
        assert.ok(control instanceof w.HTMLElement, `missing form field ${key}`);
        return control;
    };
    const set = (key, value) => {
        const control = field(key);
        control.value = String(value);
        for (const type of ['input', 'change']) control.dispatchEvent(new w.Event(type, { bubbles: true }));
    };
    function fill(transport = 'kcp') {
        container.querySelector('button[data-mode="reverse"]')?.click();
        set('portalNodeId', portal);
        set('bridgeNodeId', bridge);
        if (form.elements.namedItem('tunnelProtocol')) set('tunnelProtocol', 'vless');
        set('tunnelTransport', 'kcp');
        set('tunnelSecurity', 'none');
        for (const [key, value] of Object.entries(kcp)) set(key, value);
        if (transport !== 'kcp') set('tunnelTransport', transport);
        set('tunnelSecurity', 'none');
        set('tunnelPort', 24444);
        set('name', name);
    }
    return { locales, store, actions, form, field, set, fill, calls, reads, drafts, snapshot, events, createdStatuses, kcpMessage,
        writes: () => calls.filter(c => c.method !== 'GET'), toast: doc.getElementById('toast'),
        dialog, apply, cancel, title: get('Title'), warning: get('Warning'), details: get('Details'),
        submit: () => form.requestSubmit(),
    };
}

const expectedSave = (transport = 'kcp') => ({ method: 'POST', path: save,
    body: { ...settings, tunnelTransport: transport, ...(transport === 'kcp' && kcp) } });
const expectedPreview = { method: 'POST', path: preview, body: { linkId: savedId } };
const expectedDeploy = { method: 'POST', path: deploy, body: { expectedPreview: previewId } };
const expectedRead = { method: 'GET', path: topology, body: null };
const enabledValues = select => [...select.options].filter(o => o.value && !o.matches(':disabled') && !o.hidden).map(o => o.value);

function assertDialog(ui, allowed) {
    const labels = ui.locales.network.rebuildPreview;
    assert.equal(ui.dialog.open, true);
    assert.equal(ui.title.textContent, allowed ? labels.deployTitle : labels.refused);
    assert.equal(ui.apply.hidden, !allowed);
    assert.equal(ui.apply.textContent, labels.apply);
    assert.equal(ui.cancel.textContent, ui.locales.common[allowed ? 'cancel' : 'close']);
}

function assertSaved(ui, status) {
    assert.equal(ui.actions.isBusy(), false);
    assert.deepEqual(ui.events, ['created']);
    assert.deepEqual(ui.createdStatuses, [status], 'hand off the acknowledged draft after topology readback');
    assert.equal(ui.drafts.length, 1);
    assert.equal(ui.store.index.links.get(edgeId)?.status, status, 'status must come from topology readback');
}

test('create options follow Rebuild endpoint roles; no self-link, kcp+reality, or eager write', async t => {
    const ui = await mount(t);
    const sources = () => enabledValues(ui.field('portalNodeId')).sort();
    const targets = () => enabledValues(ui.field('bridgeNodeId')).sort();
    assert.deepEqual(sources(), [portal, relay, otherRelay]);
    assert.deepEqual(targets(), [bridge, relay, otherRelay]);
    ui.set('portalNodeId', relay);
    assert.deepEqual(targets(), [bridge, otherRelay]);
    assert.notEqual(ui.field('portalNodeId').value, ui.field('bridgeNodeId').value);
    ui.set('tunnelTransport', 'tcp');
    if (enabledValues(ui.field('tunnelSecurity')).includes('reality')) ui.set('tunnelSecurity', 'reality');
    ui.set('tunnelTransport', 'kcp');
    assert.equal(ui.field('tunnelTransport').value, 'kcp');
    assert.notEqual(ui.field('tunnelSecurity').value, 'reality');
    assert.equal(enabledValues(ui.field('tunnelSecurity')).includes('reality'), false);
    await tick();
    assert.deepEqual(ui.writes(), []);
    assert.equal(ui.dialog.open, false);
});

for (const lang of ['en', 'ru']) test(`${lang}: native submit → save-only → explicit preview Apply → one deploy and readback`, async t => {
    const saveGate = deferred(), deployGate = deferred();
    const ui = await mount(t, { lang, saveGate, deployGate });
    ui.fill();
    // These controls are not authority, even if a legacy/hidden control exists within the form.
    for (const [key, value] of Object.entries({ autoDeploy: 'true', port: '10443', muxEnabled: 'true', realitySni: 'fixture.invalid',
        kcpPassword: 'synthetic', wsPath: '/hidden', geoRouting: 'true' })) {
        const control = ui.form.ownerDocument.createElement('input');
        Object.assign(control, { type: 'hidden', name: key, value });
        ui.form.append(control);
    }
    assert.deepEqual(ui.writes(), []);
    ui.submit();
    ui.submit();
    await tick();
    assert.deepEqual(ui.calls, [expectedSave()]);
    assert.equal(ui.drafts.length, 1);
    assert.equal(ui.dialog.open, false, 'no preview before save acknowledgement');
    saveGate.resolve();
    await tick();
    assert.deepEqual(ui.writes(), [expectedSave(), expectedPreview]);
    assertDialog(ui, true);
    assert.ok(ui.details.textContent.includes(`Fixture portal — ${ui.locales.network.rebuildPreview.portal}:`));
    assert.ok(ui.details.textContent.includes(ui.locales.network.rebuildPreview.settingsUnchanged));
    ui.submit();
    ui.apply.click();
    ui.apply.click();
    await tick();
    assert.deepEqual(ui.writes(), [expectedSave(), expectedPreview, expectedDeploy]);
    assert.equal(ui.store.index.links.get(edgeId)?.status === 'deployed', false, 'not optimistic');
    deployGate.resolve();
    await tick();
    assert.deepEqual(ui.calls, [expectedSave(), expectedPreview, expectedDeploy, expectedRead]);
    assertSaved(ui, 'deployed');
    assert.equal(ui.toast.textContent, ui.locales.network.map.rebuild.applied);
});

for (const outcome of ['cancel', 'denied', 'missing ID']) test(`${outcome}: acknowledged draft is refreshed without a deploy or duplicate save`, async t => {
    const transport = outcome === 'cancel' ? 'tcp' : 'kcp';
    const ui = await mount(t, { lang: 'ru', previewResult: outcome });
    ui.fill(transport);
    ui.submit();
    await tick();
    assertDialog(ui, outcome === 'cancel');
    if (outcome === 'missing ID') assert.equal(ui.warning.textContent, ui.locales.network.map.rebuild.previewUnavailable);
    if (outcome === 'denied') assert.ok(ui.details.textContent.includes(ui.locales.network.rebuildPreview.settingsChanged));
    if (outcome !== 'cancel') {
        ui.apply.click(); // Synthetic dispatch against the hidden Apply must still be inert.
        assert.equal(ui.dialog.open, true);
    }
    ui.submit();
    assert.deepEqual(ui.writes(), [expectedSave(transport), expectedPreview]);
    ui.cancel.click();
    await tick();
    assert.equal(ui.dialog.open, false);
    assert.deepEqual(ui.calls.at(-1), expectedRead);
    assertSaved(ui, 'pending');
    assert.equal(ui.toast.textContent, ui.locales.network.map.rebuild.draftSaved);
    ui.submit(); // stale form handle after the acknowledged draft was handed off
    await tick();
    assert.deepEqual(ui.writes(), [expectedSave(transport), expectedPreview]);
});

test('save 409 with typed mKCP issues shows localized human text and never previews', async t => {
    const ui = await mount(t, { lang: 'ru', saveResult: 'kcp conflict' });
    ui.fill();
    ui.submit();
    await tick();
    assertDialog(ui, false);
    assert.equal(ui.warning.hidden, false);
    assert.equal(ui.warning.textContent, ui.kcpMessage);
    assert.doesNotMatch(ui.warning.textContent, /REBUILD_|HTTP 409/);
    ui.apply.click();
    ui.cancel.click();
    await tick();
    assert.deepEqual(ui.writes(), [expectedSave()]);
    assert.equal(ui.drafts.length, 0);
    assert.equal(ui.store.index.links.has(edgeId), false);
    assert.deepEqual(ui.events, []);
});

for (const saveResult of ['malformed ACK', 'lost ACK']) test(`${saveResult}: possible save is read back but never retried`, async t => {
    const ui = await mount(t, { saveResult });
    ui.fill();
    ui.submit();
    await tick();
    assertDialog(ui, false);
    assert.equal(ui.warning.textContent, ui.locales.network.map.rebuild.saveUnconfirmed);
    assert.equal(ui.store.index.links.get(edgeId)?.status, 'pending', 'readback does not authorize replay');
    ui.cancel.click();
    await tick();
    assert.equal(ui.actions.isBusy(), false);
    assert.deepEqual(ui.events, ['uncertain']);
    assert.deepEqual(ui.writes(), [expectedSave()]);
    if (ui.form.isConnected && ui.form.elements.namedItem('tunnelPort')) ui.set('tunnelPort', 24445);
    await ui.store.refresh();
    ui.submit();
    await tick();
    assert.deepEqual(ui.writes(), [expectedSave()]);
    assert.equal(ui.drafts.length, 1);
});

test('stale selected endpoint after a topology poll cannot submit', async t => {
    const ui = await mount(t);
    ui.fill();
    const next = ui.snapshot();
    next.nodes.find(({ data }) => data.id === bridge).data.cascadeRole = 'standalone';
    ui.reads.push({ view: next });
    await ui.store.refresh();
    assert.equal(ui.store.index.nodes.get(bridge).cascadeRole, 'standalone');
    ui.submit();
    await tick();
    assert.deepEqual(ui.writes(), []);
    assert.deepEqual(ui.events, []);
});

test('a late pre-save poll cannot satisfy post-save readback or trigger another submit', async t => {
    const ui = await mount(t, { previewResult: 'missing ID' });
    ui.fill();
    const old = ui.snapshot(), gate = deferred();
    old.nodes.find(({ data }) => data.id === portal).data.status = 'offline';
    ui.reads.push({ view: old, gate });
    const seen = [];
    ui.store.on('data', () => seen.push(ui.store.index.nodes.get(portal).status));
    const poll = ui.store.refresh();
    ui.submit();
    await tick();
    assertDialog(ui, false);
    assert.deepEqual(ui.calls, [expectedRead, expectedSave(), expectedPreview]);
    assert.equal(ui.store.index.links.has(edgeId), false);
    gate.resolve();
    await poll;
    await tick();
    assert.deepEqual(ui.calls, [expectedRead, expectedSave(), expectedPreview, expectedRead]);
    assert.deepEqual(seen, ['online']);
    assert.equal(ui.store.index.links.get(edgeId)?.status, 'pending', 'fresh readback while refusal is still open');
    assert.equal(ui.dialog.open, true);
    ui.cancel.click();
    await tick();
    assertSaved(ui, 'pending');
    assert.deepEqual(ui.writes(), [expectedSave(), expectedPreview]);
});
