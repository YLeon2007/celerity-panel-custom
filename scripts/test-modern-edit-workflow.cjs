'use strict';

// Run: node --test scripts/test-modern-edit-workflow.cjs
// Uses the same local tools as test-modern-create-workflow.cjs. If not already
// resolvable, set NODE_PATH to vetted, pre-existing module roots containing
// jsdom, esbuild and ejs (including their dependencies). No install or server.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

function localTool(name) {
    let entry;
    try { entry = require.resolve(name); } catch (error) {
        throw new Error(`Missing local ${name}; supply a vetted installed copy via NODE_PATH. No DOM fallback.`, { cause: error });
    }
    return require(entry);
}

const { JSDOM, VirtualConsole } = localTool('jsdom');
const { buildSync } = localTool('esbuild');
const { render } = localTool('ejs');
const i18n = require('../src/middleware/i18n');
const { MIN_KCP_XRAY_VERSION } = require('../src/utils/cascadeTransport');
const root = path.resolve(__dirname, '..');
const source = file => readFileSync(path.join(root, file), 'utf8');
const bundle = buildSync({ absWorkingDir: root, entryPoints: ['public/js/network/src/index.js'],
    bundle: true, write: false, format: 'iife',
    // The real entry starts in Chains. Leave the unvisited lazy views external;
    // the edit renderer, store, actions and inspector are all real modules.
    external: ['./views/graph.js', './views/geo.js'],
}).outputFiles[0].text;
const previewSource = source('public/js/rebuild-preview.js');
const appSource = source('public/js/app.js');
const lang = 'ru';
const locales = i18n.getLocale(lang);
const tr = key => i18n.t(key, lang);
const labels = { edit: 'Изменить', noChanges: 'Изменений нет', pending: 'Есть неприменённые изменения' };

const origin = 'https://panel.invalid';
const token = 's'.repeat(43);
const [portal, bridge, relay, spareBridge, id, otherId] = '1234ab'.split('').map(c => c.repeat(24));
const edgeId = `link-${id}`;
const previewId = 'be'.repeat(64);
const api = '/api/cascade';
const topologyPath = `${api}/topology`;
const linkPath = linkId => `${api}/links/${linkId}`;
const previewPath = `${api}/rebuild/preview`;
const applyPath = `${linkPath(id)}/deploy`;
const initialName = 'Синтетическая связь A';
const updatedName = 'Изменённая связь A';
const otherName = 'Синтетическая связь B';
const tlsName = 'listener.fixture.invalid';
const kcp = { kcpHeader: 'dtls', kcpMtu: 1400, kcpTti: 30, kcpUplinkCapacity: 150, kcpDownlinkCapacity: 200 };
const privateFields = Object.fromEntries(['tunnelUuid', 'realityPrivateKey', 'realityPublicKey', 'kcpPassword',
    'rebuildVlessKeyEnvelope'].map((key, i) => [key, `SYNTHETIC-NOT-A-KEY-${i}-DO-NOT-RENDER`]));
const lifecycle = { state: 'deleting', deleteJobId: 'd'.repeat(24), desiredVersion: '1'.repeat(64) };
const rows = [[portal, 'Fixture portal', 'portal'], [bridge, 'Fixture bridge', 'bridge'],
    [relay, 'Fixture relay', 'relay'], [spareBridge, 'Fixture spare bridge', 'bridge']];
const nodes = rows.map(([nodeId, name, cascadeRole], i) => ({ data: {
    id: nodeId, label: name, cascadeRole, type: 'xray', status: 'online', ip: `192.0.2.${i + 1}`,
    domain: '', flag: '', country: '', onlineUsers: 0, port: 443, sshConfigured: false,
}, position: { x: i * 150, y: 50 } }));
const report = { allowed: true, previewId, nodes: [portal, bridge].map(nodeId => ({ nodeId, profiles: [
    { profile: 'main', change: 'replace', sections: ['routing'], protectedChanged: false },
    { profile: 'bridge', change: 'unchanged', sections: [], protectedChanged: false },
] })) };
const issueMessage = (key, nodeName, version) => tr(`network.${key}`).replace('{nodeName}', nodeName)
    .replace('{version}', version ?? '').replace('{minimumVersion}', MIN_KCP_XRAY_VERSION);
const issues = [
    { nodeId: portal, nodeName: rows[0][1], reason: 'too_old', version: '26.5.9' },
    { nodeId: bridge, nodeName: rows[1][1], reason: 'unknown', version: null },
].map(issue => ({ ...issue, message: issueMessage(issue.version ? 'rebuildKcpVersionTooOld' : 'rebuildKcpVersionUnknown',
    issue.nodeName, issue.version) }));
const refusal = { error: { code: 'REBUILD_KCP_XRAY_VERSION_UNSUPPORTED', minimumVersion: MIN_KCP_XRAY_VERSION,
    message: issues.map(issue => issue.message).join(' '), issues } };

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

const turn = () => new Promise(resolve => setImmediate(resolve));
const read = ['GET', topologyPath];
const getLink = linkId => ['GET', linkPath(linkId)];
const save = ['PUT', linkPath(id)];
const preview = ['POST', previewPath];
const apply = ['POST', applyPath];
const text = el => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
const isShown = el => !el.closest('[hidden],dialog:not([open])');
const button = (scope, label) => [...scope.querySelectorAll('button')].find(el =>
    isShown(el) && [text(el), el.getAttribute('aria-label'), el.title].includes(label));
const assertNoDisclosure = w => {
    const doc = w.document;
    for (const [key, marker] of Object.entries(privateFields)) {
        assert.ok(!doc.documentElement.outerHTML.includes(marker), `synthetic ${key} leaked into markup`);
        assert.ok(![...doc.querySelectorAll('input,select,textarea')].some(el => el.value.includes(marker)),
            `synthetic ${key} leaked into a control's live value`);
        assert.ok(!doc.querySelector(`[name="${key}"]`), `unexpected control for ${key}`);
    }
};

async function mount(t, { authorized = true, edge = {}, raw = {}, expectedPatch, rejectSave = false } = {}) {
    const locals = { lang, locales, t: tr, canManageLinks: authorized, panelToken: token, c3Rebuild: true };
    const partial = file => render(source(`views/partials/${file}.ejs`), locals);
    const html = `<!doctype html><html lang="ru"><body><section id="viewNetwork">
        <div id="networkToolbar">${partial('network-map-toolbar')}</div>${partial('network-map')}
        </section>${partial('rebuild-preview')}<div id="toast" class="toast"></div></body></html>`;
    const virtualConsole = new VirtualConsole(), errors = [];
    virtualConsole.on('jsdomError', error => errors.push(error));
    virtualConsole.on('error', (...args) => errors.push(args[0]));
    const { window: w } = new JSDOM(html, { url: `${origin}/panel/nodes?map=modern`,
        runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole });
    const doc = w.document;
    const inspector = doc.querySelector('aside.nm-insp');
    const dialog = doc.querySelector('dialog#rebuildPreview');
    // Only missing platform primitives; the actual dialog buttons/listeners,
    // submit events, DOM rendering and host callbacks are not replaced.
    w.Element.prototype.scrollIntoView ??= function () {};
    dialog.showModal ??= function () { this.open = true; };
    dialog.close ??= function () {
        if (!this.open) return;
        this.open = false;
        w.setTimeout(() => this.dispatchEvent(new w.Event('close')), 0);
    };
    w.addEventListener('error', event => errors.push(event.error ?? event.message));
    t.after(() => {
        w.close(); // also stops the actual host's topology poll
        if (errors.length) {
            // Never include a payload, DOM dump or a console argument in TAP.
            throw new Error(`Unexpected browser/fetch errors: ${errors.length}; first kind: ${errors[0] instanceof assert.AssertionError ? 'fetch assertion (see test request checks)' : 'browser/runtime'}`);
        }
    });

    const calls = [], gates = {}, topologyReadbacks = [];
    const endpoint = index => ({ _id: rows[index][0], name: rows[index][1], ip: nodes[index].data.ip, flag: '', status: 'online' });
    // Direct response from GET /links/:id (not a topology edge or { link }).
    // The additional private sentinels are deliberate over-delivery at the GET boundary.
    const baseline = { _id: id, name: initialName, portalNode: endpoint(0), bridgeNode: endpoint(1),
        active: true, mode: 'reverse', tunnelPort: 24443, tunnelProtocol: 'vless', tunnelTransport: 'tcp',
        tunnelSecurity: 'tls', rebuildTlsServerName: tlsName, status: 'deployed', ...kcp, ...privateFields };
    const first = { ...baseline, ...raw };
    const second = { ...baseline, _id: otherId, name: otherName, bridgeNode: endpoint(2) };
    let pending = false;
    const snapshot = () => ({ nodes, edges: [first, second].map(row => ({ data: {
        id: `link-${row._id}`, linkId: row._id, source: row.portalNode._id, target: row.bridgeNode._id, label: row.name,
        mode: row.mode, tunnelPort: row.tunnelPort, tunnelProtocol: row.tunnelProtocol, tunnelTransport: row.tunnelTransport,
        tunnelSecurity: row.tunnelSecurity, status: row.status, latencyMs: null,
        canEdit: true, hasUnappliedChanges: row === first && pending,
        ...(row === first ? edge : {}),
    } })) });
    function permitOnly(actual, expected, label) {
        // Do not dump a failing request: it may contain a synthetic secret.
        const keys = Object.keys(expected).sort();
        assert.ok(actual && JSON.stringify(Object.keys(actual).sort()) === JSON.stringify(keys), `${label}: unexpected JSON keys`);
        for (const key of keys) assert.ok(actual[key] === expected[key], `${label}: wrong value for ${key}`);
    }
    const fetchFailures = [];
    w.fetch = async (input, init) => {
        try {
            const url = new URL(input, origin), method = init.method;
            const body = init.body === undefined ? null : JSON.parse(init.body);
            const headers = new w.Headers(init.headers);
            const route = url.pathname;
            assert.ok([topologyPath, linkPath(id), linkPath(otherId), previewPath, applyPath].includes(route), 'unexpected request path');
            assert.ok(['GET', 'PUT', 'POST'].includes(method), 'unexpected request method');
            calls.push([method, route]);
            const respond = (data, status = 200, json = async () => JSON.parse(JSON.stringify(data))) => ({
                ok: status === 200, status, url: url.href, redirected: false,
                headers: new w.Headers({ 'Content-Type': 'application/json' }), json });
            assert.ok(url.origin === origin && !url.search && !url.hash, 'request must use the synthetic origin without query/hash');
            assert.equal(init.credentials, 'same-origin');
            assert.equal(init.redirect, 'error');
            assert.equal(init.cache, 'no-store');
            assert.ok(!headers.has('authorization'), 'request must not have an Authorization header');
            if (method === 'GET') {
                assert.ok(body === null, 'GET must not have a body');
                if (route === topologyPath) {
                    const view = snapshot();
                    return respond(view, 200, async () => {
                        const row = view.edges[0].data;
                        topologyReadbacks.push({ name: row.label, status: row.status, pending: row.hasUnappliedChanges });
                        return JSON.parse(JSON.stringify(view));
                    });
                }
                assert.ok(authorized && (route === linkPath(id) || route === linkPath(otherId)), 'unexpected raw GET');
                const row = structuredClone(route === linkPath(id) ? first : second);
                if (route === linkPath(id)) await gates.edit?.promise;
                return respond(row);
            }
            assert.ok(authorized && headers.get('x-csrf-token') === token, 'request must use the panel CSRF header');
            assert.equal(headers.get('content-type'), 'application/json');
            if (method === 'PUT' && route === linkPath(id)) {
                assert.ok(expectedPatch, 'no PUT expected');
                permitOnly(body, expectedPatch, 'PUT changed fields only');
                await gates.save?.promise;
                if (rejectSave) return respond(refusal, 409);
                const { tlsServerName, ...changed } = body;
                Object.assign(first, changed, { status: 'pending' });
                if (tlsServerName !== undefined) first.rebuildTlsServerName = tlsServerName;
                pending = true;
                return respond({ executionMode: 'rebuild', desiredSaved: true, linkId: id, status: 'saved' });
            }
            assert.ok(pending && !rejectSave && method === 'POST', 'preview/Apply requires an acknowledged save');
            if (route === previewPath) {
                permitOnly(body, { linkId: id }, 'Preview');
                return respond(report);
            }
            assert.ok(route === applyPath, 'unexpected request path');
            permitOnly(body, { expectedPreview: previewId }, 'Apply');
            await gates.apply?.promise;
            pending = false;
            first.status = 'deployed';
            return respond({ executionMode: 'rebuild', status: 'succeeded', ...report });
        } catch (error) {
            // Actions catch transport errors. Keep an independent assertion
            // channel without exposing raw exception values/response bodies.
            fetchFailures.push(error instanceof assert.AssertionError ? error.message.split('\n')[0] : 'invalid request');
            throw new Error('Synthetic transport rejected request');
        }
    };
    t.after(() => assert.deepEqual(fetchFailures, []));
    for (const script of doc.querySelectorAll('script:not([src]):not([type])')) w.eval(script.textContent);
    w.eval(appSource);
    w.eval(previewSource);
    w.eval(bundle);

    async function until(predicate, message) {
        // Mocked fetch resolves on microtasks except where a gate is held.
        // The dialog also uses a platform task for its close event.
        const deadline = Date.now() + 1000;
        do {
            await turn();
            assert.deepEqual(fetchFailures, []);
            if (predicate()) return;
            await new Promise(resolve => setTimeout(resolve, 5));
        } while (Date.now() < deadline);
        assert.fail(message);
    }
    const form = () => inspector.querySelector('form');
    const editButton = () => button(inspector, labels.edit);
    const refresh = async () => {
        const control = doc.getElementById('btnNetworkRefresh');
        control.click();
        await until(() => !control.disabled, 'topology refresh did not settle');
    };
    const edit = async (linkId = id) => {
        const control = editButton();
        assert.ok(control && !control.disabled, 'selected, editable edge must have an enabled «Изменить» button');
        const count = calls.length;
        control.click();
        await until(form, 'Edit GET did not mount the real form');
        assert.deepEqual(calls.slice(count), [getLink(linkId)], 'Edit opens via one raw GET, not a topology-only or eager write path');
        return form();
    };
    const field = name => {
        const control = form()?.querySelector(`[name="${name}"]`);
        assert.ok(control, `missing edit field ${name}`);
        return control;
    };
    const change = (name, value) => {
        const control = field(name);
        control.value = String(value);
        for (const type of ['input', 'change']) control.dispatchEvent(new w.Event(type, { bubbles: true }));
    };
    const select = (linkId = id) => {
        const pill = doc.querySelector(`.nmc-pill[data-link="link-${linkId}"]`);
        assert.ok(pill, 'real Chains selection control missing');
        pill.click();
    };
    const submit = (f = form()) => f.requestSubmit();
    const craftedSubmit = (f = form()) => f.dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
    const cancelForm = () => {
        const control = button(form(), locales.network.map.create.cancel) ?? button(form(), locales.common.cancel)
            ?? button(form(), locales.network.map.close);
        assert.ok(control, 'edit form must have a cancel/close control');
        control.click();
    };
    const pendingShown = () => text(inspector).includes(labels.pending);
    const feedback = () => [inspector, doc.getElementById('toast'), dialog.open ? dialog : null].filter(Boolean).map(text).join(' ');
    const assertStatus = expected => {
        assert.ok([...inspector.querySelectorAll('.nm-st')].some(el => isShown(el) && text(el) === locales.network.map.status[expected]),
            `inspector did not render observed ${expected} status`);
    };
    const applyButton = dialog.querySelector('#rebuildPreviewApply');
    const previewCancel = dialog.querySelector('#rebuildPreviewCancel');
    await until(() => doc.querySelector(`.nmc-pill[data-link="${edgeId}"]`), 'real Chains map did not render fixture topology');
    assert.deepEqual(calls, [read], 'map startup must not fetch raw link data');
    return { doc, w, inspector, dialog, applyButton, previewCancel, calls, gates, edge, topologyReadbacks, form, editButton,
        refresh, edit, field, change, select, submit, craftedSubmit, cancelForm, pendingShown, feedback, assertStatus, until };
}

function assertPreview(ui) {
    assert.ok(ui.dialog.open, 'expected the shared Preview dialog');
    assert.equal(text(ui.dialog.querySelector('h2')), locales.network.rebuildPreview.deployTitle);
    assert.ok(!ui.applyButton.hidden && !ui.applyButton.disabled);
    assert.equal(text(ui.applyButton), locales.network.rebuildPreview.apply);
    assert.ok(text(ui.dialog).includes(rows[0][1]), 'shared Preview must resolve real store node labels');
    assertNoDisclosure(ui.w);
}

const opened = [read, getLink(id)];

test('raw GET prefill, read-only endpoints, and same values do not submit a draft', async t => {
    const ui = await mount(t);
    ui.select();
    await ui.edit();
    for (const [name, value] of Object.entries({ name: initialName,
        mode: 'reverse', tunnelPort: 24443, tunnelProtocol: 'vless', tunnelTransport: 'tcp',
        tunnelSecurity: 'tls', tlsServerName: tlsName })) {
        assert.ok(ui.field(name).value === String(value), `raw GET did not prefill ${name}`);
    }
    const endpoints = [...ui.form().querySelectorAll('[aria-describedby="nm-edit-endpoints-hint"]')];
    assert.equal(endpoints.length, 2);
    for (const [i, control] of endpoints.entries()) {
        assert.ok(control.readOnly && !control.name && control.value.includes(rows[i][1]));
    }
    assert.equal(text(ui.form().querySelector('#nm-edit-endpoints-hint')), 'Чтобы сменить ноды, удалите связь и создайте новую.');
    assertNoDisclosure(ui.w);
    // Re-enter identical settings, rather than only relying on initial dirtiness.
    ui.change('name', initialName);
    ui.change('tunnelPort', 24443);
    ui.change('tlsServerName', tlsName);
    // Try both ordinary submit and a submit event that bypasses browser gating.
    ui.submit();
    ui.craftedSubmit();
    await ui.until(() => ui.feedback().includes(labels.noChanges),
        'no-op must give the localized «Изменений нет» feedback');
    assert.deepEqual(ui.calls, opened);
    assert.equal(ui.dialog.open, false);
});

test('crafted endpoint changes cannot edit or preview the link', async t => {
    const ui = await mount(t);
    ui.select();
    const form = await ui.edit();
    const endpoints = [...form.querySelectorAll('[aria-describedby="nm-edit-endpoints-hint"]')];
    assert.equal(endpoints.length, 2);
    for (const [i, replacement] of [relay, spareBridge].entries()) {
        const control = endpoints[i];
        assert.equal(control.readOnly, true);
        control.readOnly = false;
        control.name = ['portalNodeId', 'bridgeNodeId'][i];
        control.value = replacement;
        assert.equal(control.value, replacement, 'crafted endpoint must reach the submit handler');
    }
    // Different, eligible Xray endpoints: a self-link check alone would not
    // reject this pair. Endpoints must remain fixed in edit mode.
    ui.craftedSubmit(form);
    await turn();
    assert.deepEqual(ui.calls, opened);
    assert.equal(ui.dialog.open, false);
});

for (const transport of ['kcp', 'ws']) test(`${transport}: Reality unavailable in the editor and rejected on crafted submit`, async t => {
    const ui = await mount(t);
    ui.select();
    await ui.edit();
    ui.change('tunnelTransport', transport);
    const security = ui.field('tunnelSecurity');
    const reality = [...security.options].find(o => o.value === 'reality');
    assert.ok(!reality || reality.matches(':disabled') || reality.hidden, 'Reality must not be offered');
    if (!reality) security.add(new ui.w.Option('REALITY', 'reality'));
    security.value = 'reality';
    assert.equal(security.value, 'reality');
    ui.craftedSubmit();
    await turn();
    assert.deepEqual(ui.calls, opened);
    assert.equal(ui.dialog.open, false);
});

test('canceling Preview keeps the saved delta, rereads pending, and can open Edit again independently', async t => {
    const changedTlsName = 'changed-listener.fixture.invalid';
    const ui = await mount(t, { expectedPatch: { name: updatedName, tlsServerName: changedTlsName } });
    ui.select();
    ui.assertStatus('deployed');
    assert.equal(ui.pendingShown(), false);
    const form = await ui.edit();
    ui.change('name', updatedName);
    ui.change('tlsServerName', changedTlsName);
    // Extra hidden inputs do not extend the form's write allowlist.
    for (const name of ['autoDeploy', 'expectedPreview', 'active', 'realityPrivateKey']) {
        const input = ui.doc.createElement('input');
        Object.assign(input, { type: 'hidden', name, value: 'SYNTHETIC-CRAFTED' });
        form.append(input);
    }
    ui.gates.save = deferred();
    ui.submit();
    ui.craftedSubmit(form);
    await ui.until(() => ui.calls.length >= 3, 'expected the save-only PUT');
    assert.deepEqual(ui.calls, [...opened, save]);
    assert.equal(ui.dialog.open, false, 'cannot preview before save ACK');
    // Remove the attacker-injected controls; disclosure checks cover the application's DOM.
    for (const input of form.querySelectorAll('[value="SYNTHETIC-CRAFTED"]')) input.remove();
    ui.gates.save.resolve();
    await ui.until(() => ui.dialog.open, 'save ACK did not open Preview');
    assertPreview(ui);
    assert.deepEqual(ui.calls.filter(([method, route]) => method !== 'GET' || route !== topologyPath),
        [getLink(id), save, preview]);
    ui.previewCancel.click();
    await ui.until(() => !ui.dialog.open && !ui.form() && ui.pendingShown(), 'saved-but-not-applied state did not render on reread');
    assert.ok(ui.calls.slice(3).some(([method, route]) => method === 'GET' && route === topologyPath), 'explicit post-save topology readback is required');
    assert.deepEqual(ui.calls.filter(([method]) => method !== 'GET'), [save, preview]);
    assert.deepEqual(ui.topologyReadbacks.at(-1), { name: updatedName, status: 'pending', pending: true });
    assert.ok(text(ui.inspector).includes(updatedName));
    ui.assertStatus('pending');

    // A fresh Edit entry reads the saved draft, not the disposed form or a preview cache.
    const reopened = await ui.edit();
    assert.notEqual(reopened, form);
    assertNoDisclosure(ui.w);
    assert.equal(ui.field('name').value, updatedName);
    assert.equal(ui.field('tlsServerName').value, changedTlsName);
    ui.craftedSubmit(form); // a detached prior form no longer owns a mutation
    ui.cancelForm();
    await turn();
    assert.equal(ui.form(), null);
    assert.equal(ui.pendingShown(), true);
    assert.deepEqual(ui.calls.filter(([method]) => method !== 'GET'), [save, preview]);
});

test('accepting the real dialog sends one Apply with exactly the server preview ID', async t => {
    const ui = await mount(t, { expectedPatch: { tunnelPort: 24444 } });
    ui.select();
    const form = await ui.edit();
    ui.change('tunnelPort', 24444);
    ui.submit();
    await ui.until(() => ui.dialog.open, 'expected the Apply decision');
    assertPreview(ui);
    assert.deepEqual(ui.calls.filter(([method]) => method !== 'GET'), [save, preview]);
    ui.gates.apply = deferred();
    ui.applyButton.click();
    ui.applyButton.click();
    ui.craftedSubmit(form);
    await ui.until(() => ui.calls.some(([, route]) => route === applyPath), 'Apply did not reach fetch');
    assert.deepEqual(ui.calls.filter(([method]) => method !== 'GET'), [save, preview, apply]);
    const appliedAt = ui.calls.findIndex(([, route]) => route === applyPath);
    ui.gates.apply.resolve();
    await ui.until(() => !ui.dialog.open && !ui.form(), 'confirmed edit did not return to the inspector');
    assert.deepEqual(ui.calls.filter(([method]) => method !== 'GET'), [save, preview, apply]);
    assert.ok(ui.calls.slice(appliedAt + 1).some(([method, route]) => method === 'GET' && route === topologyPath), 'must read back after Apply');
    assert.deepEqual(ui.topologyReadbacks.at(-1), { name: initialName, status: 'deployed', pending: false });
    ui.assertStatus('deployed');
    assert.equal(ui.pendingShown(), false);
    assert.ok(text(ui.inspector).includes('24444'));
});

test('failed PUT displays both mKCP issues and cannot preview or Apply', async t => {
    const ui = await mount(t, { raw: { tunnelTransport: 'kcp', tunnelSecurity: 'none' }, expectedPatch: { kcpMtu: 1401 }, rejectSave: true });
    ui.select();
    await ui.edit();
    assert.equal(ui.field('kcpMtu').value, '1400');
    ui.change('kcpMtu', 1401);
    ui.submit();
    await ui.until(() => issues.every(issue => ui.feedback().includes(issue.message)),
        'both localized server issues must be visible');
    assertNoDisclosure(ui.w);
    assert.ok(!/REBUILD_KCP_XRAY_VERSION_UNSUPPORTED|HTTP 409/.test(ui.feedback()), 'no raw error code or HTTP status');
    if (ui.dialog.open) {
        assert.ok(ui.applyButton.hidden || ui.applyButton.disabled, 'refusal has no Apply action');
        ui.applyButton.click(); // hidden button activation must still be safe
        ui.previewCancel.click();
    }
    await turn();
    assert.deepEqual(ui.calls.filter(([method]) => method !== 'GET'), [save]);
    assert.equal(ui.pendingShown(), false);
    assertNoDisclosure(ui.w);
});

for (const [title, options] of [
    ['read-only page', { authorized: false }],
    ['canEdit false', { edge: { canEdit: false } }],
    ['canEdit missing', { edge: { canEdit: undefined } }],
    ['canEdit string', { edge: { canEdit: 'true' } }],
    ['deleting edge', { edge: { canEdit: false, lifecycle, applicationState: 'deleting' }, raw: { lifecycle } }],
]) test(`${title}: no edit affordance or raw GET`, async t => {
    const ui = await mount(t, options);
    ui.select();
    assert.ok(text(ui.inspector).includes(initialName), 'negative must inspect the real edge');
    assert.equal(Boolean(ui.editButton()), false);
    await turn();
    assert.deepEqual(ui.calls, [read]);
    assert.equal(ui.form(), null);
});

for (const pendingValue of [true, false, 'true', undefined]) test(`pending marker is strict: ${JSON.stringify(pendingValue)}`, async t => {
    // Keep health 'pending' even when the edit-specific flag is not true.
    const ui = await mount(t, { edge: { status: 'pending', hasUnappliedChanges: pendingValue } });
    ui.select();
    assert.equal(ui.pendingShown(), pendingValue === true, 'pending desired state is distinct from status/health');
    assert.deepEqual(ui.calls, [read]);
});

test('revoking permission on topology refresh fences a retained Edit control', async t => {
    const edge = {};
    const ui = await mount(t, { edge });
    ui.select();
    const control = ui.editButton();
    assert.ok(control && !control.disabled, 'permission must be present before refresh');
    edge.canEdit = false;
    await ui.refresh();
    assert.equal(Boolean(ui.editButton()), false);
    control.click(); // stale control is not authority to issue the raw GET
    await turn();
    assert.deepEqual(ui.calls, [read, read]);
    assert.equal(ui.form(), null);
});

for (const [title, raw] of [
    ['inactive', { active: false }],
    ['deleting', { lifecycle, applicationState: 'deleting' }],
]) test(`raw GET reports a now-${title} link: no editor or writes`, async t => {
    // At selection time topology allowed this link. GET sees the newer row.
    const ui = await mount(t, { raw });
    ui.select();
    const control = ui.editButton();
    assert.ok(control && !control.disabled, 'expected Edit from the older topology read');
    control.click();
    await ui.until(() => ui.calls.length >= 2, 'expected fresh raw GET for initially eligible selection');
    await turn();
    assert.equal(ui.form(), null, 'now-ineligible raw row must not reach the edit renderer');
    assert.deepEqual(ui.calls.filter(([, route]) => route !== topologyPath), [getLink(id)]);
    assert.equal(ui.dialog.open && !ui.applyButton.hidden && !ui.applyButton.disabled, false);
    assertNoDisclosure(ui.w);
});

test('a raw GET that becomes stale after changing selection cannot mount the old editor', async t => {
    const ui = await mount(t);
    ui.select();
    const control = ui.editButton();
    assert.ok(control, 'expected an Edit control to start the held GET');
    ui.gates.edit = deferred();
    control.click();
    await ui.until(() => ui.calls.length >= 2, 'held raw GET did not start');
    assert.deepEqual(ui.calls, opened);
    assert.equal(ui.form(), null, 'no edit form until the GET supplies the fields');
    ui.select(otherId);
    assert.ok(text(ui.inspector).includes(otherName));
    ui.gates.edit.resolve();
    await turn();
    assert.equal(ui.form(), null, 'late GET must not replace a newer selection');
    assert.ok(text(ui.inspector).includes(otherName));
    const fresh = await ui.edit(otherId);
    assert.equal(ui.field('name').value, otherName);
    ui.change('name', 'discard this local edit');
    ui.cancelForm();
    assert.equal(ui.form(), null);
    assert.ok(text(ui.inspector).includes(otherName));
    const reopened = await ui.edit(otherId);
    assert.notEqual(reopened, fresh);
    assert.equal(ui.field('name').value, otherName);
    assert.deepEqual(ui.calls, [...opened, getLink(otherId), getLink(otherId)]);
});
