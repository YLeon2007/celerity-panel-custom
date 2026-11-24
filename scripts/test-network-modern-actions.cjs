'use strict';

// Offline integration; NODE_PATH may point at an existing jsdom/esbuild install.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const path = require('node:path');
const { describe, test } = require('node:test');
const { compileFunction } = require('node:vm');
const { JSDOM } = require('jsdom');
const { buildSync } = require('esbuild');
const { network, common } = require('../src/locales/en.json');
const { readKcpAdmission } = require('../src/services/rebuildKcpAdmission');
const { MIN_KCP_XRAY_VERSION } = require('../src/utils/cascadeTransport');

const root = path.resolve(__dirname, '..');
const source = file => readFileSync(path.resolve(root, file), 'utf8');
const bundle = buildSync({ absWorkingDir: root, stdin: { resolveDir: root, contents: `
    export { createActions } from './public/js/network/src/core/actions.js';
    export { createStore } from './public/js/network/src/core/store.js';
    export { createInspector } from './public/js/network/src/ui/inspector.js';
` }, bundle: true, format: 'iife', globalName: 'fixture', write: false }).outputFiles[0].text;
const markup = source('views/partials/rebuild-preview.ejs').match(/<dialog\b[\s\S]*?<\/dialog>/)[0];
const sharedPreview = source('public/js/rebuild-preview.js');
const labels = { ...network.rebuildPreview, lang: 'en', cancel: common.cancel, close: common.close };
const rebuild = network.map.rebuild;
const origin = 'https://panel.invalid';
const key = 'f'.repeat(43), otherKey = 'G'.repeat(43), oldToken = 'e'.repeat(64);
const linkId = 'a'.repeat(24), newId = 'b'.repeat(24), from = '1'.repeat(24), to = '2'.repeat(24);
const edgeId = `link-${linkId}`;
const cdnEdge = 'link-' + 'c'.repeat(24), internetEdge = 'link-' + 'd'.repeat(24);
const apiRoot = '/api/cascade';
const preview = `${apiRoot}/rebuild/preview`, topology = `${apiRoot}/topology`, links = `${apiRoot}/links`;
const deploy = `${links}/${linkId}/deploy`, chain = `${apiRoot}/chain/deploy`, remove = `${links}/${linkId}`, health = `${remove}/health`;
const newDeploy = `${links}/${newId}/deploy`;
const inventory = [from, to].map((_id, i) => ({ _id, cascadeRole: i ? 'bridge' : 'portal',
    name: i ? 'Fixture gateway' : 'Fixture portal', ip: `192.0.2.${i + 1}`, xrayVersion: MIN_KCP_XRAY_VERSION }));
const form = { name: 'Fixture draft', portalNodeId: from, bridgeNodeId: to, tunnelTransport: 'kcp', kcpMtu: 1350, tunnelPort: 24444 };
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

// Run the actual route handlers and report producer without starting Express,
// loading live adapters, or hooking the process-wide module loader.
function load(file, overrides) {
    const filename = path.resolve(root, file), localRequire = createRequire(filename);
    const mod = { exports: {} };
    compileFunction(source(file), ['require', 'module', 'exports'], { filename })(
        id => Object.hasOwn(overrides, id) ? overrides[id] : localRequire(id), mod, mod.exports);
    return mod.exports;
}
const forbidden = () => assert.fail('Unexpected live-adapter or non-JSON fixture path');
const codec = load('src/services/rebuildLinkSnapshot.js', { mongoose: { mongo: { BSON: { get Code() { return forbidden(); } } } } });
const composer = load('src/modules/relay-l2tp/services/rebuildTopologyComposer.js', {
    '../../../services/rebuildLinkKeys': { tunnelSettings: forbidden },
});
const exitImpact = load('src/services/rebuildPreviewExitImpact.js', {
    '../modules/relay-l2tp/services/rebuildTopologyComposer': composer,
});
const coordinator = load('src/services/rebuildCoordinator.js', {
    './rebuildLinkSnapshot': codec, './rebuildPreviewExitImpact': exitImpact,
});

function backend({ protectedChange = false, failAfterSave = false } = {}) {
    const rows = new Map([[linkId, { _id: linkId, portalNode: from, bridgeNode: to, mode: 'forward', status: 'pending' }]]);
    const roles = new Map(inventory.map(node => [node._id, node.cascadeRole]));
    const config = (outboundTag, inbounds = []) => ({ inbounds, routing: { rules: [
        { ruleTag: `${composer.REBUILD_POLICY_RULE_PREFIX}default`, outboundTag },
    ] } });
    const routeTag = composer.egressTag({ id: linkId, mode: 'forward' });
    const observed = new Map([[`${from}:main`, config(routeTag)], [`${to}:main`, config('direct')]]);
    const operations = [], receipts = [], routes = new Map();
    const add = method => (pattern, ...handlers) => routes.set(`${method} ${pattern}`, handlers);
    const { routerForRebuild } = load('src/routes/cascadeRebuild.js', {
        express: { Router: () => ({ post: add('POST'), put: add('PUT'), delete: add('DELETE'), get: add('GET') }) },
        '../middleware/auth': { requireScope: () => (req, res, next) => { assert.equal(req.session.authenticated, true); return next(); } },
        '../services/rebuildService': { createRebuildService: forbidden },
        '../services/rebuildCoordinator': coordinator,
        '../services/cascadeService': { _invalidateTopologyCache() {} },
    });
    class Link {
        constructor(fields) { Object.assign(this, fields, { _id: newId, mode: 'reverse', priority: 1 }); }
        set(key, value) { this[key] = value; }
        toObject() { return { ...this }; }
        async save() { rows.set(this._id, this.toObject()); }
    }
    const verify = async () => {};
    const query = rows => ({ select() { return this; }, read() { return this; }, readConcern() { return this; }, lean: async () => rows });
    let conflict = false;
    const admitKcp = link => readKcpAdmission({ find: filter => query(filter.type === 'hysteria'
        ? (conflict ? [{ ip: inventory[0].ip, port: form.tunnelPort }] : []) : inventory) }, [link], inventory, new Map());
    const service = {
        locks: { async run(task) {
            const result = await task(verify);
            if (failAfterSave) throw new Error('private lock-cleanup diagnostic');
            return result;
        } },
        verifyDraftKcp: admitKcp,
        execute(req) {
            operations.push(req);
            return coordinator.runRebuild({
                global: task => task(verify), withNodes: (_, task) => task(), links: async () => [...rows.values()],
                nodeRole: id => roles.get(id),
                async build(nodes, desired) {
                    for (const row of desired.filter(l => l.tunnelTransport === 'kcp')) await admitKcp(row);
                    return { candidates: nodes.flatMap(nodeId => [
                        { nodeId, profile: 'main', config: nodeId === from
                            ? config(req.remove ? 'block' : routeTag, protectedChange ? [{ protocol: 'vless', tag: 'client' }] : [])
                            : config('direct') },
                        { nodeId, profile: 'bridge', config: { inbounds: [], routing: { rules: [] } } },
                    ]) };
                },
                read: async (id, profile) => observed.get(`${id}:${profile}`) ?? null,
                async putPair(id, pair) { for (const p of pair) observed.set(`${id}:${p.profile}`, p.config); },
                async finish({ desired, removed }) {
                    for (const row of removed) rows.delete(row._id);
                    for (const row of desired) row.status = 'deployed';
                },
            }, req);
        },
    };
    routerForRebuild({ service, Link, Node: { find: () => query(inventory) } });
    const snapshot = () => ({ nodes: inventory.map(({ _id, cascadeRole, name }) => ({ data: { id: _id, cascadeRole, label: name } })),
        edges: [...rows.values()].map(row => ({ data: { id: `link-${row._id}`, source: row.portalNode, target: row.bridgeNode,
            status: row.status, mode: row.mode } })) });
    async function dispatch(target, method, body, header, session) {
        const routePath = target.pathname.slice(apiRoot.length);
        const parsed = routePath.match(/^\/links\/([a-f0-9]{24})(\/deploy)?$/);
        const handlers = routes.get(`${method} ${parsed ? `/links/:id${parsed[2] || ''}` : routePath}`);
        assert.ok(handlers, `Unscripted request ${method} ${routePath}`);
        const req = { method, params: parsed ? { id: parsed[1] } : {}, body, protocol: 'https', session,
            headers: { origin, host: target.host, 'x-csrf-token': header.get('x-csrf-token') } };
        const receipt = { status: 200 };
        const res = { locals: { lang: labels.lang }, status(code) { receipt.status = code; return this; }, json(data) { receipt.data = data; } };
        let index = 0;
        const next = () => handlers[index++](req, res, next);
        await next();
        assert.ok(Object.hasOwn(receipt, 'data'));
        receipts.push(receipt);
        return receipt;
    }
    return { dispatch, snapshot, operations, receipts, rows, blockKcp: () => { conflict = true; } };
}

async function mount(t, options) {
    const { window: w } = new JSDOM(`<!doctype html><html lang="en"><body><aside class="nm-insp"></aside>${markup}</body></html>`,
        { url: `${origin}/panel/nodes`, runScripts: 'outside-only' });
    const doc = w.document, server = backend(options);
    const get = suffix => doc.getElementById('rebuildPreview' + suffix);
    const dialog = get(''), apply = get('Apply'), cancel = get('Cancel'), details = get('Details'), warning = get('Warning'), title = get('Title');
    let openings = 0;
    dialog.showModal = () => { assert.equal(dialog.open, false); dialog.open = true; openings++; };
    dialog.close = () => {
        if (!dialog.open) return;
        dialog.open = false;
        w.queueMicrotask(() => dialog.dispatchEvent(new w.Event('close')));
    };
    const i18n = doc.createElement('script');
    i18n.id = 'networkI18n';
    i18n.type = 'application/json';
    i18n.textContent = JSON.stringify({ ...network, map: { ...network.map, rebuild } });
    doc.body.append(i18n);
    w._networkRebuildPreviewI18n = labels;
    w._networkCsrfToken = key;
    const notes = [], calls = [], transportErrors = [], handlers = new Map();
    w.addEventListener('error', event => transportErrors.push(event.error));
    w.showToast = (message, type) => notes.push({ message, type });
    w.eval(sharedPreview);
    const serverSession = { authenticated: true, panelCsrfToken: key };
    w.fetch = async (url, init) => {
        const target = new URL(url, origin), body = init.body ? JSON.parse(init.body) : null, header = new Headers(init.headers);
        calls.push({ method: init.method, path: target.pathname, body });
        const respond = (data, { status = 200, location = target.href, contentType = 'application/json', redirected = false } = {}) => ({
            status, ok: status >= 200 && status < 300, url: location, redirected,
            headers: new Headers({ 'Content-Type': contentType }), json: async () => structuredClone(data),
        });
        const checked = async task => { try { return await task(); } catch (error) { transportErrors.push(error); throw error; } };
        await checked(() => {
            assert.equal(target.origin, origin);
            if (target.pathname !== topology) assert.equal(init.mode, 'same-origin');
            assert.equal(init.cache, 'no-store');
            assert.equal(init.credentials, 'same-origin');
            assert.equal(init.redirect, 'error');
            assert.equal(header.get('authorization'), null);
            if (init.method !== 'GET') {
                assert.equal(header.get('content-type'), 'application/json');
                assert.ok(header.has('x-csrf-token'));
                assert.equal(Object.hasOwn(body, '_csrf'), false);
            }
        });
        const forward = () => checked(async () => {
            if (target.pathname === topology && init.method === 'GET') return respond(server.snapshot());
            const { data, status } = await server.dispatch(target, init.method, body, header, serverSession);
            return respond(data, { status });
        });
        const override = handlers.get(`${init.method} ${target.pathname}`);
        return override ? override(body, respond, forward) : forward();
    };
    w.eval(bundle);
    const store = w.fixture.createStore({ isVisible: () => true });
    const actions = w.fixture.createActions(store);
    const inspector = doc.querySelector('.nm-insp');
    const { render } = w.fixture.createInspector(inspector, { store, actions });
    store.on('data', render);
    store.on('select', render);
    t.after(() => { store.destroy(); w.close(); assert.deepEqual(transportErrors, []); });
    await store.load();
    assert.equal(store.index.links.has(edgeId), true);
    store.select({ kind: 'link', id: edgeId });
    assert.deepEqual(calls.splice(0), [{ method: 'GET', path: topology, body: null }]);
    const click = name => {
        const button = [...inspector.querySelectorAll('.nm-link-actions button')]
            .find(el => el.textContent === network.map.linkActions[name]);
        assert.ok(button, `Missing inspector button: ${name}`);
        button.click();
    };
    function assertRefusal(message) {
        assert.equal(dialog.open, true);
        assert.equal(title.textContent, labels.refused);
        assert.equal(cancel.textContent, labels.close);
        assert.equal(warning.hidden, false);
        assert.equal(warning.textContent, message);
        assert.equal(apply.hidden, true);
        apply.click(); // Even a dispatched click on the hidden Apply must be inert.
        assert.equal(dialog.open, true);
    }
    return { w, store, actions, inspector, server, dialog, apply, cancel, details, warning, title, calls, notes, serverSession,
        handlers, click, assertRefusal, get openings() { return openings; } };
}

for (const [name, method, route, removing] of [
    ['deploy', 'POST', deploy, false], ['deployChain', 'POST', chain, false], ['remove', 'DELETE', remove, true],
]) test(`${name}: inspector, production preview, explicit Apply, one scoped write and fresh topology`, async t => {
    const ui = await mount(t);
    const inFlight = deferred();
    ui.handlers.set(`${method} ${route}`, (_, _respond, forward) => inFlight.promise.then(forward));
    assert.deepEqual(ui.calls, []);
    ui.click(name); ui.click(name); // Before the preview arrives.
    await tick();
    const previewCall = { method: 'POST', path: preview, body: { linkId, ...(removing && { remove: true }) } };
    assert.deepEqual(ui.calls, [previewCall]);
    assert.equal(ui.dialog.open, true);
    assert.equal(ui.openings, 1);
    const report = ui.server.receipts[0].data;
    assert.match(report.previewId, /^[a-f0-9]{128}$/);
    assert.equal(report.allowed, true);
    assert.equal(ui.title.textContent, removing ? labels.removeTitle : labels.deployTitle);
    assert.equal(ui.apply.textContent, removing ? labels.remove : labels.apply);
    assert.equal(ui.apply.hidden, false);
    assert.equal(ui.cancel.textContent, labels.cancel);
    assert.ok(ui.details.textContent.includes(`Fixture portal — ${labels.portal}:`));
    assert.ok(ui.details.textContent.includes(`Fixture gateway — ${labels.bridge}:`));
    assert.ok(ui.details.textContent.includes(labels.settingsUnchanged));
    assert.equal(ui.warning.hidden, !removing);
    if (removing) {
        assert.equal(report.nodes.find(n => n.nodeId === from).exitImpact, 'lost');
        assert.equal(ui.warning.textContent, labels.exitLost.replace('{name}', 'Fixture portal'));
    }
    ui.click(name);
    ui.click(name === 'deployChain' ? 'deploy' : 'deployChain');
    assert.deepEqual(ui.calls, [previewCall]);
    ui.apply.click(); ui.apply.click();
    await tick();
    assert.equal(ui.dialog.open, false);
    assert.equal(ui.actions.isBusy(), true);
    assert.equal(ui.store.index.links.get(edgeId).status, 'pending', 'no optimistic status');
    ui.click(name);
    const write = { method, path: route, body: { ...(name === 'deployChain' && { linkId }), expectedPreview: report.previewId } };
    assert.deepEqual(ui.calls, [previewCall, write]);
    inFlight.resolve();
    await tick();
    assert.deepEqual(ui.calls, [previewCall, write, { method: 'GET', path: topology, body: null }]);
    assert.equal(ui.actions.isBusy(), false);
    assert.equal(ui.store.index.links.get(edgeId)?.status, removing ? undefined : 'deployed');
    assert.equal(ui.store.state.selection?.id, removing ? undefined : edgeId);
    assert.equal(ui.notes.at(-1)?.message, removing ? rebuild.removed : rebuild.applied);
});

test('invalid or missing selections and Cancel never Apply', async t => {
    const ui = await mount(t);
    for (const id of [linkId, `cdn-${linkId}`, `link-${newId}`, `${edgeId}\n`, null]) assert.equal(await ui.actions.deploy(id), false);
    assert.deepEqual(ui.calls, []);
    ui.click('remove');
    await tick();
    assert.equal(ui.dialog.open, true);
    ui.cancel.click(); ui.apply.click();
    await tick();
    assert.equal(ui.dialog.open, false);
    assert.equal(ui.actions.isBusy(), false);
    assert.deepEqual(ui.calls.map(c => c.path), [preview]);
    assert.equal(ui.store.index.links.get(edgeId).status, 'pending');
});

test('virtual CDN and Internet selections expose no inspector actions or write authority', async t => {
    const ui = await mount(t);
    const view = ui.server.snapshot();
    view.nodes.push({ data: { id: 'cdn', type: 'cdn', label: 'Fixture CDN' } }, { data: { id: 'internet', type: 'internet' } });
    view.edges.push({ data: { id: cdnEdge, source: 'cdn', target: from, isCdnEdge: true } },
        { data: { id: internetEdge, source: to, target: 'internet', isInternetEdge: true } });
    ui.handlers.set(`GET ${topology}`, (_, respond) => respond(view));
    await ui.store.refresh();
    ui.store.select({ kind: 'link', id: cdnEdge });
    assert.equal(ui.inspector.classList.contains('open'), true);
    assert.equal(ui.inspector.querySelector('.nm-link-actions'), null);
    ui.store.select({ kind: 'node', id: 'internet' });
    assert.equal(ui.inspector.classList.contains('open'), true);
    assert.equal(ui.inspector.querySelector('.nm-link-actions'), null);
    for (const id of [cdnEdge, internetEdge]) assert.equal(await ui.actions.deploy(id), false);
    assert.deepEqual(ui.calls.map(call => call.path), [topology]);
});

test('coordinator protection refusal displays settings and removal impact, with no Apply', async t => {
    const ui = await mount(t, { protectedChange: true });
    ui.click('remove');
    await tick();
    ui.assertRefusal(labels.exitLost.replace('{name}', 'Fixture portal'));
    assert.ok(ui.details.textContent.includes(labels.settingsChanged));
    assert.equal(ui.server.receipts[0].data.allowed, false);
    ui.cancel.click();
    await tick();
    assert.equal(ui.dialog.open, false);
    assert.equal(ui.actions.isBusy(), false);
    assert.deepEqual(ui.calls.map(c => c.path), [preview]);
    assert.equal(ui.store.state.selection.id, edgeId);
});

test('invalid preview ID receives the real refusal dialog and cannot Apply', async t => {
    const ui = await mount(t);
    ui.handlers.set(`POST ${preview}`, async (_, respond, forward) => {
        const report = await (await forward()).json();
        return respond({ ...report, previewId: `${report.previewId}\n` });
    });
    ui.click('deploy');
    await tick();
    ui.assertRefusal(rebuild.previewUnavailable);
    ui.cancel.click();
    await tick();
    assert.equal(ui.actions.isBusy(), false);
    assert.deepEqual(ui.calls.map(c => c.path), [preview]);
});

// Only these adversarial controller tests replace the confirmation entry point.
describe('controller token adversaries (not dialog integration)', () => {
    const malformed = [
        ['absent report', () => null],
        ['allowed string', r => ({ ...r, allowed: 'true' })],
        ['empty nodes', r => ({ ...r, nodes: [] })],
        ['invalid node', r => { r.nodes[0].nodeId = 'n'; return r; }],
        ['newline padded node ID', r => { r.nodes[0].nodeId = `${from.slice(1)}\n`; return r; }],
        ['missing profile', r => { r.nodes[0].profiles.pop(); return r; }],
        ['missing protection bit', r => { delete r.nodes[0].profiles[0].protectedChanged; return r; }],
        ['uppercase preview ID', r => ({ ...r, previewId: 'A'.repeat(128) })],
        ['trailing newline', r => ({ ...r, previewId: `${r.previewId}\n` })],
    ];
    for (const [name, alter] of malformed) test(`${name} cannot be approved by an override`, async t => {
        const ui = await mount(t);
        ui.handlers.set(`POST ${preview}`, async (_, respond, forward) => respond(alter(await (await forward()).json())));
        let confirmations = 0;
        ui.w.C3RebuildPreview = { ...ui.w.C3RebuildPreview, confirmReport: () => { confirmations++; return oldToken; } };
        const pending = ui.actions.deploy(edgeId);
        await tick();
        ui.assertRefusal(rebuild.previewUnavailable);
        ui.cancel.click();
        assert.equal(await pending, false);
        assert.equal(confirmations, 0);
        assert.deepEqual(ui.calls.map(c => c.path), [preview]);
    });

    for (const mode of ['denied', 'protected', 'wrong token', 'changed report']) test(`${mode}: override cannot authorize Apply`, async t => {
        const ui = await mount(t);
        ui.handlers.set(`POST ${preview}`, async (_, respond, forward) => {
            const report = await (await forward()).json();
            if (mode === 'denied') report.allowed = false;
            if (mode === 'protected') report.nodes[0].profiles[0].protectedChanged = true;
            return respond(report);
        });
        ui.w.C3RebuildPreview = { ...ui.w.C3RebuildPreview, confirmReport: ({ report }) => {
            if (mode === 'changed report') report.previewId = oldToken;
            return mode === 'wrong token' ? oldToken : report.previewId;
        } };
        const pending = ui.actions.deploy(edgeId);
        await tick();
        if (mode === 'wrong token' || mode === 'changed report') {
            ui.assertRefusal(rebuild.previewUnavailable);
            ui.cancel.click();
        } else {
            assert.equal(ui.dialog.open, false);
        }
        assert.equal(await pending, false);
        assert.deepEqual(ui.calls.map(c => c.path), [preview]);
    });
});

for (const [stage, copy] of [
    ['missing page token', 'sessionChanged'], ['changed page token', 'sessionChanged'], ['changed server session', 'sessionChanged'],
    ['stale', 'previewChanged'], ['legacy token', 'previewChanged'], ['network', 'writeUnconfirmed'], ['unconfirmed reply', 'writeUnconfirmed'],
]) test(`${stage}: show refusal, no retry or re-preview`, async t => {
    const ui = await mount(t);
    if (stage === 'missing page token') delete ui.w._networkCsrfToken;
    if (stage === 'legacy token') ui.handlers.set(`POST ${preview}`, async (_, respond, forward) =>
        respond({ ...await (await forward()).json(), previewId: oldToken }));
    if (stage === 'network') ui.handlers.set(`POST ${deploy}`, () => { throw new Error('private fixture diagnostic'); });
    if (stage === 'unconfirmed reply') ui.handlers.set(`POST ${deploy}`, (_, respond) => respond({ success: true }));
    const pending = ui.actions.deploy(edgeId);
    await tick();
    if (stage === 'changed page token') ui.w._networkCsrfToken = otherKey;
    if (stage === 'changed server session') ui.serverSession.panelCsrfToken = otherKey;
    if (stage === 'stale') ui.server.rows.get(linkId).priority = 2;
    if (stage !== 'missing page token') {
        assert.equal(ui.dialog.open, true);
        assert.equal(ui.apply.hidden, false);
        assert.deepEqual(ui.calls.map(c => c.path), [preview]);
        ui.apply.click();
        await tick();
    }
    ui.assertRefusal(rebuild[copy]);
    ui.cancel.click();
    assert.equal(await pending, false);
    const submitted = !['missing page token', 'changed page token'].includes(stage);
    assert.deepEqual(ui.calls.map(c => c.path), stage === 'missing page token' ? [] : submitted ? [preview, deploy, topology] : [preview]);
    const executed = ui.server.operations.filter(op => !op.preview);
    assert.equal(executed.length, ['stale', 'legacy token'].includes(stage) ? 1 : 0);
    if (stage === 'legacy token') assert.equal(executed[0].expectedPreview, oldToken);
});

test('foreign/redirected and non-JSON replies cannot open a confirmable preview', async t => {
    for (const options of [{ location: 'https://not-panel.invalid/' }, { redirected: true }, { contentType: 'text/html' }]) {
        const ui = await mount(t);
        ui.handlers.set(`POST ${preview}`, async (_, respond, forward) => respond(await (await forward()).json(), options));
        const pending = ui.actions.deploy(edgeId);
        await tick();
        ui.assertRefusal(rebuild.previewUnavailable);
        assert.equal(ui.openings, 1);
        ui.cancel.click();
        assert.equal(await pending, false);
        assert.deepEqual(ui.calls.map(c => c.path), [preview]);
    }
});

for (const outcome of ['applied', 'cancelled', 'preview refusal', 'apply refusal', 'save refusal', 'partial save reply', 'lost save reply', 'invalid saved id', 'unexpected acceptance']) {
    test(`create → ${outcome}: save-only, separate preview and draft-aware result`, async t => {
        const ui = await mount(t, { failAfterSave: outcome === 'partial save reply' });
        if (outcome === 'save refusal') ui.server.blockKcp();
        ui.handlers.set(`POST ${links}`, async (_, respond, forward) => {
            const reply = await forward();
            if (outcome === 'lost save reply') throw new Error('unknown fixture diagnostic');
            if (outcome === 'invalid saved id') return respond({ ...await reply.json(), linkId: 'invalid' });
            if (outcome === 'unexpected acceptance') return respond({ ...await reply.json(), status: 'waiting' }, { status: 202 });
            return reply;
        });
        if (outcome === 'preview refusal' || outcome === 'apply refusal') {
            ui.handlers.set(`POST ${outcome === 'preview refusal' ? preview : newDeploy}`, (_, _respond, forward) => {
                ui.server.blockKcp();
                return forward();
            });
        }
        // The joined entry does not mount a modern create form. Call the real
        // controller directly here; confirmation still uses the shared DOM.
        const pending = ui.actions.createAndDeploy({ ...form, autoDeploy: true, _csrf: 'ignore', expectedPreview: oldToken });
        assert.equal((await ui.actions.createAndDeploy(form)).status, 'busy');
        const previewed = ['applied', 'cancelled', 'preview refusal', 'apply refusal'].includes(outcome);
        const attemptedApply = ['applied', 'apply refusal'].includes(outcome);
        const desiredSaved = previewed || outcome === 'partial save reply';
        await tick();
        assert.equal(ui.dialog.open, true);
        const previewId = ui.server.receipts[1]?.data?.previewId;
        if (attemptedApply || outcome === 'cancelled') {
            assert.equal(ui.apply.hidden, false);
            assert.match(previewId, /^[a-f0-9]{128}$/);
            assert.deepEqual(ui.calls.map(c => c.path), [links, preview]);
            (outcome === 'cancelled' ? ui.cancel : ui.apply).click();
            await tick();
        }
        if (!['applied', 'cancelled'].includes(outcome)) {
            const issue = 'Node Fixture portal: UDP port 24444 is already reserved. Choose a different mKCP port.';
            ui.assertRefusal(outcome.includes('refusal') ? issue : rebuild.saveUnconfirmed);
            assert.equal(ui.store.index.links.has(`link-${newId}`), outcome !== 'save refusal', 'readback completes before dismissing refusal');
            assert.equal(ui.actions.isBusy(), true);
            ui.cancel.click();
        } else {
            assert.equal(ui.dialog.open, false);
        }
        const status = outcome === 'applied' ? 'applied' : desiredSaved ? 'saved' : outcome === 'save refusal' ? 'not_saved' : 'unknown';
        assert.deepEqual({ ...await pending }, { status, desiredSaved, linkId: desiredSaved ? newId : null });
        assert.deepEqual(ui.calls, [{ method: 'POST', path: links, body: form },
            ...(previewed ? [{ method: 'POST', path: preview, body: { linkId: newId } }] : []),
            ...(attemptedApply ? [{ method: 'POST', path: newDeploy, body: { expectedPreview: previewId } }] : []),
            { method: 'GET', path: topology, body: null }]);
        assert.equal(ui.store.index.links.get(`link-${newId}`)?.status,
            outcome === 'save refusal' ? undefined : outcome === 'applied' ? 'deployed' : 'pending');
        if (desiredSaved && status !== 'applied') assert.deepEqual(ui.notes.at(-1), { message: rebuild.draftSaved, type: 'warning' });
    });
}

test('health uses projected status, not healthy, and never optimistically rewrites the map', async t => {
    const ui = await mount(t);
    ui.handlers.set(`GET ${health}`, (_, respond) => {
        assert.equal(ui.store.index.links.get(edgeId).status, 'pending');
        ui.server.rows.get(linkId).status = 'deployed';
        return respond({ status: 'deployed', healthy: true, tunnelVerification: 'mkcp_runtime_unsupported' });
    });
    ui.click('checkHealth');
    await tick();
    assert.deepEqual(ui.calls.map(c => [c.method, c.path]), [['GET', health], ['GET', topology]]);
    assert.equal(ui.store.index.links.get(edgeId).status, 'deployed');
    assert.deepEqual(ui.notes[0], { message: rebuild.healthStatus.replace('{status}', network.map.status.deployed), type: 'warning' });
});

test('a missing or blocked health reply does not claim online', async t => {
    for (const [status, body] of [[200, { healthy: true }], [410, { error: { code: 'REBUILD_ROUTE_DISABLED' } }]]) {
        const ui = await mount(t);
        ui.handlers.set(`GET ${health}`, (_, respond) => respond(body, { status }));
        assert.equal(await ui.actions.checkHealth(edgeId), false);
        assert.equal(ui.notes.some(note => note.type === 'success'), false);
        assert.equal(ui.store.index.links.get(edgeId).status, 'pending');
    }
});

test('an in-flight pre-write poll is discarded and cannot satisfy the post-write read', async t => {
    const ui = await mount(t);
    const poll = deferred(), staleSnapshot = ui.server.snapshot();
    ui.handlers.set(`GET ${topology}`, (_, respond) => poll.promise.then(() => respond(staleSnapshot)));
    const runningPoll = ui.store.refresh();
    await tick();
    ui.handlers.delete(`GET ${topology}`);
    const observed = [];
    ui.store.on('data', () => observed.push(ui.store.index.links.get(edgeId).status));
    const pending = ui.actions.deploy(edgeId);
    await tick(); ui.apply.click();
    await tick();
    assert.deepEqual(ui.calls.map(c => c.path), [topology, preview, deploy]);
    assert.equal(ui.actions.isBusy(), true);
    poll.resolve();
    await runningPoll;
    assert.equal(await pending, true);
    assert.deepEqual(ui.calls.map(c => c.path), [topology, preview, deploy, topology]);
    assert.deepEqual(observed, ['deployed']);
});

test('a page-session change after a save never previews or applies under the new session', async t => {
    const ui = await mount(t);
    ui.handlers.set(`POST ${links}`, async (_, _respond, forward) => {
        const receipt = await forward();
        ui.w._networkCsrfToken = ui.serverSession.panelCsrfToken = otherKey;
        return receipt;
    });
    const pending = ui.actions.createAndDeploy(form);
    await tick();
    ui.assertRefusal(rebuild.sessionChanged);
    ui.cancel.click();
    assert.deepEqual({ ...await pending }, { status: 'saved', desiredSaved: true, linkId: newId });
    assert.deepEqual(ui.calls.map(c => c.path), [links, topology]);
});

test('health localizes staged without changing map edge labels', async t => {
    const ui = await mount(t);
    ui.handlers.set(`GET ${health}`, (_, respond) => respond({ status: 'staged', healthy: false }));
    assert.equal(await ui.actions.checkHealth(edgeId), true);
    assert.equal(ui.notes[0].message, rebuild.healthStatus.replace('{status}', rebuild.healthStaged));
    assert.equal(ui.store.index.links.get(edgeId).status, 'pending');
});
