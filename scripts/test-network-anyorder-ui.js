'use strict';

// Local VM/DOM/API evidence only. No browser, HTTP server, DB or node transport.
// [shipped] characterizes working current contracts; [spec-red] is deliberately
// failing acceptance coverage of gaps reproducible with those same contracts.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../public/js/network.js'), 'utf8');
const helpers = require('../public/js/network.js');
const id = n => n.toString(16).padStart(24, '0');
const P = id(1), R = id(2), B1 = id(3), B2 = id(4);
const nodes = [
    { _id: P, name: 'Portal', cascadeRole: 'portal' },
    { _id: R, name: 'Relay', cascadeRole: 'relay' },
    { _id: B1, name: 'Bridge 1', cascadeRole: 'bridge' },
    { _id: B2, name: 'Bridge 2', cascadeRole: 'bridge' },
];
const link = (n, from, to, extra = {}) => ({ _id: id(n), name: 'Link ' + n,
    portalNode: from, bridgeNode: to, active: true, status: 'pending', mode: 'reverse',
    tunnelPort: 10000 + n, tunnelProtocol: 'vless', tunnelTransport: 'tcp',
    tunnelSecurity: 'none', priority: n, ...extra });
const snapshot = (links = [], revision = 7) => ({ topologyRevision: revision, deployedRevision: 6, links });
const reply = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
    async json() { return JSON.parse(JSON.stringify(body)); } });
const tick = () => new Promise(resolve => setImmediate(resolve));

function harness(t, initial = snapshot()) {
    const requests = [], toasts = [], confirmations = [], timers = [], pendingReplies = [];
    const unexpected = [], errors = [], items = new Map(), elements = new Map();
    const state = { snapshot: initial, operations: new Map(), jobs: new Map(), confirm: true,
        pan: { x: 0, y: 0 }, zoom: 1, fits: 0, layouts: 0 };
    const collection = entries => Object.assign(entries, {
        toArray: () => entries,
        data(...args) { return entries[0]?.data(...args); },
        // Cytoscape filter returns a collection, not an ordinary array.
        filter(fn) { return collection(Array.prototype.filter.call(entries, fn)); },
    });
    const graph = {
        nodes: () => collection([...items.values()].filter(x => x.group === 'nodes')),
        edges: () => collection([...items.values()].filter(x => x.group === 'edges')),
        getElementById: key => items.get(key) || { length: 0 },
        elements: () => ({ remove() { items.clear(); }, unselect() {} }),
        batch: fn => fn(),
        add(entries) {
            const nodeIds = new Set(entries.filter(x => x.group === 'nodes').map(x => x.data.id));
            for (const x of entries) {
                if (x.group === 'edges') assert(nodeIds.has(x.data.source) && nodeIds.has(x.data.target));
                const values = { ...x.data };
                const entry = { group: x.group, length: 1, id: () => values.id,
                    position(value) { if (value) this.point = { ...value }; return { ...this.point }; },
                    point: { ...(x.position || { x: 0, y: 0 }) },
                    data(key, value) {
                        if (key === undefined) return values;
                        if (arguments.length === 2) values[key] = value;
                        return values[key];
                    } };
                items.set(values.id, entry);
            }
        },
        pan(value) { if (value) state.pan = { ...value }; return { ...state.pan }; },
        zoom(value) { if (value != null) state.zoom = value; return state.zoom; },
        fit() { state.fits++; state.pan = { x: -1, y: -1 }; state.zoom = 0.5; },
        layout: () => ({ run() { state.layouts++; } }),
    };
    function element(key, value = '') {
        const classes = new Set();
        const el = { value, checked: false, disabled: false, textContent: '', innerHTML: '', style: {},
            classList: { add: name => classes.add(name), remove: name => classes.delete(name),
                contains: name => classes.has(name), toggle(name, on) { if (on) classes.add(name); else classes.delete(name); } },
            querySelector: () => null, querySelectorAll: () => [], addEventListener() {}, appendChild() {} };
        elements.set(key, el);
        return el;
    }
    const form = element('addLinkForm');
    for (const name of ['name', 'mode', 'tunnelPort', 'tunnelProtocol', 'tunnelTransport', 'tunnelSecurity',
        'muxConcurrency', 'priority', 'tunnelDomain', 'realitySni', 'realityPrivateKey', 'realityPublicKey',
        'realityShortIds', 'realityDest', 'realityFingerprint', 'autoDeploy', 'muxEnabled']) form[name] = element('form-' + name);
    for (const key of ['addLinkModal', 'selectPortal', 'selectBridge', 'linkModalTitle', 'linkModalSubmit',
        'linkAutoDeployLabel', 'linkIdInput', 'geoRoutingEnabled', 'geoRoutingFields', 'geoRoutingDomains',
        'geoRoutingGeoip', 'realitySection', 'tunnelDomainGroup', 'modeHint', 'modeSwitcher',
        'nodeInfoTitleText', 'nodeInfoBody', 'nodeInfoModal', 'btnDeploy', 'btnDeployChain', 'btnDelete',
        'quickLinkModal', 'quickLinkSubmit', 'quickPortalId', 'quickBridgeId', 'quickLinkName',
        'quickLinkMode', 'quickTunnelPort', 'quickTunnelProtocol', 'quickAutoDeploy']) element(key);
    // Controls queried by name and by ID must be the same object.
    form.portalNodeId = elements.get('selectPortal'); form.bridgeNodeId = elements.get('selectBridge');
    form.linkId = elements.get('linkIdInput');
    const submit = elements.get('linkModalSubmit');
    form.querySelector = selector => selector === '[type="submit"]' ? submit : null;
    form.reset = () => { form.linkId.value = ''; form.autoDeploy.checked = true; };
    form.realityFingerprint.options = [{ value: 'random' }];
    const document = { readyState: 'loading', addEventListener() {},
        getElementById: key => elements.get(key) || null,
        querySelector(selector) {
            const match = selector.match(/^#addLinkForm \[name="([^"]+)"\]$/);
            if (match) return form[match[1]] || null;
            if (['.info-loading', '.network-loading', '.network-container'].includes(selector)) return null;
            throw Error('Unsupported DOM selector: ' + selector);
        }, createElement: () => element(Symbol('created')) };
    const topology = () => ({ nodes: nodes.map(n => ({ data: { id: n._id, label: n.name, cascadeRole: n.cascadeRole } })),
        edges: state.snapshot.links.map(l => ({ data: { ...l, id: 'link-' + l._id, linkId: l._id,
            source: l.portalNode, target: l.bridgeNode, label: l.name } })) });
    const fetch = async (url, options = {}) => {
        const request = { url, method: options.method || 'GET', headers: options.headers || {},
            ...(options.body ? { body: JSON.parse(options.body) } : {}) };
        requests.push(request);
        const index = pendingReplies.findIndex(r => r.url === url && r.method === request.method);
        if (index !== -1) return pendingReplies.splice(index, 1)[0].respond(request);
        if (request.method === 'GET') {
            if (url === '/api/nodes') return reply(nodes);
            if (url === '/api/cascade/topology') return reply(topology());
            if (url === '/api/cascade/links') return reply(state.snapshot);
            const operationId = url.split('/api/cascade/topology/operations/')[1];
            if (state.operations.has(operationId)) return reply(state.operations.get(operationId));
            const jobId = url.split('/api/cascade/links/auto-deploy-jobs/')[1];
            if (state.jobs.has(jobId)) return reply({ autoDeployJob: state.jobs.get(jobId) });
            const found = state.snapshot.links.find(l => url === '/api/cascade/links/' + l._id);
            if (found) return reply(found);
        }
        unexpected.push(request);
        throw Error('Unexpected local fixture request: ' + request.method + ' ' + url);
    };
    const window = { crypto: { randomUUID }, _networkCsrfToken: 'local-csrf',
        _networkI18n: require('../src/locales/ru.json').network,
        showToast: (message, type) => toasts.push({ message, type }) };
    // Same VM boot-boundary seam as test-network-edit-ui.js/layout-preservation.
    // Keep real loadTopology, refreshStatuses, renderGraph, handlers and polling.
    const boundary = '    // ==================== START ====================';
    const instrumented = source.replace(boundary, `    cy = window.__graph;
    initParticleSystem = function () {};
    applyLinkSnapshot(window.__snapshot);
    window.__ui = { openAddLinkModal, openEditLinkModal, onAddLinkSubmit, onQuickLinkSubmit,
        onEdgeTap, loadTopology, refreshStatuses, buildRouteSummary, handleLinkAutoDeploy };
${boundary}`);
    assert.notEqual(instrumented, source, 'real browser boot boundary must exist');
    window.__graph = graph; window.__snapshot = initial;
    vm.runInNewContext(instrumented, { window, document, fetch, cytoscape() {},
        confirm: message => { confirmations.push(message); return state.confirm; },
        alert: message => { throw Error('Unexpected alert: ' + message); },
        setTimeout(fn, delay) { const timer = { fn, delay, cancelled: false, ran: false }; timers.push(timer); return timers.length; },
        clearTimeout(key) { if (timers[key - 1]) timers[key - 1].cancelled = true; },
        console: { error: (...args) => errors.push(args), log() {} } });
    t.after(() => {
        assert.deepEqual(unexpected, [], 'test must not silently accept unimplemented API routes');
        assert.deepEqual(errors, [], 'real graph loader must not hide harness errors');
        assert.equal(pendingReplies.length, 0, 'each configured response must be consumed');
    });
    return { state, requests, toasts, confirmations, timers, elements, graph, form,
        window, ui: window.__ui,
        respond(method, url, body, status = 200, after = () => {}) {
            pendingReplies.push({ method, url, respond(request) { after(request); return reply(body, status); } });
        },
        async load() { await window.__ui.loadTopology(); await tick(); },
        async submit(row, autoDeploy, quick = false) {
            if (quick) {
                for (const [key, value] of Object.entries({ quickLinkName: row.name, quickLinkMode: row.mode,
                    quickPortalId: row.portalNode, quickBridgeId: row.bridgeNode,
                    quickTunnelPort: String(row.tunnelPort), quickTunnelProtocol: row.tunnelProtocol })) elements.get(key).value = value;
                elements.get('quickAutoDeploy').checked = autoDeploy;
                await window.__ui.onQuickLinkSubmit({ preventDefault() {} });
            } else {
                await window.__ui.openAddLinkModal();
                for (const [key, value] of Object.entries({ name: row.name, mode: row.mode,
                    portalNodeId: row.portalNode, bridgeNodeId: row.bridgeNode, tunnelPort: String(row.tunnelPort),
                    tunnelProtocol: row.tunnelProtocol, tunnelTransport: row.tunnelTransport,
                    tunnelSecurity: row.tunnelSecurity, priority: String(row.priority) })) form[key].value = value;
                form.autoDeploy.checked = autoDeploy;
                await window.__ui.onAddLinkSubmit({ target: form, preventDefault() {} });
            }
            await tick();
        },
        async poll(delay = helpers.OPERATION_POLL_INTERVAL_MS) {
            const timer = timers.find(x => x.delay === delay && !x.cancelled && !x.ran);
            assert(timer, 'expected an active ' + delay + 'ms poll');
            timer.ran = true; await timer.fn(); await tick(); await tick();
        },
        activeTimers: delay => timers.filter(x => !x.cancelled && !x.ran && (delay === undefined || x.delay === delay)),
        drawer(linkId) { window.__ui.onEdgeTap({ target: graph.getElementById('link-' + linkId) }); return elements.get('nodeInfoBody').innerHTML; },
    };
}

function permutations(entries) {
    return entries.length ? entries.flatMap((entry, i) => permutations(entries.filter((_, j) => j !== i)).map(rest => [entry, ...rest])) : [[]];
}
const graphs = {
    G1: [link(11, P, B1)],
    G2: [link(12, P, R), link(13, R, B1, { mode: 'forward' })],
    G3: [link(14, P, R), link(15, R, B1, { mode: 'forward' }), link(16, R, B2)],
};
const cases = Object.entries(graphs).flatMap(([name, links]) => permutations(links).map(order => ({ name, order })));
const writes = h => h.requests.filter(r => r.method !== 'GET');
const proofNotClaimed = h => assert(!h.toasts.some(x => /готовность подтверждена проверкой клиента/.test(x.message)));

// This matrix proves UI request targeting ONLY: API replies are explicit
// fixtures, not a replacement backend that claims any-order graph admission.
for (const { name, order } of cases) {
    for (const intent of ['auto', 'save/manual']) {
        test(`[shipped] ${name} ${intent}: ${order.map(l => l._id.slice(-2)).join(' > ')}`, async t => {
            const h = harness(t);
            for (const row of order) {
                const next = snapshot([...h.state.snapshot.links, row], h.state.snapshot.topologyRevision + 1);
                const op = { operationId: id(100 + Number.parseInt(row._id, 16)), topologyRevision: next.topologyRevision, status: 'queued' };
                h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: row._id,
                    ...(intent === 'auto' ? { autoDeployOperation: op } : {}) }, 201, () => { h.state.snapshot = next; });
                await h.submit(row, intent === 'auto');
                const request = writes(h).at(-1);
                assert.equal(request.url, '/api/cascade/links');
                assert.equal(request.body.portalNodeId, row.portalNode);
                assert.equal(request.body.bridgeNodeId, row.bridgeNode);
                assert.equal(request.body.mode, row.mode, 'mixed modes must not be unified');
                assert.equal(request.body.autoDeploy, intent === 'auto');
                assert.equal(request.body.expectedTopologyRevision, next.topologyRevision - 1);
                if (intent === 'auto') {
                    h.state.operations.set(op.operationId, { ...op, status: 'succeeded', clientReadiness: 'unverified', clientProofState: 'degraded' });
                    await h.poll();
                    assert(h.requests.some(r => r.url === '/api/cascade/topology/operations/' + op.operationId));
                } else assert.equal(h.activeTimers().length, 0, 'save-only must not schedule apply');
            }
            if (intent === 'save/manual') {
                for (const row of [...order].reverse()) {
                    const op = { operationId: id(200 + Number.parseInt(row._id, 16)), topologyRevision: h.state.snapshot.topologyRevision, status: 'queued', kind: 'link.apply' };
                    h.respond('POST', '/api/cascade/topology/deploy', op, 202);
                    await h.window._cascadeDeploy(row._id); await tick();
                    assert.deepEqual(writes(h).at(-1).body, { expectedTopologyRevision: h.state.snapshot.topologyRevision, linkId: row._id }, 'do not send sibling pending links or full Sync');
                    h.state.operations.set(op.operationId, { operationId: op.operationId, topologyRevision: op.topologyRevision, status: 'succeeded', clientReadiness: 'unverified', clientProofState: 'degraded' });
                    await h.poll();
                }
            }
            assert.equal(writes(h).filter(r => r.url === '/api/cascade/topology/deploy').length, intent === 'auto' ? 0 : order.length);
            assert(!writes(h).some(r => r.url.endsWith('/deploy') && !r.body.linkId));
            proofNotClaimed(h);
        });
    }
}

test('[shipped] quick create consumes the existing durable job, then polls its exact admitted operation', async t => {
    const h = harness(t), job = { jobId: id(300), status: 'waiting', acceptanceRevision: 7 };
    h.respond('POST', '/api/cascade/links', { autoDeployJob: job, acceptedTopologyRevision: 7 }, 202);
    await h.submit(graphs.G2[1], true, true);
    assert.equal(h.state.snapshot.links.length, 0, 'acceptance fixture is not a created draft');
    assert(h.toasts.some(x => x.message.includes(job.jobId) && /принят/.test(x.message)));
    proofNotClaimed(h);
    assert.equal(writes(h).length, 1);
    h.state.jobs.set(job.jobId, { ...job, status: 'admitted', operationId: id(301), topologyRevision: 8 });
    await h.poll(1500);
    h.state.operations.set(id(301), { operationId: id(301), status: 'succeeded', topologyRevision: 8, clientReadiness: 'verified' });
    await h.poll();
    assert(h.requests.some(r => r.url === '/api/cascade/links/auto-deploy-jobs/' + job.jobId));
    assert(h.requests.some(r => r.url === '/api/cascade/topology/operations/' + id(301)));
    assert.equal(writes(h).length, 1, 'accepted job must never trigger another POST');
});

test('[shipped] save-only edit of an AutoDeploy link omits activation; classic completion is applied, not client-ready', async t => {
    const row = link(20, P, B1, { autoDeploy: true });
    const h = harness(t, snapshot([row]));
    await h.ui.openEditLinkModal(row._id);
    assert.equal(h.form.autoDeploy.checked, false);
    h.respond('PUT', '/api/cascade/links/' + row._id, snapshot([row], 8));
    await h.ui.onAddLinkSubmit({ target: h.form, preventDefault() {} });
    assert(!Object.hasOwn(writes(h)[0].body, 'autoDeploy'));
    assert.equal(h.activeTimers().length, 0);
    const completed = { status: 'succeeded', executionMode: 'classic', topologyRevision: 7 };
    h.ui.handleLinkAutoDeploy({ ...snapshot([row]), autoDeployResult: completed }, true);
    assert(h.toasts.some(x => /применена \(classic\)/.test(x.message) && /не подтверждена/.test(x.message)));
    proofNotClaimed(h);
});

test('[shipped] operation identity mismatch and newer global revision cannot impersonate success; polling stays bounded', async t => {
    const h = harness(t);
    h.ui.handleLinkAutoDeploy({ autoDeployOperation: { operationId: id(310), status: 'queued' } }, true);
    h.state.snapshot = { ...snapshot(), topologyRevision: 99, deployedRevision: 99 };
    h.state.operations.set(id(310), { operationId: id(311), status: 'succeeded', clientReadiness: 'verified' });
    for (let i = 0; i <= helpers.OPERATION_POLL_MAX_ATTEMPTS; i++) await h.poll();
    assert.equal(h.requests.filter(r => r.url.endsWith('/operations/' + id(310))).length, helpers.OPERATION_POLL_MAX_ATTEMPTS + 1);
    assert.equal(h.activeTimers().length, 0);
    proofNotClaimed(h);
    assert(h.toasts.some(x => /в фоне/.test(x.message)));
    assert.equal(writes(h).length, 0);
});

test('[shipped] applied but unverified keeps polling; degraded, failed and rolled_back stop without a readiness claim', async t => {
    for (const terminal of ['degraded', 'failed', 'rolled_back']) {
        const h = harness(t);
        const operationId = id(320);
        h.ui.handleLinkAutoDeploy({ autoDeployOperation: { operationId, status: 'queued' } }, true);
        h.state.operations.set(operationId, { operationId, status: 'succeeded', clientReadiness: 'unverified' });
        await h.poll();
        assert.equal(h.activeTimers().length, 1);
        h.state.operations.set(operationId, terminal === 'degraded'
            ? { operationId, status: 'succeeded', clientReadiness: 'unverified', clientProofState: 'degraded' }
            : { operationId, status: terminal });
        await h.poll();
        assert.equal(h.activeTimers().length, 0);
        proofNotClaimed(h);
        assert.equal(writes(h).length, 0);
    }
});

test('[shipped] drawer separates saved, applied, connected and staged edge status from revision-bound client proof', async t => {
    for (const status of ['pending', 'deployed', 'online', 'staged']) {
        const row = link(30, P, R, { status });
        const h = harness(t, snapshot([row])); await h.load();
        let html = h.drawer(row._id);
        assert(html.includes('info-status ' + status));
        assert.match(html, /Готовность клиента не подтверждена/);
        const edge = h.graph.getElementById('link-' + row._id);
        if (status === 'online') {
            // readLinkSnapshot only projects a successful proof for online links.
            edge.data('clientReadiness', { topologyRevision: 7, priorDeployedRevision: 6, status: 'ready', clientProbe: 'passed' });
            html = h.drawer(row._id);
            assert.match(html, /Готовность подтверждена проверкой клиента/);
            edge.data('clientReadiness', { topologyRevision: 6, priorDeployedRevision: 6, status: 'ready', clientProbe: 'passed' });
            assert.match(h.drawer(row._id), /Готовность клиента не подтверждена/);
        }
    }
});

test('[shipped] checked DELETE failure retains the row; successful delete/recreate preserves node positions and viewport', async t => {
    const row = link(40, P, R, { status: 'deployed' }), neighbor = link(41, R, B1, { status: 'online' });
    const h = harness(t, snapshot([row, neighbor])); await h.load();
    h.graph.getElementById(P).position({ x: 71, y: 129 });
    h.graph.pan({ x: 19, y: 30 }); h.graph.zoom(1.36);
    const before = { layouts: h.state.layouts, fits: h.state.fits };
    h.respond('DELETE', '/api/cascade/links/' + row._id, { error: { code: 'CLASSIC_DEPLOY_UNCERTAIN', message: 'private config' } }, 409);
    await h.window._cascadeDelete(row._id); await tick();
    assert.equal(h.state.snapshot.links.length, 2);
    assert(!h.toasts.some(x => x.type !== 'error' && /удален|deleted/i.test(x.message)));
    assert(!h.toasts.some(x => /private config/.test(x.message)));
    const remaining = snapshot([neighbor], 8);
    h.respond('DELETE', '/api/cascade/links/' + row._id, remaining, 200, () => { h.state.snapshot = remaining; });
    await h.window._cascadeDelete(row._id); await tick();
    assert.deepEqual(writes(h).at(-1).body, { expectedTopologyRevision: 7 });
    assert.equal(h.graph.getElementById('link-' + row._id).length, 0);
    assert.equal(h.graph.getElementById('link-' + neighbor._id).data('status'), 'online');
    const recreated = link(42, P, R, { tunnelPort: row.tunnelPort });
    const after = snapshot([neighbor, recreated], 9);
    h.respond('POST', '/api/cascade/links', { ...after, createdLinkId: recreated._id }, 201, () => { h.state.snapshot = after; });
    await h.submit(recreated, false);
    assert.deepEqual(h.graph.getElementById(P).position(), { x: 71, y: 129 });
    assert.deepEqual(h.graph.pan(), { x: 19, y: 30 }); assert.equal(h.graph.zoom(), 1.36);
    assert.deepEqual({ layouts: h.state.layouts, fits: h.state.fits }, before);
    assert.equal(writes(h).at(-1).body.tunnelPort, row.tunnelPort);
    assert.equal(h.activeTimers().length, 0);
});

test('[shipped] main create retains its idempotency key across a failed delivery and changes it with the payload', async t => {
    const h = harness(t), row = graphs.G1[0];
    for (const candidate of [row, row, { ...row, tunnelPort: row.tunnelPort + 1 }]) {
        h.respond('POST', '/api/cascade/links', { error: { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' } }, 503);
        await h.submit(candidate, true);
        assert.equal(h.activeTimers().filter(timer => [1500, helpers.OPERATION_POLL_INTERVAL_MS].includes(timer.delay)).length, 0,
            'a rejected request must not schedule job or operation replay');
    }
    const keys = writes(h).map(r => r.headers['Idempotency-Key']);
    assert.match(keys[0], /^[0-9a-f-]{36}$/);
    assert.equal(keys[1], keys[0], 'same logical retry retains request identity');
    assert.notEqual(keys[2], keys[0], 'changed payload needs a new identity');
    assert.equal(writes(h).length, 3, 'only the three explicit submissions are sent');
});

test('[shipped] blocked AutoDeploy says saved but not applied and never falls back to a new Deploy POST', async t => {
    const h = harness(t), row = graphs.G1[0], next = snapshot([row], 8);
    h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: row._id,
        autoDeployStatus: 'blocked', autoDeployError: { code: 'TOPOLOGY_DEPLOY_BUSY', message: 'private backend detail' } }, 201,
    () => { h.state.snapshot = next; });
    await h.submit(row, true);
    assert(h.toasts.some(x => /сохранены/.test(x.message) && /не запущен/.test(x.message)));
    assert(!h.toasts.some(x => /private backend detail/.test(x.message)));
    assert.equal(writes(h).length, 1);
    assert.equal(h.activeTimers().length, 0, 'blocked is a refusal, not durable queued acceptance');
    proofNotClaimed(h);
});

test('[spec-red] successful save-only create must explicitly confirm saved without claiming applied or connected', async t => {
    const h = harness(t), row = graphs.G1[0], next = snapshot([row], 8);
    h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: row._id }, 201,
    () => { h.state.snapshot = next; });
    await h.submit(row, false);
    assert(h.toasts.some(x => /сохранен|сохранён|saved/i.test(x.message)), 'current save-only silently closes the form');
    assert(!h.toasts.some(x => /применен|применён|соединен|соединён|applied|connected/i.test(x.message)));
});

test('[spec-red] quick AutoDeploy must supply an Idempotency-Key for replay-safe durable create acceptance', async t => {
    const h = harness(t), job = { jobId: id(330), status: 'waiting', acceptanceRevision: 7 };
    h.respond('POST', '/api/cascade/links', { autoDeployJob: job, acceptedTopologyRevision: 7 }, 202);
    await h.submit(graphs.G2[1], true, true);
    assert.match(writes(h)[0].headers['Idempotency-Key'] || '', /^[0-9a-f-]{36}$/, 'quick create omits the key, so the service default generates a new key per delivery');
});

for (const status of ['preparing', 'committing', 'succeeded']) {
    test(`[spec-red] AutoDeploy must consume an actually accepted ${status} operation instead of reporting not started`, async t => {
        const h = harness(t), operationId = id(340);
        const next = snapshot([graphs.G1[0]], 8);
        h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: graphs.G1[0]._id,
            autoDeployOperation: { operationId, topologyRevision: 8, status } }, 201, () => { h.state.snapshot = next; });
        await h.submit(graphs.G1[0], true);
        assert(!h.toasts.some(x => x.type === 'error'), 'queueAutoDeploy allows this status, but the UI reports an unstarted AutoDeploy');
        assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 1, 'accepted operation needs exact-ID status/proof tracking');
    });
}

test('[spec-red] staged Portal-to-Relay drawer must not advertise an Internet path with no exit', async t => {
    const row = link(50, P, R, { status: 'staged' });
    const h = harness(t, snapshot([row])); await h.load();
    assert.doesNotMatch(h.drawer(row._id), /Client → Portal → Relay → Internet/, 'buildRouteSummary appends Internet unconditionally to an incomplete prefix');
});

test('[spec-red] applied drawer must not silently include a save-only sibling in the displayed route', async t => {
    const prefix = link(51, P, R, { status: 'deployed' }), pending = link(52, R, B1);
    const h = harness(t, snapshot([prefix, pending])); await h.load();
    assert.doesNotMatch(h.drawer(prefix._id), /Client → Portal → Relay → Bridge 1 → Internet/, 'drawer follows pending edges as though they were applied');
});

test('[spec-red] mixed-mode drawer must not truncate the traffic path at the transport-mode boundary', async t => {
    const prefix = link(53, P, R, { status: 'online' }), suffix = link(54, R, B1, { status: 'online', mode: 'forward' });
    const h = harness(t, snapshot([prefix, suffix])); await h.load();
    const summary = h.ui.buildRouteSummary(h.graph.getElementById('link-' + prefix._id).data());
    assert.match(summary.chain, /Portal → Relay → Bridge 1/, 'reverse/forward does not change user traffic direction');
});

test('[spec-red] deleting the only applied exit must warn about route interruption before dispatch', async t => {
    const row = link(55, R, B1, { status: 'online' });
    const h = harness(t, snapshot([row])); await h.load(); h.state.confirm = false;
    await h.window._cascadeDelete(row._id);
    assert.equal(writes(h).length, 0);
    assert.match(h.confirmations[0], /трафик|пользоват|выход|соединени|маршрут|traffic|user|exit|connect|route/i, 'current confirmation only asks to delete a link');
});

test('[spec-red] rejected legacy undeploy must not announce success on an HTTP error', async t => {
    const row = link(56, P, B1, { status: 'online' });
    const h = harness(t, snapshot([row])); await h.load();
    h.respond('POST', '/api/cascade/links/' + row._id + '/undeploy', { error: { code: 'LEGACY_CASCADE_UNDEPLOY_BUSY' } }, 409);
    await h.window._cascadeUndeploy(row._id); await tick();
    assert(h.toasts.some(x => x.type === 'error'), 'fetch resolves HTTP errors; undeploy currently ignores response.ok');
    assert(!h.toasts.some(x => /undeployed|деплой отменен|отключена/i.test(x.message) && x.type !== 'error'));
});

test('[spec-red] a second accepted operation must not cancel visibility of the first pending operation', async t => {
    const h = harness(t);
    const accepted = [id(350), id(351)];
    for (const operationId of accepted) {
        h.state.operations.set(operationId, { operationId, status: 'queued' });
        h.ui.handleLinkAutoDeploy({ autoDeployOperation: { operationId, status: 'queued' } }, true);
    }
    // Allow one multiplexed timer or separate timers: observable ID tracking,
    // not a prescribed timer implementation, is the acceptance criterion.
    for (const timer of h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS)) {
        timer.ran = true; await timer.fn(); await tick(); await tick();
    }
    const polled = h.requests.filter(r => r.url.startsWith('/api/cascade/topology/operations/')).map(r => r.url.split('/').at(-1));
    assert.deepEqual([...new Set(polled)].sort(), accepted, 'one global operationPollTimer cancels the prior accepted operation');
});
