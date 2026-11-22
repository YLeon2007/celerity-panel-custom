'use strict';

// Local VM/DOM/API evidence only. No browser, HTTP server, DB or node transport.
// [shipped] preserves working contracts; [regression] covers lifecycle repairs.
// Envelopes below follow HTTP 51fd18d and its real-handler acceptance tests.
// Replies model transport/persistence; they do not claim backend execution.
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

function harness(t, initial = snapshot(), locale = 'ru') {
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
        edges: state.snapshot.links.map(l => ({ data: Object.fromEntries(Object.entries({ ...l, id: 'link-' + l._id, linkId: l._id,
            source: l.portalNode, target: l.bridgeNode, label: l.name }).filter(([key]) => ![
                'applicationState', 'routeState', 'tunnelState', 'pppReadiness', 'xrayReadiness', 'desiredVersion',
                'clientReadiness', 'appliedOperationId', 'lifecycle'].includes(key))) })) });
    const fetch = async (url, options = {}) => {
        const request = { url, method: options.method || 'GET', headers: options.headers || {},
            ...(options.body ? { body: JSON.parse(options.body) } : {}) };
        requests.push(request);
        const index = pendingReplies.findIndex(r => r.url === url && r.method === request.method);
        if (index !== -1) return pendingReplies.splice(index, 1)[0].respond(request);
        if (request.method === 'GET') {
            if (url === '/api/nodes') return reply(nodes);
            if (url === '/api/cascade/topology/activation-policy') return reply({ blocked: false });
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
        _networkI18n: require('../src/locales/' + locale + '.json').network,
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
    return { state, requests, toasts, confirmations, timers, elements, graph, form, errors,
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
// publicIntent + acceptedIntentResponse, not a hypothetical delete endpoint.
const v2Job = (n, kind, row, extra = {}) => ({ jobId: id(n), version: 2, kind, linkId: row._id,
    ...(kind === 'link.create' ? { createdLinkId: row._id } : {}),
    desiredVersion: 'a'.repeat(64), desiredSaved: true, status: 'waiting', phase: 'waiting',
    acceptanceRevision: 7, ordinal: n, attempts: 0, ...extra });
const accepted = job => ({ linkId: job.linkId, desiredSaved: true, job,
    ...(job.createdLinkId ? { createdLinkId: job.createdLinkId } : {}),
    ...(job.operationId ? { operationId: job.operationId } : {}),
    acceptedTopologyRevision: job.acceptanceRevision });

test('[v2] main/quick Auto and explicit PUT Auto consume real job alias and retain edit retry keys', async t => {
    for (const kind of ['main', 'quick', 'edit']) {
        const row = graphs.G1[0], h = harness(t, snapshot(kind === 'edit' ? [row] : []));
        const job = v2Job(400, kind === 'edit' ? 'link.apply' : 'link.create', row);
        if (kind === 'edit') {
            await h.ui.openEditLinkModal(row._id); h.form.autoDeploy.checked = true;
            for (const status of [503, 202]) {
                h.respond('PUT', '/api/cascade/links/' + row._id, status === 202 ? accepted(job)
                    : { desiredSaved: true, error: { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE', phase: 'intent.accept', nextAction: 'refresh_topology' } }, status);
                await h.ui.onAddLinkSubmit({ target: h.form, preventDefault() {} });
            }
            assert.equal(writes(h)[0].headers['Idempotency-Key'], writes(h)[1].headers['Idempotency-Key']);
            assert.match(writes(h)[0].headers['Idempotency-Key'] || '', /^[A-Za-z0-9_.:-]{1,128}$/);
            assert(h.toasts.some(x => /сохранен|сохранён|saved/i.test(x.message) && x.type === 'error'));
        } else {
            h.respond('POST', '/api/cascade/links', accepted(job), 202);
            await h.submit(row, true, kind === 'quick');
        }
        assert.equal(h.activeTimers(1500).length, 1, kind + ' tracks actual job alias');
        assert(!h.toasts.some(x => /snapshot/i.test(x.message)));
        const op = { operationId: id(401), kind: 'link.apply', linkId: row._id, status: 'queued', phase: 'waiting' };
        h.respond('GET', '/api/cascade/links/auto-deploy-jobs/' + job.jobId, { job: { ...job, status: 'admitted', operationId: op.operationId } });
        await h.poll(1500);
        h.state.operations.set(op.operationId, { ...op, status: 'succeeded', phase: 'completed', clientReadiness: 'unverified', clientProofState: 'degraded' });
        await h.poll(); proofNotClaimed(h);
    }
});

test('[v2] manual apply accepts job without operation, reuses failed delivery key, and preserves independent jobs', async t => {
    const h = harness(t, snapshot(graphs.G2)), jobs = graphs.G2.map((row, i) => v2Job(410 + i, 'link.apply', row));
    h.respond('POST', '/api/cascade/topology/deploy', {}, 503, () => { throw Error('connection lost'); });
    await h.window._cascadeDeploy(graphs.G2[0]._id);
    for (const job of jobs) {
        h.respond('POST', '/api/cascade/topology/deploy', accepted(job), 202);
        await h.window._cascadeDeploy(job.linkId); await tick();
    }
    assert.match(writes(h)[0].headers['Idempotency-Key'] || '', /^[A-Za-z0-9_.:-]{1,128}$/);
    assert.equal(writes(h)[0].headers['Idempotency-Key'], writes(h)[1].headers['Idempotency-Key']);
    assert.notEqual(writes(h)[1].headers['Idempotency-Key'], writes(h)[2].headers['Idempotency-Key']);
    assert.equal(h.activeTimers(1500).length, 2);
    for (const [i, job] of jobs.entries()) {
        h.respond('GET', '/api/cascade/links/auto-deploy-jobs/' + job.jobId, { job: { ...job, status: 'admitted', operationId: id(420 + i) } });
        await h.poll(1500);
        h.state.operations.set(id(420 + i), { operationId: id(420 + i), kind: 'link.apply', linkId: job.linkId,
            status: i === 0 ? 'succeeded' : 'committing', phase: i === 0 ? 'reconcile_required' : 'waiting',
            waitingReason: i === 0 ? 'TOPOLOGY_RECONCILE_REQUIRED' : 'PPP_SYNC_PENDING', clientReadiness: 'unverified', nextAction: i === 0 ? 'inspect_operation' : 'poll_operation' });
    }
    await h.poll(); await h.poll();
    assert(!h.toasts.some(x => x.type === 'success' && /топология применена|конфигурация применена|связь установлена/i.test(x.message)));
    assert(h.toasts.some(x => /сверк|reconcil/i.test(x.message)));
    assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 1, 'PPP wait continues independently');
    assert.equal(writes(h).length, 3);
});

test('[v2] accepted delete retains arrow through list absence until exact terminal cleanup; repeated click sends no job', async t => {
    const row = link(430, P, R, { status: 'online' }), neighbor = graphs.G2[1];
    const h = harness(t, snapshot([row, neighbor])); await h.load();
    h.graph.getElementById(P).position({ x: 91, y: 32 }); h.graph.pan({ x: 5, y: 7 }); h.graph.zoom(1.8);
    const job = v2Job(431, 'link.delete', row);
    h.respond('DELETE', '/api/cascade/links/' + row._id, { ...accepted(job), applicationState: 'deleting' }, 202);
    await h.window._cascadeDelete(row._id); await tick();
    assert.match(writes(h)[0].headers['Idempotency-Key'] || '', /^[A-Za-z0-9_.:-]{1,128}$/);
    assert.equal(h.graph.getElementById('link-' + row._id).length, 1);
    assert.match(h.drawer(row._id), /Удаляется|deleting/i);
    await h.window._cascadeDelete(row._id); assert.equal(writes(h).length, 1);
    h.state.snapshot = snapshot([neighbor], 8); await h.load();
    assert.equal(h.graph.getElementById('link-' + row._id).length, 1, 'list absence alone is not cleanup proof');
    h.respond('GET', '/api/cascade/links/auto-deploy-jobs/' + job.jobId,
        { job: { ...job, status: 'admitted', operationId: id(432) } }); await h.poll(1500);
    h.state.operations.set(id(432), { operationId: id(432), kind: 'link.delete', linkId: row._id,
        status: 'succeeded', phase: 'completed', clientReadiness: 'unverified' });
    await h.poll();
    assert.equal(h.graph.getElementById('link-' + row._id).length, 0);
    assert(h.toasts.some(x => x.message === h.window._networkI18n.deleteSuccess));
    assert.deepEqual(h.graph.getElementById(P).position(), { x: 91, y: 32 });
    assert.deepEqual(h.graph.pan(), { x: 5, y: 7 }); assert.equal(h.graph.zoom(), 1.8);
    assert.equal(h.graph.getElementById('link-' + neighbor._id).length, 1);
    assert.equal(h.activeTimers().length, 0); proofNotClaimed(h);
});

test('[v2] projection uses real list fields, separates PPP/Xray, clears proof on refresh, and never traverses mixed desired neighbors', async t => {
    const prefix = link(440, P, R, { status: 'online', applicationState: 'applied', routeState: 'no_bridge_exit',
        tunnelState: 'connected', pppReadiness: 'unverified', xrayReadiness: 'unverified', appliedOperationId: id(441) });
    const h = harness(t, snapshot([prefix, graphs.G2[1]])); await h.load();
    assert.equal(h.graph.getElementById('link-' + prefix._id).data('routeState'), 'no_bridge_exit');
    const labels = h.window._networkI18n;
    let html = h.drawer(prefix._id);
    assert(html.includes(labels.routeNoBridge), 'localized missing exit is not a global failure');
    assert(html.includes('PPP/L2TP')); assert(html.includes('Xray/VLESS/REALITY'));
    h.state.snapshot = snapshot([{ ...prefix, routeState: 'no_portal_input', pppReadiness: 'verified' }], 8);
    await h.ui.refreshStatuses(); await tick(); html = h.drawer(prefix._id);
    assert(html.includes(labels.routeNoPortal));
    assert.match(html, /PPP\/L2TP<\/div><div>Подтверждено/);
    assert.match(html, /Xray\/VLESS\/REALITY<\/div><div>Готовность клиента не подтверждена/);
    h.state.snapshot = snapshot([{ ...prefix, routeState: 'complete', pppReadiness: 'unverified', xrayReadiness: 'verified' }], 9);
    await h.ui.refreshStatuses(); await tick(); html = h.drawer(prefix._id);
    assert.match(html, /Xray\/VLESS\/REALITY<\/div><div>Подтверждено/);
    assert(html.includes(labels.fullRouteUnconfirmed), 'a complete flag is not the applied path or exit policy');
    h.state.snapshot = snapshot([{ ...prefix, routeState: 'unknown', xrayReadiness: undefined, pppReadiness: undefined }], 10);
    await h.ui.refreshStatuses(); await tick(); html = h.drawer(prefix._id);
    assert(!html.includes('Подтверждено'));
    assert.equal(h.ui.buildRouteSummary(h.graph.getElementById('link-' + prefix._id).data()).chain, 'Portal → Relay');
});

test('[v2] wrong-kind Auto acceptance is not retired; its explicit retry keeps the same key', async t => {
    const row = graphs.G1[0], h = harness(t), job = v2Job(450, 'link.delete', row);
    h.respond('POST', '/api/cascade/links', accepted(job), 202); await h.submit(row, true);
    assert.equal(h.activeTimers(1500).length, 0);
    assert(h.toasts.some(x => x.type === 'error'));
    h.respond('POST', '/api/cascade/links', accepted({ ...job, kind: 'link.create' }), 202); await h.submit(row, true);
    assert.equal(writes(h)[0].headers['Idempotency-Key'], writes(h)[1].headers['Idempotency-Key']);
});

test('[v2] deletion reload resumes marker polling, exact job/link/kind and terminal list absence are all required', async t => {
    const row = link(460, P, R, { status: 'online', lifecycle: { state: 'deleting', deleteJobId: id(461), desiredVersion: 'a'.repeat(64) } });
    const h = harness(t, snapshot([row])); await h.load();
    const job = v2Job(461, 'link.delete', row), opId = id(462);
    assert.equal(h.activeTimers(1500).length, 1, 'server marker restores this delete after page reload');
    await h.window._cascadeDelete(row._id); assert.equal(writes(h).length, 0);
    h.respond('GET', '/api/cascade/links/auto-deploy-jobs/' + job.jobId, { job: { ...job, linkId: id(999), status: 'admitted', operationId: opId } });
    await h.poll(1500); assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 0);
    h.respond('GET', '/api/cascade/links/auto-deploy-jobs/' + job.jobId, { job: { ...job, status: 'admitted', operationId: opId } });
    await h.poll(1500);
    for (const wrong of [{ kind: 'link.apply', linkId: row._id }, { kind: 'link.delete', linkId: id(999) }]) {
        h.state.operations.set(opId, { operationId: opId, status: 'succeeded', phase: 'completed', ...wrong });
        await h.poll();
        assert.equal(h.graph.getElementById('link-' + row._id).length, 1);
        assert(!h.toasts.some(x => x.message === h.window._networkI18n.deleteSuccess));
    }
    h.state.operations.set(opId, { operationId: opId, kind: 'link.delete', linkId: row._id, status: 'succeeded', phase: 'completed', clientReadiness: 'unverified' });
    await h.poll();
    assert.equal(h.graph.getElementById('link-' + row._id).length, 1, 'terminal operation with row still present is not final removal');
    h.state.snapshot = snapshot([], 8);
    const staleTopology = { nodes: nodes.map(n => ({ data: { id: n._id, label: n.name, cascadeRole: n.cascadeRole } })),
        edges: [{ data: { ...row, id: 'link-' + row._id, linkId: row._id, source: P, target: R } }] };
    // /topology is independently cached. A fresh /links absence must win only
    // after the exact completed delete, not before it.
    h.respond('GET', '/api/cascade/topology', staleTopology); h.respond('GET', '/api/cascade/topology', staleTopology);
    await h.poll(); assert.equal(h.graph.getElementById('link-' + row._id).length, 0);
    assert.equal(h.activeTimers().length, 0); assert.equal(writes(h).length, 0);
});

test('[v2] retained terminal delete and blocked job remain visible as reconcile, never successful or retried', async t => {
    for (const terminal of ['blocked', 'reconcile_required', 'failed']) {
        const row = link(470, P, R, { status: 'online' }), h = harness(t, snapshot([row])); await h.load();
        const job = v2Job(471, 'link.delete', row), opId = id(472);
        h.respond('DELETE', '/api/cascade/links/' + row._id, { ...accepted(job), applicationState: 'deleting' }, 202);
        await h.window._cascadeDelete(row._id);
        h.respond('GET', '/api/cascade/links/auto-deploy-jobs/' + job.jobId, { job: { ...job,
            status: terminal === 'blocked' ? 'blocked' : 'admitted', errorCode: 'TOPOLOGY_RECONCILE_REQUIRED',
            ...(terminal === 'blocked' ? {} : { operationId: opId }) } }); await h.poll(1500);
        if (terminal !== 'blocked') {
            h.state.operations.set(opId, { operationId: opId, kind: 'link.delete', linkId: row._id,
                status: terminal === 'failed' ? 'failed' : 'succeeded', phase: 'reconcile_required',
                waitingReason: 'TOPOLOGY_RECONCILE_REQUIRED', clientReadiness: 'unverified', nextAction: 'inspect_operation' });
            await h.poll();
        }
        h.state.snapshot = snapshot([], 8); await h.load();
        assert.equal(h.graph.getElementById('link-' + row._id).length, 1);
        assert(h.drawer(row._id).includes(h.window._networkI18n.reconcileRequired));
        assert(!h.toasts.some(x => x.message === h.window._networkI18n.deleteSuccess));
        await h.window._cascadeDelete(row._id); assert.equal(writes(h).length, 1);
        assert.equal(h.activeTimers().length, 0); proofNotClaimed(h);
    }
});

test('[v2] unknown delete delivery retains exact request key after revision refresh without sending desired guesses', async t => {
    const row = link(480, P, R, { status: 'pending', desiredVersion: 'a'.repeat(64) }), h = harness(t, snapshot([row]));
    h.respond('DELETE', '/api/cascade/links/' + row._id, {}, 503, () => { throw Error('connection lost'); });
    await h.window._cascadeDelete(row._id);
    h.state.snapshot = snapshot([], 8); await h.load();
    assert.equal(h.graph.getElementById('link-' + row._id).length, 1, 'lost acceptance and list absence cannot silently hide an unfinished delete');
    assert(h.drawer(row._id).includes(h.window._networkI18n.reconcileRequired));
    const job = v2Job(481, 'link.delete', row);
    h.respond('DELETE', '/api/cascade/links/' + row._id, { ...accepted(job), applicationState: 'deleting' }, 202);
    await h.window._cascadeDelete(row._id);
    assert.equal(writes(h)[0].headers['Idempotency-Key'], writes(h)[1].headers['Idempotency-Key']);
    assert.deepEqual(writes(h)[1].body, { expectedTopologyRevision: 8 });
    assert.equal(h.activeTimers(1500).length, 1);
});

test('[v2] concurrent deletes settle only their own tombstone and read failure never substitutes for absence', async t => {
    const rows = [link(490, P, R, { status: 'online' }), link(491, R, B1, { status: 'online', mode: 'forward' })];
    const h = harness(t, snapshot(rows)); await h.load();
    const jobs = rows.map((row, i) => v2Job(492 + i, 'link.delete', row));
    for (const job of jobs) {
        h.respond('DELETE', '/api/cascade/links/' + job.linkId, { ...accepted(job), applicationState: 'deleting' }, 202);
        await h.window._cascadeDelete(job.linkId);
    }
    for (const [i, job] of jobs.entries()) {
        h.respond('GET', '/api/cascade/links/auto-deploy-jobs/' + job.jobId, { job: { ...job, status: 'admitted', operationId: id(494 + i) } }); await h.poll(1500);
        h.state.operations.set(id(494 + i), { operationId: id(494 + i), kind: 'link.delete', linkId: job.linkId,
            status: i === 0 ? 'succeeded' : 'committing', phase: i === 0 ? 'completed' : 'applying' });
    }
    h.state.snapshot = snapshot([rows[1]], 8);
    // Failed list read is not an empty list, even beside exact terminal success.
    h.respond('GET', '/api/cascade/links', { error: { code: 'INTERNAL_ERROR' } }, 503);
    await h.poll();
    assert.equal(h.errors.length, 1); assert.match(String(h.errors.pop()), /Topology load error/);
    assert.equal(h.graph.getElementById('link-' + rows[0]._id).length, 1);
    await h.poll(); // second delete is still applying
    await h.poll(); // first delete now has successful list-absence readback
    assert.equal(h.graph.getElementById('link-' + rows[0]._id).length, 0);
    assert.equal(h.graph.getElementById('link-' + rows[1]._id).length, 1);
    assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 1);
    h.state.snapshot = snapshot([], 9);
    h.state.operations.set(id(495), { operationId: id(495), kind: 'link.delete', linkId: rows[1]._id, status: 'succeeded', phase: 'completed' });
    await h.poll();
    assert.equal(h.graph.getElementById('link-' + rows[1]._id).length, 0);
    assert.equal(writes(h).length, 2); assert.equal(h.activeTimers().length, 0);
});

test('[v2] stable request keys also work with getRandomValues on pages without randomUUID', async t => {
    const row = graphs.G1[0], h = harness(t, snapshot([row]));
    h.window.crypto = { getRandomValues: buffer => require('node:crypto').randomFillSync(buffer) };
    const job = v2Job(510, 'link.apply', row);
    h.respond('POST', '/api/cascade/topology/deploy', accepted(job), 202);
    await h.window._cascadeDeploy(row._id);
    assert.equal(writes(h).length, 1, 'missing randomUUID must not disable otherwise supported manual/classic controls');
    assert.match(writes(h)[0].headers['Idempotency-Key'], /^[A-Za-z0-9_.:-]{1,128}$/);
});

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

test('[regression] successful save-only create must explicitly confirm saved without claiming applied or connected', async t => {
    const h = harness(t), row = graphs.G1[0], next = snapshot([row], 8);
    h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: row._id }, 201,
    () => { h.state.snapshot = next; });
    await h.submit(row, false);
    assert(h.toasts.some(x => /сохранен|сохранён|saved/i.test(x.message)), 'current save-only silently closes the form');
    assert(!h.toasts.some(x => /применен|применён|соединен|соединён|applied|connected/i.test(x.message)));
});

test('[regression] quick AutoDeploy must supply an Idempotency-Key for replay-safe durable create acceptance', async t => {
    const h = harness(t), job = { jobId: id(330), status: 'waiting', acceptanceRevision: 7 };
    h.respond('POST', '/api/cascade/links', { autoDeployJob: job, acceptedTopologyRevision: 7 }, 202);
    await h.submit(graphs.G2[1], true, true);
    assert.match(writes(h)[0].headers['Idempotency-Key'] || '', /^[0-9a-f-]{36}$/, 'quick create omits the key, so the service default generates a new key per delivery');
});

test('[regression] quick create retries retain identity across revision refresh, change on payload or accepted new create', async t => {
    const h = harness(t), row = graphs.G1[0];
    for (const [candidate, status] of [[row, 409], [row, 503], [{ ...row, tunnelPort: row.tunnelPort + 1 }, 503], [row, 202], [row, 202]]) {
        h.respond('POST', '/api/cascade/links', status === 202
            ? { autoDeployJob: { jobId: id(331), status: 'waiting' }, acceptedTopologyRevision: 8 }
            : { error: { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' } }, status);
        h.state.snapshot = snapshot([], 8);
        await h.submit(candidate, true, true);
    }
    const keys = writes(h).map(r => r.headers['Idempotency-Key']);
    assert.match(keys[0] || '', /^[0-9a-f-]{36}$/);
    assert.equal(keys[0], keys[1], 'snapshot revision is not a new logical create');
    assert.notEqual(keys[1], keys[2]);
    assert.notEqual(keys[3], keys[4], 'an accepted new submission starts a new logical create');
});

test('[regression] both save-only forms and edit explicitly confirm a save without work or route claims', async t => {
    const row = graphs.G1[0];
    for (const quick of [false, true]) {
        const h = harness(t), next = snapshot([row], 8);
        h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: row._id }, 201, () => { h.state.snapshot = next; });
        await h.submit(row, false, quick);
        assert(h.toasts.some(x => /сохранен|сохранён|saved/i.test(x.message)));
        assert.equal(h.activeTimers().length, 0);
        assert.equal(writes(h).length, 1);
        proofNotClaimed(h);
    }
    const h = harness(t, snapshot([row]));
    await h.ui.openEditLinkModal(row._id);
    h.respond('PUT', '/api/cascade/links/' + row._id, snapshot([row], 8));
    await h.ui.onAddLinkSubmit({ target: h.form, preventDefault() {} });
    assert(h.toasts.some(x => /сохранен|сохранён|saved/i.test(x.message)));
    assert.equal(h.activeTimers().length, 0);
});

for (const status of ['preparing', 'committing', 'succeeded']) {
    test(`[regression] AutoDeploy must consume an actually accepted ${status} operation instead of reporting not started`, async t => {
        const h = harness(t), operationId = id(340);
        const next = snapshot([graphs.G1[0]], 8);
        h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: graphs.G1[0]._id,
            autoDeployOperation: { operationId, topologyRevision: 8, status } }, 201, () => { h.state.snapshot = next; });
        await h.submit(graphs.G1[0], true);
        assert(!h.toasts.some(x => x.type === 'error'), 'queueAutoDeploy allows this status, but the UI reports an unstarted AutoDeploy');
        assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 1, 'accepted operation needs exact-ID status/proof tracking');
        h.state.operations.set(operationId, { operationId, status: 'succeeded', clientReadiness: 'unverified', clientProofState: 'degraded' });
        await h.poll();
        assert.equal(h.requests.filter(r => r.url.endsWith('/operations/' + operationId)).length, 1);
        assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 0);
        proofNotClaimed(h);
    });
}

test('[regression] manual Deploy consumes preparing/committing/succeeded operation IDs without replay or readiness inference', async t => {
    for (const status of ['preparing', 'committing', 'succeeded']) {
        const h = harness(t), operationId = id(342);
        h.respond('POST', '/api/cascade/topology/deploy', { operationId, status, kind: 'link.apply', topologyRevision: 7 }, 202);
        await h.window._cascadeDeploy(graphs.G1[0]._id); await tick();
        assert(!h.toasts.some(x => x.type === 'error'));
        h.state.operations.set(operationId, { operationId, status: 'succeeded', clientReadiness: 'verified' });
        await h.poll();
        assert.equal(writes(h).length, 1);
        assert(h.toasts.some(x => /готовность подтверждена проверкой клиента/.test(x.message)));
    }
});

test('[regression] staged Portal-to-Relay drawer must not advertise an Internet path with no exit', async t => {
    const row = link(50, P, R, { status: 'staged' });
    const h = harness(t, snapshot([row])); await h.load();
    assert.doesNotMatch(h.drawer(row._id), /Client → Portal → Relay → Internet/, 'buildRouteSummary appends Internet unconditionally to an incomplete prefix');
    assert.equal(h.ui.buildRouteSummary(h.graph.getElementById('link-' + row._id).data()).chain, 'Portal → Relay');
});

test('[regression] applied drawer must not silently include a save-only sibling in the displayed route', async t => {
    const prefix = link(51, P, R, { status: 'deployed' }), pending = link(52, R, B1);
    const h = harness(t, snapshot([prefix, pending])); await h.load();
    assert.doesNotMatch(h.drawer(prefix._id), /Client → Portal → Relay → Bridge 1 → Internet/, 'drawer follows pending edges as though they were applied');
    assert.equal(h.ui.buildRouteSummary(h.graph.getElementById('link-' + prefix._id).data()).chain, 'Portal → Relay');
});

test('[regression] mixed-mode drawer shows only the selected segment, not an inferred full applied route', async t => {
    const prefix = link(53, P, R, { status: 'online' }), suffix = link(54, R, B1, { status: 'online', mode: 'forward' });
    const h = harness(t, snapshot([prefix, suffix])); await h.load();
    // The original RED required the full Portal→Relay→Bridge chain. Current
    // fields do not prove an applied path/policy, so that assertion would force
    // another browser graph planner. Repair the false route claim, not the API.
    const summary = h.ui.buildRouteSummary(h.graph.getElementById('link-' + prefix._id).data());
    assert.equal(summary.chain, 'Portal → Relay');
    assert.equal(h.ui.buildRouteSummary(h.graph.getElementById('link-' + suffix._id).data()).chain, 'Relay → Bridge 1');
    assert.match(h.drawer(prefix._id), /выбранный участок|Выбранный участок/);
    assert.match(h.drawer(prefix._id), /маршрут.*не подтвержден|маршрут.*не подтверждён/);
    proofNotClaimed(h);
});

test('[regression] deleting the only applied exit must warn about route interruption before dispatch', async t => {
    const row = link(55, R, B1, { status: 'online' });
    const h = harness(t, snapshot([row])); await h.load(); h.state.confirm = false;
    await h.window._cascadeDelete(row._id);
    assert.equal(writes(h).length, 0);
    assert.match(h.confirmations[0], /трафик|пользоват|выход|соединени|маршрут|traffic|user|exit|connect|route/i, 'current confirmation only asks to delete a link');
});

test('[regression] rejected legacy undeploy must not announce success on an HTTP error', async t => {
    const row = link(56, P, B1, { status: 'online' });
    const h = harness(t, snapshot([row])); await h.load();
    h.respond('POST', '/api/cascade/links/' + row._id + '/undeploy', { error: { code: 'LEGACY_CASCADE_UNDEPLOY_BUSY' } }, 409);
    await h.window._cascadeUndeploy(row._id); await tick();
    assert(h.toasts.some(x => x.type === 'error'), 'fetch resolves HTTP errors; undeploy currently ignores response.ok');
    assert(!h.toasts.some(x => /undeployed|деплой отменен|отключена/i.test(x.message) && x.type !== 'error'));
    assert.equal(h.graph.getElementById('link-' + row._id).data('status'), 'online');
    assert(h.requests.some(r => r.url === '/api/cascade/topology'), 'refresh after refusal instead of leaving optimistic syncing');
});

test('[regression] undeploy confirms only the current success receipt and never displays free-form backend errors', async t => {
    for (const [body, status] of [[{ success: true }, 200], [{ error: 'private SSH credentials' }, 500], [{ success: false }, 200]]) {
        const row = link(57, P, B1, { status: 'online' }), h = harness(t, snapshot([row]));
        await h.load();
        h.respond('POST', '/api/cascade/links/' + row._id + '/undeploy', body, status);
        await h.window._cascadeUndeploy(row._id); await tick();
        const errors = h.toasts.filter(x => x.type === 'error');
        assert.equal(errors.length, body.success === true ? 0 : 1);
        assert(!h.toasts.some(x => /private SSH credentials/.test(x.message)));
        assert.equal(writes(h).length, 1);
    }
});

test('[regression] a second accepted operation must not cancel visibility of the first pending operation', async t => {
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

test('[regression] duplicate tracking preserves one poll; one terminal operation does not stop another', async t => {
    const h = harness(t), first = id(352), second = id(353);
    for (const operationId of [first, second, first]) {
        h.ui.handleLinkAutoDeploy({ autoDeployOperation: { operationId, status: 'queued' } }, true);
    }
    assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 2);
    h.state.operations.set(first, { operationId: first, status: 'failed' });
    h.state.operations.set(second, { operationId: second, status: 'committing' });
    await h.poll(); await h.poll();
    assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 1);
    h.state.operations.set(second, { operationId: second, status: 'succeeded', clientReadiness: 'verified' });
    await h.poll();
    assert.equal(h.activeTimers(helpers.OPERATION_POLL_INTERVAL_MS).length, 0);
    assert.equal(h.requests.filter(r => r.url.endsWith('/operations/' + first)).length, 1);
    assert.equal(h.requests.filter(r => r.url.endsWith('/operations/' + second)).length, 2);
});

test('[regression] main and quick logical retry identities do not replace each other after delivery failures', async t => {
    const h = harness(t), row = graphs.G1[0];
    for (const quick of [false, true, false, true]) {
        h.respond('POST', '/api/cascade/links', {}, 503, () => { throw Error('connection lost'); });
        await h.submit(row, true, quick);
    }
    const keys = writes(h).map(r => r.headers['Idempotency-Key']);
    assert.equal(keys[0], keys[2]); assert.equal(keys[1], keys[3]);
    assert.notEqual(keys[0], keys[1]);
    assert.equal(h.activeTimers().filter(timer => [1500, helpers.OPERATION_POLL_INTERVAL_MS].includes(timer.delay)).length, 0);
});

for (const locale of ['ru', 'en']) {
    test(`[regression] ${locale} visible lifecycle strings use the actual nodes template bindings`, async t => {
        const labels = require('../src/locales/' + locale + '.json').network;
        const template = fs.readFileSync(path.join(__dirname, '../views/nodes.ejs'), 'utf8');
        for (const key of ['savedWithoutDeploy', 'deployInProgress', 'operationApplied', 'selectedSegment',
            'fullRouteUnconfirmed', 'undeployFailed', 'confirmDeleteLink', 'jobAccepted', 'legacyJobAccepted', 'linkApplied',
            'jobUnavailable', 'jobStillWaiting', 'operationUnconfirmed', 'savedApplyUnconfirmed', 'linkDeleting',
            'reconcileRequired', 'linkNotApplied', 'applicationStateLabel', 'routeStateLabel', 'tunnelStateLabel',
            'routeComplete', 'routeNoPortal', 'routeNoBridge', 'routeAmbiguous', 'routeUnknown', 'readinessVerified',
            'tunnelConnected', 'tunnelDisconnected', 'tunnelUnknown', 'operationProgress', 'operationNode',
            'phaseWaiting', 'phasePreparing', 'phaseApplying', 'phaseRollback', 'phaseCompleted', 'phaseFailed',
            'phaseAdmitted', 'waitResources', 'waitPPP', 'inspectOperation', 'pollOperation', 'refreshTopology', 'retryLater']) {
            assert(labels[key], key);
            assert(template.includes(key + ": <%- JSON.stringify(t('network." + key + "')) %>"), key + ' must reach the shipped IIFE');
        }
        const row = graphs.G1[0], h = harness(t, snapshot(), locale), next = snapshot([row], 8);
        h.respond('POST', '/api/cascade/links', { ...next, createdLinkId: row._id }, 201, () => { h.state.snapshot = next; });
        await h.submit(row, false, true);
        assert(h.toasts.some(x => x.message === labels.savedWithoutDeploy));
        assert(h.drawer(row._id).includes(labels.selectedSegment));
        assert(h.drawer(row._id).includes(labels.fullRouteUnconfirmed));
        h.state.confirm = false;
        await h.window._cascadeDelete(row._id);
        assert.equal(h.confirmations[0], labels.confirmDeleteLink);
        assert.equal(writes(h).length, 1, 'cancelled delete sends nothing');
        const operationId = id(360);
        h.ui.handleLinkAutoDeploy({ autoDeployOperation: { operationId, status: 'committing' } }, true);
        assert(h.toasts.some(x => x.message.startsWith(labels.deployInProgress)));
        assert(!h.toasts.some(x => x.message.startsWith(labels.deployQueued)));
        h.state.confirm = true;
        const job = v2Job(500, 'link.delete', row);
        h.respond('DELETE', '/api/cascade/links/' + row._id, { ...accepted(job), applicationState: 'deleting' }, 202);
        await h.window._cascadeDelete(row._id);
        assert(h.toasts.some(x => x.message === labels.jobAccepted + ' ' + job.jobId));
        assert(h.drawer(row._id).includes(labels.linkDeleting));
        proofNotClaimed(h);
    });
}
