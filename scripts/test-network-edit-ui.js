const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '..', 'public/js/network.js'), 'utf8');
const LINK_ID = '507f1f77bcf86cd799439011';
const OP_ID = '507f1f77bcf86cd799439022';
const PORTAL_ID = '507f1f77bcf86cd799439055';
const BRIDGE_ID = '507f1f77bcf86cd799439066';
const snapshot = (extra = {}) => ({ topologyRevision: 7, deployedRevision: 6, links: [], ...extra });

function browserHarness({ persistedAutoDeploy = true, operation = null, job = null,
    links = [], deployResponse = null, confirmResult = true, autoDeployError = null,
    livePorts = false, locale = 'en' } = {}) {
    const requests = [];
    const toasts = [];
    const timers = [];
    const confirmations = [];
    let reloads = 0;
    const edges = links.map(link => ({
        values: { ...link, linkId: link._id, source: 'portal', target: 'bridge', mode: 'reverse' },
        data(key, value) {
            if (key === undefined) return this.values;
            if (arguments.length > 1) this.values[key] = value;
            return this.values[key];
        },
    }));
    function collection(items) {
        return { length: items.length, toArray: () => items,
            filter: predicate => collection(items.filter(predicate)),
            data: (...args) => items[0]?.data(...args) };
    }
    const graph = { edges: () => collection(edges), getElementById: () => ({ length: 0 }),
        elements: () => ({ unselect() {} }) };
    const elements = {};
    const observers = [];
    function notifyObservers(el) {
        observers.filter(o => o.target === el && !o.queued).forEach(o => {
            o.queued = true;
            queueMicrotask(() => { o.queued = false; o.fn(); });
        });
    }
    const element = (id, value = '') => {
        const classes = new Set();
        const listeners = new Map();
        const el = elements[id] = {
            value, textContent: '', innerHTML: '', style: {}, disabled: false, checked: false,
            classList: {
                add(name) { classes.add(name); notifyObservers(el); },
                remove(name) { classes.delete(name); notifyObservers(el); },
                contains: name => classes.has(name),
                toggle(name, active) { if (active) classes.add(name); else classes.delete(name); },
            },
            querySelectorAll: () => [],
            addEventListener(type, fn) { listeners.set(type, [...(listeners.get(type) || []), fn]); },
            async dispatch(type) {
                for (const fn of listeners.get(type) || []) await fn.call(el, { target: el, preventDefault() {} });
            },
        };
        return el;
    };
    const form = element('addLinkForm');
    for (const [name, value] of Object.entries({
        name: 'Existing link', mode: 'reverse', portalNodeId: 'portal', bridgeNodeId: 'bridge',
        tunnelPort: '10086', tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelSecurity: 'none',
        muxConcurrency: '8', priority: '100', tunnelDomain: '', realitySni: '', realityPrivateKey: '',
        realityPublicKey: '', realityShortIds: '', realityDest: '', realityFingerprint: 'chrome',
    })) form[name] = { value };
    form.autoDeploy = { checked: true };
    form.muxEnabled = { checked: false };
    const submit = { disabled: false, innerHTML: '' };
    form.querySelector = selector => selector === '[type="submit"]' ? submit : null;
    form.reset = () => { form.autoDeploy.checked = true; };
    for (const id of ['addLinkModal', 'selectPortal', 'selectBridge', 'linkModalTitle',
        'linkModalSubmit', 'linkAutoDeployLabel', 'linkIdInput', 'geoRoutingEnabled', 'geoRoutingFields',
        'geoRoutingDomains', 'geoRoutingGeoip', 'realitySection', 'tunnelDomainGroup',
        'modeHint', 'modeSwitcher', 'nodeInfoTitleText', 'nodeInfoBody', 'nodeInfoModal']) element(id);
    elements.nodeInfoBody.querySelector = () => null;
    elements.nodeInfoBody.appendChild = () => {};
    form.linkId = elements.linkIdInput;
    if (livePorts) {
        // Strict, linked fake DOM: named controls and ID lookups are the same
        // elements, unknown IDs return null, and selectors never invent nodes.
        for (const [name, id] of [['mode', 'linkModeInput'], ['portalNodeId', 'selectPortal'],
            ['bridgeNodeId', 'selectBridge'], ['tunnelPort', 'mainTunnelPort']]) {
            const value = form[name].value;
            form[name] = elements[id] || element(id);
            form[name].value = value;
        }
        form.portalNodeId.value = PORTAL_ID;
        form.bridgeNodeId.value = BRIDGE_ID;
        for (const id of ['portConflictHint', 'quickPortConflictHint', 'quickLinkModal',
            'quickLinkForm', 'quickLinkSubmit', 'quickPortalName', 'quickBridgeName', 'quickModeSwitcher']) element(id);
        for (const [id, value] of Object.entries({ quickPortalId: PORTAL_ID, quickBridgeId: BRIDGE_ID,
            quickTunnelPort: '10086', quickLinkMode: 'reverse', quickLinkName: 'Quick link',
            quickTunnelProtocol: 'vless' })) element(id, value);
        element('quickAutoDeploy').checked = false;
        for (const id of ['modeSwitcher', 'quickModeSwitcher']) {
            elements[id].querySelectorAll = selector => {
                assert.equal(selector, '.mode-btn');
                return ['reverse', 'forward'].map(mode => {
                    const btn = elements[id + mode] || element(id + mode);
                    btn.getAttribute = attr => { assert.equal(attr, 'data-mode'); return mode; };
                    return btn;
                });
            };
        }
    }
    const document = {
        readyState: 'loading', addEventListener() {},
        getElementById: id => elements[id] || null,
        querySelector: selector => {
            const match = selector.match(/^#addLinkForm \[name="([^"]+)"\]$/);
            if (match) return form[match[1]] || null;
            if (selector === '.info-loading') return null;
            if (livePorts) throw Error('Unsupported selector: ' + selector);
            return null;
        },
        createElement: () => ({ value: '', textContent: '' }),
    };
    form.realityFingerprint.options = [{ value: 'chrome' }];
    form.realityFingerprint.appendChild = () => {};
    const json = body => ({ ok: true, status: 200, async json() { return body; } });
    const probes = [];
    const fetch = async (url, options) => {
        requests.push({ url, method: options?.method || 'GET', headers: options?.headers, body: options?.body && JSON.parse(options.body) });
        if (url.startsWith('/api/cascade/links/port-check?')) {
            return new Promise((resolve, reject) => probes.push({ url, signal: options?.signal,
                reply(body, status = 200) { resolve({ ...json(body), ok: status === 200, status }); }, reject }));
        }
        if (url === '/api/nodes') return json([{ _id: livePorts ? PORTAL_ID : 'portal', name: 'Portal', ip: '1.2.3.4' }]);
        if (url === '/api/cascade/links' && !options) return json(snapshot({ links }));
        if (url === '/api/cascade/links/' + LINK_ID && !options) return json({
            name: 'Existing link', portalNode: livePorts ? PORTAL_ID : 'portal',
            bridgeNode: livePorts ? BRIDGE_ID : 'bridge', autoDeploy: persistedAutoDeploy,
        });
        if (url === '/api/cascade/topology/deploy' && deployResponse) return {
            ok: false, status: deployResponse.status, async json() { return deployResponse.body; },
        };
        if (url === '/api/cascade/topology/deploy') return json({
            operationId: OP_ID, status: 'queued', kind: 'link.apply', topologyRevision: 7,
        });
        if (url === '/api/cascade/topology/operations/' + OP_ID) return json({
            operationId: OP_ID, status: 'succeeded', kind: 'link.apply', topologyRevision: 7,
        });
        if (job && url === '/api/cascade/links/auto-deploy-jobs/' + job.jobId) return json({ autoDeployJob: { ...job, status: 'admitted', operationId: OP_ID, topologyRevision: 8 } });
        if (job && options?.method === 'POST' && url === '/api/cascade/links') return { ok: true, status: 202, async json() { return { autoDeployJob: job, acceptedTopologyRevision: 7 }; } };
        if (options?.method === 'PUT' || options?.method === 'POST') return json(snapshot({
            ...(operation ? { autoDeployOperation: operation } : {}),
            ...(autoDeployError ? { autoDeployError, autoDeployStatus: 'blocked' } : {}),
        }));
        throw Error('Unexpected request: ' + url);
    };
    const window = { crypto: { randomUUID: require('node:crypto').randomUUID }, _networkI18n: { save: 'Save', saveAndDeploy: 'Save & Deploy',
        deployAfterEdit: 'Deploy this link after saving', autoDeploy: 'Auto Deploy', createLink: 'Create',
        syncChain: 'Sync Chain', syncingChain: 'Syncing entire chain...',
        confirmDeployChain: 'Deploy entire chain? This will sync all connected nodes in the correct order.' },
    showToast: (...args) => toasts.push(args) };
    if (livePorts) window._networkI18n = require('../src/locales/' + locale + '.json').network;
    // Expose the real browser handlers while skipping graph bootstrapping; all
    // form reads, fetch payloads, response handling and timers remain real.
    const instrumented = source.replace('    // ==================== START ====================',
        '    cy = window.__graph; applyLinkSnapshot(window.__snapshot); loadTopology = window.__reload; refreshStatuses = async function () {}; window.__ui = { openAddLinkModal, openEditLinkModal, onAddLinkSubmit, updateLinkSubmitIntent, deployTopology, onEdgeTap, closeModal, closeQuickModal, onQuickLinkSubmit, onQuickSwap, updateLinkFormWarnings };' +
        (livePorts ? ' if (typeof initPortWarnings === "function") initPortWarnings(); initModeSwitcher("modeSwitcher", "linkModeInput", "modeHint"); initModeSwitcher("quickModeSwitcher", "quickLinkMode");' : '') + '\n    // ==================== START ====================');
    assert.notEqual(instrumented, source, 'browser probe insertion must find the boot boundary');
    window.__graph = graph;
    window.__snapshot = snapshot({ links });
    window.__reload = async () => { reloads += 1; };
    vm.runInNewContext(instrumented, {
        window, document, fetch, cytoscape: () => {}, AbortController, URLSearchParams,
        MutationObserver: class {
            constructor(fn) { this.fn = fn; }
            observe(target) { observers.push({ target, fn: this.fn }); }
        },
        confirm: message => { confirmations.push(message); return confirmResult; },
        setTimeout: (fn, delay) => { timers.push({ fn, delay, cancelled: false }); return timers.length; },
        clearTimeout: id => { if (timers[id - 1]) timers[id - 1].cancelled = true; }, console,
    });
    return { ui: window.__ui, window, form, elements, requests, toasts, timers, confirmations, probes,
        async flushPortDebounce() {
            await Promise.resolve();
            for (const timer of timers.filter(t => t.delay === 300 && !t.cancelled && !t.ran)) {
                timer.ran = true; timer.fn();
            }
            await new Promise(resolve => setImmediate(resolve));
        },
        get reloads() { return reloads; },
        renderEdge: (index = 0) => window.__ui.onEdgeTap({ target: edges[index] }) };
}

async function save(harness) {
    await harness.ui.onAddLinkSubmit({ target: harness.form, preventDefault() {} });
    return harness.requests.find(r => r.method === 'PUT' || r.method === 'POST');
}

// UI-only evidence: modeled API responses, not SSH/backend or browser proof.
test('main form warns about a source-config-only listener absent from cached DB links', async () => {
    const h = browserHarness({ livePorts: true });
    await h.ui.openAddLinkModal();
    await h.form.portalNodeId.dispatch('change');
    assert.equal(h.probes.length, 0, 'port probes must be debounced');
    await h.flushPortDebounce();
    assert.equal(h.probes.length, 1, 'valid listener must be checked on the actual node');
    const url = new URL(h.probes[0].url, 'http://local.invalid');
    assert.equal(url.pathname, '/api/cascade/links/port-check');
    assert.equal(url.searchParams.get('nodeId'), PORTAL_ID);
    assert.equal(url.searchParams.get('port'), '10086');
    assert.equal(url.searchParams.has('linkId'), false);
    h.probes[0].reply({ available: false, port: 10086, code: 'TUNNEL_PORT_IN_USE' });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.elements.portConflictHint.style.display, '');
    assert.match(h.elements.portConflictHint.textContent, /10086.*already in use/i);
    assert.equal(h.form.tunnelPort.value, '10086', 'never silently change the selected port');
});

test('explicit occupied-port result prevents main create-and-deploy and edit-and-deploy', async () => {
    for (const edit of [false, true]) {
        const h = browserHarness({ livePorts: true });
        if (edit) await h.ui.openEditLinkModal(LINK_ID);
        else await h.ui.openAddLinkModal();
        h.form.autoDeploy.checked = true;
        await h.flushPortDebounce();
        h.probes[0].reply({ available: false, port: 10086, code: 'TUNNEL_PORT_IN_USE' });
        await new Promise(resolve => setImmediate(resolve));
        await save(h);
        assert.equal(h.requests.filter(r => ['POST', 'PUT'].includes(r.method)).length, 0);
        assert(h.toasts.some(([message, type]) => type === 'error' && /already in use/i.test(message)));
    }
});

test('quick form checks the forward listener after mode change and swap, and blocks occupied deploy only', async () => {
    const h = browserHarness({ livePorts: true });
    h.elements.quickLinkModal.classList.add('active');
    await h.flushPortDebounce();
    assert.equal(new URL(h.probes[0].url, 'http://local.invalid').searchParams.get('nodeId'), PORTAL_ID);
    await h.elements.quickModeSwitcherforward.dispatch('click');
    await h.flushPortDebounce();
    assert.equal(h.probes.length, 2, 'quick mode changes must start a fresh check');
    assert.equal(new URL(h.probes[1].url, 'http://local.invalid').searchParams.get('nodeId'), BRIDGE_ID);
    assert.equal(h.probes[0].signal.aborted, true);
    h.ui.onQuickSwap();
    await h.flushPortDebounce();
    assert.equal(new URL(h.probes[2].url, 'http://local.invalid').searchParams.get('nodeId'), PORTAL_ID);
    h.probes[2].reply({ available: false, port: 10086, code: 'TUNNEL_PORT_IN_USE' });
    await new Promise(resolve => setImmediate(resolve));
    assert.match(h.elements.quickPortConflictHint.textContent, /10086.*already in use/);
    h.elements.quickAutoDeploy.checked = true;
    await h.ui.onQuickLinkSubmit({ preventDefault() {} });
    assert.equal(h.requests.filter(r => r.method === 'POST').length, 0, 'known occupied deploy is not submitted');
    h.elements.quickAutoDeploy.checked = false;
    await h.ui.onQuickLinkSubmit({ preventDefault() {} });
    const created = h.requests.find(r => r.method === 'POST');
    assert.equal(created.body.autoDeploy, false, 'save-only is not forbidden by an advisory port check');
    assert.equal(created.body.tunnelPort, 10086);
});

test('both actual form templates expose accessible localized port status beside their inputs', () => {
    const view = fs.readFileSync(path.join(__dirname, '..', 'views/nodes.ejs'), 'utf8');
    const ejs = require('ejs');
    for (const [formId, input, hint] of [['addLinkForm', 'name="tunnelPort"', 'portConflictHint'],
        ['quickLinkForm', 'id="quickTunnelPort"', 'quickPortConflictHint']]) {
        const start = view.indexOf('<form id="' + formId + '"');
        const html = ejs.render(view.slice(start, view.indexOf('</form>', start) + 7), { t: key => key });
        assert.match(html, new RegExp('<input[^>]*' + input + '[^>]*aria-describedby="[^"]*' + hint));
        assert.match(html, new RegExp('id="' + hint + '"[^>]*role="status"[^>]*aria-live="polite"'));
    }
    for (const locale of ['ru', 'en']) {
        const labels = require('../src/locales/' + locale + '.json').network;
        for (const key of ['portCheckChecking', 'portCheckOccupied', 'portCheckUnknown', 'portCheckAvailable', 'portCheckDeployConflict']) {
            assert.equal(typeof labels[key], 'string', locale + ':' + key);
            assert(view.includes("JSON.stringify(t('network." + key + "'))"), 'EJS must pass ' + key + ' to network.js');
        }
    }
});

test('manual Deploy and saved auto-deploy conflict use readable RU/EN port diagnostics, not server prose', async () => {
    for (const locale of ['ru', 'en']) {
        const expected = locale === 'ru' ? /порт.*занят/i : /port.*already in use/i;
        const error = { code: 'CLASSIC_DEPLOY_PORT_CONFLICT', message: 'secret=do-not-display' };
        const h = browserHarness({ livePorts: true, locale,
            deployResponse: { status: 409, body: { error } } });
        await h.window._cascadeDeploy(LINK_ID);
        assert(h.toasts.some(([message, type]) => type === 'error' && expected.test(message)));
        assert(!h.toasts.some(([message]) => message.includes('do-not-display')));
        const saved = browserHarness({ livePorts: true, locale, autoDeployError: error });
        await saved.ui.openAddLinkModal();
        await save(saved);
        assert(saved.toasts.some(([message, type]) => type === 'error' && expected.test(message)));
        assert(!saved.toasts.some(([message]) => message.includes('do-not-display')));
    }
});

test('closing then immediately reopening the same modal invalidates its old occupied reply', async () => {
    for (const quick of [false, true]) {
        const h = browserHarness({ livePorts: true });
        const modal = h.elements[quick ? 'quickLinkModal' : 'addLinkModal'];
        if (quick) modal.classList.add('active');
        else await h.ui.openAddLinkModal();
        await h.flushPortDebounce();
        const old = h.probes[0];
        if (quick) h.ui.closeQuickModal(); else h.ui.closeModal();
        // Simulate MutationObserver's real asynchronous delivery: close and open
        // can share a microtask checkpoint, so final class alone is insufficient.
        modal.classList.add('active');
        old.reply({ available: false, port: 10086, code: 'TUNNEL_PORT_IN_USE' });
        await new Promise(resolve => setImmediate(resolve));
        assert.doesNotMatch(h.elements[quick ? 'quickPortConflictHint' : 'portConflictHint'].textContent,
            /already in use/, 'closed-generation reply must never be revived');
        assert.equal(old.signal.aborted, true);
    }
});

test('stale occupied and available replies cannot overwrite a newer port or listening-node result', async () => {
    for (const quick of [false, true]) {
        for (const change of ['port', 'node']) {
            for (const oldAvailable of [false, true]) {
                const h = browserHarness({ livePorts: true });
                if (quick) h.elements.quickLinkModal.classList.add('active');
                else await h.ui.openAddLinkModal();
                await h.flushPortDebounce();
                const field = change === 'port'
                    ? (quick ? h.elements.quickTunnelPort : h.form.tunnelPort)
                    : (quick ? h.elements.quickPortalId : h.form.portalNodeId);
                field.value = change === 'port' ? '10087' : BRIDGE_ID;
                await field.dispatch(change === 'port' ? 'input' : 'change');
                await h.flushPortDebounce();
                assert.equal(h.probes.length, 2);
                assert.equal(h.probes[0].signal.aborted, true);
                const port = change === 'port' ? 10087 : 10086;
                h.probes[1].reply({ available: !oldAvailable, port, code: oldAvailable ? 'TUNNEL_PORT_IN_USE' : null });
                await new Promise(resolve => setImmediate(resolve));
                const hint = h.elements[quick ? 'quickPortConflictHint' : 'portConflictHint'];
                const latest = hint.textContent;
                assert.match(latest, oldAvailable ? /already in use/ : /is available/);
                // The mock deliberately ignores AbortSignal: generation and
                // exact-context checks, not transport cooperation, must win.
                h.probes[0].reply({ available: oldAvailable, port: 10086, code: oldAvailable ? null : 'TUNNEL_PORT_IN_USE' });
                await new Promise(resolve => setImmediate(resolve));
                assert.equal(hint.textContent, latest);
            }
        }
    }
});

test('rapid input is debounced and main mode change probes Bridge instead of Portal', async () => {
    const h = browserHarness({ livePorts: true });
    await h.ui.openAddLinkModal();
    h.form.tunnelPort.value = '10'; await h.form.tunnelPort.dispatch('input');
    h.form.tunnelPort.value = '10087'; await h.form.tunnelPort.dispatch('input');
    await h.flushPortDebounce();
    assert.equal(h.probes.length, 1);
    assert.match(h.probes[0].url, /port=10087/);
    await h.elements.modeSwitcherforward.dispatch('click');
    await h.flushPortDebounce();
    assert.equal(h.probes.length, 2);
    assert.equal(new URL(h.probes[1].url, 'http://local.invalid').searchParams.get('nodeId'), BRIDGE_ID);
    assert.equal(h.form.tunnelPort.value, '10087');
});

test('editing owns its unchanged listener and includes exact linkId, excluding only its own cached row', async () => {
    const h = browserHarness({ livePorts: true, links: [{ _id: LINK_ID, active: true,
        portalNode: PORTAL_ID, bridgeNode: BRIDGE_ID, tunnelPort: 10086 }] });
    await h.ui.openEditLinkModal(LINK_ID);
    await h.flushPortDebounce();
    assert.equal(h.probes.length, 1);
    assert.equal(new URL(h.probes[0].url, 'http://local.invalid').searchParams.get('linkId'), LINK_ID);
    assert.doesNotMatch(h.elements.portConflictHint.textContent, /already in use/);
    h.probes[0].reply({ available: true, port: 10086, code: null });
    await new Promise(resolve => setImmediate(resolve));
    assert.match(h.elements.portConflictHint.textContent, /is available/);
    h.elements.linkIdInput.value = OP_ID;
    h.ui.updateLinkFormWarnings();
    assert.match(h.elements.portConflictHint.textContent, /already in use/, 'a different edited row must not exclude the first one');
    await h.flushPortDebounce();
    assert.equal(new URL(h.probes[1].url, 'http://local.invalid').searchParams.get('linkId'), OP_ID);
});

test('no port-check reads occur for invalid node, invalid port, or closed forms', async () => {
    for (const quick of [false, true]) {
        for (const [node, port] of [['', '10086'], ['portal', '10086'], [PORTAL_ID, ''],
            [PORTAL_ID, '0'], [PORTAL_ID, '65536'], [PORTAL_ID, '10.5'], [PORTAL_ID, '1e3'], [PORTAL_ID, '10086x']]) {
            const h = browserHarness({ livePorts: true });
            const field = quick ? h.elements.quickTunnelPort : h.form.tunnelPort;
            const nodeField = quick ? h.elements.quickPortalId : h.form.portalNodeId;
            field.value = port; nodeField.value = node;
            if (quick) h.elements.quickLinkModal.classList.add('active');
            else await h.ui.openAddLinkModal();
            await field.dispatch('input'); await nodeField.dispatch('change');
            await h.flushPortDebounce();
            assert.equal(h.probes.length, 0, `${quick}:${node}:${port}`);
        }
        const h = browserHarness({ livePorts: true });
        const field = quick ? h.elements.quickTunnelPort : h.form.tunnelPort;
        await field.dispatch('input'); await h.flushPortDebounce();
        assert.equal(h.probes.length, 0, 'hidden forms never trigger probes');
    }
});

test('unknown and checking states are distinct from free in both languages and do not forbid draft saving', async () => {
    for (const locale of ['en', 'ru']) {
        for (const response of ['failure', '503', 'malformed', 'wrong-port', 'wrong-code']) {
            const h = browserHarness({ livePorts: true, locale });
            await h.ui.openAddLinkModal();
            await h.flushPortDebounce();
            const hint = h.elements.portConflictHint;
            assert.match(hint.textContent, locale === 'ru' ? /Проверяем/ : /Checking/);
            if (response === 'failure') h.probes[0].reject(Error('offline'));
            else if (response === '503') h.probes[0].reply({ available: true, port: 10086, code: null }, 503);
            else if (response === 'malformed') h.probes[0].reply({ available: 'yes', port: 10086, code: null });
            else if (response === 'wrong-port') h.probes[0].reply({ available: true, port: 10087, code: null });
            else h.probes[0].reply({ available: true, port: 10086, code: 'TUNNEL_PORT_IN_USE' });
            await new Promise(resolve => setImmediate(resolve));
            assert.match(hint.textContent, locale === 'ru' ? /неизвестно/ : /unknown/);
            assert.doesNotMatch(hint.textContent, locale === 'ru' ? /Порт 10086 свободен/ : /is available/);
            h.form.autoDeploy.checked = false;
            const created = await save(h);
            assert.equal(created.body.autoDeploy, false);
            assert.equal(created.body.tunnelPort, 10086);
        }
    }
});

test('cached mixed-mode conflicts survive unknown or free probes and non-listening endpoints do not conflict', async () => {
    for (const existingMode of ['reverse', 'forward', undefined]) {
        for (const collision of [false, true]) {
            const listenerField = existingMode === 'forward' ? 'bridgeNode' : 'portalNode';
            const links = [{ _id: OP_ID, active: true, mode: existingMode, tunnelPort: 10086,
                portalNode: PORTAL_ID, bridgeNode: PORTAL_ID, [listenerField]: collision ? { _id: PORTAL_ID } : BRIDGE_ID }];
            const h = browserHarness({ livePorts: true, links });
            await h.ui.openAddLinkModal(); await h.flushPortDebounce();
            const hint = h.elements.portConflictHint;
            if (collision) assert.match(hint.textContent, /already in use/);
            else assert.doesNotMatch(hint.textContent, /already in use/);
            h.probes[0].reply({ available: true, port: 10086, code: null });
            await new Promise(resolve => setImmediate(resolve));
            assert.match(hint.textContent, collision ? /already in use/ : /is available/);
            if (collision) {
                h.form.autoDeploy.checked = false;
                assert.equal((await save(h)).body.autoDeploy, false, 'known conflict remains advisory for save-only');
            }
        }
    }
    const h = browserHarness({ livePorts: true, links: [{ _id: OP_ID, active: true,
        portalNode: PORTAL_ID, tunnelPort: 10086 }] });
    await h.ui.openAddLinkModal(); await h.flushPortDebounce();
    h.probes[0].reject(Error('offline'));
    await new Promise(resolve => setImmediate(resolve));
    assert.match(h.elements.portConflictHint.textContent, /already in use/);
});

test('normal main and quick creates retain port and activation intent after a free result', async () => {
    for (const quick of [false, true]) {
        const h = browserHarness({ livePorts: true });
        if (quick) { h.elements.quickLinkModal.classList.add('active'); h.elements.quickAutoDeploy.checked = true; }
        else await h.ui.openAddLinkModal();
        await h.flushPortDebounce();
        h.probes[0].reply({ available: true, port: 10086, code: null });
        await new Promise(resolve => setImmediate(resolve));
        if (quick) await h.ui.onQuickLinkSubmit({ preventDefault() {} });
        else await save(h);
        const posts = h.requests.filter(r => r.method === 'POST');
        assert.equal(posts.length, 1);
        assert.equal(posts[0].url, '/api/cascade/links');
        assert.equal(posts[0].body.autoDeploy, true);
        assert.equal(posts[0].body.tunnelPort, 10086);
        assert.equal(posts[0].body.expectedTopologyRevision, 7);
        assert.equal(posts[0].body.portalNodeId, PORTAL_ID);
        assert.equal(posts[0].body.bridgeNodeId, BRIDGE_ID);
    }
});

test('a stalled probe becomes unknown, aborts, and cannot later announce a free port', async () => {
    const h = browserHarness({ livePorts: true });
    await h.ui.openAddLinkModal(); await h.flushPortDebounce();
    const deadline = h.timers.find(t => t.delay === 10000 && !t.cancelled);
    assert(deadline, 'live port reads need a finite unknown-state deadline');
    deadline.fn();
    assert.equal(h.probes[0].signal.aborted, true);
    assert.match(h.elements.portConflictHint.textContent, /unknown/);
    h.probes[0].reply({ available: true, port: 10086, code: null });
    await new Promise(resolve => setImmediate(resolve));
    assert.match(h.elements.portConflictHint.textContent, /unknown/);
});

test('accepted create intent polls its job without claiming a created link, saved draft or readiness', async () => {
    const job = { jobId: '507f1f77bcf86cd799439099', status: 'waiting', acceptanceRevision: 7 };
    const h = browserHarness({ job });
    await h.ui.openAddLinkModal();
    const request = await save(h);
    assert.match(request.headers['Idempotency-Key'], /^[a-f0-9-]{36}$/);
    assert.equal(h.timers.length, 1, JSON.stringify(h.toasts));
    assert(h.toasts.some(([message]) => /принят|accepted/i.test(message) && message.includes(job.jobId)));
    assert(!h.toasts.some(([message]) => /saved|сохранен|ready|готова/i.test(message)));
    await h.timers[0].fn();
    assert(h.requests.some(row => row.url.endsWith('/auto-deploy-jobs/' + job.jobId)));
    assert(!h.requests.some(row => row.url === '/api/cascade/topology/deploy'));
});

test('ordinary edit of a persisted autoDeploy link has no activation intent', async () => {
    const h = browserHarness({ persistedAutoDeploy: true });
    await h.ui.openEditLinkModal(LINK_ID);
    assert.equal(h.form.autoDeploy.checked, false);
    assert.equal(h.elements.linkAutoDeployLabel.textContent, 'Deploy this link after saving');
    assert.equal(h.elements.linkModalSubmit.textContent, 'Save');
    const request = await save(h);
    assert.equal(request.method, 'PUT');
    assert.equal(request.url, '/api/cascade/links/' + LINK_ID);
    assert.equal(Object.hasOwn(request.body, 'autoDeploy'), false);
    assert.equal(h.timers.length, 0);
});

test('explicit edit-and-deploy PUT consumes scoped operation without claiming readiness', async () => {
    const h = browserHarness({ operation: { operationId: OP_ID, status: 'queued', kind: 'link.apply' } });
    await h.ui.openEditLinkModal(LINK_ID);
    h.form.autoDeploy.checked = true;
    h.ui.updateLinkSubmitIntent();
    assert.equal(h.elements.linkModalSubmit.textContent, 'Save & Deploy');
    const request = await save(h);
    assert.equal(request.body.autoDeploy, true);
    assert.equal(h.timers.length, 1, 'queue response must start operation polling');
    assert(h.timers[0].delay > 0);
    assert(h.toasts.some(([message]) => /queued|очеред/i.test(message)));
    assert(!h.toasts.some(([message]) => /ready|готова/i.test(message)));
    assert(!h.requests.some(r => r.url === '/api/cascade/topology/deploy'));
    h.timers[0].fn();
    await new Promise(resolve => setImmediate(resolve));
    assert(h.requests.some(r => r.url === '/api/cascade/topology/operations/' + OP_ID));
    assert.equal(h.timers.length, 2, 'applied topology must keep polling for client proof');
    assert(!h.toasts.some(([message]) => /готовность подтверждена|ready/i.test(message)));
});

test('create retains checkbox opt-in and never starts unscoped deploy', async () => {
    const h = browserHarness({ operation: { operationId: OP_ID, status: 'queued', kind: 'link.apply' } });
    await h.ui.openAddLinkModal();
    assert.equal(h.form.autoDeploy.checked, true);
    assert.equal(h.elements.linkAutoDeployLabel.textContent, 'Auto Deploy');
    const request = await save(h);
    assert.equal(request.method, 'POST');
    assert.equal(request.body.autoDeploy, true);
    assert.equal(h.timers.length, 1);
    assert(!h.requests.some(r => r.url === '/api/cascade/topology/deploy'));
});

test('explicit edit opt-in with blocked API response reports failure, never ready', async () => {
    const h = browserHarness();
    await h.ui.openEditLinkModal(LINK_ID);
    h.form.autoDeploy.checked = true;
    const request = await save(h);
    assert.equal(request.body.autoDeploy, true);
    assert.equal(h.timers.length, 0);
    assert(h.toasts.some(([, type]) => type === 'error'));
    assert(!h.toasts.some(([message]) => /ready|готова/i.test(message)));
});

test('switching from edit to create clears edit intent while retaining create opt-in', async () => {
    const h = browserHarness();
    await h.ui.openEditLinkModal(LINK_ID);
    h.form.autoDeploy.checked = false;
    await h.ui.openAddLinkModal();
    assert.equal(h.form.autoDeploy.checked, true);
    assert.equal(h.elements.linkAutoDeployLabel.textContent, 'Auto Deploy');
    assert.equal(h.elements.linkModalSubmit.textContent, 'Create');
});

test('unconfirmed domain anchor directs the user to separate Deploy without any mutation', async () => {
    for (const status of ['pending', 'offline', 'error', 'syncing', undefined]) {
        const h = browserHarness({ links: [{ _id: LINK_ID, status, active: true }] });
        h.renderEdge();
        assert.match(h.elements.nodeInfoBody.innerHTML, /сначала выполните отдельный Deploy/);
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.length, 0, `must not submit ${status} anchor`);
        assert.equal(h.confirmations.length, 0);
        assert.equal(h.timers.length, 0);
        assert(h.toasts.some(([message, type]) => type === 'error'
            && /сначала выполните отдельный Deploy/.test(message)));
    }
});

test('typed 409 busy response offers a manual retry after the current operation, never replays', async () => {
    for (const code of ['TOPOLOGY_DEPLOY_BUSY', 'TOPOLOGY_OPERATION_BUSY', 'TOPOLOGY_DEPLOYMENT_BUSY', 'OPERATION_IN_PROGRESS']) {
        const h = browserHarness({ links: [{ _id: LINK_ID, status: 'deployed', active: true }],
            deployResponse: { status: 409, body: { error: { code, message: 'secret=do-not-display' } } } });
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.filter(r => r.url === '/api/cascade/topology/deploy').length, 1);
        assert(h.reloads > 0, 'conflict must refresh the snapshot');
        assert.equal(h.timers.length, 0, 'busy is not an accepted operation and must not schedule retry');
        assert(h.toasts.some(([message, type]) => type === 'error' && message.includes(code)
            && /дождитесь завершения/i.test(message) && /повторите вручную/i.test(message)));
        assert(!h.toasts.some(([message]) => message.includes('do-not-display')));
    }
});

test('blocked auto-deploy surfaces typed busy guidance after saving without retrying', async () => {
    for (const mode of ['create', 'edit']) {
        const h = browserHarness({ autoDeployError: { code: 'TOPOLOGY_DEPLOY_BUSY',
            message: 'secret=do-not-display', retryable: true } });
        if (mode === 'edit') await h.ui.openEditLinkModal(LINK_ID);
        else await h.ui.openAddLinkModal();
        h.form.autoDeploy.checked = true;
        await save(h);
        assert.equal(h.requests.filter(r => ['PUT', 'POST'].includes(r.method)).length, 1);
        assert(!h.requests.some(r => r.url === '/api/cascade/topology/deploy'));
        assert.equal(h.timers.length, 0, 'retryable hint must not schedule an automatic deploy');
        assert(h.toasts.some(([message, type]) => type === 'error' && message.includes('TOPOLOGY_DEPLOY_BUSY')
            && /дождитесь завершения/i.test(message) && /повторите вручную/i.test(message)));
        assert(!h.toasts.some(([message]) => message.includes('do-not-display')));
    }
});

test('domain Sync explains confirmed-only scope despite legacy chain translations', async () => {
    const h = browserHarness({ links: [
        { _id: LINK_ID, status: 'deployed', active: true },
        { _id: '507f1f77bcf86cd799439033', status: 'pending', active: true },
    ] });
    h.renderEdge();
    const html = h.elements.nodeInfoBody.innerHTML;
    assert.match(html, /Sync применённого домена/);
    assert.match(html, /Только подтверждённые применённые связи/);
    assert.match(html, /[Оо]жидающие связи не включаются/);
    assert.doesNotMatch(html, /Sync Chain/);
    await h.window._cascadeDeployChain(LINK_ID);
    assert.equal(h.confirmations.length, 1);
    assert.match(h.confirmations[0], /подтверждённые применённые связи/);
    assert.match(h.confirmations[0], /[Оо]жидающие связи не включаются/);
    assert.doesNotMatch(h.confirmations[0], /entire chain|all connected/);
    const deploys = h.requests.filter(r => r.url === '/api/cascade/topology/deploy');
    assert.equal(deploys.length, 1);
    assert.deepEqual(deploys[0].body, { expectedTopologyRevision: 7, domainLinkId: LINK_ID });
    assert.equal(h.timers.length, 1, 'accepted scoped operation still starts identity-bound polling');
});

test('all API-confirmed anchor states remain eligible for scoped Sync', async () => {
    for (const status of ['deployed', 'online', 'staged']) {
        const h = browserHarness({ links: [{ _id: LINK_ID, status, active: true }] });
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.length, 1);
        assert.deepEqual(h.requests[0].body, { expectedTopologyRevision: 7, domainLinkId: LINK_ID });
    }
});

test('missing, disabled or newly unconfirmed anchors cannot submit domain Sync', async () => {
    for (const links of [[], [{ _id: LINK_ID, status: 'deployed', active: false }]]) {
        const h = browserHarness({ links });
        await h.window._cascadeDeployChain(LINK_ID);
        assert.equal(h.requests.length, 0);
        assert.equal(h.confirmations.length, 0);
        assert(h.toasts.some(([, type]) => type === 'error'));
    }
    const links = [{ _id: LINK_ID, status: 'deployed', active: true }];
    const h = browserHarness({ links });
    h.renderEdge();
    links[0].status = 'pending';
    await h.window._cascadeDeployChain(LINK_ID);
    assert.equal(h.requests.length, 0, 'click must check the latest snapshot, not the drawn edge color');
});

test('cancelled domain Sync does not mutate while Full Sync requires its own explicit confirmation', async () => {
    const h = browserHarness({ links: [{ _id: LINK_ID, status: 'deployed', active: true }], confirmResult: false });
    await h.window._cascadeDeployChain(LINK_ID);
    await h.window._cascadeDeployFull();
    assert.equal(h.requests.length, 0);
    assert.equal(h.confirmations.length, 2);
    assert.match(h.confirmations[1], /всю топологию/);
    const full = browserHarness();
    await full.window._cascadeDeployFull();
    assert.deepEqual(full.requests[0].body, { expectedTopologyRevision: 7 });
    assert.equal(full.confirmations.length, 1);
});

test('server-side unconfirmed rejection stays actionable without expanding scope', async () => {
    const h = browserHarness({ links: [{ _id: LINK_ID, status: 'deployed', active: true }],
        deployResponse: { status: 422, body: { error: { code: 'INVALID_TOPOLOGY_DEPLOYMENT' },
            errors: [{ code: 'SCOPE_LINK_UNCONFIRMED' }] } } });
    await h.window._cascadeDeployChain(LINK_ID);
    assert.equal(h.requests.length, 1);
    assert.equal(h.requests[0].body.domainLinkId, LINK_ID);
    assert.equal(h.timers.length, 0);
    assert(h.toasts.some(([message]) => /сначала выполните отдельный Deploy/.test(message)));
});

test('dedicated link deploy still sends the linkId, never unscoped', async () => {
    const h = browserHarness({ links: [{ _id: LINK_ID, status: 'pending', active: true }] });
    await h.window._cascadeDeploy(LINK_ID);
    assert.equal(h.confirmations.length, 1);
    const deploy = h.requests.find(r => r.url === '/api/cascade/topology/deploy');
    assert.equal(deploy.method, 'POST');
    assert.equal(deploy.body.linkId, LINK_ID);
    assert.equal(deploy.body.expectedTopologyRevision, 7);
    assert.equal(h.timers.length, 1);
});
