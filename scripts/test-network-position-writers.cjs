'use strict';
// node --experimental-vm-modules --test scripts/test-network-position-writers.cjs
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const { network } = require('../src/locales/en.json');
const { requirePanelCsrf } = require('../src/routes/panel/csrf');

const dir = path.resolve(__dirname, '../public/js');
const origin = 'https://panel.example.invalid';
const token = 'A'.repeat(43);
const endpoint = '/api/cascade/topology/positions';
const oid = '507F1F77BCF86CD799439011';
const rows = [
    { id: oid, role: 'portal', x: 12.34, y: -6.25 },
    { id: 'internet', role: 'internet', x: 41.2, y: 0 },
    { id: 'cdn-fixture', role: 'cdn', x: 1, y: 4 },
    { id: '507F1F77BCF86CD799439012', role: 'cdn', x: 6, y: 9 },
    { id: `${oid}\n`, role: 'relay', x: 3, y: 4 },
];
const expected = [{ id: oid.toLowerCase(), x: 12.3, y: -6.2 }, { id: 'internet', x: 41.2, y: 0 }];
const response = (url, status, body, extra = {}) => ({
    url, status, ok: status >= 200 && status < 300, redirected: false,
    headers: { get: () => 'application/json; charset=utf-8' },
    async json() { return body; }, clone() { return this; }, ...extra,
});
const csrf = code => ({ error: 'CSRF validation failed', code });

function wire(send) {
    const requests = [], toasts = [];
    return {
        requests, toasts,
        window: { _networkCsrfToken: token, _networkI18n: network, location: { origin }, showToast: (...args) => toasts.push(args) },
        async fetch(url, options) {
            requests.push({ url, ...options });
            return send(url, options);
        },
    };
}

function legacy(send, { rebuild = true, points = rows } = {}) {
    const io = wire(send);
    io.window._c3Rebuild = rebuild;
    const timers = new Map();
    let nextTimer = 0;
    const nodes = points.map(p => ({
        id: () => p.id,
        data: key => ({ id: p.id, type: p.role, cascadeRole: p.role })[key],
        position: () => ({ x: p.x, y: p.y }),
    }));
    const src = readFileSync(path.join(dir, 'network.js'), 'utf8');
    const code = src.replace('    // ==================== START ====================',
        '    cy = graph; window.dragEnd = onNodeDragEnd;\n    // ==================== START ====================');
    assert.notEqual(code, src);
    vm.runInNewContext(code, {
        window: io.window, fetch: io.fetch, URL, AbortController, cytoscape() {}, graph: { nodes: () => nodes },
        document: { readyState: 'loading', addEventListener() {} },
        setTimeout(fn) { timers.set(++nextTimer, fn); return nextTimer; }, clearTimeout(id) { timers.delete(id); },
    });
    return { ...io, async dragEnd() {
        io.window.dragEnd();
        assert.equal(timers.size, 1);
        const [id, fn] = timers.entries().next().value;
        timers.delete(id);
        await fn();
        assert.equal(timers.size, 0, 'no deferred write or retry');
    } };
}

function assertPanelWrite(req) {
    assert.equal(req.url, origin + endpoint);
    assert.equal(req.method, 'POST');
    assert.equal(req.headers['x-csrf-token'], token);
    assert.equal(req.mode, 'same-origin');
    assert.equal(req.credentials, 'same-origin');
    assert.equal(req.redirect, 'error');
    assert.deepEqual(JSON.parse(req.body), { positions: expected });
    let passed = false;
    requirePanelCsrf({ method: req.method, protocol: 'https', headers: { ...req.headers, origin, host: new URL(origin).host },
        session: { authenticated: true, panelCsrfToken: token } }, { status: () => assert.fail('CSRF refused') }, () => { passed = true; });
    assert.equal(passed, true);
}

test('legacy Rebuild saves the normalized layout once after an actual drag event', async () => {
    const ui = legacy(url => response(url, 200, { success: true }));
    assert.deepEqual(ui.requests, []);
    await ui.dragEnd();
    assert.equal(ui.requests.length, 1);
    assertPanelWrite(ui.requests[0]);
    assert.ok(ui.toasts.every(([, kind]) => kind !== 'error'));
});

test('legacy Classic keeps its relative session route and excludes synthetic rows', async () => {
    const ui = legacy(url => response(url, 200, { success: true }), { rebuild: false });
    await ui.dragEnd();
    assert.equal(ui.requests.length, 1);
    assert.equal(ui.requests[0].url, endpoint);
    assert.equal(ui.requests[0].headers['x-csrf-token'], undefined);
    assert.deepEqual(JSON.parse(ui.requests[0].body), { positions: expected });
});

test('legacy Rebuild surfaces failure without replay, including after a token refresh', async () => {
    for (const reply of [
        url => response(url, 500, { error: 'write failed' }),
        url => response(url, 200, { success: false }),
        url => response(url, 200, { success: true }, { redirected: true }),
        () => { throw new Error('connection lost'); },
        url => response(url, 403, csrf('CSRF_ORIGIN_INVALID')),
        (url, { method }) => method === 'POST' ? response(url, 403, csrf('CSRF_TOKEN_INVALID'))
            : response(url, 200, { csrfRequired: true, csrfToken: 'B'.repeat(43) }),
    ]) {
        const ui = legacy(reply);
        await ui.dragEnd();
        assert.deepEqual(ui.requests.filter(r => r.method !== 'GET').map(r => r.url), [origin + endpoint]);
        assert.deepEqual(ui.toasts.map(([, kind]) => kind), ['error']);
    }
});

class Element {
    constructor(tag, text = '') { Object.assign(this, { tag, text, children: [], dataset: {}, style: { setProperty() {} }, attrs: {}, listeners: {},
        classList: { toggle() {}, contains() { return false; } } }); }
    get firstChild() { return this.children[0]; }
    append(...children) { this.children.push(...children); }
    appendChild(el) { this.append(el); return el; }
    removeChild(el) { this.children.splice(this.children.indexOf(el), 1); }
    setAttribute(name, value) { this.attrs[name] = value; if (name === 'disabled') this.disabled = true; }
    addEventListener(event, fn) { this.listeners[event] = fn; }
    get descendants() { return this.children.flatMap(el => [el, ...el.descendants]); }
}

async function modern(send, { canSavePositions = true, points = rows, session = token } = {}) {
    const io = wire(send);
    io.window._networkCsrfToken = session;
    const elements = new Map();
    let onLayoutStop, pan = { x: 19, y: 5 }, zoom = 1;
    const cy = {
        nodes: () => [...elements.values()], edges: () => [], batch: fn => fn(),
        getElementById: id => elements.get(id) || [],
        add({ data, position }) {
            elements.set(data.id, { length: 1, id: () => data.id, data(key, value) {
                if (arguments.length > 1) data[key] = value;
                else if (typeof key === 'object') Object.assign(data, key);
                else return data[key];
            }, position: () => position, renderedPosition: () => position, toggleClass() {}, remove: () => elements.delete(data.id) });
        },
        layout: () => ({ one: (_event, fn) => { onLayoutStop = fn; }, run() {} }),
        on() {}, resize() {}, width: () => 900, height: () => 700, fit() { pan = { x: 0, y: 0 }; },
        zoom(value) { if (value !== undefined) zoom = value; return zoom; },
        pan(value) { if (value !== undefined) pan = value; return pan; },
        destroy() {},
    };
    const model = require('../public/js/network/src/core/model.js');
    const nodes = points.map(p => ({ id: p.id, type: p.role === 'cdn' ? 'cdn' : p.role === 'internet' ? 'internet' : 'xray',
        role: p.role, cascadeRole: p.role, status: 'online', position: { x: p.x, y: p.y } }));
    const store = {
        state: { filter: { roles: new Set(), query: '' }, selection: null },
        index: { nodes: new Map(nodes.filter(n => n.id !== 'internet').map(n => [n.id, n])),
            internet: nodes.find(n => n.id === 'internet'), links: new Map(), cdnEdges: new Map() },
    };
    const el = new Element('div');
    const toolbar = { slot: new Element('div') };
    const document = {
        createElement: tag => new Element(tag), createElementNS: (_ns, tag) => new Element(tag),
        createTextNode: text => new Element('#text', text), addEventListener() {}, removeEventListener() {},
        getElementById: () => ({ textContent: JSON.stringify(network) }),
    };
    const context = vm.createContext({ window: io.window, document, Node: Element, URL, fetch: io.fetch, requestAnimationFrame() {} });
    const modules = new Map();
    function load(id) {
        if (modules.has(id)) return modules.get(id);
        const stubs = { cytoscape: Object.assign(() => cy, { use() {} }), 'cytoscape-dagre': {}, [path.join(dir, 'network/src/core/model.js')]: model };
        const mod = Object.hasOwn(stubs, id)
            ? new vm.SyntheticModule(['default'], function () { this.setExport('default', stubs[id]); }, { context, identifier: id })
            : new vm.SourceTextModule(readFileSync(id, 'utf8'), { context, identifier: id });
        modules.set(id, mod);
        return mod;
    }
    const mod = load(path.join(dir, 'network/src/views/graph.js'));
    await mod.link((specifier, from) => load(specifier.startsWith('.') ? path.resolve(path.dirname(from.identifier), specifier) : specifier));
    await mod.evaluate();
    const view = mod.namespace.mount(el, { store, toolbar, canSavePositions });
    const button = label => [...el.descendants, ...toolbar.slot.descendants].find(e => e.tag === 'button' && e.attrs['aria-label'] === label);
    return { ...io, view, cy, store, button,
        paint: () => view.update({ type: 'data', structural: true }),
        layoutStop: () => onLayoutStop(),
        saveButton: () => button(network.map.savePositions),
    };
}

test('modern Graph writes only on the enabled Rebuild button, preserving local coordinates and view', async () => {
    let finish;
    const ui = await modern(url => new Promise(resolve => { finish = () => resolve(response(url, 200, { success: true })); }));
    const button = ui.saveButton();
    assert.ok(button, 'Rebuild Graph has a real and labeled save button');
    assert.equal(button.disabled, true);
    ui.paint();
    ui.button(network.map.autoLayout).listeners.click();
    assert.equal(button.disabled, true, 'no save while layout is moving nodes');
    ui.layoutStop();
    ui.view.resize();
    assert.equal(button.disabled, false);
    assert.deepEqual(ui.requests, []);
    const before = JSON.stringify(ui.cy.nodes().map(n => n.position()));
    const pan = { x: 31, y: 67 };
    ui.cy.pan(pan);
    ui.cy.zoom(0.8);
    const pending = button.listeners.click();
    assert.equal(button.disabled, true);
    await button.listeners.click();
    assert.equal(ui.requests.length, 1);
    assertPanelWrite(ui.requests[0]);
    finish();
    await pending;
    assert.equal(button.disabled, false);
    assert.equal(JSON.stringify(ui.cy.nodes().map(n => n.position())), before);
    assert.deepEqual(ui.cy.pan(), pan);
    assert.equal(ui.cy.zoom(), 0.8);
    assert.deepEqual(ui.toasts, [[network.positionsSaved, 'success']]);
    ui.view.destroy();
    assert.equal(ui.requests.length, 1);
});

test('modern Graph stays read-only without the renderer capability, and omits empty writes', async () => {
    const noFetch = () => assert.fail('unexpected fetch');
    const readOnly = await modern(noFetch, { canSavePositions: false });
    readOnly.paint();
    assert.equal(readOnly.saveButton(), undefined);
    const empty = await modern(noFetch, { points: rows.filter(p => p.role === 'cdn') });
    empty.paint();
    assert.equal(empty.saveButton().disabled, true);
    await empty.saveButton().listeners.click();
    assert.equal(empty.requests.length, 0);
});

test('modern Graph reports CSRF refusal or an unconfirmed save without refresh or retry', async () => {
    for (const [reply, detail] of [
        [url => response(url, 403, csrf('CSRF_TOKEN_INVALID')), network.positionsSaveSessionChanged],
        [url => response(url, 403, csrf('CSRF_AUTH_REQUIRED')), network.csrfAuthRequired],
        [url => response(url, 403, csrf('CSRF_ORIGIN_INVALID')), network.csrfOriginInvalid],
        [url => response(url, 400, { error: 'invalid positions.0.x' }), ''],
        [url => response(url, 200, { success: false }), ''],
        [url => response(url, 200, { success: true }, { url: `${origin}/login` }), ''],
        [url => response(url, 200, { success: true }, { headers: { get: () => 'text/html' } }), ''],
        [() => { throw new Error('connection lost'); }, ''],
    ]) {
        const ui = await modern(reply);
        ui.paint();
        await ui.saveButton().listeners.click();
        assert.equal(ui.requests.length, 1);
        assert.deepEqual(ui.toasts, [[network.positionsSaveFailed + (detail ? ` ${detail}` : ''), 'error']]);
        assert.equal(ui.saveButton().disabled, false);
    }
});

test('invalid bounds and missing modern tokens fail locally with no position POST', async () => {
    const noFetch = () => assert.fail('unexpected fetch');
    const points = [{ ...rows[0], x: 1e6 + 1 }, ...rows.slice(1)];
    const oldMap = legacy(noFetch, { points });
    await oldMap.dragEnd();
    assert.deepEqual(oldMap.requests, []);
    assert.deepEqual(oldMap.toasts, [[network.positionsSaveFailed, 'error']]);
    for (const [opts, detail] of [[{ points }, ''], [{ session: '' }, ` ${network.positionsSaveSessionChanged}`]]) {
        const ui = await modern(noFetch, opts);
        ui.paint();
        await ui.saveButton().listeners.click();
        assert.deepEqual(ui.requests, []);
        assert.deepEqual(ui.toasts, [[network.positionsSaveFailed + detail, 'error']]);
    }
});
