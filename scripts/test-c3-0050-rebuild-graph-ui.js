'use strict';

// Isolated UI regression: real EJS and its selected asset, with DOM, graph
// rendering and fetch adapters. No HTTP server, database or node transport.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const ejs = require('ejs');
const en = require('../src/locales/en.json');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const csrfToken = 'synthetic-csrf';
const linksUrl = '/api/cascade/links';
const previewUrl = '/api/cascade/rebuild/preview';
const portCheckUrl = linksUrl + '/port-check?';
const nodes = [
    { _id: '000000000000000000000001', name: 'Portal', ip: '192.0.2.1', cascadeRole: 'portal' },
    { _id: '000000000000000000000002', name: 'Bridge', ip: '192.0.2.2', cascadeRole: 'bridge' },
];
const [portal, bridge] = nodes;
const linkId = '000000000000000000000003';
const link = { _id: linkId, name: 'Existing link', active: true, status: 'deployed', mode: 'reverse',
    portalNode: portal._id, bridgeNode: bridge._id, tunnelPort: 10086 };
const render = (view, c3Rebuild) => ejs.render(read('views/' + view + '.ejs'), {
    c3Rebuild, csrfToken, nodes: [], groups: [], nodesCount: 2, linksCount: 1, loadBalancingEnabled: false,
    t: key => key.split('.').reduce((value, part) => value?.[part], en) ?? key,
}, { filename: path.join(root, 'views', `${view}.ejs`) });
const attr = (tag, name) => tag.match(new RegExp('(?:^|\\s)' + name + '="([^"]*)"'))?.[1];
const tags = html => [...html.replace(/<!--[\s\S]*?-->/g, '').matchAll(/<[a-z][\w-]*(?:[^'"<>]|"[^"]*"|'[^']*')*>/gi)].map(m => m[0]);
const origin = 'http://127.0.0.1:3000';
const reply = (body, status = 200, url) => ({ ok: status < 300, status, url, async json() { return body; } });
const tick = () => new Promise(resolve => setImmediate(resolve));

async function graphUI(t, { rebuild = true, confirmations = [], preview = { allowed: true } } = {}) {
    const html = render('nodes', rebuild);
    const requests = [], errors = [], unexpected = [], timers = new Map(), observers = new Map(), toasts = [];
    const elements = new Map(), taps = new Map();
    let sequence = 0, assetUrl, entries = [], rows = [link];
    const snapshot = () => ({ topologyRevision: 12, deployedRevision: 11, links: rows });
    const collection = items => Object.assign(items, { toArray: () => items,
        filter: fn => collection(Array.prototype.filter.call(items, fn)), data: (...args) => items[0]?.data(...args) });
    const graph = {
        on(event, selector, handler) { if (handler) taps.set(event + ':' + selector, handler); },
        resize() {}, fit() {}, zoom() {}, pan() {},
        nodes: () => collection(entries.filter(e => e.group === 'nodes')),
        edges: () => collection(entries.filter(e => e.group === 'edges')),
        getElementById(id) { return entries.find(e => e.id() === id) || { length: 0 }; },
        elements: () => ({ remove() { entries = []; }, unselect() {} }),
        add(data) { entries = data.map(({ group, data, position }) => ({ group, length: 1,
            id: () => data.id, position: () => position,
            data(key, value) { if (value !== undefined) data[key] = value; return key === undefined ? data : data[key]; },
        })); },
    };
    function element(tag = '') {
        const listeners = new Map(), classes = new Set((attr(tag, 'class') || '').split(' '));
        const el = { tag, value: attr(tag, 'value') ?? '', checked: /\schecked(?=\s|>)/.test(tag),
            style: { display: attr(tag, 'style')?.match(/display:\s*([^;]+)/)?.[1] ?? '' },
            innerHTML: '', textContent: '', options: [], appendChild() {}, reset() {},
            querySelector: () => null, querySelectorAll: () => [], getAttribute: key => attr(tag, key),
            classList: { contains: value => classes.has(value),
                add(value) { classes.add(value); changed(); }, remove(value) { classes.delete(value); changed(); },
                toggle(value, on) { if (on) this.add(value); else this.remove(value); } },
            addEventListener(type, fn) { listeners.set(type, [...(listeners.get(type) || []), fn]); },
            async dispatch(type) {
                for (const fn of listeners.get(type) || []) await fn.call(el, { target: el, preventDefault() {} });
            },
        };
        function changed() { if (observers.has(el)) queueMicrotask(observers.get(el)); }
        return el;
    }
    for (const tag of tags(html.split('<script')[0])) {
        const id = attr(tag, 'id');
        if (id) elements.set(id, element(tag));
    }
    const get = id => elements.get(id) ?? null;
    for (const [formId, switcherId] of [['addLinkForm', 'modeSwitcher'], ['quickLinkForm', 'quickModeSwitcher']]) {
        const formHtml = html.match(new RegExp('<form id="' + formId + '"[\\s\\S]*?</form>'))[0];
        const form = get(formId);
        const formTags = tags(formHtml);
        const field = tag => get(attr(tag, 'id')) || element(tag);
        for (const tag of formTags.filter(tag => attr(tag, 'name'))) form[attr(tag, 'name')] = field(tag);
        for (const [, tag, optionHtml] of formHtml.matchAll(/(<select[^>]*>)([\s\S]*?)<\/select>/g)) {
            const select = form[attr(tag, 'name')] || get(attr(tag, 'id'));
            select.options = tags(optionHtml).filter(tag => tag.startsWith('<option')).map(element);
            select.value = (select.options.find(opt => /\sselected(?=\s|>)/.test(opt.tag)) ?? select.options[0])?.value ?? '';
        }
        const submit = field(formTags.find(tag => attr(tag, 'type') === 'submit'));
        form.querySelector = selector => selector === '[type="submit"]' ? submit : null;
        const modeButtons = formTags.filter(tag => attr(tag, 'data-mode')).map(element);
        get(switcherId).querySelectorAll = selector => selector === '.mode-btn' ? modeButtons : [];
    }
    const refusals = [];
    const window = { location: { origin }, alert: message => refusals.push(message),
        crypto: { randomUUID: require('node:crypto').randomUUID }, showToast: (...args) => toasts.push(args) };
    const document = {
        readyState: 'complete', getElementById: get, createElement: () => element(),
        querySelector(selector) {
            const match = selector.match(/^#addLinkForm \[name="([^"]+)"\]$/);
            return match ? get('addLinkForm')[match[1]] : null; // no canvas animation or loading decoration
        },
        body: { appendChild(script) {
            if (script.src.startsWith('/js/')) assetUrl = script.src;
            script.onload(); // resolve external graph library loading without network
        } },
    };
    const context = vm.createContext({ window, document, cytoscape: () => graph, AbortController, URL, URLSearchParams,
        setTimeout(fn, delay) { timers.set(++sequence, { fn, delay }); return sequence; },
        clearTimeout: id => timers.delete(id), setInterval() {},
        MutationObserver: class { constructor(fn) { this.fn = fn; } observe(el) { observers.set(el, this.fn); } },
        confirm() { return confirmations.shift() ?? true; },
        alert(message) { errors.push(message); }, console: { error: (...args) => errors.push(args) },
        async fetch(input, options = {}) {
            const absolute = new URL(input, origin);
            assert.equal(absolute.origin, origin);
            const url = absolute.pathname + absolute.search;
            const method = options.method || 'GET';
            requests.push({ url, method, headers: options.headers, body: options.body && JSON.parse(options.body) });
            if (method === 'GET' && url === linksUrl) return reply(snapshot());
            if (method === 'GET' && url === '/api/nodes') return reply(nodes);
            if (method === 'GET' && url === '/api/cascade/topology/activation-policy') return reply({});
            if (method === 'GET' && url === '/api/cascade/topology') return reply({
                nodes: nodes.map(n => ({ data: { id: n._id, label: n.name }, position: { x: 0, y: 0 } })),
                edges: rows.map(l => ({ data: { ...l, id: 'link-' + l._id, linkId: l._id,
                    source: l.portalNode, target: l.bridgeNode, label: l.name } })),
            });
            if (method === 'POST' && url === previewUrl) return reply({ nodes: [], previewId: 'remove-proof', ...preview });
            if (method === 'DELETE' && url === linksUrl + '/' + linkId) {
                rows = [];
                return reply({ executionMode: 'rebuild', deleted: linkId });
            }
            if (method === 'POST' && url === linksUrl + '/' + linkId + '/undeploy') return reply({ success: true });
            if (method === 'GET' && url.startsWith(portCheckUrl)) {
                if (rebuild) return reply({ error: { code: 'REBUILD_STRICT_DISABLED' } }, 409);
                return reply({ available: false, port: 10087, code: 'TUNNEL_PORT_IN_USE' });
            }
            if (method === 'POST' && url === linksUrl) return rebuild
                ? reply({ executionMode: 'rebuild', desiredSaved: true, linkId: '000000000000000000000004',
                    status: 'awaiting_preview', preview: { allowed: false, nodes: [] } }, 201, absolute.href)
                : reply(snapshot(), 201);
            unexpected.push(method + ' ' + url);
            throw Error('Unexpected fixture request');
        },
    });
    t.after(() => {
        assert.deepEqual(unexpected, []);
        assert.deepEqual(errors, []);
    });
    const start = html.indexOf('window._networkCsrfToken =');
    const end = html.indexOf('// Restore network view after page load', start);
    assert.ok(start >= 0 && end > start, 'load the real nodes graph script and UI bindings');
    const labels = html.match(/window\._networkRebuildPreviewI18n = [^\n]+/);
    if (labels) vm.runInContext(labels[0], context);
    vm.runInContext(html.slice(start, end) + '\nloadNetworkScripts();', context);
    assert.match(assetUrl, rebuild ? /^\/js\/network\.js\?v=.+$/ : /^\/js\/network\.min\.js\?v=[a-f0-9]{16}$/);
    vm.runInContext(read('public' + assetUrl.split('?')[0]), context, { filename: assetUrl });
    async function flush(delay) {
        await tick();
        for (const [key, task] of timers) if (task.delay === delay) { timers.delete(key); await task.fn(); }
        await tick();
    }
    await flush(30); // initial graph load from the normal init() path
    const info = get('nodeInfoBody');
    return { get, graph, window, assetUrl, flush, toasts, refusals,
        checks: () => requests.filter(req => req.url.startsWith(portCheckUrl)),
        writes: () => requests.filter(req => req.method !== 'GET'),
        tapEdge() { taps.get('tap:edge')({ target: graph.getElementById('link-' + linkId) }); },
        actionIds: () => tags(info.innerHTML).filter(tag => tag.startsWith('<button')).map(tag => attr(tag, 'id')),
        async clickAction(id) {
            const tag = tags(info.innerHTML).find(tag => attr(tag, 'id') === id);
            assert.ok(tag, 'drawer action not rendered: ' + id);
            await vm.runInContext(attr(tag, 'onclick'), context);
        },
    };
}

async function openCreate(ui, kind) {
    const quick = kind === 'quick';
    const form = ui.get(quick ? 'quickLinkForm' : 'addLinkForm');
    const modal = ui.get(quick ? 'quickLinkModal' : 'addLinkModal');
    if (quick) {
        // Quick has no built-in opener today; activate its shipped modal as an integration would.
        ui.get('quickPortalId').value = portal._id;
        ui.get('quickBridgeId').value = bridge._id;
        ui.get('quickLinkName').value = 'New link';
        modal.classList.add('active');
    } else {
        await ui.get('btnAddLink').dispatch('click');
        assert(form.portalNodeId.innerHTML.includes(portal._id));
        assert(form.bridgeNodeId.innerHTML.includes(bridge._id));
        form.portalNodeId.value = portal._id;
        form.bridgeNodeId.value = bridge._id;
        form.name.value = 'New link';
    }
    assert(modal.classList.contains('active'));
    const port = quick ? ui.get('quickTunnelPort') : form.tunnelPort;
    const auto = quick ? ui.get('quickAutoDeploy') : form.autoDeploy;
    const switcher = ui.get(quick ? 'quickModeSwitcher' : 'modeSwitcher');
    const mode = value => switcher.querySelectorAll('.mode-btn').find(btn => btn.getAttribute('data-mode') === value).dispatch('click');
    port.value = '10087';
    await port.dispatch('input');
    await mode('forward');
    await ui.flush(300);
    return { port, auto, mode, form, modal, hintId: quick ? 'quickPortConflictHint' : 'portConflictHint' };
}

for (const kind of ['main', 'quick']) {
    test(`rebuild ${kind} create skips unavailable port checks and never asserts availability`, async t => {
        const ui = await graphUI(t);
        const { form, modal, port, auto, mode, hintId } = await openCreate(ui, kind);
        assert.deepEqual(ui.checks(), [], 'opening and changing a valid listener must not probe the strict route');
        assert.equal(ui.get(hintId), null, 'no advisory status (unknown, checking, occupied or available) in rebuild');
        assert(!(port.getAttribute('aria-describedby') || '').split(' ').includes(hintId));
        if (kind === 'main') assert.match(ui.get('tunnelPortHint').textContent, /bridge/i);
        // A cached clash must not become a classic submit gate; rebuild uses server validation/preview.
        port.value = '10086';
        await port.dispatch('change');
        await mode('reverse');
        if (kind === 'quick') {
            await ui.get('quickSwapBtn').dispatch('click');
            await ui.get('quickSwapBtn').dispatch('click');
        }
        auto.checked = true;
        await form.dispatch('submit');
        await ui.flush(300);
        assert.deepEqual(ui.checks(), []);
        const [created, ...extra] = ui.writes();
        assert.deepEqual(extra, []);
        assert.equal(created?.url, linksUrl);
        assert.equal(created.method, 'POST');
        assert.equal(created.body.tunnelPort, 10086);
        assert.equal(created.body.autoDeploy, true);
        assert.equal(created.body.interactivePreview, true);
        assert.equal(created.headers['x-csrf-token'], csrfToken);
        assert.equal(modal.classList.contains('active'), false);
        assert.deepEqual(ui.refusals, [en.network.rebuildPreview.refused]);
        assert.equal(ui.toasts.length, 1);
        assert.equal(ui.toasts[0][1], 'error');
        assert(ui.toasts[0][0].endsWith(en.network.rebuildPreview.refused));
    });

    test(`classic ${kind} create retains the listener probe, warning and occupied deploy block`, async t => {
        const ui = await graphUI(t, { rebuild: false });
        const { form, port, auto, hintId } = await openCreate(ui, kind);
        assert.deepEqual(ui.checks().map(req => req.url), [portCheckUrl + 'nodeId=' + bridge._id + '&port=10087']);
        assert(port.getAttribute('aria-describedby').includes(hintId));
        assert.match(ui.get(hintId).textContent, /10087.*already in use/i);
        auto.checked = true;
        await form.dispatch('submit');
        assert.deepEqual(ui.writes(), []);
        auto.checked = false;
        await form.dispatch('submit');
        assert.equal(ui.writes()[0]?.body.autoDeploy, false, 'classic draft save remains possible');
    });
}
