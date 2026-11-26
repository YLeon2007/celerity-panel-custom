'use strict';

// node --experimental-vm-modules --test scripts/test-network-create-mount.cjs
// Exercise the real entry, inspector, store and actions. The separately owned
// form is replaced at its export boundary; no server, renderer or browser I/O.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const ejs = require('ejs');
const { getLocale, t: translate } = require('../src/middleware/i18n');

const src = path.resolve(__dirname, '../public/js/network/src');
const dist = path.resolve(src, '../dist');
const model = require(path.join(src, 'core/model.js'));
const source = '1'.repeat(24), target = '2'.repeat(24), linkId = '3'.repeat(24);
const edgeId = `link-${linkId}`;
const tick = () => new Promise(resolve => setImmediate(resolve));

class Element {
    constructor(tag = 'div', text = '') {
        this.tag = tag;
        this.text = text;
        this.children = [];
        this.dataset = {};
        this.style = {};
        this.attrs = {};
        this.events = {};
        this.className = '';
        this.classList = {
            add: cls => { this.className += ` ${cls}`; },
            remove: cls => { this.className = this.className.split(' ').filter(x => x !== cls).join(' '); },
            contains: cls => this.className.split(' ').includes(cls),
            toggle: (cls, on) => on ? this.classList.add(cls) : this.classList.remove(cls),
        };
    }
    appendChild(el) { this.children.push(el); }
    append(...els) { this.children.push(...els.map(el => el instanceof Element ? el : new Element('#text', String(el)))); }
    replaceChildren(...els) { this.children = []; this.append(...els); }
    removeChild(el) { this.children.splice(this.children.indexOf(el), 1); }
    get firstChild() { return this.children[0]; }
    get textContent() { return this.text + this.children.map(el => el.textContent).join(''); }
    set textContent(text) { this.text = String(text); this.children.length = 0; }
    get descendants() { return this.children.flatMap(el => [el, ...el.descendants]); }
    setAttribute(k, v) { this.attrs[k] = v; }
    querySelector(cls) { return this.descendants.find(el => el.classList.contains(cls.slice(1))); }
    querySelectorAll(cls) { return this.descendants.filter(el => el.classList.contains(cls.slice(1))); }
    addEventListener(evt, fn) { (this.events[evt] ||= []).push(fn); }
    click() { return this.hidden || this.disabled ? [] : (this.events.click || []).map(fn => fn({ target: this, stopPropagation() {} })); }
}

async function boot({ authorized = true, showButton = authorized, shipped = false, lang = 'en', send } = {}) {
    const root = new Element(), view = new Element(), toolbar = new Element();
    const add = new Element('button'), refresh = new Element('button');
    const inspector = new Element('aside');
    inspector.className = 'nm-insp';
    for (const cls of ['nm-bar', 'nm-stage', 'nm-state']) {
        const child = new Element();
        child.className = cls;
        root.append(child);
    }
    root.append(inspector);
    view.append(root);
    toolbar.append(refresh);
    if (authorized) root.dataset.linkActions = 'true';
    else root.dataset.readOnly = 'true';
    if (showButton) { add.disabled = true; toolbar.append(add); }
    const elements = { viewNetwork: view, networkToolbar: toolbar, networkRoot: root, btnNetworkRefresh: refresh };
    if (showButton) elements.btnAddLink = add;
    const document = {
        readyState: 'complete', getElementById: id => elements[id] || null,
        querySelectorAll: () => [], addEventListener() {}, removeEventListener() {},
        createElement: tag => new Element(tag), createTextNode: text => new Element('#text', text),
    };
    toolbar.querySelector = sel => sel === '#btnAddLink' && showButton ? add : null;
    let store, poll;
    let topology = { nodes: [source, target].map((id, i) => ({ data: { id, type: 'xray', label: `Node ${i + 1}` } })), edges: [] };
    const window = {}, opens = [], requests = [], focuses = [];
    let rendered;
    if (shipped) {
        window._networkCsrfToken = 'a'.repeat(43);
        rendered = await ejs.renderFile(path.resolve(__dirname, '../views/nodes.ejs'), {
            lang, locales: getLocale(lang), t: key => translate(key, lang), nodes: [], groups: [], linksCount: 0,
            useModernMap: true, c3Rebuild: true, csrfToken: window._networkCsrfToken, loadBalancingEnabled: false,
        });
        for (const [, id] of rendered.matchAll(/\bid="(rebuildPreview[\w]*)"/g)) elements[id] = new Element();
        const dialog = elements.rebuildPreview;
        dialog.showModal = () => { dialog.open = true; };
        dialog.close = () => { dialog.open = false; dialog.onclose?.(); };
        elements.networkI18n = new Element('script', rendered.match(/<script type="application\/json" id="networkI18n">([^<]*)<\/script>/)[1]);
        document.documentElement = { lang };
        document.createElementNS = (_, tag) => new Element(tag);
        topology.nodes.forEach(({ data }, i) => { data.cascadeRole = i ? 'bridge' : 'portal'; });
        topology.edges.push({ data: { id: edgeId, source, target, status: 'pending', mode: 'forward', label: 'Shipped link' } });
    }
    function renderCreateForm(container, opts) {
        const form = new Element('form'), entry = new Element('input'), status = new Element('p');
        const cancel = new Element('button');
        cancel.addEventListener('click', () => opts.onCancel());
        form.append(entry, status, cancel);
        container.append(form);
        opens.push({ opts, form, entry, status, cancel });
    }
    const origin = 'https://fixture.invalid';
    window.location = { origin };
    const context = vm.createContext({ document, window, Node: Element, navigator: {}, AbortController, URL, location: { origin },
        setTimeout: () => 1, clearTimeout() {}, setInterval: fn => { poll = fn; return 2; },
        requestAnimationFrame() {},
        fetch: async (url, init) => {
            const { method } = init;
            const pathname = new URL(url, origin).pathname;
            requests.push([method, pathname]);
            if (send) {
                const response = await send(pathname, init, topology);
                Object.defineProperty(response, 'url', { value: new URL(url, origin).href });
                return response;
            }
            assert.equal(method, 'GET');
            assert.equal(url, '/api/cascade/topology');
            return { ok: true, json: () => topology };
        },
    });
    if (shipped) {
        const labels = rendered.match(/<script>\s*(window\._networkRebuildPreviewI18n = [^\n]+)\n<\/script>/)[1];
        const asset = rendered.match(/src="\/js\/rebuild-preview\.js\?v=([a-f0-9]+)"/)[1];
        const entry = rendered.match(/\/js\/network\/dist\/index\.js\?v=([a-f0-9]+)/)[1];
        const digest = data => createHash('sha256').update(data).digest('hex').slice(0, 16);
        const shared = readFileSync(path.resolve(src, '../../rebuild-preview.js'), 'utf8');
        assert.equal(asset, digest(shared));
        assert.equal(entry, digest(readFileSync(path.join(dist, 'index.js'))));
        vm.runInContext(labels, context);
        vm.runInContext(shared, context);
    }
    const stubs = {
        'core/model.js': { default: model },
        'ui/create-form.js': { renderCreateForm },
        'ui/toolbar.js': { createToolbar: (_el, ctx) => {
            store = ctx.store;
            return { slot: new Element(), update() {}, setStatsVisible() {}, closePopover() {} };
        } },
        'views/chains.js': { mount: () => ({ update() {}, resize() {}, focus: sel => focuses.push(sel.id) }) },
    };
    const modules = new Map();
    function load(filename) {
        if (modules.has(filename)) return modules.get(filename);
        const exports = !shipped && stubs[path.relative(src, filename)];
        const mod = exports
            ? new vm.SyntheticModule(Object.keys(exports), function () {
                for (const [key, val] of Object.entries(exports)) this.setExport(key, val);
            }, { context, identifier: filename })
            : new vm.SourceTextModule(readFileSync(filename, 'utf8'), {
                context, identifier: filename, async importModuleDynamically(specifier, from) {
                    const mod = link(specifier, from);
                    if (mod.status === 'unlinked') await mod.link(link);
                    if (mod.status === 'linked') await mod.evaluate();
                    return mod;
                },
            });
        modules.set(filename, mod);
        return mod;
    }
    const link = (specifier, from) => load(path.resolve(path.dirname(from.identifier), specifier));
    const entry = load(path.join(shipped ? dist : src, 'index.js'));
    await entry.link(link);
    await entry.evaluate();
    await tick();
    return { root, elements, store, add, refresh, view, window, inspector, requests, opens, focuses, modules, poll,
        addLinkToTopology: () => { topology = { ...topology, edges: [{ data: {
            id: edgeId, source, target, label: 'Saved link fixture', status: 'pending',
        } }] }; },
    };
}

test('Add Link opens once and preserves the live form through refresh, selection and tab re-entry', async () => {
    const ui = await boot();
    ui.store.select({ kind: 'node', id: source });
    assert.equal(ui.add.disabled, false, 'authorized add button is enabled after topology loads');
    await Promise.all(ui.add.click());
    assert.equal(ui.opens.length, 1);
    const { opts, form, entry, status, cancel } = ui.opens[0];
    assert.equal(opts.source, source);
    assert.equal(opts.store, ui.store);
    assert.equal(typeof opts.actions.createAndDeploy, 'function');
    entry.value = 'entered value';

    ui.store.select({ kind: 'node', id: target });
    ui.store.select(null);
    ui.view.style.display = 'none';
    await ui.store.refresh();
    ui.view.style.display = '';
    ui.window._networkResize();
    status.text = 'Save unconfirmed; fixture blocks resubmit';
    opts.onUncertain?.();
    await Promise.all(ui.add.click());
    await Promise.all(ui.refresh.click());
    ui.poll();
    await tick();
    assert.equal(ui.opens.length, 1);
    assert.equal(ui.inspector.firstChild, form);
    assert.equal(entry.value, 'entered value');
    assert.match(form.textContent, /Save unconfirmed/);

    ui.store.select({ kind: 'node', id: target });
    cancel.click();
    assert.match(ui.inspector.textContent, /Node 2/);
    await Promise.all(ui.add.click());
    assert.equal(ui.opens.length, 2);
    assert.equal(ui.opens[1].opts.source, target);
    opts.onCreated(linkId); // A late callback from the dismissed mount does not own this inspector.
    assert.equal(ui.inspector.firstChild, ui.opens[1].form);
    assert.equal(ui.requests.length, 4);
    assert.ok(ui.requests.every(([method]) => method === 'GET'));
});

for (const present of [true, false]) {
    test(`creation callback selects the real edge ${present ? 'on completion' : 'after a later readback'}`, async () => {
        const ui = await boot();
        await Promise.all(ui.add.click());
        const { opts, form, entry } = ui.opens[0];
        entry.value = 'draft values';
        if (present) {
            ui.addLinkToTopology();
            await ui.store.refresh();
            // A selection made while the editor was visible must not eat the callback.
            ui.store.select({ kind: 'link', id: edgeId });
        }
        assert.equal(ui.inspector.firstChild, form);
        opts.onCreated(linkId);
        assert.notEqual(ui.inspector.firstChild, form);
        if (!present) {
            assert.equal(ui.store.state.selection, null, 'no phantom link selection');
            ui.addLinkToTopology();
            ui.poll();
            await tick();
        }
        assert.equal(ui.store.state.selection?.id, edgeId);
        assert.equal(ui.store.state.selection?.kind, 'link');
        assert.deepEqual(ui.focuses, [edgeId]);
        assert.match(ui.inspector.textContent, /Saved link fixture/);
        assert.ok(ui.inspector.querySelector('.nm-link-actions'));
    });
}

test('read-only mount never loads the editor or renders existing-link actions', async () => {
    for (const showButton of [false, true]) {
        const ui = await boot({ authorized: false, showButton });
        ui.addLinkToTopology();
        await ui.store.refresh();
        ui.store.select({ kind: 'link', id: edgeId });
        ui.add.disabled = false; // Even stray button markup cannot grant actions.
        await Promise.all(ui.add.click());
        assert.match(ui.inspector.textContent, /Saved link fixture/);
        assert.equal(ui.inspector.querySelector('.nm-link-actions'), undefined);
        assert.equal(ui.modules.has(path.join(src, 'ui/create-form.js')), false);
        assert.deepEqual(ui.opens, []);
    }
});

test('shipped modern Rebuild reads fresh node/link status without clearing its close-only warning', async () => {
    const preview = '/api/cascade/rebuild/preview', deploy = `/api/cascade/links/${linkId}/deploy`, read = '/api/cascade/topology';
    const previewId = 'b'.repeat(64), phase = 'xray-restart', reason = 'REBUILD_MAIN_RESTART_UNCONFIRMED';
    for (const lang of ['en', 'ru', 'zh-CN']) {
        let deployed = false, started = 0;
        const old = Promise.withResolvers(), status = Promise.withResolvers();
        const ui = await boot({ shipped: true, lang, send(url, init, topology) {
            const result = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
            if (url === read) {
                if (++started === 2) return old.promise;
                if (!deployed) return result(topology);
                return status.promise.then(() => {
                    const current = structuredClone(topology);
                    current.nodes[0].data.label = 'Read back node';
                    current.edges[0].data.status = 'offline';
                    return result(current);
                });
            }
            if (url === preview) return result({ allowed: true, previewId, nodes: [{ nodeId: source, profiles: ['main', 'bridge']
                .map(profile => ({ profile, change: 'unchanged', protectedChanged: false, sections: [] })) }] });
            assert.equal(url, deploy);
            assert.deepEqual(JSON.parse(init.body), { expectedPreview: previewId });
            deployed = true;
            return result({ error: { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', outcome: 'unknown', retryAllowed: false,
                message: '<private-wire>', failure: { phase, reason, trace: '<private-wire>' } } }, 409);
        } });
        const get = suffix => ui.elements['rebuildPreview' + suffix];
        ui.root.descendants.find(el => el.dataset.link === edgeId).click();
        const apply = ui.inspector.querySelector('.nm-link-actions').querySelector('.primary');
        assert.ok(apply, 'modern inspector rendered the actual Rebuild control');
        const [action] = apply.click();
        await tick();
        assert.equal(get('Apply').hidden, false);
        const oldRefresh = ui.refresh.click();
        get('Apply').onclick();
        await tick();
        const labels = getLocale(lang).network.rebuildPreview.mainCutover;
        assert.equal(get('Title').textContent, labels.title);
        assert.equal(get('Warning').textContent, [labels.unknown, labels.phase[phase], labels.reason[reason]].join(' '));
        assert.equal(get('Apply').hidden, true);
        apply.click(); // Busy while the outcome remains open; no second Preview or Apply.
        old.resolve(new Response(JSON.stringify({ nodes: [], edges: [] })));
        await Promise.all(oldRefresh);
        status.resolve();
        await tick();
        assert.equal(started, 3);
        assert.match(ui.inspector.textContent, /Read back node/);
        assert.ok(ui.inspector.textContent.includes(translate('network.map.alert.linkOffline', lang)));
        assert.ok(get('').open);
        assert.equal(get('Title').textContent, labels.title);
        get('Cancel').onclick();
        assert.equal(await action, false);
        assert.deepEqual(ui.requests.filter(([method]) => method === 'POST').map(([, url]) => url), [preview, deploy]);
    }
});
