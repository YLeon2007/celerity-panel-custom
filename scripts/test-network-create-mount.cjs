'use strict';

// node --experimental-vm-modules --test scripts/test-network-create-mount.cjs
// Exercise the real entry, inspector, store and actions. The separately owned
// form is replaced at its export boundary; no server, renderer or browser I/O.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const src = path.resolve(__dirname, '../public/js/network/src');
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
        };
    }
    appendChild(el) { this.children.push(el); }
    append(...els) { this.children.push(...els); }
    removeChild(el) { this.children.splice(this.children.indexOf(el), 1); }
    get firstChild() { return this.children[0]; }
    get textContent() { return this.text + this.children.map(el => el.textContent).join(''); }
    get descendants() { return this.children.flatMap(el => [el, ...el.descendants]); }
    setAttribute(k, v) { this.attrs[k] = v; }
    querySelector(cls) { return this.descendants.find(el => el.classList.contains(cls.slice(1))); }
    addEventListener(evt, fn) { (this.events[evt] ||= []).push(fn); }
    click() { return this.hidden || this.disabled ? [] : (this.events.click || []).map(fn => fn()); }
}

async function boot({ authorized = true, showButton = authorized } = {}) {
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
    function renderCreateForm(container, opts) {
        const form = new Element('form'), entry = new Element('input'), status = new Element('p');
        const cancel = new Element('button');
        cancel.addEventListener('click', () => opts.onCancel());
        form.append(entry, status, cancel);
        container.append(form);
        opens.push({ opts, form, entry, status, cancel });
    }
    const context = vm.createContext({ document, window, Node: Element, navigator: {}, AbortController,
        setTimeout: () => 1, clearTimeout() {}, setInterval: fn => { poll = fn; return 2; },
        fetch: async (url, { method }) => {
            requests.push([method, url]);
            assert.equal(method, 'GET');
            assert.equal(url, '/api/cascade/topology');
            return { ok: true, json: () => topology };
        },
    });
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
        const exports = stubs[path.relative(src, filename)];
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
    const entry = load(path.join(src, 'index.js'));
    await entry.link(link);
    await entry.evaluate();
    await tick();
    return { store, add, refresh, view, window, inspector, requests, opens, focuses, modules, poll,
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
