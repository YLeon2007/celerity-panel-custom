'use strict';

// Scoped entry-point coverage. The companion integration exercises Apply.
const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { JSDOM } = require('jsdom');
const { buildSync } = require('esbuild');
const { network } = require('../src/locales/ru.json');

const bundle = buildSync({ absWorkingDir: path.resolve(__dirname, '..'), bundle: true, write: false,
    entryPoints: ['public/js/network/src/index.js'], format: 'iife',
    // This suite only mounts Chains, not the two lazy views and their vendors.
    external: ['./views/graph.js', './views/geo.js'],
}).outputFiles[0].text;

const realId = 'link-0123456789abcdef01234567';
const otherId = 'link-0123456789abcdef01234568';
const edge = (id, extra = {}) => ({ data: { id, source: 'p', target: 'b', mode: 'reverse', status: 'pending', ...extra } });
const topology = {
    nodes: [
        { data: { id: 'p', label: 'Portal', cascadeRole: 'portal', type: 'xray' } },
        { data: { id: 'b', label: 'Bridge', cascadeRole: 'bridge', type: 'xray' } },
    ],
    edges: [edge(realId), edge(otherId, { status: 'deployed' }), edge('link-invalid')],
};

async function mount(t, attrs = 'data-link-actions="true"') {
    const { window: w } = new JSDOM(`<!doctype html><html lang="ru"><body><div id="viewNetwork">
        <div id="networkRoot" ${attrs}>
            <div class="nm-bar"></div><div class="nm-stage"></div><aside class="nm-insp"></aside><div class="nm-state"></div>
        </div>
    </div><script id="networkI18n" type="application/json"></script></body></html>`, {
        url: 'https://panel.invalid/panel/nodes', runScripts: 'outside-only', pretendToBeVisual: true,
    });
    const errors = [];
    w.addEventListener('error', event => errors.push(event.error));
    t.after(() => { w.close(); assert.deepEqual(errors, []); });
    const doc = w.document, inspector = doc.querySelector('.nm-insp');
    doc.getElementById('networkI18n').textContent = JSON.stringify(network);
    const requests = [];
    w.fetch = async (url, { method }) => {
        requests.push([method, url]);
        assert.deepEqual([method, url], ['GET', '/api/cascade/topology']);
        return { ok: true, json: async () => structuredClone(topology) };
    };
    w.eval(bundle);
    await new Promise(setImmediate);
    const click = (selector, predicate) => {
        const el = [...doc.querySelectorAll(selector)].find(predicate);
        assert.ok(el, `Missing selection control in ${selector}`);
        el.click();
        assert.ok(inspector.classList.contains('open'));
    };
    return { inspector, requests, click,
        clickEdge: id => click('.nmc-pill', el => el.dataset.link === id),
        actionButtons: () => [...inspector.querySelectorAll('.nm-link-actions button')],
    };
}

const initialRead = [['GET', '/api/cascade/topology']];
test('actual modern entry and Chains render localized editor actions for the selected link without writing', async t => {
    const ui = await mount(t);
    assert.deepEqual(ui.actionButtons(), []);
    ui.clickEdge(realId);
    const labels = network.map.linkActions;
    assert.deepEqual(ui.actionButtons().map(button => button.textContent), [labels.deploy, labels.deployChain, labels.checkHealth, labels.remove]);
    assert.ok(ui.inspector.textContent.includes(labels.reconnectHint));
    assert.ok(ui.inspector.querySelector('.nm-st.pending'));
    ui.clickEdge(otherId);
    assert.ok(ui.inspector.querySelector('.nm-st.deployed'));
    assert.deepEqual(ui.requests, initialRead);
});

test('read-only entry has no link actions; editor has none for nodes or invalid IDs', async t => {
    for (const attrs of ['', 'data-read-only="true"']) {
        const viewer = await mount(t, attrs);
        viewer.clickEdge(realId);
        assert.deepEqual(viewer.actionButtons(), []);
        assert.deepEqual(viewer.requests, initialRead);
    }
    const ui = await mount(t);
    ui.clickEdge('link-invalid');
    assert.deepEqual(ui.actionButtons(), []);
    // Use a Chains node card, not a hop that scrolls the layout into view.
    ui.click('.nmc [data-node]', el => el.dataset.node === 'p');
    assert.deepEqual(ui.actionButtons(), []);
    assert.deepEqual(ui.requests, initialRead);
});
