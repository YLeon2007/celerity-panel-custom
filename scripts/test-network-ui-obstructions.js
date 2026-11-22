'use strict';

// Source/loader regressions only; native hit-testing belongs to the separate
// test-network-ui-obstructions-browser.cjs harness after the asset rebuild.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const ejs = require('ejs');

const root = path.resolve(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const style = read('public/css/style.css');
const networkStyle = read('public/css/network.css');

function declarations(css, selector) {
    const rules = [...css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{([^{}]*)\}/g)]
        .filter(([, selectors]) => selectors.split(',').some(value => value.trim() === selector));
    return Object.fromEntries(rules.flatMap(([, , body]) => body.split(';').flatMap(value => {
        const colon = value.indexOf(':');
        return colon < 0 ? [] : [[value.slice(0, colon).trim(), value.slice(colon + 1).trim()]];
    })));
}

test('embedded map releases its modal stacking context, not the map surface or global layer scale', () => {
    assert.equal(declarations(style, '.main-content > #viewNetwork')['z-index'], 'auto',
        'fixed map modals must escape the z-index:1 view wrapper that trapped them below the sticky toolbar');
    assert.equal(declarations(style, '.main-content > #viewNetwork > .network-page')['z-index'], '1',
        'only the map surface should retain its original content layer');
    assert.equal(declarations(style, '.main-content > *:not(.toast):not(.sticky-header)')['z-index'], '1',
        'other page content keeps its existing stacking policy');
    assert.equal(declarations(style, '.sticky-header')['z-index'], '40');
    assert.equal(declarations(style, '.topbar')['z-index'], '50');
    assert.equal(declarations(networkStyle, '.modal-overlay')['z-index'], '1000',
        'do not fix a trapped ancestor by escalating a modal global z-index');
    assert.equal(declarations(networkStyle, '.modal-overlay').position, 'fixed');
    assert.equal(declarations(networkStyle, '.network-page').overflow, 'hidden');
});

function runNodesLoader(c3Rebuild, failAt = -1) {
    const loader = read('views/nodes.ejs').match(/function loadNetworkScripts\(\) \{[\s\S]*?\n\}/)?.[0];
    assert.ok(loader, 'exercise the actual embedded map loader, not a copied script list');
    const loaded = [];
    vm.runInNewContext(ejs.render(loader, { c3Rebuild }) + '\nloadNetworkScripts();', {
        window: {},
        document: {
            createElement(tag) { assert.equal(tag, 'script'); return {}; },
            body: { appendChild(script) {
                loaded.push(script.src);
                if (loaded.length - 1 === failAt) script.onerror();
                else script.onload();
            } },
        },
    });
    return loaded;
}

test('nodes loader requests only used map dependencies before the shipped network bundle', () => {
    for (const c3Rebuild of [false, true]) {
        const loaded = runNodesLoader(c3Rebuild);
        assert.deepEqual(loaded.slice(0, -1), [
            'https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.4/cytoscape.min.js',
            'https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js',
            'https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js',
        ], 'unused edgehandles must not execute without lodash during map startup');
        const asset = '/js/network' + (c3Rebuild ? '.js' : '.min.js');
        const hash = createHash('sha256').update(read('public' + asset)).digest('hex');
        assert.equal(loaded.at(-1), asset + '?v=' + hash.slice(0, 16));
        for (let failAt = 0; failAt < loaded.length; failAt++) {
            assert.deepEqual(runNodesLoader(c3Rebuild, failAt), loaded, 'retain sequential error continuation');
        }
    }
});

test('shipped node dragging and form actions do not depend on edgehandles', () => {
    const source = read('public/js/network.js');
    assert.doesNotMatch(source, /edgehandles|cytoscapeEdgehandles|ehcomplete/i);
    for (const binding of [
        "cy.on('dragfree', 'node', onNodeDragEnd)",
        "document.getElementById('btnAddLink').addEventListener('click', openAddLinkModal)",
        "document.getElementById('nodeInfoClose').addEventListener('click', closeInfoModal)",
        "document.getElementById('addLinkForm').addEventListener('submit', onAddLinkSubmit)",
        "quickForm.addEventListener('submit', onQuickLinkSubmit)",
    ]) assert.ok(source.includes(binding), 'preserve existing interaction binding: ' + binding);
});
