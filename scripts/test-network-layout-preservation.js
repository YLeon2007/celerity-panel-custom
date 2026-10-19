'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../public/js/network.js'), 'utf8');
const items = new Map();
let pan = { x: 0, y: 0 }, zoom = 1, fits = 0, layouts = 0;
const graph = {
    nodes() { return [...items.values()].filter(x => x.group === 'nodes').map(x => ({
        id: () => x.data.id, position: () => ({ ...x.position }),
    })); },
    elements() { return { remove() { items.clear(); } }; },
    add(elements) {
        for (const x of elements) items.set(x.data.id, { group: x.group, data: x.data,
            position: x.position ? { ...x.position } : { x: 0, y: 0 } });
    },
    pan(value) { if (value) pan = { ...value }; return { ...pan }; },
    zoom(value) { if (value != null) zoom = value; return zoom; },
    fit() { fits++; pan = { x: -50, y: -50 }; zoom = 0.7; },
    layout() { return { run() { layouts++; for (const x of items.values()) {
        if (x.group === 'nodes') x.position = { x: layouts * 100, y: layouts * 100 };
    } } }; },
};
const document = { readyState: 'loading', addEventListener() {}, getElementById() { return null; } };
const window = { __graph: graph };
const instrumented = source.replace('    // ==================== START ====================',
    '    cy = window.__graph; initParticleSystem = function () {}; window.__renderGraph = renderGraph;\n    // ==================== START ====================');
assert.notEqual(source, instrumented);
vm.runInNewContext(instrumented, { window, document, console, cytoscape: () => {} });
const n = (id, position) => ({ data: { id, label: id, ip: id, cascadeRole: 'portal' }, ...(position ? { position } : {}) });
const e = id => ({ data: { id: 'link-' + id, source: 'a', target: 'b', linkId: id } });
const point = id => items.get(id)?.position;
// No saved positions: changing just an edge must not re-run auto-layout.
window.__renderGraph({ nodes: [n('a'), n('b')], edges: [e('one')] });
assert.equal(layouts, 1);
items.get('a').position = { x: 70, y: 120 };
items.get('b').position = { x: 380, y: 240 };
graph.pan({ x: 18, y: 29 }); graph.zoom(1.35);
const firstFits = fits;
window.__renderGraph({ nodes: [n('a'), n('b')], edges: [e('one'), e('two')] });
assert.deepEqual(point('a'), { x: 70, y: 120 }, 'create preserves unsaved node placement');
assert.deepEqual(point('b'), { x: 380, y: 240 });
assert.deepEqual(graph.pan(), { x: 18, y: 29 }, 'create preserves viewport pan');
assert.equal(graph.zoom(), 1.35, 'create preserves viewport zoom');
assert.equal(layouts, 1, 'create must not run auto-layout');
assert.equal(fits, firstFits, 'create must not auto-fit');
window.__renderGraph({ nodes: [n('a'), n('b')], edges: [] });
assert.deepEqual(point('a'), { x: 70, y: 120 }, 'delete preserves node placement');
assert.deepEqual(graph.pan(), { x: 18, y: 29 }, 'delete preserves viewport');
assert.equal(layouts, 1);
// A fresh page has no in-memory graph and must honor the server's saved coordinates.
items.clear();
window.__renderGraph({ nodes: [n('a', { x: 11, y: 22 }), n('b', { x: 33, y: 44 })], edges: [] });
assert.deepEqual(point('a'), { x: 11, y: 22 });
assert.deepEqual(point('b'), { x: 33, y: 44 });
// The virtual icon uses its persisted server position on fresh load and keeps
// an unsaved drag during link create/delete just like physical nodes.
items.clear();
const globe = position => ({ data: { id: 'internet', label: 'Internet', cascadeRole: 'internet' }, position });
window.__renderGraph({ nodes: [n('a', { x: 11, y: 22 }), n('b', { x: 33, y: 44 }), globe({ x: 870, y: 96 })], edges: [e('one')] });
assert.deepEqual(point('internet'), { x: 870, y: 96 }, 'fresh map honors saved virtual position');
items.get('internet').position = { x: 930, y: 85 };
window.__renderGraph({ nodes: [n('a', { x: 11, y: 22 }), n('b', { x: 33, y: 44 }), globe({ x: 870, y: 96 })], edges: [e('one'), e('two')] });
assert.deepEqual(point('internet'), { x: 930, y: 85 }, 'create preserves unsaved virtual position');
window.__renderGraph({ nodes: [n('a', { x: 11, y: 22 }), n('b', { x: 33, y: 44 }), globe({ x: 870, y: 96 })], edges: [] });
assert.deepEqual(point('internet'), { x: 930, y: 85 }, 'delete preserves virtual position');
console.log('network layout preservation: OK');
