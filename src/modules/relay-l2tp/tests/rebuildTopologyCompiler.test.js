'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { compileRebuildGraph } = require('../domain/rebuildTopologyCompiler');

const nodes = [
    { id: 'z-portal', role: 'portal' }, { id: 'y-relay', role: 'relay' },
    { id: 'x-relay', role: 'relay' }, { id: 'w-merge', role: 'relay' },
    { id: 'a-exit', role: 'bridge' }, { id: 'b-exit', role: 'bridge' },
    { id: 'v-dead', role: 'relay' }, { id: 'u-unused', role: 'standalone' },
];
const edge = (id, source, target, props) => ({ id, source, target, ...props });
const geo = { enabled: true, domains: ['full:geo.example.invalid'], geoip: ['RU'] };

test('rebuild graph walks a reverse diamond bottom-up, independently of input order', () => {
    const links = [
        edge('finish', 'w-merge', 'a-exit'),
        edge('merge-x', 'x-relay', 'w-merge'), edge('merge-y', 'y-relay', 'w-merge'),
        edge('default-lower', 'z-portal', 'y-relay', { priority: 40 }),
        edge('default-best', 'z-portal', 'x-relay', { priority: 20 }),
        edge('dead', 'z-portal', 'v-dead', { priority: 1 }),
        edge('geo', 'z-portal', 'b-exit', { priority: 60, geoRouting: geo }),
        edge('ignore', 'z-portal', 'u-unused', { active: false }),
    ];
    const affectedNodeIds = nodes.filter(node => node.id !== 'u-unused').map(node => node.id);
    const result = compileRebuildGraph({ nodes, links, affectedNodeIds });
    assert.deepEqual(result, compileRebuildGraph({ nodes: nodes.slice().reverse(), links: links.slice().reverse(),
        affectedNodeIds: affectedNodeIds.slice().reverse() }));
    const portal = result.byNodeId.get('z-portal');
    assert.equal(portal.defaultLink.id, 'default-best');
    assert.deepEqual(portal.geoLinks.map(link => [link.id, link.geoip]), [['geo', ['geoip:ru']]]);
    assert.deepEqual(result.byNodeId.get('w-merge').incoming.map(link => link.id), ['merge-x', 'merge-y']);
    assert.equal(result.byNodeId.get('a-exit').isExit, true);
    assert.equal(result.byNodeId.get('v-dead').hasExit, false);
    assert.equal(result.byNodeId.has('u-unused'), false);
    for (const entry of result.byNodeId.values()) {
        for (const link of entry.outgoing) assert.ok(result.nodeIds.indexOf(link.source) < result.nodeIds.indexOf(link.target));
    }
});

test('geo-only policy has no generic exit; equal defaults are ambiguous, not random', () => {
    const links = [edge('geo', 'y-relay', 'a-exit', { geoRouting: geo }), edge('p-y', 'z-portal', 'y-relay')];
    let result = compileRebuildGraph({ nodes, links });
    assert.equal(result.byNodeId.get('z-portal').defaultLink.id, 'p-y');
    assert.equal(result.byNodeId.get('y-relay').defaultLink, null);
    assert.equal(result.byNodeId.get('y-relay').hasExit, true);
    assert.equal(result.byNodeId.get('a-exit').isExit, true);
    assert.equal(result.byNodeId.get('b-exit').isExit, false);
    result = compileRebuildGraph({ nodes, links: [...links, edge('p-b', 'z-portal', 'b-exit')] });
    assert.equal(result.byNodeId.get('z-portal').defaultLink, null);
    assert.equal(result.byNodeId.get('z-portal').hasExit, false);
});

test('invalid graph and incomplete scope are refused without serializing source descriptors', () => {
    for (const [code, links, affectedNodeIds] of [
        ['REBUILD_CYCLE', [edge('xy', 'x-relay', 'y-relay'), edge('yx', 'y-relay', 'x-relay')]],
        ['REBUILD_CYCLE', [edge('self', 'x-relay', 'x-relay')]],
        ['REBUILD_INCOMPLETE_SCOPE', [edge('ab', 'z-portal', 'b-exit')], ['z-portal']],
        ['REBUILD_UNKNOWN_NODE', [edge('ab', 'z-portal', 'missing')]],
        ['REBUILD_INVALID_EDGE_ROLE', [edge('ab', 'b-exit', 'z-portal')]],
        ['REBUILD_INVALID_PRIORITY', [edge('ab', 'z-portal', 'b-exit', { priority: '1' })]],
        ['REBUILD_INVALID_TUNNEL', [edge('bad', 'z-portal', 'b-exit', { tunnelProtocol: 'unknown' })]],
        ['REBUILD_INVALID_GEO', [edge('ab', 'z-portal', 'b-exit', { geoRouting: { enabled: true } })]],
        ['REBUILD_DUPLICATE_LINK', [edge('ab', 'z-portal', 'b-exit'), edge('ab', 'z-portal', 'a-exit')]],
    ]) {
        assert.throws(() => compileRebuildGraph({ nodes, links, affectedNodeIds }), { code });
    }
});

test('normalizes the protocol without cloning the separately prepared link descriptor', () => {
    const reverse = edge('reverse', 'z-portal', 'a-exit', { tunnelProtocol: 'vmess' });
    Object.defineProperty(reverse, '_rebuildVless', { value: Object.freeze({ decryption: 'fixture', encryption: 'fixture' }) });
    Object.freeze(reverse);
    const forward = edge('forward', 'z-portal', 'b-exit', { tunnelProtocol: 'vmess', mode: 'forward' });
    const graph = compileRebuildGraph({ nodes, links: [reverse, forward] });
    assert.ok(graph.byLinkId.get('reverse').link === reverse);
    assert.ok(graph.byLinkId.get('reverse').link._rebuildVless === reverse._rebuildVless);
    assert.equal(graph.byLinkId.get('reverse').protocol, 'vless');
    assert.equal(graph.byLinkId.get('forward').protocol, 'vmess');
});
