'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    computeTopologyDomains,
    domainOfNode,
} = require('../domain/topologyDomains');

const NODES = [
    { _id: 'p1', name: 'Портал 1', cascadeRole: 'portal' },
    { _id: 'p2', name: 'Портал 2', cascadeRole: 'portal' },
    { _id: 'p3', name: 'Портал 3', cascadeRole: 'portal' },
    { _id: 'r1', name: 'Релей 1', cascadeRole: 'relay' },
    { _id: 'r2', name: 'Релей 2', cascadeRole: 'relay' },
    { _id: 'b1', name: 'Бридж USA', cascadeRole: 'bridge' },
    { _id: 'b2', name: 'Бридж RU', cascadeRole: 'bridge' },
    { _id: 'staged', name: 'Staged', cascadeRole: 'relay' },
];

test('two disconnected components become two domains; staged node has none', () => {
    const links = [
        { _id: 'l1', source: 'p1', target: 'r1' },
        { _id: 'l2', source: 'p2', target: 'r1' },
        { _id: 'l3', source: 'r1', target: 'b1' },
        { _id: 'l4', source: 'r1', target: 'b2', geoRouting: { enabled: true, geoip: ['ru'] } },
        { _id: 'l5', source: 'p3', target: 'r2' },
    ];
    const domains = computeTopologyDomains({ nodes: NODES, links });
    assert.equal(domains.length, 2);

    const fanIn = domains.find(d => d.nodeIds.includes('r1'));
    assert.deepEqual(fanIn.portals.sort(), ['p1', 'p2']);
    assert.deepEqual(fanIn.relays, ['r1']);
    assert.deepEqual(fanIn.bridges.sort(), ['b1', 'b2']);
    assert.equal(fanIn.key, 'b1'); // lexicographically smallest node id
    assert.deepEqual(fanIn.linkIds.sort(), ['l1', 'l2', 'l3', 'l4']);
    assert.match(fanIn.label, /Порталы Портал 1, Портал 2 → бриджи Бридж USA, Бридж RU/);

    const second = domains.find(d => d.nodeIds.includes('r2'));
    assert.equal(second.nodeIds.length, 2);
    assert.equal(domainOfNode(domains, 'staged'), null);
    assert.equal(domainOfNode(domains, 'p3').key, second.key);
});

test('single chain yields one domain with singular label', () => {
    const links = [
        { _id: 'l1', source: 'p1', target: 'r1' },
        { _id: 'l2', source: 'r1', target: 'b1' },
    ];
    const domains = computeTopologyDomains({
        nodes: NODES.slice(0, 6),
        links,
    });
    assert.equal(domains.length, 1);
    assert.equal(domains[0].label, 'Портал Портал 1 → бридж Бридж USA');
});

test('links referencing unknown nodes are ignored; empty graph has no domains', () => {
    const domains = computeTopologyDomains({
        nodes: NODES.slice(0, 2),
        links: [{ _id: 'lx', source: 'p1', target: 'ghost' }],
    });
    assert.equal(domains.length, 0);
    assert.deepEqual(computeTopologyDomains({}), []);
});

test('bson ObjectId-shaped ids resolve to hex strings, not raw buffers', () => {
    // bson ObjectId: `.id` returns the raw 12-byte Buffer, `toHexString()`
    // returns the canonical id. Regression: entityId used `.id` first and
    // produced garbage, so every link was ignored and no domains formed.
    const oid = hex => ({
        id: Buffer.from(hex, 'hex'),
        toHexString: () => hex,
        toString: () => hex,
    });
    const nodes = [
        { _id: oid('6ab18adc63913ebd4a917471'), name: 'P', cascadeRole: 'portal' },
        { _id: oid('6ab189dc63913ebd4a917399'), name: 'R', cascadeRole: 'relay' },
    ];
    const links = [{ _id: oid('6ab6b94cdaac2c5e217b51b0'), portalNode: oid('6ab18adc63913ebd4a917471'), bridgeNode: oid('6ab189dc63913ebd4a917399') }];
    const domains = computeTopologyDomains({ nodes, links });
    assert.equal(domains.length, 1);
    assert.deepEqual(domains[0].nodeIds.slice().sort(), [
        '6ab189dc63913ebd4a917399',
        '6ab18adc63913ebd4a917471',
    ]);
    assert.deepEqual(domains[0].linkIds, ['6ab6b94cdaac2c5e217b51b0']);
});
