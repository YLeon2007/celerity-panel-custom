'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { compileTopology } = require('../src/modules/relay-l2tp/domain/topologyCompiler');

function singlePathTopology() {
    return {
        nodes: [
            { id: 'portal-1', role: 'portal' },
            { id: 'relay-1', role: 'relay' },
            { id: 'relay-2', role: 'relay' },
            { id: 'bridge-1', role: 'bridge' },
        ],
        links: [
            { id: 'portal-relay-1', source: 'portal-1', target: 'relay-1', mode: 'forward' },
            { id: 'relay-1-relay-2', source: 'relay-1', target: 'relay-2', mode: 'forward' },
            { id: 'relay-2-bridge-1', source: 'relay-2', target: 'bridge-1', mode: 'forward' },
        ],
        groups: [{
            id: 'path-primary',
            nodeIds: ['portal-1', 'relay-1', 'relay-2', 'bridge-1'],
            priority: 10,
            enabled: true,
        }],
        healthByPathKey: { 'path-primary': true },
    };
}

function twoPathTopology() {
    const topology = singlePathTopology();
    topology.nodes.push(
        { id: 'relay-3', role: 'relay' },
        { id: 'bridge-2', role: 'bridge' },
    );
    topology.links.push(
        { id: 'relay-1-relay-3', source: 'relay-1', target: 'relay-3', mode: 'forward' },
        { id: 'relay-3-bridge-2', source: 'relay-3', target: 'bridge-2', mode: 'forward' },
    );
    topology.groups.push({
        id: 'path-secondary',
        nodeIds: ['portal-1', 'relay-1', 'relay-3', 'bridge-2'],
        priority: 20,
        enabled: true,
    });
    topology.healthByPathKey['path-secondary'] = true;
    return topology;
}

test('compiles a relay candidate from only its downstream L2TP suffix', () => {
    const compiled = compileTopology(singlePathTopology());
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');

    assert.equal(compiled.valid, true);
    assert.deepEqual(relay.candidates, [{
        pathKey: 'path-primary',
        priority: 10,
        nextHopNodeId: 'relay-2',
        suffixLinks: [
            { id: 'relay-1-relay-2', source: 'relay-1', target: 'relay-2', mode: 'forward' },
            { id: 'relay-2-bridge-1', source: 'relay-2', target: 'bridge-1', mode: 'forward' },
        ],
    }]);
    assert.equal(relay.candidates[0].suffixLinks.some(link => link.id === 'portal-relay-1'), false);
});

test('selects the healthy lowest-priority candidate and declares its next hop', () => {
    const compiled = compileTopology(twoPathTopology());
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');

    assert.deepEqual(relay.decision, {
        decision: 'select',
        pathKey: 'path-primary',
        nextHopNodeId: 'relay-2',
    });
});

test('blocks fail-closed when no candidate is healthy', () => {
    const topology = twoPathTopology();
    topology.healthByPathKey = {
        'path-primary': false,
        'path-secondary': false,
    };
    const compiled = compileTopology(topology);
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');

    assert.deepEqual(relay.decision, {
        decision: 'block',
        error: { code: 'NO_HEALTHY_PATH' },
    });
});

test('produces deep-equal IR when input link order is permuted', () => {
    const original = twoPathTopology();
    const permuted = twoPathTopology();
    permuted.links.reverse();

    assert.deepEqual(compileTopology(permuted), compileTopology(original));
});
