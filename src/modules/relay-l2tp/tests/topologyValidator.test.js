'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { validateTopology } = require('../domain/topologyValidator');

function validTopology() {
    return {
        nodes: [
            { id: 'portal-1', role: 'portal' },
            { id: 'relay-1', role: 'relay' },
            { id: 'bridge-1', role: 'bridge' },
        ],
        links: [
            { id: 'portal-relay', source: 'portal-1', target: 'relay-1', mode: 'forward' },
            { id: 'relay-bridge', source: 'relay-1', target: 'bridge-1', mode: 'forward' },
        ],
        groups: [
            { id: 'path-1', nodeIds: ['portal-1', 'relay-1', 'bridge-1'] },
        ],
    };
}

test('accepts an ordered Portal -> Relay -> Bridge path', () => {
    assert.deepEqual(validateTopology(validTopology()), {
        valid: true,
        errors: [],
    });
});

test('rejects a discontinuous ordered path with a structured code', () => {
    const topology = validTopology();
    topology.links = topology.links.filter(link => link.id !== 'relay-bridge');

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'DISCONTINUOUS_PATH',
            groupId: 'path-1',
            sourceNodeId: 'relay-1',
            targetNodeId: 'bridge-1',
        }],
    });
});

test('rejects mixed forward and reverse links in one path', () => {
    const topology = validTopology();
    topology.links[1].mode = 'reverse';

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'MIXED_LINK_MODES',
            groupId: 'path-1',
            modes: ['forward', 'reverse'],
        }],
    });
});

test('rejects a self-loop in a path', () => {
    const topology = validTopology();
    topology.links.push({
        id: 'relay-loop',
        source: 'relay-1',
        target: 'relay-1',
        mode: 'forward',
    });

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'SELF_LOOP',
            groupId: 'path-1',
            linkId: 'relay-loop',
            nodeId: 'relay-1',
        }],
    });
});

test('rejects a cycle in a path', () => {
    const topology = validTopology();
    topology.links.push({
        id: 'bridge-portal',
        source: 'bridge-1',
        target: 'portal-1',
        mode: 'forward',
    });

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'CYCLE_DETECTED',
            groupId: 'path-1',
        }],
    });
});
