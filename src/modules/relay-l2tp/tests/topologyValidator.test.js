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
            {
                _id: 'group-1',
                mode: 'forward',
                strategy: 'priority-failover',
                paths: [{
                    pathKey: 'path-1',
                    linkIds: ['portal-relay', 'relay-bridge'],
                    priority: 10,
                }],
            },
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
    topology.links[1].source = 'bridge-2';

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'DISCONTINUOUS_PATH',
            groupId: 'group-1',
            pathKey: 'path-1',
            sourceNodeId: 'relay-1',
            targetNodeId: 'bridge-2',
        }],
    });
});

test('rejects route-group paths that reference an unknown link', () => {
    const topology = validTopology();
    topology.groups[0].paths[0].linkIds.push('missing-link');

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'UNKNOWN_LINK',
            groupId: 'group-1',
            pathKey: 'path-1',
            linkId: 'missing-link',
        }],
    });
});

test('rejects mixed forward and reverse links in one path', () => {
    const topology = validTopology();
    topology.links[1].mode = 'reverse';

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'GROUP_MODE_MISMATCH',
            groupId: 'group-1',
            pathKey: 'path-1',
            linkId: 'relay-bridge',
            groupMode: 'forward',
            linkMode: 'reverse',
        }, {
            code: 'MIXED_LINK_MODES',
            groupId: 'group-1',
            pathKey: 'path-1',
            modes: ['forward', 'reverse'],
        }],
    });
});

test('rejects a path whose links all disagree with the route-group mode', () => {
    const topology = validTopology();
    topology.groups[0].mode = 'reverse';

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [
            {
                code: 'GROUP_MODE_MISMATCH',
                groupId: 'group-1',
                pathKey: 'path-1',
                linkId: 'portal-relay',
                groupMode: 'reverse',
                linkMode: 'forward',
            },
            {
                code: 'GROUP_MODE_MISMATCH',
                groupId: 'group-1',
                pathKey: 'path-1',
                linkId: 'relay-bridge',
                groupMode: 'reverse',
                linkMode: 'forward',
            },
        ],
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
    topology.groups[0].paths[0].linkIds.splice(1, 0, 'relay-loop');

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'SELF_LOOP',
            groupId: 'group-1',
            pathKey: 'path-1',
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
    topology.groups[0].paths[0].linkIds.push('bridge-portal');

    assert.deepEqual(validateTopology(topology), {
        valid: false,
        errors: [{
            code: 'CYCLE_DETECTED',
            groupId: 'group-1',
            pathKey: 'path-1',
        }],
    });
});
