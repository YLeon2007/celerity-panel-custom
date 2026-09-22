'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { compileTopology } = require('../domain/topologyCompiler');
const { validateTopology } = require('../domain/topologyValidator');

const PORTAL_ID = '64a000000000000000000001';
const RELAY_1_ID = '64a000000000000000000002';
const RELAY_2_ID = '64a000000000000000000003';
const BRIDGE_ID = '64a000000000000000000004';
const PORTAL_RELAY_LINK_ID = '64b000000000000000000001';
const RELAY_RELAY_LINK_ID = '64b000000000000000000002';
const RELAY_BRIDGE_LINK_ID = '64b000000000000000000003';
const GROUP_ID = '64c000000000000000000001';

function routeGroupContractTopology() {
    return {
        nodes: [
            { id: PORTAL_ID, role: 'portal' },
            { id: RELAY_1_ID, role: 'relay' },
            { id: RELAY_2_ID, role: 'relay' },
            { id: BRIDGE_ID, role: 'bridge' },
        ],
        links: [
            { id: RELAY_BRIDGE_LINK_ID, source: RELAY_2_ID, target: BRIDGE_ID, mode: 'forward' },
            { id: PORTAL_RELAY_LINK_ID, source: PORTAL_ID, target: RELAY_1_ID, mode: 'forward' },
            { id: RELAY_RELAY_LINK_ID, source: RELAY_1_ID, target: RELAY_2_ID, mode: 'forward' },
        ],
        groups: [{
            _id: GROUP_ID,
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: [PORTAL_RELAY_LINK_ID, RELAY_RELAY_LINK_ID, RELAY_BRIDGE_LINK_ID],
                priority: 10,
            }],
        }],
        healthByPathKey: { [`${GROUP_ID}:primary`]: true },
    };
}

test('resolves ordered route-group linkIds into relay suffixes and a scoped decision', () => {
    const topology = routeGroupContractTopology();

    assert.deepEqual(validateTopology(topology), {
        valid: true,
        errors: [],
    });

    const compiled = compileTopology(topology);
    const relay = compiled.relays.find(candidate => candidate.nodeId === RELAY_1_ID);
    const routeGroup = relay.routeGroups.find(entry => entry.groupId === GROUP_ID);

    assert.equal(compiled.valid, true);
    assert.deepEqual(routeGroup.candidates, [{
        groupId: GROUP_ID,
        pathKey: 'primary',
        priority: 10,
        enabled: true,
        nextHopNodeId: RELAY_2_ID,
        suffixLinks: [
            { id: RELAY_RELAY_LINK_ID, source: RELAY_1_ID, target: RELAY_2_ID, mode: 'forward' },
            { id: RELAY_BRIDGE_LINK_ID, source: RELAY_2_ID, target: BRIDGE_ID, mode: 'forward' },
        ],
    }]);
    assert.equal(routeGroup.candidates[0].suffixLinks.some(link => link.id === PORTAL_RELAY_LINK_ID), false);
    assert.deepEqual(routeGroup.decision, {
        decision: 'select',
        groupId: GROUP_ID,
        pathKey: 'primary',
        nextHopNodeId: RELAY_2_ID,
    });
});

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
            _id: 'group-primary',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'path-primary',
                linkIds: ['portal-relay-1', 'relay-1-relay-2', 'relay-2-bridge-1'],
                priority: 10,
            }],
        }],
        healthByPathKey: { 'group-primary:path-primary': true },
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
    topology.groups[0].paths.push({
        pathKey: 'path-secondary',
        linkIds: ['portal-relay-1', 'relay-1-relay-3', 'relay-3-bridge-2'],
        priority: 20,
    });
    topology.healthByPathKey['group-primary:path-secondary'] = true;
    return topology;
}

test('compiles a relay candidate from only its downstream L2TP suffix', () => {
    const compiled = compileTopology(singlePathTopology());
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');
    const routeGroup = relay.routeGroups.find(entry => entry.groupId === 'group-primary');

    assert.equal(compiled.valid, true);
    assert.deepEqual(routeGroup.candidates, [{
        groupId: 'group-primary',
        pathKey: 'path-primary',
        priority: 10,
        enabled: true,
        nextHopNodeId: 'relay-2',
        suffixLinks: [
            { id: 'relay-1-relay-2', source: 'relay-1', target: 'relay-2', mode: 'forward' },
            { id: 'relay-2-bridge-1', source: 'relay-2', target: 'bridge-1', mode: 'forward' },
        ],
    }]);
    assert.equal(routeGroup.candidates[0].suffixLinks.some(link => link.id === 'portal-relay-1'), false);
});

test('selects the healthy lowest-priority candidate and declares its next hop', () => {
    const compiled = compileTopology(twoPathTopology());
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');
    const routeGroup = relay.routeGroups.find(entry => entry.groupId === 'group-primary');

    assert.deepEqual(routeGroup.decision, {
        decision: 'select',
        groupId: 'group-primary',
        pathKey: 'path-primary',
        nextHopNodeId: 'relay-2',
    });
});

test('preserves disabled candidates and excludes them from path selection', () => {
    const topology = twoPathTopology();
    topology.groups[0].paths[0].enabled = false;
    topology.groups[0].paths[1].enabled = true;

    const compiled = compileTopology(topology);
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');
    const routeGroup = relay.routeGroups.find(entry => entry.groupId === 'group-primary');

    assert.deepEqual(
        routeGroup.candidates.map(({ pathKey, enabled }) => ({ pathKey, enabled })),
        [
            { pathKey: 'path-primary', enabled: false },
            { pathKey: 'path-secondary', enabled: true },
        ],
    );
    assert.deepEqual(routeGroup.decision, {
        decision: 'select',
        groupId: 'group-primary',
        pathKey: 'path-secondary',
        nextHopNodeId: 'relay-3',
    });
});

test('blocks fail-closed when no candidate is healthy', () => {
    const topology = twoPathTopology();
    topology.healthByPathKey = {
        'group-primary:path-primary': false,
        'group-primary:path-secondary': false,
    };
    const compiled = compileTopology(topology);
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');
    const routeGroup = relay.routeGroups.find(entry => entry.groupId === 'group-primary');

    assert.deepEqual(routeGroup.decision, {
        decision: 'block',
        error: { code: 'NO_HEALTHY_PATH' },
    });
});

function twoGroupSharedPathKeyTopology() {
    return {
        nodes: [
            { id: 'portal-1', role: 'portal' },
            { id: 'relay-1', role: 'relay' },
            { id: 'relay-a', role: 'relay' },
            { id: 'relay-b', role: 'relay' },
            { id: 'bridge-a', role: 'bridge' },
            { id: 'bridge-b', role: 'bridge' },
        ],
        links: [
            { id: 'relay-b-bridge-b', source: 'relay-b', target: 'bridge-b', mode: 'forward' },
            { id: 'relay-1-relay-a', source: 'relay-1', target: 'relay-a', mode: 'forward' },
            { id: 'portal-relay-1', source: 'portal-1', target: 'relay-1', mode: 'forward' },
            { id: 'relay-a-bridge-a', source: 'relay-a', target: 'bridge-a', mode: 'forward' },
            { id: 'relay-1-relay-b', source: 'relay-1', target: 'relay-b', mode: 'forward' },
        ],
        groups: [
            {
                _id: 'group-b',
                mode: 'forward',
                strategy: 'priority-failover',
                paths: [{
                    pathKey: 'primary',
                    linkIds: ['portal-relay-1', 'relay-1-relay-b', 'relay-b-bridge-b'],
                    priority: 20,
                }],
            },
            {
                _id: 'group-a',
                mode: 'forward',
                strategy: 'priority-failover',
                paths: [{
                    pathKey: 'primary',
                    linkIds: ['portal-relay-1', 'relay-1-relay-a', 'relay-a-bridge-a'],
                    priority: 10,
                }],
            },
        ],
        healthByPathKey: {
            'group-a:primary': true,
            'group-b:primary': false,
        },
    };
}

test('isolates same-named paths by route group with scoped health decisions', () => {
    const compiled = compileTopology(twoGroupSharedPathKeyTopology());
    const relay = compiled.relays.find(candidate => candidate.nodeId === 'relay-1');

    assert.equal(compiled.valid, true);
    assert.deepEqual(relay.routeGroups, [
        {
            groupId: 'group-a',
            candidates: [{
                groupId: 'group-a',
                pathKey: 'primary',
                priority: 10,
                enabled: true,
                nextHopNodeId: 'relay-a',
                suffixLinks: [
                    { id: 'relay-1-relay-a', source: 'relay-1', target: 'relay-a', mode: 'forward' },
                    { id: 'relay-a-bridge-a', source: 'relay-a', target: 'bridge-a', mode: 'forward' },
                ],
            }],
            decision: {
                decision: 'select',
                groupId: 'group-a',
                pathKey: 'primary',
                nextHopNodeId: 'relay-a',
            },
        },
        {
            groupId: 'group-b',
            candidates: [{
                groupId: 'group-b',
                pathKey: 'primary',
                priority: 20,
                enabled: true,
                nextHopNodeId: 'relay-b',
                suffixLinks: [
                    { id: 'relay-1-relay-b', source: 'relay-1', target: 'relay-b', mode: 'forward' },
                    { id: 'relay-b-bridge-b', source: 'relay-b', target: 'bridge-b', mode: 'forward' },
                ],
            }],
            decision: {
                decision: 'block',
                error: { code: 'NO_HEALTHY_PATH' },
            },
        },
    ]);
});

test('produces deep-equal IR when input link order is permuted', () => {
    const original = twoGroupSharedPathKeyTopology();
    const permuted = twoGroupSharedPathKeyTopology();
    permuted.links.reverse();

    assert.deepEqual(compileTopology(permuted), compileTopology(original));
});
