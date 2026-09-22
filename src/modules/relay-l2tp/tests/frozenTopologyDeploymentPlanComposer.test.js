'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const Module = require('node:module');
const test = require('node:test');

const {
    composeFrozenTopologyDeploymentPlan,
} = require('../services/frozenTopologyDeploymentPlanComposer');

function reverseChainInput() {
    return {
        snapshot: {
            nodes: [
                { id: 'node-bridge-object-id', role: 'bridge' },
                { id: 'node-portal-object-id', role: 'portal' },
                { id: 'node-relay-object-id', role: 'relay' },
            ],
            links: [
                {
                    id: 'link-relay-bridge-object-id',
                    source: 'node-relay-object-id',
                    target: 'node-bridge-object-id',
                    mode: 'reverse',
                },
                {
                    id: 'link-portal-relay-object-id',
                    source: 'node-portal-object-id',
                    target: 'node-relay-object-id',
                    mode: 'reverse',
                },
            ],
            groups: [],
        },
        nodeMetadata: [
            { id: 'node-relay-object-id', role: 'relay', ssh: { password: 'relay-secret' } },
            { id: 'node-bridge-object-id', role: 'bridge', privateKey: 'bridge-secret' },
            { id: 'node-portal-object-id', role: 'portal', agentToken: 'portal-secret' },
        ],
        linkMetadata: [
            {
                id: 'link-relay-bridge-object-id',
                tunnelPort: 12002,
                tunnelUuid: 'relay-bridge-secret',
            },
            {
                id: 'link-portal-relay-object-id',
                tunnelPort: 12001,
                tunnelUuid: 'portal-relay-secret',
            },
        ],
        compiledTopology: {
            valid: true,
            errors: [],
            relays: [{ nodeId: 'node-relay-object-id', routeGroups: [] }],
        },
    };
}

test('composes frozen secret-free reverse candidates in Portal to Relay to Bridge order', () => {
    const plan = composeFrozenTopologyDeploymentPlan(reverseChainInput());

    assert.equal(plan.schemaVersion, 1);
    assert.equal(plan.mode, 'reverse');
    assert.deepEqual(plan.nodes.map(node => ({
        nodeRef: node.nodeRef,
        role: node.role,
        targetProfile: node.targetProfile,
        serviceUnit: node.serviceUnit,
        configPath: node.configPath,
    })), [
        {
            nodeRef: 'portal',
            role: 'portal',
            targetProfile: 'xray-main',
            serviceUnit: 'xray.service',
            configPath: '/usr/local/etc/xray/config.json',
        },
        {
            nodeRef: 'relay-1',
            role: 'relay',
            targetProfile: 'xray-bridge',
            serviceUnit: 'xray-bridge.service',
            configPath: '/usr/local/etc/xray-bridge/config.json',
        },
        {
            nodeRef: 'bridge',
            role: 'bridge',
            targetProfile: 'xray-bridge',
            serviceUnit: 'xray-bridge.service',
            configPath: '/usr/local/etc/xray-bridge/config.json',
        },
    ]);

    for (const node of plan.nodes) {
        const bytes = Buffer.from(node.candidate.bytes);
        assert.equal(
            node.candidate.sha256,
            createHash('sha256').update(bytes).digest('hex'),
        );
        assert.doesNotMatch(bytes.toString('utf8'), /object-id|secret/i);
        assert.equal(Object.isFrozen(node), true);
        assert.equal(Object.isFrozen(node.candidate), true);
        assert.equal(Object.isFrozen(node.candidate.bytes), true);
    }
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.nodes), true);
});

test('rejects hydrated link metadata that does not match its frozen link', () => {
    const input = reverseChainInput();
    input.linkMetadata[0].source = 'node-portal-object-id';
    input.linkMetadata[0].target = 'node-bridge-object-id';
    input.linkMetadata[0].mode = 'forward';

    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        {
            name: 'FrozenTopologyDeploymentPlanError',
            code: 'LINK_METADATA_MISMATCH',
        },
    );
});

test('rejects compiled relay data for a node outside the frozen topology', () => {
    const input = reverseChainInput();
    input.compiledTopology.relays[0].nodeId = 'missing-node-object-id';

    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        {
            name: 'FrozenTopologyDeploymentPlanError',
            code: 'COMPILED_TOPOLOGY_MISMATCH',
        },
    );
});

function forwardChainInput() {
    const input = reverseChainInput();
    input.snapshot.links.forEach(link => { link.mode = 'forward'; });
    return input;
}

test('composes forward plans in Bridge to Relay to Portal order with exact checks', () => {
    const original = forwardChainInput();
    const permuted = forwardChainInput();
    permuted.snapshot.nodes.reverse();
    permuted.snapshot.links.reverse();
    permuted.nodeMetadata.reverse();
    permuted.linkMetadata.reverse();
    permuted.compiledTopology.relays.reverse();

    const plan = composeFrozenTopologyDeploymentPlan(original);
    const second = composeFrozenTopologyDeploymentPlan(permuted);

    assert.deepEqual(second, plan);
    assert.deepEqual(plan.nodes.map(node => node.nodeRef), ['bridge', 'relay-1', 'portal']);
    assert.deepEqual(plan.nodes.map(node => node.checks), [
        [
            {
                type: 'service',
                serviceUnit: 'xray-bridge.service',
                expectedState: 'active',
            },
            {
                type: 'port',
                protocol: 'tcp',
                port: 12002,
                expectedState: 'listening',
            },
        ],
        [
            {
                type: 'service',
                serviceUnit: 'xray-bridge.service',
                expectedState: 'active',
            },
            {
                type: 'port',
                protocol: 'tcp',
                port: 12001,
                expectedState: 'listening',
            },
        ],
        [
            {
                type: 'service',
                serviceUnit: 'xray.service',
                expectedState: 'active',
            },
        ],
    ]);

    const bridgeCandidate = JSON.parse(Buffer.from(plan.nodes[0].candidate.bytes).toString('utf8'));
    assert.deepEqual(bridgeCandidate, {
        schemaVersion: 1,
        kind: 'xray-topology-node-candidate',
        mode: 'forward',
        nodeRef: 'bridge',
        role: 'bridge',
        targetProfile: 'xray-bridge',
        links: [{
            linkRef: 'link-2',
            direction: 'inbound',
            peerRef: 'relay-1',
            port: 12002,
        }],
        checks: plan.nodes[0].checks,
    });
});

test('rejects a topology node with a missing role', () => {
    const input = reverseChainInput();
    delete input.snapshot.nodes.find(node => node.role === 'relay').role;

    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        {
            name: 'FrozenTopologyDeploymentPlanError',
            code: 'MISSING_NODE_ROLE',
        },
    );
});

test('rejects a frozen chain with a missing topology link', () => {
    const input = reverseChainInput();
    input.snapshot.links.pop();

    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        {
            name: 'FrozenTopologyDeploymentPlanError',
            code: 'MISSING_TOPOLOGY_LINK',
        },
    );
});

test('rejects a topology link with missing hydrated metadata', () => {
    const input = reverseChainInput();
    input.linkMetadata.pop();

    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        {
            name: 'FrozenTopologyDeploymentPlanError',
            code: 'MISSING_LINK_METADATA',
        },
    );
});

test('does not project hostile fields, object ids, or secrets into a candidate plan', () => {
    const input = reverseChainInput();
    const hostile = 'HOSTILE; rm -rf /; $(touch /tmp/pwned)';
    input.snapshot.nodes[0].name = hostile;
    input.snapshot.links[0].shell = hostile;
    input.snapshot.groups = [{ command: hostile, argv: [hostile], objectId: 'group-object-id' }];
    input.nodeMetadata[0].command = hostile;
    input.nodeMetadata[0].password = 'password-secret';
    input.linkMetadata[0].stdin = hostile;
    input.compiledTopology.relays[0].routeGroups = [{ rawShell: hostile }];
    const untouched = structuredClone(input);

    const plan = composeFrozenTopologyDeploymentPlan(input);
    const serialized = JSON.stringify(plan);
    const forbiddenKeys = new Set([
        '_id', 'id', 'nodeId', 'linkId', 'objectId',
        'command', 'argv', 'shell', 'stdin', 'password', 'privateKey', 'agentToken', 'tunnelUuid',
    ]);
    const visit = value => {
        if (value === null || typeof value !== 'object') return;
        for (const [key, nested] of Object.entries(value)) {
            assert.equal(forbiddenKeys.has(key), false, `forbidden plan field: ${key}`);
            visit(nested);
        }
    };

    visit(plan);
    assert.doesNotMatch(serialized, /HOSTILE|object-id|password-secret|relay-secret|bridge-secret|portal-secret/);
    assert.deepEqual(input, untouched);
});

test('loads and composes without database, SSH, filesystem, or CascadeService dependencies', () => {
    const modulePath = require.resolve('../services/frozenTopologyDeploymentPlanComposer');
    const originalLoad = Module._load;
    const blocked = /(?:mongoose|node:fs|node:net|node:ssh|cascadeService|nodeSSH|repositories|models)/i;
    delete require.cache[modulePath];
    Module._load = function guardedLoad(request, parent, isMain) {
        assert.doesNotMatch(request, blocked);
        return originalLoad.call(this, request, parent, isMain);
    };
    try {
        const freshComposer = require(modulePath);
        assert.equal(freshComposer.composeFrozenTopologyDeploymentPlan(reverseChainInput()).mode, 'reverse');
    } finally {
        Module._load = originalLoad;
        delete require.cache[modulePath];
    }
});
