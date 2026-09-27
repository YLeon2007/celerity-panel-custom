'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const Module = require('node:module');
const test = require('node:test');

const { generateXrayConfigWithApi } = require('../../../services/configGenerator');
const {
    cascadePathIngressPort,
    cascadePathIngressTag,
} = require('../domain/cascadePathIngress');

const {
    composeFrozenTopologyDeploymentPlan,
} = require('../services/frozenTopologyDeploymentPlanComposer');

function nodeMetadata(id, role, index) {
    return {
        id,
        role,
        type: 'xray',
        active: true,
        cascadeRole: role,
        ip: `192.0.2.${index}`,
        domain: `${role}.example.test`,
        port: 24000 + index,
        xray: {
            accessLogs: { enabled: role === 'portal' },
            apiPort: 61000 + index,
            inboundTag: `client-${role}`,
            transport: 'tcp',
            security: 'none',
            extraInbounds: role === 'portal' ? [{
                id: 'extra-portal',
                label: 'Portal extra',
                uniqueName: false,
                port: 25000 + index,
                inboundTag: 'client-portal-extra',
                transport: 'ws',
                security: 'none',
                wsPath: '/portal-extra',
            }] : [],
        },
    };
}

function canonicalJson(value) {
    if (Array.isArray(value)) return value.map(canonicalJson);
    if (value === null || typeof value !== 'object') return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalJson(value[key])]),
    );
}

function candidateConfig(node) {
    const content = Buffer.from(node.candidate.bytes).toString('utf8');
    const config = JSON.parse(content);
    assert.equal(content, `${JSON.stringify(canonicalJson(config))}\n`);
    assert.ok(Array.isArray(config.inbounds));
    assert.ok(Array.isArray(config.outbounds));
    assert.ok(config.routing && Array.isArray(config.routing.rules));
    return config;
}

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
            groups: [{
                _id: 'group-reverse',
                mode: 'reverse',
                strategy: 'priority-failover',
                paths: [
                    {
                        pathKey: 'backup',
                        linkIds: ['link-portal-relay-object-id', 'link-relay-bridge-object-id'],
                        priority: 2,
                        enabled: true,
                    },
                    {
                        pathKey: 'main',
                        linkIds: ['link-portal-relay-object-id', 'link-relay-bridge-object-id'],
                        priority: 1,
                        enabled: true,
                    },
                    {
                        pathKey: 'off',
                        linkIds: ['link-portal-relay-object-id', 'link-relay-bridge-object-id'],
                        priority: 3,
                        enabled: false,
                    },
                ],
            }],
        },
        nodeMetadata: [
            {
                ...nodeMetadata('node-relay-object-id', 'relay', 2),
                ssh: { password: 'relay-secret' },
            },
            {
                ...nodeMetadata('node-bridge-object-id', 'bridge', 3),
                privateKey: 'bridge-secret',
            },
            {
                ...nodeMetadata('node-portal-object-id', 'portal', 1),
                agentToken: 'portal-secret',
            },
        ],
        linkMetadata: [
            {
                id: 'link-relay-bridge-object-id',
                tunnelPort: 12002,
                tunnelUuid: 'relay-bridge-secret',
                tunnelDomain: 'reverse.example.test',
                tunnelProtocol: 'vless',
                tunnelSecurity: 'none',
                tunnelTransport: 'tcp',
            },
            {
                id: 'link-portal-relay-object-id',
                tunnelPort: 12001,
                tunnelUuid: 'portal-relay-secret',
                tunnelDomain: 'reverse.example.test',
                tunnelProtocol: 'vless',
                tunnelSecurity: 'none',
                tunnelTransport: 'tcp',
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
        candidateConfig(node);
    }

    const configs = Object.fromEntries(plan.nodes.map(node => [node.nodeRef, candidateConfig(node)]));
    // The portal keeps the panel management API surface on its xray-main profile.
    assert(configs.portal.inbounds.some(inbound => inbound.tag === 'API_INBOUND'), 'portal');
    assert(configs.portal.inbounds.some(inbound => inbound.tag === 'client-portal'), 'portal');
    assert(configs.portal.inbounds.some(inbound => inbound.tag === 'client-portal-extra'), 'portal');
    // Relay reverse candidates are pure cascade configs: no baseline composition,
    // no API_INBOUND (avoids the double bind against the relay xray-main API).
    assert.equal(configs['relay-1'].api, undefined, 'relay-1');
    assert.equal(configs['relay-1'].stats, undefined, 'relay-1');
    assert.equal(configs['relay-1'].policy, undefined, 'relay-1');
    assert.equal(
        configs['relay-1'].inbounds.some(inbound => inbound.tag === 'API_INBOUND'),
        false,
        'relay-1',
    );
    assert.equal(
        configs['relay-1'].inbounds.some(inbound => inbound.tag === 'client-relay'),
        false,
        'relay-1',
    );
    // Bridge keeps its client-facing baseline but must not bind the API either.
    assert.equal(
        configs.bridge.inbounds.some(inbound => inbound.tag === 'API_INBOUND'),
        false,
        'bridge',
    );
    assert.equal(configs.bridge.api, undefined, 'bridge');
    assert(configs.bridge.inbounds.some(inbound => inbound.tag === 'client-bridge'), 'bridge');
    // Per-path socks ingress covers every enabled path routed through the relay.
    assert.deepEqual(configs['relay-1'].inbounds.filter(inbound => inbound.protocol === 'socks'), [
        {
            tag: 'cascade-backup',
            listen: '127.0.0.1',
            port: cascadePathIngressPort('group-reverse', 'backup'),
            protocol: 'socks',
            settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' },
        },
        {
            tag: 'cascade-main',
            listen: '127.0.0.1',
            port: cascadePathIngressPort('group-reverse', 'main'),
            protocol: 'socks',
            settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' },
        },
    ]);
    assert.equal(cascadePathIngressPort('group-reverse', 'backup'), 19330);
    assert.equal(cascadePathIngressPort('group-reverse', 'main'), 19592);
    for (const tag of ['cascade-backup', 'cascade-main']) {
        assert(configs['relay-1'].routing.rules.some(rule => (
            rule.inboundTag?.includes(tag) && rule.outboundTag === 'portal-down-link-2'
        )), tag);
    }
    // Disabled paths and non-relay roles get no ingress listeners.
    assert.equal(
        configs['relay-1'].inbounds.some(inbound => inbound.tag === 'cascade-off'),
        false,
    );
    assert.equal(configs.portal.inbounds.some(inbound => inbound.protocol === 'socks'), false);
    assert.equal(configs.bridge.inbounds.some(inbound => inbound.protocol === 'socks'), false);
    // The new socks listeners are covered by deployment checks.
    assert.deepEqual(plan.nodes.find(node => node.nodeRef === 'relay-1').checks, [
        { type: 'service', serviceUnit: 'xray-bridge.service', expectedState: 'active' },
        { type: 'port', protocol: 'tcp', port: 12002, expectedState: 'listening' },
        { type: 'port', protocol: 'tcp', port: 19330, expectedState: 'listening' },
        { type: 'port', protocol: 'tcp', port: 19592, expectedState: 'listening' },
    ]);
    assert.deepEqual(configs.portal.reverse.portals, [{
        tag: 'portal-link-1',
        domain: 'link-1.reverse.example.test',
    }]);
    assert(configs.portal.inbounds.some(inbound => inbound.tag === 'bridge-conn-link-1'));
    assert(configs.portal.routing.rules.some(rule => (
        rule.inboundTag?.includes('client-portal') && rule.outboundTag === 'portal-link-1'
    )));
    assert.deepEqual(configs['relay-1'].reverse.bridges, [{
        tag: 'bridge-up',
        domain: 'link-1.reverse.example.test',
    }]);
    assert.deepEqual(configs['relay-1'].reverse.portals, [{
        tag: 'portal-down-link-2',
        domain: 'link-2.reverse.example.test',
    }]);
    assert(configs['relay-1'].outbounds.some(outbound => outbound.tag === 'tunnel-up'));
    assert(configs['relay-1'].inbounds.some(inbound => inbound.tag === 'conn-down-link-2'));
    assert.deepEqual(configs.bridge.reverse.bridges, [{
        tag: 'bridge-link-2',
        domain: 'link-2.reverse.example.test',
    }]);
    assert(configs.bridge.outbounds.some(outbound => outbound.tag === 'tunnel-link-2'));
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

test('composes Reality tunnel security into portal and relay candidates', () => {
    const input = reverseChainInput();
    const realityPrivateKey = 'reality-private-key-canary';
    const realityPublicKey = 'reality-public-key-canary';
    const realityLink = input.linkMetadata.find(
        link => link.id === 'link-portal-relay-object-id',
    );
    realityLink.tunnelSecurity = 'reality';
    realityLink.realityDest = 'dl.google.com:443';
    realityLink.realitySni = ['dl.google.com'];
    realityLink.realityPrivateKey = realityPrivateKey;
    realityLink.realityPublicKey = realityPublicKey;
    realityLink.realityShortIds = ['ab01cd23'];
    realityLink.realityFingerprint = 'chrome';

    const plan = composeFrozenTopologyDeploymentPlan(input);
    const portalCandidate = plan.nodes.find(node => node.role === 'portal');
    const relayCandidate = plan.nodes.find(node => node.role === 'relay');
    const portalConfig = candidateConfig(portalCandidate);
    const relayConfig = candidateConfig(relayCandidate);

    // Portal is the listening side of the reverse tunnel: full server reality
    // settings including the private key.
    const portalTunnelInbound = portalConfig.inbounds.find(inbound =>
        inbound.streamSettings?.security === 'reality');
    assert.ok(portalTunnelInbound, 'portal listens with reality stream security');
    assert.equal(
        portalTunnelInbound.streamSettings.realitySettings.privateKey,
        realityPrivateKey,
    );
    assert.deepEqual(
        portalTunnelInbound.streamSettings.realitySettings.serverNames,
        ['dl.google.com'],
    );

    // Relay dials the portal: client-side reality settings carry the public
    // key and must never include the private key.
    const relayTunnelOutbound = relayConfig.outbounds.find(outbound =>
        outbound.streamSettings?.security === 'reality');
    assert.ok(relayTunnelOutbound, 'relay dials with reality stream security');
    assert.equal(
        relayTunnelOutbound.streamSettings.realitySettings.publicKey,
        realityPublicKey,
    );
    assert.equal(
        relayTunnelOutbound.streamSettings.realitySettings.privateKey,
        undefined,
    );
    assert.equal(
        JSON.stringify(relayConfig).includes(realityPrivateKey),
        false,
        'relay candidate must not leak the portal reality private key',
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
    permuted.snapshot.groups = permuted.snapshot.groups
        .map(group => ({ ...group, paths: [...group.paths].reverse() }))
        .reverse();
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
            {
                type: 'port',
                protocol: 'tcp',
                port: 19330,
                expectedState: 'listening',
            },
            {
                type: 'port',
                protocol: 'tcp',
                port: 19592,
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

    const configs = Object.fromEntries(plan.nodes.map(node => [node.nodeRef, candidateConfig(node)]));
    assert(configs.portal.inbounds.some(inbound => inbound.tag === 'client-portal-extra'));
    assert(configs.portal.outbounds.some(outbound => outbound.tag === 'fwd-link-1'));
    const exitOutbound = configs.portal.outbounds.find(outbound => outbound.tag === 'fwd-link-2');
    assert.deepEqual(exitOutbound.proxySettings, { tag: 'fwd-link-1', transportLayer: true });
    assert(configs.portal.routing.rules.some(rule => (
        rule.inboundTag?.includes('client-portal')
        && rule.inboundTag?.includes('client-portal-extra')
        && rule.outboundTag === 'fwd-link-2'
    )));
    assert(configs['relay-1'].inbounds.some(inbound => inbound.tag === 'fwd-hop-link-1'));
    assert(configs['relay-1'].routing.rules.some(rule => (
        rule.inboundTag?.includes('fwd-hop-link-1') && rule.outboundTag === 'direct'
    )));
    assert(configs.bridge.inbounds.some(inbound => inbound.tag === 'fwd-hop-link-2'));
    // Forward relay exposes the same per-path socks ingress, chained to the exit.
    assert.deepEqual(
        configs['relay-1'].inbounds
            .filter(inbound => inbound.protocol === 'socks')
            .map(inbound => inbound.tag),
        ['cascade-backup', 'cascade-main'],
    );
    assert(configs['relay-1'].outbounds.some(outbound => outbound.tag === 'fwd-link-2'));
    assert(configs['relay-1'].routing.rules.some(rule => (
        rule.inboundTag?.includes('cascade-backup')
        && rule.inboundTag?.includes('cascade-main')
        && rule.outboundTag === 'fwd-link-2'
    )));
    // Relay/bridge forward candidates must not bind the panel API either.
    assert.equal(configs['relay-1'].inbounds.some(inbound => inbound.tag === 'API_INBOUND'), false);
    assert.equal(configs.bridge.inbounds.some(inbound => inbound.tag === 'API_INBOUND'), false);
    assert(configs.portal.inbounds.some(inbound => inbound.tag === 'API_INBOUND'));
});

test('composes every relay in a longer reverse v1 chain', () => {
    const input = reverseChainInput();
    const relayBridge = input.snapshot.links.find(link => (
        link.id === 'link-relay-bridge-object-id'
    ));
    relayBridge.target = 'node-relay-two-object-id';
    input.snapshot.nodes.push({ id: 'node-relay-two-object-id', role: 'relay' });
    input.snapshot.links.push({
        id: 'link-relay-two-bridge-object-id',
        source: 'node-relay-two-object-id',
        target: 'node-bridge-object-id',
        mode: 'reverse',
    });
    input.nodeMetadata.push(nodeMetadata('node-relay-two-object-id', 'relay', 4));
    input.linkMetadata.find(link => link.id === relayBridge.id).target = 'node-relay-two-object-id';
    input.linkMetadata.push({
        id: 'link-relay-two-bridge-object-id',
        tunnelPort: 12003,
        tunnelDomain: 'reverse.example.test',
        tunnelProtocol: 'vless',
        tunnelSecurity: 'none',
        tunnelTransport: 'tcp',
    });
    input.compiledTopology.relays.push({
        nodeId: 'node-relay-two-object-id',
        routeGroups: [],
    });
    // Only the 'main' path extends over the new relay-2 subchain link.
    input.snapshot.groups[0].paths
        .find(path => path.pathKey === 'main')
        .linkIds.push('link-relay-two-bridge-object-id');

    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.deepEqual(
        plan.nodes.map(node => node.nodeRef),
        ['portal', 'relay-1', 'relay-2', 'bridge'],
    );
    for (const nodeRef of ['relay-1', 'relay-2']) {
        const config = candidateConfig(plan.nodes.find(node => node.nodeRef === nodeRef));
        assert.equal(config.reverse.bridges.length, 1);
        assert.equal(config.reverse.portals.length, 1);
    }
    // Per-path ingress follows the path subchain: relay-1 serves both enabled
    // paths, relay-2 only the path that actually crosses its downstream link.
    const relayOne = candidateConfig(plan.nodes.find(node => node.nodeRef === 'relay-1'));
    const relayTwo = candidateConfig(plan.nodes.find(node => node.nodeRef === 'relay-2'));
    assert(relayOne.inbounds.some(inbound => inbound.tag === 'cascade-main'));
    assert(relayOne.inbounds.some(inbound => inbound.tag === 'cascade-backup'));
    assert(relayOne.routing.rules.some(rule => (
        rule.inboundTag?.includes('cascade-main') && rule.outboundTag === 'portal-down-link-2'
    )));
    assert(relayTwo.inbounds.some(inbound => inbound.tag === 'cascade-main'));
    assert.equal(relayTwo.inbounds.some(inbound => inbound.tag === 'cascade-backup'), false);
    assert(relayTwo.routing.rules.some(rule => (
        rule.inboundTag?.includes('cascade-main') && rule.outboundTag === 'portal-down-link-3'
    )));
    assert.equal(relayTwo.inbounds.some(inbound => inbound.tag === 'API_INBOUND'), false);
});

test('composes a direct Portal to Bridge forward v1 chain without relays', () => {
    const input = forwardChainInput();
    input.snapshot.nodes = input.snapshot.nodes.filter(node => node.role !== 'relay');
    input.snapshot.links = [{
        id: 'link-portal-bridge-object-id',
        source: 'node-portal-object-id',
        target: 'node-bridge-object-id',
        mode: 'forward',
    }];
    input.nodeMetadata = input.nodeMetadata.filter(node => node.role !== 'relay');
    input.linkMetadata = [{
        id: 'link-portal-bridge-object-id',
        tunnelPort: 12001,
        tunnelDomain: 'forward.example.test',
        tunnelProtocol: 'vless',
        tunnelSecurity: 'none',
        tunnelTransport: 'tcp',
    }];
    input.compiledTopology.relays = [];

    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.deepEqual(plan.nodes.map(node => node.nodeRef), ['bridge', 'portal']);
    const portal = candidateConfig(plan.nodes.find(node => node.nodeRef === 'portal'));
    const bridge = candidateConfig(plan.nodes.find(node => node.nodeRef === 'bridge'));
    assert(portal.outbounds.some(outbound => outbound.tag === 'fwd-link-1'));
    assert(bridge.inbounds.some(inbound => inbound.tag === 'fwd-hop-link-1'));
});

test('preserves the official Xray generator baseline before adding cascade pieces', () => {
    const input = reverseChainInput();
    const portalMetadata = input.nodeMetadata.find(node => node.role === 'portal');
    const baseline = JSON.parse(generateXrayConfigWithApi(portalMetadata, []));
    const plan = composeFrozenTopologyDeploymentPlan(input);
    const portal = candidateConfig(plan.nodes.find(node => node.role === 'portal'));

    assert.deepEqual(portal.log, baseline.log);
    assert.deepEqual(portal.api, baseline.api);
    assert.deepEqual(portal.stats, baseline.stats);
    assert.deepEqual(portal.policy, baseline.policy);
    for (const inbound of baseline.inbounds) {
        assert.deepEqual(portal.inbounds.find(candidate => candidate.tag === inbound.tag), inbound);
    }
    assert.equal(baseline.inbounds[0].tag, 'API_INBOUND');
});

test('rejects a cascade listener that collides with a preserved server inbound', () => {
    const input = reverseChainInput();
    input.nodeMetadata.find(node => node.role === 'portal').port = 12001;

    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        {
            name: 'FrozenTopologyDeploymentPlanError',
            code: 'XRAY_CONFIG_GENERATION_FAILED',
            message: 'Failed to generate a frozen Xray topology candidate',
        },
    );
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
        '_id', 'nodeId', 'linkId', 'objectId',
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

test('loads and composes without database, SSH, or CascadeService dependencies', () => {
    const modulePath = require.resolve('../services/frozenTopologyDeploymentPlanComposer');
    const originalLoad = Module._load;
    const blocked = /(?:mongoose|node:net|node:ssh|cascadeService|nodeSSH|repositories|models)/i;
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

test('disconnected roled nodes are excluded from the plan instead of failing validation', () => {
    const input = reverseChainInput();
    input.snapshot.nodes.push(
        { id: 'node-staged-relay-object-id', role: 'relay' },
        { id: 'node-staged-bridge-object-id', role: 'bridge' },
    );

    const plan = composeFrozenTopologyDeploymentPlan(input);

    assert.equal(plan.mode, 'reverse');
    assert.deepEqual(
        plan.nodes.map(node => node.nodeRef).sort(),
        ['bridge', 'portal', 'relay-1'],
    );
});

test('rejects a linear chain with two portals (role flipped mid-chain)', () => {
    const input = reverseChainInput();
    input.snapshot.nodes.find(node => node.role === 'relay').role = 'portal';

    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        {
            name: 'FrozenTopologyDeploymentPlanError',
            code: 'INVALID_TOPOLOGY_ROLES',
        },
    );
});

test('composes a mixed forward/reverse linear chain hop-by-hop', () => {
    const input = reverseChainInput();
    // portal -> relay stays forward; relay -> bridge flips to reverse
    // (bridge dials the relay, e.g. when the forward hop is blocked).
    input.snapshot.links.find(link => link.id === 'link-portal-relay-object-id').mode = 'forward';
    const plan = composeFrozenTopologyDeploymentPlan(input);

    assert.equal(plan.mode, 'mixed');
    const byRef = new Map(plan.nodes.map(node => [node.nodeRef, node]));

    // Portal originates the forward hop and routes clients into it.
    const portal = candidateConfig(byRef.get('portal'));
    const fwdOutbound = portal.outbounds.find(outbound => String(outbound.tag).startsWith('fwd-'));
    assert.ok(fwdOutbound, 'portal must originate the forward hop outbound');
    assert.ok(portal.routing.rules.some(rule => (
        rule.inboundTag?.includes('client-portal') && rule.outboundTag === fwdOutbound.tag
    )));
    assert.equal(portal.reverse, undefined, 'portal has no reverse artifacts');

    // Relay terminates the forward hop and hosts the reverse portal for the
    // downstream link; hop traffic re-originates into the reverse portal.
    const relay = candidateConfig(byRef.get('relay-1'));
    const hopInbound = relay.inbounds.find(inbound => String(inbound.tag).startsWith('fwd-hop-'));
    assert.ok(hopInbound, 'relay must bind the forward hop inbound');
    assert.equal(hopInbound.port, 12001);
    const conn = relay.inbounds.find(inbound => String(inbound.tag).startsWith('bridge-conn-'));
    assert.ok(conn, 'relay must bind the reverse connector inbound');
    assert.equal(conn.port, 12002);
    const portalEntry = (relay.reverse?.portals || [])[0];
    assert.ok(portalEntry, 'relay must declare the reverse portal for its downstream link');
    assert.ok(relay.routing.rules.some(rule => (
        rule.inboundTag?.includes(hopInbound.tag) && rule.outboundTag === portalEntry.tag
    )), 'forward hop exit must route into the reverse portal');
    assert.ok(
        !relay.outbounds.some(outbound => String(outbound.tag).startsWith('fwd-')),
        'relay must not dial forward for a reverse downstream link',
    );

    // Bridge dials the relay (reverse bridge) and exits directly.
    const bridge = candidateConfig(byRef.get('bridge'));
    const bridgeEntry = (bridge.reverse?.bridges || [])[0];
    assert.ok(bridgeEntry, 'bridge must declare the reverse bridge');
    const tunnel = bridge.outbounds.find(outbound => String(outbound.tag).startsWith('tunnel-'));
    assert.ok(tunnel, 'bridge must have the reverse tunnel outbound');
    assert.equal(tunnel.settings?.vnext?.[0]?.address, '192.0.2.2', 'tunnel dials the relay');
    assert.equal(tunnel.settings?.vnext?.[0]?.port, 12002);
    assert.ok(bridge.routing.rules.some(rule => (
        rule.inboundTag?.includes(bridgeEntry.tag) && rule.outboundTag === 'direct'
    )));

    // The relay listens on both links (forward target + reverse source), plus
    // the loopback L2TP path ingress ports from the route group.
    const relayPorts = byRef.get('relay-1').checks
        .filter(check => check.type === 'port').map(check => check.port);
    assert.ok(relayPorts.includes(12001));
    assert.ok(relayPorts.includes(12002));
    const bridgePorts = byRef.get('bridge').checks
        .filter(check => check.type === 'port').map(check => check.port);
    assert.deepEqual(bridgePorts, []);

    // Listener-first order: relay (listener of both links) deploys first.
    const order = plan.nodes.map(node => node.nodeRef);
    assert.ok(order.indexOf('relay-1') < order.indexOf('portal'));
    assert.ok(order.indexOf('relay-1') < order.indexOf('bridge'));
});
