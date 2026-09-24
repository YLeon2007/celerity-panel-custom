'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

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
        domain: `${role}${index}.example.test`,
        port: 24000 + index,
        xray: {
            accessLogs: { enabled: false },
            apiPort: 61000 + index,
            inboundTag: `client-${role}${index}`,
            transport: 'tcp',
            security: 'none',
            extraInbounds: [],
        },
    };
}

function linkMetadata(id, tunnelPort, extra = {}) {
    return {
        id,
        tunnelPort,
        tunnelUuid: `uuid-${id}`,
        tunnelDomain: 'reverse.example.test',
        tunnelProtocol: 'vless',
        tunnelSecurity: 'none',
        tunnelTransport: 'tcp',
        ...extra,
    };
}

const GEO_ROUTING = {
    enabled: true,
    domains: ['category-ru'],
    geoip: ['ru', 'su'],
};

function geoChainInput(mode = 'reverse', geoRouting = GEO_ROUTING) {
    return {
        snapshot: {
            nodes: [
                { id: 'node-portal', role: 'portal' },
                { id: 'node-relay', role: 'relay' },
                { id: 'node-bridge', role: 'bridge' },
                { id: 'node-bridge-geo', role: 'bridge' },
            ],
            links: [
                {
                    id: 'link-portal-relay',
                    source: 'node-portal',
                    target: 'node-relay',
                    mode,
                },
                {
                    id: 'link-relay-bridge',
                    source: 'node-relay',
                    target: 'node-bridge',
                    mode,
                },
                {
                    id: 'link-relay-geobridge',
                    source: 'node-relay',
                    target: 'node-bridge-geo',
                    mode,
                },
            ],
            groups: [],
        },
        nodeMetadata: [
            nodeMetadata('node-portal', 'portal', 1),
            nodeMetadata('node-relay', 'relay', 2),
            nodeMetadata('node-bridge', 'bridge', 3),
            nodeMetadata('node-bridge-geo', 'bridge', 4),
        ],
        linkMetadata: [
            linkMetadata('link-portal-relay', 12001),
            linkMetadata('link-relay-bridge', 12002),
            linkMetadata('link-relay-geobridge', 12003, { geoRouting }),
        ],
        compiledTopology: {
            valid: true,
            errors: [],
            relays: [{ nodeId: 'node-relay', routeGroups: [] }],
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
    const config = JSON.parse(Buffer.from(node.candidate.bytes).toString('utf8'));
    return config;
}

test('reverse chain with a geo-routing branch bridge composes end-to-end', () => {
    const plan = composeFrozenTopologyDeploymentPlan(geoChainInput('reverse'));

    assert.deepEqual(
        plan.nodes.map(node => node.nodeRef),
        ['portal', 'relay-1', 'bridge', 'bridge-2'],
    );
    assert.deepEqual(
        plan.nodes.map(node => node.role),
        ['portal', 'relay', 'bridge', 'bridge'],
    );

    const configs = Object.fromEntries(plan.nodes.map(node => [node.nodeRef, candidateConfig(node)]));

    // Relay splits traffic: geo rules first, default bridge rule after, and
    // the private-IP blackhole stays last.
    const relayRules = configs['relay-1'].routing.rules;
    const geoRuleIndex = relayRules.findIndex(rule => rule.outboundTag === 'portal-down-link-3'
        && Array.isArray(rule.ip) && rule.ip.includes('geoip:ru'));
    const geoDomainRuleIndex = relayRules.findIndex(rule => rule.outboundTag === 'portal-down-link-3'
        && Array.isArray(rule.domain) && rule.domain.includes('geosite:category-ru'));
    const defaultRuleIndex = relayRules.findIndex(rule => rule.inboundTag?.includes('bridge-up')
        && rule.outboundTag === 'portal-down-link-2');
    const privateIndex = relayRules.findIndex(rule => Array.isArray(rule.ip)
        && rule.ip.includes('geoip:private'));
    assert.ok(geoRuleIndex >= 0, 'geoip rule must target the geo bridge portal');
    assert.ok(geoDomainRuleIndex >= 0, 'domain rule must target the geo bridge portal');
    assert.ok(defaultRuleIndex >= 0, 'default rule must target the default bridge portal');
    assert.ok(geoRuleIndex < defaultRuleIndex, 'geo rules precede the default rule');
    assert.ok(privateIndex > defaultRuleIndex, 'geoip:private stays last');

    // Every plan node carries its durable node id so the coordinator never
    // re-derives refs by walking a branching link graph.
    const byRef = Object.fromEntries(plan.nodes.map(node => [node.nodeRef, node]));
    assert.equal(byRef.portal.node, 'node-portal');
    assert.equal(byRef['relay-1'].node, 'node-relay');
    assert.equal(byRef.bridge.node, 'node-bridge');
    assert.equal(byRef['bridge-2'].node, 'node-bridge-geo');

    // The geo bridge is configured like a regular bridge for its own link:
    // in reverse mode it dials out through its tunnel outbound.
    const geoBridge = configs['bridge-2'];
    assert.ok(geoBridge.outbounds.some(outbound => outbound.tag === 'tunnel-link-3'), 'geo bridge tunnel');
});

test('forward chain with a geo-routing branch bridge composes end-to-end', () => {
    const plan = composeFrozenTopologyDeploymentPlan(geoChainInput('forward'));

    assert.deepEqual(
        plan.nodes.map(node => node.nodeRef),
        ['bridge-2', 'bridge', 'relay-1', 'portal'],
    );

    const configs = Object.fromEntries(plan.nodes.map(node => [node.nodeRef, candidateConfig(node)]));
    const portal = configs.portal;

    // Geo outbound chains through the main-chain prefix (fwd of portal->relay).
    const geoOutbound = portal.outbounds.find(outbound => outbound.tag === 'fwd-link-3');
    assert.ok(geoOutbound, 'geo branch outbound exists');
    assert.deepEqual(geoOutbound.proxySettings, { tag: 'fwd-link-1', transportLayer: true });

    const rules = portal.routing.rules;
    const geoIndex = rules.findIndex(rule => rule.outboundTag === 'fwd-link-3'
        && Array.isArray(rule.ip) && rule.ip.includes('geoip:ru'));
    const defaultIndex = rules.findIndex(rule => rule.outboundTag === 'fwd-link-2'
        && !Array.isArray(rule.ip) && !Array.isArray(rule.domain));
    const privateIndex = rules.findIndex(rule => Array.isArray(rule.ip)
        && rule.ip.includes('geoip:private'));
    assert.ok(geoIndex >= 0, 'geo rule exists');
    assert.ok(defaultIndex >= 0, 'default exit rule exists');
    assert.ok(geoIndex < defaultIndex, 'geo rules precede the default rule');
    assert.ok(privateIndex > geoIndex, 'geoip:private stays last');

    // Geo bridge accepts its forward hop inbound.
    assert.ok(configs['bridge-2'].inbounds.some(inbound => inbound.port === 12003));
});

test('candidate generation stays deterministic with geo branches', () => {
    const first = composeFrozenTopologyDeploymentPlan(geoChainInput('reverse'));
    const second = composeFrozenTopologyDeploymentPlan(geoChainInput('reverse'));
    assert.deepEqual(
        first.nodes.map(node => [node.nodeRef, node.candidate.sha256]),
        second.nodes.map(node => [node.nodeRef, node.candidate.sha256]),
    );
});

test('rejects a geo link whose rules sanitize to nothing (Cyrillic geoip)', () => {
    const input = geoChainInput('reverse', { enabled: true, domains: [], geoip: ['рф'] });
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        { name: 'FrozenTopologyDeploymentPlanError', code: 'GEO_LEAF_WITHOUT_RULES' },
    );
});

test('sanitizes invalid geoip tags but keeps valid rules', () => {
    const input = geoChainInput('reverse', { enabled: true, domains: [], geoip: ['RU', 'рф'] });
    const plan = composeFrozenTopologyDeploymentPlan(input);
    const configs = Object.fromEntries(plan.nodes.map(node => [node.nodeRef, candidateConfig(node)]));
    const geoRules = configs['relay-1'].routing.rules
        .filter(rule => rule.outboundTag === 'portal-down-link-3'
            && rule.inboundTag?.includes('bridge-up'));
    assert.equal(geoRules.length, 1);
    assert.deepEqual(geoRules[0].ip, ['geoip:ru']);
});

test('rejects duplicate geo rules across branch links', () => {
    const input = geoChainInput('reverse');
    input.snapshot.nodes.push({ id: 'node-bridge-geo2', role: 'bridge' });
    input.snapshot.links.push({
        id: 'link-relay-geobridge2',
        source: 'node-relay',
        target: 'node-bridge-geo2',
        mode: 'reverse',
    });
    input.nodeMetadata.push(nodeMetadata('node-bridge-geo2', 'bridge', 5));
    input.linkMetadata.push(linkMetadata('link-relay-geobridge2', 12004, {
        geoRouting: { enabled: true, domains: [], geoip: ['ru'] },
    }));
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        { name: 'FrozenTopologyDeploymentPlanError', code: 'DUPLICATE_GEO_RULE' },
    );
});

test('rejects geo rules on a main-chain link', () => {
    const input = geoChainInput('reverse');
    input.linkMetadata[1] = linkMetadata('link-relay-bridge', 12002, {
        geoRouting: { enabled: true, domains: [], geoip: ['us'] },
    });
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        { name: 'FrozenTopologyDeploymentPlanError', code: 'NON_LINEAR_TOPOLOGY' },
    );
});

test('rejects an extra bridge without geoRouting', () => {
    const input = geoChainInput('reverse', { enabled: false, domains: [], geoip: [] });
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        { name: 'FrozenTopologyDeploymentPlanError', code: 'NON_LINEAR_TOPOLOGY' },
    );
});

test('rejects a geo branch terminating at the default bridge', () => {
    const input = geoChainInput('reverse');
    input.snapshot.links[2].target = 'node-bridge';
    assert.throws(
        () => composeFrozenTopologyDeploymentPlan(input),
        { name: 'FrozenTopologyDeploymentPlanError', code: 'GEO_LEAF_TARGET_CONFLICT' },
    );
});
