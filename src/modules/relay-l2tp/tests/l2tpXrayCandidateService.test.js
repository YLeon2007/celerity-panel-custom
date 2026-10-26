'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'test@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || '01234567890123456789012345678901';

const assert = require('node:assert/strict');
const test = require('node:test');

const { generateXrayConfig } = require('../../../services/configGenerator');
const {
    cascadePathIngressPort,
} = require('../domain/cascadePathIngress');
const {
    L2tpXrayCandidateService,
} = require('../services/l2tpXrayCandidateService');

function safePlan(overrides = {}) {
    return {
        ok: true,
        operationId: 'operation-17',
        relayId: 'relay-1',
        routeGroupId: 'route-group-a',
        selectedPathKey: 'primary',
        nextHopNodeId: 'bridge-1',
        desired: { tproxyPort: 12345 },
        ...overrides,
    };
}

function xrayNode(overrides = {}) {
    return {
        _id: 'relay-1',
        type: 'xray',
        active: true,
        cascadeRole: 'relay',
        ip: '198.51.100.10',
        port: 443,
        xray: {
            apiPort: 61000,
            inboundTag: 'vless-in',
            transport: 'tcp',
            security: 'none',
        },
        outbounds: [],
        aclRules: [],
        ...overrides,
    };
}

const users = [{
    xrayUuid: '00000000-0000-4000-8000-000000000001',
    userId: 'test-user',
}];

test('passes one canonical L2TP fragment through the injected generator hook', async () => {
    const node = xrayNode();
    const calls = [];
    const service = new L2tpXrayCandidateService({
        async nodeResolver(request) {
            calls.push({ dependency: 'nodeResolver', request });
            return node;
        },
        async userResolver(resolvedNode) {
            calls.push({ dependency: 'userResolver', node: resolvedNode });
            return users;
        },
        configGenerator(resolvedNode, resolvedUsers, options) {
            calls.push({
                dependency: 'configGenerator',
                node: resolvedNode,
                users: resolvedUsers,
                options,
            });
            const [fragment] = options.fragments;
            return {
                inbounds: [...fragment.inbounds],
                outbounds: [
                    { tag: 'block', protocol: 'blackhole' },
                    { tag: 'cascade-primary', protocol: 'socks' },
                ],
                routing: { rules: [...fragment.routingRules] },
            };
        },
    });

    const candidate = await service.buildCandidate({ plan: safePlan() });

    assert.deepEqual(calls[0], {
        dependency: 'nodeResolver',
        request: { operationId: 'operation-17', nodeId: 'relay-1' },
    });
    assert.deepEqual(calls[1], { dependency: 'userResolver', node });
    assert.equal(calls[2].dependency, 'configGenerator');
    assert.strictEqual(calls[2].node, node);
    assert.strictEqual(calls[2].users, users);
    assert.equal(calls[2].options.fragments.length, 1);
    assert.deepEqual(calls[2].options.fragments[0], {
        id: 'relay-l2tp',
        inbounds: [{
            tag: 'relay-l2tp-route-group-a',
            listen: '0.0.0.0',
            port: 12345,
            protocol: 'dokodemo-door',
            settings: {
                network: 'tcp,udp',
                followRedirect: true,
            },
            streamSettings: { sockopt: { tproxy: 'tproxy' } },
        }],
        outbounds: [{
            tag: 'cascade-primary',
            protocol: 'socks',
            settings: {
                servers: [{
                    address: '127.0.0.1',
                    port: cascadePathIngressPort('route-group-a', 'primary'),
                }],
            },
        }],
        routingRules: [
            {
                type: 'field',
                inboundTag: ['relay-l2tp-route-group-a'],
                ip: ['geoip:private'],
                outboundTag: 'block',
            },
            {
                type: 'field',
                inboundTag: ['relay-l2tp-route-group-a'],
                ip: ['198.51.100.10'],
                outboundTag: 'block',
            },
            {
                type: 'field',
                inboundTag: ['relay-l2tp-route-group-a'],
                outboundTag: 'cascade-primary',
            },
        ],
    });
    assert.equal(candidate.operationId, 'operation-17');
    const parsed = JSON.parse(candidate.content);
    assert(parsed.inbounds.some(inbound => inbound.tag === 'relay-l2tp-route-group-a'));
    assert(parsed.routing.rules.some(rule => (
        rule.inboundTag?.includes('relay-l2tp-route-group-a')
        && rule.outboundTag === 'cascade-primary'
    )));
});

test('uses the official generator output without post-generation JSON mutation', async () => {
    const generatorCalls = [];
    let generatedOutput;
    const service = new L2tpXrayCandidateService({
        nodeResolver: async () => xrayNode(),
        userResolver: async () => users,
        configGenerator(node, resolvedUsers, options) {
            generatorCalls.push(options);
            generatedOutput = generateXrayConfig(node, resolvedUsers, options);
            return generatedOutput;
        },
    });

    const candidate = await service.buildCandidate({ plan: safePlan() });
    const config = JSON.parse(candidate.content);

    assert.equal(candidate.content, generatedOutput);
    assert.equal(generatorCalls[0].fragments.length, 1);
    assert.equal(generatorCalls[0].fragments[0].id, 'relay-l2tp');
    assert.equal(
        config.inbounds.filter(inbound => inbound.tag === 'relay-l2tp-route-group-a').length,
        1,
    );
    const cascadeOutbound = config.outbounds.find(outbound => outbound.tag === 'cascade-primary');
    assert(cascadeOutbound, 'candidate carries the cascade-<pathKey> outbound without node.outbounds');
    assert.equal(cascadeOutbound.protocol, 'socks');
    assert.deepEqual(cascadeOutbound.settings.servers, [{
        address: '127.0.0.1',
        port: cascadePathIngressPort('route-group-a', 'primary'),
    }]);
    assert(config.routing.rules.some(rule => rule.outboundTag === 'cascade-primary'));
});

test('install candidate preserves live reverse/forward cascade and other L2TP sections while refreshing subscription UUIDs', async () => {
    const generator = require('../../../services/configGenerator');
    const node = xrayNode();
    const current = JSON.parse(generator.generateXrayConfigWithApi(node, [{ userId: 'old-user', xrayUuid: 'old-uuid' }]));
    const link = { _id: 'down0001', tunnelUuid: 'persisted-tunnel-uuid', tunnelPort: 10086, bridgeNode: { ip: '192.0.2.2' } };
    generator.applyReversePortal(current, [link], ['vless-in']);
    generator.applyForwardHopInbound(current, [{ ...link, _id: 'up000001' }]);
    const otherFragment = require('../services/l2tpXrayFragmentProvider').buildL2tpXrayFragment({
        plan: { relay: { controlPlaneIps: [node.ip] }, group: { id: 'other-group' }, paths: [{ pathKey: 'secondary', healthy: true, outboundTag: 'cascade-secondary' }], selectedPathKey: 'secondary' },
        tags: { inbound: 'relay-l2tp-other-group', blockOutbound: 'block' }, tproxyPort: 12346,
    });
    current.inbounds.push(...otherFragment.inbounds);
    current.outbounds.push(...otherFragment.outbounds);
    current.routing.rules.push(...otherFragment.routingRules);
    let resolved = false;
    const service = new L2tpXrayCandidateService({
        nodeResolver: async () => node,
        userResolver: async () => users,
        currentConfigResolver: async request => {
            assert.equal(request.node, node);
            assert.equal(request.plan.relayId, node._id);
            resolved = true;
            return JSON.stringify(current);
        },
        configGenerator: generator.generateXrayConfigWithApi,
    });
    const candidate = await service.buildCandidate({ plan: safePlan() });
    const config = JSON.parse(candidate.content);
    assert.deepEqual(config.reverse, current.reverse);
    assert.equal(resolved, true);
    assert.deepEqual(config.inbounds.find(row => row.tag === 'fwd-hop-up000001'), current.inbounds.find(row => row.tag === 'fwd-hop-up000001'));
    assert.equal(config.inbounds.find(row => row.tag === 'vless-in').settings.clients[0].id, users[0].xrayUuid);
    assert(config.inbounds.some(row => row.tag === 'relay-l2tp-other-group'));
    for (const tag of ['relay-l2tp-other-group', 'relay-l2tp-route-group-a']) {
        const privateIndex = config.routing.rules.findIndex(row => row.inboundTag?.includes(tag) && row.ip?.includes('geoip:private') && row.outboundTag === 'block');
        const selectedIndex = config.routing.rules.findIndex(row => row.inboundTag?.includes(tag) && row.outboundTag?.startsWith('cascade-'));
        assert(privateIndex >= 0 && privateIndex < selectedIndex, 'scoped private refusal precedes selected cascade egress');
    }
    assert(config.outbounds.some(row => row.tag === 'cascade-secondary'));
    assert(config.routing.rules.some(row => row.inboundTag?.includes('vless-in') && row.outboundTag?.startsWith('portal-')));
});

test('classic live-config read failure or malformed content refuses candidate without leaking raw errors', async () => {
    for (const currentConfigResolver of [
        async () => { throw new Error('private-credential'); },
        async () => 'not-json-private-credential',
        async () => ({}),
    ]) {
        const service = new L2tpXrayCandidateService({ nodeResolver: async () => xrayNode(), userResolver: async () => users, configGenerator: generateXrayConfig, currentConfigResolver });
        await assert.rejects(service.buildCandidate({ plan: safePlan() }), error => {
            assert.equal(error.code, 'CURRENT_XRAY_CONFIG_UNAVAILABLE');
            assert.doesNotMatch(JSON.stringify(error), /private-credential/);
            return true;
        });
    }
});

test('classic reinstall replaces only its own old L2TP rules rather than preserving the old selected path', async () => {
    const node = xrayNode();
    const oldPlan = safePlan({ selectedPathKey: 'old-path' });
    const oldService = new L2tpXrayCandidateService({ nodeResolver: async () => node, userResolver: async () => users, configGenerator: generateXrayConfig });
    const current = (await oldService.buildCandidate({ plan: oldPlan })).content;
    const service = new L2tpXrayCandidateService({ nodeResolver: async () => node, userResolver: async () => users, configGenerator: generateXrayConfig, currentConfigResolver: async () => current });
    const config = JSON.parse((await service.buildCandidate({ plan: safePlan() })).content);
    const selectedRules = config.routing.rules.filter(rule => rule.inboundTag?.includes('relay-l2tp-route-group-a') && rule.outboundTag?.startsWith('cascade-'));
    assert.deepEqual(selectedRules.map(rule => rule.outboundTag), ['cascade-primary']);
    assert.equal(config.inbounds.filter(row => row.tag === 'relay-l2tp-route-group-a').length, 1);
});

test('keeps building candidates when the node has unrelated operator outbounds', async () => {
    const node = xrayNode({
        outbounds: [{
            type: 'socks5',
            name: 'legacy-operator-outbound',
            addr: '127.0.0.1:1080',
        }],
    });
    const service = new L2tpXrayCandidateService({
        nodeResolver: async () => node,
        userResolver: async () => users,
        configGenerator: (resolvedNode, resolvedUsers, options) => (
            generateXrayConfig(resolvedNode, resolvedUsers, options)
        ),
    });

    const candidate = await service.buildCandidate({ plan: safePlan() });
    const config = JSON.parse(candidate.content);

    assert(config.outbounds.some(outbound => outbound.tag === 'legacy-operator-outbound'));
    assert(config.outbounds.some(outbound => outbound.tag === 'cascade-primary'));
});

test('fails closed when an operator outbound collides with the cascade path tag', async () => {
    const node = xrayNode({
        outbounds: [{
            type: 'socks5',
            name: 'cascade-primary',
            addr: '127.0.0.1:1080',
        }],
    });
    const service = new L2tpXrayCandidateService({
        nodeResolver: async () => node,
        userResolver: async () => users,
        configGenerator: (resolvedNode, resolvedUsers, options) => (
            generateXrayConfig(resolvedNode, resolvedUsers, options)
        ),
    });

    await assert.rejects(
        service.buildCandidate({ plan: safePlan() }),
        error => {
            assert.equal(error.name, 'L2tpXrayCandidateError');
            assert.equal(error.code, 'XRAY_CONFIG_GENERATION_FAILED');
            return true;
        },
    );
});

test('rejects missing or blocked selections before any resolver or generator', async () => {
    const invalidPlans = [
        null,
        safePlan({ ok: false, error: { code: 'NO_HEALTHY_PATH' } }),
        safePlan({ selectedPathKey: undefined }),
        safePlan({ nextHopNodeId: undefined }),
        safePlan({ routeGroupId: undefined }),
        safePlan({ desired: { tproxyPort: 0 } }),
    ];

    for (const plan of invalidPlans) {
        const calls = [];
        const service = new L2tpXrayCandidateService({
            nodeResolver: async () => { calls.push('node'); },
            userResolver: async () => { calls.push('users'); },
            configGenerator: () => { calls.push('generator'); },
        });

        await assert.rejects(
            service.buildCandidate({ plan }),
            error => {
                assert.equal(error.name, 'L2tpXrayCandidateError');
                assert.match(error.code, /^(?:INVALID_OPERATION_PLAN|BLOCKED_TOPOLOGY)$/);
                assert.equal(Object.hasOwn(error, 'plan'), false);
                return true;
            },
        );
        assert.deepEqual(calls, []);
    }
});

test('fails closed for missing nodes, wrong node types, resolver failures, and invalid configs', async () => {
    const secret = 'candidate-error-credential';
    const cases = [
        {
            expectedCode: 'NODE_NOT_FOUND',
            nodeResolver: async () => null,
            expectedCalls: ['node'],
        },
        {
            expectedCode: 'NODE_TYPE_NOT_XRAY',
            nodeResolver: async () => xrayNode({ type: 'hysteria' }),
            expectedCalls: ['node'],
        },
        {
            expectedCode: 'NODE_CONFIG_INVALID',
            nodeResolver: async () => xrayNode({ ip: null }),
            expectedCalls: ['node'],
        },
        {
            expectedCode: 'USER_RESOLUTION_FAILED',
            nodeResolver: async () => xrayNode(),
            userResolver: async () => { throw new Error(`user lookup ${secret}`); },
            expectedCalls: ['node', 'users'],
        },
        {
            expectedCode: 'XRAY_CONFIG_GENERATION_FAILED',
            nodeResolver: async () => xrayNode(),
            userResolver: async () => users,
            configGenerator: () => { throw new Error(`generator ${secret}`); },
            expectedCalls: ['node', 'users', 'generator'],
        },
        {
            expectedCode: 'INVALID_XRAY_CANDIDATE',
            nodeResolver: async () => xrayNode(),
            userResolver: async () => users,
            configGenerator: () => '{not-json',
            expectedCalls: ['node', 'users', 'generator'],
        },
    ];

    for (const testCase of cases) {
        const calls = [];
        const service = new L2tpXrayCandidateService({
            async nodeResolver(request) {
                calls.push('node');
                return testCase.nodeResolver(request);
            },
            async userResolver(node) {
                calls.push('users');
                return (testCase.userResolver || (async () => users))(node);
            },
            configGenerator(node, resolvedUsers, options) {
                calls.push('generator');
                return (testCase.configGenerator || (() => ({
                    inbounds: options.fragments[0].inbounds,
                    outbounds: [
                        { tag: 'block' },
                        { tag: 'cascade-primary' },
                    ],
                    routing: { rules: options.fragments[0].routingRules },
                })))(node, resolvedUsers, options);
            },
        });

        await assert.rejects(
            service.buildCandidate({ plan: safePlan() }),
            error => {
                assert.equal(error.name, 'L2tpXrayCandidateError');
                assert.equal(error.code, testCase.expectedCode);
                assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
                assert.equal(Object.hasOwn(error, 'cause'), false);
                return true;
            },
        );
        assert.deepEqual(calls, testCase.expectedCalls);
    }
});
