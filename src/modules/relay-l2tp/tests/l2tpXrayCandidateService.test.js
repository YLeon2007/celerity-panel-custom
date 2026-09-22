'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'test@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || '01234567890123456789012345678901';

const assert = require('node:assert/strict');
const test = require('node:test');

const { generateXrayConfig } = require('../../../services/configGenerator');
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
        outbounds: [{
            type: 'socks5',
            name: 'cascade-primary',
            addr: '127.0.0.1:1080',
        }],
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
        outbounds: [],
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
    assert(config.outbounds.some(outbound => outbound.tag === 'cascade-primary'));
    assert(config.routing.rules.some(rule => rule.outboundTag === 'cascade-primary'));
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
