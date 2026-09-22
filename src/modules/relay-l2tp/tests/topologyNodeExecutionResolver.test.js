'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TOPOLOGY_NODE_EXECUTION_SELECT,
    TopologyNodeExecutionResolver,
} = require('../services/topologyNodeExecutionResolver');

const TEST_CONTOUR = Object.freeze({
    target: 'test',
    hostIdentity: 'test.infograd.online',
});

function createHyNode(nodes) {
    const calls = [];
    return {
        calls,
        findById(nodeId) {
            calls.push({ method: 'findById', nodeId });
            return {
                select(fields) {
                    calls.push({ method: 'select', fields });
                    return {
                        async lean() {
                            calls.push({ method: 'lean' });
                            return nodes.get(nodeId) ?? null;
                        },
                    };
                },
            };
        },
    };
}

function executionNode(nodeId, role) {
    return {
        _id: nodeId,
        name: `${role} node`,
        ip: `192.0.2.${role === 'portal' ? 10 : role === 'relay' ? 11 : 12}`,
        type: 'xray',
        active: true,
        cascadeRole: role,
        ssh: {
            port: 2222,
            username: 'celerity',
            privateKey: `${role}-private-key-secret`,
            password: `${role}-password-secret`,
        },
    };
}

test('resolves each test topology role from only allowlisted stored node connection fields', async () => {
    const nodes = new Map([
        ['portal-node', executionNode('portal-node', 'portal')],
        ['relay-node', executionNode('relay-node', 'relay')],
        ['bridge-node', executionNode('bridge-node', 'bridge')],
    ]);
    const HyNode = createHyNode(nodes);
    const constructions = [];
    class FakeNodeSSH {
        constructor(node) {
            this.node = node;
            constructions.push(node);
        }

        async exec() {
            return { code: 0, stdout: '', stderr: '' };
        }
    }
    const resolver = new TopologyNodeExecutionResolver({
        HyNode,
        NodeSSH: FakeNodeSSH,
        ...TEST_CONTOUR,
    });

    for (const role of ['portal', 'relay', 'bridge']) {
        const nodeSSH = await resolver.resolve({ nodeId: `${role}-node`, role });
        assert.ok(nodeSSH instanceof FakeNodeSSH);
        assert.equal(nodeSSH.node.cascadeRole, role);
        assert.equal(nodeSSH.node.ssh.username, 'celerity');
        assert.equal(Object.prototype.propertyIsEnumerable.call(nodeSSH.node, 'ssh'), false);
        for (const field of ['port', 'username', 'privateKey', 'password']) {
            assert.equal(
                Object.prototype.propertyIsEnumerable.call(nodeSSH.node.ssh, field),
                false,
                field,
            );
        }
    }

    assert.equal(
        TOPOLOGY_NODE_EXECUTION_SELECT,
        '_id name ip type active cascadeRole ssh.port ssh.username ssh.privateKey ssh.password',
    );
    assert.deepEqual(
        HyNode.calls.filter(call => call.method === 'select'),
        Array.from({ length: 3 }, () => ({
            method: 'select',
            fields: TOPOLOGY_NODE_EXECUTION_SELECT,
        })),
    );
    assert.equal(constructions.length, 3);
    assert.doesNotMatch(JSON.stringify({ resolver }), /private-key-secret|password-secret/);
});

test('refuses non-test contour identity before lookup with a sanitized error', async () => {
    const configurations = [
        { target: 'production', hostIdentity: 'test.infograd.online' },
        { target: 'staging', hostIdentity: 'test.infograd.online' },
        { target: 'test', hostIdentity: 'panel.infograd.online' },
        { target: 'test', hostIdentity: '' },
    ];

    for (const configuration of configurations) {
        const HyNode = createHyNode(new Map());
        class FakeNodeSSH {}
        const resolver = new TopologyNodeExecutionResolver({
            HyNode,
            NodeSSH: FakeNodeSSH,
            ...configuration,
        });

        await assert.rejects(
            resolver.resolve({ nodeId: 'portal-node', role: 'portal' }),
            error => {
                assert.equal(error.name, 'TopologyNodeExecutionResolverError');
                assert.equal(error.code, 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE');
                assert.equal(error.message, 'Topology node execution is unavailable');
                assert.equal(Object.hasOwn(error, 'target'), false);
                assert.equal(Object.hasOwn(error, 'hostIdentity'), false);
                return true;
            },
        );
        assert.deepEqual(HyNode.calls, []);
    }
});

test('rejects unknown roles, raw connection fields, and unusable stored nodes before NodeSSH use', async () => {
    const invalidNodes = [
        null,
        { ...executionNode('inactive-node', 'portal'), active: false },
        { ...executionNode('hysteria-node', 'portal'), type: 'hysteria' },
        executionNode('role-mismatch-node', 'bridge'),
        { ...executionNode('missing-ip-node', 'portal'), ip: '' },
        { ...executionNode('missing-user-node', 'portal'), ssh: { port: 22, username: '', password: 'secret' } },
        { ...executionNode('missing-port-node', 'portal'), ssh: { port: 0, username: 'root', password: 'secret' } },
        { ...executionNode('missing-credentials-node', 'portal'), ssh: { port: 22, username: 'root' } },
    ];

    for (const node of invalidNodes) {
        const nodeId = node?._id || 'missing-node';
        const HyNode = createHyNode(new Map([[nodeId, node]]));
        let constructions = 0;
        class FakeNodeSSH {
            constructor() {
                constructions += 1;
            }
        }
        const resolver = new TopologyNodeExecutionResolver({
            HyNode,
            NodeSSH: FakeNodeSSH,
            ...TEST_CONTOUR,
        });

        await assert.rejects(
            resolver.resolve({ nodeId, role: 'portal' }),
            error => error?.code === 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE',
        );
        assert.equal(constructions, 0);
    }

    const mismatchedHyNode = createHyNode(new Map([
        ['portal-node', executionNode('different-node', 'portal')],
    ]));
    let mismatchedConstructions = 0;
    class MismatchedNodeSSH {
        constructor() {
            mismatchedConstructions += 1;
        }
    }
    const mismatchedResolver = new TopologyNodeExecutionResolver({
        HyNode: mismatchedHyNode,
        NodeSSH: MismatchedNodeSSH,
        ...TEST_CONTOUR,
    });
    await assert.rejects(
        mismatchedResolver.resolve({ nodeId: 'portal-node', role: 'portal' }),
        error => error?.code === 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE',
    );
    assert.equal(mismatchedConstructions, 0);

    const forbiddenRequests = [
        { nodeId: 'portal-node', role: 'standalone' },
        { nodeId: 'portal-node', role: 'unknown' },
        { nodeId: 'portal-node', role: 'portal', ip: '203.0.113.10' },
        { nodeId: 'portal-node', role: 'portal', ssh: { password: 'request-secret' } },
        { nodeId: 'portal-node', role: 'portal', command: 'id' },
        { nodeId: 'portal-node', role: 'portal', shell: 'sh -c id' },
        { nodeId: 'portal-node', role: 'portal', argv: ['id'] },
        { nodeId: 'portal-node', role: 'portal', env: { TOKEN: 'request-secret' } },
    ];
    for (const request of forbiddenRequests) {
        const HyNode = createHyNode(new Map([
            ['portal-node', executionNode('portal-node', 'portal')],
        ]));
        const resolver = new TopologyNodeExecutionResolver({
            HyNode,
            NodeSSH: class FakeNodeSSH {},
            ...TEST_CONTOUR,
        });

        await assert.rejects(resolver.resolve(request), error => {
            assert.equal(error.code, 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE');
            assert.doesNotMatch(JSON.stringify(error), /request-secret|203\.0\.113\.10|sh -c|\bid\b/);
            return true;
        });
        assert.deepEqual(HyNode.calls, []);
    }
});
