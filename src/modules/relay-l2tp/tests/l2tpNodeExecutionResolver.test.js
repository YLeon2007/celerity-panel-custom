'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpNodeExecutionResolver,
} = require('../services/l2tpNodeExecutionResolver');

const EXECUTION_SELECT = '_id name ip type active cascadeRole ssh.port ssh.username ssh.privateKey ssh.password';

function createHyNode(result) {
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
                            return result;
                        },
                    };
                },
            };
        },
    };
}

test('selects only relay SSH execution fields and constructs one secret-safe NodeSSH on resolve', async () => {
    const secret = 'encrypted-private-key-material';
    const node = {
        _id: 'relay-17',
        name: 'relay seventeen',
        ip: '192.0.2.17',
        type: 'xray',
        active: true,
        cascadeRole: 'relay',
        ssh: {
            port: 2222,
            username: 'celerity',
            privateKey: secret,
            password: 'unused-password-secret',
        },
    };
    const HyNode = createHyNode(node);
    const constructions = [];

    class FakeNodeSSH {
        constructor(executionNode) {
            this.node = executionNode;
            constructions.push(executionNode);
        }
    }

    const resolver = new L2tpNodeExecutionResolver({ HyNode, NodeSSH: FakeNodeSSH });

    assert.deepEqual(HyNode.calls, []);
    assert.deepEqual(constructions, []);

    const nodeSSH = await resolver.resolve('relay-17');

    assert.ok(nodeSSH instanceof FakeNodeSSH);
    assert.deepEqual(HyNode.calls, [
        { method: 'findById', nodeId: 'relay-17' },
        { method: 'select', fields: EXECUTION_SELECT },
        { method: 'lean' },
    ]);
    assert.equal(constructions.length, 1);
    assert.notStrictEqual(constructions[0], node);
    assert.equal(nodeSSH.node.ssh.port, 2222);
    assert.equal(nodeSSH.node.ssh.username, 'celerity');
    assert.equal(nodeSSH.node.ssh.privateKey, secret);
    assert.equal(nodeSSH.node.ssh.password, 'unused-password-secret');
    assert.equal(Object.prototype.propertyIsEnumerable.call(nodeSSH.node, 'ssh'), false);
    for (const field of ['port', 'username', 'privateKey', 'password']) {
        assert.equal(
            Object.prototype.propertyIsEnumerable.call(nodeSSH.node.ssh, field),
            false,
            field,
        );
    }
    assert.doesNotMatch(JSON.stringify({ resolver, nodeSSH }), /private-key|password-secret/);
});

test('rejects missing, inactive, and non-Xray-relay nodes before NodeSSH construction', async () => {
    const invalidNodes = [
        null,
        { _id: 'inactive', active: false, type: 'xray', cascadeRole: 'relay' },
        { _id: 'hysteria-relay', active: true, type: 'hysteria', cascadeRole: 'relay' },
        { _id: 'xray-portal', active: true, type: 'xray', cascadeRole: 'portal' },
    ];

    for (const node of invalidNodes) {
        const HyNode = createHyNode(node);
        let constructions = 0;
        class FakeNodeSSH {
            constructor() {
                constructions += 1;
            }
        }
        const resolver = new L2tpNodeExecutionResolver({ HyNode, NodeSSH: FakeNodeSSH });

        await assert.rejects(
            resolver.resolve(node?._id || 'missing-node'),
            error => {
                assert.equal(error.name, 'L2tpNodeExecutionResolverError');
                assert.equal(error.code, 'NODE_EXECUTION_UNAVAILABLE');
                assert.equal(error.message, 'Node execution is unavailable');
                assert.equal(Object.hasOwn(error, 'nodeId'), false);
                assert.equal(Object.hasOwn(error, 'cause'), false);
                return true;
            },
        );
        assert.equal(constructions, 0);
    }
});
