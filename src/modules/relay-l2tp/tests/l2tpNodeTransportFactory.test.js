'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createL2tpNodeTransportFactory,
    createL2tpNodeTransportResolver,
} = require('../services/l2tpNodeTransportFactory');

test('creates one typed transport from the operation node only when requested', () => {
    const constructions = [];
    const operation = {
        id: 'operation-a',
        node: { id: 'node-a' },
    };

    class FakeNodeTransport {
        constructor(dependencies) {
            this.kind = 'typed-node-transport';
            constructions.push({ kind: 'transport', dependencies, instance: this });
        }
    }

    const transportFactory = createL2tpNodeTransportFactory({
        nodeSSHFactory(node) {
            const nodeSSH = { kind: 'node-ssh', node };
            constructions.push({ kind: 'node-ssh', node, instance: nodeSSH });
            return nodeSSH;
        },
        NodeTransport: FakeNodeTransport,
    });

    assert.deepEqual(constructions, []);

    const transport = transportFactory(operation.node);

    assert.ok(transport instanceof FakeNodeTransport);
    assert.deepEqual(
        constructions.map(construction => construction.kind),
        ['node-ssh', 'transport'],
    );
    assert.strictEqual(constructions[0].node, operation.node);
    assert.strictEqual(constructions[1].dependencies.nodeSSH, constructions[0].instance);
});

test('lazily adapts an injected node execution resolver to a typed transport', async () => {
    const calls = [];
    const nodeSSH = { kind: 'node-ssh-private' };
    const nodeExecutionResolver = {
        async resolve(nodeId) {
            calls.push({ method: 'resolve', nodeId });
            return nodeSSH;
        },
    };
    class FakeNodeTransport {
        constructor(dependencies) {
            this.kind = 'typed-transport';
            calls.push({ method: 'construct', dependencies, instance: this });
        }
    }

    const resolveTransport = createL2tpNodeTransportResolver({
        nodeExecutionResolver,
        NodeTransport: FakeNodeTransport,
    });

    assert.deepEqual(calls, []);

    const transport = await resolveTransport({
        operationId: 'operation-adapter',
        nodeId: 'relay-adapter',
    });

    assert.ok(transport instanceof FakeNodeTransport);
    assert.deepEqual(calls.map(call => call.method), ['resolve', 'construct']);
    assert.equal(calls[0].nodeId, 'relay-adapter');
    assert.strictEqual(calls[1].dependencies.nodeSSH, nodeSSH);
});
