'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createL2tpNodeTransportFactory,
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
