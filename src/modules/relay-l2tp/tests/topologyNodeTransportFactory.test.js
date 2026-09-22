'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');

const {
    TopologyNodeTransportFactory,
} = require('../services/topologyNodeTransportFactory');

const artifactContent = `${JSON.stringify({
    log: { loglevel: 'warning' },
    inbounds: [{
        tag: 'topology-in',
        listen: '127.0.0.1',
        port: 1080,
        protocol: 'socks',
        settings: { auth: 'noauth', udp: false },
    }],
    outbounds: [{ tag: 'direct', protocol: 'freedom', settings: {} }],
    routing: { rules: [] },
})}\n`;
const candidateHash = `sha256:${createHash('sha256').update(artifactContent).digest('hex')}`;

function receipt(command, plan) {
    return {
        ok: true,
        command,
        operationId: plan.operationId,
        nodeId: plan.nodeId,
        candidateHash: plan.candidateHash,
        backupId: plan.backupId,
        targetProfile: plan.targetProfile,
    };
}

function execResult(value) {
    return { code: 0, stdout: `${JSON.stringify(value)}\n`, stderr: '' };
}

test('creates a typed role-bound transport over only the fixed topology runner artifact facade', async () => {
    const resolverCalls = [];
    const execCalls = [];
    const nodeSecret = 'stored-node-private-key-secret';
    const nodeSSH = {
        node: { ssh: { privateKey: nodeSecret } },
        async exec(command, options) {
            execCalls.push({ command, options });
            const plan = {
                operationId: 'topology-operation-17',
                nodeId: 'portal-node',
                candidateHash,
                backupId: 'topology-backup-17-portal',
                targetProfile: 'xray-main',
            };
            return execResult(receipt('prepare', plan));
        },
    };
    const nodeExecutionResolver = {
        async resolve(request) {
            resolverCalls.push(request);
            return nodeSSH;
        },
    };
    const factory = new TopologyNodeTransportFactory({ nodeExecutionResolver });

    const transport = await factory.create({ nodeId: 'portal-node', role: 'portal' });
    const result = await transport.prepare({
        operationId: 'topology-operation-17',
        nodeId: 'portal-node',
        candidateHash,
        backupId: 'topology-backup-17-portal',
        targetProfile: 'xray-main',
        artifact: { id: 'xray-config', content: artifactContent },
    });

    assert.deepEqual(resolverCalls, [{ nodeId: 'portal-node', role: 'portal' }]);
    assert.deepEqual(execCalls, [{
        command: [
            '/usr/local/bin/celerity-topology-node-runner',
            '--command prepare',
            '--operation-id topology-operation-17',
            '--node-id portal-node',
            `--candidate-hash ${candidateHash}`,
            '--backup-id topology-backup-17-portal',
            '--target-profile xray-main',
        ].join(' '),
        options: { stdin: artifactContent },
    }]);
    assert.deepEqual(result, receipt('prepare', {
        operationId: 'topology-operation-17',
        nodeId: 'portal-node',
        candidateHash,
        backupId: 'topology-backup-17-portal',
        targetProfile: 'xray-main',
    }));
    assert.equal(transport.exec, undefined);
    assert.equal(transport.run, undefined);
    assert.deepEqual(Object.keys(transport), []);
    assert.doesNotMatch(JSON.stringify({ factory, transport }), /stored-node-private-key-secret|candidate-secret/);
});

test('binds node identity and role profile across every lifecycle command', async () => {
    const execCalls = [];
    const nodeSSH = {
        async exec(command, options) {
            execCalls.push({ command, options });
            const commandName = command.match(/--command ([a-z]+)/)?.[1];
            return execResult(receipt(commandName, {
                operationId: 'topology-operation-18',
                nodeId: 'relay-node',
                candidateHash,
                backupId: 'topology-backup-18-relay',
                targetProfile: 'xray-bridge',
            }));
        },
    };
    const factory = new TopologyNodeTransportFactory({
        nodeExecutionResolver: { resolve: async () => nodeSSH },
    });
    const transport = await factory.create({ nodeId: 'relay-node', role: 'relay' });
    const plan = {
        operationId: 'topology-operation-18',
        nodeId: 'relay-node',
        candidateHash,
        backupId: 'topology-backup-18-relay',
        targetProfile: 'xray-bridge',
    };

    await transport.prepare({
        ...plan,
        artifact: { id: 'xray-config', content: artifactContent },
    });
    for (const command of ['commit', 'verify', 'rollback']) {
        assert.deepEqual(await transport[command]({ ...plan }), receipt(command, plan));
    }

    assert.deepEqual(
        execCalls.map(call => ({
            command: call.command.match(/--command ([a-z]+)/)?.[1],
            nodeId: call.command.match(/--node-id ([A-Za-z0-9._-]+)/)?.[1],
            targetProfile: call.command.match(/--target-profile ([A-Za-z0-9._-]+)/)?.[1],
            options: call.options,
        })),
        [
            { command: 'prepare', nodeId: 'relay-node', targetProfile: 'xray-bridge', options: { stdin: artifactContent } },
            { command: 'commit', nodeId: 'relay-node', targetProfile: 'xray-bridge', options: undefined },
            { command: 'verify', nodeId: 'relay-node', targetProfile: 'xray-bridge', options: undefined },
            { command: 'rollback', nodeId: 'relay-node', targetProfile: 'xray-bridge', options: undefined },
        ],
    );

    for (const mismatch of [
        { ...plan, nodeId: 'bridge-node' },
        { ...plan, targetProfile: 'xray-main' },
    ]) {
        await assert.rejects(
            transport.commit(mismatch),
            error => error?.code === 'ARTIFACT_INVOCATION_FAILED',
        );
    }
    assert.equal(execCalls.length, 4);
});

test('rejects raw factory input, non-fixed runner calls, and missing NodeSSH without leaking details', async () => {
    const resolverCalls = [];
    const forbiddenRequests = [
        { nodeId: 'portal-node', role: { toString: () => 'portal' } },
        { nodeId: 'portal-node', role: 'portal', ip: '203.0.113.70' },
        { nodeId: 'portal-node', role: 'portal', ssh: { password: 'request-secret' } },
        { nodeId: 'portal-node', role: 'portal', command: 'id' },
        { nodeId: 'portal-node', role: 'portal', shell: 'sh -c id' },
        { nodeId: 'portal-node', role: 'portal', argv: ['id'] },
        { nodeId: 'portal-node', role: 'portal', env: { TOKEN: 'request-secret' } },
    ];
    const factory = new TopologyNodeTransportFactory({
        nodeExecutionResolver: {
            async resolve(request) {
                resolverCalls.push(request);
                return { exec: async () => null };
            },
        },
    });

    for (const request of forbiddenRequests) {
        await assert.rejects(factory.create(request), error => {
            assert.equal(error.name, 'TopologyNodeTransportFactoryError');
            assert.equal(error.code, 'TOPOLOGY_NODE_TRANSPORT_UNAVAILABLE');
            assert.equal(error.message, 'Topology node transport is unavailable');
            assert.doesNotMatch(JSON.stringify(error), /request-secret|203\.0\.113\.70|sh -c|\bid\b/);
            return true;
        });
    }
    assert.deepEqual(resolverCalls, []);

    for (const missingNodeSSH of [null, {}, { exec: null }]) {
        const unavailableFactory = new TopologyNodeTransportFactory({
            nodeExecutionResolver: { resolve: async () => missingNodeSSH },
        });
        await assert.rejects(
            unavailableFactory.create({ nodeId: 'bridge-node', role: 'bridge' }),
            error => error?.code === 'TOPOLOGY_NODE_TRANSPORT_UNAVAILABLE',
        );
    }

    let fixedFacade;
    let facadeExecCalls = 0;
    class CapturingTransport {
        constructor({ invokeArtifact }) {
            fixedFacade = invokeArtifact;
        }
    }
    const facadeFactory = new TopologyNodeTransportFactory({
        nodeExecutionResolver: {
            resolve: async () => ({
                async exec() {
                    facadeExecCalls += 1;
                    return { code: 0, stdout: '', stderr: '' };
                },
            }),
        },
        NodeTransport: CapturingTransport,
    });
    await facadeFactory.create({ nodeId: 'bridge-node', role: 'bridge' });
    await assert.rejects(
        fixedFacade('/tmp/request-runner', {
            command: 'commit',
            operationId: 'topology-operation-19',
            nodeId: 'bridge-node',
            candidateHash,
            backupId: 'topology-backup-19-bridge',
            targetProfile: 'xray-bridge',
        }),
        error => error?.code === 'TOPOLOGY_NODE_TRANSPORT_UNAVAILABLE',
    );
    assert.equal(facadeExecCalls, 0);

    await assert.rejects(
        fixedFacade('/usr/local/bin/celerity-topology-node-runner', {
            command: 'prepare',
            operationId: 'topology-operation-19',
            nodeId: 'bridge-node',
            candidateHash,
            backupId: 'topology-backup-19-bridge',
            targetProfile: 'xray-bridge',
            artifact: {
                id: 'xray-config',
                content: '{"different":"candidate"}\n',
            },
        }),
        error => error?.code === 'TOPOLOGY_NODE_TRANSPORT_UNAVAILABLE',
    );
    assert.equal(facadeExecCalls, 0);
});
