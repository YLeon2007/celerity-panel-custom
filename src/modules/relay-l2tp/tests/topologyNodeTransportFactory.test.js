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
const fencePlan = Object.freeze({ executionContext: 'test.infograd.online', attemptId: 'attempt-1', generation: 'generation-1', predecessorGeneration: 'none', commandId: 'command-1' });
const checks = Object.freeze([
    Object.freeze({
        type: 'service',
        serviceUnit: 'xray-bridge.service',
        expectedState: 'active',
    }),
    Object.freeze({
        type: 'port',
        protocol: 'tcp',
        port: 12001,
        expectedState: 'listening',
    }),
]);

function receipt(command, plan) {
    return {
        ok: true,
        command,
        ...fencePlan,
        operationId: plan.operationId,
        nodeId: plan.nodeId,
        candidateHash: plan.candidateHash,
        backupId: plan.backupId,
        targetProfile: plan.targetProfile,
        protocolVersion: 2, completion: 'completed', ownershipRetained: true, bootId: 'boot-1',
        phase: { prepare: 'prepared', commit: 'committed', verify: 'verified', rollback: 'rolledback', close: 'closed', status: 'closed' }[command],
        completedCommand: command === 'status' ? 'close' : command,
        terminal: ['close', 'status'].includes(command),
        terminalOutcome: ['close', 'status'].includes(command) ? 'verified' : 'not-terminal',
        systemdJob: command === 'prepare' ? 'not-applicable' : 'completed',
        serviceState: command === 'prepare' ? 'not-applicable' : 'active:running',
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
                ...fencePlan,
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
    const factory = new TopologyNodeTransportFactory({ executionContext: 'test.infograd.online', nodeExecutionResolver });

    const transport = await factory.create({ nodeId: 'portal-node', role: 'portal' });
    const result = await transport.prepare({
        ...fencePlan,
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
            '--execution-context test.infograd.online', '--attempt-id attempt-1',
            '--generation generation-1', '--predecessor-generation none', '--command-id command-1',
        ].join(' '),
        options: { stdin: artifactContent },
    }]);
    assert.deepEqual(result, receipt('prepare', {
        ...fencePlan,
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
                ...fencePlan,
                operationId: 'topology-operation-18',
                nodeId: 'relay-node',
                candidateHash,
                backupId: 'topology-backup-18-relay',
                targetProfile: 'xray-bridge',
            }));
        },
    };
    const factory = new TopologyNodeTransportFactory({ executionContext: 'test.infograd.online',
        nodeExecutionResolver: { resolve: async () => nodeSSH },
    });
    const transport = await factory.create({ nodeId: 'relay-node', role: 'relay' });
    const plan = {
        ...fencePlan,
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
        assert.deepEqual(await transport[command]({
            ...plan,
            ...(command === 'verify' ? { checks } : {}),
        }), receipt(command, plan));
    }

    assert.deepEqual(
        execCalls.map(call => ({
            command: call.command.match(/--command ([a-z]+)/)?.[1],
            nodeId: call.command.match(/--node-id ([A-Za-z0-9._-]+)/)?.[1],
            targetProfile: call.command.match(/--target-profile ([A-Za-z0-9._-]+)/)?.[1],
            checks: call.command.match(/--checks ([A-Za-z0-9_-]+)/)?.[1],
            options: call.options,
        })),
        [
            { command: 'prepare', nodeId: 'relay-node', targetProfile: 'xray-bridge', checks: undefined, options: { stdin: artifactContent } },
            { command: 'commit', nodeId: 'relay-node', targetProfile: 'xray-bridge', checks: undefined, options: undefined },
            {
                command: 'verify',
                nodeId: 'relay-node',
                targetProfile: 'xray-bridge',
                checks: Buffer.from(JSON.stringify(checks), 'utf8').toString('base64url'),
                options: undefined,
            },
            { command: 'rollback', nodeId: 'relay-node', targetProfile: 'xray-bridge', checks: undefined, options: undefined },
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

test('missing factory context refuses before resolver/bootstrap; bound context cannot be supplied by the plan', async () => {
    let resolves = 0, execs = 0;
    const nodeExecutionResolver = { resolve: async () => { resolves++; return { exec: async () => { execs++; } }; } };
    const unavailable = new TopologyNodeTransportFactory({ nodeExecutionResolver });
    await assert.rejects(unavailable.create({ nodeId: 'portal-node', role: 'portal' }), { code: 'TOPOLOGY_NODE_TRANSPORT_UNAVAILABLE' });
    assert.equal(resolves, 0);
    const factory = new TopologyNodeTransportFactory({ executionContext: 'test.infograd.online', nodeExecutionResolver });
    const transport = await factory.create({ nodeId: 'portal-node', role: 'portal' });
    await assert.rejects(transport.commit({ ...fencePlan, executionContext: 'lm1.infograd.online', operationId: 'operation-1', nodeId: 'portal-node', candidateHash, backupId: 'backup-1', targetProfile: 'xray-main' }), { code: 'ARTIFACT_INVOCATION_FAILED', ownershipRetained: true, remoteOutcomeUnknown: true });
    assert.equal(execs, 0);
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
    const factory = new TopologyNodeTransportFactory({ executionContext: 'test.infograd.online',
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
        const unavailableFactory = new TopologyNodeTransportFactory({ executionContext: 'test.infograd.online',
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
    const facadeFactory = new TopologyNodeTransportFactory({ executionContext: 'test.infograd.online',
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
            ...fencePlan,
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
            ...fencePlan,
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
