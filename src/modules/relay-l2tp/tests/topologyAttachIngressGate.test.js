'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { TopologyAttachIngressGate } = require('../services/topologyAttachIngressGate');
const { cascadePathIngressPort } = require('../domain/cascadePathIngress');

const port = cascadePathIngressPort('group', 'main');
const ingress = { tag: 'cascade-main', listen: '127.0.0.1', port, protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } };
const baseConfig = { inbounds: [{ tag: 'relay-l2tp-group', listen: '0.0.0.0', port: 12345, protocol: 'dokodemo-door', settings: { network: 'tcp,udp', followRedirect: true }, streamSettings: { sockopt: { tproxy: 'tproxy' } } }], outbounds: [{ tag: 'cascade-main', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port }] } }], routing: { rules: [{ type: 'field', inboundTag: ['relay-l2tp-group'], ip: ['geoip:private'], outboundTag: 'block' }, { type: 'field', inboundTag: ['relay-l2tp-group'], outboundTag: 'cascade-main' }] } };
function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}
function relayNode(config = { inbounds: [ingress], outbounds: [{ tag: 'downstream' }], routing: { rules: [{ type: 'field', inboundTag: ['cascade-main'], outboundTag: 'downstream' }] } }) {
    const content = `${JSON.stringify(canonicalize(config))}\n`;
    const hash = createHash('sha256').update(content).digest('hex');
    return { node: 'r1', nodeRef: 'relay-1', role: 'relay', targetProfile: 'xray-bridge', checks: [{ type: 'service', serviceUnit: 'xray-bridge.service', expectedState: 'active' }], state: 'pending', backupId: '', candidateHash: hash, candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes: [...Buffer.from(content)], sha256: hash } };
}
function fixture({ kind = 'link.attach', metadata = {}, node = relayNode(), gate, ppp = { async verifyPlan() { return { ok: true }; } } } = {}) {
    const events = [];
    const operation = { _id: 'operation-1', kind, groupId: 'group', pathKey: 'main', ownerNodeId: 'r1', topologyRevision: 7, priorDeployedRevision: 5, status: 'preparing', nodes: [node], ...metadata };
    const repository = {
        async claim() { events.push('claim'); return operation; },
        async renewLease() { return true; },
        async recordNode() { return true; },
        async setPhase() { return true; },
        async finishClaimed({ status }) { events.push(`finish:${status}`); return true; },
    };
    const executor = {
        async prepare() { events.push('prepare'); return { backupId: 'backup-1', prepared: {} }; },
        async commit() { events.push('commit'); return { ok: true }; },
        async verify() { events.push('verify'); return { ok: true }; },
        async rollback() { events.push('rollback'); return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; },
    };
    const worker = new TopologyOperationWorker({ operationRepository: repository, executor,
        finalizer: { async finalizeSucceeded() { events.push('finalize'); return { ok: true }; } },
        lockService: { async acquire() { return { ok: true, lock: { generation: 'g1' } }; }, async renew() { return { ok: true }; }, async releaseVerified() { return { ok: true }; }, async release() { return { ok: true }; } },
        workerId: 'worker', leaseMs: 30000, clock: { now: () => new Date('2026-09-29T00:00:00Z') },
        allowUnprovenTestExecution: true, pppReadinessGate: ppp, attachIngressGate: gate });
    return { worker, events };
}

test('verify-users-only cannot finalize attach without installed ingress proof', async () => {
    const { worker, events } = fixture();
    assert.equal((await worker.run('operation-1')).status, 'rolled_back');
    assert(events.includes('rollback'));
    assert(!events.includes('finalize'));
});

test('non-attach link.apply remains unchanged without an attach gate', async () => {
    const { worker, events } = fixture({ kind: 'link.apply' });
    assert.equal((await worker.run('operation-1')).status, 'succeeded');
    assert(events.includes('finalize'));
});

function probeFixture({ config = baseConfig, service = 'active\n', sshResult, sidecar = relayNode() } = {}) {
    const calls = [];
    const ssh = {
        async connect() { calls.push('connect'); },
        async exec(command, options) {
            calls.push(command);
            assert.equal(command, 'python3 -');
            assert.equal(options.timeout, 10000);
            assert(!options.stdin.includes('password'));
            if (sshResult) return sshResult;
            // Run the fixed readback locally with substituted read-only inputs.
            const setup = `import builtins, io, subprocess\nbuiltins.open = lambda *args, **kwargs: io.StringIO(${JSON.stringify(JSON.stringify(config))})\nsubprocess.run = lambda *args, **kwargs: type('Result', (), {'returncode': ${service === 'active\n' ? 0 : 3}, 'stdout': ${JSON.stringify(service)}, 'stderr': ''})()\n`;
            const result = spawnSync('python3', ['-'], { input: setup + options.stdin, encoding: 'utf8' });
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        },
        disconnect() { calls.push('disconnect'); },
    };
    const gate = new TopologyAttachIngressGate({ nodeExecutionResolver: { async resolve(input) {
        calls.push(input);
        return ssh;
    } } });
    const plan = { kind: 'link.attach', groupId: 'group', pathKey: 'main', ownerNodeId: 'r1', nodes: [sidecar] };
    return { gate, plan, calls };
}

test('matching installed main fragment, active service and candidate sidecar permit attach finalization', async () => {
    const { gate, plan, calls } = probeFixture();
    const { worker, events } = fixture({ gate });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: true });
    assert.equal((await worker.run('operation-1')).status, 'succeeded');
    assert(events.includes('finalize'));
    assert.deepEqual(calls.filter(call => typeof call === 'object'), [
        { nodeId: 'r1', role: 'relay' }, { nodeId: 'r1', role: 'relay' },
    ]);
});

test('reverse portal route is a valid attached ingress target', async () => {
    const sidecar = relayNode({
        inbounds: [ingress],
        outbounds: [],
        reverse: { portals: [{ tag: 'portal-downstream', domain: 'tunnel.internal' }] },
        routing: { rules: [{ type: 'field', inboundTag: ['cascade-main'], outboundTag: 'portal-downstream' }] },
    });
    const { gate, plan } = probeFixture({ sidecar });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: true });
});

test('reverse portal target must exist exactly once across reverse and ordinary outbounds', async () => {
    const make = (outbounds, portals) => relayNode({
        inbounds: [ingress], outbounds,
        reverse: { portals },
        routing: { rules: [{ type: 'field', inboundTag: ['cascade-main'], outboundTag: 'portal-downstream' }] },
    });
    for (const sidecar of [
        make([], []),
        make([], [{ tag: 'portal-downstream' }, { tag: 'portal-downstream' }]),
        make([{ tag: 'portal-downstream' }], [{ tag: 'portal-downstream' }]),
    ]) {
        const { gate, plan } = probeFixture({ sidecar });
        assert.deepEqual(await gate.verifyPlan(plan), { ok: false });
    }
});

test('wrong main port, routing, inactive service and ambiguous tags refuse attach', async () => {
    const variants = [
        { config: { ...baseConfig, outbounds: [{ ...baseConfig.outbounds[0], settings: { servers: [{ address: '127.0.0.1', port: port + 1 }] } }] } },
        { config: { ...baseConfig, routing: { rules: [{ type: 'field', inboundTag: ['relay-l2tp-group'], outboundTag: 'block' }] } } },
        { service: 'inactive\n' },
        { config: { ...baseConfig, inbounds: [...baseConfig.inbounds, baseConfig.inbounds[0]] } },
        { config: { ...baseConfig, inbounds: [{ ...baseConfig.inbounds[0], streamSettings: { sockopt: { tproxy: 'off' } } }] } },
        { config: { ...baseConfig, outbounds: [...baseConfig.outbounds, baseConfig.outbounds[0]] } },
        { sidecar: relayNode({ inbounds: [{ ...ingress, port: port + 1 }], outbounds: [{ tag: 'downstream' }], routing: { rules: [{ type: 'field', inboundTag: ['cascade-main'], outboundTag: 'downstream' }] } }) },
        { sshResult: { code: 1, stdout: '1\n', stderr: '' } },
        { sshResult: { code: 0, stdout: '1\nextra', stderr: '' } },
        { sshResult: { code: 0, stdout: '1\n', stderr: 'unexpected' } },
    ];
    for (const variant of variants) {
        const { gate, plan } = probeFixture(variant);
        assert.deepEqual(await gate.verifyPlan(plan), { ok: false }, JSON.stringify(variant));
        const { worker, events } = fixture({ gate, node: variant.sidecar ?? relayNode() });
        assert.equal((await worker.run('operation-1')).status, 'rolled_back');
        assert(!events.includes('finalize'));
    }
});

test('missing or inconsistent durable attach scope fails before executor dispatch', async () => {
    for (const metadata of [{ groupId: '' }, { pathKey: 'bad key' }, { ownerNodeId: 'other' }]) {
        const { worker, events } = fixture({ metadata });
        assert.equal((await worker.run('operation-1')).status, 'failed');
        assert(!events.includes('prepare'));
        assert(!events.includes('finalize'));
    }
});
