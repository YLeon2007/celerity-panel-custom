'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { TopologyOperationExecutor, isTopologyTerminalProof } = require('../services/topologyOperationExecutor');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { compileTopology } = require('../domain/topologyCompiler');
const { fakeRunner } = require('./helpers/topologyTerminalFakeRunner');
const { executionFence, bindingReader, bindingRecord, freeze } = require('./helpers/topologyV2Fixture');

// Real executor -> real transport/factory -> actual fenced runner entry point.
// Only systemd, Xray and ss are modeled local commands, not physical evidence.
const profilePath = profile => `usr/local/etc/${profile === 'xray-main' ? 'xray' : 'xray-bridge'}/config.json`;
function nodePlan(content, checks = []) {
    const digest = createHash('sha256').update(content).digest('hex');
    return freeze({ node: 'p', nodeRef: 'portal', role: 'portal', targetProfile: 'xray-main',
        serviceUnit: 'xray.service', serviceUnitPath: '/etc/systemd/system/xray.service',
        configPath: '/usr/local/etc/xray/config.json', checks, candidateHash: digest,
        candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
            bytes: [...Buffer.from(content)], sha256: digest } });
}
function localExecution(t, initial = new Map()) {
    const roots = new Map();
    const dispatches = [];
    const faults = new Map();
    const getRoot = id => {
        if (!roots.has(id)) {
            const f = fakeRunner(t, 'boot-local-fixture');
            const state = initial.get(id) || {};
            f.put(profilePath('xray-main'), state['xray-main'] || '{"inbounds":[],"outbounds":[]}\n');
            f.put(profilePath('xray-bridge'), state['xray-bridge'] || '{"inbounds":[],"outbounds":[]}\n');
            f.put('usr/bin/ss', `#!/usr/bin/python3
import json, os, sys
root = os.environ['CELERITY_TOPOLOGY_ROOT']
with open(root + '/ss.log', 'a') as log:
    log.write(' '.join(sys.argv[1:]) + '\\n')
if os.path.exists(root + '/ss-fail'):
    raise SystemExit(1)
port = int(sys.argv[-1].split(':')[-1])
ports = set()
for profile in ('xray', 'xray-bridge'):
    with open(root + '/usr/local/etc/' + profile + '/config.json') as handle:
        config = json.load(handle)
    ports.update(item.get('port') for item in config.get('inbounds', []))
if os.path.exists(root + '/extra-listeners.json'):
    with open(root + '/extra-listeners.json') as handle:
        ports.update(json.load(handle))
if port in ports:
    print('LISTEN 0 128 0.0.0.0:' + str(port) + ' 0.0.0.0:*')
`, 0o700);
            roots.set(id, f);
        }
        return roots.get(id);
    };
    const read = (id, profile) => fs.readFileSync(path.join(getRoot(id).root, profilePath(profile)), 'utf8');
    const log = id => {
        const file = path.join(getRoot(id).root, 'systemctl.log');
        return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    };
    const heads = new Map();
    let sequence = 0;
    async function prepare(plan) {
        sequence++;
        const fence = freeze({ ...executionFence,
            generation: `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}` });
        const contexts = plan.nodes.map(node => freeze({ operationId: `cleanup-${sequence}`,
            topologyRevision: sequence, priorDeployedRevision: sequence - 1,
            executionFence: fence, node: freeze({ ...node, candidateHash: node.candidate.sha256 }) }));
        const records = contexts.map(context => freeze({ ...bindingRecord(context),
            predecessorGeneration: heads.get(context.node.node) || 'none',
            commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close']
                .map(command => [command, `${command}-${sequence}-${context.node.node}`])) }));
        const reader = bindingReader(records);
        reader.withVerifiedBinding = async (expected, work) => work(await reader.readVerified(expected), async () => {});
        class ModeledBootstrapper { async ensureRunner() {} }
        const executor = new TopologyOperationExecutor({ target: 'test', hostIdentity: 'test.infograd.online',
            executionBindingReader: reader, RunnerBootstrapper: ModeledBootstrapper,
            nodeExecutionResolver: { async resolve({ nodeId }) {
                const f = getRoot(nodeId);
                return { async exec(command, options) {
                    dispatches.push({ nodeId, command, options });
                    const result = f.execute(command, options);
                    const fault = faults.get(command.match(/--command (\S+)/)[1]);
                    return fault ? fault(result) : result;
                } };
            } } });
        const lifecycle = [];
        for (const context of contexts) {
            const result = await executor.prepare(context);
            lifecycle.push({ ...context, ...result });
            delete lifecycle.at(-1).ok;
        }
        return { executor, contexts: lifecycle, async finish() {
            for (const context of lifecycle) await executor.commit(context);
            for (const context of lifecycle) await executor.verify(context);
            const proofs = [];
            for (const context of lifecycle) {
                const proof = await executor.close(context);
                assert.equal(isTopologyTerminalProof(proof), true);
                assert.equal(proof.ownershipRetained, true);
                heads.set(context.node.node, fence.generation);
                proofs.push(proof);
            }
            return proofs;
        } };
    }
    return { roots, getRoot, read, log, dispatches, faults, prepare };
}

test('byte-identical checked baseline follows full terminal protocol without config replacement or restart', async t => {
    const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
    const node = nodePlan(content);
    const f = localExecution(t, new Map([['p', { 'xray-main': content }]]));
    const file = path.join(f.getRoot('p').root, profilePath(node.targetProfile));
    const before = fs.statSync(file);
    const run = await f.prepare({ nodes: [node] });
    const proofs = await run.finish();
    assert.equal(proofs[0].terminalOutcome, 'verified');
    assert.equal(fs.statSync(file).ino, before.ino, 'no-op must not replace the inode');
    assert.doesNotMatch(f.log('p'), /restart|stop/);
    assert.deepEqual(f.dispatches.map(({ command }) => command.match(/--command (\S+)/)[1]),
        ['prepare', 'commit', 'verify', 'close', 'status']);
});

function topology(mode = 'forward') {
    return { nodes: [['p', 'portal'], ['b', 'bridge']].map(([id, role], index) => ({
        id, role, type: 'xray', active: true, ip: `192.0.2.${index + 1}`, port: 24001 + index,
        xray: { inboundTag: `client-${id}`, transport: 'tcp', security: 'none', extraInbounds: [] },
    })), links: [{ id: 'pb', source: 'p', target: 'b', mode, tunnelPort: 12001,
        active: true, tunnelSecurity: 'none', tunnelTransport: 'tcp' }], groups: [] };
}
async function materialize(before, after, operationKind = 'link.delete') {
    const noReads = { find() { assert.fail('trusted descriptors must not hydrate mutable state'); } };
    return new TopologyOperationPlanMaterializer({ HyNode: noReads, CascadeLink: noReads }).materialize({
        target: 'test', hostIdentity: 'test.infograd.online', operationKind,
        pinnedSnapshot: { revision: 11, topology: after, compiled: compileTopology(after) },
        baselineTopology: before, effectiveTopology: after,
    });
}
const empty = () => ({ nodes: [], links: [], groups: [] });
async function appliedTopology(mode) {
    const graph = topology(mode);
    const plan = await materialize(empty(), graph, 'link.apply');
    for (const node of graph.nodes) node.profileConfig = JSON.parse(Buffer.from(plan.nodes.find(entry => entry.node === node.id).candidate.bytes));
    return { graph, plan, initial: new Map(plan.nodes.map(node => [node.node,
        { [node.targetProfile]: Buffer.from(node.candidate.bytes).toString() }])) };
}

test('forward deletion emits owned removed-port absence and executes config readback before terminal completion', async t => {
    const { graph, initial } = await appliedTopology('forward');
    const plan = await materialize(graph, empty());
    const listener = plan.nodes.find(node => node.node === 'b');
    assert.ok(listener.checks.some(check => check.type === 'port' && check.port === 12001 && check.expectedState === 'absent'));
    const f = localExecution(t, initial);
    const peer = f.read('b', 'xray-main');
    const proofs = await (await f.prepare(plan)).finish();
    assert.equal(proofs.length, 2);
    for (const node of plan.nodes) {
        const bytes = f.read(node.node, node.targetProfile);
        assert.equal(bytes, Buffer.from(node.candidate.bytes).toString(), 'actual target readback equals frozen candidate');
        assert.equal(bytes.includes('12001'), false, 'removed listener/dialer/config elements are gone');
        assert.doesNotMatch(f.log(node.node), /stop/);
    }
    assert.equal(f.read('b', 'xray-main'), peer, 'other profile is untouched');
    assert.match(fs.readFileSync(path.join(f.getRoot('b').root, 'ss.log'), 'utf8'), /sport = :12001/);
});

test('readback refuses changed other-profile ownership rather than calling socket absence complete cleanup', async t => {
    const { graph, initial } = await appliedTopology('forward');
    const plan = await materialize(graph, empty());
    const f = localExecution(t, initial);
    const run = await f.prepare(plan);
    const context = run.contexts.find(context => context.node.node === 'b');
    await run.executor.commit(context);
    f.getRoot('b').put(profilePath('xray-main'), '{"inbounds":[],"outbounds":[{"tag":"foreign-change"}]}\n');
    await assert.rejects(run.executor.verify(context), error => error.remoteOutcomeUncertain === true);
    await assert.rejects(run.executor.close(context));
    assert.match(f.read('b', 'xray-main'), /foreign-change/, 'no write/repair to the other profile');
});

test('rolling back a byte-identical prepared candidate also leaves the serving inode and service unchanged', async t => {
    const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
    const f = localExecution(t, new Map([['p', { 'xray-main': content }]]));
    const run = await f.prepare({ nodes: [nodePlan(content)] });
    const file = path.join(f.getRoot('p').root, profilePath('xray-main'));
    const before = fs.statSync(file).ino;
    await run.executor.commit(run.contexts[0]);
    await run.executor.rollback(run.contexts[0]);
    const proof = await run.executor.close(run.contexts[0]);
    assert.equal(proof.terminalOutcome, 'rolledback');
    assert.equal(fs.statSync(file).ino, before);
    assert.doesNotMatch(f.log('p'), /restart|stop/);
});

for (const mode of ['forward', 'reverse']) {
    for (const port of [12001, 12009]) {
        test(`${mode} delete-to-empty then recreate at ${port} uses exact serial terminal generations`, async t => {
            const { graph, initial } = await appliedTopology(mode);
            const f = localExecution(t, initial);
            const deletion = await materialize(graph, empty());
            await (await f.prepare(deletion)).finish();
            const baseline = { ...empty(), nodes: graph.nodes.map(node => ({ ...node,
                profileConfig: JSON.parse(f.read(node.id, node.role === 'portal' ? 'xray-main' : 'xray-bridge')) })) };
            const after = topology(mode);
            after.links[0].tunnelPort = port;
            const attach = await materialize(baseline, after, 'link.apply');
            await (await f.prepare(attach)).finish();
            const listener = mode === 'forward' ? 'b' : 'p';
            const listenerProfile = mode === 'forward' ? 'xray-bridge' : 'xray-main';
            assert.equal(JSON.parse(f.read(listener, listenerProfile)).inbounds.filter(inbound => inbound.port === port).length, 1);
            for (const node of attach.nodes) {
                assert.equal(f.read(node.node, node.targetProfile), Buffer.from(node.candidate.bytes).toString());
                assert.doesNotMatch(f.log(node.node), /stop/);
            }
        });
    }
}

for (const fault of ['foreign-listener', 'other-profile-listener', 'ss-unavailable', 'config-drift']) {
    test(`removed-port ${fault} is uncertain, keeps the runner fence and cannot close/rollback blindly`, async t => {
        const { graph, initial } = await appliedTopology('forward');
        if (fault === 'other-profile-listener') initial.get('b')['xray-main'] =
            '{"inbounds":[{"port":12001,"tag":"other-owner"}],"outbounds":[]}\n';
        const plan = await materialize(graph, empty());
        const f = localExecution(t, initial);
        const run = await f.prepare(plan);
        const context = run.contexts.find(context => context.node.node === 'b');
        const peerBefore = f.read('b', 'xray-main');
        await run.executor.commit(context);
        const root = f.getRoot('b');
        if (fault === 'foreign-listener') root.put('extra-listeners.json', '[12001]');
        if (fault === 'ss-unavailable') root.put('ss-fail', '1');
        if (fault === 'config-drift') root.put(profilePath('xray-bridge'), '{"inbounds":[],"outbounds":[{"tag":"stale-owned-dialer"}]}\n');
        await assert.rejects(run.executor.verify(context), error => error.remoteOutcomeUncertain === true);
        const calls = f.dispatches.length;
        await assert.rejects(run.executor.close(context));
        await assert.rejects(run.executor.rollback(context));
        assert.equal(f.dispatches.length, calls, 'uncertainty forbids further mutations');
        assert.equal(f.read('b', 'xray-main'), peerBefore);
        const journal = JSON.parse(fs.readFileSync(path.join(root.root, 'var/lib/celerity/topology/fences/xray-bridge/journal.json')));
        assert.equal(journal.generations[journal.head].phase, 'verify-running');
        assert.doesNotMatch(f.dispatches.map(entry => entry.command).join('\n'), /kill|fuser|pkill/);
    });
}

test('same owned port deliberately reused by replacement remains listening, not falsely absent', async t => {
    const { graph, initial } = await appliedTopology('forward');
    const after = topology('forward');
    after.links[0].id = 'replacement';
    const plan = await materialize(graph, after, 'link.replace');
    const listener = plan.nodes.find(node => node.node === 'b');
    assert.deepEqual(listener.checks.filter(check => check.type === 'port' && check.port === 12001),
        [{ type: 'port', protocol: 'tcp', port: 12001, expectedState: 'listening' }]);
    const f = localExecution(t, initial);
    await (await f.prepare(plan)).finish();
    const before = graph.nodes.find(node => node.id === 'b').profileConfig.inbounds.find(inbound => inbound.port === 12001);
    const current = JSON.parse(f.read('b', 'xray-bridge')).inbounds.find(inbound => inbound.port === 12001);
    assert.notEqual(current.tag, before.tag, 'old config identity removed despite retained socket');
    assert.equal(JSON.parse(f.read('b', 'xray-bridge')).inbounds.some(inbound => inbound.tag === before.tag), false);
});

test('disconnected unchanged peers preserve actual users, configs and services without restart', async t => {
    const graph = topology('forward');
    graph.nodes.push(...topology('reverse').nodes.map(node => ({ ...node, id: `peer-${node.id}`,
        xray: { ...node.xray, inboundTag: `peer-${node.xray.inboundTag}` } })));
    graph.links.push({ ...topology('reverse').links[0], id: 'peer-link', source: 'peer-p', target: 'peer-b', tunnelPort: 12002 });
    const installed = await materialize(empty(), graph, 'link.apply');
    for (const node of graph.nodes) {
        node.profileConfig = JSON.parse(Buffer.from(installed.nodes.find(entry => entry.node === node.id).candidate.bytes));
        if (node.id === 'peer-p') node.profileConfig.inbounds.find(inbound => inbound.tag.startsWith('peer-client-')).settings.clients
            .push({ email: 'existing-reality-user', id: '11111111-1111-4111-8111-111111111111' });
    }
    const baseline = structuredClone(graph);
    const after = structuredClone(graph);
    after.nodes = after.nodes.filter(node => node.id.startsWith('peer-'));
    after.links = after.links.filter(link => link.id === 'peer-link');
    const plan = await materialize(baseline, after);
    const initial = new Map(graph.nodes.map(node => [node.id, {
        [node.role === 'portal' ? 'xray-main' : 'xray-bridge']: `${JSON.stringify(node.profileConfig)}\n` } ]));
    const f = localExecution(t, initial);
    const peerBytes = new Map(['peer-p', 'peer-b'].map(id => [id,
        f.read(id, id === 'peer-p' ? 'xray-main' : 'xray-bridge')]));
    await (await f.prepare(plan)).finish();
    for (const [id, bytes] of peerBytes) {
        assert.equal(f.read(id, id === 'peer-p' ? 'xray-main' : 'xray-bridge'), bytes);
        assert.doesNotMatch(f.log(id), /restart|stop/);
    }
    assert.match(f.read('peer-p', 'xray-main'), /existing-reality-user/);
});

for (const baselineKind of ['different', 'identical']) {
    test(`checked ${baselineKind} baseline drift refuses activation before replacing live bytes`, async t => {
        const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
        const initial = baselineKind === 'identical' ? content : '{"inbounds":[],"outbounds":[{"tag":"old"}]}\n';
        const f = localExecution(t, new Map([['p', { 'xray-main': initial }]]));
        const run = await f.prepare({ nodes: [nodePlan(content)] });
        const drift = '{"inbounds":[],"outbounds":[{"tag":"new-owner"}]}\n';
        f.getRoot('p').put(profilePath('xray-main'), drift);
        await assert.rejects(run.executor.commit(run.contexts[0]), error => error.remoteOutcomeUncertain === true);
        assert.equal(f.read('p', 'xray-main'), drift);
        assert.doesNotMatch(f.log('p'), /restart|stop/);
    });
}

for (const fault of ['unowned', 'retained']) {
    test(`${fault} absent-port request cannot pretend an owned listener was removed`, async t => {
        const content = fault === 'retained'
            ? '{"inbounds":[{"port":12001,"tag":"kept"}],"outbounds":[],"routing":{"rules":[]}}\n'
            : '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
        const f = localExecution(t, new Map([['p', { 'xray-main': content }]]));
        const node = nodePlan(content, [{ type: 'port', protocol: 'tcp', port: 12001, expectedState: 'absent' }]);
        const run = await f.prepare({ nodes: [node] });
        await run.executor.commit(run.contexts[0]);
        await assert.rejects(run.executor.verify(run.contexts[0]), error => error.remoteOutcomeUncertain === true);
        assert.equal(fs.existsSync(path.join(f.getRoot('p').root, 'ss.log')), false, 'unowned probes rejected before host socket read');
    });
}

for (const fault of ['timeout', 'nonzero', 'malformed']) {
    test(`byte-identical ${fault} terminal response never bypasses owner evidence`, async t => {
        const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
        const f = localExecution(t, new Map([['p', { 'xray-main': content }]]));
        const run = await f.prepare({ nodes: [nodePlan(content)] });
        const context = run.contexts[0];
        await run.executor.commit(context);
        await run.executor.verify(context);
        f.faults.set('close', result => {
            if (fault === 'timeout') throw new Error('modeled lost close delivery');
            return fault === 'nonzero' ? { ...result, code: 1 } : { ...result, stdout: '{}\n' };
        });
        await assert.rejects(run.executor.close(context), error => error.remoteOutcomeUncertain === true);
        const dispatched = f.dispatches.length;
        await assert.rejects(run.executor.rollback(context));
        await assert.rejects(run.executor.close(context));
        assert.equal(f.dispatches.length, dispatched);
        assert.doesNotMatch(f.log('p'), /restart|stop/);
    });
}

const absent = { type: 'port', protocol: 'tcp', port: 12001, expectedState: 'absent' };
for (const [label, checks] of [
    ['zero port', [{ ...absent, port: 0 }]], ['too high port', [{ ...absent, port: 65536 }]],
    ['noninteger', [{ ...absent, port: '12001' }]], ['UDP', [{ ...absent, protocol: 'udp' }]],
    ['extra shell field', [{ ...absent, command: 'true' }]], ['unknown state', [{ ...absent, expectedState: 'closed' }]],
    ['service absence', [{ type: 'service', serviceUnit: 'xray.service', expectedState: 'absent' }]],
    ['excess checks', Array.from({ length: 65 }, () => ({ ...absent }))],
]) {
    test(`removed-listener schema refuses ${label} before transport`, async t => {
        const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
        const f = localExecution(t);
        await assert.rejects(f.prepare({ nodes: [nodePlan(content, checks)] }),
            error => error.code === 'INVALID_FROZEN_NODE_PLAN' && error.remoteOutcomeUncertain === false);
        assert.equal(f.dispatches.length, 0);
    });
}

test('blocked PPP ingress is retained and checked while only its retired tunnel listener must disappear', async t => {
    const graph = topology('reverse');
    graph.nodes[0].role = 'relay';
    graph.links[0].source = 'p';
    graph.groups = [{ _id: 'ppp-owner', mode: 'reverse', strategy: 'priority-failover',
        paths: [{ pathKey: 'mine', linkIds: ['pb'], enabled: true, priority: 0 }] }];
    const installed = await materialize(empty(), graph, 'link.apply');
    for (const node of graph.nodes) node.profileConfig = JSON.parse(Buffer.from(installed.nodes.find(entry => entry.node === node.id).candidate.bytes));
    const after = { ...empty(), groups: [{ ...graph.groups[0], paths: [{ ...graph.groups[0].paths[0], linkIds: [] }] }] };
    const plan = await materialize(graph, after);
    const relay = plan.nodes.find(node => node.node === 'p');
    const config = JSON.parse(Buffer.from(relay.candidate.bytes));
    const ingress = config.inbounds.find(inbound => inbound.tag === 'cascade-mine');
    assert.ok(ingress);
    assert.ok(relay.checks.some(check => check.port === ingress.port && check.expectedState === 'listening'));
    assert.ok(relay.checks.some(check => check.port === 12001 && check.expectedState === 'absent'));
    assert.ok(config.routing.rules.some(rule => rule.inboundTag?.includes(ingress.tag) && rule.outboundTag === 'block'));
    const initial = new Map(installed.nodes.map(node => [node.node, { [node.targetProfile]: Buffer.from(node.candidate.bytes).toString() }]));
    const f = localExecution(t, initial);
    await (await f.prepare(plan)).finish();
    assert.doesNotMatch(f.log('p'), /stop/);
});
