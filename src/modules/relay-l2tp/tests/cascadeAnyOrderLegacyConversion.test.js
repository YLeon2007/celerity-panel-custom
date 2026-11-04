'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { fixture, id } = require('./cascadeAnyOrderLegacyImport.test');
const generator = require('../../../services/configGenerator');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
const { compileTopology } = require('../domain/topologyCompiler');
const { fakeRunner } = require('./helpers/topologyTerminalFakeRunner');
const { executionFence, bindingReader, bindingRecord, freeze } = require('./helpers/topologyV2Fixture');
const profilePath = profile => `usr/local/etc/${profile === 'xray-main' ? 'xray' : 'xray-bridge'}/config.json`;
const configOf = node => JSON.parse(Buffer.from(node.candidate.bytes));
const noReads = { find() { assert.fail('accepted descriptors must not hydrate desired metadata'); } };
async function materialize(before, after, operationKind = 'link.apply') {
    return new TopologyOperationPlanMaterializer({ HyNode: noReads, CascadeLink: noReads }).materialize({
        target: 'test', hostIdentity: 'test.infograd.online', operationKind,
        pinnedSnapshot: { revision: 7, topology: after, compiled: compileTopology(after) },
        baselineTopology: before, effectiveTopology: after,
    });
}
// Existing real executor/transport/runner, with explicit local persistence and
// systemd/Xray/socket command models. No public adoption/terminal authority is
// manufactured: the transfer fixture supplies simulated physical observations;
// bindingReader supplies simulated executor authority, not DB/physical proof.
function runner(t, topology) {
    const roots = new Map(), heads = new Map(); let sequence = 0;
    for (const node of topology.nodes) {
        const root = fakeRunner(t, 'boot-local-fixture'); roots.set(node.id, root);
        for (const profile of ['xray-main', 'xray-bridge']) root.put(profilePath(profile),
            profile === (node.role === 'portal' ? 'xray-main' : 'xray-bridge') ? node.profileConfig : '{"inbounds":[],"outbounds":[]}\n');
        root.put('usr/bin/ss', `#!/usr/bin/python3
import json, os, sys
root = os.environ['CELERITY_TOPOLOGY_ROOT']
port = int(sys.argv[-1].split(':')[-1])
for profile in ('xray', 'xray-bridge'):
    with open(root + '/usr/local/etc/' + profile + '/config.json') as handle:
        config = json.load(handle)
    if any(item.get('port') == port for item in config.get('inbounds', [])):
        print('LISTEN 0 128 0.0.0.0:' + str(port) + ' 0.0.0.0:*')
`, 0o700);
    }
    const read = (id, profile) => fs.readFileSync(path.join(roots.get(id).root, profilePath(profile)), 'utf8');
    return { read, roots, async apply(plan) {
        sequence++;
        const fence = freeze({ ...executionFence, generation: `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}` });
        const contexts = plan.nodes.map(node => freeze({ operationId: `conversion-${sequence}`, topologyRevision: sequence,
            priorDeployedRevision: sequence - 1, executionFence: fence, node: freeze({ ...node, candidateHash: node.candidate.sha256 }) }));
        const records = contexts.map(context => freeze({ ...bindingRecord(context),
            predecessorGeneration: heads.get(context.node.node) || 'none',
            commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close']
                .map(command => [command, `${command}-${sequence}-${context.node.node}`])) }));
        const reader = bindingReader(records);
        reader.withVerifiedBinding = async (expected, work) => work(await reader.readVerified(expected), async () => {});
        const executor = new TopologyOperationExecutor({ target: 'test', hostIdentity: 'test.infograd.online',
            executionBindingReader: reader, RunnerBootstrapper: class { async ensureRunner() {} },
            nodeExecutionResolver: { async resolve({ nodeId }) { return { async exec(command, options) { return roots.get(nodeId).execute(command, options); } }; } } });
        const prepared = [];
        for (const context of contexts) { const value = { ...context, ...await executor.prepare(context) }; delete value.ok; prepared.push(value); }
        for (const context of prepared) await executor.commit(context);
        for (const context of prepared) await executor.verify(context);
        for (const context of prepared) { await executor.close(context); heads.set(context.node.node, fence.generation); }
        for (const node of plan.nodes) assert.equal(read(node.node, node.targetProfile), Buffer.from(node.candidate.bytes).toString(), 'actual fake-root readback equals exact candidate bytes');
    } };
}
function regenerate(f, { single = false, reality = false } = {}) {
    if (reality) for (const link of f.topology.links) Object.assign(link, {
        tunnelSecurity: 'reality', realityPrivateKey: 'dummy-private-for-conversion', realityPublicKey: 'dummy-public-for-conversion',
        realityDest: 'decoy.invalid:443', realitySni: ['decoy.invalid'], realityShortIds: ['1234abcd'], realityFingerprint: 'chrome',
    });
    const nodes = f.topology.nodes;
    const populated = f.topology.links.map(link => ({ ...link, _id: link.id,
        portalNode: { ...nodes.find(n => n.id === link.source), _id: link.source },
        bridgeNode: { ...nodes.find(n => n.id === link.target), _id: link.target } }));
    for (const node of nodes) {
        const current = JSON.parse(node.profileConfig), incoming = populated.filter(link => link.target === node.id), outgoing = populated.filter(link => link.source === node.id);
        let config;
        if (node.role === 'portal') {
            config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, []));
            config.inbounds.find(inbound => inbound.tag === 'client-in').settings.clients = current.inbounds.find(inbound => inbound.tag === 'client-in').settings.clients;
            generator.applyReversePortal(config, outgoing, ['client-in']);
        } else if (node.role === 'relay') config = JSON.parse(generator.generateRelayConfig(incoming[0], incoming[0].portalNode, outgoing));
        else config = JSON.parse(single ? generator.generateBridgeConfig(incoming[0], incoming[0].portalNode) : generator.generateCombinedBridgeConfig(incoming));
        config.inbounds ||= [];
        config.inbounds.push(structuredClone(current.inbounds.find(inbound => inbound.tag === 'unrelated-client')));
        config.outbounds.push({ tag: 'unrelated-out', protocol: 'blackhole' });
        config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-client'], outboundTag: 'unrelated-out' });
        config.policy = structuredClone(current.policy);
        config.log = { loglevel: 'warning', access: '/dummy/retained.log' };
        node.profileConfig = JSON.stringify(config, null, 2) + '\n';
        f.physical.get(node.id).config = node.profileConfig;
        const desired = f.desiredLinks.find(row => row._id === outgoing[0]?.id);
        if (desired) Object.assign(desired, f.topology.links.find(link => link.id === desired._id));
    }
}
function assertPreserved(plan, originals, surviving) {
    const configs = new Map(plan.nodes.map(node => [node.node, configOf(node)]));
    for (const [nodeId, before] of originals) {
        const config = configs.get(nodeId);
        assert.deepEqual(config.policy, before.policy); assert.deepEqual(config.log, before.log);
        assert.deepEqual(config.inbounds.filter(inbound => inbound.tag === 'unrelated-client'), before.inbounds.filter(inbound => inbound.tag === 'unrelated-client'));
        assert.deepEqual(config.outbounds.filter(outbound => outbound.tag === 'unrelated-out'), before.outbounds.filter(outbound => outbound.tag === 'unrelated-out'));
        assert.deepEqual(config.routing.rules.filter(rule => rule.inboundTag?.includes('unrelated-client')), before.routing.rules.filter(rule => rule.inboundTag?.includes('unrelated-client')));
        if (before.inbounds.some(inbound => inbound.tag === 'client-in')) assert.deepEqual(config.inbounds.find(inbound => inbound.tag === 'client-in').settings.clients,
            before.inbounds.find(inbound => inbound.tag === 'client-in').settings.clients);
        assert.equal(new Set(config.inbounds.map(item => item.tag)).size, config.inbounds.length);
        assert.equal(config.inbounds.some(item => item.tag.startsWith('conn-down-')), false);
        assert.equal(config.outbounds.some(item => ['tunnel-up', 'tunnel'].includes(item.tag)), false);
        for (const [kind, endpoint, prefix] of [['portals', 'source', 'portal'], ['bridges', 'target', 'bridge']]) {
            const expected = surviving.filter(link => link[endpoint] === nodeId).map(link => ({
                tag: `${prefix}-${link.id.slice(-8)}`, domain: `${link.id.slice(-8)}.${link.tunnelDomain}` }));
            assert.deepEqual(config.reverse?.[kind] || [], expected, 'only the precise surviving reverse artifacts remain');
        }
    }
    for (const link of surviving) {
        const suffix = link.id.slice(-8), domain = `${suffix}.${link.tunnelDomain}`;
        const source = configs.get(link.source), target = configs.get(link.target);
        assert.ok(source.reverse.portals.some(item => item.domain === domain));
        assert.ok(target.reverse.bridges.some(item => item.domain === domain));
        const inbound = source.inbounds.find(item => item.port === link.tunnelPort);
        assert.equal(inbound.settings.clients[0].id, link.tunnelUuid);
        const tunnel = target.outbounds.find(item => item.tag === `tunnel-${suffix}`);
        assert.equal(tunnel.settings.vnext[0].users[0].id, link.tunnelUuid);
        for (const artifact of [inbound, tunnel]) {
            assert.equal(artifact.streamSettings.network, link.tunnelTransport);
            assert.equal(artifact.streamSettings.security, link.tunnelSecurity);
        }
        if (link.tunnelSecurity === 'reality') {
            assert.equal(inbound.streamSettings.realitySettings.privateKey, link.realityPrivateKey);
            assert.equal(tunnel.streamSettings.realitySettings.publicKey, link.realityPublicKey);
            assert.deepEqual(inbound.streamSettings.realitySettings.shortIds, link.realityShortIds);
        }
    }
}
for (const shape of ['combined', 'single', 'relay', 'shared']) for (const reality of [false, true]) {
    test(`classic ${shape}/${reality ? 'REALITY' : 'none'} public adoption -> materializer -> actual local runner apply/delete/recreate`, async t => {
        const f = fixture(undefined, { relay: shape === 'relay' });
        if (shape === 'shared') {
            const portal = { ...structuredClone(f.topology.nodes[0]), id: id(4), ip: '192.0.2.4' };
            const peer = { ...structuredClone(f.topology.links[0]), id: id(12), source: portal.id, tunnelPort: 25012,
                tunnelUuid: '33333333-3333-4333-8333-333333333333' };
            f.topology.nodes.push(portal); f.topology.links.push(peer);
            f.physical.set(portal.id, { config: portal.profileConfig, unit: 'dummy-peer-unit', active: 'active', enabled: 'enabled' });
            f.repository.snapshotReader.HyNode.rows.push({ ...portal, _id: portal.id, cascadeRole: portal.role });
            f.desiredLinks.push({ ...peer, _id: peer.id, portalNode: peer.source, bridgeNode: peer.target, status: 'online' });
        }
        regenerate(f, { reality, single: shape === 'single' });
        const saved = structuredClone(f.topology);
        for (const node of f.topology.nodes) await f.adopt(node);
        const selected = await f.read();
        assert.deepEqual(selected.baselineTopology, saved);
        const originals = new Map(saved.nodes.map(node => [node.id, JSON.parse(node.profileConfig)]));
        const execution = runner(t, saved);
        const peers = new Map(saved.nodes.map(node => [node.id, execution.read(node.id, node.role === 'portal' ? 'xray-bridge' : 'xray-main')]));
        let current = selected.effectiveTopology, plan = await materialize(selected.baselineTopology, current);
        assertPreserved(plan, originals, current.links);
        await execution.apply(plan);
        assert.deepEqual(f.topology, saved, 'raw imported inventory/digests are unchanged');
        assert.equal(f.Operation.rows.length, 0, 'local execution never forges a durable settled operation');
        // Feed the actual candidate readback into the next local transition.
        // Operational reader publication is separately owned, not simulated by
        // inventing lastSettledOperation pointers or adoption records here.
        const readback = topology => ({ ...structuredClone(topology), nodes: topology.nodes.map(node => ({ ...node,
            profileConfig: execution.read(node.id, node.role === 'portal' ? 'xray-main' : 'xray-bridge') })) });
        const restarts = () => [...execution.roots.values()].map(root => {
            const file = path.join(root.root, 'systemctl.log');
            return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(line => line.startsWith('restart ')).length : 0;
        });
        const beforeReplay = restarts();
        const replay = await materialize(readback(current), current);
        assert.deepEqual(replay.nodes.map(node => Buffer.from(node.candidate.bytes).toString()), plan.nodes.map(node => Buffer.from(node.candidate.bytes).toString()), 'repeat apply is exact byte no-op');
        await execution.apply(replay);
        assert.deepEqual(restarts(), beforeReplay, 'repeat apply must not restart the simulated service');
        for (const link of saved.links) {
            const after = { ...structuredClone(current), links: current.links.filter(item => item.id !== link.id) };
            plan = await materialize(readback(current), after, 'link.delete');
            assertPreserved(plan, originals, after.links);
            assert.equal(plan.nodes.flatMap(node => configOf(node).inbounds).some(inbound => inbound.port === link.tunnelPort), false);
            await execution.apply(plan); current = after;
        }
        // Recreate using original descriptors/credentials, without changing any
        // installed clients or private original transfer snapshots.
        plan = await materialize(readback(current), saved);
        await execution.apply(plan);
        for (const link of saved.links) {
            const listener = configOf(plan.nodes.find(node => node.node === link.source)).inbounds.find(inbound => inbound.port === link.tunnelPort);
            assert.equal(listener.settings.clients[0].id, link.tunnelUuid, 'recreate uses the exact accepted UUID');
            if (reality) assert.equal(listener.streamSettings.realitySettings.privateKey, link.realityPrivateKey);
        }
        for (const node of plan.nodes) {
            const config = configOf(node), before = originals.get(node.node);
            assert.deepEqual(config.inbounds.find(inbound => inbound.tag === 'unrelated-client'), before.inbounds.find(inbound => inbound.tag === 'unrelated-client'));
            if (before.inbounds.some(inbound => inbound.tag === 'client-in')) assert.deepEqual(
                config.inbounds.find(inbound => inbound.tag === 'client-in').settings.clients,
                before.inbounds.find(inbound => inbound.tag === 'client-in').settings.clients);
            assert.equal(execution.read(node.node, node.targetProfile === 'xray-main' ? 'xray-bridge' : 'xray-main'), peers.get(node.node));
        }
        for (const owner of f.Owner.rows) assert.deepEqual(owner.legacyAppliedTopology, saved);
    });
}

test('conversion normalizes absent bridge inbounds only in its private candidate copy', async () => {
    const f = fixture(), [portal, bridge] = f.topology.nodes;
    const populated = { ...f.topology.links[0], _id: f.topology.links[0].id, portalNode: { ...portal, _id: portal.id } };
    bridge.profileConfig = generator.generateCombinedBridgeConfig([populated]);
    assert.equal(JSON.parse(bridge.profileConfig).inbounds, undefined);
    f.physical.get(bridge.id).config = bridge.profileConfig;
    const originalBytes = bridge.profileConfig;
    for (const node of f.topology.nodes) await f.adopt(node);
    const selected = await f.read(), plan = await materialize(selected.baselineTopology, selected.effectiveTopology);
    assert.deepEqual(configOf(plan.nodes.find(node => node.node === bridge.id)).inbounds, []);
    assert.equal(bridge.profileConfig, originalBytes);
    assert.equal(f.Owner.rows.find(owner => owner.node === bridge.id).legacyAppliedTopology.nodes[1].profileConfig, originalBytes);
});

test('a failed exact classic dialer match cannot fall back to unchecked modern removal', async () => {
    const f = fixture();
    for (const node of f.topology.nodes) await f.adopt(node);
    const selected = await f.read(), before = structuredClone(selected.baselineTopology);
    const bridge = before.nodes[1], config = JSON.parse(bridge.profileConfig);
    config.outbounds.find(item => item.tag.startsWith('tunnel-')).settings.vnext[0].users[0].id = 'changed-unverified-uuid';
    bridge.profileConfig = JSON.stringify(config);
    await assert.rejects(materialize(before, selected.effectiveTopology), { code: 'TOPOLOGY_PROFILE_BASELINE_MISMATCH' });
});
