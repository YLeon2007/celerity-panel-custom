'use strict';
// Actual public transfer -> default host/HTTP queue -> coordinator/worker/
// finalizer -> selected reader. Persistence and physical authority are MODELED.
// No manual operation binding, terminal statuses or next-raw-profile injection.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { fixture, app, request, settleTick, id, sha, copy, context, provider } = require('./cascadeAnyOrderRuntimeFixture');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const generator = require('../../../services/configGenerator');
test.after(() => require('../../../services/sshPoolService').closeAll());
async function adoptedFixture() {
    const f = fixture({ roles: ['portal', 'relay', 'bridge', 'bridge'] });
    for (const node of f.data.HyNode) node.xray = { security: 'none', transport: 'tcp', inboundTag: 'client-in', extraInbounds: [] };
    const nodes = f.data.HyNode.slice(0, 3).map(({ _id, cascadeRole, ...rest }) => ({ ...copy(rest), id: _id, role: cascadeRole }));
    const links = nodes.slice(1).map((node, index) => ({ id: id(index + 10), source: nodes[index].id, target: node.id,
        mode: 'reverse', active: true, tunnelPort: 25000 + index, tunnelUuid: `${index + 1}`.repeat(8) + '-1111-4111-8111-111111111111',
        tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelDomain: 'old-tunnel.invalid', priority: 1 }));
    const populated = links.map(link => ({ ...copy(link), _id: link.id,
        portalNode: { ...nodes.find(n => n.id === link.source), _id: link.source },
        bridgeNode: { ...nodes.find(n => n.id === link.target), _id: link.target } }));
    for (const node of nodes) {
        let config;
        if (node.role === 'portal') {
            config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, []));
            config.inbounds.find(n => n.tag === 'client-in').settings.clients.push({ id: '88888888-8888-4888-8888-888888888888', email: 'kept@invalid' });
            generator.applyReversePortal(config, populated.filter(link => link.source === node.id), ['client-in']);
        } else if (node.role === 'relay') config = JSON.parse(generator.generateRelayConfig(populated[0], populated[0].portalNode, [populated[1]]));
        else config = JSON.parse(generator.generateCombinedBridgeConfig([populated[1]]));
        config.inbounds ||= [];
        config.inbounds.push({ tag: 'unrelated-client', port: 27000, protocol: 'socks', settings: { auth: 'noauth', udp: false } });
        config.outbounds.push({ tag: 'unrelated-out', protocol: 'blackhole' });
        config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-client'], outboundTag: 'unrelated-out' });
        node.profileConfig = JSON.stringify(config, null, 2) + '\n';
    }
    const topology = { nodes, links, groups: [] };
    f.data.CascadeLink.push(...links.map(({ id, source, target, ...rest }) => ({ ...copy(rest), _id: id, portalNode: source, bridgeNode: target, status: 'online', name: id })));
    f.data.RelayL2tpState.push({ node: id(2), status: 'not_installed', desiredState: 'absent', secretRevision: 0 });
    f.data.TopologyConfigOwner.length = 0;
    const physical = new Map(f.data.HyNode.map(node => [node._id, nodes.find(n => n.id === node._id)?.profileConfig || '{}\n']));
    const Model = f.models.TopologyConfigOwner;
    Model.collection = { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] };
    const create = Model.create.bind(Model);
    Model.create = (docs, options = {}) => options.session ? create(docs, options) : Model.db.transaction(session => create(docs, { ...options, session }));
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Model,
        withVerifiedMaintenance: async ({ binding }, work) => work({ status: 'verified', authority: 'external-maintenance-v1', binding: copy(binding),
            proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
            oldBackend: { instanceId: 'modeled-classic', pid: 42, processStartTime: 'modeled-start', processTree: 'stopped', dispatch: 'disabled' },
            readback: { source: 'node-readback', configSha256: sha(physical.get(binding.node)), unitSha256: sha('unit'), serviceActive: 'active', serviceEnabled: 'enabled' } }) });
    for (const [index, node] of f.data.HyNode.entries()) {
        const classic = await transfer.initializeClassic({ node: node._id, profile: node.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge',
            nodeIdentity: { machineId: String(index + 1).repeat(32), sshHostKeySha256: String(index + 1).repeat(64) } });
        await transfer.adopt({ node: node._id, profile: classic.profile, generation: classic.generation, proofRef: 'modeled-held-readback',
            ...(index < 3 ? { legacyTopology: topology } : {}) });
    }
    const host = f.host(); provider.installActiveHost(host); f.http = app(f); host.start();
    const runtime = f.deployments[0], executor = runtime.operationWorker.executor;
    const prepare = executor.prepare.bind(executor), commit = executor.commit.bind(executor);
    executor.prepare = async input => ({ ...await prepare(input), before: physical.get(String(input.node.node)) });
    executor.commit = async input => { await commit(input); physical.set(String(input.node.node), Buffer.from(input.node.candidate.bytes).toString('utf8')); return { ok: true }; };
    executor.verify = async input => { assert.equal(sha(physical.get(String(input.node.node))), input.node.candidateHash); return { ok: true }; };
    const read = async linkId => runtime.topologyRepository.readSelected({ snapshot: await runtime.topologyRepository.snapshotReader.readDraft(),
        scope: { kind: 'link.apply', linkId }, executionContext: context });
    async function drain(response) {
        assert.equal(response.status, 202, JSON.stringify(response.body));
        for (let i = 0; i < 8; i++) await settleTick(f);
        const job = f.data.TopologyCreateIntent.find(row => row._id === response.body.job.jobId);
        assert.equal(job.status, 'succeeded', JSON.stringify({ job, operations: f.data.TopologyOperation.map(op => ({ status: op.status, error: op.error })) }));
        const op = f.data.TopologyOperation.find(row => row._id === job.operationId);
        assert.equal(op.status, 'succeeded'); assert.equal(op.heldTopologyAdmission, false);
        assert.equal(f.data.NodeOperationLock.length, 0);
        return op;
    }
    const deploy = linkId => request(f.http, 'POST', '/topology/deploy', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision, linkId }, randomUUID()).then(drain);
    const remove = linkId => request(f.http, 'DELETE', `/links/${linkId}`, { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision }, randomUUID()).then(drain);
    return { ...f, topology, physical, runtime, transfer, read, deploy, remove, drain, close: async () => { provider.clearActiveHost(host); await host.stop(); } };
}
test('public classic adoption -> selected worker publication -> readNext -> delete-all/recreate retains current profiles and historical import', async () => {
    const f = await adoptedFixture();
    try {
        const original = copy(f.topology), imports = copy(f.data.TopologyConfigOwner.map(owner => owner.legacyAppliedTopology));
        assert.deepEqual((await f.read(id(10))).baselineTopology, original);
        const first = await f.deploy(id(10));
        const next = await f.read(id(11));
        for (const node of next.baselineTopology.nodes) assert.equal(node.profileConfig, f.physical.get(node.id), 'reader must publish actual committed/readback candidate, not original import');
        assert.notEqual(next.baselineTopology.nodes[1].profileConfig, original.nodes[1].profileConfig);
        assert.equal(first.nodes.every(node => node.state === 'committed'), true);
        await f.remove(id(11));
        await f.remove(id(10));
        assert.equal(f.data.CascadeLink.some(link => [id(10), id(11)].includes(link._id)), false);
        for (const link of original.links) {
            const response = await request(f.http, 'POST', '/links', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
                name: 'recreated', portalNodeId: link.source, bridgeNodeId: link.target, mode: link.mode, tunnelPort: link.tunnelPort, tunnelSecurity: 'none', autoDeploy: true }, randomUUID());
            await f.drain(response);
        }
        for (const [index, owner] of f.data.TopologyConfigOwner.entries()) assert.deepEqual(owner.legacyAppliedTopology, imports[index], 'historical handback evidence must never be rewritten');
        const portal = JSON.parse(f.physical.get(id(1)));
        assert.equal(portal.inbounds.find(n => n.tag === 'client-in').settings.clients[0].email, 'kept@invalid');
    } finally { await f.close(); }
});
test('settled endpoint cleanup supplies the detached profile on its next selected use', async () => {
    const f = await adoptedFixture();
    try {
        await f.deploy(id(10));
        const edit = await request(f.http, 'PUT', `/links/${id(11)}`, { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
            name: 'new endpoint', bridgeNodeId: id(4), autoDeploy: true }, randomUUID());
        const moved = await f.drain(edit);
        assert.ok(moved.nodes.some(node => node.node === id(3)), 'old endpoint is actually cleaned by worker');
        const saved = await request(f.http, 'POST', '/links', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
            name: 'reuse old endpoint', portalNodeId: id(2), bridgeNodeId: id(3), mode: 'reverse', tunnelPort: 25012, tunnelSecurity: 'none', autoDeploy: false }, randomUUID());
        assert.equal(saved.status, 201, JSON.stringify(saved.body));
        const selected = await f.read(saved.body.createdLinkId);
        assert.equal(selected.baselineTopology.nodes.find(node => node.id === id(3))?.profileConfig, f.physical.get(id(3)), 'detached cleanup candidate remains checked current profile evidence');
        await f.deploy(saved.body.createdLinkId);
        assert.ok(JSON.parse(f.physical.get(id(3))).inbounds.some(n => n.tag === 'unrelated-client'));
    } finally { await f.close(); }
});
module.exports = { adoptedFixture };
