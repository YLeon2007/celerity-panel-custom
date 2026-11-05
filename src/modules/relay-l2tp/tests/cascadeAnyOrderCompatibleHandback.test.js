'use strict';
// Public transfer/import -> real HTTP queue/default host/worker/typed executor/
// V2 settlement -> original restoration -> public handback -> ordinary Sync.
// Persistence, accepted enrollment/physical authority and ALL node IO are modeled.
// No manufactured terminal operations, Mongo, SSH, subprocess or physical probe.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');
const sift = require('sift').default;
const mongoose = require('mongoose');
const { fixture, app, request, settleTick, id, sha, copy, env, context, provider } = require('./cascadeAnyOrderRuntimeFixture');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
const { freeze, runnerRequest, v2Receipt, simulatedConnectionAuthority } = require('./helpers/topologyV2Fixture');
const { RECORD_KEYS } = require('../models/topologyExecutionBindingContract');
const generator = require('../../../services/configGenerator');
const MAIN = '/usr/local/etc/xray/config.json', BRIDGE = '/usr/local/etc/xray-bridge/config.json';
const profilePath = profile => profile === 'xray-main' ? MAIN : BRIDGE;
const key = (node, file) => `${node}:${file}`;
const user = { userId: 'preserved@invalid', xrayUuid: '88888888-8888-4888-8888-888888888888', enabled: true, nodes: [id(1)], groups: [] };
async function withEnv(work) {
    const prior = { ...process.env }; Object.assign(process.env, env);
    try { return await work(); } finally {
        for (const name of Object.keys(process.env)) if (!(name in prior)) delete process.env[name];
        Object.assign(process.env, prior);
    }
}
// Real Sync + ownership + classic generation fence; replace ONLY imported IO.
function classicCaller(f) {
    const root = path.resolve(__dirname, '../../../..'), loaded = new Map(), stubs = new Map(), events = [];
    const query = read => {
        let populate = [];
        const q = { select() { return q; }, session() { return q; }, read() { return q; }, readConcern() { return q; }, maxTimeMS() { return q; },
            populate(fields) { populate.push(...fields.split(' ')); return q; },
            async lean() {
                const result = copy(read());
                const fill = row => { for (const field of populate) if (row?.[field]) row[field] = copy(f.data.HyNode.find(node => node._id === String(row[field]))); return row; };
                return Array.isArray(result) ? result.map(fill) : fill(result);
            }, then(a, b) { return q.lean().then(a, b); } };
        return q;
    };
    const model = rows => ({ find: filter => query(() => rows.filter(sift(filter))), exists: filter => query(() => rows.find(sift(filter)) || null),
        async findOneAndUpdate(filter, update) { const row = rows.find(sift(filter)), before = copy(row || null); await this.updateOne(filter, update); return before; },
        async updateOne(filter, update) {
            const row = rows.find(sift(filter));
            if (row) for (const [name, value] of Object.entries(update.$set || {})) {
                const parts = name.split('.'), field = parts.pop(); let parent = row;
                for (const part of parts) parent = parent[part] ||= {};
                parent[field] = copy(value);
            }
            return { matchedCount: row ? 1 : 0 };
        } });
    const stub = (file, value) => stubs.set(path.resolve(root, file), value);
    stub('config.js', { PANEL_DOMAIN: context.hostIdentity, ENCRYPTION_KEY: 'local-only' });
    stub('src/utils/logger.js', { info() {}, warn() {}, error() {}, debug() {} });
    stub('src/utils/helpers.js', { invalidateNodesCache: async () => {}, invalidateUserCache: async () => {} });
    stub('src/services/cacheService.js', { invalidateNodes: async () => {}, invalidateAllSubscriptions: async () => {}, invalidateDashboardCounts: async () => {} });
    stub('src/services/nodeSetup.js', { reloadCcAgent: async () => {} });
    stub('src/services/webhookService.js', { emit() {}, EVENTS: {} });
    stub('src/models/hyNodeModel.js', model(f.data.HyNode)); stub('src/models/hyUserModel.js', model([user]));
    stub('src/models/settingsModel.js', { get: async () => ({}) });
    stub('src/models/cascadeLinkModel.js', model(f.data.CascadeLink));
    stub('src/modules/relay-l2tp/models/cascadeRouteGroupModel.js', model([]));
    stub('src/modules/relay-l2tp/models/relayL2tpStateModel.js', model([]));
    stub('src/modules/relay-l2tp/models/topologyOperationModel.js', model(f.data.TopologyOperation));
    stub('src/modules/relay-l2tp/models/nodeOperationLockModel.js', f.models.NodeOperationLock);
    const native = { Types: mongoose.Types, connection: { db: { collection(name) {
        assert.equal(name, 'topologyconfigowners');
        return { find: filter => ({ toArray: async () => copy(f.data.TopologyConfigOwner.filter(row => row.node === String(filter.node))) }) };
    } } } };
    class SSH {
        constructor(node) { this.node = node; }
        async connect() { events.push(['connect', this.node._id]); }
        disconnect() {}
        async uploadContent(bytes, file) { events.push(['upload', this.node._id, file]); f.files.set(key(this.node._id, file), bytes); }
        async exec(command) { events.push(['exec', this.node._id, command]); return { code: 0, stdout: command.includes('command -v xray') ? '/usr/bin/xray\n' : '', stderr: '' }; }
    }
    stub('src/services/nodeSSH.js', SSH);
    const axios = async options => { events.push(['agent', options.url]); return { status: 200, data: {} }; };
    function load(filename) {
        if (stubs.has(filename)) return stubs.get(filename);
        if (loaded.has(filename)) return loaded.get(filename).exports;
        const mod = new Module(filename, module); mod.filename = filename; mod.paths = Module._nodeModulePaths(path.dirname(filename)); loaded.set(filename, mod);
        mod.require = name => {
            if (name === 'mongoose') return native;
            if (name === 'axios') return axios;
            const resolved = Module._resolveFilename(name, mod);
            if (stubs.has(resolved)) return stubs.get(resolved);
            if (resolved.startsWith(path.join(root, 'src/services/'))) return load(resolved);
            return Module.prototype.require.call(mod, name);
        };
        mod._compile(fs.readFileSync(filename, 'utf8'), filename); return mod.exports;
    }
    return { service: load(path.join(root, 'src/services/syncService.js')), events };
}
async function assembled() {
    const f = fixture({ roles: ['portal', 'bridge', 'portal', 'bridge'] });
    f.files = new Map(); f.units = new Map(); f.services = new Map();
    for (const node of f.data.HyNode) {
        node.name = 'modeled'; node.ssh = { password: 'local-dummy', port: 22, username: 'synthetic' };
        node.xray = { security: 'none', transport: 'tcp', inboundTag: 'client-in', extraInbounds: [], agentToken: 'local-dummy' };
    }
    const nodes = f.data.HyNode.slice(0, 2).map(({ _id, cascadeRole, ...rest }) => ({ ...copy(rest), id: _id, role: cascadeRole }));
    const link = { id: id(10), source: id(1), target: id(2), mode: 'reverse', active: true, tunnelPort: 25010,
        tunnelUuid: '11111111-1111-4111-8111-111111111111', tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelDomain: 'legacy.invalid', priority: 1 };
    const populated = { ...copy(link), _id: link.id, portalNode: { ...nodes[0], _id: id(1) }, bridgeNode: { ...nodes[1], _id: id(2) } };
    const portal = JSON.parse(generator.generateXrayConfig(f.data.HyNode[0], [user]));
    generator.applyReversePortal(portal, [populated], ['client-in']);
    nodes[0].profileConfig = JSON.stringify(portal);
    nodes[1].profileConfig = generator.generateCombinedBridgeConfig([populated]);
    f.data.CascadeLink.push({ ...copy(link), _id: link.id, portalNode: link.source, bridgeNode: link.target, status: 'online' });
    delete f.data.CascadeLink[0].id; delete f.data.CascadeLink[0].source; delete f.data.CascadeLink[0].target;
    const topology = { nodes, links: [link], groups: [] };
    for (const node of f.data.HyNode) {
        f.files.set(key(node._id, MAIN), nodes.find(row => row.id === node._id && row.role === 'portal')?.profileConfig || '{}');
        f.files.set(key(node._id, BRIDGE), nodes.find(row => row.id === node._id && row.role === 'bridge')?.profileConfig || '{}');
        f.units.set(node._id, `original-unit-${node._id}`); f.services.set(node._id, { serviceActive: 'active', serviceEnabled: 'enabled' });
    }
    const originals = { files: new Map(f.files), units: new Map(f.units), services: new Map(copy([...f.services])) };
    f.data.TopologyConfigOwner.length = 0;
    const Owner = f.models.TopologyConfigOwner;
    Owner.collection = { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] };
    const create = Owner.create.bind(Owner);
    Owner.create = (docs, options = {}) => options.session ? create(docs, options) : Owner.db.transaction(session => create(docs, { ...options, session }));
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Owner,
        withVerifiedMaintenance: async ({ binding }, work) => work({ binding: copy(binding), status: 'verified', authority: 'external-maintenance-v1',
            proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
            oldBackend: { instanceId: 'modeled-held', pid: 42, processStartTime: 'modeled-start', processTree: 'stopped', dispatch: 'disabled' },
            readback: { source: 'node-readback', configSha256: sha(f.files.get(key(binding.node, profilePath(binding.profile)))),
                unitSha256: sha(f.units.get(binding.node)), ...f.services.get(binding.node) } }) });
    for (const [i, node] of nodes.entries()) {
        const original = await transfer.initializeClassic({ node: node.id, profile: i === 0 ? 'xray-main' : 'xray-bridge',
            nodeIdentity: { machineId: `${i + 1}`.repeat(32), sshHostKeySha256: `${i + 1}`.repeat(64) } });
        await transfer.adopt({ node: node.id, profile: original.profile, generation: original.generation, proofRef: 'modeled-accepted-originals', legacyTopology: topology });
    }
    const db = Owner.db, commands = [];
    const transaction = db.transaction.bind(db);
    const client = { options: {}, topology: { description: { type: 'ReplicaSetWithPrimary' } }, db: () => ({ command: async () => ({ ok: 1 }) }) };
    db.transaction = work => transaction(session => { session.client = client; return work(session); });
    db.getClient = () => client;
    db.startSession = async () => ({ client, inTransaction: () => true, transaction: { transition() {} }, startTransaction() {}, async abortTransaction() {}, async endSession() {} });
    // Explicit modeled accepted enrollment; no real-store/physical provisioning
    // claim. Durable terminal rows are written ONLY by the actual finalizer.
    let held = 0;
    const reader = {
        async readVerified(expected) {
            const lock = f.data.NodeOperationLock.find(row => row.node === expected.nodeId && row.operationId === expected.operationId && row.generation === expected.generation);
            assert.ok(lock, 'binding authority starts only after the real worker acquires its generation');
            let row = f.data.TopologyExecutionBinding.find(row => row.nodeId === expected.nodeId && row.operationId === expected.operationId);
            if (!row) {
                const owner = f.data.TopologyConfigOwner.find(row => row.node === expected.nodeId);
                const enrollment = { _id: randomUUID(), nodeId: expected.nodeId, targetProfile: expected.targetProfile, executionContext: context.hostIdentity,
                    ownerGeneration: owner.generation, nodeIdentity: copy(owner.nodeIdentity), endpoint: { ip: `192.0.2.${Number.parseInt(expected.nodeId, 16)}`, port: 22, username: 'synthetic' },
                    bootId: randomUUID(), maintenanceId: randomUUID() };
                f.data.TopologyExecutionEnrollment.push(enrollment);
                row = { ...expected, ...enrollment, _id: randomUUID(), enrollmentId: enrollment._id, attemptId: randomUUID(), predecessorGeneration: 'none',
                    commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(command => [command, randomUUID()])) };
                f.data.TopologyExecutionBinding.push(row);
            }
            return freeze(copy(Object.fromEntries(RECORD_KEYS.map(key => [key, row[key]]))));
        },
        async withVerifiedBinding(expected, work) { held++; try { return await work(await this.readVerified(expected), async () => {}); } finally { held--; } },
        async readVerifiedConnection(expected, binding) { return simulatedConnectionAuthority(binding); },
    };
    const executor = new TopologyOperationExecutor({ ...context, executionBindingReader: reader,
        RunnerBootstrapper: class { async ensureRunner() { return { ok: true }; } },
        nodeExecutionResolver: { async resolve(input) { return { async writeFile() {}, async exec(command) {
            const request = runnerRequest(command); commands.push(request);
            if (['close', 'status'].includes(request.command)) assert.ok(held, 'terminal receipt remains inside the modeled held binding scope');
            const row = f.data.TopologyExecutionBinding.find(row => row.nodeId === request.nodeId && row.operationId === request.operationId);
            const node = f.data.TopologyOperation.find(op => op._id === request.operationId).nodes.find(node => node.node === request.nodeId);
            if (request.command === 'commit') f.files.set(key(request.nodeId, profilePath(request.targetProfile)), Buffer.from(node.candidate.bytes).toString());
            if (request.command === 'verify') assert.equal(sha(f.files.get(key(request.nodeId, profilePath(request.targetProfile)))), node.candidateHash);
            const terminal = ['close', 'status'].includes(request.command) ? { terminal: true, phase: 'closed', terminalOutcome: 'verified', completedCommand: 'close' } : {};
            return { code: 0, stderr: '', stdout: JSON.stringify(v2Receipt(request, { bootId: row.bootId, ...terminal })) + '\n' };
        } }; } } });
    const bg = classicCaller(f);
    const host = f.host({ createTopologyOperationExecutor: () => executor });
    const runtime = f.deployments[0];
    // Real Sync assignment/user producer through its local IO seams.
    runtime.operationWorker.userResync._syncService = bg.service;
    provider.installActiveHost(host); f.http = app(f); host.start();
    return Object.assign(f, { transfer, runtime, originals, bg, commands,
        async apply() {
            const response = await request(f.http, 'POST', '/topology/deploy', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision, linkId: id(10) }, randomUUID());
            assert.equal(response.status, 202, JSON.stringify(response.body));
            for (let i = 0; i < 8; i++) await settleTick(f);
            const job = f.data.TopologyCreateIntent.find(row => row._id === response.body.job.jobId);
            const operation = f.data.TopologyOperation.find(row => row._id === job.operationId);
            assert.equal(job.status, 'succeeded', JSON.stringify({ job, operation: operation && { status: operation.status, nodes: operation.nodes.map(node => ({ state: node.state })), v2Terminal: operation.v2Terminal } })); return operation;
        },
        async handback(owner) { return transfer.handback({ node: owner.node, profile: owner.profile, generation: owner.generation, proofRef: 'modeled-checked-original-restoration' }); },
        restore(owner) { f.files.set(key(owner.node, profilePath(owner.profile)), originals.files.get(key(owner.node, profilePath(owner.profile)))); f.units.set(owner.node, originals.units.get(owner.node)); f.services.set(owner.node, copy(originals.services.get(owner.node))); },
        async close() { provider.clearActiveHost(host); await host.stop(); assert.equal(f.timer.callbacks.size, 0); } });
}
test.after(() => require('../../../services/sshPoolService').closeAll());
test('settled native history survives checked original handback while ordinary classic Sync resumes', async () => withEnv(async () => {
    const f = await assembled();
    try {
        const descriptors = copy({ nodes: f.data.HyNode, links: f.data.CascadeLink }), owners = copy(f.data.TopologyConfigOwner);
        const users = copy(user);
        const independent = [...f.files].filter(([name]) => name.startsWith(`${id(3)}:`) || name.startsWith(`${id(4)}:`));
        const operation = await f.apply();
        assert.equal(operation.status, 'succeeded'); assert.equal(operation.heldTopologyAdmission, false);
        assert.equal(operation.v2Terminal.state, 'proven'); assert.ok(operation.v2Terminal.ownerFences.every(row => row.owner === 'topology'));
        assert.deepEqual(f.data.NodeOperationLock, []);
        assert.ok(f.commands.some(row => row.command === 'close')); assert.ok(f.commands.some(row => row.command === 'status'));
        const history = copy({ operations: f.data.TopologyOperation, bindings: f.data.TopologyExecutionBinding, enrollments: f.data.TopologyExecutionEnrollment, jobs: f.data.TopologyCreateIntent });
        assert.equal(await f.bg.service._topologyManagesNode(f.data.HyNode[0]), true);
        for (const owner of owners) {
            assert.notEqual(f.files.get(key(owner.node, profilePath(owner.profile))), f.originals.files.get(key(owner.node, profilePath(owner.profile))));
            await assert.rejects(f.handback(owner), { code: 'CONFIG_RESTORATION_MISMATCH' });
            f.restore(owner);
            const returned = await f.handback(owner);
            assert.equal(returned.owner, 'classic'); assert.notEqual(returned.generation, owner.generation);
            assert.deepEqual(returned.adoptionReceipt, owner.adoptionReceipt);
            assert.deepEqual(returned.originalSnapshot, owner.originalSnapshot);
            assert.equal(returned.lastSettledOperation, operation._id);
            await assert.rejects(f.handback(owner), { code: 'CONFIG_OWNERSHIP_CONFLICT' });
        }
        assert.deepEqual([...f.files], [...f.originals.files]); assert.deepEqual([...f.units], [...f.originals.units]); assert.deepEqual([...f.services], [...f.originals.services]);
        assert.deepEqual(f.data.CascadeLink.map(row => row.tunnelUuid), descriptors.links.map(row => row.tunnelUuid));
        assert.deepEqual(f.data.HyNode.map(row => row.cascadeRole), descriptors.nodes.map(row => row.cascadeRole));
        assert.equal(await f.bg.service._topologyManagesNode(f.data.HyNode[0]), false);
        assert.equal(await f.bg.service.updateXrayNodeConfig(f.data.HyNode[0]), true, JSON.stringify({ node: f.data.HyNode[0], events: f.bg.events }));
        assert.ok(f.bg.events.some(([kind, node]) => kind === 'upload' && node === id(1)), 'actual classic caller reaches modeled upload under its real shared generation');
        assert.deepEqual(f.data.NodeOperationLock, []);
        assert.deepEqual({ operations: f.data.TopologyOperation, bindings: f.data.TopologyExecutionBinding, enrollments: f.data.TopologyExecutionEnrollment, jobs: f.data.TopologyCreateIntent }, history);
        assert.deepEqual([...f.files].filter(([name]) => name.startsWith(`${id(3)}:`) || name.startsWith(`${id(4)}:`)), independent);
        assert.deepEqual(f.data.HyNode.slice(2), descriptors.nodes.slice(2));
        assert.deepEqual(f.data.HyNode.map(row => ({ ssh: row.ssh, token: row.xray.agentToken })),
            descriptors.nodes.map(row => ({ ssh: row.ssh, token: row.xray.agentToken })));
        assert.deepEqual(user, users);
        const portal = JSON.parse(f.files.get(key(id(1), MAIN)));
        assert.ok(portal.inbounds.find(row => row.tag === 'client-in').settings.clients.some(row => row.id === user.xrayUuid));
        const beforeDispatch = f.commands.length;
        await assert.rejects(f.runtime.topologyRepository.readSelected({ snapshot: await f.runtime.topologyRepository.snapshotReader.readDraft(),
            scope: { kind: 'link.apply', linkId: id(10) }, executionContext: context }), { code: 'TOPOLOGY_CONFIG_OWNER_REQUIRED' });
        const successor = await request(f.http, 'POST', '/topology/deploy', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision, linkId: id(10) }, randomUUID());
        assert.equal(successor.status, 500, JSON.stringify(successor.body));
        assert.equal(successor.body.error.code, 'INTERNAL_ERROR', JSON.stringify(successor.body));
        for (let i = 0; i < 8; i++) await settleTick(f);
        assert.equal(f.commands.length, beforeDispatch, 'old adopted generation cannot dispatch a successor after handback');
    } finally { await f.close(); }
}));
module.exports = { assembled, withEnv };
