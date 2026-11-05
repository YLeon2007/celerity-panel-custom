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
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: syntheticContext } = require('../domain/topologyExecutionContext');
const { resolveL2tpExecutionAuthorization } = require('../domain/l2tpExecutionAuthorization');
const { freeze, runnerRequest, v2Receipt, simulatedConnectionAuthority } = require('./helpers/topologyV2Fixture');
const { RECORD_KEYS } = require('../models/topologyExecutionBindingContract');
const generator = require('../../../services/configGenerator');
const MAIN = '/usr/local/etc/xray/config.json', BRIDGE = '/usr/local/etc/xray-bridge/config.json';
const profilePath = profile => profile === 'xray-main' ? MAIN : BRIDGE;
const key = (node, file) => `${node}:${file}`;
const user = { userId: 'preserved@invalid', xrayUuid: '88888888-8888-4888-8888-888888888888', enabled: true, nodes: [id(1)], groups: [] };
// Canonical identity, but ONLY a synthetic local fixture: no deployed settings
// or production controller is loaded, changed or made available by these flags.
const syntheticEnv = Object.freeze({ PANEL_DOMAIN: syntheticContext.hostIdentity,
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    L2TP_PRODUCTION_EXECUTION_ENABLED: 'true', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'false' });
async function withEnv(work, deploymentEnv = env) {
    const prior = { ...process.env }; Object.assign(process.env, deploymentEnv);
    try { return await work(); } finally {
        for (const name of Object.keys(process.env)) if (!(name in prior)) delete process.env[name];
        Object.assign(process.env, prior);
    }
}
// Real Sync + ownership + classic generation fence; replace ONLY imported IO.
function classicCaller(f) {
    const root = path.resolve(__dirname, '../../../..'), loaded = new Map(), stubs = new Map(), events = [];
    const generations = [];
    function observe(kind, node) {
        if (!f.checkedClassicNode || node !== f.checkedClassicNode) return;
        assert.equal(resolveL2tpExecutionAuthorization(process.env).enableInstallAdmission, true, 'shared fence stays enabled');
        assert.equal(load(path.join(root, 'src/services/topologyConfigOwnership.js')).usesTestTopologyConfig(
            f.data.HyNode.find(row => row._id === node)), false, 'checked selector, never TEST compatibility');
        const lock = f.data.NodeOperationLock.find(row => row.node === node);
        assert.ok(lock && lock.owner === 'classic-config-writer' && lock.remoteUncertain === true, `${kind} holds actual classic generation`);
        if (!generations.length) generations.push(copy(lock));
        assert.deepEqual(lock, generations[0], `${kind} retains the SAME exact generation`);
        events.push(['held', node, kind, lock.generation]);
    }
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
    stub('config.js', { PANEL_DOMAIN: f.executionContext.hostIdentity, ENCRYPTION_KEY: 'local-only' });
    stub('src/utils/logger.js', Object.fromEntries(['info', 'warn', 'error', 'debug'].map(level => [level, (...args) => events.push(['log', level, ...args])])));
    stub('src/utils/helpers.js', { invalidateNodesCache: async () => {}, invalidateUserCache: async () => {} });
    stub('src/services/cacheService.js', { invalidateNodes: async () => {}, invalidateAllSubscriptions: async () => {}, invalidateDashboardCounts: async () => {} });
    stub('src/services/nodeSetup.js', { reloadCcAgent: async () => {} });
    stub('src/services/webhookService.js', { emit() {}, EVENTS: {} });
    stub('src/models/hyNodeModel.js', model(f.data.HyNode)); stub('src/models/hyUserModel.js', model(f.users));
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
        async connect() { observe('connect', this.node._id); events.push(['connect', this.node._id]); }
        disconnect() { observe('disconnect', this.node._id); }
        async uploadContent(bytes, file) {
            observe('upload', this.node._id);
            events.push(['upload', this.node._id, file]);
            if (f.onClassicUpload) await f.onClassicUpload(this.node, bytes, file);
            f.files.set(key(this.node._id, file), bytes);
        }
        async exec(command) {
            events.push(['exec', this.node._id, command]);
            const file = command.match(/cat (\/usr\/local\/etc\/xray(?:-bridge)?\/config\.json)/)?.[1];
            observe(file === MAIN ? 'MAIN read' : file === BRIDGE ? 'sidecar read' : 'exec', this.node._id);
            if (file && require('../domain/l2tpExecutionAuthorization').resolveL2tpExecutionAuthorization(process.env).enableInstallAdmission) {
                assert.ok(f.data.NodeOperationLock.some(row => row.node === this.node._id
                    && row.owner === 'classic-config-writer' && row.remoteUncertain), 'read restored bytes inside an enabled classic generation');
            }
            if (f.onClassicExec) {
                const result = await f.onClassicExec(this.node, command);
                if (result !== undefined) return result;
            }
            const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/)?.[0];
            const stdout = file ? f.files.get(key(this.node._id, file)) ?? 'C3_CLASSIC_PROFILE_ABSENT'
                : command.includes('command -v xray') ? '/usr/bin/xray\n' : '';
            return { code: 0, stdout: stdout + (receipt ? `\n${receipt}\n` : ''), stderr: '' };
        }
    }
    stub('src/services/nodeSSH.js', SSH);
    const axios = async options => {
        const url = new URL(options.url), node = f.data.HyNode.find(row => row.ip === url.hostname);
        assert.ok(node, 'agent IO stays inside declared modeled nodes');
        observe(`agent ${url.pathname}`, node._id);
        events.push(['agent', options.url]);
        if (f.onClassicAgent) {
            const result = await f.onClassicAgent(node, options);
            if (result !== undefined) return result;
        }
        return { status: 200, data: {} };
    };
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
    return { service: load(path.join(root, 'src/services/syncService.js')), events, generations };
}
async function assembled({ executionContext = context, deploymentEnv = env, transit = false } = {}) {
    const context = executionContext;
    const f = fixture({ roles: transit ? ['portal', 'relay', 'bridge', 'portal', 'bridge'] : ['portal', 'bridge', 'portal', 'bridge'],
        executionContext, deploymentEnv });
    f.users = [copy(user)];
    if (transit) f.users[0].nodes.push(id(2));
    f.files = new Map(); f.units = new Map(); f.services = new Map();
    for (const node of f.data.HyNode) {
        node.name = 'modeled'; node.ssh = { password: 'local-dummy', port: 22, username: 'synthetic' };
        node.xray = { security: 'none', transport: 'tcp', inboundTag: 'client-in', extraInbounds: [], agentToken: 'local-dummy' };
    }
    const nodes = f.data.HyNode.slice(0, transit ? 3 : 2).map(({ _id, cascadeRole, ...rest }) => ({ ...copy(rest), id: _id, role: cascadeRole }));
    const link = { id: id(10), source: id(1), target: id(2), mode: 'reverse', active: true, tunnelPort: 25010,
        tunnelUuid: '11111111-1111-4111-8111-111111111111', tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelDomain: 'legacy.invalid', priority: 1 };
    const populated = { ...copy(link), _id: link.id, portalNode: { ...nodes[0], _id: id(1) }, bridgeNode: { ...nodes[1], _id: id(2) } };
    const portal = JSON.parse(generator.generateXrayConfig(f.data.HyNode[0], f.users));
    generator.applyReversePortal(portal, [populated], ['client-in']);
    nodes[0].profileConfig = JSON.stringify(portal);
    const links = [link];
    if (transit) {
        const downstream = { ...copy(link), id: id(11), source: id(2), target: id(3), tunnelPort: 25011,
            tunnelUuid: '22222222-2222-4222-8222-222222222222' };
        links.push(downstream);
        const peer = { ...copy(downstream), _id: downstream.id,
            portalNode: { ...nodes[1], _id: id(2) }, bridgeNode: { ...nodes[2], _id: id(3) } };
        nodes[1].profileConfig = generator.generateRelayConfig(populated, populated.portalNode, [peer]);
        nodes[2].profileConfig = generator.generateCombinedBridgeConfig([peer]);
        f.data.RelayL2tpState.push({ node: id(2), status: 'not_installed', desiredState: 'absent', secretRevision: 0 });
    } else nodes[1].profileConfig = generator.generateCombinedBridgeConfig([populated]);
    f.data.CascadeLink.push({ ...copy(link), _id: link.id, portalNode: link.source, bridgeNode: link.target, status: 'online' });
    delete f.data.CascadeLink[0].id; delete f.data.CascadeLink[0].source; delete f.data.CascadeLink[0].target;
    for (const row of links.slice(1)) {
        const { id: linkId, source, target, ...rest } = row;
        f.data.CascadeLink.push({ ...copy(rest), _id: linkId, portalNode: source, bridgeNode: target, status: 'online' });
    }
    const topology = { nodes, links, groups: [] };
    for (const node of f.data.HyNode) {
        f.files.set(key(node._id, MAIN), nodes.find(row => row.id === node._id && row.role === 'portal')?.profileConfig
            || (transit ? generator.generateXrayConfig(node, f.users.filter(user => user.nodes.includes(node._id))) : '{}'));
        f.files.set(key(node._id, BRIDGE), nodes.find(row => row.id === node._id && row.role !== 'portal')?.profileConfig || '{}');
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
        const original = await transfer.initializeClassic({ node: node.id, profile: node.role === 'portal' ? 'xray-main' : 'xray-bridge',
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
    let bindingLifecycle;
    const reader = {
        executionContext: context,
        async reserveBinding(expected) { return this.readVerified(expected); },
        async readVerified(expected) {
            if (bindingLifecycle) await bindingLifecycle.assertHeld();
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
    let runtimeOverride = {};
    if (context.target === 'production') {
        // Existing trusted constructor seam: actual lifecycle + actual worker,
        // with ONLY its binding persistence/external hold modeled. Do not set
        // allowUnprovenTestExecution or replace run/claim/settlement/receipts.
        let externalHeld = false;
        bindingLifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: context,
            controller: { executionContext: context, async withHeldAuthority(selected, work) {
                assert.strictEqual(selected, context);
                assert.equal(externalHeld, false);
                externalHeld = true;
                try { return await work({ assertHeld: async () => assert.equal(externalHeld, true),
                    withVerifiedAuthority: async () => assert.fail('no physical/store attestation claimed by this modeled binding fixture') }); }
                finally { externalHeld = false; }
            } } });
        const entry = require('..');
        runtimeOverride = { moduleEntry: { ...entry, registerModels: () => f.models,
            createTopologyDeploymentService(options) {
                const service = entry.createTopologyDeploymentService({ ...options,
                    OperationWorker: function WorkerWithModeledPersistence(dependencies) {
                        return new TopologyOperationWorker({ ...dependencies, bindingProvisioner: reader, bindingLifecycle });
                    } });
                f.deployments.push(service); return service;
            } } };
    }
    const host = f.host({ createTopologyOperationExecutor: () => executor, ...runtimeOverride });
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
        // Also exercise ordinary checked-profile composition, not only the
        // historical TEST compatibility-status branch used above.
        process.env.TOPOLOGY_TEST_EXECUTION_ENABLED = 'false';
        assert.equal(require('../../../services/topologyConfigOwnership').usesTestTopologyConfig(f.data.HyNode[0]), false);
        assert.equal(await f.bg.service.updateXrayNodeConfig(f.data.HyNode[0]), true, JSON.stringify(f.bg.events));
        assert.ok(f.bg.events.some(([kind, node, command]) => kind === 'exec' && node === id(1)
            && command.includes('cat /usr/local/etc/xray/config.json')), 'new checked classic Sync actually reads the restored profile');
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
function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

async function joinedHandback() {
    const f = await assembled({ executionContext: syntheticContext, deploymentEnv: syntheticEnv, transit: true });
    try {
        assert.ok(f.runtime.operationWorker instanceof TopologyOperationWorker);
        assert.strictEqual(f.runtime.operationWorker.executionContext, syntheticContext);
        assert.equal(f.data.TopologyOperation.length, 0, 'public initialize/adopt fabricates no terminal history');
        const owners = copy(f.data.TopologyConfigOwner);
        const operation = await f.apply();
        assert.equal(operation.status, 'succeeded');
        assert.deepEqual(operation.executionContext, syntheticContext);
        assert.equal(operation.heldTopologyAdmission, false);
        assert.equal(operation.v2Terminal.state, 'proven');
        assert.equal(operation.v2Terminal.bindings.length, 3);
        assert.ok(operation.v2Terminal.ownerFences.every(row => row.owner === 'topology'));
        assert.deepEqual(f.data.NodeOperationLock, []);
        for (const owner of owners) {
            await assert.rejects(f.handback(owner), { code: 'CONFIG_RESTORATION_MISMATCH' });
            f.restore(owner);
            const returned = await f.handback(owner);
            assert.equal(returned.owner, 'classic');
            assert.notEqual(returned.generation, owner.generation);
            assert.deepEqual(returned.originalSnapshot, owner.originalSnapshot);
            assert.deepEqual(returned.adoptionReceipt, owner.adoptionReceipt);
            assert.deepEqual(returned.nodeIdentity, owner.nodeIdentity);
            assert.equal(returned.lastSettledOperation, operation._id);
            await assert.rejects(f.handback(owner), { code: 'CONFIG_OWNERSHIP_CONFLICT' });
        }
        assert.deepEqual([...f.files], [...f.originals.files]);
        assert.deepEqual([...f.units], [...f.originals.units]);
        assert.deepEqual([...f.services], [...f.originals.services]);
        f.checkedClassicNode = id(2);
        f.bg.events.length = 0;
        f.classicReleases = [];
        const deleteOne = f.models.NodeOperationLock.deleteOne.bind(f.models.NodeOperationLock);
        f.models.NodeOperationLock.deleteOne = async filter => {
            const lock = f.data.NodeOperationLock.find(row => row.node === f.checkedClassicNode);
            assert.deepEqual(filter, { node: lock.node, owner: lock.owner, operationId: lock.operationId,
                generation: lock.generation, remoteUncertain: true }, 'release uses the exact acquired generation predicate');
            f.classicReleases.push(copy(filter));
            return deleteOne(filter);
        };
        return f;
    } catch (error) { await f.close(); throw error; }
}

test('synthetic canonical non-TEST fixture leaves the ordinary production worker quiescence gate closed', async () => {
    const f = fixture({ executionContext: syntheticContext, deploymentEnv: syntheticEnv });
    const host = f.host();
    try {
        assert.deepEqual(await f.deployments[0].operationWorker.run(id(999)), {
            claimed: false, operationId: id(999), stopped: true, errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN' });
        assert.deepEqual(f.calls, []);
        assert.deepEqual(f.data.TopologyOperation, []);
        assert.deepEqual(f.data.NodeOperationLock, []);
    } finally { await host.stop(); }
});

test('public native handback reaches checked MAIN/sidecar Sync under ONE continuously enabled shared generation', { timeout: 10000 }, async () => withEnv(async () => {
    const f = await joinedHandback(), gates = ['MAIN read', 'sidecar read', 'upload', 'restart'].map(kind => ({ kind,
        entered: deferred(), release: deferred() }));
    let syncing;
    try {
        const node = f.data.HyNode[1], preserved = copy({ history: { operations: f.data.TopologyOperation,
            bindings: f.data.TopologyExecutionBinding, enrollments: f.data.TopologyExecutionEnrollment, jobs: f.data.TopologyCreateIntent },
            owners: f.data.TopologyConfigOwner, users: f.users, links: f.data.CascadeLink,
            credentials: f.data.HyNode.map(row => ({ ssh: row.ssh, xray: row.xray, role: row.cascadeRole })) });
        const files = new Map(f.files);
        assert.equal(await f.bg.service._topologyManagesNode(node), false);
        async function pause(kind) {
            const gate = gates.find(gate => gate.kind === kind);
            gate.entered.resolve(); await gate.release.promise;
        }
        f.onClassicExec = async (node, command) => {
            if (command.includes(`cat ${MAIN}`)) await pause('MAIN read');
            else if (command.includes(`cat ${BRIDGE}`)) await pause('sidecar read');
        };
        f.onClassicUpload = async () => pause('upload');
        f.onClassicAgent = async (node, options) => { if (new URL(options.url).pathname === '/restart') await pause('restart'); };
        let finished = false;
        syncing = f.bg.service.updateXrayNodeConfig(node).finally(() => { finished = true; });
        for (const gate of gates) {
            await gate.entered.promise;
            assert.equal(finished, false, `${gate.kind} completion is still pending`);
            assert.equal(resolveL2tpExecutionAuthorization(process.env).enableInstallAdmission, true);
            assert.deepEqual(f.data.NodeOperationLock, f.bg.generations, `${gate.kind} cannot release before checked completion`);
            assert.deepEqual(f.classicReleases, [], `${gate.kind} cannot attempt early release`);
            await assert.rejects(f.bg.service.updateXrayNodeConfig(node), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
            assert.deepEqual(f.data.NodeOperationLock, f.bg.generations);
            gate.release.resolve();
        }
        assert.equal(await syncing, true, JSON.stringify(f.bg.events));
        assert.equal(f.bg.generations.length, 1, 'actual lock, never a seeded owner or replacement generation');
        assert.deepEqual(f.data.NodeOperationLock, [], 'exact generation releases only after all real Sync steps report success');
        assert.equal(f.classicReleases.length, 1, 'one exact-generation release after checked success');
        const held = f.bg.events.filter(([kind]) => kind === 'held');
        for (const step of ['MAIN read', 'sidecar read', 'upload', 'agent /restart', 'agent /sync', 'agent /info']) {
            assert.ok(held.some(([, , kind]) => kind === step), `actual checked caller reaches ${step}`);
        }
        assert.deepEqual(new Set(held.map(([, , , generation]) => generation)), new Set([f.bg.generations[0].generation]));
        assert.deepEqual({ operations: f.data.TopologyOperation, bindings: f.data.TopologyExecutionBinding,
            enrollments: f.data.TopologyExecutionEnrollment, jobs: f.data.TopologyCreateIntent }, preserved.history);
        assert.deepEqual(f.data.TopologyConfigOwner, preserved.owners);
        assert.deepEqual(f.users, preserved.users);
        assert.deepEqual(f.data.CascadeLink, preserved.links);
        assert.deepEqual(f.data.HyNode.map(row => ({ ssh: row.ssh, xray: row.xray, role: row.cascadeRole })), preserved.credentials);
        for (const [name, bytes] of files) if (name !== key(node._id, MAIN)) assert.equal(f.files.get(name), bytes, `other profile/peer ${name}`);
        const main = JSON.parse(f.files.get(key(node._id, MAIN)));
        assert.ok(main.inbounds.find(row => row.tag === 'client-in').settings.clients.some(row => row.id === user.xrayUuid));
        assert.equal(main.inbounds.some(row => row.port === 25011), false, 'sidecar owns the downstream listener, not MAIN');
        assert.ok(JSON.parse(f.files.get(key(node._id, BRIDGE))).inbounds.some(row => row.port === 25011));
        const dispatched = f.commands.length;
        await assert.rejects(f.runtime.topologyRepository.readSelected({ snapshot: await f.runtime.topologyRepository.snapshotReader.readDraft(),
            scope: { kind: 'link.apply', linkId: id(10) }, executionContext: syntheticContext }), { code: 'TOPOLOGY_CONFIG_OWNER_REQUIRED' });
        assert.equal(f.commands.length, dispatched, 'handback does not authorize re-enrollment or successor dispatch');
    } finally { for (const gate of gates) gate.release.resolve(); if (syncing) await syncing.catch(() => {}); await f.close(); }
}, syntheticEnv));

for (const unknown of ['MAIN read', 'sidecar read', 'upload', 'restart']) {
    test(`joined checked handback Sync retains its exact generation after unknown ${unknown}`, async () => withEnv(async () => {
        const f = await joinedHandback();
        try {
            const node = f.data.HyNode[1], history = copy({ operations: f.data.TopologyOperation,
                bindings: f.data.TopologyExecutionBinding, enrollments: f.data.TopologyExecutionEnrollment,
                jobs: f.data.TopologyCreateIntent, owners: f.data.TopologyConfigOwner, users: f.users, links: f.data.CascadeLink });
            const files = new Map(f.files);
            let injected = false;
            if (unknown.endsWith('read')) f.onClassicExec = async (node, command) => {
                if (command.includes(`cat ${unknown === 'MAIN read' ? MAIN : BRIDGE}`)) {
                    injected = true;
                    return { code: null, stdout: '', stderr: '' }; // unconfirmed transport completion
                }
            };
            else if (unknown === 'upload') f.onClassicUpload = async (node, bytes, file) => {
                injected = true;
                // Delivery may have happened; losing acknowledgement must NOT
                // roll back bytes or authorize release of the shared generation.
                f.files.set(key(node._id, file), bytes);
                throw Error('modeled lost upload acknowledgement');
            };
            else f.onClassicAgent = async (node, options) => {
                if (new URL(options.url).pathname === '/restart') {
                    injected = true; throw Error('modeled lost restart completion');
                }
            };
            // The fenced SSH wrapper refuses a missing exit code before the
            // profile decoder, and Sync's public completion contract is false.
            assert.equal(await f.bg.service.updateXrayNodeConfig(node), false);
            assert.equal(injected, true, 'negative reaches the actual checked caller boundary');
            assert.equal(f.bg.generations.length, 1);
            assert.deepEqual(f.data.NodeOperationLock, f.bg.generations, 'uncertainty retains exact acquired owner/generation');
            assert.deepEqual(f.classicReleases, [], 'unknown completion never attempts release');
            const effects = f.bg.events.filter(([kind]) => ['connect', 'upload', 'agent', 'exec'].includes(kind));
            await assert.rejects(f.bg.service.updateXrayNodeConfig(node), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
            assert.deepEqual(f.bg.events.filter(([kind]) => ['connect', 'upload', 'agent', 'exec'].includes(kind)), effects, 'retained fence prevents redispatch');
            assert.deepEqual(f.data.NodeOperationLock, f.bg.generations);
            if (unknown.endsWith('read')) assert.deepEqual([...f.files], [...files], 'unknown read dispatches no upload');
            for (const [name, bytes] of files) if (name !== key(node._id, MAIN)) assert.equal(f.files.get(name), bytes);
            assert.deepEqual({ operations: f.data.TopologyOperation, bindings: f.data.TopologyExecutionBinding,
                enrollments: f.data.TopologyExecutionEnrollment, jobs: f.data.TopologyCreateIntent,
                owners: f.data.TopologyConfigOwner, users: f.users, links: f.data.CascadeLink }, history);
        } finally { await f.close(); }
    }, syntheticEnv));
}

module.exports = { assembled, withEnv };
