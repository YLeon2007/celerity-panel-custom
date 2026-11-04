'use strict';
// Assembled source regression: actual public adoption, host/queue/worker/
// settlement, classic writers, health and maintenance targets. Only persistence,
// settings/cache and SSH/agent/TCP IO are modeled. Not Mongo/SSH/systemd,
// operational maintenance authority, real PPP sessions/Internet or handback evidence.
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { randomUUID } = require('node:crypto');
const sift = require('sift').default;
const { Types } = require('mongoose');
const { fixture, app, request, settleTick, id, sha, copy, env, context, provider } = require('./cascadeAnyOrderRuntimeFixture');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { maintainAutoL2tpPaths } = require('../services/autoL2tpPathMaintenance');
const generator = require('../../../services/configGenerator');
const { installedIngressAdapters, modeledInstalledMain } = require('./helpers/cascadeInstalledIngressFixture');
const ROOT = path.resolve(__dirname, '../../../..');
const MAIN = '/usr/local/etc/xray/config.json';
const BRIDGE = '/usr/local/etc/xray-bridge/config.json';
const profilePath = profile => profile === 'xray-main' ? MAIN : BRIDGE;
const key = (node, file) => `${node}:${file}`;
const user = { userId: 'kept@invalid', xrayUuid: '88888888-8888-4888-8888-888888888888', enabled: true,
    nodes: [id(1), id(2), id(3), id(4)], groups: [] };
const runtimeUser = { id: user.xrayUuid, email: user.userId, flow: '' };
async function withEnv(work) {
    const prior = { ...process.env };
    Object.assign(process.env, env);
    try { return await work(); } finally {
        for (const name of Object.keys(process.env)) if (!(name in prior)) delete process.env[name];
        Object.assign(process.env, prior);
    }
}
function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

// Query-shaped views of the SAME runtime arrays. Population and dotted updates
// belong to this explicit DB seam; no ownership decision/service is replaced.
function backgroundCallers(f) {
    const events = [], loaded = new Map(), stubs = new Map();
    const users = [copy(user), { ...copy(user), userId: 'not-assigned', nodes: [id(999)] },
        { ...copy(user), userId: 'disabled', enabled: false }];
    const settings = { accessLogs: { enabled: true, ingestUrl: 'https://fixture.invalid/ingest' } };
    const set = (row, dotted, value) => {
        const parts = dotted.split('.'), last = parts.pop();
        for (const part of parts) row = row[part] ||= {};
        row[last] = copy(value);
    };
    const query = read => {
        const fields = [];
        const q = { select() { return q; }, session() { return q; }, setOptions() { return q; },
            read() { return q; }, readConcern() { return q; }, maxTimeMS() { return q; },
            populate(value) { fields.push(...value.split(' ')); return q; },
            async lean() {
                const result = copy(await read());
                const populate = row => {
                    for (const field of fields) if (row?.[field]) row[field] = copy(f.data.HyNode.find(node => node._id === String(row[field])));
                    return row;
                };
                return Array.isArray(result) ? result.map(populate) : populate(result);
            }, then(a, b) { return q.lean().then(a, b); } };
        return q;
    };
    const model = rows => ({
        find: filter => query(() => rows.filter(sift(filter))),
        findById: node => query(() => rows.find(row => String(row._id) === String(node)) || null),
        exists: filter => query(() => rows.find(sift(filter)) || null),
        findOneAndUpdate(filter, update) { return query(async () => {
            const before = copy(rows.find(sift(filter)) || null); await this.updateOne(filter, update); return before;
        }); },
        async updateOne(filter, update) {
            const row = rows.find(sift(filter));
            if (row) {
                for (const [name, value] of Object.entries(update.$set || {})) set(row, name, value);
                for (const [name, value] of Object.entries(update.$inc || {})) set(row, name, (row[name] || 0) + value);
            }
            return { matchedCount: row ? 1 : 0 };
        },
    });
    function stub(relative, value) { stubs.set(path.resolve(ROOT, relative), value); }
    stub('config.js', { PANEL_DOMAIN: context.hostIdentity, BASE_URL: 'https://fixture.invalid', ENCRYPTION_KEY: 'local-only-dummy-key' });
    stub('src/utils/logger.js', { info() {}, warn() {}, error() {}, debug() {} });
    stub('src/utils/helpers.js', { invalidateNodesCache: async () => {}, invalidateUserCache: async () => {} });
    stub('src/services/cacheService.js', { invalidateNodes: async () => {}, invalidateAllSubscriptions: async () => {}, invalidateDashboardCounts: async () => {} });
    stub('src/services/webhookService.js', { emit() {}, EVENTS: { NODE_OFFLINE: 'offline' } });
    stub('src/models/hyNodeModel.js', model(f.data.HyNode));
    stub('src/models/hyUserModel.js', model(users));
    stub('src/models/cascadeLinkModel.js', model(f.data.CascadeLink));
    stub('src/models/cascadeRouteGroupModel.js', model(f.data.CascadeRouteGroup));
    stub('src/models/settingsModel.js', { get: async () => copy(settings), update: async update => {
        for (const [name, value] of Object.entries(update)) set(settings, name, value);
    } });
    for (const [file, name] of [['topologyOperationModel', 'TopologyOperation'], ['nodeOperationLockModel', 'NodeOperationLock'],
        ['cascadeTopologyStateModel', 'CascadeTopologyState'], ['topologyCreateIntentModel', 'TopologyCreateIntent'],
        ['topologyIntentQueueStateModel', 'TopologyIntentQueueState'], ['relayL2tpStateModel', 'RelayL2tpState']]) {
        stub(`src/modules/relay-l2tp/models/${file}.js`, name === 'TopologyOperation' ? model(f.data[name]) : f.models[name]);
    }
    const native = { Types, connection: { db: { collection(name) {
        assert.equal(name, 'topologyconfigowners');
        return { find: filter => ({ toArray: async () => copy(f.data.TopologyConfigOwner.filter(row => String(row.node) === String(filter.node))) }) };
    } } } };
    class SSH {
        constructor(node) { this.node = node; }
        async connect() { events.push({ kind: 'connect', node: this.node._id }); }
        disconnect() { events.push({ kind: 'disconnect', node: this.node._id }); }
        async uploadContent(content, file) {
            events.push({ kind: 'upload', node: this.node._id, file });
            f.files.set(key(this.node._id, file), content);
        }
        async exec(command) {
            events.push({ kind: 'exec', node: this.node._id, command });
            if (f.onExec) {
                const result = await f.onExec(this.node, command);
                if (result !== undefined) return result;
            }
            const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/)?.[0];
            const stdout = command.includes('command -v xray') ? '/usr/bin/xray\n'
                : command.includes('is-active xray-bridge') ? 'active\n'
                    : command.includes('ss -tnH') ? '1\n' : '';
            return { code: 0, stdout: stdout + (receipt ? `\n${receipt}\n` : ''), stderr: '' };
        }
    }
    stub('src/services/nodeSSH.js', SSH);
    class Socket extends EventEmitter {
        setTimeout() { return this; }
        destroy() {}
        connect(port, host, done) {
            events.push({ kind: 'tcp', host, port });
            queueMicrotask(() => { done?.(); this.emit('connect'); }); return this;
        }
    }
    const net = { ...require('node:net'), Socket,
        createConnection: ({ host, port }) => new Socket().connect(port, host) };
    const axios = async options => {
        const url = new URL(options.url), node = f.data.HyNode.find(row => row.ip === url.hostname);
        assert.ok(node, 'only declared node agent endpoints');
        events.push({ kind: 'agent', node: node._id, path: url.pathname, body: copy(options.data) });
        if (f.failAgent === node._id) return { status: 503, data: {} };
        if (url.pathname === '/sync') f.runtimeUsers.set(node._id, copy(options.data.users));
        else if (url.pathname === '/users') {
            const rows = f.runtimeUsers.get(node._id) || [];
            f.runtimeUsers.set(node._id, [...rows.filter(row => row.email !== options.data.email), copy(options.data)]);
        } else assert.ok(['/info', '/restart'].includes(url.pathname), url.pathname);
        return { status: 200, data: { agent_version: '1.4.0', xray_version: 'modeled' } };
    };
    function load(filename) {
        if (stubs.has(filename)) return stubs.get(filename);
        if (loaded.has(filename)) return loaded.get(filename).exports;
        const mod = new Module(filename, module); mod.filename = filename;
        mod.paths = Module._nodeModulePaths(path.dirname(filename)); loaded.set(filename, mod);
        mod.require = request => {
            if (request === 'mongoose') return native;
            if (request === 'axios') return axios;
            if (request === 'net' || request === 'node:net') return net;
            const resolved = Module._resolveFilename(request, mod);
            if (stubs.has(resolved)) return stubs.get(resolved);
            // Compile unchanged checked-out service bytes with only these IO/DB
            // imports rebased. All decisions, locks and receipts remain actual.
            if (resolved.startsWith(path.join(ROOT, 'src/services/')) && resolved.endsWith('.js')) return load(resolved);
            if (resolved.endsWith('/legacyCascadeUndeploy.js')) return load(resolved);
            return Module.prototype.require.call(mod, request);
        };
        mod._compile(fs.readFileSync(filename, 'utf8'), filename); return mod.exports;
    }
    return { events, settings, users,
        sync: load(path.join(ROOT, 'src/services/syncService.js')),
        cascade: load(path.join(ROOT, 'src/services/cascadeService.js')),
        logs: load(path.join(ROOT, 'src/services/accessLogs/provisionService.js')) };
}

function honorProjection(model) {
    for (const method of ['find', 'findById']) {
        const original = model[method].bind(model);
        model[method] = (...args) => {
            const q = original(...args), lean = q.lean.bind(q);
            let selection;
            q.select = fields => { selection = fields; return q; };
            q.lean = async () => {
                const value = await lean();
                if (!selection || selection.split(' ').every(field => field.startsWith('+'))) return value;
                const project = row => {
                    if (!row) return row;
                    const result = { _id: row._id };
                    for (const field of selection.split(' ').map(field => field.replace(/^\+/, ''))) {
                        const parts = field.split('.'); let source = row, target = result;
                        for (let i = 0; i < parts.length; i++) {
                            const part = parts[i]; source = source?.[part];
                            if (source === undefined) break;
                            if (i === parts.length - 1) target[part] = copy(source);
                            else target = target[part] ||= {};
                        }
                    }
                    return result;
                };
                return Array.isArray(value) ? value.map(project) : project(value);
            };
            return q;
        };
    }
}
async function assembled({ installed = false } = {}) {
    const f = fixture({ roles: installed ? ['relay', 'bridge', 'portal', 'bridge', 'standalone', 'standalone']
        : ['portal', 'relay', 'bridge', 'portal', 'standalone', 'standalone'] });
    // The shared fixture intentionally ignores select(); background health
    // writes require the real consumer's projections at this DB boundary.
    honorProjection(f.models.HyNode); honorProjection(f.models.CascadeLink);
    f.files = new Map(); f.runtimeUsers = new Map();
    const nativeNodes = f.data.HyNode.slice(0, 4);
    for (const node of f.data.HyNode) {
        node.name = `fixture-${node._id}`; node.ssh = { password: 'local-dummy' }; node.agentVersion = '1.4.0';
        node.xray = { security: 'none', transport: 'tcp', inboundTag: 'client-in', extraInbounds: [], agentToken: 'local-dummy-agent' };
        f.runtimeUsers.set(node._id, nativeNodes.includes(node) ? [copy(runtimeUser)] : []);
    }
    const nodes = nativeNodes.map(({ _id, cascadeRole, ...rest }) => ({ ...copy(rest), id: _id, role: cascadeRole }));
    const links = (installed ? [] : [[10, 1, 2], [11, 2, 3], [12, 4, 3]]).map(([n, source, target]) => ({ id: id(n), source: id(source), target: id(target),
        mode: 'reverse', active: true, tunnelPort: 25000 + n, tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`,
        tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelDomain: 'legacy.invalid', priority: n }));
    const populated = links.map(link => ({ ...copy(link), _id: link.id,
        portalNode: { ...nodes.find(node => node.id === link.source), _id: link.source },
        bridgeNode: { ...nodes.find(node => node.id === link.target), _id: link.target } }));
    for (const node of nodes) {
        // Installed setup starts with genuinely empty adopted role profiles.
        // Every sidecar listener/path below must be produced by a real job.
        if (installed) { node.profileConfig = '{}'; continue; }
        let config;
        if (node.role === 'portal') {
            config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, []));
            config.inbounds.find(row => row.tag === 'client-in').settings.clients.push({ id: user.xrayUuid, email: user.userId });
            generator.applyReversePortal(config, populated.filter(link => link.source === node.id), ['client-in']);
        } else if (node.role === 'relay') config = JSON.parse(generator.generateRelayConfig(populated[0], populated[0].portalNode, [populated[1]]));
        else config = JSON.parse(generator.generateCombinedBridgeConfig(populated.filter(link => link.target === node.id)));
        (config.inbounds ||= []).push({ tag: 'unrelated-client', port: 27000, protocol: 'socks', settings: { auth: 'noauth', udp: false } });
        config.outbounds.push({ tag: 'unrelated-out', protocol: 'blackhole' });
        config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-client'], outboundTag: 'unrelated-out' });
        node.profileConfig = JSON.stringify(config, null, 2) + '\n';
    }
    const topology = { nodes, links, groups: [] };
    f.data.CascadeLink.push(...links.map(({ id: linkId, source, target, ...rest }) => ({ ...copy(rest), _id: linkId, portalNode: source, bridgeNode: target, status: 'online', name: linkId })));
    const pending = { mode: 'reverse', active: true, bridgeNode: id(4), ...copy(f.data.CascadeLink[2]), _id: id(13), portalNode: id(1), tunnelPort: 25113,
        tunnelUuid: '00000000-0000-4000-8000-000000000013', status: 'pending', autoDeploy: false };
    const inactive = { ...copy(pending), _id: id(14), active: false, tunnelPort: 25114 };
    const classic = { ...copy(pending), _id: id(15), portalNode: id(5), bridgeNode: id(6), tunnelPort: 25115 };
    delete classic.status;
    f.data.CascadeLink.push(pending, inactive, classic);
    let installedAdapters;
    if (installed) {
        const state = { _id: id(70), node: id(1), routeGroup: id(60), activePathKey: 'mine', status: 'installed', desiredState: 'installed',
            secretRevision: 41, appliedTopologyRevision: 0, pskEncrypted: 'modeled-preserved-psk', clientCidr: '10.255.30.0/24',
            localAddress: '10.255.30.1', poolStart: '10.255.30.10', poolEnd: '10.255.30.250', dnsServers: ['1.1.1.1'],
            tproxyPort: 12345, fwmark: 100, routeTable: 100 };
        f.data.RelayL2tpState.push(state);
        f.data.CascadeRouteGroup.push({ _id: id(60), name: 'installed', mode: 'reverse', strategy: 'priority-failover', paths: [
            { pathKey: 'mine', linkIds: [], priority: 4, enabled: true }, { pathKey: 'peer', linkIds: [], priority: 17, enabled: false }] });
        f.data.L2tpUser.push({ _id: id(80), relayNode: id(1), login: 'kept-user', passwordEncrypted: 'kept-secret', ip: '10.255.30.10',
            enabled: true, desiredRevision: 41, appliedRevision: 41, syncStatus: 'synced', syncOperationId: id(81) });
        // Explicit pre-existing PPP sync fact, NOT a topology operation or
        // manufactured terminal publication. PPP/session IO remains modeled.
        f.data.L2tpOperation.push({ _id: id(81), node: id(1), kind: 'sync_users', status: 'succeeded',
            plan: { operationId: id(81), relayId: id(1), desired: { credentialRevision: 41 } } });
        installedAdapters = installedIngressAdapters({ models: f.models, state,
            readMain: () => JSON.parse(f.files.get(key(id(1), MAIN))) });
        f.installed = { state, ...installedAdapters };
    } else f.data.RelayL2tpState.push({ node: id(2), status: 'not_installed', desiredState: 'absent', secretRevision: 0 });
    f.data.TopologyConfigOwner.length = 0;
    for (const node of f.data.HyNode) {
        const main = generator.generateXrayConfig(node, nativeNodes.includes(node) ? [user] : []);
        f.files.set(key(node._id, MAIN), nodes.find(row => row.id === node._id && row.role === 'portal')?.profileConfig || main);
        f.files.set(key(node._id, BRIDGE), nodes.find(row => row.id === node._id && row.role !== 'portal')?.profileConfig || '{}\n');
    }
    if (installed) f.files.set(key(id(1), MAIN), JSON.stringify(modeledInstalledMain(f.installed.state)));
    const Owner = f.models.TopologyConfigOwner;
    Owner.collection = { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] };
    const create = Owner.create.bind(Owner);
    Owner.create = (docs, options = {}) => options.session ? create(docs, options) : Owner.db.transaction(session => create(docs, { ...options, session }));
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Owner,
        withVerifiedMaintenance: async ({ binding }, work) => work({ status: 'verified', authority: 'external-maintenance-v1', binding: copy(binding),
            proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
            oldBackend: { instanceId: 'modeled-classic', pid: 42, processStartTime: 'modeled-start', processTree: 'stopped', dispatch: 'disabled' },
            readback: { source: 'node-readback', configSha256: sha(f.files.get(key(binding.node, profilePath(binding.profile)))),
                unitSha256: sha('unit'), serviceActive: 'active', serviceEnabled: 'enabled' } }) });
    for (const [index, node] of nativeNodes.entries()) {
        const original = await transfer.initializeClassic({ node: node._id, profile: node.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge',
            nodeIdentity: { machineId: String(index + 1).repeat(32), sshHostKeySha256: String(index + 1).repeat(64) } });
        await transfer.adopt({ node: node._id, profile: original.profile, generation: original.generation, proofRef: 'modeled-held',
            ...(installed ? {} : { legacyTopology: topology }) });
    }
    assert.equal(f.data.TopologyOperation.length, 0, 'public adoption never fabricates settled topology');
    // Test-only dependency handoff at the real default-host/runtime boundary,
    // not mutation of the assembled worker or a successful service substitute.
    // The ordinary L2TP lifecycle is intentionally dormant in this fixture.
    if (installed) {
        const originalHost = f.host;
        f.host = () => originalHost({ moduleEntry: { ...require('..'), registerModels: () => f.models,
            createTopologyDeploymentService(options) {
                const runtime = require('..').createTopologyDeploymentService({ ...options, installedIngressPreparer: installedAdapters.prepare });
                f.deployments.push(runtime); return runtime;
            } } });
    }
    const bg = backgroundCallers(f), createHost = f.host;
    let host = createHost(); provider.installActiveHost(host); f.http = app(f);
    const runtime = f.deployments[0], executor = runtime.operationWorker.executor;
    // Replace the fixture's empty resolver with the ACTUAL Sync implementation;
    // its real user DB queries and agent HTTP calls use the seams above.
    runtime.operationWorker.userResync._syncService = bg.sync;
    const prepare = executor.prepare.bind(executor), commit = executor.commit.bind(executor);
    const backups = new Map();
    executor.prepare = async input => {
        const result = await prepare(input);
        backups.set(input.node.node, f.files.get(key(input.node.node, profilePath(input.node.targetProfile))));
        return result;
    };
    executor.commit = async input => {
        await commit(input);
        f.files.set(key(input.node.node, profilePath(input.node.targetProfile)), Buffer.from(input.node.candidate.bytes).toString('utf8'));
        if (input.node.targetProfile === 'xray-main') f.runtimeUsers.set(input.node.node, []); // modeled restart empties RPC inventory
        return { ok: true };
    };
    executor.verify = async input => {
        assert.equal(sha(f.files.get(key(input.node.node, profilePath(input.node.targetProfile)))), input.node.candidateHash);
        if (f.failVerify) throw new Error('modeled known verification failure');
        return { ok: true };
    };
    executor.rollback = async input => {
        f.files.set(key(input.node.node, profilePath(input.node.targetProfile)), backups.get(input.node.node));
        f.calls.push(['rollback', input.node]); return { ok: true };
    };
    host.start();
    async function accept(linkId = id(10), method = 'POST') {
        const response = await request(f.http, method, method === 'DELETE' ? `/links/${linkId}` : '/topology/deploy',
            { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision, ...(method === 'DELETE' ? {} : { linkId }) }, randomUUID());
        assert.equal(response.status, 202, JSON.stringify(response.body));
        return response.body.job.jobId;
    }
    async function drain(jobId, status = 'succeeded') {
        for (let i = 0; i < 8; i++) await settleTick(f);
        const job = f.data.TopologyCreateIntent.find(row => row._id === jobId);
        const op = f.data.TopologyOperation.find(row => row._id === job.operationId);
        assert.equal(job.status, status === 'succeeded' ? 'succeeded' : 'failed', JSON.stringify({ job, operations: f.data.TopologyOperation.map(row => ({ status: row.status, error: row.error })) }));
        assert.equal(op.status, status); assert.equal(op.heldTopologyAdmission, false);
        assert.equal(f.data.NodeOperationLock.filter(row => row.owner !== 'classic-config-writer').length, 0);
        return op;
    }
    const read = async linkId => runtime.topologyRepository.readSelected({ snapshot: await runtime.topologyRepository.snapshotReader.readDraft(),
        scope: { kind: 'link.apply', linkId }, executionContext: context });
    return Object.assign(f, { bg, host, topology, pending, inactive, classic, runtime, accept, drain, read,
        maintenance: () => maintainAutoL2tpPaths(f.models),
        async restart() {
            provider.clearActiveHost(host); await host.stop();
            host = createHost(); f.host = host; f.runtime = f.deployments.at(-1);
            f.runtime.operationWorker.userResync._syncService = bg.sync;
            provider.installActiveHost(host); host.start();
        },
        nativeFiles: () => [...f.files].filter(([name]) => nativeNodes.some(node => name.startsWith(`${node._id}:`))),
        async close() { provider.clearActiveHost(host); await host.stop(); assert.equal(f.timer.callbacks.size, 0); } });
}
function configEffects(f, node) {
    return f.bg.events.filter(event => event.node === node && (event.kind === 'upload'
        || event.kind === 'exec' && !event.command.includes('ss -tnH')));
}
async function managedBackground(f, { nativeHeld = false } = {}) {
    const before = copy(f.nativeFiles());
    const bridge = f.data.HyNode.find(node => node._id === id(3));
    assert.equal((await f.bg.logs.reconcileNode(bridge, f.bg.settings)).status, 'error');
    assert.equal(bridge.xray.accessLogs.appliedFingerprint, undefined);
    assert.equal(await f.bg.sync.updateXrayNodeConfig(f.data.HyNode[0]), true);
    if (nativeHeld) await assert.rejects(f.bg.cascade._undeployLinkWithCompletion(f.data.CascadeLink.find(link => link._id === id(11))),
        { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    await f.bg.cascade.healthCheckAll();
    assert.equal(f.pending.status, 'pending', 'health tick excludes save-only drafts');
    assert.equal(f.inactive.active, false);
    assert.deepEqual(await f.maintenance(), { updated: 0, deferred: [], revision: null });
    assert.deepEqual(f.nativeFiles(), before, 'actual background callers preserve BOTH profiles');
    for (const [, text] of f.nativeFiles()) {
        const config = JSON.parse(text);
        assert.equal((config.inbounds || []).some(row => [25113, 25114].includes(row.port)), false);
        assert.equal(text.includes(f.pending.tunnelUuid), false, 'save-only neighbor has no installed tunnel credentials');
    }
    for (const node of f.topology.nodes) {
        assert.deepEqual(configEffects(f, node.id), []);
        const config = JSON.parse(f.files.get(key(node.id, node.role === 'portal' ? MAIN : BRIDGE)));
        assert.ok(config.inbounds?.some(row => row.tag === 'unrelated-client'));
        assert.ok(config.outbounds.some(row => row.tag === 'unrelated-out'));
        assert.ok(config.routing.rules.some(row => row.inboundTag?.includes('unrelated-client') && row.outboundTag === 'unrelated-out'));
        if (node.role === 'portal') assert.ok(config.inbounds.find(row => row.tag === 'client-in').settings.clients.some(row => row.id === user.xrayUuid));
    }
    assert.deepEqual(f.runtimeUsers.get(id(1)), [runtimeUser], 'actual assigned, enabled nonempty users only');
}

test.after(() => require('../../../services/sshPoolService').closeAll());
test('public adoption and serial actual worker publication coexist with real background targets and nonempty users', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled();
    try {
        const imports = copy(f.data.TopologyConfigOwner.map(owner => owner.legacyAppliedTopology));
        await managedBackground(f);
        const first = await f.drain(await f.accept());
        assert.ok(first.nodes.every(node => node.state === 'committed'));
        const next = await f.read(id(11));
        assert.equal(next.baselineTopology.links.some(link => [id(13), id(14)].includes(link.id)), false);
        for (const node of next.baselineTopology.nodes) assert.equal(node.profileConfig,
            f.files.get(key(node.id, profilePath(node.role === 'portal' ? 'xray-main' : 'xray-bridge'))));
        await managedBackground(f);
        const cleanup = await f.drain(await f.accept(id(11), 'DELETE'));
        assert.equal(f.data.CascadeLink.some(link => link._id === id(11)), false);
        assert.ok(cleanup.nodes.some(node => node.node === id(3)), 'actual cleanup publishes detached/shared bridge candidate');
        assert.equal((await f.read(id(12))).baselineTopology.links.some(link => link.id === id(12)), true, 'shared bridge peer survives');
        await managedBackground(f);
        const recreated = await request(f.http, 'POST', '/links', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
            name: 'recreated native suffix', portalNodeId: id(2), bridgeNodeId: id(3), mode: 'reverse',
            tunnelPort: 25011, tunnelSecurity: 'none', autoDeploy: true }, randomUUID());
        assert.equal(recreated.status, 202, JSON.stringify(recreated.body));
        await f.drain(recreated.body.job.jobId);
        await managedBackground(f);
        assert.deepEqual(f.data.TopologyConfigOwner.map(owner => owner.legacyAppliedTopology), imports);
        for (const node of first.nodes.filter(node => node.targetProfile === 'xray-main')) assert.deepEqual(f.runtimeUsers.get(node.node), [runtimeUser]);
        assert.ok(f.bg.events.some(event => event.kind === 'agent' && event.path === '/users'), 'worker really restores users after modeled restart');
    } finally { await f.close(); }
}));

test('suspended actual worker retains exact generations while classic/background contenders refuse and unrelated classic Sync progresses', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled(), entered = deferred(), release = deferred();
    let tick;
    try {
        await managedBackground(f); // settle the real config-affecting desired logging setting before admission
        f.setPause(async () => { entered.resolve(); await release.promise; });
        const jobId = await f.accept();
        tick = f.timer.tick();
        await entered.promise;
        const held = copy(f.data.NodeOperationLock);
        assert.ok(held.length > 0); assert.ok(held.every(row => row.remoteUncertain));
        assert.ok(f.timer.callbacks.size > 0, 'real lifecycle schedule, not an empty fake scheduler');
        const publishedBefore = f.data.TopologyConfigOwner.map(owner => owner.lastSettledOperation);
        await managedBackground(f, { nativeHeld: true });
        assert.deepEqual(f.data.NodeOperationLock, held);
        assert.deepEqual(f.data.TopologyConfigOwner.map(owner => owner.lastSettledOperation), publishedBefore);
        assert.equal(await f.bg.sync.updateXrayNodeConfig(f.data.HyNode[4]), true);
        assert.ok(configEffects(f, id(5)).some(event => event.kind === 'upload'), 'independent classic really dispatches');
        const classicConfig = JSON.parse(f.files.get(key(id(5), MAIN)));
        assert.ok(classicConfig.inbounds.some(row => row.port === f.classic.tunnelPort), 'legacy no-status peer still has its actual listener');
        assert.ok(classicConfig.reverse.portals.length > 0);
        assert.deepEqual(f.data.NodeOperationLock, held, 'unrelated classic releases only its own generation');
        release.resolve(); await tick; f.setPause(undefined);
        await f.drain(jobId);
    } finally { release.resolve(); if (tick) await tick; await f.close(); }
}));

test('actual legacy stop remains held during suspension and unknown completion without blocking unrelated native publication', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled(), entered = deferred(), release = deferred();
    let stopping;
    try {
        f.onExec = async (node, command) => {
            if (node._id === id(6) && command.includes('systemctl stop xray-bridge')) {
                entered.resolve(); await release.promise;
                return { code: 0, stdout: '', stderr: '' }; // no invocation receipt: genuinely unknown
            }
        };
        stopping = f.bg.cascade._undeployLinkWithCompletion(f.classic);
        const outcome = stopping.then(() => null, error => error);
        await entered.promise;
        const held = copy(f.data.NodeOperationLock.find(row => row.node === id(6)));
        assert.ok(held?.remoteUncertain);
        await assert.rejects(f.bg.sync.updateXrayNodeConfig(f.data.HyNode[5]), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
        await f.drain(await f.accept());
        assert.deepEqual(f.data.NodeOperationLock.find(row => row.node === id(6)), held);
        release.resolve();
        assert.equal((await outcome).code, 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN');
        assert.deepEqual(f.data.NodeOperationLock.find(row => row.node === id(6)), held);
        await managedBackground(f);
    } finally { release.resolve(); if (stopping) await stopping.catch(() => {}); await f.close(); }
}));

test('actual known verification failure rolls back profiles and restores assigned users before background retry', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled();
    try {
        await managedBackground(f);
        const before = copy(f.nativeFiles()), imports = copy(f.data.TopologyConfigOwner);
        f.failVerify = true;
        const rolledBack = await f.drain(await f.accept(), 'rolled_back');
        assert.ok(f.calls.some(([kind]) => kind === 'rollback'), 'real worker takes rollback path');
        assert.ok(rolledBack.nodes.some(node => node.state === 'rolled_back'));
        assert.deepEqual(f.nativeFiles(), before);
        assert.deepEqual(f.data.TopologyConfigOwner, imports, 'rollback does not synthesize applied publication');
        assert.deepEqual(f.runtimeUsers.get(id(1)), [runtimeUser]);
        await managedBackground(f);
        f.failVerify = false;
        await f.drain(await f.accept());
    } finally { await f.close(); }
}));

test('real host stop removes a nonempty schedule and awaits the suspended worker before restart/recovery settlement', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled(), entered = deferred(), release = deferred();
    let tick, stopped;
    try {
        await managedBackground(f);
        f.setPause(async () => { entered.resolve(); await release.promise; });
        const jobId = await f.accept();
        tick = f.timer.tick(); await entered.promise;
        assert.ok(f.timer.callbacks.size > 0);
        let drained = false;
        stopped = f.host.stop().then(result => { drained = true; return result; });
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(f.timer.callbacks.size, 0);
        assert.equal(drained, false, 'stop must await actual in-flight target');
        const generations = copy(f.data.NodeOperationLock);
        await managedBackground(f, { nativeHeld: true });
        assert.deepEqual(f.data.NodeOperationLock, generations);
        release.resolve(); await tick; await stopped;
        assert.equal(drained, true);
        f.setPause(undefined);
        const prepares = f.calls.filter(([kind]) => kind === 'prepare').length;
        await f.timer.tick();
        assert.equal(f.calls.filter(([kind]) => kind === 'prepare').length, prepares, 'stopped schedule cannot dispatch twice');
        await f.restart(); await f.drain(jobId);
        assert.equal(f.calls.filter(([kind]) => kind === 'prepare').length, prepares, 'recovery settles the existing job without reapplying');
    } finally { release.resolve(); if (tick) await tick; if (stopped) await stopped; await f.close(); }
}));

test('an unapplied logging request during native dispatch grants no classic effects or fabricated logging success', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled(), entered = deferred(), release = deferred();
    let tick;
    try {
        f.setPause(async () => { entered.resolve(); await release.promise; });
        const jobId = await f.accept(id(11)); tick = f.timer.tick(); await entered.promise;
        await managedBackground(f, { nativeHeld: true });
        const bridge = f.data.HyNode[2];
        assert.equal(bridge.xray.accessLogs.enabled, true, 'actual caller records desired settings, not installed evidence');
        assert.equal(bridge.xray.accessLogs.appliedFingerprint, undefined);
        release.resolve(); await tick; f.setPause(undefined);
        const op = await f.drain(jobId);
        assert.ok(op.nodes.every(node => node.state === 'committed'));
        assert.equal(bridge.xray.accessLogs.appliedFingerprint, undefined, 'native settlement cannot invent logging acknowledgement');
        for (const node of (await f.read(id(12))).baselineTopology.nodes) assert.equal(node.profileConfig,
            f.files.get(key(node.id, profilePath(node.role === 'portal' ? 'xray-main' : 'xray-bridge'))));
    } finally { release.resolve(); if (tick) await tick; await f.close(); }
}));

test('idle adopted legacy cleanup conservatively retains its own vetoed generation without touching either profile', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled();
    try {
        const before = copy(f.nativeFiles());
        await assert.rejects(f.bg.cascade._undeployLinkWithCompletion(f.data.CascadeLink.find(link => link._id === id(11))),
            { code: 'CLASSIC_CONFIG_WRITE_OWNER_VETO' });
        const held = copy(f.data.NodeOperationLock);
        assert.equal(held.length, 1); assert.equal(held[0].node, id(2)); assert.equal(held[0].remoteUncertain, true);
        assert.deepEqual(f.nativeFiles(), before);
        assert.deepEqual(configEffects(f, id(2)), []);
        await managedBackground(f);
        assert.deepEqual(f.data.NodeOperationLock, held, 'no test cleanup erases uncertain ownership');
    } finally { await f.close(); }
}));

test('actual managed Sync fails closed for missing/erroring agent without SSH fallback after native settlement', { timeout: 5000 }, async () => withEnv(async () => {
    const f = await assembled();
    try {
        await f.drain(await f.accept());
        const node = f.data.HyNode[0], before = copy(f.nativeFiles()), runtimeBefore = copy(f.runtimeUsers);
        delete node.xray.agentToken;
        assert.equal(await f.bg.sync.updateXrayNodeConfig(node), false);
        node.xray.agentToken = 'local-dummy-agent'; f.failAgent = node._id;
        assert.equal(await f.bg.sync.updateXrayNodeConfig(node), false);
        assert.deepEqual(configEffects(f, node._id), []);
        assert.deepEqual(f.nativeFiles(), before); assert.deepEqual(f.runtimeUsers, runtimeBefore);
    } finally { await f.close(); }
}));

require('./helpers/cascadeInstalledBackgroundCases')({ test, assert, assembled, withEnv, request, settleTick, id, copy, key, MAIN, BRIDGE,
    randomUUID, modeledInstalledMain, configEffects, deferred });
