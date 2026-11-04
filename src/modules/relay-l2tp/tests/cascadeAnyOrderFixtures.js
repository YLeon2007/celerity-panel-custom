'use strict';

// Local orchestration evidence only: actual HTTP handlers, draft repository,
// classic coordinator/core and generators; in-memory persistence and SSH protocol.
// No app config/.env, connection, worker, real SSH or service is started.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const express = require('express');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const { createTopologyDraftWriteService } = require('../services/topologyDraftWriteService');
const ROOT = path.resolve(__dirname, '../../..');
const MAIN = '/usr/local/etc/xray/config.json';
const TRANSIT = '/usr/local/etc/xray-bridge/config.json';
const IDS = Object.freeze({ P: '507f1f77bcf86cd799439031', R: '507f1f77bcf86cd799439032',
    B1: '507f1f77bcf86cd799439033', B2: '507f1f77bcf86cd799439034' });
const CLASSIC_ENV = Object.freeze({
    // Exact selector fixture used by existing cascadeLifecycleIngress tests.
    // This object is NEVER assigned to process.env and contains no real secrets.
    PANEL_DOMAIN: 'lm1.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
    CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'true',
    CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: 'ab'.repeat(32),
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false',
});
const GRAPHS = Object.freeze([
    { name: 'G1', edges: [{ key: 'PB1', source: 'P', target: 'B1', port: 12001, priority: 10 }] },
    { name: 'G2', edges: [{ key: 'PR', source: 'P', target: 'R', port: 12002, priority: 10 },
        { key: 'RB1', source: 'R', target: 'B1', port: 12003, priority: 10 }] },
    { name: 'G3', edges: [{ key: 'PR', source: 'P', target: 'R', port: 12002, priority: 10 },
        { key: 'RB1', source: 'R', target: 'B1', port: 12003, priority: 10 },
        { key: 'RB2', source: 'R', target: 'B2', port: 12004, priority: 20,
            geoRouting: { enabled: true, domains: ['domain:example.net'], geoip: [] } }] },
]);
function permutations(items) {
    if (items.length === 0) return [[]];
    return items.flatMap((item, i) => permutations(items.filter((_, j) => i !== j))
        .map(rest => [item, ...rest]));
}
const CREATION_CASES = GRAPHS.flatMap(graph => permutations(graph.edges).map(order => ({
    graph, order, label: `${graph.name} ${order.map(edge => edge.key).join(' > ')}`,
})));
const quiet = { info() {}, warn() {}, error() {}, debug() {} };
function load(relative, replacements = {}) {
    const filename = path.join(ROOT, relative);
    const mod = new Module(filename, module);
    mod.filename = filename;
    mod.paths = Module._nodeModulePaths(path.dirname(filename));
    mod.require = id => Object.hasOwn(replacements, id) ? replacements[id]
        : Module.prototype.require.call(mod, id);
    mod._compile(fs.readFileSync(filename, 'utf8'), filename);
    return mod.exports;
}
function copy(value) {
    if (value == null || typeof value !== 'object') return value;
    if (value instanceof Date) return new Date(value);
    if (typeof value.toHexString === 'function') return value.toHexString();
    if (Array.isArray(value)) return value.map(copy);
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, copy(item)]));
}
const id = value => String(value?._id ?? value);
const get = (row, key) => key.split('.').reduce((obj, part) => obj?.[part], row);
function matches(row, filter = {}) {
    return Object.entries(filter).every(([key, expected]) => {
        if (key === '$or') return expected.some(term => matches(row, term));
        if (key === '$and') return expected.every(term => matches(row, term));
        const actual = get(row, key);
        if (expected && typeof expected === 'object' && !Array.isArray(expected)) {
            return Object.entries(expected).every(([operator, operand]) => {
                if (operator === '$in') return operand.map(id).includes(id(actual));
                if (operator === '$nin') return !operand.map(id).includes(id(actual));
                if (operator === '$exists') return (actual !== undefined) === operand;
                if (operator === '$ne') return actual !== operand;
                assert.fail(`Unmodeled persistence predicate ${operator}`);
            });
        }
        if (Array.isArray(expected)) return JSON.stringify(actual) === JSON.stringify(expected);
        return actual === expected;
    });
}
function set(row, key, value) {
    const parts = key.split('.');
    const last = parts.pop();
    let object = row;
    for (const part of parts) object = object[part] ||= {};
    object[last] = copy(value);
}
function update(row, change) {
    for (const [key, value] of Object.entries(change.$set || {})) set(row, key, value);
    for (const [key, amount] of Object.entries(change.$inc || {})) set(row, key, (get(row, key) || 0) + amount);
    for (const key of Object.keys(change.$unset || {})) delete row[key];
}
function mainProfile() {
    return { log: { loglevel: 'warning' }, inbounds: [{ tag: 'vless-in', port: 443,
        protocol: 'vless', settings: { clients: [{ id: 'synthetic-existing-user', email: 'fixture@example.invalid' }] } }],
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [{ type: 'field', ip: ['geoip:private'], outboundTag: 'block' }] } };
}
async function createHarness(t) {
    const rows = { CascadeLink: [], HyNode: Object.entries(IDS).map(([name, nodeId], index) => ({
        _id: nodeId, name, ip: `192.0.2.${index + 1}`, active: true, type: 'xray',
        cascadeRole: name === 'P' ? 'portal' : name === 'R' ? 'relay' : 'bridge',
        ssh: { password: 'synthetic-local-only' }, xray: { inboundTag: 'vless-in' },
    })), CascadeRouteGroup: [], RelayL2tpState: [], TopologyOperation: [], TopologyCreateIntent: [],
    TopologyIntentQueueState: [], NodeOperationLock: [],
    CascadeTopologyState: [{ _id: 'singleton', revision: 1, deployedRevision: 0,
        replacementEpoch: 0, topologyAdmissionCount: 0, remoteAdmissionCount: 0 }] };
    const calls = { core: [], failures: [], transport: [], writes: [], diagnostics: [], transactions: 0 };
    const files = new Map(rows.HyNode.map(node => [`${node._id}:${MAIN}`, JSON.stringify(mainProfile())]));
    const query = (read, modelName) => {
        let populate = false;
        let selection;
        const execute = () => {
            let result = copy(read());
            const project = row => {
                if (!row || typeof row !== 'object') return row;
                if (populate && modelName === 'CascadeLink') {
                    for (const field of ['portalNode', 'bridgeNode']) {
                        row[field] = copy(rows.HyNode.find(node => node._id === id(row[field])) || row[field]);
                    }
                }
                if (selection && !selection.startsWith('+')) {
                    const projected = { _id: row._id };
                    for (const field of selection.split(/\s+/)) {
                        const value = get(row, field);
                        if (value !== undefined) set(projected, field, value);
                    }
                    row = projected;
                }
                return row;
            };
            return Array.isArray(result) ? result.map(project) : project(result);
        };
        return { session() { return this; }, setOptions() { return this; }, sort() { return this; },
            select(value) { selection = value; return this; }, populate() { populate = true; return this; },
            async lean() { return execute(); }, then(resolve, reject) { return Promise.resolve().then(execute).then(resolve, reject); } };
    };
    const connection = { async transaction(work) {
        const before = copy(rows); calls.transactions++;
        try { return await work({ localFixtureSession: true }); }
        catch (error) { for (const key of Object.keys(rows)) rows[key].splice(0, rows[key].length, ...before[key]); throw error; }
    } };
    const models = {};
    for (const name of Object.keys(rows)) models[name] = {
        db: connection,
        find: filter => query(() => rows[name].filter(row => matches(row, filter)), name),
        findById: nodeId => query(() => rows[name].find(row => row._id === id(nodeId)) || null, name),
        findOne: filter => query(() => rows[name].find(row => matches(row, filter)) || null, name),
        exists: filter => query(() => rows[name].find(row => matches(row, filter)) ? { _id: 'exists' } : null),
        async create(input) {
            const list = Array.isArray(input) ? input : [input];
            const created = list.map(document => ({ ...(name === 'CascadeLink' ? { active: true, status: 'pending' } : {}), ...copy(document) }));
            if (name === 'NodeOperationLock' && created.some(row => rows[name].some(old => id(old.node) === id(row.node)))) {
                throw Object.assign(new Error('local duplicate node lock'), { code: 11000 });
            }
            rows[name].push(...created);
            return Array.isArray(input) ? created : created[0];
        },
        async updateOne(filter, change) {
            const row = rows[name].find(row => matches(row, filter));
            if (row) update(row, change);
            return { acknowledged: true, matchedCount: row ? 1 : 0 };
        },
        findOneAndUpdate: (filter, change) => query(() => {
            const row = rows[name].find(row => matches(row, filter));
            if (row) update(row, change);
            return row || null;
        }, name),
        async deleteOne(filter) {
            const index = rows[name].findIndex(row => matches(row, filter));
            if (index >= 0) rows[name].splice(index, 1);
            return { acknowledged: true, deletedCount: index >= 0 ? 1 : 0 };
        },
    };
    const lockService = new NodeOperationLockService({ clock: { now: () => new Date() }, repository: {
        async acquireLease(row) {
            const currentLock = rows.NodeOperationLock.find(old => id(old.node) === id(row.node));
            if (currentLock) return { acquired: false, currentLock };
            rows.NodeOperationLock.push(copy(row)); return { acquired: true, lock: copy(row) };
        },
        async findByNode(node) { return rows.NodeOperationLock.find(row => id(row.node) === id(node)) || null; },
        async deleteVerifiedOwned(lock) {
            const index = rows.NodeOperationLock.findIndex(row => ['node', 'owner', 'operationId', 'generation']
                .every(key => row[key] === lock[key]));
            if (index < 0) return false;
            rows.NodeOperationLock.splice(index, 1); return true;
        },
    } });
    const ownership = { APPLIED_LINK_STATUSES: ['staged', 'deployed', 'online'],
        topologyManagesNodeConfig: async () => false, usesTestTopologyConfig: () => false };
    const held = load('services/classicNodeConfigWrite.js', {
        '../modules/relay-l2tp/models/nodeOperationLockModel': models.NodeOperationLock,
        './topologyConfigOwnership': ownership,
    });
    const admission = load('services/classicPortalBridgeAdmission.js', { './classicNodeConfigWrite': held });
    const generator = load('services/configGenerator.js', { '../utils/logger': quiet,
        '../../config': { panel: { domain: 'fixture.invalid' } } });
    // Established idle bridge profiles from the product constructor bytes;
    // bootstrap/installation itself belongs to its existing separate suite.
    const portPreflight = load('services/classicScopedPortPreflight.js', { './configGenerator': generator });
    const bootstrapper = load('services/classicPortalBridgeBootstrap.js', { './configGenerator': generator });
    for (const node of rows.HyNode) files.set(`${node._id}:${TRANSIT}`, bootstrapper.IDLE_BYTES);
    class LocalSSH {
        constructor(node) { this.node = node; }
        async connect() { calls.transport.push({ nodeId: id(this.node), kind: 'connect' }); }
        disconnect() {}
        async exec(command, options = {}) {
            const nodeId = id(this.node);
            calls.transport.push({ nodeId, command });
            const marker = command.match(/C3_(?:SCOPED_DONE|PORT_READ)_[a-f0-9]+/);
            assert.ok(marker, 'only the real finite scoped/preflight protocol is modeled');
            let stdout = '';
            if (command.includes('C3_READ_CONFIG')) {
                const file = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/config\.json(?:\.[a-f0-9]+\.stage)?/)[0];
                stdout = files.get(`${nodeId}:${file}`) ?? 'C3_CONFIG_ABSENT';
            } else if (command.includes('systemctl show')) {
                const file = command.includes('xray-bridge') ? TRANSIT : MAIN;
                stdout = `ActiveState=active\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${file} ; }\n`;
            } else if (options.stdin !== undefined) {
                const stage = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/[^'\s]+\.stage/)[0];
                files.set(`${nodeId}:${stage}`, String(options.stdin)); calls.writes.push({ nodeId, stage });
            } else if (command.includes('mv --')) {
                const stage = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/[^'\s]+\.stage/)[0];
                const file = stage.replace(/\.[a-f0-9]+\.stage$/, '');
                assert.ok(files.has(`${nodeId}:${stage}`), 'install requires actual staged bytes');
                files.set(`${nodeId}:${file}`, files.get(`${nodeId}:${stage}`)); files.delete(`${nodeId}:${stage}`);
            } else if (command.includes('ss -tnH')) {
                const port = command.match(/sport = :(\d+)/)[1];
                const peer = command.match(/and dst ([0-9.]+)/)[1];
                stdout = `0 0 ${this.node.ip}:${port} ${peer}:49900`;
            }
            return { code: 0, stdout: `${stdout}\n${marker[0]}\n`, stderr: '' };
        }
    }
    const core = load('services/cascadeService.js', {
        '../models/cascadeLinkModel': models.CascadeLink, '../models/hyNodeModel': models.HyNode,
        '../models/settingsModel': {}, './configGenerator': generator, './nodeSSH': LocalSSH,
        './classicNodeConfigWrite': { ...held,
            // Existing env injection seam, synthetic and local; never load application env.
            withClassicNodeConfigWrite: (options, work) => held.withClassicNodeConfigWrite({ ...options, env: CLASSIC_ENV }, work) },
        './classicPortalBridgeAdmission': admission,
        './classicScopedPortPreflight': portPreflight, './classicPortalBridgeBootstrap': bootstrapper,
        '../modules/relay-l2tp/models/cascadeTopologyStateModel': models.CascadeTopologyState,
        '../modules/relay-l2tp/models/relayL2tpStateModel': models.RelayL2tpState,
        './cacheService': {}, '../utils/logger': quiet, './webhookService': {},
        './topologyConfigOwnership': ownership,
        '../modules/relay-l2tp/services/legacyCascadeUndeploy': { trackLegacyCascadeUndeploy: work => work() },
    });
    const coordinatorModule = load('services/classicScopedCascadeDeploymentService.js', {
        './classicPortalBridgeAdmission': admission, './classicScopedPortPreflight': portPreflight,
    });
    const coordinator = coordinatorModule.createClassicScopedCascadeDeploymentService({ ...models,
        env: CLASSIC_ENV, NodeSSH: LocalSSH, lockService, topologyManagesNodeConfig: ownership.topologyManagesNodeConfig,
        logger: { warn: event => calls.diagnostics.push(JSON.parse(event)) },
        cascadeService: Object.fromEntries(['deployScopedClassicLink', 'removeScopedClassicLink'].map(method => [method, async input => {
            calls.core.push({ method, linkId: input.linkId, baselineLinkIds: input.baselineLinkIds });
            try { return await core[method](input); }
            catch (error) { calls.failures.push({ method, code: error.code }); throw error; }
        }])),
    });
    const writeService = createTopologyDraftWriteService({ ...models, deploymentEnv: CLASSIC_ENV,
        withScopedNodeLocks: (options, work) => admission.withScopedClassicNodeLocks({ ...options, lockService }, work) });
    const eager = {
        '../models/cascadeLinkModel': models.CascadeLink, '../models/hyNodeModel': models.HyNode,
        ...Object.fromEntries(Object.entries({ CascadeRouteGroup: 'cascadeRouteGroup', CascadeTopologyState: 'cascadeTopologyState',
            RelayL2tpState: 'relayL2tpState', L2tpUser: 'l2tpUser', L2tpOperation: 'l2tpOperation',
            TopologyOperation: 'topologyOperation', NodeOperationLock: 'nodeOperationLock' }).map(([name, filename]) =>
            [`../modules/relay-l2tp/models/${filename}Model`, models[name] || {}])),
        '../services/nodeSSH': LocalSSH, '../utils/logger': quiet,
        './topologyTestDiagnostics': { logTopologyTestFailure() {} },
        '../middleware/auth': Object.assign((req, res, next) => next(), { requireScope: () => (req, res, next) => next() }),
    };
    const linksModule = load('routes/cascadeLinks.js', eager);
    const topologyModule = load('routes/cascadeTopologyDeploy.js', { ...eager,
        '../modules/relay-l2tp': { createTopologyDeploymentService: () => coordinator },
        './cascadeLinks': linksModule,
    });
    const app = express();
    app.use(express.json());
    const pass = (req, res, next) => next();
    app.use('/api/cascade/links', linksModule.createCascadeLinksRouter({ Link: models.CascadeLink,
        Node: models.HyNode, RouteGroup: models.CascadeRouteGroup, RelayState: models.RelayL2tpState,
        TopologyState: models.CascadeTopologyState, topologyDraftWriteService: writeService,
        topologyCoordinator: coordinator, deploymentEnv: CLASSIC_ENV,
        maintainAutoL2tpPathsFn: async () => undefined, invalidateSubscriptions: async () => {}, invalidateTopology: async () => {} }));
    app.use('/api/cascade/topology', topologyModule.createCascadeTopologyDeployRouter({
        topologyDeploymentService: coordinator, models, requireAuth: pass, requireScope: () => pass,
        csrf: pass, deployRateLimiter: pass, operationStatusRateLimiter: pass, routeLogger: quiet,
    }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
    async function request(method, endpoint, body) {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${endpoint}`, {
            method, headers: { 'content-type': 'application/json', connection: 'close' },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        return { status: response.status, body: await response.json() };
    }
    const state = () => rows.CascadeTopologyState[0];
    return { rows, files, calls, models, generator, coordinator, state, request,
        create(edge, autoDeploy = false, mode = 'reverse') {
            return request('POST', '/api/cascade/links', { expectedTopologyRevision: state().revision,
                name: edge.key, portalNodeId: IDS[edge.source], bridgeNodeId: IDS[edge.target],
                mode, tunnelPort: edge.port, tunnelUuid: `00000000-0000-4000-8000-${String(edge.port).padStart(12, '0')}`,
                tunnelSecurity: 'none', tunnelTransport: 'tcp', priority: edge.priority,
                geoRouting: edge.geoRouting, autoDeploy });
        },
        deploy(linkId) { return request('POST', '/api/cascade/topology/deploy', { expectedTopologyRevision: state().revision, linkId }); },
        remove(linkId) { return request('DELETE', `/api/cascade/links/${linkId}`, { expectedTopologyRevision: state().revision }); },
        async snapshot() { const result = await request('GET', '/api/cascade/links'); assert.equal(result.status, 200); return result.body; },
    };
}
function semanticLinks(links) {
    return links.map(link => ({ name: link.name, source: id(link.portalNode), target: id(link.bridgeNode),
        mode: link.mode, port: link.tunnelPort, priority: link.priority, geo: link.geoRouting?.enabled === true }))
        .sort((left, right) => left.name.localeCompare(right.name));
}
function expectApplied(response, label) {
    assert.equal(response.body.autoDeployStatus, undefined,
        `${label}: accepted draft is NOT applied; ${response.body.autoDeployError?.code || response.body.error?.code}`);
    assert.ok(response.body.autoDeployResult?.status === 'succeeded'
        || ['queued', 'preparing', 'committing', 'succeeded'].includes(response.body.autoDeployOperation?.status)
        || response.body.autoDeployJob?.jobId, `${label}: missing apply result/operation: ${JSON.stringify(response.body)}`);
}
// A simulated imported applied inventory, NOT evidence that current creation
// can build G2/G3. Saving it uses the actual route/repository; established legacy
// bytes use the actual shipped portal/relay/bridge generators. This separates a
// deletion regression from the earlier create regression that would mask it.
async function seedAppliedGraph(h, graph) {
    for (const edge of graph.edges) {
        const saved = await h.create(edge, false);
        assert.equal(saved.status, 201, `baseline save ${edge.key}: ${JSON.stringify(saved.body)}`);
    }
    const links = h.rows.CascadeLink;
    for (const link of links) link.status = 'deployed';
    const populated = links.map(link => ({ ...copy(link),
        portalNode: copy(h.rows.HyNode.find(node => node._id === link.portalNode)),
        bridgeNode: copy(h.rows.HyNode.find(node => node._id === link.bridgeNode)) }));
    for (const node of h.rows.HyNode) {
        const incoming = populated.filter(link => id(link.bridgeNode) === node._id);
        const outgoing = populated.filter(link => id(link.portalNode) === node._id);
        if (outgoing.length) {
            const main = JSON.parse(h.files.get(`${node._id}:${MAIN}`));
            h.generator.applyReversePortal(main, outgoing, ['vless-in']);
            h.files.set(`${node._id}:${MAIN}`, JSON.stringify(main, null, 2));
        }
        if (incoming.length) h.files.set(`${node._id}:${TRANSIT}`,
            node.cascadeRole === 'relay'
                ? h.generator.generateRelayConfig(incoming[0], incoming[0].portalNode, outgoing)
                : h.generator.generateCombinedBridgeConfig(incoming));
    }
    return new Map(links.map(link => [link.name, link._id]));
}
module.exports = { MAIN, TRANSIT, IDS, GRAPHS, CREATION_CASES, permutations, createHarness,
    semanticLinks, expectApplied, seedAppliedGraph, copy };
