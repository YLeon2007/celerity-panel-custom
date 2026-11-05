'use strict';
// TEST-only: synthesized PEM input, generated once before these tests were
// written. No live credentials/certificates, TLS sockets or certificate framework.
// Actual public transfer + selected default host/queue/worker/finalizer;
// persistence, executor transport, maintenance and physical exclusion MODELED.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const sift = require('sift').default;
const { fixture, app, request, settleTick, id, sha, copy, context, provider } = require('./cascadeAnyOrderRuntimeFixture');
const generator = require('../../../services/configGenerator');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { NODE_METADATA_SELECT } = require('../services/topologyOperationPlanMaterializer');
const HyNode = require('../../../models/hyNodeModel');
const Owner = require('../../../models/topologyConfigOwnerModel');
const TEST_CERT = "-----BEGIN CERTIFICATE-----\nMIIBozCCAUmgAwIBAgIUIEi/yyqmCdjIOf7zc7CxreqsRl8wCgYIKoZIzj0EAwIw\nJzElMCMGA1UEAwwcbWFudWFsLXRscy1URVNULW9ubHkuaW52YWxpZDAeFw0yNjEx\nMDUxMzQxMDdaFw0yNjExMDYxMzQxMDdaMCcxJTAjBgNVBAMMHG1hbnVhbC10bHMt\nVEVTVC1vbmx5LmludmFsaWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASFhbGd\n0kUt9VQRmQH7eQUiKaB5jWd+3oF4osl0wstdOYF/ViwYTCjdxlMV3jNMzp2l8YOF\nqiUWOp4K63ON6dOCo1MwUTAdBgNVHQ4EFgQUt1GOhmzRSKa16HfgI8M8rY/YuEMw\nHwYDVR0jBBgwFoAUt1GOhmzRSKa16HfgI8M8rY/YuEMwDwYDVR0TAQH/BAUwAwEB\n/zAKBggqhkjOPQQDAgNIADBFAiEA1EAthzOGK8XLiADXrV+980UQQeNxQM6eJHWg\njOj1w6gCIDt6qFXZTXjUCrV+GZP4GqI5kqEKT2DDQr5gAlXuV79v\n-----END CERTIFICATE-----\n";
const TEST_KEY = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDuGxhuZ0JhRQRhzL\nYdEbi61EgLP2Q+WySTfTguSQbIGhRANCAASFhbGd0kUt9VQRmQH7eQUiKaB5jWd+\n3oF4osl0wstdOYF/ViwYTCjdxlMV3jNMzp2l8YOFqiUWOp4K63ON6dOC\n-----END PRIVATE KEY-----\n";
const plain = value => JSON.parse(JSON.stringify(value));
const get = (row, path) => path.split('.').reduce((value, part) => value?.[part], row);
function set(row, path, value) {
    const parts = path.split('.'); let target = row;
    for (const part of parts.slice(0, -1)) target = target[part] ||= {};
    target[parts.at(-1)] = copy(value);
}
function project(row, projection = {}) {
    const includes = Object.entries(projection).filter(([, value]) => value === 1);
    const result = includes.length ? {} : copy(row);
    if (includes.length && projection._id !== 0 && row._id !== undefined) result._id = copy(row._id);
    for (const [path] of includes) if (get(row, path) !== undefined) set(result, path, get(row, path));
    for (const [path, value] of Object.entries(projection)) if (value === 0) {
        const parts = path.split('.'), target = parts.slice(0, -1).reduce((v, k) => v?.[k], result);
        if (target) delete target[parts.at(-1)];
    }
    return result;
}
// REAL Mongoose query casting and select:false projection, native driver edge
// modeled in-process. Never a no-op select(). No connection/openUri is called.
function strictReads(target, source, rows, queries) {
    const connection = mongoose.createConnection();
    const schema = source.schema.clone();
    schema.set('bufferCommands', false); schema.set('autoIndex', false); schema.set('autoCreate', false);
    const Model = connection.model(source.modelName, schema);
    const choose = (filter, options) => {
        queries.push({ model: source.modelName, filter: plain(filter), projection: copy(options.projection || {}) });
        return rows.filter(sift(plain(filter))).map(row => project(row, options.projection));
    };
    Model.collection.buffer = false;
    Model.collection.collection = {
        find: (filter, options = {}) => ({ toArray: async () => choose(filter, options) }),
        findOne: async (filter, options = {}) => choose(filter, options)[0] || null,
    };
    for (const method of ['find', 'findOne', 'findById']) target[method] = Model[method].bind(Model);
    return connection;
}
function otherConfig(node) {
    return JSON.stringify({ inbounds: [{ tag: 'independent-other-profile', port: 28000, protocol: 'socks', settings: { auth: 'noauth', udp: false } }],
        outbounds: [{ tag: 'independent-other-block', protocol: 'blackhole' }],
        routing: { rules: [{ type: 'field', inboundTag: ['independent-other-profile'], outboundTag: 'independent-other-block' }] },
        remarks: `TEST-only independent ${node}` }, null, 2) + '\n';
}
async function manualTlsFixture(variant = 'primary') {
    const f = fixture({ roles: ['portal', 'bridge'] });
    // Clear inherited synthetic ownership BEFORE any host or reader can see it.
    f.data.TopologyConfigOwner.length = 0;
    const queries = [], connections = [];
    for (const node of f.data.HyNode) Object.assign(node, { name: `TEST-only-${node.cascadeRole}`, domain: 'manual-tls-TEST-only.invalid',
        xray: { security: 'none', transport: 'tcp', inboundTag: 'client-in', extraInbounds: [] } });
    const portal = f.data.HyNode[0];
    Object.assign(portal.xray, { tlsSource: 'manual', manualCert: TEST_CERT, manualKey: TEST_KEY,
        alpn: ['http/1.1', 'h2'], flow: 'xtls-rprx-vision', security: variant === 'primary' ? 'tls' : 'none' });
    if (variant === 'extra') portal.xray.extraInbounds = [{ inboundTag: 'tls-extra', port: 24444, protocol: 'vless',
        security: 'tls', transport: 'tcp', alpn: ['h2', 'http/1.1'], flow: 'xtls-rprx-vision' }];
    connections.push(strictReads(f.models.HyNode, HyNode, f.data.HyNode, queries));
    connections.push(strictReads(f.models.TopologyConfigOwner, Owner, f.data.TopologyConfigOwner, queries));
    const rows = await f.models.HyNode.find({}).select(NODE_METADATA_SELECT).lean();
    const nodes = rows.map(({ _id, cascadeRole, ...rest }) => ({ ...copy(rest), id: _id, role: cascadeRole }));
    const link = { id: id(10), name: `TEST-${id(10)}`, source: id(1), target: id(2), mode: 'reverse', active: true,
        tunnelPort: 25000, tunnelUuid: '11111111-1111-4111-8111-111111111111', tunnelSecurity: variant === 'extra' ? 'reality' : 'none',
        tunnelTransport: 'tcp', tunnelDomain: 'old-tunnel.invalid', priority: 1,
        ...(variant === 'extra' ? { realityPrivateKey: 'TEST-only-reality-private', realityPublicKey: 'TEST-only-reality-public',
            realityShortIds: ['1234abcd'], realityDest: 'decoy.invalid:443', realitySni: ['decoy.invalid'], realityFingerprint: 'chrome' } : {}) };
    const populated = { ...copy(link), _id: link.id, portalNode: { ...nodes[0], _id: nodes[0].id }, bridgeNode: { ...nodes[1], _id: nodes[1].id } };
    const users = [{ xrayUuid: '88888888-8888-4888-8888-888888888888', userId: 'TEST-kept@invalid' }];
    for (const node of nodes) {
        let config;
        if (node.role === 'portal') {
            config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, users));
            generator.applyReversePortal(config, [populated], ['client-in', ...(variant === 'extra' ? ['tls-extra'] : [])]);
        } else config = JSON.parse(generator.generateCombinedBridgeConfig([populated]));
        config.inbounds ||= [];
        config.inbounds.push({ tag: 'unrelated-client', port: 27000, protocol: 'vless', settings: { decryption: 'none',
            clients: [{ id: '99999999-9999-4999-8999-999999999999', email: 'TEST-unrelated@invalid', flow: 'xtls-rprx-vision' }] } });
        config.outbounds.push({ tag: 'unrelated-out', protocol: 'blackhole' });
        config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-client'], outboundTag: 'unrelated-out' });
        config.policy = { levels: { 0: { statsUserUplink: true } } };
        node.profileConfig = JSON.stringify(config, null, 2) + '\n';
    }
    const topology = { nodes, links: [link], groups: [] };
    f.data.CascadeLink.push(...[link, { ...link, id: id(90), tunnelPort: 25990, status: 'pending' },
        { ...link, id: id(91), tunnelPort: 25991, active: false, status: 'online' }].map(({ id, source, target, ...rest }) =>
        ({ ...copy(rest), _id: id, portalNode: source, bridgeNode: target, status: rest.status || 'online', name: `TEST-${id}` })));
    const profileFor = node => node === id(1) ? 'xray-main' : 'xray-bridge';
    const key = (node, profile) => `${node}/${profile}`;
    const physical = new Map(nodes.flatMap(node => [
        [key(node.id, profileFor(node.id)), node.profileConfig],
        [key(node.id, profileFor(node.id) === 'xray-main' ? 'xray-bridge' : 'xray-main'), otherConfig(node.id)],
    ]));
    const originals = copy([...physical]);
    let maintenanceCalls = 0, adoptionCAS = 0;
    const Model = f.models.TopologyConfigOwner;
    Model.collection = { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] };
    // Dedicated persistence seam honors the real compound node/profile index.
    Model.create = async docs => {
        for (const doc of docs) {
            const validated = new Owner(doc); await validated.validate();
            assert.equal(f.data.TopologyConfigOwner.some(row => row.node === doc.node && row.profile === doc.profile), false);
            f.data.TopologyConfigOwner.push(copy(doc));
        }
        return copy(docs);
    };
    const update = Model.findOneAndUpdate.bind(Model);
    Model.findOneAndUpdate = (filter, changes, options) => {
        if (changes.$set?.owner === 'topology') adoptionCAS++;
        return update(filter, changes, options);
    };
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Model,
        withVerifiedMaintenance: async ({ binding }, work) => {
            maintenanceCalls++;
            return work({ status: 'verified', authority: 'external-maintenance-v1', binding: copy(binding),
                proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
                oldBackend: { instanceId: 'MODELED-classic', pid: 42, processStartTime: 'MODELED-start', processTree: 'stopped', dispatch: 'disabled' },
                readback: { source: 'node-readback', configSha256: sha(physical.get(key(binding.node, binding.profile))),
                    unitSha256: sha('TEST-modeled-unit'), serviceActive: 'active', serviceEnabled: 'enabled' } });
        } });
    const initialize = (node, profile = profileFor(node)) => transfer.initializeClassic({ node, profile,
        nodeIdentity: { machineId: (node === id(1) ? '1' : '2').repeat(32), sshHostKeySha256: (node === id(1) ? '1' : '2').repeat(64) } });
    const adopt = async (node, snapshot = topology, profile = profileFor(node)) => {
        const classic = await initialize(node, profile);
        return transfer.adopt({ node, profile, generation: classic.generation, proofRef: 'TEST-modeled-held-readback',
            ...(snapshot === null ? {} : { legacyTopology: snapshot }) });
    };
    let host, runtime;
    async function start() {
        host = f.host(); provider.installActiveHost(host); f.http = app(f); host.start();
        runtime = f.deployments[0];
        const executor = runtime.operationWorker.executor;
        const prepare = executor.prepare.bind(executor), commit = executor.commit.bind(executor);
        executor.prepare = async input => ({ ...await prepare(input), before: physical.get(key(String(input.node.node), input.node.targetProfile)) });
        executor.commit = async input => {
            await commit(input);
            const candidate = Buffer.from(input.node.candidate.bytes).toString('utf8');
            const target = key(String(input.node.node), input.node.targetProfile);
            // Explicitly MODELED byte-aware transport: no-op/restart observations
            // are not real Xray, runner/systemd or physical acceptance.
            f.calls.push([physical.get(target) === candidate ? 'modeled-noop' : 'modeled-write-restart', target]);
            physical.set(target, candidate); return { ok: true };
        };
        executor.verify = async input => {
            assert.equal(sha(physical.get(key(String(input.node.node), input.node.targetProfile))), input.node.candidateHash);
            return { ok: true };
        };
        return runtime;
    }
    const read = async (linkId = id(10)) => runtime.topologyRepository.readSelected({ snapshot: await runtime.topologyRepository.snapshotReader.readDraft(),
        scope: { kind: 'link.apply', linkId }, executionContext: context });
    async function drain(response) {
        assert.equal(response.status, 202, JSON.stringify(response.body));
        for (let i = 0; i < 8; i++) await settleTick(f);
        const job = f.data.TopologyCreateIntent.find(row => row._id === response.body.job.jobId);
        assert.equal(job?.status, 'succeeded', JSON.stringify({ job, operations: f.data.TopologyOperation.map(op => ({ status: op.status, error: op.error })) }));
        const op = f.data.TopologyOperation.find(row => row._id === job.operationId);
        assert.equal(op.status, 'succeeded'); assert.equal(op.heldTopologyAdmission, false);
        assert.equal(f.data.NodeOperationLock.length, 0);
        return op;
    }
    const deployRequest = (linkId = id(10), requestKey = randomUUID()) => request(f.http, 'POST', '/topology/deploy',
        { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision, linkId }, requestKey);
    return Object.assign(f, { topology, physical, originals, queries, transfer, initialize, adopt, start, read, drain, deployRequest,
        profileFor, key, stats: () => ({ maintenanceCalls, adoptionCAS }),
        deploy: linkId => deployRequest(linkId).then(drain),
        remove: linkId => request(f.http, 'DELETE', `/links/${linkId}`, { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision }, randomUUID()).then(drain),
        close: async () => { if (host) { provider.clearActiveHost(host); await host.stop(); } for (const connection of connections) await connection.close(); },
    });
}
module.exports = { manualTlsFixture, TEST_CERT, TEST_KEY, NODE_METADATA_SELECT, id, copy, sha, request };
