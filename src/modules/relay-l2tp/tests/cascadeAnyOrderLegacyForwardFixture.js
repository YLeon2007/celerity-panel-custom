'use strict';
// Local persistence and held physical observations only. Never opens Mongo/SSH,
// starts services, enrolls a runner, or claims operational writer exclusion.
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const configPath = require.resolve('../../../../config');
require.cache[configPath] = { id: configPath, filename: configPath, loaded: true,
    exports: { panel: { domain: 'legacy-forward.invalid' }, xray: {} } };
const loggerPath = require.resolve('../../../utils/logger');
require.cache[loggerPath] = { id: loggerPath, filename: loggerPath, loaded: true,
    exports: { info() {}, warn() {}, error() {} } };
const generator = require('../../../services/configGenerator');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const copy = value => structuredClone(value);
const key = (node, profile) => `${node}:${profile}`;
const targets = {
    'xray-main': { targetProfile: 'xray-main', configPath: '/usr/local/etc/xray/config.json',
        serviceUnit: 'xray.service', serviceUnitPath: '/etc/systemd/system/xray.service' },
    'xray-bridge': { targetProfile: 'xray-bridge', configPath: '/usr/local/etc/xray-bridge/config.json',
        serviceUnit: 'xray-bridge.service', serviceUnitPath: '/etc/systemd/system/xray-bridge.service' },
};
function freeze(value) {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
}
function canonical(value) {
    return Array.isArray(value) ? value.map(canonical)
        : value && typeof value === 'object'
            ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
}
function candidate(config) {
    const bytes = Buffer.from(`${JSON.stringify(canonical(config))}\n`);
    return { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
        bytes: [...bytes], sha256: sha(bytes) };
}
// Query-aware local double: owner uniqueness really is (node, profile), not
// node alone. Private descriptors are absent unless explicitly selected.
function model(rows, db) {
    const matches = (row, filter) => Object.entries(filter).every(([field, value]) =>
        value?.$in ? value.$in.includes(row[field]) : same(row[field], value));
    const query = work => {
        let imported = false;
        const q = { select(fields) { imported ||= fields.split(/\s+/).includes('+legacyAppliedTopology'); return q; },
            session() { return q; }, read() { return q; }, readConcern() { return q; }, maxTimeMS() { return q; },
            async lean() {
                const result = copy(work());
                if (!imported) for (const row of Array.isArray(result) ? result : [result]) if (row) delete row.legacyAppliedTopology;
                return result;
            }, then(a, b) { return q.lean().then(a, b); } };
        return q;
    };
    return { rows, db,
        collection: { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] },
        async create(docs) {
            for (const doc of docs) {
                if (rows.some(row => row.node === doc.node && row.profile === doc.profile)) {
                    throw Object.assign(Error('duplicate owner profile'), { code: 11000 });
                }
                rows.push(copy(doc));
            }
            return copy(docs);
        },
        find: filter => query(() => rows.filter(row => matches(row, filter))),
        findById: value => query(() => rows.find(row => row._id === value) || null),
        findOne: filter => query(() => rows.find(row => matches(row, filter)) || null),
        findOneAndUpdate: (filter, change) => query(() => {
            const row = rows.find(row => matches(row, filter));
            if (!row) return null;
            Object.assign(row, copy(change.$set || {}));
            for (const field of Object.keys(change.$unset || {})) delete row[field];
            return row;
        }),
    };
}
function forwardFixture(security = 'none') {
    const session = { inTransaction: () => true }, db = { transaction: work => work(session) };
    const nodes = ['portal', 'bridge'].map((role, index) => ({ id: id(index + 1), role,
        type: 'xray', active: true, ip: `192.0.2.${index + 1}`, port: 24443,
        xray: { inboundTag: 'client-in', security: 'none', transport: 'tcp', extraInbounds: [] } }));
    const link = { id: id(10), source: nodes[0].id, target: nodes[1].id, mode: 'forward', active: true,
        tunnelPort: 25000, tunnelUuid: '11111111-1111-4111-8111-111111111111',
        tunnelSecurity: security, tunnelTransport: 'tcp', priority: 1,
        ...(security === 'reality' ? { realityPrivateKey: 'modeled-private-not-a-real-key',
            realityPublicKey: 'modeled-public-not-a-real-key', realityShortIds: ['1234abcd'],
            realityDest: 'decoy.invalid:443', realitySni: ['decoy.invalid'], realityFingerprint: 'chrome' } : {}) };
    const metadata = node => ({ ...copy(node), _id: node.id, cascadeRole: node.role });
    const populated = { ...copy(link), _id: link.id, portalNode: metadata(nodes[0]), bridgeNode: metadata(nodes[1]) };
    const bases = new Map(), physical = new Map();
    for (const [index, node] of nodes.entries()) {
        const base = JSON.parse(generator.generateXrayConfig(metadata(node), []));
        base.inbounds.find(inbound => inbound.tag === 'client-in').settings.clients.push({
            id: `${index + 8}`.repeat(8) + '-8888-4888-8888-888888888888', email: `${node.role}-existing@invalid` });
        base.inbounds.push({ tag: 'unrelated-ingress', listen: '127.0.0.1', port: 27000,
            protocol: 'socks', settings: { auth: 'noauth', udp: false } });
        base.outbounds.push({ tag: 'unrelated-out', protocol: 'blackhole' });
        base.routing.rules.push({ type: 'field', inboundTag: ['unrelated-ingress'], outboundTag: 'unrelated-out' });
        base.policy = { levels: { 0: { statsUserUplink: true } } };
        bases.set(node.id, copy(base));
        const installed = copy(base);
        if (node.role === 'portal') generator.applyForwardChain(installed, [populated], ['client-in']);
        else generator.applyForwardHopInbound(installed, [populated]);
        node.profileConfig = JSON.stringify(installed, null, 2) + '\n';
        physical.set(key(node.id, 'xray-main'), { config: node.profileConfig,
            unit: `modeled-main-unit-${node.id}\n`, active: 'active', enabled: 'enabled' });
        // Independently observed unrelated SIDECAR content. It is nonempty too:
        // a future native listener must not overwrite these existing users or
        // rules merely because no classic forward hop lives in this profile.
        const sidecar = copy(base);
        sidecar.inbounds.forEach(inbound => { if (inbound.port) inbound.port += 100; });
        physical.set(key(node.id, 'xray-bridge'), { config: JSON.stringify(sidecar, null, 2) + '\n',
            unit: `modeled-sidecar-unit-${node.id}\n`, active: 'active', enabled: 'enabled' });
    }
    const topology = { nodes, links: [link], groups: [] }, Owner = model([], db), observed = [];
    let held = false;
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Owner,
        withVerifiedMaintenance: async ({ binding }, work) => {
            held = true;
            const current = physical.get(key(binding.node, binding.profile));
            assert.ok(current, 'no absent-profile or role-derived physical evidence');
            observed.push({ node: binding.node, profile: binding.profile, generation: binding.generation });
            try {
                await work({ status: 'verified', authority: 'external-maintenance-v1', binding: copy(binding),
                    proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
                    oldBackend: { instanceId: 'modeled-classic', pid: 42, processStartTime: 'modeled-start',
                        processTree: 'stopped', dispatch: 'disabled' },
                    readback: { source: 'node-readback', configSha256: sha(current.config), unitSha256: sha(current.unit),
                        serviceActive: current.active, serviceEnabled: current.enabled } });
                held = false;
            } catch (error) { throw error; } // Model retained exclusion on unknown/refused work.
        } });
    const identity = node => ({ machineId: (nodes.indexOf(node) + 1).toString().repeat(32),
        sshHostKeySha256: (nodes.indexOf(node) + 1).toString().repeat(64) });
    const initialize = (node, profile) => transfer.initializeClassic({ node: node.id, profile, nodeIdentity: identity(node) });
    const adopt = async (node, profile, legacyTopology) => {
        const classic = await initialize(node, profile);
        return transfer.adopt({ node: node.id, profile, generation: classic.generation,
            proofRef: 'modeled-held-exact-forward-profile', ...(legacyTopology ? { legacyTopology } : {}) });
    };
    return { nodes, link, topology, bases, physical, Owner, transfer, observed, initialize, adopt,
        held: () => held, db, session };
}
module.exports = { forwardFixture, generator, context, id, key, sha, copy, model, targets, freeze, candidate };
