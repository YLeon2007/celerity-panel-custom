'use strict';
// LOCAL modeled pre-existing legacy inventory, not installed service evidence.
// Actual classic generators/public adoption/Mongoose schema and query casting;
// disconnected driver persistence, maintenance and config/unit/state IO MODELED.
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const mongoose = require('mongoose');
const sift = require('sift').default;
const configPath = require.resolve('../../../../../config');
require.cache[configPath] = { id: configPath, filename: configPath, loaded: true,
    exports: { panel: { domain: 'legacy-group.invalid' }, xray: {} } };
const loggerPath = require.resolve('../../../../utils/logger');
require.cache[loggerPath] = { id: loggerPath, filename: loggerPath, loaded: true,
    exports: { info() {}, warn() {}, error() {} } };
const generator = require('../../../../services/configGenerator');
const { finishClassicConfigRouting } = require('../../../../services/classicL2tpConfigComposition');
const { buildL2tpXrayFragment } = require('../../services/l2tpXrayFragmentProvider');
const { projectGroups } = require('../../domain/topologyDraft');
const { TopologyConfigTransfer } = require('../../../../services/topologyConfigTransfer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const copy = value => structuredClone(value);
const bson = value => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(value));
const key = (node, profile) => `${node}:${profile}`;
const profileFor = node => node.role === 'portal' ? 'xray-main' : 'xray-bridge';
function addUnrelated(config, index) {
    (config.inbounds ||= []).push({ tag: 'unrelated-client', port: 27000 + index, protocol: 'vless',
        settings: { decryption: 'none', clients: [{ id: '99999999-9999-4999-8999-999999999999', email: 'kept@invalid' }] } });
    config.outbounds.push({ tag: 'unrelated-out', protocol: 'freedom' });
    config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-client'], outboundTag: 'unrelated-out' });
    config.policy = { levels: { 0: { statsUserUplink: true } } };
    return config;
}
function installedGroupFixture(context = TEST) {
    const nodes = ['portal', 'relay', 'bridge'].map((role, i) => ({ id: id(i + 1), role, type: 'xray', active: true,
        ip: `192.0.2.${i + 1}`, port: 24443 + i,
        xray: { protocol: 'vless', security: 'none', transport: 'tcp', inboundTag: 'client-in', extraInbounds: [] } }));
    const links = nodes.slice(1).map((node, i) => ({ id: id(10 + i), source: nodes[i].id, target: node.id,
        mode: 'reverse', active: true, tunnelProtocol: 'vless', tunnelSecurity: 'none', tunnelTransport: 'tcp',
        tunnelPort: 25000 + i, tunnelUuid: `${i + 1}`.repeat(8) + '-1111-4111-8111-111111111111',
        tunnelDomain: 'legacy-group.invalid', priority: 1 }));
    const group = { _id: id(60), name: 'modeled-preexisting-group', mode: 'reverse', strategy: 'priority-failover',
        paths: [{ pathKey: 'legacy-main', linkIds: [links[1].id], priority: 4, enabled: true }] };
    const groups = projectGroups([group]), path = groups[0].paths[0];
    const metadata = node => ({ ...node, _id: node.id, cascadeRole: node.role });
    const populated = links.map(link => ({ ...link, _id: link.id,
        portalNode: metadata(nodes.find(node => node.id === link.source)),
        bridgeNode: metadata(nodes.find(node => node.id === link.target)) }));
    for (const [index, node] of nodes.entries()) {
        let config;
        if (node.role === 'portal') {
            config = JSON.parse(generator.generateXrayConfig(metadata(node), []));
            config.inbounds.find(row => row.tag === 'client-in').settings.clients.push({
                id: '88888888-8888-4888-8888-888888888888', email: 'legacy@invalid' });
            generator.applyReversePortal(config, [populated[0]], ['client-in']);
        } else if (node.role === 'relay') {
            // Match the REAL classic writer order. The fourth generator argument
            // would move ingress before IPv6 refusal and is NOT equivalent.
            config = JSON.parse(generator.generateRelayConfig(populated[0], populated[0].portalNode, [populated[1]]));
            generator.applyCascadePathIngress(config, [{ pathKey: path.pathKey, port: path.cascadePathIngress.port,
                egressTag: `portal-down-${links[1].id.slice(-8)}` }]);
            finishClassicConfigRouting(config);
        } else config = JSON.parse(generator.generateCombinedBridgeConfig([populated[1]]));
        node.profileConfig = JSON.stringify(addUnrelated(config, index), null, 2) + '\n';
    }
    const topology = { nodes, links, groups };
    // These state/users/sync rows are MODELED PRE-EXISTING LEGACY INVENTORY.
    // They are NOT generated by adoption or a fabricated topology settlement.
    const state = { _id: id(70), node: id(2), routeGroup: group._id, activePathKey: path.pathKey,
        status: 'installed', desiredState: 'installed', secretRevision: 41, appliedTopologyRevision: 7,
        pskEncrypted: 'synthetic-fixture-private-psk', clientCidr: '10.255.30.0/24', localAddress: '10.255.30.1',
        poolStart: '10.255.30.10', poolEnd: '10.255.30.250', dnsServers: ['1.1.1.1'],
        tproxyPort: 12345, fwmark: 100, routeTable: 100, mtu: 1400, mru: 1400 };
    const users = [{ _id: id(80), relayNode: id(2), login: 'synthetic-fixture-user', passwordEncrypted: 'synthetic-fixture-private',
        ip: '10.255.30.10', enabled: true, desiredRevision: 41, appliedRevision: 41, syncStatus: 'synced', syncOperationId: id(81) }];
    const syncFacts = [{ _id: id(81), node: id(2), kind: 'sync_users', status: 'succeeded',
        plan: { operationId: id(81), relayId: id(2), desired: { credentialRevision: 41 } } }];
    const physical = new Map();
    for (const [index, node] of nodes.entries()) {
        physical.set(key(node.id, profileFor(node)), { config: node.profileConfig, unit: `modeled-selected-unit-${index}\n`, active: 'active', enabled: 'enabled' });
        const other = profileFor(node) === 'xray-main' ? 'xray-bridge' : 'xray-main';
        const fragment = node.role !== 'relay' ? [] : [buildL2tpXrayFragment({
            plan: { relay: { controlPlaneIps: [node.ip] }, group: { id: group._id }, selectedPathKey: path.pathKey,
                paths: [{ pathKey: path.pathKey, healthy: true, outboundTag: path.cascadePathIngress.tag }] },
            tags: { inbound: `relay-l2tp-${group._id}`, blockOutbound: 'block' }, tproxyPort: state.tproxyPort })];
        const config = JSON.parse(generator.generateXrayConfig(metadata(node), [], { fragments: fragment }));
        config.inbounds.find(row => row.tag === 'client-in').settings.clients.push({
            id: '77777777-7777-4777-8777-777777777777', email: 'independent@invalid' });
        finishClassicConfigRouting(config);
        physical.set(key(node.id, other), { config: JSON.stringify(addUnrelated(config, 10 + index), null, 2) + '\n',
            unit: `modeled-independent-unit-${index}\n`, active: 'active', enabled: 'enabled' });
    }
    const connection = mongoose.createConnection(); // Never connected, no Mongo.
    const session = { inTransaction: () => true, client: connection.getClient() };
    const events = [], data = {}, calls = [];
    let held = false;
    // Reusable by B/C: REAL same-root schema/query/BSON, modeled native driver.
    function model(name, source, initial = []) {
        const schema = source.schema.clone(); schema.set('autoCreate', false); schema.set('autoIndex', false);
        const Model = connection.model(name, schema, name);
        const rows = data[name] = initial.map(bson);
        const project = (row, options = {}) => {
            if (!row) return null;
            const result = bson(row), projection = options.projection || {};
            const inclusive = Object.entries(projection).filter(([k, v]) => v === 1 && k !== '_id');
            if (inclusive.length) {
                const pick = (value, paths) => {
                    if (Array.isArray(value)) return value.map(item => pick(item, paths));
                    if (!value || typeof value !== 'object') return value;
                    const selected = {};
                    for (const [k, v] of Object.entries(value)) {
                        if (paths.includes(k)) selected[k] = v;
                        else {
                            const children = paths.filter(path => path.startsWith(`${k}.`)).map(path => path.slice(k.length + 1));
                            if (children.length) selected[k] = pick(v, children);
                        }
                    }
                    return selected;
                };
                const projected = pick(result, inclusive.map(([k]) => k));
                if (projection._id !== 0 && result._id !== undefined) projected._id = result._id;
                return projected;
            }
            const remove = (value, parts) => {
                if (Array.isArray(value)) { for (const item of value) remove(item, parts); return; }
                if (!value || typeof value !== 'object') return;
                if (parts.length === 1) delete value[parts[0]];
                else remove(value[parts[0]], parts.slice(1));
            };
            for (const [k, v] of Object.entries(projection)) if (v === 0) remove(result, k.split('.'));
            return result;
        };
        const record = (method, filter = {}, options = {}, update) => events.push({ name, method,
            filter: bson(filter), options: { ...options }, ...(update ? { update: bson(update) } : {}), held });
        const matches = (row, filter) => Object.entries(filter).every(([k, v]) => k.startsWith('$') || k.includes('.')
            || v && typeof v === 'object' && Object.keys(v).some(field => field.startsWith('$'))
            ? sift({ [k]: v })(row) : same(row[k], v));
        Model.collection.buffer = false;
        Model.collection.collection = {
            async indexes() { record('indexes'); return schema.indexes().map(([key, options]) => ({ key, ...options })); },
            async insertOne(doc, options) { record('insertOne', {}, options); rows.push(bson(doc)); return { acknowledged: true, insertedId: doc._id }; },
            async findOne(filter, options) { record('findOne', filter, options); return project(rows.find(row => matches(row, filter)), options); },
            find(filter, options) { record('find', filter, options); return { toArray: async () => rows.filter(row => matches(row, filter)).map(row => project(row, options)) }; },
            async findOneAndUpdate(filter, update, options) {
                record('findOneAndUpdate', filter, options, update);
                const row = rows.find(row => matches(row, filter)); if (!row) return null;
                const before = bson(row);
                for (const [k, v] of Object.entries(update.$set || {})) row[k] = bson({ v }).v;
                for (const k of Object.keys(update.$unset || {})) delete row[k];
                return project(options.returnDocument === 'after' ? row : before, options);
            },
        };
        return Model;
    }
    connection.transaction = async (work, options) => {
        events.push({ method: 'transaction', options, held });
        return work(session); // Transaction-SHAPED only; no atomicity claim.
    };
    const Owner = model('TopologyConfigOwner', require('../../../../models/topologyConfigOwnerModel'));
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Owner,
        async withVerifiedMaintenance({ binding }, work) {
            held = true;
            const observed = physical.get(key(binding.node, binding.profile));
            assert.ok(observed, 'modeled independent readback must exist');
            try {
                await work({ status: 'verified', authority: 'external-maintenance-v1', binding: copy(binding),
                    proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
                    oldBackend: { instanceId: 'modeled-legacy', pid: 42, processStartTime: 'modeled-start', processTree: 'stopped', dispatch: 'disabled' },
                    readback: { source: 'node-readback', configSha256: sha(observed.config), unitSha256: sha(observed.unit),
                        serviceActive: observed.active, serviceEnabled: observed.enabled } });
            } finally { held = false; }
        } });
    const initialize = (node, profile = profileFor(node)) => transfer.initializeClassic({ node: node.id, profile,
        nodeIdentity: { machineId: String(nodes.indexOf(node) + 1).repeat(32), sshHostKeySha256: String(nodes.indexOf(node) + 1).repeat(64) } });
    const adopt = async (node, proposed = topology, profile = profileFor(node)) => {
        const classic = await initialize(node, profile);
        return transfer.adopt({ node: node.id, profile, generation: classic.generation,
            proofRef: 'modeled-preexisting-legacy-readback', ...(proposed === null ? {} : { legacyTopology: proposed }) });
    };
    const desiredLinks = links.map(({ id: _id, source, target, ...rest }) =>
        ({ ...copy(rest), _id, portalNode: source, bridgeNode: target, status: 'online' }));
    const inventory = { label: 'MODELED_PREEXISTING_LEGACY_INVENTORY', groups: [group,
        { _id: id(61), name: 'unrelated-preserved-group', mode: 'reverse', strategy: 'priority-failover', paths: [] }],
        states: [state], users, syncFacts,
        nodes: nodes.map(({ id: _id, role: cascadeRole, profileConfig, ...rest }) => ({ ...copy(rest), _id, cascadeRole })),
        links: [...desiredLinks,
            { ...copy(desiredLinks[0]), _id: id(90), status: 'pending', tunnelPort: 25990 },
            { ...copy(desiredLinks[0]), _id: id(91), active: false, status: 'offline', tunnelPort: 25991 }] };
    return { context, topology, group, state, users, syncFacts, inventory, populated, physical, key, profileFor,
        Owner, model, connection, session, data, events, calls, transfer, initialize, adopt, held: () => held };
}
module.exports = { installedGroupFixture, id, sha, copy, bson, key, profileFor, generator };
