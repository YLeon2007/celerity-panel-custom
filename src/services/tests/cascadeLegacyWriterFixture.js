'use strict';

// Actual services/generators/fence/ownership reader; persistence and SSH are
// explicit local maps. No application config/.env, DB, agent or shell is loaded.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { randomUUID } = require('node:crypto');
const sift = require('sift').default;
const { Types } = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const MAIN = '/usr/local/etc/xray/config.json';
const BRIDGE = '/usr/local/etc/xray-bridge/config.json';
const enabled = { PANEL_DOMAIN: PROD.hostIdentity, L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false' };
async function withEnv(values, work) {
    const prior = { ...process.env };
    try { Object.assign(process.env, enabled, values); return await work(); }
    finally { for (const key of Object.keys(process.env)) if (!(key in prior)) delete process.env[key]; Object.assign(process.env, prior); }
}
function node(n, role = 'portal') {
    return { _id: id(n), name: `node-${n}`, ip: `192.0.2.${n}`, type: 'xray', active: true, cascadeRole: role,
        ssh: { password: 'local-dummy' }, xray: { security: 'none', transport: 'tcp', inboundTag: 'clients', port: 443 } };
}
function link(n, source, target, fields = {}) {
    return { _id: id(n), name: `link-${n}`, portalNode: source._id, bridgeNode: target._id, active: true,
        mode: 'reverse', status: 'online', autoDeploy: false, tunnelPort: 11000 + n,
        tunnelUuid: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
        tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelDomain: 'reverse.tunnel.internal', priority: n, ...fields };
}
function fixture({ nodes = [node(1), node(2, 'bridge'), node(3), node(4, 'bridge')], links,
    onExec, onOwnerRead, onFindLinks } = {}) {
    links ||= [link(10, nodes[0], nodes[1])];
    const locks = new Map(), owners = [], operations = [], events = [], files = new Map();
    const users = [{ userId: 'preserved-user', xrayUuid: '11111111-1111-4111-8111-111111111111' }];
    const row = key => nodes.find(n => n._id === String(key?._id || key));
    const key = (nodeId, file) => `${nodeId}:${file}`;
    const query = (read, populated = '') => ({
        populate(fields) { return query(read, fields); },
        select() { return this; }, setOptions() { return this; },
        lean() { return this.then(value => structuredClone(value)); },
        then(resolve, reject) { return Promise.resolve().then(async () => {
            let result = await read();
            if (populated) result = result.map(item => {
                const copy = { ...item };
                for (const field of populated.split(' ')) if (copy[field]) copy[field] = row(copy[field]);
                return copy;
            });
            return result;
        }).then(resolve, reject); },
    });
    const Lock = {
        async create(value) {
            events.push({ kind: 'acquire', node: String(value.node), generation: value.generation });
            if (locks.has(String(value.node))) throw Object.assign(new Error('duplicate'), { code: 11000 });
            locks.set(String(value.node), structuredClone(value)); return value;
        },
        findOne({ node: nodeId }) { return query(() => locks.get(String(nodeId)) || null); },
        async deleteOne(filter) {
            events.push({ kind: 'release', ...filter });
            const value = locks.get(String(filter.node));
            if (!value || !sift(filter)(value)) return { deletedCount: 0 };
            locks.delete(String(filter.node)); return { deletedCount: 1 };
        },
    };
    const Link = {
        find(filter) { return query(async () => {
            events.push({ kind: 'links', filter });
            await onFindLinks?.({ filter, locks, links });
            return links.filter(sift(filter));
        }); },
        exists(filter) { return query(() => links.find(sift(filter)) || null); },
        async updateOne(filter, update) {
            const current = links.find(sift(filter));
            if (current) Object.assign(current, update.$set);
            return { acknowledged: true, matchedCount: current ? 1 : 0 };
        },
    };
    const Node = { findById: nodeId => query(() => row(nodeId)), updateOne: async () => ({ acknowledged: true, matchedCount: 1 }) };
    const noop = () => {};
    const logger = { info: noop, warn: noop, error: noop, debug: noop };
    const cache = { invalidateNodes: async () => {}, invalidateAllSubscriptions: async () => {}, invalidateDashboardCounts: async () => {} };
    class SSH {
        constructor(target) { this.node = target; }
        async connect() { events.push({ kind: 'connect', node: this.node._id }); }
        disconnect() { events.push({ kind: 'disconnect', node: this.node._id }); }
        async uploadContent(content, file) {
            events.push({ kind: 'upload', node: this.node._id, file });
            files.set(key(this.node._id, file), content);
        }
        async exec(command) {
            events.push({ kind: 'exec', node: this.node._id, command });
            const overridden = await onExec?.({ node: this.node, command, locks, events });
            if (overridden !== undefined) return overridden;
            const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/)?.[0];
            const output = command.includes('command -v xray') ? '/usr/bin/xray\n'
                : command.includes('is-active xray-bridge') ? 'active\n' : '';
            return { code: 0, stdout: output + (receipt ? `\n${receipt}\n` : ''), stderr: '' };
        }
    }
    const native = { Types, connection: { db: { collection(name) {
        assert.equal(name, 'topologyconfigowners');
        return { find(filter, options) { return { toArray: async () => {
            events.push({ kind: 'owners', node: String(filter.node), options });
            await onOwnerRead?.({ nodeId: String(filter.node), locks, owners });
            return owners.filter(item => String(item.node) === String(filter.node));
        } }; } };
    } } } };
    const built = new Map();
    function load(name) {
        if (built.has(name)) return built.get(name).exports;
        const filename = path.resolve(__dirname, `../${name}.js`);
        const loaded = new Module(filename, module); loaded.filename = filename;
        loaded.paths = Module._nodeModulePaths(path.dirname(filename)); built.set(name, loaded);
        loaded.require = request => {
            if (request === 'mongoose') return native;
            if (request === '../../config') return {};
            if (request === '../utils/logger') return logger;
            if (request === '../utils/helpers') return { invalidateNodesCache: async () => {} };
            if (request === './cacheService') return cache;
            if (request === './webhookService' || request === './nodeSetup') return {};
            if (request === './nodeSSH') return SSH;
            if (['./cascadeService', './syncService', './configGenerator', './classicL2tpConfigComposition', './topologyConfigOwnership', './classicNodeConfigWrite'].includes(request)) return load(request.slice(2));
            if (request.endsWith('/nodeOperationLockModel')) return Lock;
            if (request.endsWith('/topologyOperationModel')) return { exists: filter => query(() => operations.find(sift(filter)) || null) };
            if (request.endsWith('/cascadeLinkModel')) return Link;
            if (request.endsWith('/hyNodeModel')) return Node;
            if (request.endsWith('/settingsModel') || request.endsWith('/hyUserModel')) return {};
            if (request.endsWith('/relayL2tpStateModel')) return { exists: async () => null };
            if (request.endsWith('/cascadeRouteGroupModel')) return { find: () => query(() => []) };
            // The service's invocation is exercised, but global undeploy admission
            // has its own completion suite; this fixture owns local node fences.
            if (request.endsWith('/legacyCascadeUndeploy')) return { trackLegacyCascadeUndeploy: work => work() };
            return Module.prototype.require.call(loaded, request);
        };
        loaded._compile(fs.readFileSync(filename, 'utf8'), filename); return loaded.exports;
    }
    const cascade = load('cascadeService'), sync = load('syncService'), fence = load('classicNodeConfigWrite');
    sync._getUsersForNode = async () => structuredClone(users);
    sync.checkXrayAgentHealth = async () => ({ online: true });
    sync._agentRequest = async () => { throw new Error('unexpected agent call'); };
    return { cascade, sync, fence, generator: load('configGenerator'), nodes, links, locks, owners, operations, users, events, files, key,
        adopt(nodeId, profile = 'xray-bridge') { owners.push({ node: nodeId, profile, executionContext: PROD,
            owner: 'topology', generation: randomUUID(), nodeIdentity: { machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) } }); },
        foreign(nodeId) { const winner = { node: nodeId, owner: 'l2tp', operationId: 'foreign-op', generation: randomUUID(),
            remoteUncertain: true, leaseUntil: new Date(0) }; locks.set(nodeId, winner); return structuredClone(winner); },
    };
}
module.exports = { fixture, withEnv, node, link, id, MAIN, BRIDGE };
