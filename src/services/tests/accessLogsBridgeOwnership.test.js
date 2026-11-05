'use strict';
// Actual access-log service, ownership reader, classic helper and lock
// repository/service; only persistence, settings/credentials and remote IO are
// modeled. No application config/.env, MongoDB, SSH, timers or services start.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const Module = require('node:module');
const path = require('node:path');
const fs = require('node:fs');
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { ObjectId } = require('mongoose').Types;
const sift = require('sift').default;
const ROOT = path.resolve(__dirname, '../../..');
const BRIDGE = '507f1f77bcf86cd799439011';
const OTHER = '507f1f77bcf86cd799439012';
const CONFIG = '/usr/local/etc/xray-bridge/config.json';
const MAIN = '/usr/local/etc/xray/config.json';
const ENV = { PANEL_DOMAIN: 'lm1.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'false', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false' };
const sha = value => createHash('sha256').update(value).digest('hex');
const clone = value => structuredClone(value);
async function withEnv(values, work) {
    const prior = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
    Object.assign(process.env, values);
    try { return await work(); } finally {
        for (const [key, value] of Object.entries(prior)) {
            if (value === undefined) delete process.env[key]; else process.env[key] = value;
        }
    }
}
function fixture(options = {}) {
    const events = [], locks = new Map(), owners = [], operations = [], cache = new Map();
    const node = id => ({ _id: id, name: `bridge-${id.slice(-2)}`, type: 'xray', active: true,
        cascadeRole: 'bridge', ip: '192.0.2.10', agentVersion: '1.4.0',
        xray: { accessLogs: { enabled: false, status: 'disabled', ingestTokenHash: 'dummy-hash' } } });
    const nodes = new Map([[BRIDGE, node(BRIDGE)]]);
    const link = (id, bridgeNode, status = 'online') => ({ _id: id, bridgeNode,
        portalNode: { _id: '507f1f77bcf86cd799439020', ip: '192.0.2.20' },
        active: true, status, mode: 'reverse', tunnelPort: 12000 + Number(id.slice(-1)),
        tunnelUuid: `00000000-0000-4000-8000-${id.slice(-12)}`, tunnelSecurity: 'none' });
    const links = [link('507f1f77bcf86cd799439031', BRIDGE), link('507f1f77bcf86cd799439032', BRIDGE)];
    const files = new Map();
    const settings = { accessLogs: { enabled: true, ingestUrl: 'https://panel.invalid/api/access-logs/ingest' } };
    const absolute = relative => path.resolve(ROOT, relative);
    const stubs = new Map();
    const stub = (relative, value) => stubs.set(absolute(relative), value);
    const quiet = { info() {}, warn() {}, error() {}, debug() {} };
    function setPath(target, key, value) {
        const parts = key.split('.');
        const last = parts.pop();
        for (const part of parts) target = target[part] ||= {};
        target[last] = clone(value);
    }
    stub('config.js', { BASE_URL: 'https://panel.invalid' });
    stub('src/utils/logger.js', quiet);
    stub('src/models/hyNodeModel.js', {
        find: async query => [...nodes.values()].filter(sift(query)).map(clone),
        findById: id => ({ select: async () => clone(nodes.get(String(id))) }),
        updateOne: async (query, update) => {
            events.push({ type: 'metadata', node: String(query._id), update: clone(update) });
            const row = nodes.get(String(query._id));
            for (const [key, value] of Object.entries(update.$set || {})) setPath(row, key, value);
            return { matchedCount: 1 };
        },
    });
    stub('src/models/settingsModel.js', { get: async () => clone(settings),
        update: async update => { for (const [key, value] of Object.entries(update)) setPath(settings, key, value); } });
    stub('src/services/accessLogs/credentialService.js', {
        ensureIngestToken: async () => ({ token: 'synthetic-token', created: false }),
        revokeIngestToken: async () => {},
    });
    stub('src/models/cascadeLinkModel.js', {
        exists: async query => links.find(sift(query)) || null,
        find: query => ({ populate: async () => {
            events.push({ type: 'links', query: clone(query) });
            return clone(links.filter(sift(query)));
        } }),
    });
    stub('src/modules/relay-l2tp/models/topologyOperationModel.js', {
        exists: async query => { events.push({ type: 'operations' }); return operations.find(sift(query)) || null; },
    });
    const lockModel = {
        create: async row => {
            events.push({ type: 'acquire', node: String(row.node) });
            await options.onAcquire?.(row, f);
            if (locks.has(String(row.node))) throw Object.assign(new Error('duplicate'), { code: 11000 });
            locks.set(String(row.node), clone(row));
            return clone(row);
        },
        findOne: ({ node }) => ({ lean: async () => clone(locks.get(String(node)) || null) }),
        deleteOne: async filter => {
            events.push({ type: 'release', filter: clone(filter) });
            const row = locks.get(String(filter.node));
            if (!row || !Object.entries(filter).every(([key, value]) => isDeepStrictEqual(row[key], value))) return { deletedCount: 0 };
            locks.delete(String(filter.node)); return { deletedCount: 1 };
        },
    };
    stub('src/modules/relay-l2tp/models/nodeOperationLockModel.js', lockModel);
    const mongoose = { Types: { ObjectId }, connection: { db: { collection(name) {
        assert.equal(name, 'topologyconfigowners');
        return { find(query, readOptions) {
            events.push({ type: 'owner-read', node: String(query.node), readOptions });
            return { toArray: async () => {
                if (options.ownerReadError) throw new Error('owner read unavailable');
                await options.onOwnerRead?.(f);
                return clone(owners.filter(row => String(row.node) === String(query.node)));
            } };
        } };
    } } } };
    class SSH {
        constructor(node) { this.node = node; }
        async connect() { events.push({ type: 'connect', node: this.node._id }); }
        disconnect() { events.push({ type: 'disconnect', node: this.node._id }); }
        async uploadContent(content, target) {
            events.push({ type: 'upload', node: this.node._id, target });
            await options.onUpload?.(this.node, f);
            if (options.uploadError) throw new Error('upload outcome unknown');
            files.set(`${this.node._id}:${target}`, content);
            return options.uploadResult;
        }
        async exec(command) {
            events.push({ type: 'exec', node: this.node._id, command });
            const configured = typeof options.execResult === 'function' ? options.execResult(command) : options.execResult;
            const target = command.match(/cat (\/usr\/local\/etc\/xray(?:-bridge)?\/config\.json)/)?.[1];
            // A read-only installed-file seam; do not fabricate a successful
            // readback independently of the bytes the test put on the node.
            return configured || { code: 0, stdout: target ? files.get(`${this.node._id}:${target}`) ?? 'C3_CLASSIC_PROFILE_ABSENT' : '', stderr: '' };
        }
    }
    stub('src/services/nodeSSH.js', SSH);
    stub('src/services/nodeSetup.js', { reloadCcAgent: async (node, ssh) => {
        events.push({ type: 'agent', node: node._id });
        // IO-boundary double includes a real call through the supplied transport
        // so unconfirmed nested commands cannot silently authorize lock release.
        if (options.agentExec) { try { await ssh.exec('systemctl restart cc-agent'); } catch (_) {} }
        if (options.agentError) throw new Error('agent reload unknown');
    } });
    function load(filename) {
        if (stubs.has(filename)) return stubs.get(filename);
        if (cache.has(filename)) return cache.get(filename).exports;
        const loaded = new Module(filename, module);
        cache.set(filename, loaded);
        loaded.filename = filename; loaded.paths = Module._nodeModulePaths(path.dirname(filename));
        loaded.require = id => {
            if (id === 'mongoose') return mongoose;
            const resolved = Module._resolveFilename(id, loaded);
            if (resolved.startsWith(`${ROOT}/`) && resolved.endsWith('.js')) return load(resolved);
            return Module.prototype.require.call(loaded, id);
        };
        loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
        return loaded.exports;
    }
    const f = { events, locks, owners, operations, nodes, links, files, settings };
    f.generator = load(absolute('src/services/configGenerator.js'));
    f.provision = load(absolute('src/services/accessLogs/provisionService.js'));
    f.fence = load(absolute('src/services/classicNodeConfigWrite.js'));
    f.context = load(absolute('src/modules/relay-l2tp/domain/topologyExecutionContext.js')).PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT;
    const stored = JSON.parse(f.generator.generateCombinedBridgeConfig(links));
    const clients = [{ tag: 'preserved-client', protocol: 'vless', port: 24443,
        settings: { clients: [{ id: '00000000-0000-4000-8000-000000000007', email: 'existing-user' }] } }];
    if (options.nativeProfile !== false) {
        // Modeled installed topology/foreign fragments, not a classic generator
        // layout. Classic-positive fixtures keep the actual generated sidecar.
        stored.inbounds = clients;
        stored.routing.rules.unshift({ type: 'field', inboundTag: ['preserved-client'],
            outboundTag: stored.outbounds.find(outbound => outbound.protocol === 'vless').tag });
    }
    files.set(`${BRIDGE}:${CONFIG}`, JSON.stringify(stored));
    files.set(`${BRIDGE}:${MAIN}`, JSON.stringify({ inbounds: clients, routing: { rules: [] } }));
    f.hashes = () => Object.fromEntries([...files].filter(([key]) => key.startsWith(BRIDGE)).map(([key, value]) => [key, sha(value)]));
    f.adopt = async () => {
        const matches = query => row => Object.entries(query).every(([key, value]) => isDeepStrictEqual(row[key], value));
        const Model = { collection: { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] },
            db: { transaction: async work => work({ modeledSession: true }) },
            create: async rows => { owners.push(...clone(rows)); },
            findOne(query) {
                const q = { read: () => q, readConcern: () => q, maxTimeMS: () => q,
                    lean: async () => clone(owners.find(matches(query)) || null) }; return q;
            },
            findOneAndUpdate: async (query, update) => {
                const row = owners.find(matches(query)); if (!row) return null;
                Object.assign(row, clone(update.$set));
                for (const key of Object.keys(update.$unset || {})) delete row[key];
                return clone(row);
            },
        };
        const { TopologyConfigTransfer } = load(absolute('src/services/topologyConfigTransfer.js'));
        const transfer = new TopologyConfigTransfer({ executionContext: f.context, TopologyConfigOwner: Model,
            withVerifiedMaintenance: async ({ binding }, work) => work({ binding, status: 'verified',
                authority: 'external-maintenance-v1', proofId: randomUUID(), maintenanceId: randomUUID(),
                maintenance: 'held', allWriters: 'drained', oldBackend: { instanceId: 'modeled-old-backend',
                    pid: 42, processStartTime: 'modeled-start', processTree: 'stopped', dispatch: 'disabled' },
                readback: { source: 'node-readback', configSha256: sha(files.get(`${BRIDGE}:${CONFIG}`)),
                    unitSha256: sha('modeled-unit'), serviceActive: 'active', serviceEnabled: 'enabled' } }) });
        const classic = await transfer.initializeClassic({ node: BRIDGE, profile: 'xray-bridge',
            nodeIdentity: { machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) } });
        return transfer.adopt({ node: BRIDGE, profile: 'xray-bridge', generation: classic.generation, proofRef: 'modeled-original' });
    };
    const generate = f.generator.generateCombinedBridgeConfig;
    f.generator.generateCombinedBridgeConfig = (...args) => {
        events.push({ type: 'generate', node: String(args[0][0]?.bridgeNode) });
        return generate(...args);
    };
    return f;
}
function effects(f) { return f.events.filter(event => ['generate', 'connect', 'upload', 'exec', 'agent'].includes(event.type)); }
function winner(node = BRIDGE) { return { node, owner: 'topology-worker', operationId: 'foreign-operation',
    generation: randomUUID(), remoteUncertain: true, leaseUntil: new Date(0) }; }

test('held foreign bridge generation survives background reconciliation while unrelated classic component applies', async () => {
    const f = fixture();
    const held = winner(); f.locks.set(BRIDGE, clone(held));
    f.nodes.set(OTHER, { ...clone(f.nodes.get(BRIDGE)), _id: OTHER, name: 'independent-classic' });
    const otherLinks = f.links.map((link, index) => {
        const legacy = { ...clone(link), bridgeNode: OTHER, _id: `507f1f77bcf86cd79943904${index}` };
        delete legacy.status; return legacy;
    });
    f.links.push(...otherLinks);
    f.files.set(`${OTHER}:${CONFIG}`, f.generator.generateCombinedBridgeConfig(otherLinks));
    const before = f.hashes();
    const result = await withEnv(ENV, () => f.provision.reconcileAll());
    assert.deepEqual(effects(f).filter(event => event.node === BRIDGE), [], 'foreign lock must prevent bridge dispatch');
    assert.deepEqual(f.locks.get(BRIDGE), held);
    assert.deepEqual(f.hashes(), before);
    assert.equal(result.results.find(row => row.node === 'independent-classic').status, 'active');
    assert.equal(result.results.find(row => row.node !== 'independent-classic').status, 'error');
    assert.equal(f.locks.has(OTHER), false, 'checked success releases only own generation');
    const uploaded = JSON.parse(f.files.get(`${OTHER}:${CONFIG}`));
    const expected = JSON.parse(f.generator.generateCombinedBridgeConfig(otherLinks));
    assert.deepEqual(uploaded.reverse, expected.reverse);
    assert.deepEqual(uploaded.routing, expected.routing);
    assert.deepEqual(uploaded.outbounds, expected.outbounds);
    assert.equal(uploaded.log.access, '/var/log/xray-bridge/access.log');
});

test('unconfirmed bridge command cannot publish logging success or release its generation', async () => {
    const f = fixture({ execResult: { code: 1, stdout: 'modeled failure' } });
    const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.equal(result.status, 'error', 'nonzero remote exit is not verified completion');
    assert.equal(f.locks.get(BRIDGE)?.remoteUncertain, true);
    assert.equal(f.events.some(event => event.type === 'release'), false);
    assert.equal(f.nodes.get(BRIDGE).xray.accessLogs.appliedFingerprint, undefined);
});

test('paired TEST applied-selection policy never enables pending-only reverse peers', async () => {
    const f = fixture();
    f.links.forEach(link => { link.status = 'pending'; });
    const before = f.hashes();
    const result = await withEnv({ ...ENV, PANEL_DOMAIN: 'test.infograd.online', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' },
        () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.deepEqual(effects(f), [], 'pending-only TEST desired links are not applied topology');
    assert.equal(result.status, 'error');
    assert.deepEqual(f.hashes(), before);
    assert.equal(f.locks.size, 0, 'known pending-only preflight does not acquire uncertain ownership');
});

test('settings background target preserves publicly adopted shared bridge, clients and pending peer', async () => {
    const f = fixture();
    await f.adopt();
    f.links.push({ ...clone(f.links[0]), _id: '507f1f77bcf86cd799439039', status: 'pending' });
    const before = f.hashes();
    const ownerBefore = clone(f.owners);
    await withEnv(ENV, async () => {
        const result = await f.provision.reconcileAll();
        assert.deepEqual(effects(f), [], 'adopted bridge must never be regenerated/uploaded/restarted by reconciliation');
        assert.equal(result.state, 'error', 'deferred logging must not claim applied/active');
        assert.equal(result.results[0].status, 'error');
        assert.equal(f.nodes.get(BRIDGE).xray.accessLogs.appliedFingerprint, undefined);
    });
    assert.deepEqual(f.hashes(), before, 'both full profile hashes include retained clients and peer routing');
    assert.deepEqual(f.owners, ownerBefore);
});

test('failed disable on an adopted bridge cannot claim globally disabled while logging remains installed', async () => {
    const f = fixture(); await f.adopt();
    f.nodes.get(BRIDGE).xray.accessLogs = { enabled: true, status: 'active', appliedFingerprint: 'previously-installed' };
    f.settings.accessLogs.enabled = false;
    const before = f.hashes();
    const result = await withEnv(ENV, () => f.provision.reconcileAll());
    assert.equal(result.results[0].status, 'error');
    assert.equal(result.state, 'error', 'managed refusal is not a completed global disable');
    assert.equal(f.settings.accessLogs.state, 'error');
    assert.equal(f.nodes.get(BRIDGE).xray.accessLogs.appliedFingerprint, 'previously-installed');
    assert.deepEqual(effects(f), []);
    assert.deepEqual(f.hashes(), before);
});

test('ownership adopted between precheck and lock acquisition vetoes before generation', async () => {
    const f = fixture({ onAcquire: async (_row, state) => state.adopt() });
    const before = f.hashes();
    const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.equal(result.status, 'error');
    assert.match(result.error, /CLASSIC_CONFIG_WRITE_OWNER_VETO/);
    assert.deepEqual(effects(f), []);
    assert.deepEqual(f.hashes(), before);
    assert.equal(f.owners[0].owner, 'topology');
    assert.equal(f.locks.get(BRIDGE).remoteUncertain, true, 'existing helper conservatively retains under-lock veto');
    assert.equal(f.events.some(event => event.type === 'release'), false);
});

test('foreign winner inserted at acquisition is neither overwritten nor released', async () => {
    const foreign = winner();
    const f = fixture({ onAcquire: async (_row, state) => state.locks.set(BRIDGE, clone(foreign)) });
    const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.equal(result.status, 'error');
    assert.deepEqual(effects(f), []);
    assert.deepEqual(f.locks.get(BRIDGE), foreign);
    assert.equal(f.events.some(event => event.type === 'release'), false);
});

test('paused bridge upload holds the same generation against actual competing classic and log callers', async () => {
    let started, finish;
    const ready = new Promise(resolve => { started = resolve; });
    const paused = new Promise(resolve => { finish = resolve; });
    const f = fixture({ onUpload: async () => { started(); await paused; } });
    await withEnv(ENV, async () => {
        const first = f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings);
        await ready;
        try {
            const held = clone(f.locks.get(BRIDGE));
            assert.equal(held.remoteUncertain, true);
            let dispatches = 0;
            await assert.rejects(f.fence.withClassicNodeConfigWrite({ nodeId: BRIDGE, kind: 'competing-sync', env: ENV },
                async () => { dispatches++; return true; }), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
            const second = await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings);
            assert.equal(second.status, 'error');
            assert.equal(dispatches, 0);
            assert.deepEqual(f.locks.get(BRIDGE), held);
            assert.equal(f.events.filter(event => event.type === 'upload').length, 1);
            assert.equal(f.events.some(event => event.type === 'release'), false);
        } finally { finish(); }
        assert.equal((await first).status, 'active');
        assert.equal(f.locks.size, 0);
    });
});

for (const [name, options] of [
    ['missing command exit', { execResult: { stdout: 'no exit status' } }],
    ['upload timeout', { uploadError: true }],
    ['non-void upload acknowledgement', { uploadResult: { code: 0 } }],
    ['agent reload failure', { agentError: true }],
    ['swallowed nested agent command failure', { agentExec: true,
        execResult: command => command === 'systemctl restart cc-agent' ? { code: 1 } : { code: 0 } }],
]) {
    test(`unverified ${name} retains exact generation and blocks retry`, async () => {
        const f = fixture(options);
        await withEnv(ENV, async () => {
            const result = await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings);
            assert.equal(result.status, 'error');
            const held = clone(f.locks.get(BRIDGE));
            assert.equal(held.remoteUncertain, true);
            assert.equal(f.events.some(event => event.type === 'release'), false);
            const priorEffects = effects(f).length;
            assert.equal((await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings)).status, 'error');
            assert.equal(effects(f).length, priorEffects);
            assert.deepEqual(f.locks.get(BRIDGE), held);
            assert.equal(f.nodes.get(BRIDGE).xray.accessLogs.appliedFingerprint, undefined);
        });
    });
}

test('replaced generation during upload prevents later restart and cannot be released', async () => {
    const foreign = winner();
    const f = fixture({ onUpload: async (_node, state) => state.locks.set(BRIDGE, clone(foreign)) });
    const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.equal(result.status, 'error');
    assert.deepEqual(f.locks.get(BRIDGE), foreign);
    assert.equal(f.events.filter(event => event.type === 'exec' && event.command.includes('restart')).length, 0);
    assert.equal(f.events.some(event => event.type === 'release'), false);
});

for (const state of ['queued', 'retained-terminal']) {
    test(`${state} operation history protects bridge with no adopted owner row`, async () => {
        const f = fixture();
        f.operations.push({ status: state === 'queued' ? 'queued' : 'failed',
            heldTopologyAdmission: state === 'retained-terminal', nodes: [{ node: BRIDGE, state: 'pending' }] });
        const before = f.hashes();
        const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
        assert.equal(result.status, 'error');
        assert.deepEqual(effects(f), []);
        assert.deepEqual(f.hashes(), before);
        assert.equal(f.locks.size, 0);
    });
}

test('unreadable ownership refuses bridge dispatch without acquiring a lock', async () => {
    const f = fixture({ ownerReadError: true });
    const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.equal(result.status, 'error');
    assert.match(result.error, /owner read unavailable/);
    assert.deepEqual(effects(f), []);
    assert.equal(f.locks.size, 0);
});

test('adopted bridge is protected with execution flags off', async () => {
    const f = fixture(); await f.adopt();
    const before = f.hashes();
    const result = await withEnv({ ...ENV, L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false' },
        () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.equal(result.status, 'error');
    assert.deepEqual(effects(f), []);
    assert.deepEqual(f.hashes(), before);
    assert.equal(f.locks.size, 0);
});

test('classic online shared peers retain routing and tunnel identities; repeated reconciliation is a no-op', async () => {
    const f = fixture({ nativeProfile: false });
    const expected = JSON.parse(f.generator.generateCombinedBridgeConfig(f.links));
    f.events.length = 0;
    f.links.push({ ...clone(f.links[0]), _id: '507f1f77bcf86cd799439039', active: false });
    f.links.push({ ...clone(f.links[0]), _id: '507f1f77bcf86cd799439038', mode: 'forward' });
    const mainBefore = sha(f.files.get(`${BRIDGE}:${MAIN}`));
    await withEnv(ENV, async () => {
        assert.equal((await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings)).status, 'active');
        const uploaded = JSON.parse(f.files.get(`${BRIDGE}:${CONFIG}`));
        assert.deepEqual(uploaded.reverse, expected.reverse);
        assert.deepEqual(uploaded.outbounds, expected.outbounds);
        assert.deepEqual(uploaded.routing, expected.routing);
        assert.equal(sha(f.files.get(`${BRIDGE}:${MAIN}`)), mainBefore);
        const effectCount = effects(f).length;
        assert.equal((await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings)).skipped, true);
        assert.equal(effects(f).length, effectCount);
        assert.equal(f.locks.size, 0);
    });
});

test('classic disabled logging still applies through the shared fence without changing peers', async () => {
    const f = fixture({ nativeProfile: false });
    await withEnv(ENV, async () => {
        await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings);
        const enabled = JSON.parse(f.files.get(`${BRIDGE}:${CONFIG}`));
        f.settings.accessLogs.enabled = false;
        const result = await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings);
        assert.equal(result.status, 'disabled');
        const disabled = JSON.parse(f.files.get(`${BRIDGE}:${CONFIG}`));
        assert.equal(disabled.log.access, undefined);
        assert.deepEqual(disabled.reverse, enabled.reverse);
        assert.deepEqual(disabled.outbounds, enabled.outbounds);
        assert.deepEqual(disabled.routing, enabled.routing);
        assert.equal(f.events.filter(event => event.type === 'release').length, 2);
        assert.equal(f.locks.size, 0);
    });
});

for (const status of ['pending', 'offline', 'error', undefined]) {
    test(`access-log background rewrite preserves installed ${status} peers and excludes an absent save-only peer`, async () => {
        const f = fixture({ nativeProfile: false });
        f.links.forEach(row => { if (status === undefined) delete row.status; else row.status = status; });
        const saved = { ...clone(f.links[0]), _id: '507f1f77bcf86cd799439039', status: 'pending', autoDeploy: false,
            tunnelUuid: '00000000-0000-4000-8000-000000000099' };
        f.links.push(saved);
        const original = JSON.parse(f.files.get(`${BRIDGE}:${CONFIG}`));
        const clients = { tag: 'retained-client', protocol: 'vless', port: 24443,
            settings: { clients: [{ id: '00000000-0000-4000-8000-000000000007' }] },
            streamSettings: { security: 'reality', realitySettings: { privateKey: 'dummy-private' } } };
        original.inbounds = [clients];
        f.files.set(`${BRIDGE}:${CONFIG}`, JSON.stringify(original));
        const main = f.files.get(`${BRIDGE}:${MAIN}`);
        const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
        assert.equal(result.status, 'active');
        const after = JSON.parse(f.files.get(`${BRIDGE}:${CONFIG}`));
        assert.deepEqual(after.inbounds, [clients]);
        assert.deepEqual(after.reverse, original.reverse);
        assert.deepEqual(after.outbounds, original.outbounds);
        assert.deepEqual(after.routing, original.routing);
        assert.equal(JSON.stringify(after).includes(saved.tunnelUuid), false);
        assert.equal(f.files.get(`${BRIDGE}:${MAIN}`), main);
        assert.equal(f.locks.size, 0);
    });
}

test('access-log background rewrite refuses an unrecognized installed profile without publishing a fingerprint', async () => {
    const f = fixture({ nativeProfile: false });
    const original = JSON.parse(f.files.get(`${BRIDGE}:${CONFIG}`));
    original.reverse.bridges.push({ tag: 'unknown-peer', domain: 'foreign.invalid' });
    f.files.set(`${BRIDGE}:${CONFIG}`, JSON.stringify(original));
    const before = f.hashes();
    const result = await withEnv(ENV, () => f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings));
    assert.equal(result.status, 'error');
    assert.match(result.error, /CLASSIC_APPLIED_/);
    assert.deepEqual(f.hashes(), before);
    assert.equal(f.events.some(row => row.type === 'upload'), false);
    assert.equal(f.nodes.get(BRIDGE).xray.accessLogs.appliedFingerprint, undefined);
});

test('PROD legacy selection remains fixed if the environment changes during ownership read', async () => {
    const f = fixture({ nativeProfile: false, onOwnerRead: async () => {
        process.env.PANEL_DOMAIN = 'test.infograd.online'; process.env.TOPOLOGY_TEST_EXECUTION_ENABLED = 'true';
    } });
    f.links.forEach(link => { delete link.status; });
    await withEnv(ENV, async () => {
        assert.equal((await f.provision.reconcileNode(clone(f.nodes.get(BRIDGE)), f.settings)).status, 'active');
    });
    assert.equal(JSON.parse(f.files.get(`${BRIDGE}:${CONFIG}`)).reverse.bridges.length, 2);
    assert.equal(f.events.filter(event => event.type === 'links').every(event => !event.query.status), true);
    assert.equal(f.events.some(event => event.type === 'release'), true);
});
