'use strict';
// Local orchestration only: persistence and SSH are modeled, not physical exclusion.
process.env.PANEL_DOMAIN = 'lm1.infograd.online';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
process.env.L2TP_EXECUTION_ENABLED = 'true';
process.env.L2TP_MIGRATIONS_ENABLED = 'true';
process.env.L2TP_PRODUCTION_EXECUTION_ENABLED = 'true';
process.env.TOPOLOGY_TEST_EXECUTION_ENABLED = 'false';
process.env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED = 'false';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const { NodeOperationLockService } = require('../../modules/relay-l2tp/services/nodeOperationLockService');
const { NodeOperationLockRepository } = require('../../modules/relay-l2tp/services/nodeOperationLockRepository');
const { L2tpOperationWorker } = require('../../modules/relay-l2tp/workers/l2tpOperationWorker');
const { materializeInstallOperation } = require('../../modules/relay-l2tp/services/l2tpOperationMaterializer');
const generator = require('../configGenerator');
const { cascadePathIngressPort } = require('../../modules/relay-l2tp/domain/cascadePathIngress');
const { buildL2tpXrayFragment } = require('../../modules/relay-l2tp/services/l2tpXrayFragmentProvider');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const NODE = '6ab189dc63913ebd4a917399';
const HEAD = '507f1f77bcf86cd799439012';
const EXIT = '507f1f77bcf86cd799439013';
const GROUP = '507f1f77bcf86cd799439014';
const UP = '507f1f77bcf86cd799439015';
const DOWN = '507f1f77bcf86cd799439016';
const users = [{ userId: 'subscription', xrayUuid: '00000000-0000-4000-8000-000000000001' }];
const relay = { _id: NODE, name: 'relay', type: 'xray', active: true, cascadeRole: 'relay', ip: '192.0.2.2', port: 443, ssh: { privateKey: 'fake-key' }, xray: { transport: 'tcp', security: 'none' } };
const head = { ...relay, _id: HEAD, ip: '192.0.2.1' };
const exit = { ...relay, _id: EXIT, ip: '192.0.2.3' };
const upstream = { _id: UP, portalNode: head, bridgeNode: relay, mode: 'reverse', active: true, status: 'online', tunnelUuid: '00000000-0000-4000-8000-000000000002' };
const downstream = { _id: DOWN, portalNode: relay, bridgeNode: exit, mode: 'reverse', active: true, status: 'online', tunnelUuid: '00000000-0000-4000-8000-000000000003' };
const group = { _id: GROUP, mode: 'reverse', paths: [{ pathKey: 'main', linkIds: [DOWN], enabled: true }] };
const query = value => {
    let selected = value;
    return { session() { return this; }, setOptions() { return this; }, select(fields) {
        if (!value) return this;
        selected = {};
        for (const name of ['_id', ...fields.split(/\s+/).map(key => key.replace(/^\+/, ''))]) {
            const parts = name.split('.');
            let field = value;
            for (const part of parts) field = field?.[part];
            if (field === undefined) continue;
            let target = selected;
            for (const part of parts.slice(0, -1)) target = target[part] ||= {};
            target[parts.at(-1)] = field;
        }
        return this;
    }, lean: async () => selected, populate() { return this; },
    then(resolve, reject) { return Promise.resolve(selected).then(resolve, reject); } };
};
const resolveUsers = node => active.resolveUsers ? active.resolveUsers(node) : users;
const id = value => String(value?._id ?? value);
const matches = (row, filter) => Object.entries(filter).every(([key, value]) => {
    if (key === '$or') return value.some(branch => matches(row, branch));
    if (key === '$and') return value.every(branch => matches(row, branch));
    if (key === 'paths.linkIds') return row.paths.some(path => path.linkIds.some(linkId => value.$in.map(String).includes(String(linkId))));
    if (value?.$in) return value.$in.map(String).includes(id(row[key]));
    if (value?.$ne !== undefined) return id(row[key]) !== id(value.$ne);
    return id(row[key]) === id(value);
});
let active;
const original = Module._load;
Module._load = function(request, parent, isMain) {
    const filename = parent?.filename || '';
    if (filename.endsWith('/topologyConfigOwnership.js')) {
        if (request.endsWith('/topologyOperationModel')) return { exists: async filter => { active.events.push('owner-read'); active.assertHeld(); return active.legacy
            ? active.legacy.data.topologyoperations.find(require('sift').default(filter)) || null : false; } };
        if (request === 'mongoose') {
            const real = original.call(this, request, parent, isMain);
            return { Types: real.Types, connection: { db: active.legacy?.db || { collection: () => ({ find: () => ({ toArray: async () => active.owners }) }) } } };
        }
    }
    if (filename.endsWith('/l2tpRuntimeLifecycleHook.js')) {
        if (request === '../models/cascadeLinkModel') return { find: filter => query(active.links.filter(row => matches(row, filter))) };
        if (request.endsWith('/cascadeRouteGroupModel')) return { findById: () => query(group) };
    }
    if (filename.endsWith('/cascadeService.js')) {
        if (request === '../models/cascadeLinkModel') return { find: filter => query(active.links.filter(row => matches(row, filter))) };
        if (request.endsWith('/cascadeRouteGroupModel')) return { find: filter => query([group].filter(row => matches(row, filter))) };
        if (request.endsWith('/relayL2tpStateModel')) return { exists: async () => true };
        if (request === '../models/hyNodeModel' || request === '../models/settingsModel') return {};
        if (request === './nodeSSH') return SSH;
        if (request === './syncService') return { _getUsersForNode: async node => resolveUsers(node),
            _agentRequest: async () => { active.events.push('agent-restart'); if (active.agentError) throw active.agentError; return active.agentResult; } };
        if (request === './cacheService' || request === './webhookService') return {};
    }
    if (filename.endsWith('/classicNodeConfigWrite.js') && request.endsWith('/nodeOperationLockModel')) return active.model;
    return original.call(this, request, parent, isMain);
};
class SSH {
    constructor(node) { this.node = node; }
    async connect() { await active.assertScope?.(); active.assertHeld(); active.events.push('connect'); }
    disconnect() {}
    async uploadContent(content, path) {
        await active.assertScope?.(); active.assertHeld(); active.events.push('upload:' + path); active.uploads.push({ content, path });
        if (active.uploadFailure) throw new Error('unknown SFTP');
        if (path === '/usr/local/etc/xray/config.json') active.live = content;
        if (path === '/usr/local/etc/xray-bridge/config.json') active.liveBridge = content;
    }
    async exec(command) {
        await active.assertScope?.(); active.assertHeld(); active.commands.push(command); active.events.push(command.includes('cat /usr/local/etc/xray/config.json') ? 'live-main' : 'exec');
        let stdout = command.includes('cat /usr/local/etc/xray/config.json') ? active.live
            : command.includes('cat /usr/local/etc/xray-bridge/config.json') ? active.liveBridge
                : command.includes('is-active') ? 'active' : '/usr/local/bin/xray';
        const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/);
        if (receipt) stdout += '\n' + receipt[0] + '\n';
        return { code: active.restartFailure && command.includes('systemctl restart xray-bridge') ? 1 : 0, stdout, stderr: '' };
    }
}
const { createL2tpRootHostDependencies } = require('../../modules/l2tpRuntimeLifecycleHook');
function seedAppliedForwardProfile() {
    // Explicit fixture setup, never observation inferred from desired status.
    const current = JSON.parse(active.live);
    generator.applyForwardChain(current, active.links.filter(link => link.mode === 'forward' && id(link.portalNode) === NODE), ['vless-in']);
    require('../classicL2tpConfigComposition').finishClassicConfigRouting(current);
    active.live = JSON.stringify(current);
    const incoming = active.links.filter(link => link.mode !== 'forward' && id(link.bridgeNode) === NODE);
    active.liveBridge = incoming.length ? generator.generateCombinedBridgeConfig(incoming) : null;
}
function fixture({ conflict = false, veto = false, uploadFailure = false, restartFailure = false } = {}) {
    const events = [], uploads = [];
    const rows = new Map();
    if (conflict) rows.set(NODE, { node: NODE, owner: 'winner', generation: 'foreign', remoteUncertain: true });
    const model = {
        async create(row) { events.push('lock'); if (rows.has(id(row.node))) throw Object.assign(new Error('duplicate'), { code: 11000 }); rows.set(id(row.node), row); return row; },
        findOne: ({ node }) => query(rows.get(id(node))),
        async updateOne(filter, update) { const row = rows.get(id(filter.node)); if (!row || row.generation !== filter.generation || row.owner !== filter.owner || row.operationId !== filter.operationId || row.leaseUntil <= filter.leaseUntil.$gt) return { matchedCount: 0 }; Object.assign(row, update.$set); return { matchedCount: 1 }; },
        async deleteOne(filter) { const row = rows.get(id(filter.node)); if (!row || !Object.entries(filter).every(([key, value]) => id(row[key]) === id(value))) return { deletedCount: 0 }; events.push('release'); rows.delete(id(filter.node)); return { deletedCount: 1 }; },
    };
    const planInput = { ok: true, operationId: 'install-op', relayId: NODE, routeGroupId: GROUP, selectedPathKey: 'main', nextHopNodeId: EXIT,
        desired: { tproxyPort: 12345, credentialRevision: 7 } };
    const plan = { ...planInput, topologyRevision: 196,
        desired: { ...planInput.desired, clientCidr: '10.77.0.0/24', localAddress: '10.77.0.1',
            poolStart: '10.77.0.10', poolEnd: '10.77.0.200', dnsServers: ['1.1.1.1'], fwmark: 77, routeTable: 177 },
        steps: require('../../modules/relay-l2tp/services/l2tpProvisionPlanService').INSTALL_STEP_TYPES.map(type => ({ type })) };
    const live = JSON.parse(generator.generateXrayConfigWithApi(relay, users));
    live.outbounds.push({ tag: 'cascade-main', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: cascadePathIngressPort(GROUP, 'main') }] } });
    live.inbounds.push({ tag: 'relay-l2tp-other', protocol: 'dokodemo-door', port: 12346 });
    active = { model, rows, events, uploads, commands: [], links: [upstream, downstream], uploadFailure, restartFailure, live: JSON.stringify(live),
        liveBridge: generator.generateRelayConfig(upstream, head, [downstream]),
        owners: veto ? [{ node: NODE, profile: 'xray-main', owner: 'topology', executionContext: context, generation: '00000000-0000-4000-8000-000000000001', nodeIdentity: { machineId: 'a'.repeat(32), sshHostKeySha256: 'b'.repeat(64) } }] : [],
        assertHeld() { const row = rows.get(NODE); assert(row && row.remoteUncertain === true
            && (active.teardown ? row.owner.startsWith('simple-uninstall:') : row.owner === 'worker' && row.operationId === 'install-op'),
            'remote/generation must be under the worker node lock'); },
    };
    const root = createL2tpRootHostDependencies({ env: process.env, HyNode: { findById: nodeId => query([relay, head, exit].find(row => id(row) === id(nodeId))) }, NodeSSH: SSH,
        syncService: { _getUsersForNode: async node => resolveUsers(node) }, createTopologyExecutionAuthority: () => undefined,
        requireAuth() {}, requireOnboarding() {}, csrf() {}, rateLimiter() {}, renderPage() {},
        createPreflightRunner: () => async () => ({}), secretBox: {}, secretKey: 'fixture',
    });
    const candidateService = root.createCandidateService();
    const lockService = new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model }), clock: { now: () => new Date() } });
    return { ...active, root, plan, candidateService, lockService };
}
test('default root candidate reads live MAIN instead of producing a sparse replacement', async () => {
    const f = fixture();
    const acquired = await f.lockService.acquire({ node: NODE, owner: 'worker', operationId: 'install-op', leaseMs: 30000 });
    const candidate = await f.candidateService.withLockedPreparation({ lock: acquired.lock, lockService: f.lockService,
        clock: { now: () => new Date() } }, () => f.candidateService.buildCandidate({ plan: f.plan }));
    assert(f.events.includes('live-main'), 'default root must provide LIVE currentConfigResolver');
    const config = JSON.parse(candidate.content);
    assert(config.inbounds.some(row => row.tag === 'relay-l2tp-other'));
    assert.deepEqual(config.outbounds.find(row => row.tag === 'cascade-main'), JSON.parse(f.live).outbounds.find(row => row.tag === 'cascade-main'));
    assert.equal(config.inbounds.find(row => row.tag === 'vless-in').settings.clients[0].id, users[0].xrayUuid);
    assert(acquired.ok);
});
function assembledRuntime(f, kind = 'install') {
    const { createL2tpRuntime } = require('../../modules/relay-l2tp/runtime/createL2tpRuntime');
    let claimed = false;
    const operation = { _id: 'install-op', kind, node: NODE, status: 'running',
        leaseOwner: 'worker', ownerGeneration: 1, admissionId: 'admitted', executionContext: f.executionContext || context,
        plan: kind === 'install' ? f.plan : { ok: true, operationId: 'install-op', relayId: NODE, desired: { credentialRevision: 7 },
            steps: [{ type: 'backup' }, { type: 'sync_users', artifacts: [{ type: 'desired', path: 'desired.json' }] }, { type: 'verify_users' }] } };
    const pass = (_req, _res, next) => next();
    const settlement = f.legacy ? standaloneRepository(f).repository : null;
    if (settlement) {
        settlement.L2tpOperation = { db: settlement.RemoteAdmission.db,
            findOne: filter => query(require('sift').default(filter)(operation) ? operation : null) };
        settlement.NodeOperationLock = f.model;
    }
    const runtime = createL2tpRuntime({
        executionContext: f.executionContext || context, enableProductionExecution: !f.executionContext,
        enableUnsafeExecutionForTests: !!f.executionContext,
        operationModel: { updateOne: async (filter, update) => { f.events.push('operation-write');
            assert.equal(filter.leaseOwner, 'worker'); assert.equal(filter.ownerGeneration, 1);
            Object.assign(operation, update.$set || {});
            return { matchedCount: 1 }; } },
        operationRepository: {}, nodeRepository: {}, stateRepository: {}, stateManagementService: {}, userManagementService: {},
        preflightRunner: async () => ({}), lockService: f.lockService,
        remoteAdmissionRepository: {
            claimQueuedInstall: async () => { if (claimed) return null; claimed = true; if (f.legacy) { f.legacy.data.remoteadmissions = [{ _id: 'admitted', nodeId: NODE, kind,
                phase: 'running', operationId: 'install-op', leaseOwner: 'worker', ownerGeneration: 1 }];
                f.legacy.data.cascadetopologystates[0].remoteAdmissionCount = 1; } return operation; },
            claimQueuedSyncUsers: async () => null,
            completeTerminalOperation: async () => { f.events.push('admission-terminal'); return true; },
            completeVerifiedOperation: async request => { assert.equal(f.rows.size, 0);
                if (settlement) await settlement.completeVerifiedOperation(request);
                f.events.push('admission-done'); return true; },
            markOperationRecoveryRequired: async () => { f.events.push('retained'); return true; },
        },
        secretResolver: async () => { f.assertHeld(); f.events.push('psk'); return { psk: 'already-stored-psk', users: [] }; },
        userSnapshotResolver: async () => { await active.assertScope?.(); f.assertHeld(); f.events.push('user-snapshot');
            return f.resolveUserSnapshot ? f.resolveUserSnapshot() : { credentialRevision: 7, users: [] }; },
        userSyncReconciler: { finalizeClaimedVerifiedSync: async () => { f.assertHeld(); return { ok: true }; } }, stateReconciler: async () => f.assertHeld(),
        candidateService: f.candidateService, operationMaterializer: materializeInstallOperation,
        transport: { uploadRootFile: async request => { f.assertHeld(); f.events.push('candidate-upload:' + request.path); f.uploads.push(request); },
            runArtifactCommand: async ({ command }) => { f.assertHeld(); f.events.push('runner:' + command); return command === 'verify-users'
                ? { ok: true, credentialRevision: 7, enabledUserCount: 0, managedUserCount: 0, code: 'USERS_VERIFIED' } : { ok: true }; } },
        requireAuth: pass, requireOnboarding: pass, csrf: pass, rateLimiter: pass, loadPanelOverview: async () => ({}), renderPage() {},
        clock: { now: () => new Date() }, workerId: 'worker', leaseMs: 30000,
    });
    return runtime;
}

test('assembled root -> real runtime/worker/candidate/classic wrapper installs secondary ingress before candidate upload', async () => {
    const f = fixture();
    const runtime = assembledRuntime(f);
    const result = await runtime.worker.runOnce();
    assert.deepEqual(result, { claimed: true, operationId: 'install-op', status: 'succeeded' });
    const bridge = f.uploads.find(row => row.path === '/usr/local/etc/xray-bridge/config.json');
    assert(bridge, 'a real secondary config upload must occur');
    const bridgeConfig = JSON.parse(bridge.content);
    assert.equal(bridgeConfig.inbounds.find(row => row.tag === 'cascade-main').port, cascadePathIngressPort(GROUP, 'main'));
    assert(bridgeConfig.routing.rules.some(row => row.inboundTag?.includes('cascade-main') && row.outboundTag === 'portal-down-' + DOWN.slice(-8)));
    assert.equal(bridgeConfig.inbounds.find(row => row.tag === 'conn-down-' + DOWN.slice(-8)).settings.clients[0].id, downstream.tunnelUuid);
    assert(f.events.indexOf('lock') < f.events.indexOf('owner-read'));
    assert(f.events.indexOf('live-main') < f.events.indexOf('upload:/usr/local/etc/xray-bridge/config.json'), 'checked live MAIN must precede any preparation write');
    assert(f.events.indexOf('upload:/usr/local/etc/xray-bridge/config.json') < f.events.lastIndexOf('live-main'));
    assert(f.events.lastIndexOf('live-main') < f.events.indexOf('candidate-upload:xray-candidate.json'));
    const candidate = JSON.parse(f.uploads.find(row => row.path === 'xray-candidate.json').content);
    assert.equal(candidate.inbounds.find(row => row.tag === 'vless-in').settings.clients[0].id, users[0].xrayUuid);
    assert(candidate.inbounds.some(row => row.tag === 'relay-l2tp-other'));
    assert.equal(candidate.outbounds.find(row => row.tag === 'cascade-main').settings.servers[0].port,
        bridgeConfig.inbounds.find(row => row.tag === 'cascade-main').port);
    assert(f.uploads.find(row => row.path === 'artifacts.json').content.includes('already-stored-psk'));
    assert.equal(f.events.filter(row => row === 'lock').length, 1, 'classic wrapper must not reacquire worker lock');
    assert.equal(f.rows.size, 0);
});

test('assembled reverse preparation preserves both existing fan-in upstreams while selecting exact L2TP egress', async () => {
    const f = fixture();
    const other = { ...upstream, _id: '507f1f77bcf86cd799439017',
        portalNode: { ...head, _id: '507f1f77bcf86cd799439018', ip: '192.0.2.18' },
        tunnelUuid: '00000000-0000-4000-8000-000000000018' };
    f.links.push(other);
    // These are existing upstreams, so their actual pre-preparation sidecar
    // bytes must be present, not merely desired rows marked "online".
    active.liveBridge = generator.generateRelayConfig(upstream, head, [downstream], [], [{ link: other, portal: other.portalNode }]);
    assert.equal((await assembledRuntime(f).worker.runOnce()).status, 'succeeded');
    const secondary = JSON.parse(f.uploads.find(row => row.path === '/usr/local/etc/xray-bridge/config.json').content);
    assert.equal(secondary.reverse.bridges.length, 2, 'neither existing upstream may be discarded');
    const upstreamOutbounds = secondary.outbounds.filter(row => row.protocol === 'vless');
    assert.deepEqual(upstreamOutbounds.map(row => row.settings.vnext[0].users[0].id).sort(),
        [upstream.tunnelUuid, other.tunnelUuid].sort());
    for (const bridge of secondary.reverse.bridges) {
        assert(secondary.routing.rules.some(row => row.domain?.includes('full:' + bridge.domain)
            && upstreamOutbounds.some(out => out.tag === row.outboundTag)));
        assert(secondary.routing.rules.some(row => row.inboundTag?.includes(bridge.tag)
            && row.outboundTag === 'portal-down-' + DOWN.slice(-8)));
    }
    assert(secondary.routing.rules.some(row => row.inboundTag?.includes('cascade-main')
        && row.outboundTag === 'portal-down-' + DOWN.slice(-8)));
    assert.equal(f.events.filter(row => row === 'lock').length, 1);
    assert.equal(f.rows.size, 0);
});

for (const candidateFailure of [false, true]) test(`forward preparation retains full node routing and actual grouped subscribers with faithful projection: candidateFailure=${candidateFailure}`, async () => {
    const priorMode = group.mode;
    const prior = Object.fromEntries(['groups', 'outbounds', 'aclRules', 'domain', 'sni'].map(key => [key, relay[key]]));
    Object.assign(relay, { groups: ['507f1f77bcf86cd799439099'],
        outbounds: [{ name: 'operator-egress', type: 'socks5', addr: '192.0.2.99:1080' }],
        aclRules: ['operator-egress(all)'], domain: 'relay.example.invalid', sni: 'relay.example.invalid' });
    const f = fixture(); group.mode = 'forward';
    f.links.splice(1, 1, { ...downstream, mode: 'forward' });
    seedAppliedForwardProfile();
    // Actual _getUsersForNode implementation, with only its persistence/import
    // seam modeled. No replacement of the group-vs-ungrouped branch under test.
    const filename = require.resolve('../syncService');
    const loaded = new Module(filename, module); loaded.filename = filename;
    loaded.paths = Module._nodeModulePaths(require('node:path').dirname(filename));
    const grouped = { ...users[0], userId: 'group-subscriber' };
    const unrelated = { userId: 'unrelated-ungrouped', xrayUuid: '00000000-0000-4000-8000-000000000099' };
    loaded.require = request => request.endsWith('/hyUserModel') ? { find: filter => query(filter.nodes ? [] : filter.groups?.$in ? [grouped] : [unrelated]) }
        : request === 'https' ? require('node:https') : request === '../utils/logger' ? { info() {}, warn() {}, error() {} } : {};
    loaded._compile(require('node:fs').readFileSync(filename, 'utf8'), filename);
    active.resolveUsers = node => loaded.exports._getUsersForNode(node);
    if (candidateFailure) f.candidateService.userResolver = async () => { throw new Error('modeled user resolver failure after checked preparation'); };
    try {
        assert(JSON.parse(f.live).outbounds.some(row => row.tag === 'operator-egress'));
        const result = await assembledRuntime(f).worker.runOnce();
        assert.equal(result.status, candidateFailure ? 'failed' : 'succeeded');
        const prepared = JSON.parse(f.uploads.find(row => row.path === '/usr/local/etc/xray/config.json').content);
        for (const config of [prepared, JSON.parse(active.live)]) {
            assert(config.outbounds.some(row => row.tag === 'operator-egress'), 'prepared/live MAIN must retain the operator outbound');
            assert(config.routing.rules.some(row => row.outboundTag === 'operator-egress'), 'prepared/live MAIN must retain ACL routing');
            assert.deepEqual(config.inbounds.find(row => row.tag === 'vless-in').settings.clients.map(row => row.email), [grouped.userId]);
            assert(config.inbounds.some(row => row.tag === 'relay-l2tp-other'));
        }
        assert(f.commands.some(command => command.includes('systemctl restart xray')));
        if (candidateFailure) {
            assert(!f.uploads.some(row => row.path === 'xray-candidate.json'));
            assert.equal(f.rows.size, 0, 'known completed preparation can release after local candidate refusal without losing prior MAIN settings');
        }
    } finally {
        group.mode = priorMode;
        for (const [key, value] of Object.entries(prior)) { if (value === undefined) delete relay[key]; else relay[key] = value; }
    }
});

test('assembled forward preparation deploys MAIN ingress and candidate rereads that prepared MAIN', async () => {
    const f = fixture(); const priorMode = group.mode; group.mode = 'forward';
    f.links.splice(1, 1, { ...downstream, mode: 'forward' });
    seedAppliedForwardProfile();
    try {
        assert.equal((await assembledRuntime(f).worker.runOnce()).status, 'succeeded');
        const prepared = f.uploads.find(row => row.path === '/usr/local/etc/xray/config.json');
        assert(prepared);
        const candidate = JSON.parse(f.uploads.find(row => row.path === 'xray-candidate.json').content);
        assert.equal(candidate.inbounds.find(row => row.tag === 'cascade-main').port, cascadePathIngressPort(GROUP, 'main'));
        assert(candidate.routing.rules.some(row => row.inboundTag?.includes('cascade-main') && row.outboundTag === 'fwd-' + DOWN.slice(-8)));
        assert.equal(candidate.outbounds.find(row => row.tag === 'fwd-' + DOWN.slice(-8)).settings.vnext[0].users[0].id, downstream.tunnelUuid);
        assert(f.events.indexOf('upload:/usr/local/etc/xray/config.json') < f.events.lastIndexOf('live-main'));
        assert.equal(f.events.filter(row => row === 'lock').length, 1);
    } finally { group.mode = priorMode; }
});

for (const mode of ['conflict', 'veto', 'uploadFailure', 'restartFailure']) {
    test('assembled default path refuses/retains correctly: ' + mode, async () => {
        const f = fixture({ [mode]: true });
        const result = await assembledRuntime(f).worker.runOnce();
        if (mode === 'uploadFailure' || mode === 'restartFailure') {
            assert.equal(result.errorCode, 'REMOTE_COMMAND_OUTCOME_UNCERTAIN');
            assert.equal(f.rows.size, 1);
            assert(f.events.includes('retained'));
            assert.equal(f.events.filter(row => row === 'live-main').length, 1, 'only the pre-write MAIN read may happen before uncertain preparation stops');
            assert(!f.events.some(row => row.startsWith('candidate-upload:')));
        } else {
            assert.equal(result.status, 'failed');
            assert(!f.events.includes('connect'));
            assert.equal(f.uploads.length, 0);
            if (mode === 'veto') assert.equal(f.rows.size, 0, 'known local veto releases exact generation');
            else assert.equal(f.rows.get(NODE).generation, 'foreign');
        }
    });
}

for (const veto of [false, true]) {
    test('actual sync_users worker shares post-lock durable owner veto: ' + veto, async () => {
        const f = fixture({ veto });
        const result = await assembledRuntime(f, 'sync_users').worker.runOnce();
        assert.equal(result.status, veto ? 'failed' : 'succeeded');
        assert(f.events.indexOf('lock') < f.events.indexOf('owner-read'));
        assert.equal(f.events.includes('user-snapshot'), !veto);
        assert.equal(f.events.some(row => row.startsWith('runner:')), !veto);
        assert.equal(f.rows.size, 0);
    });
}

test('held worker scope refuses foreign generation and escaped callbacks', async () => {
    const f = fixture();
    const { withHeldL2tpNodeConfigWrite, withClassicNodeConfigWrite } = require('../classicNodeConfigWrite');
    const acquired = await f.lockService.acquire({ node: NODE, owner: 'worker', operationId: 'install-op', leaseMs: 30000 });
    let escaped;
    await withHeldL2tpNodeConfigWrite({ lock: acquired.lock, lockService: f.lockService, clock: { now: () => new Date() } }, async () => {
        escaped = new Promise(resolve => { setImmediate(() => resolve(withClassicNodeConfigWrite({ nodeId: NODE, kind: 'escape' }, async () => { throw new Error('must not dispatch'); }))); });
    });
    await assert.rejects(escaped, { code: 'CLASSIC_CONFIG_WRITE_SCOPE_CLOSED' });
    f.rows.set(NODE, { ...acquired.lock, generation: 'replacement' });
    await assert.rejects(withHeldL2tpNodeConfigWrite({ lock: acquired.lock, lockService: f.lockService, clock: { now: () => new Date() } }, async () => { throw new Error('must not dispatch'); }), { code: 'CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN' });
});

for (const method of ['_deployPortalConfig', '_deployBridgeConfig', '_deployRelayNode', '_deployPureBridge', '_deployForwardHopConfig']) {
    test('full classic entry loses to an existing generation before generation/read/upload: ' + method, async () => {
        const f = fixture({ conflict: true });
        const cascade = require('../cascadeService');
        const args = method === '_deployBridgeConfig' ? [upstream, relay, head]
            : method === '_deployRelayNode' ? [relay, upstream, head, [downstream]]
                : method === '_deployPureBridge' ? [relay, upstream, head] : [relay, []];
        await assert.rejects(cascade[method](...args), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
        assert.deepEqual(f.events, ['lock']);
        assert.equal(f.uploads.length, 0);
        assert.equal(f.rows.get(NODE).generation, 'foreign');
    });
}

test('missing selected accepted link refuses before remote preparation and never falls back direct', async () => {
    const f = fixture();
    f.links.splice(1);
    const result = await assembledRuntime(f).worker.runOnce();
    assert.equal(result.status, 'failed');
    assert.equal(f.uploads.length, 0);
    assert(!f.events.includes('connect'));
    assert.equal(f.rows.size, 0);
});

test('actual sync composition adds forward path ingress and retains scoped private refusal after live merge', async () => {
    const f = fixture();
    const priorMode = group.mode;
    group.mode = 'forward';
    f.links.splice(0, f.links.length, { ...downstream, mode: 'forward' });
    const fragment = buildL2tpXrayFragment({ plan: { relay: { controlPlaneIps: [relay.ip] }, group: { id: GROUP },
        paths: [{ pathKey: 'main', healthy: true, outboundTag: 'cascade-main' }], selectedPathKey: 'main' },
        tags: { inbound: 'relay-l2tp-' + GROUP, blockOutbound: 'block' }, tproxyPort: 12345 });
    active.live = generator.generateXrayConfigWithApi(relay, users, { fragments: [fragment] });
    seedAppliedForwardProfile();
    const fs = require('node:fs'), path = require('node:path');
    const filename = path.resolve(__dirname, '../syncService.js');
    const loaded = new Module(filename, module);
    loaded.filename = filename; loaded.paths = Module._nodeModulePaths(path.dirname(filename));
    loaded.require = request => {
        if (['./configGenerator', './classicL2tpConfigComposition', './classicAppliedConfig', './classicNodeConfigWrite', './topologyConfigOwnership', './cascadeService'].includes(request)
            || request.endsWith('/l2tpExecutionAuthorization') || request.endsWith('/l2tpXrayConfigMerge')) return Module.prototype.require.call(loaded, request);
        if (request === './nodeSSH') return SSH;
        if (request.endsWith('/hyNodeModel')) return { updateOne: async () => ({ matchedCount: 1 }) };
        if (request.endsWith('/relayL2tpStateModel')) return { exists: async () => true };
        if (request.endsWith('/cascadeLinkModel')) return { find: filter => query(active.links.filter(row => matches(row, filter))) };
        if (request === '../utils/helpers') return { invalidateNodesCache: async () => {} };
        if (request === '../utils/logger') return { info() {}, warn() {}, error() {} };
        if (request === 'https') return require('node:https');
        return {};
    };
    loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
    const sync = loaded.exports;
    sync._getUsersForNode = async () => users;
    sync.checkXrayAgentHealth = async () => ({ online: true });
    const lock = await f.lockService.acquire({ node: NODE, owner: 'worker', operationId: 'install-op', leaseMs: 30000 });
    try {
        const result = await f.candidateService.withLockedPreparation({ lock: lock.lock, lockService: f.lockService,
            clock: { now: () => new Date() } }, () => sync.updateXrayNodeConfig(relay));
        assert.equal(result, true);
        const config = JSON.parse(f.uploads.find(row => row.path === '/usr/local/etc/xray/config.json').content);
        assert.equal(config.inbounds.find(row => row.tag === 'cascade-main').port, cascadePathIngressPort(GROUP, 'main'));
        assert.equal(config.outbounds.find(row => row.tag === 'fwd-' + DOWN.slice(-8)).settings.vnext[0].users[0].id, downstream.tunnelUuid);
        assert(config.routing.rules.some(row => row.inboundTag?.includes('cascade-main') && row.outboundTag === 'fwd-' + DOWN.slice(-8)));
        assert(config.routing.rules.some(row => row.inboundTag?.includes('relay-l2tp-' + GROUP) && row.ip?.includes('geoip:private') && row.outboundTag === 'block'));
        assert.equal(config.inbounds.find(row => row.tag === 'vless-in').settings.clients[0].id, users[0].xrayUuid);
        assert.equal(f.events.filter(row => row === 'lock').length, 1);
    } finally { group.mode = priorMode; }
});

for (const content of ['not-json', '{}']) {
    test('unavailable live MAIN refuses before secondary or main write: ' + content, async () => {
        const f = fixture(); active.live = content;
        const result = await assembledRuntime(f).worker.runOnce();
        assert.equal(result.status, 'failed');
        assert(f.events.includes('live-main'));
        assert.equal(f.uploads.length, 0);
        assert.equal(f.rows.size, 0);
    });
}

for (const mode of ['success', 'undefined', 'false', 'timeout']) {
    test('classic full portal completion/poison under inherited worker generation: ' + mode, async () => {
        const f = fixture();
        active.agentResult = mode === 'success' ? { status: 200, data: { ok: true } } : mode === 'false' ? false : undefined;
        if (mode === 'timeout') active.agentError = new Error('modeled agent timeout');
        const acquired = await f.lockService.acquire({ node: NODE, owner: 'worker', operationId: 'install-op', leaseMs: 30000 });
        const run = () => f.candidateService.withLockedPreparation({ lock: acquired.lock, lockService: f.lockService, clock: { now: () => new Date() } },
            () => require('../cascadeService')._deployPortalConfig({ ...relay, xray: { ...relay.xray, agentToken: 'fake-token' } }));
        if (mode === 'success') assert.equal(await run(), true);
        else await assert.rejects(run(), error => error.remoteOutcomeUncertain === true);
        assert(f.events.includes('agent-restart'));
        assert(!f.commands.some(command => command.includes('systemctl restart xray')));
        assert.equal(f.events.filter(row => row === 'lock').length, 1);
        assert.equal(f.rows.get(NODE).generation, acquired.lock.generation);
    });
}

test('uninstall checks native durable owner after exact lock and before SSH construction', async () => {
    const f = fixture({ veto: true }); active.teardown = true;
    f.legacy = { data: { cascadetopologystates: [{ _id: 'singleton', topologyAdmissionCount: 0, remoteAdmissionCount: 0 }] } };
    const remote = standaloneRepository(f);
    const release = remote.repository.release.bind(remote.repository);
    remote.repository.release = async admissionId => { await release(admissionId); f.events.push('admission-released'); };
    const { service } = uninstallService(f, remote);
    await assert.rejects(service.uninstallRelay(NODE), { code: 'CLASSIC_CONFIG_WRITE_OWNER_VETO' });
    assert.deepEqual(f.events, ['lock', 'owner-read', 'release', 'admission-released']);
    assert.equal(f.rows.size, 0);
});

// B1: assembled default-root services + actual worker/simple paths, with
// SIMULATED persistence, SSH and physical authority (no network/database).
async function releasedFixture() {
    const f = fixture();
    const legacy = require('./fixtures/legacyReleaseSimulation').fixture();
    legacy.data.hynodes[0] = { ...relay };
    await legacy.service().retire();
    Object.defineProperty(legacy.data, 'nodeoperationlocks', { get: () => [...f.rows.values()] });
    f.legacy = active.legacy = legacy;
    f.executionContext = require('../../modules/relay-l2tp/domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT;
    active.assertScope = async () => require('../classicNodeConfigWrite').assertHeldL2tpNodeConfigWrite(NODE);
    const guard = f.candidateService.assertConfigWriteAllowed;
    f.candidateService.assertConfigWriteAllowed = async node => {
        await guard(node); await active.assertScope(); f.events.push('guard-held');
    };
    return f;
}
for (const kind of ['install', 'sync_users']) test('receipt assembled actual worker succeeds inside held pre-remote scope: ' + kind, async () => {
    const f = await releasedFixture();
    const history = require('mongodb').BSON.serialize({ rows: f.legacy.data.topologyoperations });
    const result = await assembledRuntime(f, kind).worker.runOnce();
    assert.deepEqual(result, { claimed: true, operationId: 'install-op', status: 'succeeded' });
    assert(f.events.indexOf('guard-held') > f.events.indexOf('lock'));
    const firstRemote = f.events.findIndex(e => e === 'connect' || e.startsWith('runner:') || e.startsWith('candidate-upload:'));
    assert(firstRemote > f.events.indexOf('guard-held'));
    assert(f.events.indexOf('release') < f.events.indexOf('admission-done'));
    assert.equal(f.rows.size, 0);
    assert.equal(f.legacy.data.remoteadmissions[0].phase, 'completed');
    assert.equal(f.legacy.data.cascadetopologystates[0].remoteAdmissionCount, 0);
    assert.deepEqual(require('mongodb').BSON.serialize({ rows: f.legacy.data.topologyoperations }), history);
});
// Actual standalone acquire()/release() create their real schema shape, NOT a
// made-up operationId to satisfy recognition. Only model persistence is fake.
function standaloneRepository(f) {
    const { RemoteAdmissionRepository } = require('../../modules/relay-l2tp/repositories/remoteAdmissionRepository');
    const data = f.legacy.data;
    const connection = { startSession: async () => ({ withTransaction: work => work({}), endSession: async () => {} }),
        transaction: work => work({}) };
    const matches = (row, filter) => require('sift').default(filter)(row);
    f.model.db = connection;
    const CascadeTopologyState = { db: connection, findById: () => query({ stateTransitionRevision: 0 }),
        findOneAndUpdate: () => query({ stateTransitionRevision: 1 }),
        updateOne: async (filter, update) => {
            const row = data.cascadetopologystates.find(r => matches(r, filter));
            if (!row) return { matchedCount: 0 };
            for (const [key, n] of Object.entries(update.$inc || {})) row[key] = (row[key] || 0) + n;
            return { matchedCount: 1 };
        } };
    const RemoteAdmission = { db: connection,
        findOne: filter => query((data.remoteadmissions || []).find(row => matches(row, filter)) || null),
        create: async rows => { (data.remoteadmissions ||= []).push(...rows); return rows; },
        updateOne: async (filter, update) => { const row = data.remoteadmissions.find(r => matches(r, filter));
            if (!row) return { matchedCount: 0 }; Object.assign(row, update.$set); return { matchedCount: 1 }; } };
    return { repository: new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission,
        transactionRunner: work => work({}) }), connection, CascadeTopologyState, RemoteAdmission };
}
function uninstallService(f, remote) {
    const { L2tpSimpleService } = require('../../modules/relay-l2tp/services/l2tpSimpleService');
    active.teardown = true;
    const state = { node: NODE, status: 'installed' };
    const service = new L2tpSimpleService({ configWriteEnv: { ...process.env }, allowRemoteExecution: true,
        HyNode: { find: () => query([relay]), findById: () => query(relay) },
        RelayL2tpState: { db: remote.connection, find: () => query([]), findOne: () => query(state),
            findOneAndUpdate: async (_, update) => { Object.assign(state, update.$set); return state; } },
        CascadeTopologyState: remote.CascadeTopologyState,
        L2tpUser: { find: () => query([]) }, CascadeRouteGroup: { find: () => query([]) },
        l2tpService: { install() {}, getOperation() {} }, stateManagementService: { configureRelay() {}, revealPsk() {} },
        userManagementService: { createUser() {}, deleteUser() {}, importUser() {} },
        stateRepository: { getTopologyRevision: async () => 196 }, lockService: f.lockService,
        remoteAdmissionRepository: remote.repository,
        nodeSSHFactory: () => ({ exec: async () => { await active.assertScope(); f.assertHeld();
            f.events.push('teardown-ssh'); await f.afterTeardown?.(); return { code: 0, stdout: 'TEARDOWN_OK' }; }, disconnect() {} }),
    });
    return { service, state };
}
test('receipt assembled actual simple uninstall binds real acquired standalone admission', async () => {
    const f = await releasedFixture(); const remote = standaloneRepository(f);
    const { service, state } = uninstallService(f, remote);
    assert.deepEqual(await service.uninstallRelay(NODE), { ok: true });
    assert.equal(state.status, 'not_installed');
    assert.equal(f.rows.size, 0);
    const [admission] = f.legacy.data.remoteadmissions;
    assert.equal(admission.kind, 'standalone_preflight');
    assert.equal(admission.phase, 'completed');
    assert.equal(Object.hasOwn(admission, 'operationId'), false);
    assert.equal(Object.hasOwn(admission, 'leaseOwner'), false);
    assert.equal(f.legacy.data.cascadetopologystates[0].remoteAdmissionCount, 0);
    assert(f.events.indexOf('owner-read') < f.events.indexOf('teardown-ssh'));
});

for (const [name, mutate] of [
    ['wrong-node', a => { a.nodeId = HEAD; }],
    ['replacement-id', a => { a._id = 'replacement-admission'; }],
    ['foreign-worker-link', a => { a.operationId = 'foreign'; }],
    ['wrong-kind', a => { a.kind = 'install'; }],
    ['wrong-generation', a => { a.ownerGeneration = 2; }],
    ['non-running', a => { a.phase = 'recovery_required'; }],
]) test('receipt actual uninstall refuses foreign standalone admission before SSH: ' + name, async () => {
    const f = await releasedFixture(); const remote = standaloneRepository(f);
    const { service, state } = uninstallService(f, remote);
    const acquire = f.lockService.acquire.bind(f.lockService);
    f.lockService.acquire = async input => { const result = await acquire(input);
        mutate(f.legacy.data.remoteadmissions[0]); return result; };
    await assert.rejects(service.uninstallRelay(NODE));
    assert(!f.events.includes('teardown-ssh'));
    assert.equal(state.status, 'installed');
    assert.equal(f.legacy.data.cascadetopologystates[0].remoteAdmissionCount, 1);
});
for (const drift of ['admission-replacement', 'generation-replacement', 'expired-lease', 'admission-read-error'])
test('receipt actual uninstall retains fences on post-SSH drift: ' + drift, async () => {
    const f = await releasedFixture(); const remote = standaloneRepository(f);
    const { service, state } = uninstallService(f, remote);
    f.afterTeardown = () => {
        if (drift === 'admission-replacement') f.legacy.data.remoteadmissions[0]._id = 'replacement-admission';
        if (drift === 'generation-replacement') f.rows.set(NODE, { ...f.rows.get(NODE), generation: 'replacement' });
        if (drift === 'expired-lease') f.rows.get(NODE).leaseUntil = new Date(0);
        if (drift === 'admission-read-error') remote.repository.RemoteAdmission.findOne = () => ({
            setOptions() { return this; }, lean: async () => { throw new Error('SIMULATED read failure'); } });
    };
    await assert.rejects(service.uninstallRelay(NODE));
    assert(f.events.includes('teardown-ssh'));
    assert.equal(state.status, 'installed');
    assert.equal(f.rows.size, 1, 'final held verification must fail before exact release');
    assert.equal(f.legacy.data.cascadetopologystates[0].remoteAdmissionCount, 1);
    assert.equal(f.legacy.data.remoteadmissions[0].phase, 'running');
});
test('receipt genuine standalone held scope refuses outside, escaped and replaced generation', async () => {
    const f = await releasedFixture(); const remote = standaloneRepository(f);
    const admissionId = await remote.repository.acquire({ nodeId: NODE });
    const acquired = await f.lockService.acquire({ node: NODE, owner: 'worker', operationId: 'install-op', leaseMs: 30000 });
    const { withHeldL2tpNodeConfigWrite } = require('../classicNodeConfigWrite');
    const read = () => require('../testLegacyTopologyRelease').hasTestLegacyTopologyRelease({
        db: f.legacy.db, nodeId: NODE, env: process.env });
    await assert.rejects(read(), /SCOPE_CLOSED/);
    let escaped;
    const scope = { lock: acquired.lock, lockService: f.lockService, clock: f.lockService.clock,
        standaloneAdmission: { id: admissionId, repository: remote.repository } };
    await withHeldL2tpNodeConfigWrite(scope, async () => {
        assert.equal(await read(), true);
        escaped = new Promise(resolve => setImmediate(() => resolve(read())));
    });
    await assert.rejects(escaped, /SCOPE_CLOSED/);
    f.rows.set(NODE, { ...acquired.lock, generation: 'foreign-generation' });
    await assert.rejects(withHeldL2tpNodeConfigWrite(scope, read), /LOCK_UNCERTAIN/);
    assert.equal(f.rows.size, 1);
});

for (const kind of ['install', 'sync_users']) for (const veto of ['native-owner', 'foreign-admission']) {
    test(`receipt actual worker keeps ${veto} veto before first SSH: ${kind}`, async () => {
        const f = await releasedFixture();
        if (veto === 'native-owner') f.legacy.data.topologyconfigowners = [{}];
        else {
            const create = f.model.create;
            f.model.create = async row => { const lock = await create(row);
                f.legacy.data.remoteadmissions[0].operationId = 'foreign-operation'; return lock; };
        }
        const result = await assembledRuntime(f, kind).worker.runOnce();
        assert.equal(result.status, 'failed');
        assert(!f.events.includes('connect'));
        assert(!f.events.includes('user-snapshot'));
        assert(!f.events.some(e => e.startsWith('runner:') || e.startsWith('candidate-upload:')));
    });
}
test('receipt genuine standalone scope rejects a repository from a foreign connection', async () => {
    const f = await releasedFixture(); const remote = standaloneRepository(f);
    const admissionId = await remote.repository.acquire({ nodeId: NODE });
    const acquired = await f.lockService.acquire({ node: NODE, owner: 'worker', operationId: 'install-op', leaseMs: 30000 });
    remote.repository.RemoteAdmission.db = { foreign: true };
    await assert.rejects(require('../classicNodeConfigWrite').withHeldL2tpNodeConfigWrite({
        lock: acquired.lock, lockService: f.lockService, clock: f.lockService.clock,
        standaloneAdmission: { id: admissionId, repository: remote.repository },
    }, () => { throw new Error('must not dispatch'); }), /ADMISSION_UNCERTAIN/);
    assert.equal(f.rows.size, 1);
});

for (const kind of ['install', 'sync_users']) test('receipt actual worker retains unknown held completion before settlement: ' + kind, async () => {
    const f = await releasedFixture();
    if (kind === 'install') {
        const build = f.candidateService.buildCandidate.bind(f.candidateService);
        f.candidateService.buildCandidate = async input => { const result = await build(input);
            f.rows.get(NODE).leaseUntil = new Date(0); return result; };
    } else f.resolveUserSnapshot = async () => { f.rows.get(NODE).leaseUntil = new Date(0);
        return { credentialRevision: 7, users: [] }; };
    const result = await assembledRuntime(f, kind).worker.runOnce();
    assert.equal(result.errorCode, 'REMOTE_COMMAND_OUTCOME_UNCERTAIN');
    assert.equal(result.stopped, true);
    assert.equal(f.rows.size, 1);
    assert.equal(f.legacy.data.cascadetopologystates[0].remoteAdmissionCount, 1);
    assert(!f.events.includes('release'));
    assert(!f.events.includes('admission-done'));
});

test('receipt actual execution factory forwards root-owned guard to real simple uninstall', async () => {
    const f = await releasedFixture(); const remote = standaloneRepository(f); active.teardown = true;
    const { createL2tpExecutionRuntime } = require('../../modules/relay-l2tp/runtime/createL2tpExecutionRuntime');
    const state = { node: NODE, status: 'installed', ...f.plan.desired };
    class TeardownSSH {
        async exec() { await active.assertScope(); f.events.push('factory-teardown-ssh');
            return { code: 0, stdout: 'TEARDOWN_OK' }; }
        disconnect() {}
    }
    const rootDependencies = f.root;
    const host = createL2tpExecutionRuntime({ ...rootDependencies,
        workerLifecycle: { enabled: true },
        HyNode: { find: () => query([relay]), findById: () => query(relay) },
        RelayL2tpState: { db: remote.connection, find: () => query([]), findOne: () => query(state),
            findOneAndUpdate: async (_, update) => { Object.assign(state, update.$set); return state; } },
        L2tpUser: { find: () => query([]), findOne: () => query(null),
            findOneAndUpdate: async () => { throw new Error('unused user write'); },
            create: async () => { throw new Error('unused user create'); } },
        CascadeRouteGroup: { find: () => query([]) },
        CascadeTopologyState: remote.CascadeTopologyState, RemoteAdmission: remote.RemoteAdmission,
        operationModel: {}, lockModel: f.model, NodeSSH: TeardownSSH, NodeTransport: class {},
        createCandidateService: () => f.candidateService,
        createUserSnapshotResolver: () => async () => ({ credentialRevision: 7, users: [] }),
        createUserSyncReconciler: () => ({ finalizeVerifiedSync() {} }),
        stateManagementService: { configureRelay() {}, revealPsk() {} },
        secretBox: { encrypt() {}, decrypt() {} }, secretKey: 'SIMULATED-key',
        runtimeDependencies: { executionContext: f.executionContext, enableInstallAdmission: true,
            stateRepository: { getTopologyRevision: async () => 196 } },
        createRuntime: () => ({ service: { install() {}, getOperation() {} }, worker: {} }),
        createWorkerLifecycle: () => ({ start() {}, stop() {} }),
    });
    assert.deepEqual(await host.runtime.simpleService.uninstallRelay(NODE), { ok: true });
    assert(f.events.indexOf('guard-held') < f.events.indexOf('factory-teardown-ssh'));
    assert.equal(f.rows.size, 0);
    assert.equal(f.legacy.data.cascadetopologystates[0].remoteAdmissionCount, 0);
    assert.equal(f.legacy.data.remoteadmissions[0].phase, 'completed');
});

process.on('exit', () => { Module._load = original; });