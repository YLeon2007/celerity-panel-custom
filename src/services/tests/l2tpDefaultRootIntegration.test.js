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
const NODE = '507f1f77bcf86cd799439011';
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
const query = value => ({ select() { return this; }, lean: async () => value, populate() { return this; }, then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); } });
const id = value => String(value?._id ?? value);
const matches = (row, filter) => Object.entries(filter).every(([key, value]) => {
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
        if (request.endsWith('/topologyOperationModel')) return { exists: async () => { active.events.push('owner-read'); active.assertHeld(); return false; } };
        if (request === 'mongoose') {
            const real = original.call(this, request, parent, isMain);
            return { Types: real.Types, connection: { db: { collection: () => ({ find: () => ({ toArray: async () => active.owners }) }) } } };
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
        if (request === './syncService') return { _getUsersForNode: async () => users,
            _agentRequest: async () => { active.events.push('agent-restart'); if (active.agentError) throw active.agentError; return active.agentResult; } };
        if (request === './cacheService' || request === './webhookService') return {};
    }
    if (filename.endsWith('/classicNodeConfigWrite.js') && request.endsWith('/nodeOperationLockModel')) return active.model;
    return original.call(this, request, parent, isMain);
};
class SSH {
    constructor(node) { this.node = node; }
    async connect() { active.assertHeld(); active.events.push('connect'); }
    disconnect() {}
    async uploadContent(content, path) {
        active.assertHeld(); active.events.push('upload:' + path); active.uploads.push({ content, path });
        if (active.uploadFailure) throw new Error('unknown SFTP');
        if (path === '/usr/local/etc/xray/config.json') active.live = content;
    }
    async exec(command) {
        active.assertHeld(); active.commands.push(command); active.events.push(command.includes('cat /usr/local/etc/xray/config.json') ? 'live-main' : 'exec');
        let stdout = command.includes('cat /usr/local/etc/xray/config.json') ? active.live : command.includes('is-active') ? 'active' : '/usr/local/bin/xray';
        const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/);
        if (receipt) stdout += '\n' + receipt[0] + '\n';
        return { code: active.restartFailure && command.includes('systemctl restart xray-bridge') ? 1 : 0, stdout, stderr: '' };
    }
}
const { createL2tpRootHostDependencies } = require('../../modules/l2tpRuntimeLifecycleHook');
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
        owners: veto ? [{ node: NODE, profile: 'xray-main', owner: 'topology', executionContext: context, generation: '00000000-0000-4000-8000-000000000001', nodeIdentity: { machineId: 'a'.repeat(32), sshHostKeySha256: 'b'.repeat(64) } }] : [],
        assertHeld() { const row = rows.get(NODE); assert(row && row.remoteUncertain === true
            && (active.teardown ? row.owner.startsWith('simple-uninstall:') : row.owner === 'worker' && row.operationId === 'install-op'),
            'remote/generation must be under the worker node lock'); },
    };
    const root = createL2tpRootHostDependencies({ env: process.env, HyNode: { findById: nodeId => query([relay, head, exit].find(row => id(row) === id(nodeId))) }, NodeSSH: SSH,
        syncService: { _getUsersForNode: async () => users }, createTopologyExecutionAuthority: () => undefined,
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
        leaseOwner: 'worker', ownerGeneration: 1, admissionId: 'admitted', executionContext: context,
        plan: kind === 'install' ? f.plan : { ok: true, operationId: 'install-op', relayId: NODE, desired: { credentialRevision: 7 },
            steps: [{ type: 'backup' }, { type: 'sync_users', artifacts: [{ type: 'desired', path: 'desired.json' }] }, { type: 'verify_users' }] } };
    const pass = (_req, _res, next) => next();
    const runtime = createL2tpRuntime({
        executionContext: context, enableProductionExecution: true,
        operationModel: { updateOne: async (filter, update) => { f.events.push('operation-write');
            assert.equal(filter.leaseOwner, 'worker'); assert.equal(filter.ownerGeneration, 1);
            if (update.$set?.status) operation.status = update.$set.status;
            return { matchedCount: 1 }; } },
        operationRepository: {}, nodeRepository: {}, stateRepository: {}, stateManagementService: {}, userManagementService: {},
        preflightRunner: async () => ({}), lockService: f.lockService,
        remoteAdmissionRepository: {
            claimQueuedInstall: async () => { if (claimed) return null; claimed = true; return operation; },
            claimQueuedSyncUsers: async () => null,
            completeTerminalOperation: async () => { f.events.push('admission-terminal'); return true; },
            completeVerifiedOperation: async () => { assert.equal(f.rows.size, 0); f.events.push('admission-done'); return true; },
            markOperationRecoveryRequired: async () => { f.events.push('retained'); return true; },
        },
        secretResolver: async () => { f.assertHeld(); f.events.push('psk'); return { psk: 'already-stored-psk', users: [] }; },
        userSnapshotResolver: async () => { f.assertHeld(); f.events.push('user-snapshot'); return { credentialRevision: 7, users: [] }; },
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

test('assembled forward preparation deploys MAIN ingress and candidate rereads that prepared MAIN', async () => {
    const f = fixture(); const priorMode = group.mode; group.mode = 'forward';
    f.links.splice(1, 1, { ...downstream, mode: 'forward' });
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
    const fs = require('node:fs'), path = require('node:path');
    const filename = path.resolve(__dirname, '../syncService.js');
    const loaded = new Module(filename, module);
    loaded.filename = filename; loaded.paths = Module._nodeModulePaths(path.dirname(filename));
    loaded.require = request => {
        if (['./configGenerator', './classicL2tpConfigComposition', './classicNodeConfigWrite', './topologyConfigOwnership', './cascadeService'].includes(request)
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
    const { L2tpSimpleService } = require('../../modules/relay-l2tp/services/l2tpSimpleService');
    const service = new L2tpSimpleService({
        configWriteEnv: { PANEL_DOMAIN: context.hostIdentity }, allowRemoteExecution: true,
        HyNode: { find: () => query([relay]), findById: () => query(relay) },
        RelayL2tpState: { find: () => query([]), findOne: () => query({ node: NODE, status: 'installed' }) },
        L2tpUser: { find: () => query([]) }, CascadeRouteGroup: { find: () => query([]) },
        l2tpService: { install() {}, getOperation() {} }, stateManagementService: { configureRelay() {}, revealPsk() {} },
        userManagementService: { createUser() {}, deleteUser() {}, importUser() {} },
        stateRepository: { getTopologyRevision: async () => 196 }, lockService: f.lockService,
        remoteAdmissionRepository: { acquire: async () => 'admitted', release: async () => { f.events.push('admission-released'); } },
        nodeSSHFactory: () => { throw new Error('must not construct SSH on owner veto'); },
    });
    await assert.rejects(service.uninstallRelay(NODE), { code: 'CLASSIC_CONFIG_WRITE_OWNER_VETO' });
    assert.deepEqual(f.events, ['lock', 'owner-read', 'release', 'admission-released']);
    assert.equal(f.rows.size, 0);
});

process.on('exit', () => { Module._load = original; });
