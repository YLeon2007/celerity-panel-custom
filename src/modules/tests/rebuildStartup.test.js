'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const entry = path.resolve(__dirname, '../../../index.js');

const probe = `
const assert = require('node:assert/strict');
const Module = require('node:module');
const noIO = name => () => assert.fail('unexpected ' + name);
const net = require('node:net');
net.Socket.prototype.connect = noIO('network connect');
net.Server.prototype.listen = noIO('network listen');
const http = require('node:http');
const { EventEmitter } = require('node:events');
const requests = (app, method, url) => new Promise(resolve => {
    const req = new http.IncomingMessage(new net.Socket());
    Object.assign(req, { url, method, session: { authenticated: true } });
    const res = new http.ServerResponse(req);
    res.end = bytes => resolve({ status: res.statusCode, body: JSON.parse(String(bytes)) });
    app(req, res);
});
const load = Module._load;
const ddl = { collections: [], indexes: [] };
const cron = new Map();
const startup = [];
let connect;
Module._load = function(id, parent) {
    if (id === 'dotenv') return { config() {
        if (process.env.DUMMY_DOTENV_CONFLICT) process.env.L2TP_MIGRATIONS_ENABLED = 'true';
    } };
    if (process.env.DUMMY_CONFLICT && (id === 'mongoose' || id === './src/utils/logger')) {
        assert.fail('application imported before validation: ' + id);
    }
    if (/l2tpModelIndexReadiness|l2tpMigrationBootstrap|createL2tpStartupLifecycle|productionPhysicalAuthority|createTopologyOperationRuntime|createL2tpPanelHost|topologyTestActivation|topologyTransferDrafts/.test(id)) {
        assert.fail('strict runtime imported: ' + id);
    }
    if (id === 'node-cron') return { schedule(expr, callback) { cron.set(expr, callback); return { stop() {} }; } };
    if (id === 'http' && parent?.filename === process.argv[1]) {
        return { createServer(app) {
            const server = new EventEmitter();
            server.listen = (...args) => {
                startup.push('listen');
                args.at(-1)();
                setImmediate(() => verify(app).catch(error => { console.error(error); process.exit(1); }));
            };
            return server;
        } };
    }
    if (id === './src/services/accessLogs/processService') return { start() { startup.push('access-logs'); } };
    const value = load.apply(this, arguments);
    if (id.endsWith('/modules/relay-l2tp')) return {
        ...value,
        registerModels: noIO('strict model catalog registration'),
        registerRoutes: noIO('L2TP route registration'),
        createTopologyDeploymentService: noIO('strict deployment coordinator'),
    };
    if (id === 'mongoose' && !connect) {
        const pending = Promise.withResolvers();
        value.connection._waitForConnect = () => pending.promise;
        value.Model.createCollection = async function() { ddl.collections.push(this.modelName); };
        value.Model.ensureIndexes = async function() { ddl.indexes.push(this.modelName); };
        connect = value.connect = async (uri, options) => {
            Object.assign(value.connection.config, options);
            value.connection.collection = () => ({ async indexes() { return []; }, async dropIndex() {} });
            pending.resolve();
        };
    }
    if (id === './src/services/cacheService' && parent?.filename === process.argv[1]) {
        value.connect = async () => {
            const classic = ['Admin','ApiKey','CascadeLink','HyNode','HyUser','ServerGroup','Settings','StatsSnapshot','UaSnapshot','UserDevice'];
            assert.deepEqual(ddl.collections.sort(), classic);
            assert.deepEqual(ddl.indexes.sort(), classic);
            startup.push('cache');
            value.redis = { status: 'ready' };
        };
        value.getStats = async () => ({});
    }
    if (id === './src/models/hyUserModel') {
        value.find = () => ({ select: async () => [] });
        value.updateMany = async () => ({});
    }
    if (id === './src/models/hyNodeModel') value.updateMany = async () => ({});
    if (id === './src/models/settingsModel') value.get = async () => ({ deployment: { completed: true } });
    if (id === './src/services/homepageService') value.init = async () => { startup.push('homepage'); };
    if (id === './src/services/expireScheduler') value.init = async () => { startup.push('expiry'); };
    if (id === './src/services/syncService') {
        value.collectXrayAgentOnlineStates = async () => { startup.push('agent-poll'); };
    }
    if (id === '../services/cascadeService') value.getTopology = async () => ({ nodes: [], edges: [] });
    return value;
};
async function verify(app) {
    assert.deepEqual(startup, ['cache', 'homepage', 'expiry', 'listen', 'access-logs']);
    await cron.get('*/5 * * * * *')();
    assert.equal(startup.at(-1), 'agent-poll');
    // No real sockets: use the application's mounted Express stack.
    const assertBlocked = async (method, url) => {
        const result = await requests(app, method, url);
        assert.equal(result.status, 409, url + ': ' + JSON.stringify(result));
        assert.equal(result.body.error.code, 'REBUILD_STRICT_DISABLED');
    };
    for (const [method, suffix] of [
        ['POST', 'topology/replace'], ['GET', 'topology/operations/dummy'],
        ['GET', 'topology/activation-policy'], ['POST', 'topology-test/resume-bindings'],
        ['POST', 'topology-transfer-drafts/import'], ['GET', 'links/auto-deploy-jobs/dummy'],
        ['POST', 'links/auto-deploy-jobs/dummy/settle-unadmitted-preparation'], ['GET', 'links/port-check'],
        ['POST', 'links/dummy/undeploy'],
        ['POST', 'route-groups'],
    ]) await assertBlocked(method, '/api/cascade/' + suffix);
    // Dedicated rebuild mutations are mounted before the old routes. A session
    // without a CSRF token reaches neither strict admission nor a DB writer.
    for (const [method, suffix] of [['POST','topology/deploy'],['POST','links'],['PUT','links/dummy'],['DELETE','links/dummy']]) {
        const result = await requests(app, method, '/api/cascade/' + suffix);
        assert.equal(result.status, 403); assert.equal(result.body.code, 'CSRF_TOKEN_INVALID');
    }
    assert.deepEqual((await requests(app,'GET','/api/cascade/rebuild/mode')).body,{mode:'rebuild'});
    await assertBlocked('GET', '/panel/l2tp');
    await assertBlocked('POST', '/panel/nodes/dummy/l2tp/install');
    assert.equal((await requests(app, 'GET', '/health')).status, 200);
    assert.deepEqual(await requests(app, 'GET', '/api/cascade/topology'), {
        status: 200, body: { nodes: [], edges: [] },
    });
    const { manageCascade } = require(require('node:path').join(process.argv[1], '../src/mcp/tools/cascade'));
    await assert.rejects(manageCascade({ action: 'delete' }), { code: 'REBUILD_STRICT_DISABLED' });
    console.log('REBUILD_CLASSIC_STARTUP_REACHED');
    process.exit(0);
}
require(process.argv[1]);
`;

function run(env = {}) {
    return spawnSync(process.execPath, ['-e', probe, entry], {
        env: {
            PATH: process.env.PATH, NODE_PATH: process.env.NODE_PATH,
            PANEL_DOMAIN: 'unit.example.invalid', ACME_EMAIL: 'unit@example.invalid',
            ENCRYPTION_KEY: 'x'.repeat(32), SESSION_SECRET: 'dummy',
            C3_REBUILD_ENABLED: 'true', USE_CADDY: 'true',
            ...env,
        }, encoding: 'utf8', timeout: 15000,
    });
}

test('rebuild rejects conflicts before application imports, including dotenv opt-ins', () => {
    for (const [key, value] of Object.entries({
        L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
        L2TP_PRODUCTION_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
        TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_STARTUP_MODE: 'dedicated-runtime-v1',
        CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true', CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'true',
        C3_REBUILD_ENABLED: '1', C3_SETTINGS: '/unused-mode-conflict.json', DUMMY_DOTENV_CONFLICT: '1',
    })) {
        const result = run({ DUMMY_CONFLICT: '1', [key]: value });
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stderr, /C3_REBUILD_ENABLED.*(?:exactly|conflicts with)/, key + ': ' + result.stderr);
        assert.doesNotMatch(result.stderr, /application imported before validation/);
    }
});

test('rebuild runs classic startup and agent poll with strict routes refused and only classic automatic DDL', () => {
    const result = run();
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /REBUILD_CLASSIC_STARTUP_REACHED/);
});

test('rebuild root skips migration, schema verification, runtime and owner enrollment', async () => {
    const { createL2tpRootLifecycle, createL2tpRuntimeLifecycleHook } = require('../l2tpRuntimeLifecycleHook');
    const forbidden = () => assert.fail('strict dependency entered');
    const env = { C3_REBUILD_ENABLED: 'true' };
    const root = createL2tpRootLifecycle({ env,
        createMigrationBootstrap: forbidden, ensureModelIndexes: forbidden,
        createRuntimeLifecycleHook: forbidden, createTopologyExecutionAuthority: forbidden });
    await assert.rejects(root.enrollTestOwnersAfterDatabase(), { code: 'REBUILD_STRICT_DISABLED' });
    await root.startAfterDatabase();
    await root.stop();
    assert.throws(() => createL2tpRuntimeLifecycleHook({ env, createStartupLifecycle: forbidden }), { code: 'REBUILD_STRICT_DISABLED' });
});

test('rebuild cannot enter the dormant classic config-writer bypass', async () => {
    const { withClassicNodeConfigWrite } = require('../../services/classicNodeConfigWrite');
    const options = { nodeId: 'dummy', kind: 'sync-xray' };
    await assert.rejects(withClassicNodeConfigWrite({ ...options, env: { C3_REBUILD_ENABLED: 'true' } },
        () => assert.fail('unfenced writer entered')), { code: 'REBUILD_WRITER_UNAVAILABLE' });
    assert.equal(await withClassicNodeConfigWrite({ ...options, env: {} }, () => 'existing classic'), 'existing classic');
});
