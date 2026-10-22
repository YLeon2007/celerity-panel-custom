'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// Ordering-only unit seam: real entry point + schemas + dependencies, with the
// connection boundary intercepted before any network or HTTP work. Actual
// serving/deadlines are exercised separately by the immutable bundle replay.
test('classic startup compiles all 25 schemas before opening Mongo and before route assembly', async t => {
    const directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-startup-order-'));
    t.after(() => fs.rm(directory, { recursive: true, force: true }));
    const entry = path.resolve(__dirname, '../../../index.js');
    const settings = path.join(directory, 'settings.json');
    await fs.writeFile(settings, JSON.stringify({ version: 1, context: 'test.infograd.online',
        stateDirectory: directory, listenAddress: '127.0.0.1', environment: {
            PANEL_DOMAIN: 'test.infograd.online', ACME_EMAIL: 'unit@example.invalid',
            ENCRYPTION_KEY: 'a'.repeat(64), SESSION_SECRET: 'b'.repeat(64),
            MONGO_URI: 'mongodb://127.0.0.1:1/order_only', REDIS_URL: 'redis://127.0.0.1:1',
            USE_CADDY: 'true', PORT: '12345', L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false',
            TOPOLOGY_TEST_EXECUTION_ENABLED: 'false', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false',
            L2TP_PRODUCTION_EXECUTION_ENABLED: 'false',
        } }), { mode: 0o600 });
    const probe = `
        const Module = require('module'), fs = require('fs'), path = require('path');
        const entry = process.argv[1], baseline = process.env.C3_BASELINE_INDEX;
        const compile = Module.prototype._compile;
        Module.prototype._compile = function(bytes, file) {
            return compile.call(this, baseline && file === entry ? fs.readFileSync(baseline, 'utf8') : bytes, file);
        };
        const load = Module._load;
        Module._load = function(id) {
            const value = load.apply(this, arguments);
            if (id === 'mongoose') value.connect = (uri, options) => {
                const names = Object.keys(value.models).sort();
                const indexes = Object.values(value.models).reduce((n, m) => n + m.schema.indexes().length, 0);
                const routesLoaded = Object.keys(require.cache).some(p => p === path.join(path.dirname(entry), 'src/routes/users.js'));
                console.log('STARTUP_ORDER:' + JSON.stringify({ names, indexes, options, routesLoaded }));
                process.exit(0);
            };
            return value;
        };
        require(entry);
    `;
    const result = spawnSync(process.execPath, ['-e', probe, entry], {
        env: { ...process.env, C3_SETTINGS: settings }, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr);
    const row = JSON.parse(result.stdout.split('\n').find(line => line.startsWith('STARTUP_ORDER:')).slice(14));
    assert.deepEqual(row.names, ['Admin', 'ApiKey', 'CascadeLink', 'CascadeRouteGroup', 'CascadeTopologyState',
        'HyNode', 'HyUser', 'L2tpOperation', 'L2tpUser', 'NodeOperationLock', 'RelayL2tpMigrationState',
        'RelayL2tpState', 'RelayL2tpTopologyTransferDraft', 'RemoteAdmission', 'ServerGroup', 'Settings',
        'StatsSnapshot', 'TopologyConfigOwner', 'TopologyCreateIntent', 'TopologyExecutionBinding',
        'TopologyExecutionEnrollment', 'TopologyIntentQueueState', 'TopologyOperation', 'UaSnapshot', 'UserDevice']);
    assert.equal(row.indexes, 55);
    assert.equal(row.routesLoaded, false, 'automatic DDL can start before expensive route/service compilation');
    assert.equal(row.options.maxPoolSize, 10);
    assert.equal(row.options.autoIndex, undefined, 'automatic index initialization remains authoritative');
    assert.equal(row.options.autoCreate, undefined);
});
