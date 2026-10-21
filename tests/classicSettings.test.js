'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const dir = fs.mkdtempSync(path.join(process.env.TMPDIR, 'classic-settings-'));
const flags = ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED', 'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED', 'L2TP_PRODUCTION_EXECUTION_ENABLED'];
function settings() {
    return { version: 1, context: 'test.infograd.online', stateDirectory: path.join(dir, 'state'), listenAddress: '127.0.0.1', environment: {
        PANEL_DOMAIN: 'test.infograd.online', ACME_EMAIL: 'test@example.invalid',
        ENCRYPTION_KEY: 'e'.repeat(32), SESSION_SECRET: 's'.repeat(32),
        MONGO_URI: 'mongodb://127.0.0.1:27099/classic_local', REDIS_URL: 'redis://127.0.0.1:6399',
        USE_CADDY: 'true', PORT: '3000', ...Object.fromEntries(flags.map(k => [k, 'false'])) } };
}
function run(s, code = `const c=require('./config'); console.log(JSON.stringify({domain:c.PANEL_DOMAIN,mongo:c.MONGO_URI,redis:process.env.REDIS_URL,caddy:process.env.USE_CADDY,flag:process.env.L2TP_EXECUTION_ENABLED,ambient:process.env.UPDATER_SECRET}));`) {
    const file = path.join(dir, 'classic.json'); fs.writeFileSync(file, JSON.stringify(s), { mode: 0o600 });
    return spawnSync(process.execPath, ['-e', code], { cwd: root, encoding: 'utf8', timeout: 5000,
        env: { NODE_PATH: process.env.NODE_PATH, NODE_ENV: 'production', C3_SETTINGS: file,
            PANEL_DOMAIN: 'ambient.invalid', UPDATER_SECRET: 'ambient-secret', L2TP_EXECUTION_ENABLED: 'true' } });
}
test('selected settings supply actual config and env-only callers without ambient fallthrough', () => {
    const r = run(settings()); assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), {domain:'test.infograd.online',mongo:'mongodb://127.0.0.1:27099/classic_local',redis:'redis://127.0.0.1:6399',caddy:'true',flag:'false'});
});
test('strict TEST schema refuses flags, unknown keys and malformed values without secret output', () => {
    const mutations = [s => s.context = 'prod.invalid', s => s.environment.PANEL_DOMAIN = 'prod.invalid',
        s => s.environment.USE_CADDY = 'false', s => s.environment.PORT = ['3000'],
        s => s.environment.PORT = '65536', s => s.environment.SESSION_SECRET = 'secret-canary',
        s => s.environment.EXTRA = 'secret-canary', s => s.extra = true,
        s => delete s.environment.REDIS_URL, s => s.environment.REDIS_URL = 'http://bad',
        s => s.environment.REDIS_URL = 'redis://', s => s.environment.MONGO_URI = 'mongodb://',
        s => s.environment.MONGO_URI = 'mongodb://127.0.0.1:27017',
        s => s.environment.REDIS_URL = 'redis://127.0.0.1:99999',
        ...flags.map(k => s => s.environment[k] = 'true')];
    for (const mutate of mutations) {
        const s = settings(); mutate(s); const r = run(s);
        assert.notEqual(r.status, 0); assert.match(r.stderr, /CLASSIC_SETTINGS_REFUSED/);
        assert.doesNotMatch(r.stdout + r.stderr, /secret-canary|eeeeeeee|ssssssss|mongodb:/);
    }
});
test('ordinary config still accepts env and dotenv without selecting file mode', () => {
    const cwd = fs.mkdtempSync(path.join(dir, 'legacy-'));
    fs.writeFileSync(path.join(cwd, '.env'), 'PANEL_DOMAIN=dotenv.invalid\nACME_EMAIL=dotenv@example.invalid\nENCRYPTION_KEY=' + 'd'.repeat(32) + '\nSESSION_SECRET=legacy\n');
    const r = spawnSync(process.execPath, ['-e', `console.log(require(${JSON.stringify(path.join(root, 'config'))}).PANEL_DOMAIN)`], {
        cwd, encoding: 'utf8', env: {NODE_PATH:process.env.NODE_PATH, PANEL_DOMAIN:'env.invalid'} });
    assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout.trim(), 'env.invalid');
});
test('selected logger writes only in private state, not source logs', () => {
    const r = run(settings(), `require('./src/utils/logger').info('classic-log-witness'); setTimeout(()=>process.exit(0),150);`);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(path.join(dir, 'state/logs/combined.log')), 'state log exists');
    assert.match(fs.readFileSync(path.join(dir, 'state/logs/combined.log'),'utf8'), /classic-log-witness/);
});
