'use strict';
// Opt-in file configuration for the independently pinned fresh classic bundle.
// The launcher fixes /etc/classic.json and /state. Absolute paths also permit
// ordinary unprivileged local application tests; this reader grants no authority.
const fs = require('node:fs');
const path = require('node:path');
const FLAGS = Object.freeze(['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED',
    'TOPOLOGY_TEST_EXECUTION_ENABLED', 'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED', 'L2TP_PRODUCTION_EXECUTION_ENABLED']);
const KEYS = ['PANEL_DOMAIN', 'ACME_EMAIL', 'ENCRYPTION_KEY', 'SESSION_SECRET',
    'MONGO_URI', 'REDIS_URL', 'USE_CADDY', 'PORT', ...FLAGS];
function need(value) { if (!value) throw new Error('CLASSIC_SETTINGS_REFUSED'); }
function exact(object, keys) {
    need(object !== null && typeof object === 'object' && !Array.isArray(object));
    need(Object.keys(object).sort().join('\0') === [...keys].sort().join('\0'));
}
function absolute(value) { return typeof value === 'string' && value.startsWith('/') && path.resolve(value) === value && !value.includes('\0'); }
function load() {
    if (process.env.C3_SETTINGS === undefined) return null;
    try {
        const file = process.env.C3_SETTINGS;
        need(absolute(file));
        // No dotenv, shell expansion, JS evaluation, symlink file or unbounded input.
        const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        let raw;
        try {
            const stat = fs.fstatSync(fd);
            need(stat.isFile() && stat.nlink === 1 && stat.size <= 16384 && !(stat.mode & 0o022));
            const bytes = Buffer.alloc(16385);
            const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
            need(count <= 16384); raw = bytes.subarray(0, count).toString('utf8');
        } finally { fs.closeSync(fd); }
        const settings = JSON.parse(raw);
        exact(settings, ['version', 'context', 'stateDirectory', 'listenAddress', 'environment']);
        need(require('node:net').isIPv4(settings.listenAddress) && settings.listenAddress !== '0.0.0.0');
        need(settings.version === 1 && settings.context === 'test.infograd.online');
        need(absolute(settings.stateDirectory) && settings.stateDirectory !== '/');
        const env = settings.environment;
        exact(env, KEYS);
        for (const value of Object.values(env)) need(typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\x00-\x1f\x7f]/.test(value));
        need(env.PANEL_DOMAIN === settings.context && env.USE_CADDY === 'true');
        need(/^[1-9][0-9]{0,4}$/.test(env.PORT) && Number(env.PORT) <= 65535);
        need(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(env.ACME_EMAIL));
        need(env.ENCRYPTION_KEY.length >= 32 && env.SESSION_SECRET.length >= 32);
        const mongo = new URL(env.MONGO_URI);
        const redis = new URL(env.REDIS_URL);
        // Deliberately narrow single-host classic bundle, not a URI/options migration.
        need(mongo.protocol === 'mongodb:' && mongo.hostname && !/[,%]/.test(mongo.hostname) && !mongo.hash
            && /^\/[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(mongo.pathname));
        need(redis.protocol === 'redis:' && redis.hostname && !redis.hash
            && /^(?:\/[0-9]+)?$/.test(redis.pathname));
        for (const key of FLAGS) need(env[key] === 'false');
        // All validation precedes environment publication and all application imports.
        // Env-only legacy consumers (Redis, lifecycle, HTTP) see the same file.
        for (const key of Object.keys(process.env)) delete process.env[key];
        Object.assign(process.env, env, { C3_SETTINGS: file, NODE_ENV: 'production',
            ACCESS_LOGS_DIR: path.join(settings.stateDirectory, 'access-logs'),
            TMPDIR: settings.stateDirectory, TMP: settings.stateDirectory, TEMP: settings.stateDirectory });
        return Object.freeze({ stateDirectory: settings.stateDirectory, listenAddress: settings.listenAddress,
            logsDirectory: path.join(settings.stateDirectory, 'logs') });
    } catch (_) {
        // Never expose JSON, paths, connection strings or secret validation values.
        throw new Error('CLASSIC_SETTINGS_REFUSED');
    }
}
module.exports = load();
