/**
 * DuckDB access layer for the panel.
 *
 * Spawns the duckdbWorker child process for each heavy query, enforcing a hard
 * timeout, a single concurrent heavy query, and graceful degradation when the
 * native binding is unavailable (search returns a degraded flag instead of
 * throwing, so the dashboard keeps working from Mongo rollups).
 */

const path = require('path');
const { fork } = require('child_process');
const logger = require('../../utils/logger');

const WORKER_PATH = path.join(__dirname, 'duckdbWorker.js');

// Only one heavy DuckDB query at a time (weak-hardware constraint). Additional
// requests are rejected fast rather than queued unbounded.
let activeQueries = 0;
const MAX_CONCURRENT = 1;
const DEFAULT_TIMEOUT_MS = 30000;

// Cache the availability probe result so we do not spawn a worker on every call
// once we know the binding is missing.
let availabilityCache = null;

function runWorker(job, timeoutMs) {
    return new Promise((resolve) => {
        const payload = Buffer.from(JSON.stringify(job), 'utf8').toString('base64');
        const child = fork(WORKER_PATH, [payload], {
            stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        });

        let out = '';
        let err = '';
        let settled = false;

        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            try { child.kill('SIGKILL'); } catch (_) {}
            resolve({ ok: false, error: 'timeout' });
        }, timeoutMs);

        if (child.stdout) child.stdout.on('data', (d) => { out += d.toString(); });
        if (child.stderr) child.stderr.on('data', (d) => { err += d.toString(); });

        child.on('error', (e) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve({ ok: false, error: String(e && e.message || e) });
        });

        child.on('exit', () => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try {
                resolve(JSON.parse(out));
            } catch (_) {
                resolve({ ok: false, error: err ? err.slice(0, 500) : 'no output' });
            }
        });
    });
}

/**
 * Check whether DuckDB is usable in this environment. Result is cached.
 * @returns {Promise<boolean>}
 */
async function isAvailable() {
    if (availabilityCache !== null) return availabilityCache;
    const res = await runWorker({ sql: 'SELECT 1 AS ok', params: [], rowLimit: 1 }, 10000);
    availabilityCache = !!(res && res.ok);
    if (!availabilityCache) {
        logger.warn(`[AccessLogs] DuckDB unavailable (${res && res.error}); search will be degraded, dashboard uses Mongo rollups`);
    }
    return availabilityCache;
}

// Allow tests / provisioning to reset the cached probe.
function _resetAvailabilityCache() {
    availabilityCache = null;
}

/**
 * Run a parameterized read-only query. The caller must build parameterized SQL
 * (never interpolate user input). Returns { ok, rows } or { ok:false, error }.
 */
async function query(sql, params = [], opts = {}) {
    if (activeQueries >= MAX_CONCURRENT) {
        return { ok: false, error: 'busy' };
    }
    activeQueries += 1;
    try {
        const res = await runWorker(
            {
                sql,
                params,
                rowLimit: opts.rowLimit || 1000,
                threads: opts.threads || 1,
                memoryLimitMb: opts.memoryLimitMb || 256,
            },
            opts.timeoutMs || DEFAULT_TIMEOUT_MS
        );
        if (!res.ok && res.error === 'duckdb_unavailable') {
            availabilityCache = false;
        }
        return res;
    } finally {
        activeQueries -= 1;
    }
}

module.exports = {
    isAvailable,
    query,
    _resetAvailabilityCache,
    WORKER_PATH,
};
