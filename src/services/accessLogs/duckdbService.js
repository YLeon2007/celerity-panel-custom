/**
 * DuckDB access layer for the panel.
 *
 * Spawns the duckdbWorker child process for each heavy query, enforcing a hard
 * timeout, a single concurrent heavy query, and graceful degradation when the
 * native binding is unavailable (search returns a degraded flag instead of
 * throwing, so the dashboard keeps working from Mongo rollups).
 *
 * Concurrency: only ONE heavy query runs at a time (weak-hardware constraint),
 * but concurrent callers are SERIALIZED (queued) rather than rejected. Earlier
 * a second simultaneous request (e.g. the dashboard's analytics + the event
 * search firing together) hit an "activeQueries >= 1" guard and came back
 * empty — the aggregates showed hits while the search table said "not found".
 * A short queue removes that race; only a pathological backlog past
 * MAX_QUEUE_DEPTH is shed with a 'busy' error.
 */

const path = require('path');
const { fork } = require('child_process');
const logger = require('../../utils/logger');

const WORKER_PATH = path.join(__dirname, 'duckdbWorker.js');

const DEFAULT_TIMEOUT_MS = 30000;

// Serialize DuckDB work: one query at a time, later callers wait their turn.
// The queue is bounded so a stampede cannot pile up unbounded pending work.
const MAX_QUEUE_DEPTH = 8;
let queueTail = Promise.resolve();
let queueDepth = 0;

// Run `task` (returns a Promise) exclusively: it starts only after all
// previously queued tasks settle. Returns { ok:false, error:'busy' } without
// running when the queue is already saturated.
function serialize(task) {
    if (queueDepth >= MAX_QUEUE_DEPTH) {
        return Promise.resolve({ ok: false, error: 'busy' });
    }
    queueDepth += 1;
    // Chain after the current tail regardless of whether it resolved/rejected.
    const result = queueTail.then(task, task);
    // Advance the tail on a swallowed copy so one failing task never breaks the
    // chain for the next waiter.
    queueTail = result.then(() => {}, () => {});
    const release = () => { queueDepth -= 1; };
    result.then(release, release);
    return result;
}

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
    const res = await serialize(() => runWorker({ sql: 'SELECT 1 AS ok', params: [], rowLimit: 1 }, 10000));
    // A saturated queue ('busy') is not a signal about the binding — leave the
    // cache untouched and report available so the caller retries via the queue.
    if (res && res.error === 'busy') return true;
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
    return serialize(async () => {
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
    });
}

/**
 * Run several labelled read-only queries in ONE worker spawn (shared DuckDB
 * connection). Cheaper than N separate query() calls for a dashboard: a single
 * child process, one Parquet metadata warm-up. Counts as one heavy query
 * against the concurrency limit.
 *
 * @param {Array<{key:string, sql:string, params?:any[], rowLimit?:number}>} queries
 * @returns {Promise<{ok:boolean, results?:Object, error?:string}>}
 *          results maps each query key -> rows array.
 */
async function queryBatch(queries, opts = {}) {
    return serialize(async () => {
        const res = await runWorker(
            {
                queries,
                threads: opts.threads || 1,
                memoryLimitMb: opts.memoryLimitMb || 256,
            },
            opts.timeoutMs || DEFAULT_TIMEOUT_MS
        );
        if (!res.ok && res.error === 'duckdb_unavailable') {
            availabilityCache = false;
        }
        return res;
    });
}

module.exports = {
    isAvailable,
    query,
    queryBatch,
    _resetAvailabilityCache,
    WORKER_PATH,
};
