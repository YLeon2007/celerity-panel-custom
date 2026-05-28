/**
 * Marzban → Celerity migration service.
 *
 * Pulls users from a running Marzban panel via its REST API, normalises them
 * to Celerity's `HyUser` shape, and writes them in batches with
 * `bulkWrite({ordered:false})`. The import runs as an in-memory background
 * task so the wizard can stream progress over SSE without holding the HTTP
 * request open.
 *
 * Why no direct DB access to Marzban:
 *   - keeps Celerity free of mysql/sqlite client dependencies
 *   - Marzban's API already enforces the proper "users belong to this admin"
 *     scoping when a non-sudo admin token is used
 *
 * The single piece of state the API never exposes — the JWT secret used to
 * sign subscription tokens — is fed in via the wizard form. Without it the
 * legacy-link compat route cannot validate signatures, so it is mandatory
 * for the finalize step (but optional for the import itself).
 */

const axios = require('axios');
const crypto = require('crypto');
const https = require('https');

const HyUser = require('../models/hyUserModel');
const logger = require('../utils/logger');

// Concurrency for paged /api/users fetches. Marzban backs to SQLite or MySQL
// — 4 in-flight queries comfortably saturates the network without overloading
// the upstream DB. Raising this further mostly buys lock contention.
const FETCH_CONCURRENCY = 4;

// Page size for /api/users. 200 is the largest comfortable size — Marzban
// returns ~5KB per UserResponse, so a single page is ~1MB on the wire.
const PAGE_SIZE = 200;

// Mongo bulkWrite batch size. Mongoose buffers internally, but keeping batches
// small produces smoother progress updates and lower peak memory.
const WRITE_BATCH_SIZE = 100;

// Marzban allowed statuses we accept by default (everything else is skipped
// when `onlyActive` is on — disabled/expired/limited users would just produce
// inert HyUser rows in Celerity).
const ACCEPTED_STATUSES = new Set(['active', 'on_hold']);

// In-memory task store. Keyed by uuid generated at startImport(). Each task
// carries a circular-safe shape so the SSE stream can serialise it directly.
const _tasks = new Map();

// Shared keep-alive HTTPS agent — every page fetch goes through the same TLS
// connection, which is critical when a Marzban panel sits behind Cloudflare.
const _httpsAgent = new https.Agent({ keepAlive: true, maxSockets: FETCH_CONCURRENCY * 2 });

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Probe the Marzban panel: authenticate, count users, list admins. Used by
 * the wizard's "Test" button to validate connectivity before the user fills
 * in the rest of the form.
 *
 * @returns {Promise<{ok: boolean, error?: string, total?: number, admins?: Array, isSudo?: boolean}>}
 */
async function testConnection({ baseUrl, username, password }) {
    const url = _normalizeBaseUrl(baseUrl);
    if (!url) return { ok: false, error: 'Invalid Marzban URL' };
    if (!username || !password) return { ok: false, error: 'Username and password required' };

    try {
        const token = await _authenticate(url, username, password);
        const client = _buildClient(url, token);

        // /api/admins is sudo-only. Non-sudo admins still need to be able to
        // run a migration of their own users, so we tolerate a 403 here.
        let admins = [];
        let isSudo = true;
        try {
            const adminsRes = await client.get('/api/admins', { params: { limit: 100 } });
            admins = Array.isArray(adminsRes.data) ? adminsRes.data : [];
        } catch (err) {
            if (err.response?.status === 403) {
                isSudo = false;
                admins = [{ username, is_sudo: false }];
            } else {
                throw err;
            }
        }

        const usersRes = await client.get('/api/users', { params: { limit: 1, offset: 0 } });
        const total = Number(usersRes.data?.total || 0);

        return { ok: true, total, admins, isSudo };
    } catch (err) {
        return { ok: false, error: _formatAxiosError(err) };
    }
}

/**
 * Kick off the actual import. Returns immediately with a task id; the caller
 * polls /panel/migration/status/:taskId for the SSE stream.
 *
 * @param {Object} opts
 * @param {string} opts.baseUrl
 * @param {string} opts.username
 * @param {string} opts.password
 * @param {Object<string, string>} [opts.groupMap]  Marzban admin username → Celerity ServerGroup _id
 * @param {string|null} [opts.defaultGroupId]       Fallback ServerGroup _id when admin not in map
 * @param {{onlyActive?: boolean, importVlessUuid?: boolean}} [opts.options]
 * @returns {string} taskId
 */
function startImport(opts) {
    const taskId = crypto.randomUUID();
    const task = {
        id: taskId,
        startedAt: Date.now(),
        progress: 0,
        total: 0,
        imported: 0,
        skipped: 0,
        errors: 0,
        conflicts: [],
        logs: [],
        done: false,
        success: false,
        error: null,
    };
    _tasks.set(taskId, task);

    // Schedule on next tick so the route can return the id before the first
    // log line is appended (avoids a race on the SSE consumer side).
    setImmediate(() => {
        _runImport(task, opts).catch(err => {
            _log(task, `Fatal: ${err.message}`);
            task.error = err.message;
            task.done = true;
            task.success = false;
        });
    });

    return taskId;
}

function getTask(taskId) {
    return _tasks.get(taskId) || null;
}

/**
 * Drop tasks older than 1h to bound the map size. Called opportunistically by
 * the panel routes — no separate timer.
 */
function pruneTasks(maxAgeMs = 60 * 60 * 1000) {
    const cutoff = Date.now() - maxAgeMs;
    for (const [id, task] of _tasks) {
        if (task.done && task.startedAt < cutoff) _tasks.delete(id);
    }
}

// ─── Internal: orchestration ─────────────────────────────────────────────────

async function _runImport(task, opts) {
    const url = _normalizeBaseUrl(opts.baseUrl);
    if (!url) throw new Error('Invalid Marzban URL');

    _log(task, `Authenticating against ${url}…`);
    const token = await _authenticate(url, opts.username, opts.password);
    const client = _buildClient(url, token);

    _log(task, 'Counting users…');
    const headRes = await client.get('/api/users', { params: { limit: 1, offset: 0 } });
    const total = Number(headRes.data?.total || 0);
    task.total = total;
    _log(task, `Marzban reports ${total} users.`);

    if (total === 0) {
        task.done = true;
        task.success = true;
        _log(task, 'Nothing to import — finished.');
        return;
    }

    // Pre-load existing userIds so we can detect collisions without an extra
    // round-trip per page. For panels with >100k users this is still <10MB.
    _log(task, 'Loading existing Celerity userIds…');
    const existingDocs = await HyUser.find({}, { userId: 1 }).lean();
    const existingIds = new Set(existingDocs.map(d => d.userId));
    _log(task, `Found ${existingIds.size} existing Celerity users.`);

    const onlyActive = opts.options?.onlyActive !== false;
    const importVless = opts.options?.importVlessUuid !== false;
    const groupMap = opts.groupMap || {};
    const defaultGroupId = opts.defaultGroupId || null;

    const pageCount = Math.ceil(total / PAGE_SIZE);
    const pageIndexes = Array.from({ length: pageCount }, (_, i) => i);

    let pending = [];
    const flush = async () => {
        if (pending.length === 0) return;
        const batch = pending;
        pending = [];
        try {
            const res = await HyUser.bulkWrite(batch, { ordered: false });
            // bulkWrite returns upserted count; matched-but-not-modified counts
            // as a no-op which is fine — duplicate import is idempotent.
            task.imported += (res.upsertedCount || 0) + (res.modifiedCount || 0);
        } catch (err) {
            task.errors += batch.length;
            _log(task, `bulkWrite error: ${err.message}`);
        }
    };

    // Run page fetches with bounded concurrency. We do not order pages — bulk
    // writes are independent so commit order does not matter.
    let cursor = 0;
    const worker = async () => {
        while (cursor < pageIndexes.length) {
            const myIdx = cursor++;
            if (myIdx >= pageIndexes.length) return;
            const offset = pageIndexes[myIdx] * PAGE_SIZE;
            let page;
            try {
                const res = await client.get('/api/users', { params: { offset, limit: PAGE_SIZE } });
                page = Array.isArray(res.data?.users) ? res.data.users : [];
            } catch (err) {
                task.errors += 1;
                _log(task, `Page offset=${offset} failed: ${_formatAxiosError(err)}`);
                continue;
            }

            for (const u of page) {
                const op = _mapMarzbanUser(u, {
                    onlyActive,
                    importVless,
                    groupMap,
                    defaultGroupId,
                    existingIds,
                    task,
                });
                if (op) pending.push(op);
                task.progress += 1;
            }

            if (pending.length >= WRITE_BATCH_SIZE) {
                await flush();
            }
        }
    };

    await Promise.all(Array.from({ length: FETCH_CONCURRENCY }, () => worker()));
    await flush();

    task.done = true;
    task.success = true;
    _log(task, `Done. imported=${task.imported} skipped=${task.skipped} errors=${task.errors} conflicts=${task.conflicts.length}`);
}

// ─── Internal: HTTP ──────────────────────────────────────────────────────────

function _normalizeBaseUrl(raw) {
    if (!raw || typeof raw !== 'string') return null;
    let url = raw.trim();
    if (!url) return null;
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    // Operators routinely paste the full dashboard URL (e.g.
    // `https://host/dashboard/`) — Marzban's REST API always lives at the
    // origin's root, so strip path / query / hash and keep only the origin.
    try {
        return new URL(url).origin;
    } catch (_) {
        return null;
    }
}

function _buildClient(baseUrl, token) {
    return axios.create({
        baseURL: baseUrl,
        timeout: 30000,
        httpsAgent: _httpsAgent,
        headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json',
        },
    });
}

async function _authenticate(baseUrl, username, password) {
    const body = new URLSearchParams({
        username,
        password,
        grant_type: 'password',
    });
    const res = await axios.post(`${baseUrl}/api/admin/token`, body.toString(), {
        timeout: 20000,
        httpsAgent: _httpsAgent,
        // Accept JSON only — without this, a misrouted endpoint that returns
        // HTML (e.g. when baseUrl points at /dashboard/ instead of origin)
        // would deserialize as a string and surface as a cryptic "no
        // access_token" error several layers up.
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept':       'application/json',
        },
        responseType: 'json',
    });

    const data = res.data;
    if (typeof data !== 'object' || data === null) {
        throw new Error(`Marzban did not return JSON at ${baseUrl}/api/admin/token — check the panel URL (use the origin without /dashboard/).`);
    }
    const token = data.access_token;
    if (!token) {
        throw new Error('Marzban returned no access_token — verify the admin credentials.');
    }
    return token;
}

function _formatAxiosError(err) {
    if (err.response) {
        const detail = err.response.data?.detail || err.response.statusText || '';
        return `HTTP ${err.response.status}${detail ? `: ${detail}` : ''}`;
    }
    if (err.code === 'ECONNREFUSED') return 'Connection refused';
    if (err.code === 'ENOTFOUND') return 'Host not found';
    if (err.code === 'ETIMEDOUT') return 'Connection timeout';
    return err.message || 'Network error';
}

// ─── Internal: mapping ───────────────────────────────────────────────────────

/**
 * Build the userId from a marzban username. Lower-case mirrors Marzban's
 * NOCASE collation; this is the same identifier the compat route will look up,
 * so it MUST be deterministic.
 */
function _toUserId(marzbanUsername) {
    return String(marzbanUsername || '').toLowerCase();
}

/**
 * Mirror of `hyUserSchema.pre('save')` token generation — bulkWrite skips the
 * Mongoose pre-save hook so we have to produce subscriptionToken here.
 */
function _newSubscriptionToken(userId) {
    return crypto.createHash('sha256')
        .update(userId + crypto.randomBytes(8).toString('hex'))
        .digest('hex')
        .substring(0, 16);
}

/**
 * Convert a Marzban UserResponse into a Mongoose bulkWrite operation.
 * Returns null when the user is skipped (status filter / collision).
 *
 * Skipped users are recorded on the task so the wizard can show a table
 * to the operator at the finalize step.
 */
function _mapMarzbanUser(u, ctx) {
    if (!u || typeof u.username !== 'string') return null;

    const userId = _toUserId(u.username);
    if (!userId) return null;

    if (ctx.onlyActive && !ACCEPTED_STATUSES.has(u.status)) {
        ctx.task.skipped += 1;
        return null;
    }

    if (ctx.existingIds.has(userId)) {
        ctx.task.skipped += 1;
        if (ctx.task.conflicts.length < 200) {
            ctx.task.conflicts.push({ marzbanUsername: u.username, reason: 'userId already exists' });
        }
        return null;
    }

    const adminUsername = u.admin?.username || '';
    const groupId = ctx.groupMap[adminUsername] || ctx.defaultGroupId;
    const groups = groupId ? [groupId] : [];

    const vlessUuid = ctx.importVless && u.proxies?.vless?.id ? String(u.proxies.vless.id) : null;

    const usedTraffic = Number(u.used_traffic || 0);
    const dataLimit = Number(u.data_limit || 0);

    // $set carries data that should be refreshed on every re-import (so the
    // operator can re-run the wizard after manually editing groups).
    // $setOnInsert seeds the secret/identity fields that must not change once
    // the user is materialised.
    return {
        updateOne: {
            filter: { userId },
            update: {
                $set: {
                    username: u.username,
                    enabled: ACCEPTED_STATUSES.has(u.status),
                    trafficLimit: dataLimit > 0 ? dataLimit : 0,
                    expireAt: u.expire ? new Date(u.expire * 1000) : null,
                    'traffic.rx': usedTraffic,
                    'traffic.tx': 0,
                    'traffic.lastUpdate': new Date(),
                    ...(groups.length > 0 ? { groups } : {}),
                },
                $setOnInsert: {
                    userId,
                    nodes: [],
                    subscriptionToken: _newSubscriptionToken(userId),
                    password: crypto.randomBytes(16).toString('hex'),
                    xrayUuid: vlessUuid || crypto.randomUUID(),
                },
            },
            upsert: true,
        },
    };
}

// ─── Internal: logging ───────────────────────────────────────────────────────

function _log(task, message) {
    const line = `[${new Date().toISOString()}] ${message}`;
    task.logs.push(line);
    // Bound the log buffer — the SSE consumer only renders the tail anyway.
    if (task.logs.length > 1000) task.logs.splice(0, task.logs.length - 1000);
    logger.debug(`[Migration:${task.id.slice(0, 8)}] ${message}`);
}

module.exports = {
    testConnection,
    startImport,
    getTask,
    pruneTasks,
};
