'use strict';

/**
 * Celerity panel updater sidecar.
 *
 * A tiny, dependency-free HTTP service that lives next to the panel and is the
 * ONLY component with access to the Docker socket. The panel itself never gets
 * docker.sock; instead it sends an HMAC-signed request asking this service to
 * move the `backend` service to a specific released version.
 *
 * Two modes:
 *   - hub:    pull a pre-built image tag (docker-compose.hub.yml).
 *   - source: git checkout the tag and rebuild locally (docker-compose.yml).
 *
 * Fail-safe by design:
 *   - Without a strong UPDATER_SECRET the service refuses every request (503)
 *     rather than crash-looping, so a misconfigured deployment simply has the
 *     UI update button disabled.
 *   - `docker pull` / `docker build` run BEFORE the container is recreated, so
 *     any failure leaves the currently running panel untouched.
 */

const http = require('http');
const crypto = require('crypto');
const { execFile } = require('child_process');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');

const PORT = parseInt(process.env.UPDATER_PORT, 10) || 8484;
const SECRET = process.env.UPDATER_SECRET || '';
const MODE = process.env.UPDATE_MODE === 'source' ? 'source' : 'hub';
const PROJECT_DIR = process.env.PROJECT_DIR || process.cwd();
const COMPOSE_FILE = process.env.COMPOSE_FILE || 'docker-compose.yml';
const SERVICE = process.env.SERVICE || 'backend';
const ENV_FILE = path.join(PROJECT_DIR, '.env');
const STATE_DIR = process.env.UPDATER_STATE_DIR || path.join(PROJECT_DIR, 'data', 'updater');
const LAST_RUN_FILE = path.join(STATE_DIR, 'last-run.json');

// Signature freshness window and replay protection.
const TIMESTAMP_WINDOW_MS = 60 * 1000;
const SEEN_REQUEST_TTL_MS = 5 * 60 * 1000;
const MAX_LOG_LINES = 200;
const MAX_BODY_BYTES = 16 * 1024;

// Only fully-qualified semver, optionally prefixed with `v`. No shell input.
const VERSION_RE = /^v?\d+\.\d+\.\d+$/;

const configured = SECRET.length >= 32;
if (!configured) {
    // Do not exit: exiting would crash-loop under `restart: always`. Stay up and
    // reject everything so the panel can detect "not configured" gracefully.
    console.error('[Updater] UPDATER_SECRET is missing or shorter than 32 chars; refusing all requests until configured.');
}

/**
 * Validate the runtime environment once at startup. A misconfigured PROJECT_DIR
 * (e.g. compose started without $PWD set, so the project mount is broken) must
 * disable the updater rather than let `docker compose` run against a wrong or
 * empty directory. Returns an error string or null when everything is sane.
 */
function validateEnvironment() {
    if (!configured) {
        return 'Updater not configured';
    }
    if (!PROJECT_DIR || !path.isAbsolute(PROJECT_DIR)) {
        return 'PROJECT_DIR is not an absolute path';
    }
    try {
        fs.accessSync(path.join(PROJECT_DIR, COMPOSE_FILE));
    } catch (_) {
        return `Compose file not found: ${COMPOSE_FILE} (check the project mount)`;
    }
    return null;
}

const configError = validateEnvironment();
if (configError && configured) {
    console.error(`[Updater] Environment invalid: ${configError}; refusing all requests.`);
}

// In-flight guard: at most one update at a time.
let running = false;
let currentStatus = {
    state: 'idle', // idle | running | success | error
    version: null,
    step: null,
    startedAt: null,
    finishedAt: null,
    error: null,
    log: [],
};

const seenRequests = new Map();

function pruneSeenRequests() {
    const now = Date.now();
    for (const [id, ts] of seenRequests) {
        if (now - ts > SEEN_REQUEST_TTL_MS) seenRequests.delete(id);
    }
}

function timingSafeEqualHex(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

function sign(ts, rawBody) {
    return crypto.createHmac('sha256', SECRET).update(`${ts}.${rawBody}`).digest('hex');
}

/**
 * Verify HMAC signature, timestamp window and replay for a request.
 * Returns { ok: true } or { ok: false, code, error }.
 */
function verifyRequest(req, rawBody) {
    const ts = req.headers['x-updater-ts'];
    const sig = req.headers['x-updater-signature'];
    if (!ts || !sig) return { ok: false, code: 401, error: 'Missing signature headers' };

    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum)) return { ok: false, code: 401, error: 'Invalid timestamp' };
    if (Math.abs(Date.now() - tsNum) > TIMESTAMP_WINDOW_MS) {
        return { ok: false, code: 401, error: 'Timestamp outside allowed window' };
    }

    const expected = sign(ts, rawBody);
    if (!timingSafeEqualHex(sig, expected)) return { ok: false, code: 401, error: 'Invalid signature' };

    return { ok: true };
}

function appendLog(line) {
    const stamped = `[${new Date().toISOString()}] ${line}`;
    currentStatus.log.push(stamped);
    if (currentStatus.log.length > MAX_LOG_LINES) {
        currentStatus.log.splice(0, currentStatus.log.length - MAX_LOG_LINES);
    }
    console.log(`[Updater] ${line}`);
}

async function persistLastRun() {
    try {
        await fsp.mkdir(STATE_DIR, { recursive: true });
        await fsp.writeFile(LAST_RUN_FILE, JSON.stringify(currentStatus, null, 2), 'utf8');
    } catch (err) {
        console.error(`[Updater] Failed to persist last run: ${err.message}`);
    }
}

function loadLastRun() {
    try {
        const raw = fs.readFileSync(LAST_RUN_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && parsed.state !== 'running') {
            currentStatus = { ...currentStatus, ...parsed, log: Array.isArray(parsed.log) ? parsed.log : [] };
        }
    } catch (_) {
        // No previous run or unreadable; keep defaults.
    }
}

/**
 * Run a command with arguments (no shell). Rejects on non-zero exit with a
 * bounded stderr/stdout tail attached.
 */
function run(cmd, args, opts = {}) {
    // Child processes (docker/git) do not need the HMAC secret; keep it out of
    // their environment.
    const childEnv = { ...process.env };
    delete childEnv.UPDATER_SECRET;
    return new Promise((resolve, reject) => {
        appendLog(`$ ${cmd} ${args.join(' ')}`);
        execFile(cmd, args, {
            cwd: PROJECT_DIR,
            timeout: opts.timeout || 15 * 60 * 1000,
            maxBuffer: 8 * 1024 * 1024,
            env: childEnv,
        }, (err, stdout, stderr) => {
            const tail = (s) => String(s || '').split('\n').slice(-15).join('\n').trim();
            if (stdout && tail(stdout)) appendLog(tail(stdout));
            if (stderr && tail(stderr)) appendLog(tail(stderr));
            if (err) {
                const msg = tail(stderr) || err.message;
                return reject(new Error(`${cmd} failed: ${msg}`));
            }
            resolve({ stdout, stderr });
        });
    });
}

function composeArgs(rest) {
    return ['compose', '-f', COMPOSE_FILE, ...rest];
}

/**
 * Read the current PANEL_TAG from .env (hub mode) so we can roll it back if the
 * pull fails. Returns null when the file or key is absent.
 */
async function readPanelTag() {
    try {
        const raw = await fsp.readFile(ENV_FILE, 'utf8');
        const line = raw.split(/\r?\n/).find((l) => /^PANEL_TAG\s*=/.test(l));
        if (!line) return null;
        return line.split('=').slice(1).join('=').trim();
    } catch (_) {
        return null;
    }
}

/**
 * Upsert PANEL_TAG=<value> in .env, preserving the rest of the file. Creates
 * the file if it does not exist. Passing null removes the line entirely
 * (restores the implicit `latest` default).
 */
async function writePanelTag(value) {
    let lines = [];
    try {
        const raw = await fsp.readFile(ENV_FILE, 'utf8');
        lines = raw.split(/\r?\n/);
    } catch (_) {
        lines = [];
    }
    const idx = lines.findIndex((l) => /^PANEL_TAG\s*=/.test(l));
    if (value === null) {
        if (idx >= 0) lines.splice(idx, 1);
    } else if (idx >= 0) {
        lines[idx] = `PANEL_TAG=${value}`;
    } else {
        if (lines.length && lines[lines.length - 1] === '') lines.pop();
        lines.push(`PANEL_TAG=${value}`);
    }
    await fsp.writeFile(ENV_FILE, lines.join('\n') + '\n', 'utf8');
}

async function performHubUpdate(version) {
    const tag = version.replace(/^v/, '');
    const previousTag = await readPanelTag();

    currentStatus.step = 'write-tag';
    await writePanelTag(tag);

    try {
        currentStatus.step = 'pull';
        await run('docker', composeArgs(['pull', SERVICE]));
    } catch (err) {
        // Restore the previous .env state so a later manual `up` does not
        // accidentally switch versions after a failed pull. When there was no
        // PANEL_TAG before, remove the line we added (back to implicit latest).
        await writePanelTag(previousTag).catch(() => {});
        throw err;
    }

    currentStatus.step = 'recreate';
    await run('docker', composeArgs(['up', '-d', SERVICE]));
}

async function performSourceUpdate(version) {
    const tag = version.startsWith('v') ? version : `v${version}`;

    currentStatus.step = 'fetch';
    await run('git', ['fetch', '--tags', '--prune', '--force']);

    // Remember the current checkout so we can restore it on build failure.
    let previousRef = null;
    try {
        const { stdout } = await run('git', ['rev-parse', 'HEAD']);
        previousRef = String(stdout || '').trim();
    } catch (_) {
        previousRef = null;
    }

    // A deployment working tree accumulates runtime edits to tracked files
    // (release version bumps, hotfixes applied in place, CRLF churn). A plain
    // checkout would refuse with "local changes would be overwritten", so use
    // --force: the deployment copy is not a development checkout and released
    // tags are the source of truth. Untracked/ignored files (.env, data/,
    // logs/, backups/) are never touched by a forced checkout.
    currentStatus.step = 'checkout';
    await run('git', ['-c', 'advice.detachedHead=false', 'checkout', '--force', tag]);

    try {
        currentStatus.step = 'build';
        await run('docker', composeArgs(['build', SERVICE]));
    } catch (err) {
        if (previousRef) {
            currentStatus.step = 'rollback-checkout';
            await run('git', ['-c', 'advice.detachedHead=false', 'checkout', '--force', previousRef]).catch(() => {});
        }
        throw err;
    }

    currentStatus.step = 'recreate';
    await run('docker', composeArgs(['up', '-d', SERVICE]));
}

async function performUpdate(version) {
    currentStatus = {
        state: 'running',
        version,
        step: 'start',
        startedAt: new Date().toISOString(),
        finishedAt: null,
        error: null,
        log: [],
    };
    appendLog(`Starting ${MODE} update to ${version} (service=${SERVICE}, compose=${COMPOSE_FILE})`);

    try {
        if (MODE === 'source') {
            await performSourceUpdate(version);
        } else {
            await performHubUpdate(version);
        }
        currentStatus.state = 'success';
        currentStatus.step = 'done';
        appendLog(`Update to ${version} completed`);
    } catch (err) {
        currentStatus.state = 'error';
        currentStatus.error = err.message;
        appendLog(`Update failed: ${err.message}`);
    } finally {
        currentStatus.finishedAt = new Date().toISOString();
        running = false;
        await persistLastRun();
    }
}

function sendJson(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                // Drain the rest instead of destroying the socket: destroying
                // would tear the connection down before the 413 response is
                // flushed and the client would see a socket error, not JSON.
                req.removeAllListeners('data');
                req.resume();
                reject(new Error('Body too large'));
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
    });
}

function publicStatus() {
    return {
        mode: MODE,
        service: SERVICE,
        state: currentStatus.state,
        version: currentStatus.version,
        step: currentStatus.step,
        startedAt: currentStatus.startedAt,
        finishedAt: currentStatus.finishedAt,
        error: currentStatus.error,
        log: currentStatus.log,
    };
}

const server = http.createServer(async (req, res) => {
    try {
        if (configError) {
            return sendJson(res, 503, { error: configError });
        }

        const url = (req.url || '').split('?')[0];

        if (req.method === 'GET' && url === '/status') {
            const rawBody = '';
            const verdict = verifyRequest(req, rawBody);
            if (!verdict.ok) return sendJson(res, verdict.code, { error: verdict.error });
            return sendJson(res, 200, publicStatus());
        }

        if (req.method === 'POST' && url === '/update') {
            let rawBody;
            try {
                rawBody = await readBody(req);
            } catch (err) {
                // Close the connection after the response so an oversized (or
                // endless) unauthenticated stream cannot hold the socket open.
                res.setHeader('Connection', 'close');
                return sendJson(res, 413, { error: err.message });
            }

            const verdict = verifyRequest(req, rawBody);
            if (!verdict.ok) return sendJson(res, verdict.code, { error: verdict.error });

            let payload;
            try {
                payload = JSON.parse(rawBody || '{}');
            } catch (_) {
                return sendJson(res, 400, { error: 'Invalid JSON body' });
            }

            const version = String(payload.version || '').trim();
            const requestId = String(payload.requestId || '').trim();

            if (!VERSION_RE.test(version)) {
                return sendJson(res, 400, { error: 'Invalid version format' });
            }
            if (!requestId) {
                return sendJson(res, 400, { error: 'requestId is required' });
            }

            pruneSeenRequests();
            if (seenRequests.has(requestId)) {
                return sendJson(res, 409, { error: 'Duplicate request' });
            }
            seenRequests.set(requestId, Date.now());

            if (running) {
                return sendJson(res, 409, { error: 'An update is already in progress' });
            }

            running = true;
            // Fire-and-forget: respond immediately, let the panel poll /status.
            performUpdate(version).catch((err) => {
                console.error(`[Updater] Unhandled update error: ${err.message}`);
            });

            return sendJson(res, 202, { accepted: true, version });
        }

        return sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
        console.error(`[Updater] Request error: ${err.message}`);
        if (!res.headersSent) sendJson(res, 500, { error: 'Internal error' });
    }
});

// Only bind the port when executed directly. When required (tests) we expose
// the pure helpers without side effects.
if (require.main === module) {
    loadLastRun();
    server.listen(PORT, () => {
        console.log(`[Updater] Listening on :${PORT} (mode=${MODE}, configured=${configured})`);
    });
}

module.exports = { sign, verifyRequest, VERSION_RE, SECRET_CONFIGURED: configured };
