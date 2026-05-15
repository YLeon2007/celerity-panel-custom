/**
 * Homepage Service - serves the public root page (`/`).
 *
 * Modes:
 *   - 'nginx'  : built-in fake nginx welcome page (mask the panel)
 *   - 'custom' : user-uploaded HTML stored on disk
 *
 * Hot path (`respond`) only touches in-memory state — no DB or disk
 * reads per request. Cache is rebuilt on init() and on setMode/setCustom/clearCustom.
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const logger = require('../utils/logger');

const DATA_DIR = path.join(__dirname, '../../data/homepage');
const CUSTOM_PATH = path.join(DATA_DIR, 'custom.html');
const TMP_PATH = path.join(DATA_DIR, 'custom.html.tmp');

// 256 KB is plenty for a static landing/decoy page and bounds heap usage.
const MAX_CUSTOM_BYTES = 256 * 1024;

const FAKE_SERVER_HEADER = 'nginx/1.24.0';

// Verbatim nginx 1.24 (Debian/Ubuntu) welcome page — kept byte-for-byte
// so masking is convincing. Do not pretty-print or reformat.
const NGINX_WELCOME_HTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`;

const NGINX_BUFFER = Buffer.from(NGINX_WELCOME_HTML, 'utf8');
const NGINX_ETAG = computeEtag(NGINX_BUFFER);

// Atomically-replaced state object. Always treat as immutable; never mutate fields.
let state = {
    mode: 'nginx',
    body: NGINX_BUFFER,
    etag: NGINX_ETAG,
};

function computeEtag(buf) {
    return '"' + crypto.createHash('sha1').update(buf).digest('hex') + '"';
}

async function ensureDataDir() {
    await fsp.mkdir(DATA_DIR, { recursive: true });
}

async function readCustomFromDisk() {
    try {
        const buf = await fsp.readFile(CUSTOM_PATH);
        if (buf.length === 0) return null;
        if (buf.length > MAX_CUSTOM_BYTES) {
            logger.warn(`[Homepage] custom.html is ${buf.length} bytes, exceeds ${MAX_CUSTOM_BYTES}; ignoring`);
            return null;
        }
        return buf;
    } catch (err) {
        if (err.code === 'ENOENT') return null;
        logger.warn(`[Homepage] Failed to read custom.html: ${err.message}`);
        return null;
    }
}

/**
 * Initialize the in-memory cache. Reads Settings.homepage.mode and the
 * custom HTML file (if any). Falls back to 'nginx' if mode='custom' but
 * the file is missing or invalid.
 */
async function init() {
    try {
        await ensureDataDir();

        const Settings = require('../models/settingsModel');
        const settings = await Settings.get();
        const mode = settings?.homepage?.mode === 'custom' ? 'custom' : 'nginx';

        if (mode === 'custom') {
            const buf = await readCustomFromDisk();
            if (buf) {
                state = { mode: 'custom', body: buf, etag: computeEtag(buf) };
                logger.info(`[Homepage] Loaded custom HTML (${buf.length} bytes)`);
                return;
            }
            logger.warn('[Homepage] mode=custom but no valid custom.html found; falling back to nginx');
        }
        state = { mode: 'nginx', body: NGINX_BUFFER, etag: NGINX_ETAG };
        logger.info('[Homepage] Serving fake nginx welcome page');
    } catch (err) {
        logger.error(`[Homepage] init failed: ${err.message}`);
        state = { mode: 'nginx', body: NGINX_BUFFER, etag: NGINX_ETAG };
    }
}

/**
 * Switch the active mode. If 'custom' is requested but no file is loaded,
 * keep the current cached body (init has already validated on startup).
 */
async function setMode(mode) {
    if (mode !== 'nginx' && mode !== 'custom') return;

    if (mode === 'nginx') {
        state = { mode: 'nginx', body: NGINX_BUFFER, etag: NGINX_ETAG };
        return;
    }

    const buf = await readCustomFromDisk();
    if (!buf) {
        state = { mode: 'nginx', body: NGINX_BUFFER, etag: NGINX_ETAG };
        logger.warn('[Homepage] setMode(custom) requested but no custom.html on disk; staying on nginx');
        return;
    }
    state = { mode: 'custom', body: buf, etag: computeEtag(buf) };
}

/**
 * Persist a new custom HTML buffer atomically (write tmp + rename) and
 * refresh the in-memory cache.
 */
async function setCustom(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
        throw new Error('Empty file');
    }
    if (buffer.length > MAX_CUSTOM_BYTES) {
        throw new Error(`File too large (max ${MAX_CUSTOM_BYTES} bytes)`);
    }
    // Reject obvious binary content — checking the first 4 KB is enough
    // to catch executables/images while keeping cost negligible.
    const probe = buffer.subarray(0, Math.min(4096, buffer.length));
    if (probe.includes(0)) {
        throw new Error('Binary content not allowed');
    }

    await ensureDataDir();
    await fsp.writeFile(TMP_PATH, buffer, { mode: 0o644 });
    await fsp.rename(TMP_PATH, CUSTOM_PATH);

    state = { mode: 'custom', body: buffer, etag: computeEtag(buffer) };
    logger.info(`[Homepage] Custom HTML saved (${buffer.length} bytes)`);
}

/**
 * Remove the custom HTML file and reset the cache to the built-in nginx page.
 */
async function clearCustom() {
    try {
        await fsp.rm(CUSTOM_PATH, { force: true });
    } catch (err) {
        logger.warn(`[Homepage] clearCustom: ${err.message}`);
    }
    state = { mode: 'nginx', body: NGINX_BUFFER, etag: NGINX_ETAG };
    logger.info('[Homepage] Custom HTML cleared, reverted to nginx');
}

function hasCustom() {
    try {
        return fs.existsSync(CUSTOM_PATH);
    } catch {
        return false;
    }
}

function getCustomSize() {
    try {
        return fs.statSync(CUSTOM_PATH).size;
    } catch {
        return 0;
    }
}

/**
 * Express handler for `GET /` (and HEAD /). Serves the cached body with
 * masking headers and ETag-based 304 support.
 */
function respond(req, res) {
    const { body, etag } = state;

    res.setHeader('Server', FAKE_SERVER_HEADER);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.setHeader('ETag', etag);
    res.removeHeader('X-Powered-By');

    if (req.headers['if-none-match'] === etag) {
        res.status(304).end();
        return;
    }

    if (req.method === 'HEAD') {
        res.setHeader('Content-Length', body.length);
        res.status(200).end();
        return;
    }

    res.status(200).send(body);
}

function getMode() {
    return state.mode;
}

module.exports = {
    init,
    setMode,
    setCustom,
    clearCustom,
    respond,
    hasCustom,
    getCustomSize,
    getMode,
    MAX_CUSTOM_BYTES,
};
