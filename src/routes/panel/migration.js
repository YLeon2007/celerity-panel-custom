/**
 * Panel routes for the Marzban → Celerity migration wizard.
 *
 * Flow:
 *   GET  /panel/migration                  → wizard shell + current state
 *   POST /panel/migration/test             → probe Marzban credentials
 *   POST /panel/migration/start            → kick off background import, returns taskId
 *   GET  /panel/migration/status/:taskId   → SSE stream of progress + logs
 *   POST /panel/migration/finalize         → persist secret/path, arm compat route
 *   POST /panel/migration/disable          → flip compat route back off (rollback)
 *   POST /panel/migration/probe-link       → diagnose a single legacy URL
 */

const router = require('express').Router();
const rateLimit = require('express-rate-limit');

const Settings = require('../../models/settingsModel');
const cacheService = require('../../services/cacheService');
const cryptoService = require('../../services/cryptoService');
const migrationService = require('../../services/marzbanMigrationService');
const syncService = require('../../services/syncService');
const logger = require('../../utils/logger');
const { _isValidPath, PATH_BLACKLIST } = require('../marzbanCompat');

// Rate limiter for the credential-bearing endpoints. The wizard sees this UI
// only after panel auth, but cycling through Marzban passwords from a hijacked
// session should still cost — bucket per IP, same as login.
const migrationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ error: res.locals.t?.('common.tooManyRequests') || 'Too many requests. Try again later.' }),
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

function _normalizePath(raw) {
    return String(raw || '').trim().toLowerCase().replace(/^\/+|\/+$/g, '');
}

function _pathError(path) {
    if (!path) return 'Subscription path is required.';
    if (PATH_BLACKLIST.has(path)) return `Path "${path}" is reserved by Celerity — choose another.`;
    if (!_isValidPath(path)) return 'Path must be 1..32 chars of [a-z0-9_-].';
    return null;
}

function _parseGroupMap(body) {
    const out = {};
    const adminNames = body['marzban_admin'];
    const groupIds = body['celerity_group'];
    if (!adminNames || !groupIds) return out;
    const a = Array.isArray(adminNames) ? adminNames : [adminNames];
    const g = Array.isArray(groupIds) ? groupIds : [groupIds];
    for (let i = 0; i < a.length; i++) {
        const admin = String(a[i] || '').trim();
        const gid = String(g[i] || '').trim();
        if (admin && gid) out[admin] = gid;
    }
    return out;
}

// ─── Routes ──────────────────────────────────────────────────────────────────
// Note: the wizard UI lives in the Settings page (Migration tab). This module
// exposes only the JSON / SSE endpoints the tab calls into.

// POST /panel/migration/test — probe Marzban credentials
router.post('/migration/test', migrationLimiter, async (req, res) => {
    const { baseUrl, username, password } = req.body || {};
    const out = await migrationService.testConnection({ baseUrl, username, password });
    if (!out.ok) return res.status(400).json({ error: out.error });
    res.json({
        total: out.total,
        admins: out.admins,
        isSudo: out.isSudo,
    });
});

// POST /panel/migration/start — kick off background import
router.post('/migration/start', migrationLimiter, async (req, res) => {
    try {
        const baseUrl = String(req.body.baseUrl || '').trim();
        const username = String(req.body.username || '').trim();
        const password = String(req.body.password || '');
        if (!baseUrl || !username || !password) {
            return res.status(400).json({ error: 'baseUrl, username and password are required' });
        }

        const groupMap = _parseGroupMap(req.body);
        const defaultGroupId = String(req.body.defaultGroupId || '').trim() || null;
        const onlyActive = req.body.onlyActive !== 'false' && req.body.onlyActive !== false;
        const importVlessUuid = req.body.importVlessUuid !== 'false' && req.body.importVlessUuid !== false;

        migrationService.pruneTasks();

        const taskId = migrationService.startImport({
            baseUrl,
            username,
            password,
            groupMap,
            defaultGroupId,
            options: { onlyActive, importVlessUuid },
        });

        res.json({ taskId });
    } catch (err) {
        logger.error(`[Migration] start: ${err.message}`);
        res.status(500).json({ error: err.message });
    }
});

// GET /panel/migration/status/:taskId — SSE log + progress stream
router.get('/migration/status/:taskId', (req, res) => {
    const task = migrationService.getTask(req.params.taskId);

    res.setHeader('Content-Type',      'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control',     'no-cache');
    res.setHeader('Connection',        'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    if (!task) {
        res.write(`data: ${JSON.stringify({ type: 'error', message: 'Task not found' })}\n\n`);
        return res.end();
    }

    let sentLogIdx = 0;
    let lastProgress = -1;

    const send = (type, data) => {
        if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
            if (typeof res.flush === 'function') res.flush();
        }
    };

    const flush = () => {
        while (sentLogIdx < task.logs.length) {
            send('log', { message: task.logs[sentLogIdx++] });
        }
        if (task.progress !== lastProgress) {
            lastProgress = task.progress;
            send('progress', {
                progress: task.progress,
                total:    task.total,
                imported: task.imported,
                skipped:  task.skipped,
                errors:   task.errors,
            });
        }
        if (task.done) {
            send('done', {
                success:   task.success,
                error:     task.error || null,
                imported:  task.imported,
                skipped:   task.skipped,
                errors:    task.errors,
                conflicts: task.conflicts || [],
            });
            clearInterval(intervalId);
            res.end();
        }
    };

    const intervalId = setInterval(flush, 400);
    req.on('close', () => clearInterval(intervalId));
});

// POST /panel/migration/finalize — persist secret + path, enable compat route
router.post('/migration/finalize', migrationLimiter, async (req, res) => {
    try {
        const path = _normalizePath(req.body.path);
        const pathErr = _pathError(path);
        if (pathErr) return res.status(400).json({ error: pathErr });

        const jwtSecret = String(req.body.jwtSecret || '').trim();
        if (!jwtSecret) return res.status(400).json({ error: 'JWT secret is required.' });

        const acceptUrlSalt = req.body.acceptUrlSalt === true || req.body.acceptUrlSalt === 'true' || req.body.acceptUrlSalt === 'on';

        const stats = {
            imported: Number(req.body['stats.imported']) || 0,
            skipped:  Number(req.body['stats.skipped'])  || 0,
            errors:   Number(req.body['stats.errors'])   || 0,
        };

        await Settings.update({
            'migration.marzban.enabled':            true,
            'migration.marzban.path':               path,
            'migration.marzban.jwtSecretEncrypted': cryptoService.encrypt(jwtSecret),
            'migration.marzban.acceptUrlSalt':      acceptUrlSalt,
            'migration.marzban.completedAt':        new Date(),
            'migration.marzban.stats':              stats,
        });

        // Drop any cached subscriptions so the next hit regenerates with the
        // current user data — important when migration was preceded by manual
        // edits in the panel.
        await cacheService.invalidateAllSubscriptions();

        // Refresh the cached regex/secret + cacheService TTLs.
        const { reloadSettings } = require('../../../index');
        await reloadSettings();

        // Xray nodes do not call the panel auth API on every connection like
        // Hysteria does. They need a runtime/config sync so migrated users'
        // xrayUuid values are pushed into Xray after the bulk import.
        syncService.syncAllNodes().catch(err => {
            logger.warn(`[Migration] Post-finalize sync failed: ${err.message}`);
        });

        res.json({ ok: true });
    } catch (err) {
        logger.error(`[Migration] finalize: ${err.message}`);
        res.status(500).json({ error: err.message });
    }
});

// POST /panel/migration/disable — flip compat route off (rollback)
router.post('/migration/disable', migrationLimiter, async (req, res) => {
    try {
        await Settings.update({ 'migration.marzban.enabled': false });
        const { reloadSettings } = require('../../../index');
        await reloadSettings();
        res.json({ ok: true });
    } catch (err) {
        logger.error(`[Migration] disable: ${err.message}`);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
