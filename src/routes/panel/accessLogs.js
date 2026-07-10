/**
 * Admin-only access-logs UI + JSON API.
 *
 * Routes (all behind the panel auth chain applied in panel/index.js):
 *   GET  /panel/access-logs             -> dashboard page
 *   GET  /panel/access-logs/api/analytics -> combined overview: totals, series,
 *                                          top dests/ports/blocked, per-user
 *                                          IP/fan-out (Parquet via DuckDB in one
 *                                          worker spawn; Mongo rollups when degraded)
 *   GET  /panel/access-logs/api/search  -> paged raw-event search (DuckDB)
 *   GET  /panel/access-logs/api/status  -> per-node shipping + pipeline status
 *   POST /panel/access-logs/api/purge   -> delete the entire stored dataset
 *
 * Search/summary never interpolate user input into SQL — filters are bound as
 * parameters inside searchService. When the feature is off, the page shows a
 * banner and the APIs return empty/disabled payloads.
 */

const express = require('express');
const router = express.Router();

const { render } = require('./helpers');
const logger = require('../../utils/logger');

// Parse a bounded date from a query string; returns null when absent/invalid.
function parseDate(v) {
    if (!v) return null;
    const d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
}

// Build the filter object from query params, shared by search + summary.
function filtersFromQuery(q) {
    const f = {};
    const from = parseDate(q.from);
    const to = parseDate(q.to);
    if (from) f.from = from;
    if (to) f.to = to;
    if (q.nodeId) f.nodeId = String(q.nodeId).slice(0, 64);
    if (q.email) f.email = String(q.email).slice(0, 256);
    if (q.sourceIp) f.sourceIp = String(q.sourceIp).slice(0, 64);
    if (q.destination) f.destination = String(q.destination).slice(0, 256);
    if (q.action && ['accepted', 'rejected', 'blocked'].includes(q.action)) f.action = q.action;
    if (q.network && ['tcp', 'udp'].includes(q.network)) f.network = q.network;
    if (q.q) f.q = String(q.q).slice(0, 256);
    return f;
}

async function isEnabled() {
    const Settings = require('../../models/settingsModel');
    const s = await Settings.get();
    return !!s?.accessLogs?.enabled;
}

// ─── Page ────────────────────────────────────────────────────────────────────

router.get('/access-logs', async (req, res) => {
    try {
        const Settings = require('../../models/settingsModel');
        const HyNode = require('../../models/hyNodeModel');
        const settings = await Settings.get();
        const nodes = await HyNode.find({
            type: 'xray',
            cascadeRole: { $in: ['standalone', 'portal'] },
        }).select('name xray.accessLogs.status xray.accessLogs.lastBatchAt').lean();

        render(res, 'access-logs', {
            title: res.locals.t?.('accessLogs.pageTitle') || 'Access logs',
            page: 'accessLogs',
            enabled: !!settings?.accessLogs?.enabled,
            state: settings?.accessLogs?.state || 'disabled',
            nodes,
        });
    } catch (error) {
        logger.error('[Panel] GET /access-logs error:', error.message);
        res.status(500).send(`${res.locals.t?.('common.error') || 'Error'}: ${error.message}`);
    }
});

// ─── JSON API ────────────────────────────────────────────────────────────────

router.get('/access-logs/api/analytics', async (req, res) => {
    try {
        if (!(await isEnabled())) return res.json({ enabled: false });
        const filters = filtersFromQuery(req.query);
        const searchService = require('../../services/accessLogs/searchService');
        const result = await searchService.overview(filters, { topN: 10, userLimit: 25 });

        if (result.degraded) {
            // DuckDB is down: fall back to Mongo rollups for the cheap aggregates
            // (totals + timeline + top destinations). Per-user IP/fan-out tables
            // and port/blocked breakdowns need Parquet, so they are empty and the
            // UI flags them as requiring DuckDB.
            const rollupService = require('../../services/accessLogs/rollupService');
            const from = filters.from || new Date(Date.now() - 24 * 60 * 60 * 1000);
            const to = filters.to || new Date();
            const roll = await rollupService.readSummary(from, to, filters.nodeId);
            return res.json({
                enabled: true,
                degraded: true,
                duckdbRequired: true,
                totals: roll.totals,
                series: roll.series,
                topDestinations: roll.topDestinations,
                topPorts: [],
                topBlocked: [],
                users: [],
            });
        }
        if (result.error) {
            return res.json({ enabled: true, error: result.error, totals: {}, series: [], users: [] });
        }
        return res.json({ enabled: true, degraded: false, ...result });
    } catch (error) {
        logger.error('[Panel] access-logs analytics error:', error.message);
        res.status(500).json({ error: 'analytics failed' });
    }
});

router.get('/access-logs/api/search', async (req, res) => {
    try {
        if (!(await isEnabled())) return res.json({ enabled: false, rows: [] });
        const filters = filtersFromQuery(req.query);
        const opts = {
            limit: Math.min(1000, parseInt(req.query.limit, 10) || 200),
            offset: Math.max(0, parseInt(req.query.offset, 10) || 0),
            sort: req.query.sort,
            dir: req.query.dir,
        };
        const searchService = require('../../services/accessLogs/searchService');
        const result = await searchService.search(filters, opts);
        return res.json({ enabled: true, ...result });
    } catch (error) {
        logger.error('[Panel] access-logs search error:', error.message);
        res.status(500).json({ error: 'search failed' });
    }
});

router.get('/access-logs/api/status', async (req, res) => {
    try {
        const Settings = require('../../models/settingsModel');
        const HyNode = require('../../models/hyNodeModel');
        const spoolService = require('../../services/accessLogs/spoolService');
        const duckdb = require('../../services/accessLogs/duckdbService');

        const settings = await Settings.get();
        const nodes = await HyNode.find({
            type: 'xray',
            cascadeRole: { $in: ['standalone', 'portal'] },
        }).select('name agentVersion xray.accessLogs').lean();

        const spool = await spoolService.spoolSize();
        const duckAvailable = await duckdb.isAvailable();

        res.json({
            enabled: !!settings?.accessLogs?.enabled,
            state: settings?.accessLogs?.state || 'disabled',
            stats: settings?.accessLogs?.stats || {},
            spool,
            duckdb: duckAvailable,
            nodes: nodes.map(n => ({
                id: String(n._id),
                name: n.name,
                agentVersion: n.agentVersion || '',
                status: n.xray?.accessLogs?.status || 'disabled',
                lastBatchAt: n.xray?.accessLogs?.lastBatchAt || null,
                lastError: n.xray?.accessLogs?.lastError || '',
            })),
        });
    } catch (error) {
        logger.error('[Panel] access-logs status error:', error.message);
        res.status(500).json({ error: 'status failed' });
    }
});

router.post('/access-logs/api/purge', async (req, res) => {
    try {
        const fsp = require('fs/promises');
        const paths = require('../../services/accessLogs/paths');
        const AccessLogRollup = require('../../models/accessLogRollupModel');

        // Remove Parquet, incoming spool, and quarantine; recreate empty dirs.
        for (const dir of [paths.PARQUET_DIR, paths.INCOMING_DIR, paths.QUARANTINE_DIR]) {
            await fsp.rm(dir, { recursive: true, force: true });
            await fsp.mkdir(dir, { recursive: true });
        }
        await AccessLogRollup.deleteMany({});

        // Reset the aggregate ingest counters so the settings dashboard reflects
        // the now-empty dataset.
        const Settings = require('../../models/settingsModel');
        await Settings.update({
            'accessLogs.stats.ingestedBatches': 0,
            'accessLogs.stats.rejectedBatches': 0,
            'accessLogs.stats.duplicateBatches': 0,
            'accessLogs.stats.lastIngestAt': null,
        });

        logger.info('[AccessLogs] stored dataset purged by admin');
        res.json({ ok: true });
    } catch (error) {
        logger.error('[Panel] access-logs purge error:', error.message);
        res.status(500).json({ error: 'purge failed' });
    }
});

module.exports = router;
