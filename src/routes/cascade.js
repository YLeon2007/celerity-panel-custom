/**
 * Cascade API routes — CRUD for cascade links, deploy/undeploy, topology.
 */

const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const { withLegacyCascadeUndeploy } = require('../modules/relay-l2tp/services/legacyCascadeUndeploy');
const cascadeLinksRoutes = require('./cascadeLinks');
const cascadeService = require('../services/cascadeService');
const cache = require('../services/cacheService');
const logger = require('../utils/logger');
const { requireScope } = require('../middleware/auth');
const { requirePanelCsrf } = require('./panel/csrf');
const { parsePositionsBody } = require('../utils/cascadeTopology');
const { isRebuildEnabled, rejectRebuildRoute } = require('../services/rebuildMode');
const { isReverse, hasKcpStatus, projectLinkHealth, observationSelect } = require('../services/rebuildReverseLinkHealth');

async function invalidateCascadeCache() {
    await cache.invalidateAllSubscriptions();
}

const deployLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
});

function isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

// ==================== VERSIONED LINK DRAFT CRUD ====================

router.use('/links', cascadeLinksRoutes);

// Link reconnects are operational actions, not topology draft mutations.
// Clients use the explicit deploy/undeploy endpoints below; changing link
// endpoints must never undeploy or rewrite a link as a hidden side effect.

// ==================== DEPLOY / UNDEPLOY ====================

/**
 * POST /cascade/links/:id/deploy — retired unsafe per-link deployment
 */
router.post('/links/:id/deploy', requireScope('nodes:write'), deployLimiter, async (req, res) => {
    res.status(410).json({
        error: {
            code: 'LEGACY_CASCADE_DEPLOY_DISABLED',
            message: 'Use POST /api/cascade/topology/deploy with expectedTopologyRevision',
        },
    });
});

/**
 * POST /cascade/links/:id/undeploy — remove cascade config from nodes
 */
if (isRebuildEnabled()) router.post('/links/:id/undeploy', rejectRebuildRoute);
router.post('/links/:id/undeploy', requireScope('nodes:write'), deployLimiter, async (req, res) => {
    try {
        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid link ID' });
        }

        const link = await CascadeLink.findById(req.params.id);
        if (!link) return res.status(404).json({ error: 'Cascade link not found' });

        // The legacy teardown is not queue-aware. Reject active/uncertain work
        // before its first node effect and hold exact non-expiring ownership
        // across the asynchronous teardown. Never purge queue-bound operations.
        await withLegacyCascadeUndeploy(async () => {
            // Resolve operational metadata only after ownership: an earlier
            // draft edit may have won the race with the initial existence read.
            const current = await CascadeLink.findById(req.params.id);
            if (!current) throw new Error('Cascade link disappeared before undeploy');
            await cascadeService.undeployLink(current);
        });

        // Invalidate subscription cache after undeploy
        await invalidateCascadeCache();

        res.json({ success: true, message: 'Cascade link undeployed' });
    } catch (error) {
        if (error.code === 'LEGACY_CASCADE_UNDEPLOY_BUSY') {
            return res.status(409).json({ error: { code: error.code, message: error.message } });
        }
        logger.error(`[Cascade API] Undeploy error: ${error.message}`);
        res.status(500).json({ error: { code: error.code || 'INTERNAL_ERROR', message: error.message } });
    }
});

// ==================== CHAIN DEPLOY ====================

/**
 * POST /cascade/chain/deploy — retired unversioned chain deployment
 */
router.post('/chain/deploy', requireScope('nodes:write'), deployLimiter, async (req, res) => {
    res.status(410).json({
        error: {
            code: 'LEGACY_CASCADE_DEPLOY_DISABLED',
            message: 'Use POST /api/cascade/topology/deploy with expectedTopologyRevision',
        },
    });
});

// ==================== HEALTH ====================

/**
 * GET /cascade/links/:id/health — health-check a single link
 */
router.get('/links/:id/health', requireScope('nodes:read'), async (req, res) => {
    const rebuild = isRebuildEnabled();
    if (rebuild) res.set('Cache-Control', 'no-store');
    try {
        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid link ID' });
        }

        const link = await CascadeLink.findById(req.params.id).select('+rebuildKcpApplied');
        if (!link) return res.status(404).json({ error: 'Cascade link not found' });

        const healthy = await cascadeService.healthCheckLink(link);
        const updated = await CascadeLink.findById(req.params.id).select(rebuild ? observationSelect : '+rebuildKcpApplied').lean();
        if (!updated) return res.status(404).json({ error: 'Cascade link not found' });
        const reverse = rebuild && isReverse(updated);
        const kcp = hasKcpStatus(updated);
        const current = projectLinkHealth(updated, rebuild);

        res.json({
            healthy: kcp ? false : reverse ? current.status === 'online' : healthy,
            status: current.status,
            ...(kcp ? { tunnelState: current.tunnelState, tunnelVerification: current.tunnelVerification } : {}),
            ...(reverse && current.observationExpiresAt ? { observationExpiresAt: current.observationExpiresAt } : {}),
            lastHealthCheck: current.lastHealthCheck,
            latencyMs: current.latencyMs,
        });
    } catch (error) {
        logger.error(`[Cascade API] Health error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// ==================== TOPOLOGY ====================

/**
 * GET /cascade/topology — full network graph for the visual map
 */
router.get('/topology', requireScope('nodes:read'), async (req, res) => {
    try {
        if (isRebuildEnabled()) res.set('Cache-Control', 'no-store');
        const topology = await cascadeService.getTopology();
        res.json(topology);
    } catch {
        logger.error('[Cascade API] Topology read failed');
        res.status(500).json({ error: 'Unable to load topology' });
    }
});

function requirePositionsCsrf(req, res, next) {
    // Preserve the classic layout client and the scoped API-key contract.
    return isRebuildEnabled() && !req.apiKey ? requirePanelCsrf(req, res, next) : next();
}

/**
 * POST /cascade/topology/positions — save node positions from the map editor
 */
router.post('/topology/positions', requireScope('nodes:write'), requirePositionsCsrf, async (req, res) => {
    const parsed = parsePositionsBody(req.body);
    if (!parsed.ok) return res.status(400).json({ error: parsed.error });

    try {
        await cascadeService.savePositions(parsed.positions);
        res.json({ success: true });
    } catch (error) {
        logger.error(`[Cascade API] Positions error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
