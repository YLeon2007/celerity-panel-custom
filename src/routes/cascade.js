/**
 * Cascade API routes — CRUD for cascade links, deploy/undeploy, topology.
 */

const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const cascadeLinksRoutes = require('./cascadeLinks');
const cascadeService = require('../services/cascadeService');
const cache = require('../services/cacheService');
const logger = require('../utils/logger');
const { requireScope } = require('../middleware/auth');

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
 * POST /cascade/links/:id/deploy — deploy configs to both nodes
 */
router.post('/links/:id/deploy', requireScope('nodes:write'), deployLimiter, async (req, res) => {
    try {
        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid link ID' });
        }

        const link = await CascadeLink.findById(req.params.id)
            .populate('portalNode')
            .populate('bridgeNode');

        if (!link) return res.status(404).json({ error: 'Cascade link not found' });

        const result = await cascadeService.deployLink(link);

        // Invalidate subscription cache after deploy
        await invalidateCascadeCache();

        if (result.success) {
            res.json({ success: true, message: 'Cascade link deployed' });
        } else {
            res.status(500).json({ success: false, error: result.error });
        }
    } catch (error) {
        logger.error(`[Cascade API] Deploy error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /cascade/links/:id/undeploy — remove cascade config from nodes
 */
router.post('/links/:id/undeploy', requireScope('nodes:write'), deployLimiter, async (req, res) => {
    try {
        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid link ID' });
        }

        const link = await CascadeLink.findById(req.params.id);
        if (!link) return res.status(404).json({ error: 'Cascade link not found' });

        await cascadeService.undeployLink(link);

        // Invalidate subscription cache after undeploy
        await invalidateCascadeCache();

        res.json({ success: true, message: 'Cascade link undeployed' });
    } catch (error) {
        logger.error(`[Cascade API] Undeploy error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// ==================== CHAIN DEPLOY ====================

/**
 * POST /cascade/chain/deploy — deploy entire cascade chain in correct order
 * Accepts either nodeId or linkId to identify the chain
 */
router.post('/chain/deploy', requireScope('nodes:write'), deployLimiter, async (req, res) => {
    try {
        const { nodeId, linkId } = req.body;

        let startNodeId;
        if (nodeId) {
            if (!isValidObjectId(nodeId)) {
                return res.status(400).json({ error: 'Invalid nodeId' });
            }
            startNodeId = nodeId;
        } else if (linkId) {
            if (!isValidObjectId(linkId)) {
                return res.status(400).json({ error: 'Invalid linkId' });
            }
            const link = await CascadeLink.findById(linkId);
            if (!link) return res.status(404).json({ error: 'Link not found' });
            startNodeId = link.portalNode;
        } else {
            return res.status(400).json({ error: 'nodeId or linkId is required' });
        }

        const result = await cascadeService.deployChain(startNodeId);

        // Invalidate subscription cache after chain deploy
        await invalidateCascadeCache();

        if (result.success) {
            res.json({
                success: true,
                message: `Chain deployed: ${result.deployed} nodes`,
                deployed: result.deployed,
            });
        } else {
            res.status(500).json({
                success: false,
                deployed: result.deployed,
                errors: result.errors,
            });
        }
    } catch (error) {
        logger.error(`[Cascade API] Chain deploy error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// ==================== HEALTH ====================

/**
 * GET /cascade/links/:id/health — health-check a single link
 */
router.get('/links/:id/health', requireScope('nodes:read'), async (req, res) => {
    try {
        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ error: 'Invalid link ID' });
        }

        const link = await CascadeLink.findById(req.params.id);
        if (!link) return res.status(404).json({ error: 'Cascade link not found' });

        const healthy = await cascadeService.healthCheckLink(link);
        const updated = await CascadeLink.findById(req.params.id);

        res.json({
            healthy,
            status: updated.status,
            lastHealthCheck: updated.lastHealthCheck,
            latencyMs: updated.latencyMs,
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
        const topology = await cascadeService.getTopology();
        res.json(topology);
    } catch (error) {
        logger.error(`[Cascade API] Topology error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /cascade/topology/positions — save node positions from the map editor
 */
router.post('/topology/positions', requireScope('nodes:write'), async (req, res) => {
    try {
        const { positions } = req.body;
        if (!Array.isArray(positions)) {
            return res.status(400).json({ error: 'positions must be an array' });
        }

        await cascadeService.savePositions(positions);
        res.json({ success: true });
    } catch (error) {
        logger.error(`[Cascade API] Positions error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
