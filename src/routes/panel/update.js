/**
 * Panel routes: self-update status/check/apply.
 */

const router = require('express').Router();
const rateLimit = require('express-rate-limit');

const updateService = require('../../services/updateService');
const logger = require('../../utils/logger');

const updateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({
        success: false,
        error: res.locals.t?.('common.tooManyRequests') || 'Too many requests. Try again later.',
    }),
});

// GET /panel/update/status
router.get('/update/status', updateLimiter, async (req, res) => {
    try {
        const status = await updateService.getStatus();
        res.json(status);
    } catch (error) {
        logger.warn(`[SelfUpdate] Status route error: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST /panel/update/check
router.post('/update/check', updateLimiter, async (req, res) => {
    try {
        const status = await updateService.checkNow();
        res.json(status);
    } catch (error) {
        logger.warn(`[SelfUpdate] Check route error: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST /panel/update/apply
router.post('/update/apply', updateLimiter, async (req, res) => {
    try {
        const result = await updateService.applyUpdate();
        res.json(result);
    } catch (error) {
        logger.error(`[SelfUpdate] Apply route error: ${error.message}`);
        const status = error.code === 'UPDATE_RUNNING' ? 409 : 500;
        res.status(status).json({ success: false, error: error.message });
    }
});

module.exports = router;
