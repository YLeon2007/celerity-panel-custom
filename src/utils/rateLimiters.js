/**
 * Shared rate limiters used across the public-facing endpoints.
 *
 * Kept in a tiny dedicated module so middleware and routes outside the main
 * `index.js` (e.g. the Marzban-compat handler) can reuse the same limiter
 * instance — important because each `rateLimit({...})` call owns its own
 * in-memory bucket. Sharing the instance keeps a single bucket per client IP
 * across the native `/api/files`, `/api/info`, and legacy `/{path}/{token}`
 * endpoints.
 *
 * The thresholds are driven by `Settings.rateLimit` and live-reloaded via
 * `applyRateLimits(settings)` (called from `reloadSettings()` in index.js).
 */

const rateLimit = require('express-rate-limit');

const logger = require('./logger');

// Live thresholds. Mutated by applyRateLimits(); the limiter `max` callback
// reads from this object so updates take effect on the next request.
const _state = {
    subscriptionPerMinute: 100,
    authPerSecond: 200,
};

const subscriptionLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: () => _state.subscriptionPerMinute,
    handler: (req, res) => {
        logger.warn(`[Sub] Rate limit: ${req.ip}`);
        res.status(429).type('text/plain').send('# Too many requests');
    },
});

const authLimiter = rateLimit({
    windowMs: 1000,
    max: () => _state.authPerSecond,
    handler: (req, res) => {
        logger.warn(`[Auth] Rate limit: ${req.ip}`);
        res.status(429).json({ ok: false });
    },
});

function applyRateLimits(settings) {
    if (settings?.rateLimit) {
        _state.subscriptionPerMinute = settings.rateLimit.subscriptionPerMinute || 100;
        _state.authPerSecond = settings.rateLimit.authPerSecond || 200;
        logger.info(`[Settings] Rate limits: sub=${_state.subscriptionPerMinute}/min auth=${_state.authPerSecond}/sec`);
    }
}

function getRateLimitState() {
    return _state;
}

module.exports = {
    subscriptionLimiter,
    authLimiter,
    applyRateLimits,
    getRateLimitState,
};
