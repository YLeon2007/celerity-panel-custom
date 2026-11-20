'use strict';

const { createRebuildService } = require('../../services/rebuildService');

const methods = Object.freeze({ create: 'createRelayAccount', disable: 'disableRelayAccount', delete: 'deleteRelayAccount' });
const blocked = new Set(['REBUILD_L2TP_ACCOUNTS_BLOCKED', 'REBUILD_L2TP_ACCOUNTS_INTENT_UNKNOWN',
    'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN', 'REBUILD_L2TP_ACCOUNTS_FINISH_UNKNOWN',
    'REBUILD_L2TP_ACCOUNTS_RELEASE_UNKNOWN', 'REBUILD_L2TP_ACCOUNTS_CLEANUP_FAILED']);
const unavailable = new Set(['REBUILD_L2TP_ACCOUNTS_UNAVAILABLE', 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE']);
const rejected = new Set(['REBUILD_L2TP_ACCOUNTS_DISABLED', 'REBUILD_L2TP_ACCOUNTS_NO_INSTALLED',
    'REBUILD_L2TP_ACCOUNTS_NOT_OWNED', 'REBUILD_L2TP_ACCOUNTS_BINDING_MISMATCH', 'REBUILD_L2TP_ACCOUNTS_ACCOUNT_CONFLICT',
    'REBUILD_L2TP_ACCOUNTS_POOL_EXHAUSTED', 'REBUILD_L2TP_ACCOUNTS_PREFLIGHT_REFUSED', 'REBUILD_L2TP_ACCOUNTS_CHANGED',
    'REBUILD_BUSY', 'REBUILD_LOCK_LOST']);
const invalid = 'REBUILD_L2TP_ACCOUNTS_INVALID_REQUEST';

function accountHandler(action, service = createRebuildService) {
    if (!Object.hasOwn(methods, action)) throw new TypeError('Unknown relay account action');
    return async (req, res) => {
        const body = req.body;
        const allowed = action === 'create' ? ['_csrf', 'login', 'password'] : ['_csrf', 'login'];
        if (Object.keys(req.query ?? {}).length || !body || typeof body !== 'object' || Array.isArray(body)
            || Object.keys(body).some(key => !allowed.includes(key)) || typeof body.login !== 'string'
            || (action === 'create' && typeof body.password !== 'string')) return res.status(400).json({ error: { code: invalid } });
        try {
            const result = await service()[methods[action]]({ login: body.login, ...(action === 'create' && { password: body.password }) });
            return res.status(action === 'create' ? 201 : 200).json(result);
        } catch (error) {
            const { code } = error ?? {};
            if (code === invalid) return res.status(400).json({ error: { code } });
            if (blocked.has(code)) return res.status(409).json({ error: { code, retryAllowed: false } });
            if (unavailable.has(code)) return res.status(503).json({ error: { code } });
            return res.status(409).json({ error: { code: rejected.has(code) ? code : 'REBUILD_L2TP_ACCOUNTS_FAILED' } });
        }
    };
}

module.exports = { accountHandler };
