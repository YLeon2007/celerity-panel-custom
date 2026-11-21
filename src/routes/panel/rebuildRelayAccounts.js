'use strict';

const { createRebuildService } = require('../../services/rebuildService');

const methods = Object.freeze({ create: 'createRelayAccount', disable: 'disableRelayAccount', delete: 'deleteRelayAccount' });
const statuses = Object.freeze({ create: 'created', disable: 'disabled', delete: 'deleted' });
const blocked = new Set(['REBUILD_L2TP_ACCOUNTS_BLOCKED', 'REBUILD_L2TP_ACCOUNTS_INTENT_UNKNOWN',
    'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN', 'REBUILD_L2TP_ACCOUNTS_FINISH_UNKNOWN',
    'REBUILD_L2TP_ACCOUNTS_CLEANUP_FAILED']);
const unavailable = new Set(['REBUILD_L2TP_ACCOUNTS_UNAVAILABLE', 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE']);
const rejected = new Set(['REBUILD_L2TP_ACCOUNTS_DISABLED', 'REBUILD_L2TP_ACCOUNTS_NO_INSTALLED',
    'REBUILD_L2TP_ACCOUNTS_NOT_OWNED', 'REBUILD_L2TP_ACCOUNTS_BINDING_MISMATCH', 'REBUILD_L2TP_ACCOUNTS_ACCOUNT_CONFLICT',
    'REBUILD_L2TP_ACCOUNTS_POOL_EXHAUSTED', 'REBUILD_L2TP_ACCOUNTS_PREFLIGHT_REFUSED', 'REBUILD_L2TP_ACCOUNTS_CHANGED',
    'REBUILD_L2TP_ACCOUNTS_OPERATOR_LIST_REQUIRED', 'REBUILD_BUSY', 'REBUILD_LOCK_LOST']);
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
            const { login } = body;
            const result = await service()[methods[action]]({ login, ...(action === 'create' && { password: body.password }) });
            const status = statuses[action], { relayCount, sessionsTerminated } = result ?? {};
            if (result?.executionMode !== 'rebuild' || result.status !== status || result.login !== login
                || !Number.isSafeInteger(relayCount) || relayCount < 1
                || (action !== 'create' && (!Number.isSafeInteger(sessionsTerminated) || sessionsTerminated < 0))) {
                return res.status(409).json({ error: { code: 'REBUILD_L2TP_ACCOUNTS_FAILED', retryAllowed: false } });
            }
            // Only the public receipt crosses this boundary, even if the
            // service starts returning private inventory or transport metadata.
            return res.status(action === 'create' ? 201 : 200).json({ executionMode: 'rebuild', status, login, relayCount,
                ...(action !== 'create' && { sessionsTerminated }) });
        } catch (error) {
            const { code } = error ?? {};
            if (code === invalid) return res.status(400).json({ error: { code } });
            if (blocked.has(code)) {
                const count = error.confirmedSessionsTerminated;
                return res.status(409).json({ error: { code, retryAllowed: false,
                    ...(action !== 'create' && Number.isSafeInteger(count) && count >= 0 && { confirmedSessionsTerminated: count }) } });
            }
            if (unavailable.has(code)) return res.status(503).json({ error: { code } });
            if (rejected.has(code)) return res.status(409).json({ error: { code } });
            return res.status(409).json({ error: { code: 'REBUILD_L2TP_ACCOUNTS_FAILED', retryAllowed: false } });
        }
    };
}

module.exports = { accountHandler };
