'use strict';

const { randomBytes } = require('node:crypto');
const { isRebuildEnabled } = require('../../services/rebuildMode');
const { runtimeForeignChange, networkNotReadyDetails, isNetworkNotReady } = require('../../services/rebuildRelayRuntimeRefusal');
const { validNodeId, identityChanged, grantConflict, grantUnavailable, grantEffectStatus } = require('./rebuildRelayAdmission');
const { observe } = require('./rebuildL2tpObservation');

// One-use, process-local tickets. A restart evicts them; keys and the private
// estimates never enter the session store. This panel has one active instance.
const tickets = new Map();
const ttl = 120_000;
const max = 256;
const required = 'REBUILD_L2TP_REMOVE_CONFIRMATION_REQUIRED';
const uncertainCodes = new Set(['OUTCOME_UNKNOWN', 'FINISH_OUTCOME_UNKNOWN', 'RESERVATION_OUTCOME_UNKNOWN',
    'RESERVATION_CLEANUP_FAILED'].map(code => `REBUILD_L2TP_REMOVE_${code}`));
const removedCleanup = 'REBUILD_L2TP_REMOVED_CLEANUP_FAILED';

function canPreviewRemoval(req) {
    return req.method === 'GET' && !!req.session?.authenticated && !!req.sessionID
        && req.headers['sec-fetch-site'] !== 'cross-site' && isRebuildEnabled() && validNodeId(req.params.id);
}

const identityReviewUrl = nodeId => `/panel/l2tp?identityChanged=${nodeId}#relay-${nodeId}`;

// Only charge the limiter once the node page actually needs a removal preview.
// Let the service own the current ENV/DB grant and install-ownership checks.
function admitPreview(req, res) {
    const limiter = res.locals.rebuildRemovalLimiter;
    if (!limiter) return Promise.resolve(false);
    return new Promise(resolve => {
        const stopped = () => finish(false);
        function finish(allowed) {
            res.off('finish', stopped);
            res.off('close', stopped);
            resolve(allowed);
        }
        res.once('finish', stopped);
        res.once('close', stopped);
        limiter(req, res, error => finish(!error));
    });
}

function issueRemovalTicket(req, estimate) {
    if (!canPreviewRemoval(req) || !estimate?.confirmable || estimate.nodeId !== req.params.id) return null;
    const now = performance.now();
    for (const [key, entry] of tickets) if (entry.expires <= now) tickets.delete(key);
    while (tickets.size >= max) tickets.delete(tickets.keys().next().value);
    const key = randomBytes(32).toString('hex');
    tickets.set(key, { sessionId: req.sessionID, nodeId: estimate.nodeId, estimate, expires: now + ttl });
    return key;
}

const localizedErrors = Object.freeze({
    [required]: 'nodes.rebuildRemoveRefresh',
    REBUILD_L2TP_REMOVE_PREVIEW_CHANGED: 'nodes.rebuildRemoveRefresh',
    REBUILD_L2TP_REMOVE_REFUSED: 'nodes.rebuildRemoveRefresh',
    REBUILD_L2TP_REMOVE_COUNT_UNAVAILABLE: 'nodes.rebuildRemoveCountUnavailable',
    REBUILD_L2TP_REMOVE_SESSIONS_BUSY: 'nodes.rebuildRemoveBusy',
    REBUILD_L2TP_REMOVE_IPSEC_BUSY: 'nodes.rebuildRemoveIpsecBusy',
    REBUILD_L2TP_ACCOUNTS_BLOCKED: 'rebuildL2tp.admission.blocked',
    [grantConflict]: 'rebuildL2tp.admission.grantConflict',
    [grantUnavailable]: 'rebuildL2tp.admission.grantUnavailable',
});
const publicCodes = new Set([...Object.keys(localizedErrors), identityChanged, runtimeForeignChange,
    'REBUILD_BUSY', 'REBUILD_LOCK_LOST', 'REBUILD_LOCK_RELEASE_UNCONFIRMED', 'REBUILD_TRANSPORT_CLEANUP_FAILED',
    ...['DISABLED', 'NOT_OWNED', 'CHANGED', 'REFUSED', 'OUTCOME_UNKNOWN', 'FINISH_OUTCOME_UNKNOWN', 'RESERVATION_FAILED',
        'RESERVATION_OUTCOME_UNKNOWN', 'BACKEND_UNAVAILABLE', 'PLAN_INVALID', 'RESERVATION_CLEANUP_FAILED'].map(code => `REBUILD_L2TP_REMOVE_${code}`),
    'REBUILD_L2TP_REMOVED_CLEANUP_FAILED', 'REBUILD_L2TP_ACCOUNTS_BLOCKED']);

async function handleRemoval(req, res, decision) {
    const { id } = req.params;
    const body = req.body;
    const invalid = () => res.status(400).json({ error: { code: 'REBUILD_INVALID_REQUEST' } });
    const nodeUrl = `/panel/nodes/${id}`;
    const html = req.accepts(['json', 'html']) === 'html';
    const conflict = (code, error) => {
        const status = grantEffectStatus(code) ?? 409;
        const outcome = uncertainCodes.has(code) || error?.outcome === 'unknown' ? 'unknown'
            : code === removedCleanup ? 'removed' : code === identityChanged && error?.retryAllowed === false ? 'unknown' : undefined;
        if (outcome) {
            if (html) return res.redirect(303, `/panel/l2tp?view=${outcome === 'unknown' ? 'remove-unconfirmed' : 'remove-cleanup'}`);
            return res.status(status).json({ error: { code, outcome, retryAllowed: false } });
        }
        if (code === runtimeForeignChange) {
            if (html) return res.redirect(303, '/panel/l2tp?view=remove-foreign-change');
            return res.status(409).json({ error: { code, retryAllowed: false } });
        }
        if (code === networkNotReadyDetails.code) {
            if (html) return res.redirect(303, '/panel/l2tp?view=remove-network-not-ready');
            return res.status(409).json({ error: networkNotReadyDetails });
        }
        if (html && code === identityChanged) return res.redirect(303, identityReviewUrl(id));
        if (html && res.locals.t) {
            const key = localizedErrors[code] ?? (grantEffectStatus(code) === 503 ? localizedErrors[grantUnavailable]
                : grantEffectStatus(code) === 409 ? localizedErrors[grantConflict] : 'nodes.rebuildRemoveFailed');
            return res.redirect(303, `${nodeUrl}?error=${encodeURIComponent(`${res.locals.t(key)} (${code})`)}`);
        }
        return res.status(status).json({ error: { code, ...(code === identityChanged && { outcome: 'refused' }),
            ...(error?.retryAllowed === false && { retryAllowed: false }) } });
    };
    res.set('Cache-Control', 'no-store');
    if (!validNodeId(id) || Object.keys(req.query || {}).length
        || !body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).some(key => !['_csrf', 'decision', 'ticket'].includes(key))) return invalid();
    if (body.decision !== decision || typeof body.ticket !== 'string'
        || body.ticket.length !== 64 || !/^[a-f0-9]{64}$/.test(body.ticket)) return conflict(required);
    const entry = tickets.get(body.ticket);
    if (!req.session?.authenticated || !req.sessionID || !entry || entry.sessionId !== req.sessionID
        || entry.nodeId !== id || entry.expires <= performance.now()) return conflict(required);
    // Consume synchronously, before any DB/SSH await, including on cancellation.
    tickets.delete(body.ticket);
    if (decision === 'cancel') return res.redirect(303, '/panel/nodes');
    const acknowledge = observe(req);
    try {
        const result = await require('../../services/rebuildService').createRebuildService().confirmRemoveRelay(id, entry.estimate);
        if (result?.status !== 'not_installed' || result.nodeId !== id) return conflict('REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN');
        acknowledge('removed');
        return html ? res.redirect(303, '/panel/l2tp') : res.json({ executionMode: 'rebuild', status: 'not_installed', nodeId: id });
    } catch (error) {
        const code = publicCodes.has(error?.code) || isNetworkNotReady(error) || grantEffectStatus(error?.code)
            ? error.code : 'REBUILD_L2TP_REMOVE_FAILED';
        return conflict(code, error);
    }
}

module.exports = {
    canPreviewRemoval, issueRemovalTicket, identityReviewUrl, admitPreview,
    submitRemoval: (req, res) => handleRemoval(req, res, 'confirm'),
    cancelRemoval: (req, res) => handleRemoval(req, res, 'cancel'),
};
