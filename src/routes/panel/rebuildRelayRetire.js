'use strict';

const { randomBytes } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { requireAuth } = require('./helpers');
const { validNodeId, validActor } = require('./rebuildRelayAdmission');
const { neighborRefusalForError } = require('../../services/rebuildNeighborRefusal');

const retirePath = /^\/rebuild\/relays\/[^/]+\/retire\/(?:preview|confirm)$/;
const invalid = 'REBUILD_RETIRE_INVALID_REQUEST';
const unavailable = 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE';
const unconfirmed = 'REBUILD_RETIRE_OUTCOME_UNCONFIRMED';
const neighborUnavailable = 'REBUILD_NEIGHBOR_UNAVAILABLE';
const changed = 'PREVIEW_CHANGED';
const protectedChange = 'REBUILD_RETIRE_PROTECTED_CHANGE';
const respondError = (res, status, code, details) => res.status(status).json({ error: { code, ...details } });
const rejectRetire = res => respondError(res, 400, invalid);
const getService = () => require('../../services/rebuildService').createRebuildService();
const isConfirm = path => path.endsWith('/confirm');
const ticketField = String.raw`"ticket"\s*:\s*"[a-f0-9]{64}"`;
const decisionField = String.raw`"decision"\s*:\s*(?:"(?:[^"\\]|\\.)*"|true|false|null|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)`;
const confirmJson = new RegExp(String.raw`^\s*\{\s*(?:${ticketField}(?:\s*,\s*${decisionField})?|${decisionField}\s*,\s*${ticketField})\s*\}\s*$`);
const emptyJson = /^\s*\{\s*\}\s*$/;
const validRetireJson = (path, bytes) => (isConfirm(path) ? confirmJson : emptyJson).test(bytes.toString('utf8'));

// Like standalone L2TP Remove, retain the actual service estimate in this
// process, never in Redis/the session cookie or in the JSON projection.
const tickets = new Map();
const ttl = 120_000;
const max = 256;
const validCount = n => Number.isSafeInteger(n) && n >= 0;
const normalizeSince = value => {
    if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)(?![\s\S])/.test(value)) return null;
    const time = Date.parse(value);
    return Number.isFinite(time) ? new Date(time).toISOString() : null;
};

async function freshPreview(req, nodeId) {
    const estimate = await getService().previewRetireRelay(nodeId);
    if (estimate?.nodeId !== nodeId || !['online', 'abandon'].includes(estimate.mode)
        || typeof estimate.allowed !== 'boolean') throw new Error(unavailable);
    const { mode, activeClients, accountCount, unavailableSince, allowed } = estimate;
    if ((activeClients !== null && !validCount(activeClients)) || (accountCount !== null && !validCount(accountCount))
        || (allowed && mode === 'online' && activeClients === null)
        || (mode === 'abandon' && activeClients !== null)) throw new Error(unavailable);
    const preview = { nodeId, mode, activeClients, accountCount, allowed,
        unavailableSince: mode === 'abandon' ? normalizeSince(unavailableSince) : null };
    if (!allowed) {
        const code = safeRefusal(estimate);
        return code ? { ...preview, code } : preview;
    }
    const decision = mode === 'abandon' ? 'abandon' : activeClients > 0 ? 'force' : 'delete';
    const now = performance.now();
    for (const [ticket, entry] of tickets) if (entry.expires <= now) tickets.delete(ticket);
    while (tickets.size >= max) tickets.delete(tickets.keys().next().value);
    const ticket = randomBytes(32).toString('hex');
    tickets.set(ticket, { sessionId: req.sessionID, actor: req.session.adminUsername, nodeId,
        expires: now + ttl, estimate, decision, activeClients });
    return { ...preview, ticket };
}

function safeRefusal(error) {
    if (error?.outcome === 'unknown') return null;
    if (error?.code === neighborUnavailable) return neighborUnavailable;
    if (error?.code === protectedChange || error?.code === 'REBUILD_CLIENT_CHANGE') return protectedChange;
    return null;
}

async function sendPreview(req, res, nodeId, stale) {
    try {
        const preview = await freshPreview(req, nodeId);
        const body = stale ? { error: { code: changed }, preview } : { preview };
        return res.status(stale ? 409 : 200).type('application/json').end(JSON.stringify(body));
    } catch (error) {
        const refusal = neighborRefusalForError(error);
        if (refusal) return res.status(409).json({ error: refusal });
        const code = safeRefusal(error);
        return code ? respondError(res, 409, code) : respondError(res, 503, unavailable);
    }
}

async function confirm(req, res, nodeId) {
    const { ticket, decision } = req.body;
    const entry = tickets.get(ticket);
    if (!entry || entry.sessionId !== req.sessionID || entry.actor !== req.session.adminUsername
        || entry.nodeId !== nodeId || entry.expires <= performance.now()) {
        return respondError(res, 409, 'REBUILD_RETIRE_CONFIRMATION_REQUIRED');
    }
    // Consume synchronously before any await, even on a mismatched decision.
    tickets.delete(ticket);
    if (decision !== entry.decision) return respondError(res, 409, 'REBUILD_RETIRE_DECISION_REQUIRED',
        entry.decision === 'force' ? { activeClients: entry.activeClients } : undefined);
    try {
        const result = await getService().confirmRetireRelay(nodeId, entry.estimate, entry.decision);
        if (result?.nodeId === nodeId && result.status === 'deleted') return res.json({ nodeId, status: 'deleted' });
    } catch (error) {
        // Abandon confirmation must not probe the target, even on refusal.
        // A replacement online preview never retries confirm.
        if (error?.code === changed && error.outcome !== 'unknown' && error.retryAllowed !== false) {
            return entry.decision === 'abandon' ? respondError(res, 409, changed) : sendPreview(req, res, nodeId, true);
        }
        const refusal = neighborRefusalForError(error);
        if (refusal) return res.status(409).json({ error: refusal });
        const code = safeRefusal(error);
        if (code) return respondError(res, 409, code);
    }
    return respondError(res, 503, unconfirmed);
}

function mountRetire(router, { requireSessionId, checkCsrf, requireCompletedOnboarding }, limiter) {
    router.post(retirePath, requireAuth, requireSessionId, (req, res, next) => {
        if (!validActor(req.session.adminUsername)) return respondError(res, 403, 'REBUILD_RETIRE_SESSION_REQUIRED');
        next();
    }, checkCsrf, (req, res, next) => {
        const nodeId = req.path.split('/')[3];
        const body = req.body;
        if (!validNodeId(nodeId) || req.url.includes('?') || !req.is('application/json')
            || !body || Object.getPrototypeOf(body) !== Object.prototype) return rejectRetire(res);
        const valid = isConfirm(req.path)
            ? typeof body.ticket === 'string' && /^[a-f0-9]{64}(?![\s\S])/.test(body.ticket)
                && Object.keys(body).every(key => key === 'ticket' || key === 'decision')
            : Object.keys(body).length === 0;
        if (!valid) return rejectRetire(res);
        next();
    }, limiter, requireCompletedOnboarding(res => respondError(res, 503, unavailable)), (req, res) => {
        const nodeId = req.path.split('/')[3];
        return isConfirm(req.path) ? confirm(req, res, nodeId) : sendPreview(req, res, nodeId, false);
    });
    router.all(retirePath, (_req, res) => respondError(res.set('Allow', 'POST'), 405, 'METHOD_NOT_ALLOWED'));
    router.all(retirePath, (_err, _req, res, _next) => respondError(res, 503, unconfirmed));
}

module.exports = { retirePath, validRetireJson, rejectRetire, mountRetire };
