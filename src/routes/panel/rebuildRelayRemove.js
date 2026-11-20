'use strict';

const { randomBytes } = require('node:crypto');
const { canInstallRelay } = require('../../services/rebuildRelayAuthorization');

// One-use, process-local tickets. A restart evicts them; keys and the private
// estimates never enter the session store. This panel has one active instance.
const tickets = new Map();
const ttl = 120_000;
const max = 256;
const required = 'REBUILD_L2TP_REMOVE_CONFIRMATION_REQUIRED';

function canPreviewRemoval(req) {
    return req.method === 'GET' && !!req.session?.authenticated && !!req.sessionID
        && req.headers['sec-fetch-site'] !== 'cross-site' && canInstallRelay(process.env, req.params.id);
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
    REBUILD_L2TP_REMOVE_COUNT_UNAVAILABLE: 'nodes.rebuildRemoveCountUnavailable',
    REBUILD_L2TP_REMOVE_SESSIONS_BUSY: 'nodes.rebuildRemoveBusy',
});

async function handleRemoval(req, res, decision) {
    const { id } = req.params;
    const body = req.body;
    const invalid = () => res.status(400).json({ error: { code: 'REBUILD_INVALID_REQUEST' } });
    const nodeUrl = `/panel/nodes/${id}`;
    const html = req.accepts(['json', 'html']) === 'html';
    const conflict = code => {
        if (html && res.locals.t) {
            const key = Object.hasOwn(localizedErrors, code) ? localizedErrors[code] : 'nodes.rebuildRemoveFailed';
            return res.redirect(303, `${nodeUrl}?error=${encodeURIComponent(`${res.locals.t(key)} (${code})`)}`);
        }
        return res.status(409).json({ error: { code } });
    };
    res.set('Cache-Control', 'no-store');
    if (typeof id !== 'string' || id.length !== 24 || !/^[a-f0-9]{24}$/.test(id) || Object.keys(req.query || {}).length
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
    try {
        const result = await require('../../services/rebuildService').createRebuildService().confirmRemoveRelay(id, entry.estimate);
        return html ? res.redirect(303, nodeUrl) : res.json(result);
    } catch (error) {
        const code = typeof error?.code === 'string' && /^REBUILD_[A-Z0-9_]+$(?!\n)/.test(error.code)
            ? error.code : 'REBUILD_L2TP_REMOVE_FAILED';
        return conflict(code);
    }
}

module.exports = {
    canPreviewRemoval, issueRemovalTicket,
    submitRemoval: (req, res) => handleRemoval(req, res, 'confirm'),
    cancelRemoval: (req, res) => handleRemoval(req, res, 'cancel'),
};
