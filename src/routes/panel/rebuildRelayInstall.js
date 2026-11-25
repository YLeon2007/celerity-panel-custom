'use strict';

const { publicInstallFailure } = require('../../services/rebuildRelayInstallDiagnostics');
const { identityChanged, grantEffectStatus, validActor } = require('./rebuildRelayAdmission');
const { observe } = require('./rebuildL2tpObservation');

const token = /^[a-f0-9]{64}(?![\s\S])/;
const validCleanup = value => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === 2 && Object.hasOwn(value, 'token') && Object.hasOwn(value, 'fixXrayUnitMode')
    && typeof value.token === 'string' && token.test(value.token) && typeof value.fixXrayUnitMode === 'boolean';

function handler(service = () => require('../../services/rebuildService').createRebuildService()) {
    return async (req, res) => {
        if (!/^[a-f0-9]{24}(?![\s\S])/.test(req.params.id) || Object.keys(req.query || {}).length ||
            (req.body !== undefined && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
            Object.keys(req.body).some(k => k !== '_csrf' && k !== 'foreignCleanup') ||
            (Object.hasOwn(req.body, 'foreignCleanup') && !validCleanup(req.body.foreignCleanup))))) {
            return res.status(400).json({ error: { code: 'REBUILD_INVALID_REQUEST', outcome: 'refused' } });
        }
        const acknowledge = observe(req);
        try {
            // New reservations bind recovery to the same authenticated admin.
            // Never accept an actor (or any recovery witness) from the request body.
            const actor = req.session?.adminUsername;
            const sessionId = req.session?.authenticated === true && validActor(actor)
                && typeof req.sessionID === 'string' && req.sessionID.length <= 256 ? req.sessionID : undefined;
            const foreignCleanup = req.body?.foreignCleanup;
            if (foreignCleanup && !sessionId) {
                return res.status(400).json({ error: { code: 'REBUILD_INVALID_REQUEST', outcome: 'refused' } });
            }
            const options = req.session?.authenticated === true && validActor(actor) ? { actor } : undefined;
            // A cleanup challenge is available only to an actual panel session.
            if (options && sessionId) Object.defineProperty(options, 'cleanupSessionId', { value: sessionId });
            if (foreignCleanup) options.foreignCleanup = { token: foreignCleanup.token, fixXrayUnitMode: foreignCleanup.fixXrayUnitMode };
            const result = await service().installRelay(req.params.id, options);
            if (result?.status !== 'installed' || (result.nodeId !== undefined && result.nodeId !== req.params.id)) {
                return res.status(503).json({ error: { outcome: 'unknown', retryAllowed: false } });
            }
            acknowledge('installed');
            return res.json({ executionMode: 'rebuild', status: 'installed', nodeId: req.params.id });
        } catch (error) {
            const failure = publicInstallFailure(error);
            const code = error?.code;
            const status = grantEffectStatus(code);
            if (status) {
                if (code === identityChanged) {
                    const refusal = failure.outcome === 'refused' && failure.retryAllowed !== false;
                    return res.status(status).json({ error: { code, outcome: refusal ? 'refused' : 'unknown',
                        ...(!refusal && { retryAllowed: false }) } });
                }
                return res.status(status).json({ error: { code, retryAllowed: false,
                    ...(error?.outcome === 'unknown' && { outcome: 'unknown' }) } });
            }
            return res.status(409).json({ error: failure });
        }
    };
}
module.exports = handler();
module.exports.handler = handler;
