'use strict';

const { publicInstallFailure } = require('../../services/rebuildRelayInstallDiagnostics');
const { identityChanged, grantEffectStatus } = require('./rebuildRelayAdmission');

function handler(service = () => require('../../services/rebuildService').createRebuildService()) {
    return async (req, res) => {
        if (!/^[a-f0-9]{24}(?![\s\S])/.test(req.params.id) || Object.keys(req.query || {}).length ||
            (req.body !== undefined && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
            Object.keys(req.body).some(k => k !== '_csrf')))) {
            return res.status(400).json({ error: { code: 'REBUILD_INVALID_REQUEST', outcome: 'refused' } });
        }
        try {
            const result = await service().installRelay(req.params.id);
            if (result?.status !== 'installed' || (result.nodeId !== undefined && result.nodeId !== req.params.id)) {
                return res.status(503).json({ error: { outcome: 'unknown', retryAllowed: false } });
            }
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
