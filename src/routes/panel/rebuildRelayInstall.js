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
            const code = error?.code;
            const status = grantEffectStatus(code);
            if (status) {
                const { outcome } = publicInstallFailure(error);
                return res.status(status).json({ error: { code, retryAllowed: false,
                    ...(code === identityChanged && { outcome: outcome === 'refused' ? 'refused' : 'unknown' }) } });
            }
            return res.status(409).json({ error: publicInstallFailure(error) });
        }
    };
}
module.exports = handler();
module.exports.handler = handler;
