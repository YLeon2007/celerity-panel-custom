'use strict';

const { publicInstallFailure } = require('../../services/rebuildRelayInstallDiagnostics');

function handler(service = () => require('../../services/rebuildService').createRebuildService()) {
    return async (req, res) => {
        if (!/^[a-f0-9]{24}(?![\s\S])/.test(req.params.id) || Object.keys(req.query || {}).length ||
            (req.body !== undefined && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
            Object.keys(req.body).some(k => k !== '_csrf')))) {
            return res.status(400).json({ error: { code: 'REBUILD_INVALID_REQUEST', outcome: 'refused' } });
        }
        try { return res.json(await service().installRelay(req.params.id)); }
        catch (error) {
            return res.status(409).json({ error: publicInstallFailure(error) });
        }
    };
}
module.exports = handler();
module.exports.handler = handler;
