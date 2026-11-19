'use strict';
const {createRebuildService} = require('../../services/rebuildService');
function handler(service = () => createRebuildService()) {
    return async (req, res) => {
        if (!/^[a-f0-9]{24}$/.test(req.params.id) || Object.keys(req.query || {}).length ||
            (req.body !== undefined && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
            Object.keys(req.body).some(k => k !== '_csrf')))) return res.status(400).json({error:{code:'REBUILD_INVALID_REQUEST'}});
        try { return res.json(await service().installRelay(req.params.id)); }
        catch (error) { return res.status(409).json({error:{code:/^REBUILD_[A-Z_]+$/.test(error.code)?error.code:'REBUILD_L2TP_INSTALL_FAILED'}}); }
    };
}
module.exports=handler();
module.exports.handler=handler;
