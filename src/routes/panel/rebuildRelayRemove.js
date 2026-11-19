'use strict';

const { createRebuildService } = require('../../services/rebuildService');

module.exports = async (req, res) => {
    const { id } = req.params;
    if (typeof id !== 'string' || id.length !== 24 || !/^[a-f0-9]{24}$/.test(id) || Object.keys(req.query || {}).length
        || (req.body !== undefined && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)
            || Object.keys(req.body).some(key => key !== '_csrf')))) {
        return res.status(400).json({ error: { code: 'REBUILD_INVALID_REQUEST' } });
    }
    try { return res.json(await createRebuildService().removeRelay(id)); }
    catch (error) {
        const code = typeof error?.code === 'string' && /^REBUILD_[A-Z0-9_]+$(?!\n)/.test(error.code)
            ? error.code : 'REBUILD_L2TP_REMOVE_FAILED';
        return res.status(409).json({ error: { code } });
    }
};
