'use strict';
const {createRebuildService} = require('../../services/rebuildService');
const actions = Object.freeze({
    REBUILD_L2TP_PPP_MODULES_REQUIRED: 'Have the kernel host administrator check PPP module availability, loading policy and /dev/ppp.',
    REBUILD_L2TP_PPP_MODULES_PERSISTENCE_CONFLICT: 'Have the kernel host administrator review the modules-load.d conflict or boot-loader policy.',
    REBUILD_L2TP_PPP_MODULES_LOAD_FAILED: 'Have the kernel host administrator check module loading and /dev/ppp. Reconcile the retained Install before retrying.',
    REBUILD_L2TP_NETWORK_OBSERVATION_REQUIRED: 'Have the relay administrator provide working kernel socket diagnostics, nf_tables and XFRM before retrying.',
});
function handler(service = () => createRebuildService()) {
    return async (req, res) => {
        if (!/^[a-f0-9]{24}$/.test(req.params.id) || Object.keys(req.query || {}).length ||
            (req.body !== undefined && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
            Object.keys(req.body).some(k => k !== '_csrf')))) return res.status(400).json({error:{code:'REBUILD_INVALID_REQUEST'}});
        try { return res.json(await service().installRelay(req.params.id)); }
        catch (error) {
            const code = typeof error?.code === 'string' && /^REBUILD_[A-Z0-9_]+(?![\s\S])/.test(error.code)
                ? error.code : 'REBUILD_L2TP_INSTALL_FAILED';
            return res.status(409).json({ error: { code, ...(Object.hasOwn(actions, code) && { operatorAction: actions[code] }),
                ...(Object.hasOwn(actions, code) && error?.retryAllowed === false && { retryAllowed: false }) } });
        }
    };
}
module.exports=handler();
module.exports.handler=handler;
