'use strict';
// Explicit TEST activation. Acknowledgement does not claim enrollment/readiness.
const express = require('express');
function createTopologyTestActivationRouter({ env = process.env,
    activeHostProvider = require('../modules/l2tpActiveHostProvider').l2tpActiveHostProvider,
    auth = require('../middleware/auth'), csrf = require('./panel/csrf').requirePanelCsrf } = {}) {
    const router = express.Router(); const selected = Object.freeze({ ...env });
    if (selected.PANEL_DOMAIN !== 'test.infograd.online' || selected.TOPOLOGY_TEST_STARTUP_MODE !== 'dedicated-runtime-v1') return router;
    require('../../scripts/test-topology-owner').assertTestContext(selected);
    const host = () => activeHostProvider.getActiveHost();
    router.get('/status', auth, auth.requireScope('nodes:read'), async (req, res) => {
        try { return res.json(await host().readTestActivationStatus()); }
        catch { return res.status(503).json({ status: 'unavailable', code: 'TEST_RUNTIME_UNAVAILABLE' }); }
    });
    router.post(['/resume-bootstrap', '/cancel-bootstrap', '/resume-settled-bootstrap', '/resume-settled-runtime', '/resume-bindings', '/resume-verification', '/resume-preparation', '/resume-closed-settlement', '/resume-prepared-commit', '/settle-undispatched-preparation'], auth, auth.requireScope('nodes:write'), csrf, (req, res) => {
        if (!req.body || Array.isArray(req.body) || Object.keys(req.body).join(',') !== 'operationId'
            || typeof req.body.operationId !== 'string' || !/^[a-f0-9]{24}$/.test(req.body.operationId)) {
            return res.status(400).json({ code: 'INVALID_REQUEST' });
        }
        try { return res.status(202).json({ ...host().beginBootstrapContinuation(req.body.operationId, req.path === '/settle-undispatched-preparation' ? 'undispatched-failure' : req.path === '/resume-prepared-commit' ? 'prepared' : req.path === '/resume-closed-settlement' ? 'closed' : req.path === '/resume-preparation' ? 'preparation' : req.path === '/resume-settled-runtime' ? 'runtime' : req.path === '/resume-verification' ? 'verification' : req.path === '/resume-bindings' ? 'bindings' : req.path === '/resume-settled-bootstrap' ? 'settled' : req.path === '/cancel-bootstrap'),
            statusUrl: '/api/cascade/topology-test/status' }); }
        catch { return res.status(409).json({ status: 'retained', code: 'TEST_BOOTSTRAP_CONTINUATION_UNPROVEN' }); }
    });
    router.post('/handback', auth, auth.requireScope('nodes:write'), csrf, (req, res) => {
        if (!req.body || Array.isArray(req.body) || Object.keys(req.body).length) return res.status(400).json({ code: 'INVALID_REQUEST' });
        try { return res.status(202).json({ ...host().beginTestHandback(), statusUrl: '/api/cascade/topology-test/status' }); }
        catch { return res.status(409).json({ code: 'TEST_OWNER_HANDBACK_UNPROVEN' }); }
    });
    for (const action of ['activate', 'resume']) router.post('/' + action, auth, auth.requireScope('nodes:write'), csrf, async (req, res) => {
        if (!req.body || Object.keys(req.body).length !== 0 || Array.isArray(req.body)) return res.status(400).json({ code: 'INVALID_REQUEST', error: 'Используется только установленный TEST inventory.' });
        try {
            const h = host();
            if (typeof h?.beginTestActivation !== 'function') throw Error('TEST_RUNTIME_UNAVAILABLE');
            const policy = await h.readBusinessReentryRestriction();
            if (policy.blocked) return res.status(409).json({ status: 'blocked', code: policy.code,
                message: require('../modules/relay-l2tp/services/topologyReentryPolicy').MESSAGE });
            const status = h.beginTestActivation({ resumeOnly: action === 'resume' });
            return res.status(status.status === 'active' ? 200 : status.status === 'retained' ? 409 : 202)
                .json({ ...status, target: 'test', statusUrl: '/api/cascade/topology-test/status' });
        } catch { return res.status(409).json({ status: 'retained', code: 'TOPOLOGY_TEST_ACTIVATION_RETAINED' }); }
    });
    return router;
}
module.exports = { createTopologyTestActivationRouter };
