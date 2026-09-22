'use strict';

const express = require('express');

const ERROR_STATUS_BY_CODE = new Map([
    ['BAD_REQUEST', 400],
    ['INVALID_INPUT', 400],
    ['INVALID_REQUEST', 400],
    ['INVALID_NODE_ID', 400],
    ['INVALID_OPERATION_ID', 400],
    ['INVALID_CLIENT_CIDR', 400],
    ['INVALID_DNS_SERVERS', 400],
    ['INVALID_ROUTE_GROUP_ID', 400],
    ['INVALID_TOPOLOGY_REVISION', 400],
    ['UNSUPPORTED_OS', 400],
    ['NOT_FOUND', 404],
    ['NODE_NOT_FOUND', 404],
    ['OPERATION_NOT_FOUND', 404],
    ['ROUTE_GROUP_NOT_FOUND', 404],
    ['CONFLICT', 409],
    ['WRONG_ROLE', 409],
    ['NODE_NOT_RELAY', 409],
    ['NODE_ROLE_CONFLICT', 409],
    ['STALE_TOPOLOGY_REVISION', 409],
    ['ROUTE_GROUP_REQUIRED', 409],
    ['MISSING_ROUTE_GROUP', 409],
    ['ROUTE_GROUP_AMBIGUOUS', 409],
    ['AMBIGUOUS_ROUTE_GROUP', 409],
    ['OPERATION_IN_PROGRESS', 409],
    ['ACTIVE_OPERATION', 409],
    ['L2TP_OPERATION_ACTIVE', 409],
    ['NODE_OPERATION_LOCK_CONFLICT', 409],
    ['CONFIG_DRIFT', 409],
    ['CONFIG_DRIFT_CONFLICT', 409],
    ['UNPROCESSABLE_ENTITY', 422],
    ['PREFLIGHT_FAILED', 422],
    ['PREFLIGHT_CHECK_FAILED', 422],
    ['NO_HEALTHY_PATH', 422],
    ['INSTALL_PLAN_REJECTED', 422],
]);

function pickOperationInput(body = {}) {
    return {
        clientCidr: body.clientCidr,
        dnsServers: body.dnsServers,
        routeGroupId: body.routeGroupId,
        expectedTopologyRevision: body.expectedTopologyRevision,
    };
}

function sendServiceError(res, error) {
    const status = ERROR_STATUS_BY_CODE.get(error?.code);
    if (!status) {
        return res.status(500).json({
            error: {
                code: 'INTERNAL_ERROR',
                message: 'Internal server error',
            },
        });
    }

    return res.status(status).json({
        error: {
            code: error.code,
            message: error.message,
        },
    });
}

function createL2tpRouter({
    l2tpService,
    requireAuth,
    requireOnboarding,
    csrf,
    rateLimiter,
    loadPanelOverview,
    renderPage,
}) {
    const router = express.Router();

    router.get('/l2tp', requireAuth, requireOnboarding, async (req, res) => {
        try {
            const overview = await loadPanelOverview();
            renderPage(res, {
                title: 'L2TP',
                page: 'l2tp',
                csrfToken: res.locals.csrfToken,
                ...overview,
            });
        } catch (error) {
            res.status(500).send('Internal server error');
        }
    });

    router.get('/nodes/:id/l2tp/status', requireAuth, requireOnboarding, async (req, res) => {
        try {
            const status = await l2tpService.getStatus(req.params.id);
            res.json(status);
        } catch (error) {
            sendServiceError(res, error);
        }
    });

    router.post(
        '/nodes/:id/l2tp/preflight',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            try {
                const result = await l2tpService.preflight(
                    req.params.id,
                    pickOperationInput(req.body),
                );
                res.json(result);
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.post(
        '/nodes/:id/l2tp/install',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            try {
                const result = await l2tpService.install(
                    req.params.id,
                    pickOperationInput(req.body),
                );
                res.status(202).json(result);
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.get('/l2tp/operations/:operationId', requireAuth, requireOnboarding, async (req, res) => {
        try {
            const operation = await l2tpService.getOperation(req.params.operationId);
            res.json(operation);
        } catch (error) {
            sendServiceError(res, error);
        }
    });

    return router;
}

module.exports = { createL2tpRouter };
