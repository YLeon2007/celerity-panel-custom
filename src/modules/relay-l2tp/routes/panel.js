'use strict';

const express = require('express');

const CONFIGURE_INPUT_FIELDS = Object.freeze([
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
    'routeGroupId',
    'psk',
    'generatePsk',
]);
const NODE_STATUS_SAFE_FIELDS = Object.freeze([
    'nodeId',
    'role',
    'desiredState',
    'status',
    'routeGroupId',
    'operationId',
    'appliedTopologyRevision',
    'lastErrorCode',
]);
const DESIRED_STATE_SAFE_FIELDS = Object.freeze([
    '_id',
    'node',
    'desiredState',
    'status',
    'routeGroup',
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
    'routingMode',
    'secretRevision',
    'createdAt',
    'updatedAt',
]);
const L2TP_USER_INPUT_FIELDS = Object.freeze(['login', 'ip', 'password', 'enabled']);
const L2TP_USER_SYNC_FAILURE_CODE = 'L2TP_USER_SYNC_FAILED';
const L2TP_USER_SAFE_FIELDS = Object.freeze([
    'id',
    'relayNode',
    'login',
    'ip',
    'enabled',
    'desiredRevision',
    'appliedRevision',
    'syncStatus',
    'syncOperationId',
    'lastSyncedAt',
    'lastErrorCode',
    'createdAt',
    'updatedAt',
]);

const ERROR_STATUS_BY_CODE = new Map([
    ['BAD_REQUEST', 400],
    ['INVALID_INPUT', 400],
    ['INVALID_REQUEST', 400],
    ['INVALID_NODE_ID', 400],
    ['INVALID_L2TP_USER', 400],
    ['INVALID_L2TP_USER_ID', 400],
    ['INVALID_L2TP_LOGIN', 400],
    ['INVALID_L2TP_IP', 400],
    ['INVALID_L2TP_PASSWORD', 400],
    ['INVALID_L2TP_ENABLED', 400],
    ['INVALID_OPERATION_ID', 400],
    ['INVALID_CLIENT_CIDR', 400],
    ['INVALID_DESIRED_STATE', 400],
    ['INVALID_LOCAL_ADDRESS', 400],
    ['INVALID_CLIENT_POOL', 400],
    ['INVALID_DNS_SERVERS', 400],
    ['INVALID_TPROXY_PORT', 400],
    ['INVALID_FWMARK', 400],
    ['INVALID_ROUTE_TABLE', 400],
    ['NODE_REQUIRED', 400],
    ['PSK_SOURCE_REQUIRED', 400],
    ['INVALID_ROUTE_GROUP_ID', 400],
    ['INVALID_TOPOLOGY_REVISION', 400],
    ['UNSUPPORTED_OS', 400],
    ['NOT_FOUND', 404],
    ['NODE_NOT_FOUND', 404],
    ['L2TP_USER_NOT_FOUND', 404],
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
    ['DESIRED_STATE_NOT_INSTALLED', 409],
    ['STALE_TOPOLOGY_REVISION', 409],
    ['RELAY_GROUP_PLAN_REQUIRED', 409],
    ['L2TP_OPERATION_ACTIVE', 409],
    ['L2TP_USER_CONFLICT', 409],
    ['L2TP_USER_STALE_REVISION', 409],
    ['L2TP_USER_REVISION_CONFLICT', 409],
    ['L2TP_NOT_CONFIGURED', 409],
    ['NODE_OPERATION_LOCK_CONFLICT', 409],
    ['CONFIG_DRIFT', 409],
    ['CONFIG_DRIFT_CONFLICT', 409],
    ['UNPROCESSABLE_ENTITY', 422],
    ['INVALID_PSK', 422],
    ['PSK_ENCRYPTION_FAILED', 422],
    ['L2TP_USER_ENCRYPTION_FAILED', 422],
    ['PREFLIGHT_FAILED', 422],
    ['PREFLIGHT_CHECK_FAILED', 422],
    ['NO_HEALTHY_PATH', 422],
    ['INSTALL_PLAN_REJECTED', 422],
    ['INVALID_INPUT', 400],
    ['RELAY_L2TP_STATE_NOT_FOUND', 404],
    ['PSK_NOT_CONFIGURED', 404],
    ['PSK_DECRYPTION_FAILED', 422],
    ['NO_INSTALLED_RELAYS', 409],
    ['POOL_EXHAUSTED', 409],
    ['ADDRESS_SPACE_EXHAUSTED', 409],
    ['UNINSTALL_FAILED', 502],
]);

const SAFE_ERROR_MESSAGE_BY_CODE = new Map([
    [
        'L2TP_USER_STALE_REVISION',
        'The L2TP user changed before this request was applied',
    ],
    [
        'L2TP_USER_REVISION_CONFLICT',
        'The L2TP user revision conflicts with the current relay revision',
    ],
]);

function pickOperationInput(body = {}) {
    return {
        clientCidr: body.clientCidr,
        dnsServers: body.dnsServers,
        routeGroupId: body.routeGroupId,
        expectedTopologyRevision: body.expectedTopologyRevision,
    };
}

function pickDefined(source, fields) {
    return fields.reduce((result, field) => {
        if (source?.[field] !== undefined) {
            result[field] = Array.isArray(source[field]) ? [...source[field]] : source[field];
        }
        return result;
    }, {});
}

function pickConfigureInput(body) {
    return pickDefined(body, CONFIGURE_INPUT_FIELDS);
}

function safeNodeStatus(status) {
    return pickDefined(status, NODE_STATUS_SAFE_FIELDS);
}

function safeDesiredState(state) {
    return pickDefined(state, DESIRED_STATE_SAFE_FIELDS);
}

function pickL2tpUserInput(body) {
    return pickDefined(body, L2TP_USER_INPUT_FIELDS);
}

function safeL2tpUser(user) {
    const safe = pickDefined(user, L2TP_USER_SAFE_FIELDS);
    if (safe.syncStatus === 'error') {
        safe.lastErrorCode = L2TP_USER_SYNC_FAILURE_CODE;
    } else if (safe.lastErrorCode !== undefined) {
        safe.lastErrorCode = '';
    }
    return safe;
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
            message: SAFE_ERROR_MESSAGE_BY_CODE.get(error.code) ?? error.message,
            // Diagnostic detail (failureCode / nodeId / routeGroupId) is safe:
            // it contains no secrets, only machine-readable failure context.
            ...(error.details && typeof error.details === 'object'
                ? { details: error.details }
                : {}),
        },
    });
}

function createL2tpRouter({
    l2tpService,
    stateManagementService,
    userManagementService,
    simpleService,
    requireAuth,
    requireOnboarding,
    csrf,
    rateLimiter,
    loadPanelOverview,
    renderPage,
}) {
    const router = express.Router();

    function requireSimpleService(res) {
        if (simpleService) return true;
        res.status(503).json({
            error: {
                code: 'L2TP_RUNTIME_UNAVAILABLE',
                message: 'The L2TP runtime is unavailable',
            },
        });
        return false;
    }

    router.get(
        '/l2tp/simple/overview',
        requireAuth,
        requireOnboarding,
        async (req, res) => {
            if (!requireSimpleService(res)) return;
            try {
                res.json(await simpleService.overview());
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.post(
        '/l2tp/simple/relays/:id/install',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            if (!requireSimpleService(res)) return;
            try {
                const result = await simpleService.installRelay(req.params.id);
                res.status(202).json(result);
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.post(
        '/l2tp/simple/relays/:id/uninstall',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            if (!requireSimpleService(res)) return;
            try {
                res.json(await simpleService.uninstallRelay(req.params.id));
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.post(
        '/l2tp/simple/accounts',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            if (!requireSimpleService(res)) return;
            try {
                const result = await simpleService.createAccount({
                    login: req.body?.login,
                    password: req.body?.password,
                });
                res.status(201).json(result);
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.post(
        '/l2tp/simple/accounts/:login/delete',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            if (!requireSimpleService(res)) return;
            try {
                res.json(await simpleService.deleteAccount(req.params.login));
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.get('/l2tp', requireAuth, requireOnboarding, async (req, res) => {
        try {
            const overview = await loadPanelOverview();
            renderPage(res, {
                ...overview,
                title: 'L2TP',
                page: 'l2tp',
                csrfToken: res.locals.csrfToken,
            });
        } catch (error) {
            res.status(500).send('Internal server error');
        }
    });

    router.get(
        '/nodes/:id/l2tp/users',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            try {
                const users = await userManagementService.listUsers(req.params.id);
                if (!Array.isArray(users)) throw new Error('invalid L2TP user list');
                res.json(users.map(safeL2tpUser));
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.post(
        '/nodes/:id/l2tp/users',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            try {
                const user = await userManagementService.createUser(
                    req.params.id,
                    pickL2tpUserInput(req.body),
                );
                res.status(201).json(safeL2tpUser(user));
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.patch(
        '/nodes/:id/l2tp/users/:userId',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            try {
                const input = pickL2tpUserInput(req.body);
                const isDisableOnly = Object.keys(input).length === 1 && input.enabled === false;
                const user = isDisableOnly
                    ? await userManagementService.disableUser(req.params.id, req.params.userId)
                    : await userManagementService.updateUser(
                        req.params.id,
                        req.params.userId,
                        input,
                    );
                res.json(safeL2tpUser(user));
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

    router.get('/nodes/:id/l2tp/status', requireAuth, requireOnboarding, async (req, res) => {
        try {
            const status = await l2tpService.getStatus(req.params.id);
            res.json(safeNodeStatus(status));
        } catch (error) {
            sendServiceError(res, error);
        }
    });

    router.post(
        '/nodes/:id/l2tp/configure',
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        async (req, res) => {
            try {
                const state = await stateManagementService.configureRelay(
                    req.params.id,
                    pickConfigureInput(req.body),
                );
                res.json(safeDesiredState(state));
            } catch (error) {
                sendServiceError(res, error);
            }
        },
    );

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
