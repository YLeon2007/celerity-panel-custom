'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');

const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const requireAuthMiddleware = require('../middleware/auth');
const relayL2tpModule = require('../modules/relay-l2tp');
const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
const CascadeTopologyState = require('../modules/relay-l2tp/models/cascadeTopologyStateModel');
const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
const TopologyOperation = require('../modules/relay-l2tp/models/topologyOperationModel');
const NodeOperationLock = require('../modules/relay-l2tp/models/nodeOperationLockModel');
const {
    requirePanelCsrf,
} = require('./panel/csrf');
const logger = require('../utils/logger');

const DEFAULT_MODELS = Object.freeze({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    CascadeTopologyState,
    RelayL2tpState,
    TopologyOperation,
    NodeOperationLock,
});

const ERROR_STATUS_BY_CODE = new Map([
    ['INVALID_REQUEST', 400],
    ['INVALID_TOPOLOGY_REVISION', 400],
    ['INVALID_OPERATION_ID', 400],
    ['OPERATION_NOT_FOUND', 404],
    ['STALE_TOPOLOGY_REVISION', 409],
    ['INVALID_TOPOLOGY_DEPLOYMENT', 422],
    ['NODE_DEPLOY_FAILED', 502],
    ['NODE_VERIFICATION_FAILED', 502],
    ['NODE_DEPLOYER_CONTRACT_VIOLATION', 502],
    ['DEPLOYED_REVISION_UPDATE_FAILED', 500],
    ['TOPOLOGY_DEPLOYMENT_FAILED', 500],
    ['TOPOLOGY_OPERATION_QUEUE_FAILED', 500],
    ['TOPOLOGY_DEPLOYMENT_UNAVAILABLE', 503],
]);
const PUBLIC_ERROR_FIELDS = Object.freeze([
    'operationId',
    'expectedTopologyRevision',
    'topologyRevision',
    'failedNodeId',
    'changedNodeIds',
    'rolledBackNodeIds',
    'rollbackFailedNodeIds',
    'errors',
]);

class TopologyDeployRequestError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'TopologyDeployRequestError';
        this.code = code;
    }
}

function normalizeDeployRequest(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        throw new TopologyDeployRequestError('INVALID_REQUEST', 'Request body must be an object');
    }
    if (!Object.hasOwn(body, 'expectedTopologyRevision')) {
        throw new TopologyDeployRequestError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
        );
    }
    const keys = Object.keys(body);
    if (keys.length !== 1 || keys[0] !== 'expectedTopologyRevision') {
        throw new TopologyDeployRequestError(
            'INVALID_REQUEST',
            'Only expectedTopologyRevision is accepted',
        );
    }
    const expectedTopologyRevision = body.expectedTopologyRevision;
    if (!Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) {
        throw new TopologyDeployRequestError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
        );
    }
    return { expectedTopologyRevision };
}

const OPERATION_ID_PATTERN = /^[0-9a-fA-F]{24}$/;
// Status lifecycle mirrors TopologyOperation. No kind/causeCode/reason or any
// freeform field ever leaves this boundary.
const OPERATION_STATUS_VALUES = new Set([
    'queued',
    'preparing',
    'committing',
    'rolling_back',
    'succeeded',
    'failed',
    'rolled_back',
]);

// UI polls scoped operations (link.apply/domain.reconcile) by operationId
// because they intentionally do not advance the global deployedRevision.
// Strict projection: never leaks plan/candidate/reality/user/credentials.
function publicOperationStatus(operation = {}) {
    const body = {};
    const operationId = operation.operationId ?? operation._id ?? operation.id;
    if (operationId !== undefined && operationId !== null) {
        body.operationId = String(operationId);
    }
    if (OPERATION_STATUS_VALUES.has(operation.status)) body.status = operation.status;
    if (Number.isSafeInteger(operation.topologyRevision) && operation.topologyRevision >= 0) {
        body.topologyRevision = operation.topologyRevision;
    }
    return body;
}

function publicResult(result = {}) {
    const body = {};
    for (const field of ['operationId', 'topologyRevision', 'deployedRevision', 'status']) {
        if (result[field] !== undefined) body[field] = result[field];
    }
    if (Array.isArray(result.nodeEvidence)) {
        body.nodeEvidence = result.nodeEvidence.map(evidence => {
            const publicEvidence = {};
            for (const field of [
                'nodeId',
                'deploymentEvidenceId',
                'verificationEvidenceId',
            ]) {
                if (evidence?.[field] !== undefined) publicEvidence[field] = evidence[field];
            }
            return publicEvidence;
        });
    }
    return body;
}

function publicError(error) {
    const body = {
        error: {
            code: error.code,
            message: error.message,
        },
    };
    for (const field of PUBLIC_ERROR_FIELDS) {
        if (error[field] !== undefined) body[field] = error[field];
    }
    return body;
}

function sendError(res, error, routeLogger = logger) {
    const status = ERROR_STATUS_BY_CODE.get(error?.code);
    if (status) {
        // 5xx bodies are sanitized before reaching the client, so the real
        // message must always land in the log.
        if (status >= 500) {
            routeLogger.error(`[Cascade Topology Deploy API] ${error?.code}: ${error?.message || 'Unknown error'}`);
        }
        return res.status(status).json(publicError(error));
    }
    routeLogger.error(`[Cascade Topology Deploy API] ${error?.message || 'Unknown error'}`);
    return res.status(500).json({
        error: {
            code: 'INTERNAL_ERROR',
            message: 'Internal server error',
        },
    });
}

const defaultDeployRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({
        error: {
            code: 'TOPOLOGY_DEPLOY_RATE_LIMITED',
            message: 'Too many topology deployment requests',
        },
    }),
});

// UI polling is read-only and frequent, so it gets its own higher cap that
// never shares budget with the deploy mutation limiter.
const defaultOperationStatusRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({
        error: {
            code: 'TOPOLOGY_OPERATION_STATUS_RATE_LIMITED',
            message: 'Too many topology operation status requests',
        },
    }),
});

function createCascadeTopologyDeployRouter({
    topologyDeploymentService,
    createService = relayL2tpModule.createTopologyDeploymentService,
    models = DEFAULT_MODELS,
    requireAuth = requireAuthMiddleware,
    requireScope = requireAuthMiddleware.requireScope,
    csrf = requirePanelCsrf,
    deployRateLimiter = defaultDeployRateLimiter,
    operationStatusRateLimiter = defaultOperationStatusRateLimiter,
    routeLogger = logger,
} = {}) {
    if (typeof createService !== 'function') {
        throw new TypeError('Cascade topology deploy router requires a deployment service factory');
    }
    const deploymentService = topologyDeploymentService ?? createService(models);
    if (typeof deploymentService?.deploy !== 'function') {
        throw new TypeError('Cascade topology deploy router requires a deployment service');
    }
    if (typeof requireAuth !== 'function' || typeof requireScope !== 'function') {
        throw new TypeError('Cascade topology deploy router requires authentication and authorization');
    }
    if (typeof csrf !== 'function' || typeof deployRateLimiter !== 'function'
        || typeof operationStatusRateLimiter !== 'function') {
        throw new TypeError('Cascade topology deploy router requires CSRF and rate-limit protection');
    }

    const router = express.Router();
    const readScope = requireScope('nodes:read');
    const writeScope = requireScope('nodes:write');
    const sessionWriteCsrf = (req, res, next) => (
        req.apiKey ? next() : csrf(req, res, next)
    );

    // Read-only operation polling for the UI; authenticated, nodes:read
    // scoped, and rate limited — but no CSRF since it never mutates state.
    router.get(
        '/operations/:operationId',
        requireAuth,
        readScope,
        operationStatusRateLimiter,
        async (req, res) => {
            try {
                const { operationId } = req.params;
                if (!OPERATION_ID_PATTERN.test(operationId)) {
                    throw new TopologyDeployRequestError(
                        'INVALID_OPERATION_ID',
                        'Operation id must be a 24-character hex string',
                    );
                }
                const operation = await models.TopologyOperation.findById(operationId)
                    .select('_id status topologyRevision')
                    .lean();
                if (!operation) {
                    throw new TopologyDeployRequestError(
                        'OPERATION_NOT_FOUND',
                        'Topology operation not found',
                    );
                }
                res.set('Cache-Control', 'no-store');
                return res.status(200).json(publicOperationStatus(operation));
            } catch (error) {
                return sendError(res, error, routeLogger);
            }
        },
    );

    router.post(
        '/deploy',
        requireAuth,
        writeScope,
        sessionWriteCsrf,
        deployRateLimiter,
        async (req, res) => {
            try {
                const result = await deploymentService.deploy(normalizeDeployRequest(req.body));
                const status = result?.status === 'queued' ? 202 : 200;
                return res.status(status).json(publicResult(result));
            } catch (error) {
                return sendError(res, error, routeLogger);
            }
        },
    );

    return router;
}

const router = createCascadeTopologyDeployRouter();

module.exports = router;
module.exports.DEFAULT_MODELS = DEFAULT_MODELS;
module.exports.ERROR_STATUS_BY_CODE = ERROR_STATUS_BY_CODE;
module.exports.PUBLIC_ERROR_FIELDS = PUBLIC_ERROR_FIELDS;
module.exports.TopologyDeployRequestError = TopologyDeployRequestError;
module.exports.createCascadeTopologyDeployRouter = createCascadeTopologyDeployRouter;
module.exports.normalizeDeployRequest = normalizeDeployRequest;
module.exports.publicError = publicError;
module.exports.publicOperationStatus = publicOperationStatus;
module.exports.publicResult = publicResult;
module.exports.sendError = sendError;
