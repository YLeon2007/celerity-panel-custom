'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');

const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const requireAuthMiddleware = require('../middleware/auth');
const relayL2tpModule = require('../modules/relay-l2tp');
const { TopologyOperationRepository } = require('../modules/relay-l2tp/repositories/topologyOperationRepository');
const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
const CascadeTopologyState = require('../modules/relay-l2tp/models/cascadeTopologyStateModel');
const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
const L2tpUser = require('../modules/relay-l2tp/models/l2tpUserModel');
const L2tpOperation = require('../modules/relay-l2tp/models/l2tpOperationModel');
const TopologyOperation = require('../modules/relay-l2tp/models/topologyOperationModel');
const NodeOperationLock = require('../modules/relay-l2tp/models/nodeOperationLockModel');
const {
    requirePanelCsrf,
} = require('./panel/csrf');
const logger = require('../utils/logger');
const { selectLinkApplyBaselineLinkIds } = require('./cascadeLinks');

const DEFAULT_MODELS = Object.freeze({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    CascadeTopologyState,
    RelayL2tpState,
    L2tpUser,
    L2tpOperation,
    TopologyOperation,
    NodeOperationLock,
});

const ERROR_STATUS_BY_CODE = new Map([
    ['INVALID_REQUEST', 400],
    ['INVALID_TOPOLOGY_REVISION', 400],
    ['INVALID_OPERATION_ID', 400],
    ['INVALID_LINK_ID', 400],
    ['CASCADE_LINK_NOT_FOUND', 404],
    ['CASCADE_LINK_DISABLED', 409],
    ['OPERATION_NOT_FOUND', 404],
    ['STALE_TOPOLOGY_REVISION', 409],
    ['TOPOLOGY_REPLACEMENT_RESERVED', 409],
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
    if (keys.some(key => !['expectedTopologyRevision', 'linkId', 'domainLinkId'].includes(key))
        || (Object.hasOwn(body, 'linkId') && Object.hasOwn(body, 'domainLinkId'))) {
        throw new TopologyDeployRequestError(
            'INVALID_REQUEST',
            'Only expectedTopologyRevision and one optional linkId or domainLinkId are accepted',
        );
    }
    if (Object.hasOwn(body, 'linkId') && !/^[0-9a-fA-F]{24}$/.test(body.linkId)) {
        throw new TopologyDeployRequestError('INVALID_LINK_ID', 'Link id must be a 24-character hex string');
    }
    if (Object.hasOwn(body, 'domainLinkId') && !/^[0-9a-fA-F]{24}$/.test(body.domainLinkId)) {
        throw new TopologyDeployRequestError('INVALID_LINK_ID', 'Domain link id must be a 24-character hex string');
    }
    const expectedTopologyRevision = body.expectedTopologyRevision;
    if (!Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) {
        throw new TopologyDeployRequestError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
        );
    }
    return {
        expectedTopologyRevision,
        ...(Object.hasOwn(body, 'linkId') ? { linkId: body.linkId } : {}),
        ...(Object.hasOwn(body, 'domainLinkId') ? { domainLinkId: body.domainLinkId } : {}),
    };
}

const OPERATION_ID_PATTERN = /^[0-9a-fA-F]{24}$/;

function normalizeReplacementRequest(body) {
    const keys = ['expectedTopologyRevision', 'groupId', 'pathKey',
        'oldLinkId', 'newLinkId', 'linkIds'];
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).length !== keys.length
        || !Object.keys(body).every(key => keys.includes(key))
        || !Number.isSafeInteger(body.expectedTopologyRevision)
        || body.expectedTopologyRevision < 0
        || !['groupId', 'oldLinkId', 'newLinkId'].every(key =>
            typeof body[key] === 'string' && OPERATION_ID_PATTERN.test(body[key]))
        || typeof body.pathKey !== 'string' || !body.pathKey.trim()
        || !Array.isArray(body.linkIds) || body.linkIds.length < 2
        || !body.linkIds.every(id => typeof id === 'string' && OPERATION_ID_PATTERN.test(id))
        || new Set(body.linkIds).size !== body.linkIds.length
        || !body.linkIds.includes(body.newLinkId)
        || body.oldLinkId === body.newLinkId
        || body.linkIds.includes(body.oldLinkId)) {
        throw new TopologyDeployRequestError('INVALID_REQUEST', 'Invalid explicit replacement request');
    }
    return body;
}
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
    if (['verified', 'unverified'].includes(operation.clientReadiness)) {
        body.clientReadiness = operation.clientReadiness;
    }
    if (operation.clientReadiness === 'unverified'
        && ['active_unverified', 'degraded'].includes(operation.clientProofState)) {
        body.clientProofState = operation.clientProofState;
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
        if (status >= 500) {
            // Backend errors can contain short credentials. Neither logs nor
            // HTTP responses may echo free-form text or attached diagnostics.
            routeLogger.error(`[Cascade Topology Deploy API] ${error.code}`);
            return res.status(status).json({
                error: {
                    code: error.code,
                    message: error.code === 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE'
                        ? 'Topology deployment capabilities are unavailable'
                        : 'Topology deployment failed',
                },
            });
        }
        return res.status(status).json(publicError(error));
    }
    routeLogger.error('[Cascade Topology Deploy API] INTERNAL_ERROR');
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
                const operation = await new TopologyOperationRepository({
                    model: models.TopologyOperation,
                    topologyStateModel: models.CascadeTopologyState,
                }).findPublicById(operationId);
                if (!operation) {
                    throw new TopologyDeployRequestError(
                        'OPERATION_NOT_FOUND',
                        'Topology operation not found',
                    );
                }
                res.set('Cache-Control', 'no-store');
                return res.status(200).json(publicOperationStatus({ ...operation, operationId }));
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
                const input = normalizeDeployRequest(req.body);
                let result;
                if (input.linkId || input.domainLinkId) {
                    if (typeof deploymentService.queue !== 'function') {
                        throw new TopologyDeployRequestError(
                            'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
                            'Scoped topology deployment is unavailable',
                        );
                    }
                    // The coordinator fences this revision and re-reads the
                    // pinned snapshot before applying. This read only selects
                    // candidate baseline ids; it cannot authorize a stale edge.
                    const links = await models.CascadeLink.find({})
                        .select('_id portalNode bridgeNode active status')
                        .lean();
                    const linkId = input.linkId || input.domainLinkId;
                    const selected = links.find(link => String(link._id) === linkId);
                    if (!selected) {
                        throw new TopologyDeployRequestError('CASCADE_LINK_NOT_FOUND', 'Cascade link not found');
                    }
                    if (selected.active === false) {
                        throw new TopologyDeployRequestError('CASCADE_LINK_DISABLED', 'Cascade link is disabled');
                    }
                    if (input.domainLinkId && !['deployed', 'online', 'staged'].includes(selected.status)) {
                        throw new TopologyDeployRequestError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The chosen domain link is not confirmed applied',
                        );
                    }
                    const baseline = selectLinkApplyBaselineLinkIds({
                        links,
                        linkId,
                        portalNodeId: selected.portalNode,
                        bridgeNodeId: selected.bridgeNode,
                    });
                    result = await deploymentService.queue({
                        expectedTopologyRevision: input.expectedTopologyRevision,
                        scope: {
                            kind: input.domainLinkId ? 'domain.reconcile' : 'link.apply',
                            linkId,
                            linkIds: [linkId, ...baseline],
                        },
                    });
                    if (!result || result.topologyRevision !== input.expectedTopologyRevision
                        || !['queued', 'succeeded'].includes(result.status)) {
                        throw new TopologyDeployRequestError(
                            'TOPOLOGY_OPERATION_QUEUE_FAILED',
                            'Scoped topology deployment could not be queued',
                        );
                    }
                } else {
                    result = await deploymentService.deploy(input);
                }
                const status = result?.status === 'queued' ? 202 : 200;
                return res.status(status).json({
                    ...publicResult(result),
                    ...(input.linkId ? { kind: 'link.apply' }
                        : input.domainLinkId ? { kind: 'domain.reconcile' } : {}),
                });
            } catch (error) {
                return sendError(res, error, routeLogger);
            }
        },
    );

    router.post('/replace', requireAuth, writeScope, sessionWriteCsrf,
        deployRateLimiter, async (req, res) => {
            try {
                const input = normalizeReplacementRequest(req.body);
                if (typeof deploymentService.queue !== 'function') {
                    throw new TopologyDeployRequestError(
                        'TOPOLOGY_DEPLOYMENT_UNAVAILABLE', 'Replacement queue is unavailable');
                }
                const result = await deploymentService.queue({
                    expectedTopologyRevision: input.expectedTopologyRevision,
                    scope: {
                        kind: 'link.replace', linkId: input.newLinkId,
                        linkIds: input.linkIds, oldLinkId: input.oldLinkId,
                        groupId: input.groupId, pathKey: input.pathKey,
                    },
                });
                if (!result || result.topologyRevision !== input.expectedTopologyRevision
                    || !['queued', 'succeeded'].includes(result.status)) {
                    throw new TopologyDeployRequestError(
                        'TOPOLOGY_OPERATION_QUEUE_FAILED', 'Replacement could not be queued');
                }
                return res.status(result.status === 'queued' ? 202 : 200)
                    .json({ ...publicResult(result), kind: 'link.replace' });
            } catch (error) {
                return sendError(res, error, routeLogger);
            }
        });

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
module.exports.normalizeReplacementRequest = normalizeReplacementRequest;
module.exports.publicError = publicError;
module.exports.publicOperationStatus = publicOperationStatus;
module.exports.publicResult = publicResult;
module.exports.sendError = sendError;
