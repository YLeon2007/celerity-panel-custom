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
const {
    computeTopologyDomains,
} = require('../modules/relay-l2tp/domain/topologyDomains');
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
    ['STALE_TOPOLOGY_REVISION', 409],
    ['INVALID_TOPOLOGY_DEPLOYMENT', 422],
    ['NODE_DEPLOY_FAILED', 502],
    ['NODE_VERIFICATION_FAILED', 502],
    ['NODE_DEPLOYER_CONTRACT_VIOLATION', 502],
    ['DEPLOYED_REVISION_UPDATE_FAILED', 500],
    ['TOPOLOGY_DEPLOYMENT_FAILED', 500],
    ['TOPOLOGY_OPERATION_QUEUE_FAILED', 500],
    ['TOPOLOGY_DEPLOYMENT_UNAVAILABLE', 503],
    ['TOPOLOGY_DOMAIN_REQUIRED', 409],
    ['TOPOLOGY_DOMAIN_NOT_FOUND', 422],
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
    'domainKey',
    'domains',
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
    const allowedKeys = new Set(['expectedTopologyRevision', 'domainKey']);
    if (!keys.includes('expectedTopologyRevision') || keys.some(key => !allowedKeys.has(key))) {
        throw new TopologyDeployRequestError(
            'INVALID_REQUEST',
            'Only expectedTopologyRevision (and optionally domainKey) is accepted',
        );
    }
    const expectedTopologyRevision = body.expectedTopologyRevision;
    if (!Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) {
        throw new TopologyDeployRequestError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
        );
    }
    let domainKey;
    if (Object.hasOwn(body, 'domainKey')) {
        if (typeof body.domainKey !== 'string' || body.domainKey.length === 0) {
            throw new TopologyDeployRequestError(
                'INVALID_REQUEST',
                'domainKey must be a non-empty string when provided',
            );
        }
        domainKey = body.domainKey;
    }
    return domainKey === undefined
        ? { expectedTopologyRevision }
        : { expectedTopologyRevision, domainKey };
}

function publicResult(result = {}) {
    const body = {};
    for (const field of ['operationId', 'topologyRevision', 'deployedRevision', 'status']) {
        if (result[field] !== undefined) body[field] = result[field];
    }
    if (result.domain !== undefined && result.domain !== null) {
        body.domain = {
            key: result.domain.key,
            label: result.domain.label,
        };
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

function createCascadeTopologyDeployRouter({
    topologyDeploymentService,
    createService = relayL2tpModule.createTopologyDeploymentService,
    models = DEFAULT_MODELS,
    requireAuth = requireAuthMiddleware,
    requireScope = requireAuthMiddleware.requireScope,
    csrf = requirePanelCsrf,
    deployRateLimiter = defaultDeployRateLimiter,
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
    if (typeof csrf !== 'function' || typeof deployRateLimiter !== 'function') {
        throw new TypeError('Cascade topology deploy router requires CSRF and rate-limit protection');
    }

    const router = express.Router();
    const writeScope = requireScope('nodes:write');
    const readScope = requireScope('nodes:read');
    const sessionWriteCsrf = (req, res, next) => (
        req.apiKey ? next() : csrf(req, res, next)
    );

    router.get(
        '/domains',
        requireAuth,
        readScope,
        async (req, res) => {
            try {
                const [nodes, links, domainStates] = await Promise.all([
                    models.HyNode.find({}).select('_id name role cascadeRole').lean(),
                    models.CascadeLink.find({}).select('_id source target portalNode bridgeNode').lean(),
                    models.CascadeTopologyState.find({ _id: /^domain:/ })
                        .select('_id domainKey label revision deployedRevision updatedAt')
                        .lean(),
                ]);
                const domains = computeTopologyDomains({ nodes, links });
                const stateByKey = new Map(
                    (domainStates || []).map(doc => [doc.domainKey || String(doc._id).slice('domain:'.length), doc]),
                );
                return res.status(200).json({
                    domains: domains.map(domain => {
                        const state = stateByKey.get(domain.key);
                        return {
                            key: domain.key,
                            label: domain.label,
                            nodeIds: domain.nodeIds,
                            linkIds: domain.linkIds,
                            deployedRevision: state?.deployedRevision ?? null,
                        };
                    }),
                });
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
module.exports.publicResult = publicResult;
module.exports.sendError = sendError;
