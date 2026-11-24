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
const { logTopologyTestFailure } = require('./topologyTestDiagnostics');
const { isCompletedClassicDeploymentResult, isClassicProductionDeploymentConfigured } = require('../services/classicScopedCascadeDeploymentService');
const { selectLinkApplyBaselineLinkIds, acceptedIntentResponse, readPersistedIntent } = require('./cascadeLinks');
const { linkDesiredVersion } = require('../modules/relay-l2tp/services/topologyIntentService');
const { nodeActivation: normalizeNodeActivation, selectedDesiredVersion } = require('../modules/relay-l2tp/services/topologyNodeActivation');
const { l2tpActiveHostProvider } = require('../modules/l2tpActiveHostProvider');
const { isRebuildEnabled, rejectRebuildRoute } = require('../services/rebuildMode');
const { CLASSIC_KCP_REBUILD_ONLY, CLASSIC_KCP_MESSAGE, assertClassicTunnelTransport } = require('../utils/cascadeTransport');

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
    ['APPLIED_BASELINE_REQUIRED', 409],
    ['TOPOLOGY_CANCELLED_BASELINE_UNPROVEN', 409],
    ['STALE_TOPOLOGY_REVISION', 409],
    ['TOPOLOGY_REPLACEMENT_RESERVED', 409],
    ['TOPOLOGY_DEPLOY_BUSY', 409],
    ['INVALID_TOPOLOGY_DEPLOYMENT', 422],
    ['NODE_DEPLOY_FAILED', 502],
    ['NODE_VERIFICATION_FAILED', 502],
    ['NODE_DEPLOYER_CONTRACT_VIOLATION', 502],
    ['DEPLOYED_REVISION_UPDATE_FAILED', 500],
    ['TOPOLOGY_DEPLOYMENT_FAILED', 500],
    ['TOPOLOGY_OPERATION_QUEUE_FAILED', 500],
    ['TOPOLOGY_DEPLOYMENT_UNAVAILABLE', 503],
    ['CLASSIC_DEPLOY_UNSUPPORTED', 409],
    ['CLASSIC_DEPLOY_BUSY', 409],
    ['CLASSIC_DEPLOY_NODE_BUSY', 409],
    ['CLASSIC_DEPLOY_PREFLIGHT_FAILED', 409],
    ['CLASSIC_DEPLOY_SCOPE_CHANGED', 409],
    ['CLASSIC_DEPLOY_IN_USE', 409],
    ['CLASSIC_DEPLOY_OWNER_VETO', 409],
    ['CLASSIC_DEPLOY_PORT_CONFLICT', 409],
    ['CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED', 409],
    ['CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE', 503],
    ['CLASSIC_DEPLOY_UNCERTAIN', 503],
    ['CLASSIC_DEPLOY_FENCE_LOST', 503],
    ['CASCADE_LINK_DELETING', 409],
    ['INVALID_IDEMPOTENCY_KEY', 400],
    ['INVALID_TOPOLOGY_INTENT', 400],
    ['TOPOLOGY_INTENT_KEY_CONFLICT', 409],
    ['TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT', 409],
    ['TOPOLOGY_INTENT_BACKLOG_FULL', 503],
    ['TOPOLOGY_INTENT_STATE_MISSING', 503],
    ['TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE', 503],
    ['TOPOLOGY_INTENT_RESOURCES_INVALID', 503],
    ['TOPOLOGY_INTENT_DRAFT_TRANSACTION_UNAVAILABLE', 503],
    ['TOPOLOGY_INTENT_DRAFT_CONNECTION_MISMATCH', 503],
    ['TOPOLOGY_INTENT_DRAFT_BINDING_INVALID', 503],
    ['TOPOLOGY_INTENT_DELETE_BINDING_INVALID', 503],
    ['TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH', 409],
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
    if (keys.some(key => !['expectedTopologyRevision', 'linkId', 'domainLinkId', 'desiredVersion', 'nodeActivation'].includes(key))
        || (Object.hasOwn(body, 'linkId') && Object.hasOwn(body, 'domainLinkId'))) {
        throw new TopologyDeployRequestError(
            'INVALID_REQUEST',
            'Only expectedTopologyRevision and one optional linkId or domainLinkId are accepted',
        );
    }
    if (Object.hasOwn(body, 'linkId') && (typeof body.linkId !== 'string' || !/^[0-9a-f]{24}$/.test(body.linkId))) {
        throw new TopologyDeployRequestError('INVALID_LINK_ID', 'Link id must be a 24-character hex string');
    }
    if (Object.hasOwn(body, 'domainLinkId') && (typeof body.domainLinkId !== 'string' || !/^[0-9a-f]{24}$/.test(body.domainLinkId))) {
        throw new TopologyDeployRequestError('INVALID_LINK_ID', 'Domain link id must be a 24-character hex string');
    }
    if (Object.hasOwn(body, 'desiredVersion') && (!body.linkId
        || typeof body.desiredVersion !== 'string' || !/^[a-f0-9]{64}$/.test(body.desiredVersion))) {
        throw new TopologyDeployRequestError('INVALID_REQUEST', 'Invalid desired link version');
    }
    const expectedTopologyRevision = body.expectedTopologyRevision;
    if (body.nodeActivation !== undefined && (!body.linkId || body.domainLinkId)) {
        throw new TopologyDeployRequestError('INVALID_REQUEST', 'Node activation requires an explicit applied anchor');
    }
    if (!Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) {
        throw new TopologyDeployRequestError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
        );
    }
    return {
        expectedTopologyRevision,
        ...(body.nodeActivation !== undefined ? { nodeActivation: normalizeNodeActivation(body.nodeActivation) } : {}),
        ...(Object.hasOwn(body, 'linkId') ? { linkId: body.linkId } : {}),
        ...(Object.hasOwn(body, 'domainLinkId') ? { domainLinkId: body.domainLinkId } : {}),
        ...(Object.hasOwn(body, 'desiredVersion') ? { desiredVersion: body.desiredVersion } : {}),
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
// Status lifecycle mirrors TopologyOperation. Only bounded public identity and
// phase/reason enums leave this boundary, never candidate/config diagnostics.
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
    if (['link.apply', 'link.delete', 'domain.reconcile', 'link.replace', 'link.attach'].includes(operation.kind)) body.kind = operation.kind;
    if (typeof operation.linkId === 'string' && /^[a-f0-9]{24}$/.test(operation.linkId)) body.linkId = operation.linkId;
    const phase = { queued: 'waiting', preparing: 'preparing', committing: 'applying',
        rolling_back: 'rolling_back', succeeded: 'completed', failed: 'failed', rolled_back: 'rolled_back' }[operation.status];
    if (phase) body.phase = phase;
    if (['TOPOLOGY_INTENT_RESOURCE_BUSY', 'TOPOLOGY_DEPLOY_BUSY', 'TOPOLOGY_RECONCILE_REQUIRED'].includes(operation.waitingReason)) body.waitingReason = operation.waitingReason;
    if (typeof operation.failedNodeId === 'string' && /^[a-f0-9]{24}$/.test(operation.failedNodeId)) body.nodeId = operation.failedNodeId;
    if (operation.status === 'queued') body.nextAction = 'poll_operation';
    else if (['failed', 'rolling_back'].includes(operation.status)) body.nextAction = 'inspect_operation';
    if (operation.pppWaiting === true) {
        body.phase = 'waiting'; body.waitingReason = 'PPP_SYNC_PENDING'; body.nextAction = 'poll_operation';
    }
    if (operation.heldTopologyAdmission === true && ['failed', 'rolled_back', 'succeeded'].includes(operation.status)) {
        body.phase = 'reconcile_required'; body.waitingReason = 'TOPOLOGY_RECONCILE_REQUIRED'; body.nextAction = 'inspect_operation';
        body.clientReadiness = 'unverified';
    }
    return body;
}

function publicResult(result = {}) {
    const body = {};
    for (const field of ['operationId', 'topologyRevision', 'deployedRevision', 'status']) {
        if (result[field] !== undefined) body[field] = result[field];
    }
    if (isCompletedClassicDeploymentResult(result, result.topologyRevision)) body.executionMode = 'classic';
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
    if (error.code === 'CLASSIC_DEPLOY_NODE_BUSY') {
        return { error: { code: error.code, message: 'A node used by this link is busy; retry after its operation finishes' } };
    }
    if (error.code === 'CLASSIC_DEPLOY_PREFLIGHT_FAILED') {
        return { error: { code: error.code, message: 'The node preflight failed before remote changes; retry remains available' } };
    }
    if (error.code === 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED') {
        return { error: { code: error.code, message: 'Configuration was applied and verified, but the tunnel has no confirmed connection. Check connectivity between nodes. Retry and checked deletion remain available.' } };
    }
    if (error.code === 'CLASSIC_DEPLOY_PORT_CONFLICT') {
        return { error: { code: error.code, message: 'The tunnel port is already in use on the source node; edit the port and retry' } };
    }
    if (typeof error.code === 'string' && error.code.startsWith('CLASSIC_DEPLOY_')) {
        return { error: { code: error.code, message: 'Classic deployment is blocked; reload the topology or recover retained ownership' } };
    }
    const body = {
        error: {
            code: error.code,
            message: error.message,
        },
    };
    for (const field of PUBLIC_ERROR_FIELDS) {
        if (error[field] !== undefined) body[field] = error[field];
    }
    if (error.code === 'TOPOLOGY_DEPLOY_BUSY') {
        body.error.message = 'Another topology deployment owns the slot; retry after it finishes';
        body.error.retryable = true;
    }
    return body;
}

function sendError(res, error, routeLogger = logger, context = {}) {
    if (error?.code === CLASSIC_KCP_REBUILD_ONLY) {
        return res.status(409).json({ error: { code: CLASSIC_KCP_REBUILD_ONLY,
            message: res.locals.t?.('network.classicKcpRebuildOnly') ?? CLASSIC_KCP_MESSAGE } });
    }
    if (context.action) logTopologyTestFailure({ ...context, error });
    const status = ERROR_STATUS_BY_CODE.get(error?.code);
    if (context.nativeIntent) {
        const code = status ? error.code : 'INTERNAL_ERROR';
        if (!status || status >= 500) routeLogger.error(`[Cascade Topology Deploy API] ${code}`);
        return res.status(status || 500).json({ error: { code,
            message: code === 'TOPOLOGY_INTENT_BACKLOG_FULL' ? 'The deployment queue is full; retry later'
                : code === 'TOPOLOGY_INTENT_KEY_CONFLICT' ? 'The request key belongs to different content'
                    : code === 'TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT' ? 'The requested link version changed; reload the topology'
                        : status && status < 500 ? 'The deployment request was refused' : 'Durable deployment acceptance is unavailable',
            phase: 'intent.accept',
            ...(typeof context.linkId === 'string' && /^[a-f0-9]{24}$/.test(context.linkId) ? { linkId: context.linkId } : {}),
            nextAction: code === 'TOPOLOGY_INTENT_BACKLOG_FULL' ? 'retry_later' : 'refresh_topology',
        } });
    }
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
    topologyIntentService,
    readPublicOperation,
    deploymentEnv = process.env,
    createService = relayL2tpModule.createTopologyDeploymentService,
    models = DEFAULT_MODELS,
    requireAuth = requireAuthMiddleware,
    requireScope = requireAuthMiddleware.requireScope,
    csrf = requirePanelCsrf,
    deployRateLimiter = defaultDeployRateLimiter,
    operationStatusRateLimiter = defaultOperationStatusRateLimiter,
    routeLogger = logger,
} = {}) {
    const router = express.Router();
    if (isRebuildEnabled(deploymentEnv)) {
        // Do not construct a strict coordinator or fall through to classic.
        // Keep the graph and its layout endpoint on the separate cascade router.
        router.all(['/activation-policy', '/operations/:operationId', '/deploy', '/replace'], rejectRebuildRoute);
        return router;
    }
    if (typeof createService !== 'function') {
        throw new TypeError('Cascade topology deploy router requires a deployment service factory');
    }
    deploymentEnv = Object.freeze({ ...deploymentEnv });
    const deploymentService = topologyDeploymentService ?? createService({ ...models, env: deploymentEnv });
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

    const readScope = requireScope('nodes:read');
    const writeScope = requireScope('nodes:write');
    const sessionWriteCsrf = (req, res, next) => (
        req.apiKey ? next() : csrf(req, res, next)
    );

    // Restriction only: absence of a ban is not enrollment or execution proof.
    // Ordinary classic Deploy and operations in an active native epoch are not gated.
    router.get('/activation-policy', requireAuth, readScope, operationStatusRateLimiter, async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const executionContext = require('../modules/relay-l2tp/domain/topologyExecutionContext')
                .TOPOLOGY_EXECUTION_CONTEXTS.find(context => context.hostIdentity === deploymentEnv.PANEL_DOMAIN);
            const policy = executionContext ? await require('../modules/relay-l2tp/services/topologyReentryPolicy')
                .readBusinessReentryRestriction({ executionContext, ...models }) : { blocked: false };
            return res.json(policy);
        } catch {
            return res.status(503).json({ code: 'TOPOLOGY_REENTRY_POLICY_UNAVAILABLE',
                message: 'Проверка истории повторного включения недоступна.' });
        }
    });

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
                const reader = readPublicOperation ?? l2tpActiveHostProvider.getActiveHost()?.readPublicOperation;
                let operation = reader ? await reader(operationId) : await new TopologyOperationRepository({
                    model: models.TopologyOperation,
                    topologyStateModel: models.CascadeTopologyState,
                }).findPublicById(operationId);
                if (operation && !reader) {
                    const metadata = await models.TopologyOperation.findById(operationId)
                        .select('admissionScope kind linkId waitingReason failedNodeId heldTopologyAdmission pppWait.relayNode').lean();
                    operation = { ...operation, kind: metadata?.kind, linkId: metadata?.linkId == null ? undefined : String(metadata.linkId),
                        waitingReason: metadata?.waitingReason, failedNodeId: metadata?.failedNodeId == null ? undefined : String(metadata.failedNodeId),
                        heldTopologyAdmission: metadata?.heldTopologyAdmission, pppWaiting: !!metadata?.pppWait,
                        ...(metadata?.admissionScope === 'selected' ? { clientReadiness: 'unverified' } : {}) };
                }
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
                if (input.nodeActivation && (isClassicProductionDeploymentConfigured(deploymentEnv)
                    || deploymentService.requiresL2tpIngressPreparation === false)) {
                    throw new TopologyDeployRequestError('TOPOLOGY_DEPLOYMENT_UNAVAILABLE', 'Node activation requires native selected runtime');
                }
                if (input.linkId && !isClassicProductionDeploymentConfigured(deploymentEnv)
                    && deploymentService.requiresL2tpIngressPreparation !== false) {
                    const service = topologyIntentService === undefined
                        ? l2tpActiveHostProvider.getActiveHost()?.selectedTopologyIntentService : topologyIntentService;
                    if (typeof service?.accept !== 'function') {
                        throw new TopologyDeployRequestError('TOPOLOGY_DEPLOYMENT_UNAVAILABLE', 'Durable selected mutation runtime is unavailable');
                    }
                    const requestKey = req.get('Idempotency-Key');
                    if (typeof requestKey !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(requestKey)) throw new TopologyDeployRequestError('INVALID_IDEMPOTENCY_KEY', 'A valid Idempotency-Key is required');
                    const selected = await models.CascadeLink.findById(input.linkId).lean();
                    assertClassicTunnelTransport(selected);
                    const existing = !selected || selected.lifecycle || selected.active === false
                        ? await readPersistedIntent(service, models.CascadeLink, requestKey) : null;
                    if (existing && (existing.version !== 2 || existing.kind !== 'link.apply' || String(existing.linkId) !== input.linkId)) throw new TopologyDeployRequestError('TOPOLOGY_INTENT_KEY_CONFLICT', 'The request key belongs to different content');
                    if (!selected && !existing) throw new TopologyDeployRequestError('CASCADE_LINK_NOT_FOUND', 'Cascade link not found');
                    if (selected?.lifecycle?.state === 'deleting' && !existing) throw new TopologyDeployRequestError('CASCADE_LINK_DELETING', 'Cascade link is being deleted');
                    if (selected?.active === false && !existing) throw new TopologyDeployRequestError('CASCADE_LINK_DISABLED', 'Cascade link is disabled');
                    const job = await service.accept({ version: 2, kind: 'link.apply',
                        expectedTopologyRevision: input.expectedTopologyRevision,
                        requestKey, linkId: input.linkId,
                        ...(input.nodeActivation ? { nodeActivation: input.nodeActivation } : {}),
                        desiredVersion: input.desiredVersion ?? (selected ? await selectedDesiredVersion(models, selected, input.nodeActivation) : existing.desiredVersion) });
                    return res.status(202).json(acceptedIntentResponse(job));
                }
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
                        .select('_id portalNode bridgeNode active status tunnelTransport')
                        .lean();
                    const linkId = input.linkId || input.domainLinkId;
                    const selected = links.find(link => String(link._id) === linkId);
                    if (!selected) {
                        throw new TopologyDeployRequestError('CASCADE_LINK_NOT_FOUND', 'Cascade link not found');
                    }
                    assertClassicTunnelTransport(selected);
                    if (selected.active === false) {
                        throw new TopologyDeployRequestError('CASCADE_LINK_DISABLED', 'Cascade link is disabled');
                    }
                    if (input.domainLinkId && !['deployed', 'online', 'staged'].includes(selected.status)) {
                        throw new TopologyDeployRequestError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The chosen domain link is not confirmed applied',
                        );
                    }
                    const selectBaseline = typeof deploymentService.selectBaselineLinkIds === 'function'
                        ? deploymentService.selectBaselineLinkIds : selectLinkApplyBaselineLinkIds;
                    const baseline = selectBaseline({
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
                        || (result.executionMode === 'classic'
                            && !isCompletedClassicDeploymentResult(result, input.expectedTopologyRevision))
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
                return sendError(res, error, routeLogger, {
                    action: 'topology.sync', phase: 'deploy.queue',
                    nativeIntent: !!req.body?.linkId && !isClassicProductionDeploymentConfigured(deploymentEnv),
                    revision: req.body?.expectedTopologyRevision,
                    linkId: req.body?.linkId || req.body?.domainLinkId });
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
                return sendError(res, error, routeLogger, {
                    action: 'topology.replace', phase: 'deploy.queue',
                    revision: req.body?.expectedTopologyRevision,
                    linkId: req.body?.newLinkId });
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
