'use strict';

const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
const CascadeTopologyState = require('../modules/relay-l2tp/models/cascadeTopologyStateModel');
const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
const L2tpUser = require('../modules/relay-l2tp/models/l2tpUserModel');
const L2tpOperation = require('../modules/relay-l2tp/models/l2tpOperationModel');
const TopologyOperation = require('../modules/relay-l2tp/models/topologyOperationModel');
const NodeOperationLock = require('../modules/relay-l2tp/models/nodeOperationLockModel');
const NodeSSH = require('../services/nodeSSH');
const {
    createTopologyDraftWriteService,
} = require('../modules/relay-l2tp/services/topologyDraftWriteService');
const { maintainAutoL2tpPaths } = require('../modules/relay-l2tp/services/autoL2tpPathMaintenance');
const { l2tpActiveHostProvider } = require('../modules/l2tpActiveHostProvider');
const { isRebuildEnabled, rejectRebuildRoute } = require('../services/rebuildMode');
const logger = require('../utils/logger');
const { logTopologyTestFailure } = require('./topologyTestDiagnostics');
const {
    isCompletedClassicDeploymentResult,
    isClassicProductionDeploymentConfigured,
    createClassicScopedCascadeDeploymentService,
} = require('../services/classicScopedCascadeDeploymentService');
const { requireScope } = require('../middleware/auth');
const { requirePanelCsrf } = require('./panel/csrf');
const { issueClassicLifecycleGrant } = require('../services/classicLifecycleAuthorization');
const { linkDesiredVersion } = require('../modules/relay-l2tp/services/topologyIntentService');

const LINK_POPULATE_SELECT = 'name ip flag status';
const TOPOLOGY_STATE_SELECT = 'revision deployedRevision';
const REALITY_KEY_RE = /^[A-Za-z0-9_\-+/]{43,44}=?$/;
const REALITY_SHORT_ID_RE = /^[0-9a-fA-F]{0,16}$/;
const TUNNEL_PROTOCOLS = new Set(['vless', 'vmess']);
const ERROR_STATUS_BY_CODE = new Map([
    ['INVALID_TOPOLOGY_REVISION', 400],
    ['INVALID_REQUEST', 400],
    ['INVALID_LINK_ID', 400],
    ['PORTAL_NODE_NOT_FOUND', 404],
    ['BRIDGE_NODE_NOT_FOUND', 404],
    ['CASCADE_LINK_NOT_FOUND', 404],
    ['STALE_TOPOLOGY_REVISION', 409],
    ['CASCADE_LINK_CONFLICT', 409],
    ['CASCADE_LINK_IN_USE', 409],
    ['CASCADE_LINK_DELETING', 409],
    ['CASCADE_LINK_DISABLED', 409],
    ['TOPOLOGY_REPLACEMENT_RESERVED', 409],
    ['INVALID_TOPOLOGY_DRAFT', 422],
    ['TOPOLOGY_DEPLOY_BUSY', 409],
    ['TOPOLOGY_ADMISSION_UNAVAILABLE', 409],
    ['NODE_OPERATION_LOCK_CONFLICT', 409],
    ['TOPOLOGY_DEPLOYMENT_UNAVAILABLE', 503],
    ['CLASSIC_DEPLOY_UNSUPPORTED', 409],
    ['CLASSIC_DEPLOY_BUSY', 409],
    ['CLASSIC_DEPLOY_NODE_BUSY', 409],
    ['CLASSIC_DEPLOY_PREFLIGHT_FAILED', 409],
    ['TOPOLOGY_DRAFT_LOCK_SCOPE_CHANGED', 409],
    ['CLASSIC_DEPLOY_SCOPE_CHANGED', 409],
    ['CLASSIC_DEPLOY_IN_USE', 409],
    ['CLASSIC_DEPLOY_OWNER_VETO', 409],
    ['CLASSIC_DEPLOY_PORT_CONFLICT', 409],
    ['CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED', 409],
    ['CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE', 503],
    ['CLASSIC_DEPLOY_UNCERTAIN', 503],
    ['CLASSIC_DEPLOY_FENCE_LOST', 503],
    ['TOPOLOGY_INTENT_BACKLOG_FULL', 503],
    ['TOPOLOGY_INTENT_KEY_CONFLICT', 409],
    ['TOPOLOGY_INTENT_NOT_FOUND', 404],
    ['TOPOLOGY_INTENT_STATE_MISSING', 503],
    ['INVALID_IDEMPOTENCY_KEY', 400],
    ['TOPOLOGY_INTENT_PAYLOAD_TOO_LARGE', 413],
    ['INVALID_TOPOLOGY_INTENT', 400],
    ['INVALID_TOPOLOGY_INTENT_VERSION', 400],
    ['TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT', 409],
    ['TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE', 503],
    ['TOPOLOGY_INTENT_PREPARATION_UNAVAILABLE', 503],
    ['TOPOLOGY_INTENT_RESOURCES_INVALID', 503],
    ['TOPOLOGY_INTENT_DRAFT_BINDING_INVALID', 503],
    ['TOPOLOGY_INTENT_DELETE_BINDING_INVALID', 503],
    ['TOPOLOGY_INTENT_DELETE_WRITER_UNAVAILABLE', 503],
    ['TOPOLOGY_INTENT_DRAFT_TRANSACTION_UNAVAILABLE', 503],
    ['TOPOLOGY_INTENT_DRAFT_CONNECTION_MISMATCH', 503],
    ['TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH', 409],
]);

class RequestValidationError extends Error {
    constructor(message, details, code = 'INVALID_REQUEST') {
        super(message);
        this.name = 'RequestValidationError';
        this.code = code;
        this.details = details;
    }
}

function normalizeExpectedTopologyRevision(input) {
    const revision = input?.expectedTopologyRevision;
    if (!Number.isSafeInteger(revision) || revision < 0) {
        throw new RequestValidationError(
            'expectedTopologyRevision must be a non-negative safe integer',
            undefined,
            'INVALID_TOPOLOGY_REVISION',
        );
    }
    return revision;
}

function normalizeAutoDeploy(value) {
    if (value === undefined || value === null || value === false || value === 'false') return false;
    if (value === true || value === 'true') return true;
    throw new RequestValidationError('autoDeploy must be a boolean', undefined, 'INVALID_AUTO_DEPLOY');
}

// Confirmed-applied link statuses: deployed/online are fully confirmed;
// staged means a link.apply physically applied the link to its endpoints but
// the component is not client-ready yet. All three are valid auto-deploy
// baseline members; pending/error/offline never are.
const CONFIRMED_DEPLOYED_LINK_STATUSES = new Set(['deployed', 'online', 'staged']);

function scopedLinkEntityId(value) {
    const id = value !== null && typeof value === 'object'
        ? value._id ?? value.id ?? value.node
        : value;
    return id === null || id === undefined ? '' : String(id);
}

// The auto-deploy baseline is the connected component of confirmed-applied
// (deployed/online/staged), active links reachable from either endpoint of
// the newly created link. Traversal deliberately never crosses a pending, errored,
// offline, or disabled edge: an old pending link on a shared relay is not
// proof of deployment and must stay out of the scoped candidate even when it
// touches the exact node the new link attaches to.
function selectLinkApplyBaselineLinkIds({ links, linkId, portalNodeId, bridgeNodeId } = {}) {
    const requestedId = scopedLinkEntityId(linkId);
    const adjacency = new Map();
    for (const link of Array.isArray(links) ? links : []) {
        const id = scopedLinkEntityId(link?._id ?? link?.id);
        if (!id || id === requestedId) continue;
        if (link?.active === false) continue;
        if (!CONFIRMED_DEPLOYED_LINK_STATUSES.has(link?.status)) continue;
        const source = scopedLinkEntityId(link?.portalNode);
        const target = scopedLinkEntityId(link?.bridgeNode);
        if (!source || !target) continue;
        if (!adjacency.has(source)) adjacency.set(source, []);
        if (!adjacency.has(target)) adjacency.set(target, []);
        adjacency.get(source).push({ nodeId: target, linkId: id });
        adjacency.get(target).push({ nodeId: source, linkId: id });
    }
    const visitedNodes = new Set();
    const baseline = new Set();
    const queue = [scopedLinkEntityId(portalNodeId), scopedLinkEntityId(bridgeNodeId)]
        .filter(Boolean);
    while (queue.length > 0) {
        const nodeId = queue.shift();
        if (visitedNodes.has(nodeId)) continue;
        visitedNodes.add(nodeId);
        for (const edge of adjacency.get(nodeId) || []) {
            if (!baseline.has(edge.linkId)) {
                baseline.add(edge.linkId);
                queue.push(edge.nodeId);
            }
        }
    }
    return [...baseline].sort((left, right) => left.localeCompare(right, 'en'));
}

const SAFE_AUTO_DEPLOY_BLOCKED_CODES = new Set([
    'INVALID_REQUEST',
    'INVALID_TOPOLOGY_REVISION',
    'STALE_TOPOLOGY_REVISION',
    'INVALID_TOPOLOGY_DEPLOYMENT',
    'TOPOLOGY_DEPLOY_BUSY',
    'TOPOLOGY_OPERATION_QUEUE_FAILED',
    'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
    'CLASSIC_DEPLOY_UNSUPPORTED',
    'CLASSIC_DEPLOY_BUSY',
    'CLASSIC_DEPLOY_NODE_BUSY',
    'CLASSIC_DEPLOY_PREFLIGHT_FAILED',
    'CLASSIC_DEPLOY_SCOPE_CHANGED',
    'CLASSIC_DEPLOY_IN_USE',
    'CLASSIC_DEPLOY_OWNER_VETO',
    'CLASSIC_DEPLOY_PORT_CONFLICT',
    'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED',
    'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE',
    'CLASSIC_DEPLOY_UNCERTAIN',
    'CLASSIC_DEPLOY_FENCE_LOST',
]);

function autoDeployBlockedError(error) {
    const code = typeof error?.code === 'string' && SAFE_AUTO_DEPLOY_BLOCKED_CODES.has(error.code)
        ? error.code
        : 'TOPOLOGY_OPERATION_QUEUE_FAILED';
    return {
        code,
        message: code === 'CLASSIC_DEPLOY_NODE_BUSY'
            ? 'A selected node is busy; retry after its operation finishes'
            : code === 'CLASSIC_DEPLOY_PREFLIGHT_FAILED'
                ? 'Deployment preflight rejected the request before any remote write'
                : code === 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED'
            ? 'Configuration was applied and verified, but the tunnel has no confirmed connection. Check connectivity between nodes. Retry and checked deletion remain available.'
            : code === 'CLASSIC_DEPLOY_PORT_CONFLICT'
            ? 'The tunnel port is already in use on the source node; edit the port and retry'
            : code === 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE'
                ? 'Port inspection was unavailable; no deployment was started'
                : code.startsWith('CLASSIC_DEPLOY_')
            ? 'Classic deployment was not confirmed; inspect retained ownership before retrying'
            : code === 'TOPOLOGY_DEPLOY_BUSY'
                ? 'Another topology deployment owns the slot; retry after it finishes'
                : 'The auto-deploy operation could not be queued',
        ...(code === 'TOPOLOGY_DEPLOY_BUSY' ? { retryable: true } : {}),
    };
}

function normalizeStringArray(value) {
    if (Array.isArray(value)) return value.map(candidate => String(candidate).trim());
    if (value === undefined || value === null || value === '') return [];
    return [String(value).trim()];
}

function generateRealityKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const publicJwk = publicKey.export({ format: 'jwk' });
    const privateJwk = privateKey.export({ format: 'jwk' });
    if (!publicJwk?.x || !privateJwk?.d) {
        throw new Error('Failed to generate REALITY x25519 key pair');
    }
    return { privateKey: privateJwk.d, publicKey: publicJwk.x };
}

function resolveRealitySettings(input = {}, listenerNode = null, { generate = true } = {}) {
    // Inherit each empty field independently from the node accepting the
    // connection. The global fallback is only for an unset listener field.
    const nodeDest = String(listenerNode?.xray?.realityDest || '').trim();
    // Keep the legacy v2 create fingerprint stable before preparation.
    const parseSni = value => normalizeStringArray(value)
        .flatMap(entry => generate ? entry.split(',').map(name => name.trim()) : [entry])
        .filter(Boolean);
    const nodeSni = parseSni(listenerNode?.xray?.realitySni);
    let privateKey = String(input.realityPrivateKey || '').trim();
    let publicKey = String(input.realityPublicKey || '').trim();
    if (generate && (!privateKey || !publicKey)) {
        const generated = generateRealityKeyPair();
        privateKey = generated.privateKey;
        publicKey = generated.publicKey;
    }
    if ((generate || privateKey) && !REALITY_KEY_RE.test(privateKey)) {
        throw new RequestValidationError(
            'Invalid REALITY privateKey format (expected base64 x25519 key)',
        );
    }
    if ((generate || publicKey) && !REALITY_KEY_RE.test(publicKey)) {
        throw new RequestValidationError(
            'Invalid REALITY publicKey format (expected base64 x25519 key)',
        );
    }
    const inputShortIds = normalizeStringArray(input.realityShortIds);
    for (const shortId of inputShortIds) {
        if (!REALITY_SHORT_ID_RE.test(shortId)) {
            throw new RequestValidationError(
                'Invalid REALITY shortId format (expected hex string, max 16 chars)',
            );
        }
    }
    const realitySni = parseSni(input.realitySni);
    return {
        realityDest: String(input.realityDest || '').trim() || nodeDest || (generate ? 'www.google.com:443' : ''),
        realitySni: realitySni.length > 0 ? realitySni : (nodeSni.length > 0 ? nodeSni : generate ? ['www.google.com'] : []),
        realityPrivateKey: privateKey,
        realityPublicKey: publicKey,
        realityShortIds: inputShortIds.some(Boolean)
            ? inputShortIds
            : generate ? [crypto.randomBytes(8).toString('hex')] : [],
        realityFingerprint: String(input.realityFingerprint || 'random').trim() || 'random',
    };
}

// Inject into the real intent service as prepareLink. Admission invokes this
// only after persisted-key replay; HTTP does not generate credentials first.
function prepareIntentLink(link, listenerNode = null) {
    return { ...link, tunnelUuid: link.tunnelUuid || crypto.randomUUID(),
        ...(link.tunnelSecurity === 'reality' ? resolveRealitySettings(link, listenerNode) : {}) };
}

function acceptedIntentResponse(job, { autoDeploy = false } = {}) {
    if (job?.version !== 2 || !['link.create', 'link.apply', 'link.delete'].includes(job.kind)
        || typeof job.jobId !== 'string' || !/^[a-f0-9]{24}$/.test(job.jobId)
        || typeof job.linkId !== 'string' || !/^[a-f0-9]{24}$/.test(job.linkId)
        || (job.operationId !== undefined && (typeof job.operationId !== 'string' || !/^[a-f0-9]{24}$/.test(job.operationId)))
        || job.desiredSaved !== true) {
        throw Object.assign(new Error('Durable mutation acceptance was not confirmed'), {
            code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
        });
    }
    return { linkId: job.linkId, desiredSaved: true, job,
        ...(job.createdLinkId ? { createdLinkId: job.createdLinkId } : {}),
        ...(job.operationId ? { operationId: job.operationId } : {}),
        ...(autoDeploy ? { autoDeployJob: job } : {}),
        acceptedTopologyRevision: job.acceptanceRevision };
}

function requireIntentKey(req) {
    const key = req.get('Idempotency-Key');
    if (typeof key !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(key)) {
        throw new RequestValidationError('A valid Idempotency-Key is required', undefined, 'INVALID_IDEMPOTENCY_KEY');
    }
    return key;
}

async function readPersistedIntent(service, Link, requestKey) {
    if (!service.TopologyCreateIntent || service.TopologyCreateIntent.db !== Link.db) {
        throw Object.assign(new Error('Durable intent lookup is unavailable'), { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
    }
    return service.TopologyCreateIntent.findOne({ requestKey })
        .read('primary').readConcern('majority').maxTimeMS(5000).lean();
}

async function listLinks(Link, filter = {}) {
    return Link.find(filter)
        .populate('portalNode', LINK_POPULATE_SELECT)
        .populate('bridgeNode', LINK_POPULATE_SELECT)
        .sort({ createdAt: -1 })
        .lean();
}

function projectLinkLifecycle(link) {
    const { applicationState, routeState, tunnelState, clientReadiness, pppReadiness, xrayReadiness, ...publicLink } = link;
    const deleting = link.lifecycle?.state === 'deleting';
    // Lifecycle status is not a fresh client/route proof. In particular, never
    // reconstruct a complete applied path from mutable desired neighbours.
    return { ...publicLink,
        desiredVersion: linkDesiredVersion({ ...link,
            portalNode: scopedLinkEntityId(link.portalNode), bridgeNode: scopedLinkEntityId(link.bridgeNode) }),
        applicationState: deleting ? 'deleting'
            : CONFIRMED_DEPLOYED_LINK_STATUSES.has(link.status) ? 'applied'
                : ['offline', 'error'].includes(link.status) ? 'reconcile_required' : 'not_applied',
        routeState: 'unknown',
        tunnelState: link.status === 'online' ? 'connected' : link.status === 'offline' ? 'disconnected' : 'unknown',
    };
}

async function readLinkSnapshot({ Link, TopologyState, ClientProofOperation,
    revisions, filter = {}, includeClientReadiness = false, readLinkApplicationState }) {
    const linksPromise = listLinks(Link, filter);
    let topologyRevision;
    let deployedRevision;
    if (revisions) {
        topologyRevision = revisions.revision;
        deployedRevision = revisions.deployedRevision;
    } else {
        const state = await TopologyState.findById('singleton')
            .select(TOPOLOGY_STATE_SELECT)
            .lean();
        topologyRevision = state?.revision ?? 0;
        deployedRevision = state?.deployedRevision ?? 0;
    }
    let links = ((await linksPromise) || []).map(projectLinkLifecycle);
    if (includeClientReadiness && typeof readLinkApplicationState !== 'function') {
        // Never trust a link-local/legacy ready flag. Only a durable, successful
        // client probe scoped to this exact live revision pair can paint green.
        links = links.map(({ clientReadiness, ...link }) => link);
        const onlineIds = links.filter(link => link.active === true && link.status === 'online' && !link.lifecycle)
            .map(link => String(link._id));
        if (onlineIds.length > 0 && ClientProofOperation?.find) {
            try {
                const operations = await ClientProofOperation.find({
                    topologyRevision,
                    linkIds: { $in: onlineIds },
                }).select('status clientReadiness kind admissionScope topologyRevision priorDeployedRevision clientProofRevision linkIds')
                    .sort({ createdAt: -1, _id: -1 }).lean();
                const verifiedIds = new Set();
                const seenIds = new Set();
                const online = new Set(onlineIds);
                for (const operation of operations || []) {
                    const relevant = Array.isArray(operation.linkIds)
                        ? operation.linkIds.map(String).filter(linkId => online.has(linkId)
                            && !seenIds.has(linkId))
                        : [];
                    for (const linkId of relevant) seenIds.add(linkId);
                    // Selected freshness needs its settled profile/descriptor pins.
                    // A global revision pair can neither validate nor invalidate it.
                    if (operation.admissionScope === 'selected'
                        || operation.status !== 'succeeded' || operation.clientReadiness !== 'verified'
                        || operation.topologyRevision !== topologyRevision
                        || operation.clientProofRevision !== topologyRevision) continue;
                    // Scoped success deliberately leaves deployedRevision at its
                    // previous value. Legacy full sync has no kind and advances it.
                    const liveScope = operation.kind == null
                        ? deployedRevision === topologyRevision
                        : ['link.apply', 'domain.reconcile', 'link.replace', 'link.attach'].includes(operation.kind)
                            && operation.priorDeployedRevision === deployedRevision;
                    if (!liveScope) continue;
                    for (const linkId of relevant) verifiedIds.add(linkId);
                }
                links = links.map(link => verifiedIds.has(String(link._id))
                    ? { ...link, clientReadiness: {
                        status: 'ready', clientProbe: 'passed',
                        topologyRevision, priorDeployedRevision: deployedRevision,
                    } }
                    : link);
            } catch (_) {
                logger.warn('[Cascade Links API] Client proof projection unavailable');
                // The snapshot remains readable, but never becomes client-ready.
            }
        }
    }
    if (typeof readLinkApplicationState === 'function') {
        try {
            // Trusted repository seam must validate selected settled-owner/profile
            // pins. Neither request data nor a panel-wide revision can provide it.
            const states = await readLinkApplicationState({ links: links.map(link => ({
                linkId: String(link._id), desiredVersion: link.desiredVersion,
            })) });
            const byId = new Map();
            const duplicates = new Set();
            for (const state of Array.isArray(states) ? states : []) {
                if (byId.has(state?.linkId)) duplicates.add(state.linkId);
                byId.set(state?.linkId, state);
            }
            links = links.map(link => {
                const state = byId.get(String(link._id));
                if (!state || duplicates.has(String(link._id)) || state.desiredVersion !== link.desiredVersion
                    || typeof state.operationId !== 'string' || !/^[a-f0-9]{24}$/.test(state.operationId)
                    || !['not_applied', 'applying', 'applied', 'deleting', 'reconcile_required'].includes(state.applicationState)
                    || !['complete', 'no_portal_input', 'no_bridge_exit', 'policy_ambiguous'].includes(state.routeState)
                    || !['unknown', 'connected', 'disconnected'].includes(state.tunnelState)) return link;
                const projected = { ...link, applicationState: link.lifecycle?.state === 'deleting' ? 'deleting' : state.applicationState,
                    routeState: state.routeState, tunnelState: state.tunnelState, appliedOperationId: state.operationId,
                    pppReadiness: state.pppReadiness === 'verified' ? 'verified' : 'unverified',
                    xrayReadiness: state.xrayReadiness === 'verified' && state.applicationState === 'applied'
                        && state.routeState === 'complete' && state.tunnelState === 'connected' ? 'verified' : 'unverified' };
                delete projected.clientReadiness;
                if (projected.xrayReadiness === 'verified' && projected.applicationState === 'applied') {
                    projected.clientReadiness = { status: 'ready', clientProbe: 'passed', operationId: state.operationId };
                }
                return projected;
            });
        } catch (_) { logger.warn('[Cascade Links API] Selected application state unavailable'); }
    }
    return { topologyRevision, deployedRevision, links };
}

function sendError(res, error, operation, context = {}) {
    if (['Create', 'Update', 'Delete'].includes(operation)) {
        logTopologyTestFailure({ action: `link.${operation.toLowerCase()}`,
            phase: 'draft.write', revision: context.revision,
            linkId: context.linkId, error });
    }
    let code = error?.code;
    let status;
    if (error instanceof RequestValidationError || error?.name === 'ValidationError') {
        code = code || 'INVALID_REQUEST';
        status = 400;
    } else if (error?.code === 11000 || error?.code === 11001) {
        code = 'CASCADE_LINK_CONFLICT';
        status = 409;
    } else {
        status = ERROR_STATUS_BY_CODE.get(code);
    }
    if (!status) {
        logger.error(`[Cascade Links API] ${operation}: INTERNAL_ERROR`);
        return res.status(500).json({
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
    }
    if (code.startsWith('TOPOLOGY_INTENT_') || code === 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' || code === 'INVALID_IDEMPOTENCY_KEY') {
        return res.status(status).json({ ...(context.desiredSaved ? { desiredSaved: true } : {}), error: { code,
            message: code === 'INVALID_IDEMPOTENCY_KEY' ? 'A valid Idempotency-Key is required'
                : code === 'TOPOLOGY_INTENT_BACKLOG_FULL' ? 'The deployment queue is full; retry later'
                : code === 'TOPOLOGY_INTENT_KEY_CONFLICT' ? 'The request key belongs to different content'
                    : code === 'TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT' ? 'The requested link version changed; reload the topology'
                        : 'Durable deployment acceptance is unavailable',
            phase: 'intent.accept', ...(context.linkId ? { linkId: context.linkId } : {}),
            nextAction: error.code === 'TOPOLOGY_INTENT_BACKLOG_FULL' && !context.desiredSaved ? 'retry_later' : 'refresh_topology',
        } });
    }
    if (code.startsWith('CLASSIC_DEPLOY_')) {
        // Known public codes are not permission to serialize transport text or
        // arbitrary attached details (including checked-delete failures).
        return res.status(status).json({ error: { code, message: autoDeployBlockedError(error).message } });
    }
    const body = { error: { code, message: error.message } };
    if (Array.isArray(error?.errors)) body.error.details = error.errors;
    else if (error?.details !== undefined) body.error.details = error.details;
    else {
        const details = {};
        for (const key of [
            'expectedTopologyRevision',
            'topologyRevision',
            'linkId',
            'routeGroupIds',
        ]) {
            if (error?.[key] !== undefined) details[key] = error[key];
        }
        if (Object.keys(details).length > 0) body.error.details = details;
    }
    return res.status(status).json(body);
}

function createCascadeLinksRouter({
    Link = CascadeLink,
    Node = HyNode,
    RouteGroup = CascadeRouteGroup,
    TopologyState = CascadeTopologyState,
    RelayState = RelayL2tpState,
    ClientProofOperation = TopologyOperation,
    readLinkApplicationState,
    topologyDraftWriteService,
    topologyIntentService,
    createDraftWriteService = createTopologyDraftWriteService,
    maintainAutoL2tpPathsFn = maintainAutoL2tpPaths,
    prepareL2tpIngressFn = async input => {
        const service = l2tpActiveHostProvider.getActiveHost()?.runtime?.simpleService;
        if (typeof service?.prepareConfiguredRelayIngress === 'function') {
            return service.prepareConfiguredRelayIngress(input);
        }
        // Do not freeze a candidate that silently omits an existing relay's
        // ingress when the L2TP runtime has not been installed in this process.
        const states = await RelayState.find({ routeGroup: { $ne: null } }).lean();
        if ((states || []).length > 0) {
            const error = new Error('The L2TP ingress preparation runtime is unavailable');
            error.code = 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE';
            throw error;
        }
        return { revision: input.expectedTopologyRevision };
    },
    deploymentEnv = process.env,
    topologyCoordinator,
    createTopologyCoordinator = () => require('../modules/relay-l2tp')
        .createTopologyDeploymentService({
            env: deploymentEnv,
            HyNode: Node,
            CascadeLink: Link,
            CascadeRouteGroup: RouteGroup,
            CascadeTopologyState: TopologyState,
            RelayL2tpState: RelayState,
            L2tpUser,
            L2tpOperation,
            TopologyOperation,
            NodeOperationLock,
            NodeSSH,
        }),
    classicTopologyCoordinator,
    createClassicTopologyCoordinator = () => createClassicScopedCascadeDeploymentService({
        env: deploymentEnv,
        HyNode: Node,
        CascadeLink: Link,
        CascadeRouteGroup: RouteGroup,
        CascadeTopologyState: TopologyState,
        RelayL2tpState: RelayState,
        TopologyOperation,
        NodeOperationLock,
    }),
    portCheckSSH = NodeSSH,
    invalidateSubscriptions = () => require('../services/cacheService').invalidateAllSubscriptions(),
    invalidateTopology = () => require('../services/cascadeService')._invalidateTopologyCache(),
} = {}) {
    deploymentEnv = Object.freeze({ ...deploymentEnv });
    const router = express.Router();
    if (isRebuildEnabled(deploymentEnv)) {
        router.use('/auto-deploy-jobs', rejectRebuildRoute);
        router.get('/port-check', rejectRebuildRoute);
        // Transitional refusal: parent wires dedicated rebuild mutation handlers.
        router.post('/', rejectRebuildRoute);
        router.put('/:id', rejectRebuildRoute);
        router.delete('/:id', rejectRebuildRoute);
    }
    const getIntentService = (method = 'accept') => {
        const service = topologyIntentService === undefined
            ? (method === 'accept' ? l2tpActiveHostProvider.getActiveHost()?.selectedTopologyIntentService
                : l2tpActiveHostProvider.getActiveHost()?.selectedTopologyIntentService
                    ?? l2tpActiveHostProvider.getActiveHost()?.topologyIntentService) : topologyIntentService;
        if (typeof service?.[method] !== 'function') {
            throw Object.assign(new Error('The supervised auto-deploy intent runtime is unavailable'), { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
        }
        return service;
    };
    let writeService = topologyDraftWriteService;
    const getWriteService = () => {
        if (!writeService) {
            writeService = createDraftWriteService({
                HyNode: Node,
                CascadeLink: Link,
                CascadeRouteGroup: RouteGroup,
                CascadeTopologyState: TopologyState,
                RelayL2tpState: RelayState,
                deploymentEnv,
            });
        }
        return writeService;
    };
    let coordinator = topologyCoordinator;
    // Resolve lazily only for explicit deploy or checked classic deletion;
    // importing this router must never construct or start the runtime.
    const getTopologyCoordinator = () => {
        if (!coordinator) {
            if (isClassicProductionDeploymentConfigured(deploymentEnv)) {
                coordinator = classicTopologyCoordinator || createClassicTopologyCoordinator();
            } else {
                coordinator = createTopologyCoordinator();
            }
        }
        return coordinator;
    };
    // Queue the scoped link.apply for an explicit autoDeploy opt-in. Runs
    // strictly AFTER the draft write transaction and L2TP path maintenance
    // have settled, pinning the post-maintenance revision. The result is
    // truthful: an operation id with its real queued status, or a blocked
    // reason — never a readiness claim.
    const queueAutoDeploy = async ({ link, portalNodeId, bridgeNodeId, revision, links, action, linkCreated = false, creationCapability }) => {
        const linkId = String(link._id);
        try {
            const scopedCoordinator = await getTopologyCoordinator();
            const selectBaseline = typeof scopedCoordinator?.selectBaselineLinkIds === 'function'
                ? scopedCoordinator.selectBaselineLinkIds : selectLinkApplyBaselineLinkIds;
            const baselineLinkIds = selectBaseline({ links, linkId, portalNodeId, bridgeNodeId });
            if (typeof scopedCoordinator?.queue !== 'function') {
                const error = new Error('Topology deployment capabilities are unavailable');
                error.code = 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE';
                throw error;
            }
            const queueMethod = linkCreated && typeof scopedCoordinator.queueCreatedLink === 'function'
                ? scopedCoordinator.queueCreatedLink
                : scopedCoordinator.queue;
            const result = linkCreated
                ? await queueMethod({
                    expectedTopologyRevision: revision,
                    scope: {
                        kind: 'link.apply',
                        linkId,
                        linkIds: [linkId, ...baselineLinkIds],
                    },
                }, creationCapability)
                : await queueMethod({
                    expectedTopologyRevision: revision,
                    scope: {
                        kind: 'link.apply',
                        linkId,
                        linkIds: [linkId, ...baselineLinkIds],
                    },
                });
            if (isCompletedClassicDeploymentResult(result, revision)) {
                // Synchronous checked completion, not a queued native operation.
                return { autoDeployResult: { status: 'succeeded', executionMode: 'classic', topologyRevision: revision } };
            }
            if (!result || result.executionMode === 'classic' || typeof result.operationId !== 'string'
                || result.operationId.length === 0
                || result.topologyRevision !== revision
                || !['queued', 'preparing', 'committing', 'succeeded'].includes(result.status)) {
                const error = new Error('The topology operation could not be queued');
                error.code = 'TOPOLOGY_OPERATION_QUEUE_FAILED';
                throw error;
            }
            return {
                autoDeployOperation: {
                    operationId: result.operationId,
                    topologyRevision: result.topologyRevision,
                    // Preserve the actual operation lifecycle state; a queued
                    // operation is not a client-ready chain.
                    status: result.status,
                },
            };
        } catch (error) {
            logTopologyTestFailure({ action, phase: 'auto-deploy.queue',
                revision, linkId, error });
            const blocked = autoDeployBlockedError(error);
            logger.warn(
                `[Cascade Links API] Auto-deploy of link ${linkId} blocked: ${blocked.code}: ${blocked.message}`,
            );
            return {
                autoDeployStatus: 'blocked',
                autoDeployError: blocked,
            };
        }
    };
    // Only the locked repository's fresh transactional classification may
    // bypass unrelated global maintenance. Never trust a request-body flag.
    const isIndependentClassicDraft = revisions =>
        isClassicProductionDeploymentConfigured(deploymentEnv) && revisions?.standaloneClassicDraft === true;
    const invalidateCaches = async () => {
        const results = await Promise.allSettled([
            invalidateSubscriptions(),
            invalidateTopology(),
        ]);
        for (const result of results) {
            if (result.status === 'rejected') {
                logger.warn(`[Cascade Links API] Cache invalidation failed: ${result.reason?.message}`);
            }
        }
    };
    // Link create/update/delete can strand the L2TP auto route-group path
    // (deletions strip paths that used the removed link). Rebuild the path
    // from the live graph so installed L2TP relays heal on the next topology
    // sync instead of requiring a reinstall. Best-effort: never fails the
    // link mutation itself.
    const maintainL2tpPaths = async ({ required = false } = {}) => {
        try {
            return await maintainAutoL2tpPathsFn({
                HyNode: Node,
                CascadeLink: Link,
                CascadeRouteGroup: RouteGroup,
                RelayL2tpState: RelayState,
                CascadeTopologyState: TopologyState,
                logger,
            });
        } catch (error) {
            logger.warn(`[Cascade Links API] L2TP auto path maintenance failed: ${error.message}`);
            if (required) throw error;
        }
    };

    router.get('/', requireScope('nodes:read'), async (req, res) => {
        try {
            const filter = {};
            if (req.query.active !== undefined) filter.active = req.query.active === 'true';
            if (req.query.status) filter.status = req.query.status;
            if (req.query.nodeId) {
                filter.$or = [
                    { portalNode: req.query.nodeId },
                    { bridgeNode: req.query.nodeId },
                ];
            }
            return res.json(await readLinkSnapshot({
                Link, TopologyState, ClientProofOperation, filter, includeClientReadiness: true,
                readLinkApplicationState: readLinkApplicationState ?? l2tpActiveHostProvider.getActiveHost()?.readLinkApplicationState,
            }));
        } catch (error) {
            return sendError(res, error, 'List');
        }
    });

    router.get('/auto-deploy-jobs/:jobId', requireScope('nodes:read'), async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.jobId)) throw new RequestValidationError('Invalid job ID');
            const job = await getIntentService('get').get(req.params.jobId);
            if (!job) throw Object.assign(new Error('The auto-deploy job was not found'), { code: 'TOPOLOGY_INTENT_NOT_FOUND' });
            return res.json({ job, autoDeployJob: job });
        } catch (error) { return sendError(res, error, 'Get job'); }
    });

    if (deploymentEnv.PANEL_DOMAIN === 'test.infograd.online'
        && deploymentEnv.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1') {
        router.post('/auto-deploy-jobs/:jobId/settle-unadmitted-preparation', requireScope('nodes:write'), requirePanelCsrf, async (req, res) => {
            try {
                if (typeof req.params.jobId !== 'string' || !/^[a-f0-9]{24}$/.test(req.params.jobId)
                    || !req.body || Array.isArray(req.body) || Object.keys(req.body).join(',') !== 'expectedTopologyRevision') {
                    throw new RequestValidationError('Invalid unadmitted preparation readback');
                }
                const expectedTopologyRevision = normalizeExpectedTopologyRevision(req.body);
                const job = await getIntentService('settleUnadmittedPreparation').settleUnadmittedPreparation({
                    jobId: req.params.jobId, expectedTopologyRevision });
                return res.json({ job, autoDeployJob: job, remoteDispatch: false });
            } catch (error) {
                if (error?.code === 'TOPOLOGY_INTENT_RECONCILIATION_UNPROVEN') {
                    return res.status(409).json({ error: { code: error.code, message: 'Отсутствие принятого применения не подтверждено; состояние сохранено.' } });
                }
                return sendError(res, error, 'Unadmitted preparation');
            }
        });
    }

    router.get('/port-check', requireScope('nodes:read'), async (req, res) => {
        res.set('Cache-Control', 'no-store');
        const { nodeId, port: rawPort, linkId } = req.query;
        const validId = value => typeof value === 'string' && /^[a-f0-9]{24}$/.test(value);
        if (Object.keys(req.query).some(key => !['nodeId', 'port', 'linkId'].includes(key))
            || !validId(nodeId) || typeof rawPort !== 'string' || !/^[1-9]\d{0,4}$/.test(rawPort)
            || Number(rawPort) > 65535 || (linkId !== undefined && !validId(linkId))) {
            return res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'Invalid tunnel port check request' } });
        }
        const port = Number(rawPort);
        try {
            const read = { maxTimeMS: 5000, readPreference: 'primary', readConcern: { level: 'majority' } };
            const node = await Node.findById(nodeId).setOptions(read).lean();
            if (!node) return res.status(404).json({ error: { code: 'NODE_NOT_FOUND', message: 'Node was not found' } });
            let target = null;
            if (linkId !== undefined) {
                const link = await Link.findById(linkId).populate('portalNode bridgeNode').setOptions(read).lean();
                if (!link) return res.status(404).json({ error: { code: 'CASCADE_LINK_NOT_FOUND', message: 'Link was not found' } });
                if (!['reverse', 'forward'].includes(link.mode ?? 'reverse')) throw Error('Unsupported listener mode');
                const listener = (link.mode ?? 'reverse') === 'reverse' ? link.portalNode : link.bridgeNode;
                if (link.active === true && scopedLinkEntityId(listener) === nodeId && link.tunnelPort === port) target = link;
            }
            const { preflightTunnelPort } = require('../services/classicScopedPortPreflight');
            await preflightTunnelPort({ node, port, target }, { NodeSSH: portCheckSSH });
            return res.json({ available: true, port, code: null });
        } catch (error) {
            if (error?.code === 'TUNNEL_PORT_IN_USE') return res.json({ available: false, port, code: 'TUNNEL_PORT_IN_USE' });
            // Unknown is not free, and transport/config text is never public.
            return res.status(503).json({ error: { code: 'TUNNEL_PORT_CHECK_UNAVAILABLE', message: 'Tunnel port inspection could not be completed' } });
        }
    });

    router.get('/:id', requireScope('nodes:read'), async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                throw new RequestValidationError(
                    'Invalid link ID',
                    undefined,
                    'INVALID_LINK_ID',
                );
            }
            const link = await Link.findById(req.params.id)
                .populate('portalNode', LINK_POPULATE_SELECT)
                .populate('bridgeNode', LINK_POPULATE_SELECT)
                .lean();
            if (!link) {
                const error = new Error('The cascade link was not found');
                error.code = 'CASCADE_LINK_NOT_FOUND';
                error.linkId = req.params.id;
                throw error;
            }
            const reader = readLinkApplicationState ?? l2tpActiveHostProvider.getActiveHost()?.readLinkApplicationState;
            if (typeof reader === 'function') {
                const snapshot = await readLinkSnapshot({ Link, TopologyState,
                    filter: { _id: req.params.id }, readLinkApplicationState: reader });
                const current = snapshot.links.find(candidate => String(candidate._id) === req.params.id);
                if (!current) throw Object.assign(new Error('The cascade link was not found'), { code: 'CASCADE_LINK_NOT_FOUND' });
                return res.json(current);
            }
            return res.json(projectLinkLifecycle(link));
        } catch (error) {
            return sendError(res, error, 'Get');
        }
    });

    router.post('/', requireScope('nodes:write'), async (req, res) => {
        try {
            const expectedTopologyRevision = normalizeExpectedTopologyRevision(req.body);
            const {
                name,
                portalNodeId,
                bridgeNodeId,
                tunnelPort,
                tunnelProtocol,
                tunnelSecurity,
                tunnelTransport,
                tunnelDomain,
                tunnelUuid,
                tcpFastOpen,
                tcpKeepAlive,
                tcpNoDelay,
                wsPath,
                wsHost,
                grpcServiceName,
                xhttpPath,
                xhttpHost,
                xhttpMode,
                mode,
                muxEnabled,
                muxConcurrency,
                geoRouting,
                realityDest,
                realitySni,
                realityPrivateKey,
                realityPublicKey,
                realityShortIds,
                realityFingerprint,
                autoDeploy,
                priority,
            } = req.body || {};
            if (!name || !portalNodeId || !bridgeNodeId) {
                throw new RequestValidationError(
                    'name, portalNodeId and bridgeNodeId are required',
                );
            }
            if (!mongoose.Types.ObjectId.isValid(portalNodeId)
                || !mongoose.Types.ObjectId.isValid(bridgeNodeId)) {
                throw new RequestValidationError('Invalid node ID format');
            }
            if (portalNodeId === bridgeNodeId) {
                throw new RequestValidationError('Portal and Bridge must be different nodes');
            }
            const linkMode = mode || 'reverse';
            if (!['reverse', 'forward'].includes(linkMode)) {
                throw new RequestValidationError('mode must be "reverse" or "forward"');
            }
            const parsedPort = parseInt(tunnelPort, 10);
            const port = Number.isNaN(parsedPort) ? 10086 : parsedPort;
            if (port < 1 || port > 65535) {
                throw new RequestValidationError('tunnelPort must be between 1 and 65535');
            }
            const security = tunnelSecurity || 'none';
            const transport = tunnelTransport || 'tcp';
            const protocol = tunnelProtocol || 'vless';
            if (!TUNNEL_PROTOCOLS.has(protocol)) {
                throw new RequestValidationError('tunnelProtocol must be "vless" or "vmess"');
            }
            if (security === 'reality' && transport === 'ws') {
                throw new RequestValidationError(
                    'REALITY security is not compatible with WebSocket transport. Use TCP, gRPC, or SplitHTTP.',
                );
            }
            const durableAutoDeploy = normalizeAutoDeploy(autoDeploy)
                && !isClassicProductionDeploymentConfigured(deploymentEnv);
            if (durableAutoDeploy) { getIntentService(); requireIntentKey(req); }
            // v2 replay must precede mutable node defaults/existence checks too.
            // The joined draft service validates endpoint inventory transactionally.
            const [portalNode, bridgeNode] = durableAutoDeploy ? [] : await Promise.all([
                Node.findById(portalNodeId),
                Node.findById(bridgeNodeId),
            ]);
            if (!durableAutoDeploy && !portalNode) {
                throw new RequestValidationError(
                    'Portal node not found',
                    undefined,
                    'PORTAL_NODE_NOT_FOUND',
                );
            }
            if (!durableAutoDeploy && !bridgeNode) {
                throw new RequestValidationError(
                    'Bridge node not found',
                    undefined,
                    'BRIDGE_NODE_NOT_FOUND',
                );
            }
            const portCheckField = linkMode === 'forward' ? 'bridgeNode' : 'portalNode';
            const portCheckId = linkMode === 'forward' ? bridgeNodeId : portalNodeId;
            const existingLink = normalizeAutoDeploy(autoDeploy) ? null : await Link.findOne({
                [portCheckField]: portCheckId,
                tunnelPort: port,
                active: true,
            });
            if (existingLink) {
                const sideLabel = linkMode === 'forward' ? 'bridge/relay' : 'portal';
                throw new RequestValidationError(
                    `Port ${port} is already used by link "${existingLink.name}" on the ${sideLabel} node`,
                );
            }
            const link = {
                ...(!durableAutoDeploy ? { _id: new mongoose.Types.ObjectId() } : {}),
                name,
                mode: linkMode,
                portalNode: portalNodeId,
                bridgeNode: bridgeNodeId,
                ...(tunnelUuid ? { tunnelUuid } : !durableAutoDeploy ? { tunnelUuid: crypto.randomUUID() } : {}),
                tunnelPort: port,
                tunnelDomain: tunnelDomain || 'reverse.tunnel.internal',
                tunnelProtocol: protocol,
                tunnelSecurity: security,
                tunnelTransport: transport,
                tcpFastOpen: tcpFastOpen !== false,
                tcpKeepAlive: parseInt(tcpKeepAlive, 10) || 100,
                tcpNoDelay: tcpNoDelay !== false,
                wsPath: wsPath || '/cascade',
                wsHost: wsHost || '',
                grpcServiceName: grpcServiceName || 'cascade',
                xhttpPath: xhttpPath || '/cascade',
                xhttpHost: xhttpHost || '',
                xhttpMode: xhttpMode || 'auto',
                muxEnabled: !!muxEnabled,
                muxConcurrency: parseInt(muxConcurrency, 10) || 8,
                priority: parseInt(priority, 10) || 100,
                autoDeploy: normalizeAutoDeploy(autoDeploy),
            };
            if (security === 'reality') {
                Object.assign(link, resolveRealitySettings({
                    realityDest,
                    realitySni,
                    realityPrivateKey,
                    realityPublicKey,
                    realityShortIds,
                    realityFingerprint,
                }, linkMode === 'forward' ? bridgeNode : portalNode, { generate: !durableAutoDeploy }));
            }
            if (geoRouting && typeof geoRouting === 'object') {
                link.geoRouting = {
                    enabled: !!geoRouting.enabled,
                    domains: Array.isArray(geoRouting.domains)
                        ? geoRouting.domains.filter(Boolean)
                        : [],
                    geoip: Array.isArray(geoRouting.geoip)
                        ? geoRouting.geoip.filter(Boolean)
                        : [],
                };
            }
            // Server-owned authorization is inserted atomically with this new
            // draft, for save-only and auto creates alike. Never adopt old rows.
            if (linkMode === 'reverse' && isClassicProductionDeploymentConfigured(deploymentEnv)) {
                const grant = issueClassicLifecycleGrant(link, deploymentEnv);
                if (grant !== undefined) link.classicLifecycleGrant = grant;
            }
            if (link.autoDeploy === true && isClassicProductionDeploymentConfigured(deploymentEnv)) {
                if (linkMode !== 'reverse') {
                    throw new RequestValidationError(
                        'Classic auto-deploy supports reverse links only',
                        undefined,
                        'CLASSIC_DEPLOY_UNSUPPORTED',
                    );
                }
                const classicCoordinator = getTopologyCoordinator();
                if (typeof classicCoordinator?.beginCreatedLinkCapability !== 'function'
                    || typeof classicCoordinator?.confirmCreatedLinkCapability !== 'function'
                    || typeof classicCoordinator?.queueCreatedLink !== 'function') {
                    throw Object.assign(new Error('Classic deployment capabilities are unavailable'), {
                        code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
                    });
                }
                const creationCapability = classicCoordinator.beginCreatedLinkCapability({
                    linkId: String(link._id),
                });
                // Classic has no durable native intent worker. Persist the draft,
                // then run the same fenced, completion-checked scoped apply used by
                // the manual Deploy action; never return a synthetic 202 job.
                const revisions = await getWriteService().createLink({
                    expectedTopologyRevision,
                    link,
                });
                await invalidateCaches();
                const maintenance = isIndependentClassicDraft(revisions) ? null : await maintainL2tpPaths();
                const finalRevisions = Number.isSafeInteger(maintenance?.revision)
                    ? { ...revisions, revision: maintenance.revision } : revisions;
                classicCoordinator.confirmCreatedLinkCapability(creationCapability, {
                    linkId: String(link._id),
                    expectedTopologyRevision: finalRevisions.revision,
                });
                const snapshot = await readLinkSnapshot({ Link, TopologyState, revisions: finalRevisions });
                const created = snapshot.links.find(candidate => String(candidate._id) === String(link._id));
                const autoDeploy = await queueAutoDeploy({
                    link: created || link,
                    action: 'link.create',
                    portalNodeId: portalNodeId,
                    bridgeNodeId: bridgeNodeId,
                    revision: finalRevisions.revision,
                    links: snapshot.links,
                    linkCreated: true,
                    creationCapability,
                });
                await invalidateCaches();
                const finalSnapshot = await readLinkSnapshot({ Link, TopologyState, revisions: finalRevisions });
                const creationOutcome = autoDeploy.autoDeployResult?.status === 'succeeded'
                    ? 'Created and auto-deployed'
                    : autoDeploy.autoDeployStatus === 'blocked'
                        ? 'Created; auto-deploy blocked for'
                        : 'Created; auto-deploy queued for';
                logger.info(`[Cascade Links API] ${creationOutcome} ${linkMode} link ${name}: ${portalNode.name} -> ${bridgeNode.name}`);
                return res.status(201).json({
                    ...finalSnapshot,
                    ...autoDeploy,
                    createdLinkId: String(link._id), desiredSaved: true,
                });
            }
            if (link.autoDeploy === true) {
                if (security === 'reality' && typeof getIntentService().dependencies?.prepareLink !== 'function') {
                    throw Object.assign(new Error('Durable REALITY credential preparation is unavailable'), { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
                }
                const job = await getIntentService().accept({
                    version: 2, kind: 'link.create', expectedTopologyRevision, link,
                    requestKey: req.get('Idempotency-Key'),
                });
                const body = acceptedIntentResponse(job, { autoDeploy: true });
                await invalidateCaches();
                return res.status(202).json(body);
            }
            const revisions = await getWriteService().createLink({
                expectedTopologyRevision,
                link,
            });
            await invalidateCaches();
            const maintenance = isIndependentClassicDraft(revisions) ? null : await maintainL2tpPaths();
            const finalRevisions = Number.isSafeInteger(maintenance?.revision)
                ? { ...revisions, revision: maintenance.revision } : revisions;
            const snapshot = await readLinkSnapshot({ Link, TopologyState, revisions: finalRevisions });
            logger.info(`[Cascade Links API] Created ${linkMode} link ${name}: ${portalNode.name} -> ${bridgeNode.name}`);
            return res.status(201).json({ ...snapshot, createdLinkId: String(link._id), desiredSaved: true });
        } catch (error) {
            return sendError(res, error, 'Create', {
                revision: req.body?.expectedTopologyRevision });
        }
    });

    router.put('/:id', requireScope('nodes:write'), async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                throw new RequestValidationError(
                    'Invalid link ID',
                    undefined,
                    'INVALID_LINK_ID',
                );
            }
            const expectedTopologyRevision = normalizeExpectedTopologyRevision(req.body);
            const allowedFields = [
                'name', 'mode', 'tunnelPort', 'tunnelDomain', 'tunnelProtocol',
                'tunnelSecurity', 'tunnelTransport', 'tunnelUuid',
                'tcpFastOpen', 'tcpKeepAlive', 'tcpNoDelay', 'active', 'priority', 'autoDeploy',
                'wsPath', 'wsHost', 'grpcServiceName',
                'xhttpPath', 'xhttpHost', 'xhttpMode',
                'muxEnabled', 'muxConcurrency',
                'realityDest', 'realityPrivateKey', 'realityPublicKey',
                'realityFingerprint',
            ];
            const changes = {};
            for (const key of allowedFields) {
                if (req.body?.[key] !== undefined) changes[key] = req.body[key];
            }
            const requestedSni = normalizeStringArray(req.body?.realitySni).filter(Boolean);
            // The editable shipped form uses the same endpoint ID names as
            // create. Preserve them in the existing structural mutation path;
            // silently ignoring a requested move can falsely report a no-op.
            for (const [field, alias] of [['portalNode', 'portalNodeId'], ['bridgeNode', 'bridgeNodeId']]) {
                const canonical = req.body?.[field];
                const aliased = req.body?.[alias];
                if (canonical !== undefined && aliased !== undefined && canonical !== aliased) {
                    throw new RequestValidationError('Conflicting endpoint identifiers');
                }
                const value = aliased !== undefined ? aliased : canonical;
                if (value !== undefined) {
                    if (typeof value !== 'string' || !/^[a-f0-9]{24}$/.test(value)) {
                        throw new RequestValidationError('Invalid endpoint identifier');
                    }
                    changes[field] = value;
                }
            }
            if (changes.autoDeploy !== undefined) {
                changes.autoDeploy = normalizeAutoDeploy(changes.autoDeploy);
            }
            const durableAutoDeploy = changes.autoDeploy === true
                && !isClassicProductionDeploymentConfigured(deploymentEnv);
            if (durableAutoDeploy) { getIntentService(); requireIntentKey(req); }
            if (changes.tunnelProtocol !== undefined
                && !TUNNEL_PROTOCOLS.has(changes.tunnelProtocol)) {
                throw new RequestValidationError('tunnelProtocol must be "vless" or "vmess"');
            }

            if (durableAutoDeploy) {
                if (changes.tunnelPort !== undefined) {
                    const port = parseInt(changes.tunnelPort, 10);
                    if (!Number.isInteger(port) || port < 1 || port > 65535) {
                        throw new RequestValidationError('tunnelPort must be between 1 and 65535');
                    }
                    changes.tunnelPort = port;
                }
                if (req.body?.geoRouting !== undefined) {
                    const geoRouting = req.body.geoRouting;
                    if (!geoRouting || typeof geoRouting !== 'object' || Array.isArray(geoRouting)) {
                        throw new RequestValidationError('geoRouting must be an object');
                    }
                    changes['geoRouting.enabled'] = !!geoRouting.enabled;
                    if (Array.isArray(geoRouting.domains)) changes['geoRouting.domains'] = geoRouting.domains.map(String);
                    if (Array.isArray(geoRouting.geoip)) changes['geoRouting.geoip'] = geoRouting.geoip.map(String);
                }
                if (req.body?.realitySni !== undefined) changes.realitySni = requestedSni;
                if (req.body?.realityShortIds !== undefined) changes.realityShortIds = normalizeStringArray(req.body.realityShortIds);
                // Freeze requested content in the real intent service before any
                // row-dependent defaults/credentials. Its joined writer owns the
                // desired revision, tombstone check and job in ONE transaction.
                const job = await getIntentService().accept({ version: 2, kind: 'link.apply',
                    expectedTopologyRevision, requestKey: requireIntentKey(req), linkId: req.params.id, changes });
                await invalidateCaches();
                return res.status(202).json(acceptedIntentResponse(job, { autoDeploy: true }));
            }

            if (changes.realityDest === null || (typeof changes.realityDest === 'string' && !changes.realityDest.trim())) delete changes.realityDest;
            if (requestedSni.length) changes.realitySni = requestedSni;
            const needsCurrentLink = changes.tunnelPort !== undefined
                || changes.mode !== undefined
                || changes.portalNode !== undefined
                || changes.bridgeNode !== undefined
                || changes.tunnelSecurity !== undefined
                || changes.tunnelTransport !== undefined
                || req.body?.realityDest !== undefined
                || changes.realityFingerprint !== undefined
                || changes.realityPrivateKey !== undefined
                || changes.realityPublicKey !== undefined
                || req.body?.realitySni !== undefined
                || req.body?.realityShortIds !== undefined;
            let currentLink = null;
            if (needsCurrentLink || !isClassicProductionDeploymentConfigured(deploymentEnv)) {
                currentLink = await Link.findById(req.params.id);
                if (!currentLink) {
                    const error = new Error('The cascade link was not found');
                    error.code = 'CASCADE_LINK_NOT_FOUND';
                    error.linkId = req.params.id;
                    throw error;
                }
                if (currentLink.lifecycle?.state === 'deleting') {
                    throw Object.assign(new Error('The cascade link is being deleted'), { code: 'CASCADE_LINK_DELETING' });
                }
            }

            if (changes.tunnelPort !== undefined) {
                const port = parseInt(changes.tunnelPort, 10);
                if (!Number.isInteger(port) || port < 1 || port > 65535) {
                    throw new RequestValidationError('tunnelPort must be between 1 and 65535');
                }
                changes.tunnelPort = port;
                const effectiveMode = changes.mode || currentLink.mode || 'reverse';
                const nodeField = effectiveMode === 'forward' ? 'bridgeNode' : 'portalNode';
                const conflictingLink = await Link.findOne({
                    [nodeField]: changes[nodeField] || currentLink[nodeField],
                    tunnelPort: port,
                    active: true,
                    _id: { $ne: req.params.id },
                });
                if (conflictingLink) {
                    throw new RequestValidationError(
                        `Port ${port} is already used by link "${conflictingLink.name}" on this node`,
                    );
                }
            }

            if (changes.tunnelSecurity === 'reality' || changes.tunnelTransport) {
                const effectiveSecurity = changes.tunnelSecurity
                    || currentLink?.tunnelSecurity
                    || 'none';
                const effectiveTransport = changes.tunnelTransport
                    || currentLink?.tunnelTransport
                    || 'tcp';
                if (effectiveSecurity === 'reality' && effectiveTransport === 'ws') {
                    throw new RequestValidationError(
                        'REALITY security is not compatible with WebSocket transport',
                    );
                }
            }

            if (req.body?.geoRouting !== undefined) {
                const geoRouting = req.body.geoRouting;
                if (!geoRouting || typeof geoRouting !== 'object' || Array.isArray(geoRouting)) {
                    throw new RequestValidationError('geoRouting must be an object');
                }
                changes['geoRouting.enabled'] = !!geoRouting.enabled;
                if (Array.isArray(geoRouting.domains)) {
                    changes['geoRouting.domains'] = geoRouting.domains.map(String);
                }
                if (Array.isArray(geoRouting.geoip)) {
                    changes['geoRouting.geoip'] = geoRouting.geoip.map(String);
                }
            }
            if (req.body?.realityShortIds !== undefined) {
                changes.realityShortIds = normalizeStringArray(req.body.realityShortIds);
            }
            const effectiveSecurity = changes.tunnelSecurity
                || currentLink?.tunnelSecurity
                || 'none';
            if (effectiveSecurity === 'reality') {
                const unchangedFingerprint = changes.realityFingerprint !== undefined
                    && changes.realityFingerprint === currentLink?.realityFingerprint;
                const listenerField = (changes.mode || currentLink?.mode) === 'forward' ? 'bridgeNode' : 'portalNode';
                const listenerId = changes[listenerField] || currentLink?.[listenerField];
                const listenerNode = listenerId ? await Node.findById(listenerId) : null;
                Object.assign(changes, resolveRealitySettings({
                    realityDest: changes.realityDest !== undefined
                        ? changes.realityDest
                        : currentLink?.realityDest,
                    realitySni: changes.realitySni !== undefined
                        ? changes.realitySni
                        : currentLink?.realitySni,
                    realityPrivateKey: changes.realityPrivateKey !== undefined
                        ? changes.realityPrivateKey
                        : currentLink?.realityPrivateKey,
                    realityPublicKey: changes.realityPublicKey !== undefined
                        ? changes.realityPublicKey
                        : currentLink?.realityPublicKey,
                    realityShortIds: changes.realityShortIds !== undefined
                        ? changes.realityShortIds
                        : currentLink?.realityShortIds,
                    realityFingerprint: changes.realityFingerprint !== undefined
                        ? changes.realityFingerprint
                        : currentLink?.realityFingerprint,
                }, listenerNode));
                // Only a new link or a changed fingerprint adopts the Random
                // default. Preserve a legacy value even if an edit resubmits it.
                if (req.body?.realityFingerprint === undefined) {
                    delete changes.realityFingerprint;
                } else if (unchangedFingerprint) {
                    changes.realityFingerprint = currentLink.realityFingerprint;
                }
            }

            const revisions = await getWriteService().updateLink({
                expectedTopologyRevision,
                linkId: req.params.id,
                changes,
            });
            await invalidateCaches();
            let maintenance = null;
            let maintenanceError = null;
            try {
                if (!isIndependentClassicDraft(revisions)) {
                    maintenance = await maintainL2tpPaths({ required: changes.autoDeploy === true });
                }
            } catch (error) {
                maintenanceError = error;
            }
            if (changes.autoDeploy === true && maintenanceError) {
                logTopologyTestFailure({ action: 'link.update', phase: 'auto-path.maintain',
                    revision: revisions.revision, linkId: req.params.id, error: maintenanceError });
                logger.warn(`[Cascade Links API] L2TP auto path maintenance blocked autoDeploy: ${maintenanceError.code || 'UNKNOWN'}`);
            }
            let finalRevisions = Number.isSafeInteger(maintenance?.revision)
                ? { ...revisions, revision: maintenance.revision }
                : revisions;
            logger.info(`[Cascade Links API] Updated link ${req.params.id}`);
            let snapshot = await readLinkSnapshot({
                Link,
                TopologyState,
                revisions: finalRevisions,
            });
            let body = { ...snapshot, desiredSaved: true };
            // Only this PUT's explicit opt-in may queue; persisted metadata on
            // another edit is never an instruction to activate the link.
            if (changes.autoDeploy === true) {
                const link = snapshot.links.find(candidate => String(candidate._id) === req.params.id);
                if (link?.active === true) {
                    let preparationError = maintenanceError;
                    if (!preparationError) {
                        try {
                            const scopedCoordinator = await getTopologyCoordinator();
                            // Only a trusted server-selected service can omit the
                            // native hook. Its queue retains all admission checks.
                            if (!isIndependentClassicDraft(revisions)
                                && scopedCoordinator?.requiresL2tpIngressPreparation !== false) {
                                const baselineLinkIds = selectLinkApplyBaselineLinkIds({
                                    links: snapshot.links,
                                    linkId: link._id,
                                    portalNodeId: link.portalNode,
                                    bridgeNodeId: link.bridgeNode,
                                });
                                const prepared = await prepareL2tpIngressFn({
                                    link,
                                    linkId: String(link._id),
                                    linkIds: [String(link._id), ...baselineLinkIds],
                                    expectedTopologyRevision: finalRevisions.revision,
                                });
                                if (!Number.isSafeInteger(prepared?.revision)
                                    || prepared.revision < finalRevisions.revision) {
                                    const error = new Error('L2TP ingress preparation returned no exact revision');
                                    error.code = 'TOPOLOGY_OPERATION_QUEUE_FAILED';
                                    throw error;
                                }
                                if (prepared.revision !== finalRevisions.revision) {
                                    finalRevisions = { ...finalRevisions, revision: prepared.revision };
                                    snapshot = { ...snapshot, topologyRevision: prepared.revision };
                                    body = { ...body, topologyRevision: prepared.revision };
                                }
                            }
                        } catch (error) {
                            preparationError = error;
                            logTopologyTestFailure({ action: 'link.update', phase: 'ingress.prepare',
                                revision: finalRevisions.revision, linkId: req.params.id, error });
                            logger.warn(`[Cascade Links API] L2TP ingress preparation blocked: ${error.code || 'UNKNOWN'}`);
                        }
                    }
                    if (preparationError) {
                        Object.assign(body, {
                            autoDeployStatus: 'blocked',
                            autoDeployError: autoDeployBlockedError(preparationError),
                        });
                    } else {
                        Object.assign(body, await queueAutoDeploy({
                            link,
                            action: 'link.update',
                            portalNodeId: link.portalNode,
                            bridgeNodeId: link.bridgeNode,
                            revision: finalRevisions.revision,
                            links: snapshot.links,
                        }));
                    }
                }
            }
            return res.json(body);
        } catch (error) {
            return sendError(res, error, 'Update', {
                revision: req.body?.expectedTopologyRevision, linkId: req.params.id });
        }
    });

    router.delete('/:id', requireScope('nodes:write'), async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                throw new RequestValidationError(
                    'Invalid link ID',
                    undefined,
                    'INVALID_LINK_ID',
                );
            }
            const expectedTopologyRevision = normalizeExpectedTopologyRevision(req.body);
            // A draft-only delete can strand live classic configuration. The
            // lifecycle coordinator owns checked removal and atomic settlement,
            // even when issuing new durable grants is disabled.
            if (!isClassicProductionDeploymentConfigured(deploymentEnv)) {
                const service = getIntentService();
                const link = await Link.findById(req.params.id).lean();
                const existing = !link ? await readPersistedIntent(service, Link, requireIntentKey(req)) : null;
                if (existing && (existing.version !== 2 || existing.kind !== 'link.delete' || String(existing.linkId) !== req.params.id)) {
                    throw Object.assign(new Error('The request key belongs to a different mutation'), { code: 'TOPOLOGY_INTENT_KEY_CONFLICT' });
                }
                const desiredVersion = req.body?.desiredVersion ?? (link ? linkDesiredVersion(link) : existing?.desiredVersion);
                if (!link && !desiredVersion) throw Object.assign(new Error('The cascade link was not found'), { code: 'CASCADE_LINK_NOT_FOUND' });
                if (typeof desiredVersion !== 'string' || !/^[a-f0-9]{64}$/.test(desiredVersion)) throw new RequestValidationError('Invalid desired link version');
                // Pending/offline/error is NOT evidence of never-dispatched work.
                // Without an authoritative history proof, always use durable cleanup.
                const job = await service.accept({ version: 2, kind: 'link.delete',
                    expectedTopologyRevision, requestKey: req.get('Idempotency-Key'),
                    linkId: req.params.id, desiredVersion });
                const body = acceptedIntentResponse(job);
                await invalidateCaches();
                return res.status(202).json({ ...body,
                    ...(['succeeded', 'failed'].includes(job.status) ? {} : {
                        applicationState: job.status === 'blocked' ? 'reconcile_required' : 'deleting',
                    }) });
            }
            const deletionService = getTopologyCoordinator();
            if (typeof deletionService?.deleteLink !== 'function') {
                throw Object.assign(new Error('Checked cascade deletion is unavailable'), {
                    code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
                });
            }
            const revisions = await deletionService.deleteLink({
                expectedTopologyRevision,
                linkId: req.params.id,
            });
            await invalidateCaches();
            const maintenance = isIndependentClassicDraft(revisions) ? null : await maintainL2tpPaths();
            let finalRevisions = Number.isSafeInteger(maintenance?.revision)
                ? { ...revisions, revision: maintenance.revision }
                : revisions;
            logger.info(`[Cascade Links API] Deleted link ${req.params.id}`);
            return res.json(await readLinkSnapshot({
                Link,
                TopologyState,
                revisions: finalRevisions,
            }));
        } catch (error) {
            return sendError(res, error, 'Delete', {
                revision: req.body?.expectedTopologyRevision, linkId: req.params.id });
        }
    });

    return router;
}

const router = createCascadeLinksRouter();

module.exports = router;
module.exports.ERROR_STATUS_BY_CODE = ERROR_STATUS_BY_CODE;
module.exports.LINK_POPULATE_SELECT = LINK_POPULATE_SELECT;
module.exports.TOPOLOGY_STATE_SELECT = TOPOLOGY_STATE_SELECT;
module.exports.RequestValidationError = RequestValidationError;
module.exports.createCascadeLinksRouter = createCascadeLinksRouter;
module.exports.listLinks = listLinks;
module.exports.normalizeExpectedTopologyRevision = normalizeExpectedTopologyRevision;
module.exports.normalizeStringArray = normalizeStringArray;
module.exports.readLinkSnapshot = readLinkSnapshot;
module.exports.resolveRealitySettings = resolveRealitySettings;
module.exports.prepareIntentLink = prepareIntentLink;
module.exports.acceptedIntentResponse = acceptedIntentResponse;
module.exports.readPersistedIntent = readPersistedIntent;
module.exports.selectLinkApplyBaselineLinkIds = selectLinkApplyBaselineLinkIds;
