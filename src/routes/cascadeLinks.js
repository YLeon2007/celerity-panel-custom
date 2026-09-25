'use strict';

const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
const CascadeTopologyState = require('../modules/relay-l2tp/models/cascadeTopologyStateModel');
const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
const {
    createTopologyDraftWriteService,
} = require('../modules/relay-l2tp/services/topologyDraftWriteService');
const { maintainAutoL2tpPaths } = require('../modules/relay-l2tp/services/autoL2tpPathMaintenance');
const logger = require('../utils/logger');
const { requireScope } = require('../middleware/auth');

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
    ['INVALID_TOPOLOGY_DRAFT', 422],
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

function resolveRealitySettings(input = {}, targetNode = null) {
    // When the link form leaves realityDest/realitySni empty, inherit them
    // from the TARGET node's card (xray.realityDest/realitySni); the global
    // google defaults apply only when the target node has none configured.
    const targetXray = targetNode && typeof targetNode.xray === 'object' ? targetNode.xray : null;
    const nodeDest = String(targetXray?.realityDest || '').trim();
    const nodeSni = Array.isArray(targetXray?.realitySni)
        ? targetXray.realitySni.map(value => String(value).trim()).filter(Boolean)
        : [];
    let privateKey = String(input.realityPrivateKey || '').trim();
    let publicKey = String(input.realityPublicKey || '').trim();
    if (!privateKey || !publicKey) {
        const generated = generateRealityKeyPair();
        privateKey = generated.privateKey;
        publicKey = generated.publicKey;
    }
    if (!REALITY_KEY_RE.test(privateKey)) {
        throw new RequestValidationError(
            'Invalid REALITY privateKey format (expected base64 x25519 key)',
        );
    }
    if (!REALITY_KEY_RE.test(publicKey)) {
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
    const realitySni = normalizeStringArray(input.realitySni).filter(Boolean);
    return {
        realityDest: String(input.realityDest || '').trim() || nodeDest || 'www.google.com:443',
        realitySni: realitySni.length > 0 ? realitySni : (nodeSni.length > 0 ? nodeSni : ['www.google.com']),
        realityPrivateKey: privateKey,
        realityPublicKey: publicKey,
        realityShortIds: inputShortIds.some(Boolean)
            ? inputShortIds
            : [crypto.randomBytes(8).toString('hex')],
        realityFingerprint: String(input.realityFingerprint || 'chrome').trim() || 'chrome',
    };
}

async function listLinks(Link, filter = {}) {
    return Link.find(filter)
        .populate('portalNode', LINK_POPULATE_SELECT)
        .populate('bridgeNode', LINK_POPULATE_SELECT)
        .sort({ createdAt: -1 })
        .lean();
}

async function readLinkSnapshot({ Link, TopologyState, revisions, filter = {} }) {
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
    return {
        topologyRevision,
        deployedRevision,
        links: (await linksPromise) || [],
    };
}

function sendError(res, error, operation) {
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
        logger.error(`[Cascade Links API] ${operation} error: ${error.message}`);
        return res.status(500).json({
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
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
    topologyDraftWriteService,
    createDraftWriteService = createTopologyDraftWriteService,
    invalidateSubscriptions = () => require('../services/cacheService').invalidateAllSubscriptions(),
    invalidateTopology = () => require('../services/cascadeService')._invalidateTopologyCache(),
} = {}) {
    const router = express.Router();
    let writeService = topologyDraftWriteService;
    const getWriteService = () => {
        if (!writeService) {
            writeService = createDraftWriteService({
                HyNode: Node,
                CascadeLink: Link,
                CascadeRouteGroup: RouteGroup,
                CascadeTopologyState: TopologyState,
                RelayL2tpState: RelayState,
            });
        }
        return writeService;
    };
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
    const maintainL2tpPaths = async () => {
        try {
            await maintainAutoL2tpPaths({
                HyNode: Node,
                CascadeLink: Link,
                CascadeRouteGroup: RouteGroup,
                RelayL2tpState: RelayState,
                CascadeTopologyState: TopologyState,
                logger,
            });
        } catch (error) {
            logger.warn(`[Cascade Links API] L2TP auto path maintenance failed: ${error.message}`);
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
            return res.json(await readLinkSnapshot({ Link, TopologyState, filter }));
        } catch (error) {
            return sendError(res, error, 'List');
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
            return res.json(link);
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
            const [portalNode, bridgeNode] = await Promise.all([
                Node.findById(portalNodeId),
                Node.findById(bridgeNodeId),
            ]);
            if (!portalNode) {
                throw new RequestValidationError(
                    'Portal node not found',
                    undefined,
                    'PORTAL_NODE_NOT_FOUND',
                );
            }
            if (!bridgeNode) {
                throw new RequestValidationError(
                    'Bridge node not found',
                    undefined,
                    'BRIDGE_NODE_NOT_FOUND',
                );
            }
            const portCheckField = linkMode === 'forward' ? 'bridgeNode' : 'portalNode';
            const portCheckId = linkMode === 'forward' ? bridgeNodeId : portalNodeId;
            const existingLink = await Link.findOne({
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
                _id: new mongoose.Types.ObjectId(),
                name,
                mode: linkMode,
                portalNode: portalNodeId,
                bridgeNode: bridgeNodeId,
                tunnelUuid: tunnelUuid || crypto.randomUUID(),
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
            };
            if (security === 'reality') {
                Object.assign(link, resolveRealitySettings({
                    realityDest,
                    realitySni,
                    realityPrivateKey,
                    realityPublicKey,
                    realityShortIds,
                    realityFingerprint,
                }, bridgeNode));
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
            const revisions = await getWriteService().createLink({
                expectedTopologyRevision,
                link,
            });
            await invalidateCaches();
            await maintainL2tpPaths();
            logger.info(
                `[Cascade Links API] Created ${linkMode} link ${name}: ${portalNode.name} -> ${bridgeNode.name}`,
            );
            return res.status(201).json(await readLinkSnapshot({
                Link,
                TopologyState,
                revisions,
            }));
        } catch (error) {
            return sendError(res, error, 'Create');
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
                'tcpFastOpen', 'tcpKeepAlive', 'tcpNoDelay', 'active', 'priority',
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
            if (changes.tunnelProtocol !== undefined
                && !TUNNEL_PROTOCOLS.has(changes.tunnelProtocol)) {
                throw new RequestValidationError('tunnelProtocol must be "vless" or "vmess"');
            }

            const needsCurrentLink = changes.tunnelPort !== undefined
                || changes.mode !== undefined
                || changes.tunnelSecurity !== undefined
                || changes.tunnelTransport !== undefined
                || changes.realityDest !== undefined
                || changes.realityFingerprint !== undefined
                || changes.realityPrivateKey !== undefined
                || changes.realityPublicKey !== undefined
                || req.body?.realitySni !== undefined
                || req.body?.realityShortIds !== undefined;
            let currentLink = null;
            if (needsCurrentLink) {
                currentLink = await Link.findById(req.params.id);
                if (!currentLink) {
                    const error = new Error('The cascade link was not found');
                    error.code = 'CASCADE_LINK_NOT_FOUND';
                    error.linkId = req.params.id;
                    throw error;
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
                    [nodeField]: currentLink[nodeField],
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
            if (req.body?.realitySni !== undefined) {
                changes.realitySni = normalizeStringArray(req.body.realitySni).filter(Boolean);
            }
            if (req.body?.realityShortIds !== undefined) {
                changes.realityShortIds = normalizeStringArray(req.body.realityShortIds);
            }
            const effectiveSecurity = changes.tunnelSecurity
                || currentLink?.tunnelSecurity
                || 'none';
            if (effectiveSecurity === 'reality') {
                const targetNodeId = changes.bridgeNode || currentLink?.bridgeNode;
                const targetNode = targetNodeId ? await Node.findById(targetNodeId) : null;
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
                }, targetNode));
            }

            const revisions = await getWriteService().updateLink({
                expectedTopologyRevision,
                linkId: req.params.id,
                changes,
            });
            await invalidateCaches();
            await maintainL2tpPaths();
            logger.info(`[Cascade Links API] Updated link ${req.params.id}`);
            return res.json(await readLinkSnapshot({
                Link,
                TopologyState,
                revisions,
            }));
        } catch (error) {
            return sendError(res, error, 'Update');
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
            const revisions = await getWriteService().deleteLink({
                expectedTopologyRevision,
                linkId: req.params.id,
            });
            await invalidateCaches();
            await maintainL2tpPaths();
            logger.info(`[Cascade Links API] Deleted link ${req.params.id}`);
            return res.json(await readLinkSnapshot({
                Link,
                TopologyState,
                revisions,
            }));
        } catch (error) {
            return sendError(res, error, 'Delete');
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
