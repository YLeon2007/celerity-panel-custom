'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
const CascadeTopologyState = require('../modules/relay-l2tp/models/cascadeTopologyStateModel');
const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
const {
    createTopologyDraftWriteService,
} = require('../modules/relay-l2tp/services/topologyDraftWriteService');
const logger = require('../utils/logger');
const { requireScope } = require('../middleware/auth');

const ROUTE_GROUP_SELECT = '_id name mode strategy paths.pathKey paths.linkIds paths.priority paths.enabled';
const TOPOLOGY_STATE_SELECT = 'revision deployedRevision';
const ROUTE_GROUP_MODES = new Set(['reverse', 'forward']);
const ROUTE_GROUP_STRATEGY = 'priority-failover';
const ERROR_STATUS_BY_CODE = new Map([
    ['INVALID_TOPOLOGY_REVISION', 400],
    ['INVALID_REQUEST', 400],
    ['INVALID_ROUTE_GROUP_ID', 400],
    ['CASCADE_ROUTE_GROUP_NOT_FOUND', 404],
    ['STALE_TOPOLOGY_REVISION', 409],
    ['CASCADE_ROUTE_GROUP_CONFLICT', 409],
    ['CASCADE_ROUTE_GROUP_IN_USE', 409],
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

function plainObject(value) {
    if (value && typeof value.toObject === 'function') return value.toObject();
    return value || {};
}

function projectRouteGroup(value) {
    const group = plainObject(value);
    return {
        id: String(group._id ?? group.id),
        name: group.name,
        mode: group.mode,
        strategy: group.strategy,
        paths: (group.paths || []).map(rawPath => {
            const path = plainObject(rawPath);
            return {
                pathKey: path.pathKey,
                linkIds: (path.linkIds || []).map(linkId => String(linkId)),
                priority: path.priority,
                enabled: path.enabled !== false,
            };
        }),
    };
}

function compareRouteGroups(left, right) {
    return String(left.name).localeCompare(String(right.name))
        || String(left.id).localeCompare(String(right.id));
}

function normalizeObjectId(value, field) {
    if (typeof value !== 'string' || !mongoose.Types.ObjectId.isValid(value)) {
        throw new RequestValidationError(`${field} must be a valid link ID`);
    }
    return value;
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

function normalizeRouteGroupInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new RequestValidationError('Request body must be an object');
    }

    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (!name) throw new RequestValidationError('name is required');

    if (!ROUTE_GROUP_MODES.has(input.mode)) {
        throw new RequestValidationError('mode must be "reverse" or "forward"');
    }

    const strategy = input.strategy === undefined ? ROUTE_GROUP_STRATEGY : input.strategy;
    if (strategy !== ROUTE_GROUP_STRATEGY) {
        throw new RequestValidationError('strategy must be "priority-failover"');
    }

    if (!Array.isArray(input.paths) || input.paths.length === 0) {
        throw new RequestValidationError('paths must contain at least one ordered path');
    }

    const pathKeys = new Set();
    const priorities = new Set();
    const paths = input.paths.map((rawPath, pathIndex) => {
        if (!rawPath || typeof rawPath !== 'object' || Array.isArray(rawPath)) {
            throw new RequestValidationError(`paths[${pathIndex}] must be an object`);
        }

        const pathKey = typeof rawPath.pathKey === 'string' ? rawPath.pathKey.trim() : '';
        if (!pathKey) throw new RequestValidationError(`paths[${pathIndex}].pathKey is required`);
        if (pathKeys.has(pathKey)) throw new RequestValidationError('pathKey values must be unique');
        pathKeys.add(pathKey);

        if (!Array.isArray(rawPath.linkIds) || rawPath.linkIds.length === 0) {
            throw new RequestValidationError(`paths[${pathIndex}].linkIds must contain at least one link`);
        }
        const linkIds = rawPath.linkIds.map((linkId, linkIndex) => normalizeObjectId(
            linkId,
            `paths[${pathIndex}].linkIds[${linkIndex}]`,
        ));
        if (new Set(linkIds).size !== linkIds.length) {
            throw new RequestValidationError(`paths[${pathIndex}].linkIds must not contain duplicates`);
        }

        const priority = rawPath.priority;
        if (typeof priority !== 'number' || !Number.isFinite(priority) || priority <= 0) {
            throw new RequestValidationError(`paths[${pathIndex}].priority must be a positive finite number`);
        }
        if (priorities.has(priority)) {
            throw new RequestValidationError('path priorities must be unique');
        }
        priorities.add(priority);

        if (rawPath.enabled !== undefined && typeof rawPath.enabled !== 'boolean') {
            throw new RequestValidationError(`paths[${pathIndex}].enabled must be a boolean`);
        }

        return {
            pathKey,
            linkIds,
            priority,
            enabled: rawPath.enabled !== false,
        };
    });

    return { name, mode: input.mode, strategy, paths };
}

async function listRouteGroups(RouteGroup) {
    const rows = await RouteGroup.find({})
        .select(ROUTE_GROUP_SELECT)
        .sort({ name: 1, _id: 1 })
        .lean();
    return (rows || []).map(projectRouteGroup).sort(compareRouteGroups);
}

async function readRouteGroupSnapshot({ RouteGroup, TopologyState, revisions }) {
    const routeGroupsPromise = listRouteGroups(RouteGroup);
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
        routeGroups: await routeGroupsPromise,
    };
}

function sendError(res, error, operation) {
    let code = error?.code;
    let status;

    if (error instanceof RequestValidationError || error?.name === 'ValidationError') {
        code = code || 'INVALID_REQUEST';
        status = 400;
    } else if (error?.code === 11000 || error?.code === 11001) {
        code = 'CASCADE_ROUTE_GROUP_CONFLICT';
        status = 409;
    } else {
        status = ERROR_STATUS_BY_CODE.get(code);
    }

    if (!status) {
        logger.error(`[Cascade Route Groups API] ${operation} error: ${error.message}`);
        return res.status(500).json({
            error: {
                code: 'INTERNAL_ERROR',
                message: 'Internal server error',
            },
        });
    }

    const body = {
        error: {
            code,
            message: error.message,
        },
    };
    if (Array.isArray(error?.errors)) body.error.details = error.errors;
    else if (error?.details !== undefined) body.error.details = error.details;
    return res.status(status).json(body);
}

function createCascadeRouteGroupsRouter({
    RouteGroup = CascadeRouteGroup,
    Link = CascadeLink,
    Node = HyNode,
    TopologyState = CascadeTopologyState,
    RelayState = RelayL2tpState,
    topologyDraftWriteService,
    createDraftWriteService = createTopologyDraftWriteService,
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
    const mutationLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 30,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => res.status(429).json({
            error: 'Too many cascade route group changes',
        }),
    });

    router.get('/', requireScope('nodes:read'), async (req, res) => {
        try {
            res.json(await readRouteGroupSnapshot({ RouteGroup, TopologyState }));
        } catch (error) {
            sendError(res, error, 'List');
        }
    });

    router.post('/', requireScope('nodes:write'), mutationLimiter, async (req, res) => {
        try {
            const expectedTopologyRevision = normalizeExpectedTopologyRevision(req.body);
            const group = normalizeRouteGroupInput(req.body);
            const revisions = await getWriteService().createRouteGroup({
                expectedTopologyRevision,
                routeGroup: { _id: new mongoose.Types.ObjectId(), ...group },
            });
            res.status(201).json(await readRouteGroupSnapshot({
                RouteGroup,
                TopologyState,
                revisions,
            }));
        } catch (error) {
            sendError(res, error, 'Create');
        }
    });

    router.put('/:id', requireScope('nodes:write'), mutationLimiter, async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                throw new RequestValidationError(
                    'Invalid route group ID',
                    undefined,
                    'INVALID_ROUTE_GROUP_ID',
                );
            }
            const expectedTopologyRevision = normalizeExpectedTopologyRevision(req.body);
            const group = normalizeRouteGroupInput(req.body);
            const revisions = await getWriteService().updateRouteGroup({
                expectedTopologyRevision,
                routeGroupId: req.params.id,
                changes: group,
            });
            return res.json(await readRouteGroupSnapshot({
                RouteGroup,
                TopologyState,
                revisions,
            }));
        } catch (error) {
            return sendError(res, error, 'Update');
        }
    });

    router.delete('/:id', requireScope('nodes:write'), mutationLimiter, async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                throw new RequestValidationError(
                    'Invalid route group ID',
                    undefined,
                    'INVALID_ROUTE_GROUP_ID',
                );
            }
            const expectedTopologyRevision = normalizeExpectedTopologyRevision(req.body);
            const revisions = await getWriteService().deleteRouteGroup({
                expectedTopologyRevision,
                routeGroupId: req.params.id,
            });
            return res.json(await readRouteGroupSnapshot({
                RouteGroup,
                TopologyState,
                revisions,
            }));
        } catch (error) {
            return sendError(res, error, 'Delete');
        }
    });

    return router;
}

const router = createCascadeRouteGroupsRouter();

module.exports = router;
module.exports.ERROR_STATUS_BY_CODE = ERROR_STATUS_BY_CODE;
module.exports.ROUTE_GROUP_SELECT = ROUTE_GROUP_SELECT;
module.exports.TOPOLOGY_STATE_SELECT = TOPOLOGY_STATE_SELECT;
module.exports.createCascadeRouteGroupsRouter = createCascadeRouteGroupsRouter;
module.exports.listRouteGroups = listRouteGroups;
module.exports.normalizeExpectedTopologyRevision = normalizeExpectedTopologyRevision;
module.exports.normalizeRouteGroupInput = normalizeRouteGroupInput;
module.exports.projectRouteGroup = projectRouteGroup;
module.exports.readRouteGroupSnapshot = readRouteGroupSnapshot;
