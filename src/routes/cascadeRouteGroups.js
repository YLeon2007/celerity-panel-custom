'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const CascadeLink = require('../models/cascadeLinkModel');
const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
const { validateTopology } = require('../modules/relay-l2tp/domain/topologyValidator');
const logger = require('../utils/logger');
const { requireScope } = require('../middleware/auth');

const ROUTE_GROUP_SELECT = '_id name mode strategy paths.pathKey paths.linkIds paths.priority paths.enabled';
const LINK_VALIDATION_SELECT = '_id portalNode bridgeNode mode';
const ROUTE_GROUP_MODES = new Set(['reverse', 'forward']);
const ROUTE_GROUP_STRATEGY = 'priority-failover';

class RequestValidationError extends Error {
    constructor(message, details) {
        super(message);
        this.name = 'RequestValidationError';
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

function referencedLinkIds(group) {
    const seen = new Set();
    const orderedIds = [];
    for (const path of group.paths) {
        for (const linkId of path.linkIds) {
            if (seen.has(linkId)) continue;
            seen.add(linkId);
            orderedIds.push(linkId);
        }
    }
    return orderedIds;
}

async function validateRouteGroupLinks(Link, group, groupId = 'new') {
    const linkIds = referencedLinkIds(group);
    const rows = await Link.find({ _id: { $in: linkIds } })
        .select(LINK_VALIDATION_SELECT)
        .lean();
    const links = (rows || []).map(rawLink => {
        const link = plainObject(rawLink);
        return {
            id: String(link._id ?? link.id),
            source: String(link.portalNode),
            target: String(link.bridgeNode),
            mode: link.mode,
        };
    });
    const validation = validateTopology({
        links,
        groups: [{ _id: groupId, ...group }],
    });
    if (!validation.valid) {
        throw new RequestValidationError('Invalid route group topology', validation.errors);
    }
}

function sendError(res, error, operation) {
    if (error instanceof RequestValidationError || error?.name === 'ValidationError') {
        const body = { error: error.message };
        if (error.details) body.details = error.details;
        return res.status(400).json(body);
    }
    logger.error(`[Cascade Route Groups API] ${operation} error: ${error.message}`);
    return res.status(500).json({ error: `Failed to ${operation.toLowerCase()} cascade route group` });
}

function createCascadeRouteGroupsRouter({
    RouteGroup = CascadeRouteGroup,
    Link = CascadeLink,
} = {}) {
    const router = express.Router();
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
            const rows = await RouteGroup.find({})
                .select(ROUTE_GROUP_SELECT)
                .sort({ name: 1, _id: 1 })
                .lean();
            res.json((rows || []).map(projectRouteGroup).sort(compareRouteGroups));
        } catch (error) {
            sendError(res, error, 'List');
        }
    });

    router.post('/', requireScope('nodes:write'), mutationLimiter, async (req, res) => {
        try {
            const group = normalizeRouteGroupInput(req.body);
            await validateRouteGroupLinks(Link, group);
            const created = await RouteGroup.create(group);
            res.status(201).json(projectRouteGroup(created));
        } catch (error) {
            sendError(res, error, 'Create');
        }
    });

    router.put('/:id', requireScope('nodes:write'), mutationLimiter, async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                throw new RequestValidationError('Invalid route group ID');
            }
            const group = normalizeRouteGroupInput(req.body);
            await validateRouteGroupLinks(Link, group, req.params.id);
            const updated = await RouteGroup.findByIdAndUpdate(
                req.params.id,
                { $set: group },
                { new: true, runValidators: true },
            );
            if (!updated) {
                return res.status(404).json({ error: 'Cascade route group not found' });
            }
            return res.json(projectRouteGroup(updated));
        } catch (error) {
            return sendError(res, error, 'Update');
        }
    });

    router.delete('/:id', requireScope('nodes:write'), mutationLimiter, async (req, res) => {
        try {
            if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
                throw new RequestValidationError('Invalid route group ID');
            }
            const deleted = await RouteGroup.findByIdAndDelete(req.params.id);
            if (!deleted) {
                return res.status(404).json({ error: 'Cascade route group not found' });
            }
            return res.json({ success: true, id: req.params.id });
        } catch (error) {
            return sendError(res, error, 'Delete');
        }
    });

    return router;
}

const router = createCascadeRouteGroupsRouter();

module.exports = router;
module.exports.LINK_VALIDATION_SELECT = LINK_VALIDATION_SELECT;
module.exports.ROUTE_GROUP_SELECT = ROUTE_GROUP_SELECT;
module.exports.createCascadeRouteGroupsRouter = createCascadeRouteGroupsRouter;
module.exports.normalizeRouteGroupInput = normalizeRouteGroupInput;
module.exports.projectRouteGroup = projectRouteGroup;
module.exports.validateRouteGroupLinks = validateRouteGroupLinks;
