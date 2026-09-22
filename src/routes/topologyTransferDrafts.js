'use strict';

const express = require('express');

const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const requireAuthMiddleware = require('../middleware/auth');
const relayL2tpModule = require('../modules/relay-l2tp');
const {
    IMPORT_DRAFT_KIND,
    TRANSFER_KIND,
    canonicalizeTopologyTransfer,
} = require('../modules/relay-l2tp/domain/topologyTransfer');
const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
const RelayL2tpTopologyTransferDraft = require(
    '../modules/relay-l2tp/models/relayL2tpTopologyTransferDraftModel'
);
const {
    projectDraft,
} = require('../modules/relay-l2tp/services/topologyTransferDraftService');
const {
    issuePanelCsrfToken,
    requirePanelCsrf,
} = require('./panel/csrf');
const logger = require('../utils/logger');

const DEFAULT_MODELS = Object.freeze({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    RelayL2tpState,
    RelayL2tpTopologyTransferDraft,
});
const ERROR_STATUS_BY_CODE = new Map([
    ['INVALID_TOPOLOGY_TRANSFER', 400],
    ['INVALID_TOPOLOGY_TRANSFER_DRAFT', 400],
    ['TOPOLOGY_TRANSFER_DRAFT_NOT_FOUND', 404],
    ['CSRF_AUTH_REQUIRED', 403],
    ['CSRF_ORIGIN_INVALID', 403],
    ['CSRF_TOKEN_INVALID', 403],
]);

function canonicalTransferDocument(value, expectedKind) {
    return canonicalizeTopologyTransfer(value, { kind: expectedKind });
}

function publicDraft(value, { includeDocument = true } = {}) {
    const draft = projectDraft(value, { includeDocument });
    if (includeDocument && draft.document !== undefined) {
        draft.document = canonicalTransferDocument(
            draft.document,
            draft.source === 'export' ? TRANSFER_KIND : IMPORT_DRAFT_KIND,
        );
    }
    return draft;
}

function sendError(res, error, operation, routeLogger = logger) {
    let status = ERROR_STATUS_BY_CODE.get(error?.code);
    let code = error?.code;

    if (!status && (error?.code === 11000 || error?.code === 11001)) {
        status = 409;
        code = 'TOPOLOGY_TRANSFER_DRAFT_CONFLICT';
    }
    if (!status && error?.name === 'ValidationError') {
        status = 400;
        code = 'INVALID_TOPOLOGY_TRANSFER_DRAFT';
    }

    if (!status) {
        routeLogger.error(`[Topology Transfer Drafts API] ${operation} error: ${error?.message}`);
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
    if (Array.isArray(error?.details) && error.details.length > 0) {
        body.error.details = error.details;
    }
    return res.status(status).json(body);
}

function createTopologyTransferDraftsRouter({
    service,
    createService = relayL2tpModule.createTopologyTransferDraftService,
    models = DEFAULT_MODELS,
    requireAuth = requireAuthMiddleware,
    requireScope = requireAuthMiddleware.requireScope,
    csrf = requirePanelCsrf,
    issueCsrf = issuePanelCsrfToken,
    routeLogger = logger,
} = {}) {
    if (typeof requireAuth !== 'function') {
        throw new TypeError('Topology transfer drafts router requires authentication');
    }
    if (typeof requireScope !== 'function') {
        throw new TypeError('Topology transfer drafts router requires scope authorization');
    }
    if (typeof csrf !== 'function' || typeof issueCsrf !== 'function') {
        throw new TypeError('Topology transfer drafts router requires CSRF protection');
    }

    const transferService = service ?? createService(models);
    if (!transferService || typeof transferService !== 'object') {
        throw new TypeError('Topology transfer drafts router requires a service');
    }

    const router = express.Router();
    const readScope = requireScope('nodes:read');
    const writeScope = requireScope('nodes:write');
    const sessionWriteCsrf = (req, res, next) => (
        req.apiKey ? next() : csrf(req, res, next)
    );

    router.get('/export', requireAuth, readScope, async (req, res) => {
        try {
            const document = await transferService.exportCurrentTopology();
            return res.json(canonicalTransferDocument(document, TRANSFER_KIND));
        } catch (error) {
            return sendError(res, error, 'Export current topology', routeLogger);
        }
    });

    router.post('/export', requireAuth, writeScope, sessionWriteCsrf, async (req, res) => {
        try {
            const draft = await transferService.createExportDraft({ name: req.body?.name });
            return res.status(201).json(publicDraft(draft));
        } catch (error) {
            return sendError(res, error, 'Create export draft', routeLogger);
        }
    });

    router.post('/import', requireAuth, writeScope, sessionWriteCsrf, async (req, res) => {
        try {
            const draft = await transferService.importTopologyDraft({
                name: req.body?.name,
                document: req.body?.document,
            });
            return res.status(201).json(publicDraft(draft));
        } catch (error) {
            return sendError(res, error, 'Import topology draft', routeLogger);
        }
    });

    router.get('/drafts', requireAuth, readScope, async (req, res) => {
        try {
            const drafts = await transferService.listDrafts();
            return res.json((drafts || []).map(draft => publicDraft(draft, {
                includeDocument: false,
            })));
        } catch (error) {
            return sendError(res, error, 'List drafts', routeLogger);
        }
    });

    router.get('/drafts/:draftId', requireAuth, readScope, async (req, res) => {
        try {
            return res.json(publicDraft(await transferService.getDraft(req.params.draftId)));
        } catch (error) {
            return sendError(res, error, 'Read draft', routeLogger);
        }
    });

    router.get('/csrf-token', requireAuth, readScope, (req, res) => {
        if (req.apiKey) return res.json({ csrfRequired: false });
        try {
            return res.json({
                csrfRequired: true,
                csrfToken: issueCsrf(req),
            });
        } catch (error) {
            return sendError(res, error, 'Issue CSRF token', routeLogger);
        }
    });

    return router;
}

const router = createTopologyTransferDraftsRouter();

module.exports = router;
module.exports.DEFAULT_MODELS = DEFAULT_MODELS;
module.exports.ERROR_STATUS_BY_CODE = ERROR_STATUS_BY_CODE;
module.exports.createTopologyTransferDraftsRouter = createTopologyTransferDraftsRouter;
module.exports.publicDraft = publicDraft;
module.exports.sendError = sendError;
