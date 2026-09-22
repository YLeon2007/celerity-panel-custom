'use strict';

const { randomUUID } = require('node:crypto');

const {
    IMPORT_DRAFT_KIND,
    TopologyTransferValidationError,
    assertNoSensitiveMaterial,
    canonicalizeTopologyTransfer,
    exportTopologyTransfer,
} = require('../domain/topologyTransfer');
const { compileTopology } = require('../domain/topologyCompiler');
const { validateTopology } = require('../domain/topologyValidator');
const {
    TopologyTransferDraftRepository,
} = require('../repositories/topologyTransferDraftRepository');

const DRAFT_STATUS = 'DRAFT';
const PUBLIC_DRAFT_FIELDS = Object.freeze([
    'draftId',
    'status',
    'source',
    'name',
    'document',
    'counts',
    'createdAt',
]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

class TopologyTransferDraftNotFoundError extends Error {
    constructor() {
        super('Topology transfer draft not found');
        this.name = 'TopologyTransferDraftNotFoundError';
        this.code = 'TOPOLOGY_TRANSFER_DRAFT_NOT_FOUND';
    }
}

class TopologyTransferDraftInputError extends Error {
    constructor(message, details = []) {
        super(message);
        this.name = 'TopologyTransferDraftInputError';
        this.code = 'INVALID_TOPOLOGY_TRANSFER_DRAFT';
        this.details = details;
    }
}

function normalizeName(value, fallback) {
    if (value === undefined) return fallback;
    if (typeof value !== 'string' || value.trim() === '') {
        throw new TopologyTransferDraftInputError('name must be a non-empty string');
    }
    const name = value.trim();
    if (name.length > 120) {
        throw new TopologyTransferDraftInputError('name must not exceed 120 characters');
    }
    try {
        assertNoSensitiveMaterial({ name });
    } catch (error) {
        throw new TopologyTransferDraftInputError(error.message);
    }
    return name;
}

function countsFor(document) {
    return {
        nodes: document.topology.nodes.length,
        links: document.topology.links.length,
        routeGroups: document.topology.routeGroups.length,
        relayStates: document.topology.relayStates.length,
    };
}

function compilerInput(document) {
    return {
        nodes: document.topology.nodes.map(node => ({
            id: node.key,
            role: node.role,
        })),
        links: document.topology.links.map(link => ({
            id: link.key,
            source: link.source,
            target: link.target,
            mode: link.mode,
            active: link.active,
        })),
        groups: document.topology.routeGroups.map(group => ({
            id: group.key,
            _id: group.key,
            mode: group.mode,
            strategy: group.strategy,
            paths: group.paths.map(path => ({
                pathKey: path.pathKey,
                linkIds: [...path.links],
                priority: path.priority,
                enabled: path.enabled,
            })),
        })),
    };
}

function validateDocumentTopology(document, {
    validator = validateTopology,
    compiler = compileTopology,
} = {}) {
    const input = compilerInput(document);
    const nodesByKey = new Map(document.topology.nodes.map(node => [node.key, node]));
    const transferErrors = document.topology.relayStates
        .filter(state => nodesByKey.get(state.node)?.role !== 'relay')
        .map(state => ({
            code: 'RELAY_STATE_NODE_NOT_RELAY',
            nodeKey: state.node,
        }));
    const validation = validator(input);
    const compilation = compiler(input);
    const errors = [
        ...transferErrors,
        ...(validation?.errors || []),
        ...(compilation?.errors || []),
    ]
        .filter((error, index, values) => (
            values.findIndex(candidate => JSON.stringify(candidate) === JSON.stringify(error)) === index
        ));
    if (transferErrors.length > 0 || !validation?.valid || !compilation?.valid) {
        throw new TopologyTransferDraftInputError('Topology transfer draft is invalid', errors);
    }
    return document;
}

function projectDraft(value, { includeDocument = true } = {}) {
    const projected = {};
    for (const field of PUBLIC_DRAFT_FIELDS) {
        if (!includeDocument && field === 'document') continue;
        if (value?.[field] !== undefined) projected[field] = value[field];
    }
    assertNoSensitiveMaterial(projected);
    return projected;
}

class TopologyTransferDraftService {
    constructor({
        repository,
        idFactory = randomUUID,
        validator = validateTopology,
        compiler = compileTopology,
    } = {}) {
        if (!repository || typeof repository !== 'object') {
            throw new TypeError('Topology transfer draft service requires a repository');
        }
        if (typeof idFactory !== 'function') {
            throw new TypeError('Topology transfer draft service requires an id factory');
        }
        if (typeof validator !== 'function' || typeof compiler !== 'function') {
            throw new TypeError('Topology transfer draft service requires topology validation');
        }
        this.repository = repository;
        this.idFactory = idFactory;
        this.validator = validator;
        this.compiler = compiler;
    }

    async buildCurrentExport() {
        if (typeof this.repository.loadCurrentTopology !== 'function') {
            throw new TypeError('Topology transfer draft repository cannot load current topology');
        }
        const current = await this.repository.loadCurrentTopology();
        const document = exportTopologyTransfer(current);
        return validateDocumentTopology(document, {
            validator: this.validator,
            compiler: this.compiler,
        });
    }

    exportCurrentTopology() {
        return this.buildCurrentExport();
    }

    async listDrafts() {
        if (typeof this.repository.listDrafts !== 'function') {
            throw new TypeError('Topology transfer draft repository cannot list drafts');
        }
        const drafts = await this.repository.listDrafts();
        return (drafts || []).map(draft => projectDraft(draft, { includeDocument: false }));
    }

    async getDraft(draftId) {
        if (typeof draftId !== 'string' || !UUID_PATTERN.test(draftId)) {
            throw new TopologyTransferDraftInputError('draftId must be a UUID');
        }
        if (typeof this.repository.findDraftById !== 'function') {
            throw new TypeError('Topology transfer draft repository cannot read drafts');
        }
        const draft = await this.repository.findDraftById(draftId);
        if (!draft) throw new TopologyTransferDraftNotFoundError();
        return projectDraft(draft);
    }

    async createExportDraft({ name } = {}) {
        const document = await this.buildCurrentExport();
        return this.persistDraft({
            source: 'export',
            name: normalizeName(name, 'Current topology export'),
            document,
        });
    }

    async importTopologyDraft({ name, document: input } = {}) {
        let document;
        try {
            document = canonicalizeTopologyTransfer(input, { kind: IMPORT_DRAFT_KIND });
            validateDocumentTopology(document, {
                validator: this.validator,
                compiler: this.compiler,
            });
        } catch (error) {
            if (error instanceof TopologyTransferDraftInputError) throw error;
            if (error instanceof TopologyTransferValidationError) {
                throw new TopologyTransferDraftInputError(error.message, error.details);
            }
            throw error;
        }
        return this.persistDraft({
            source: 'import',
            name: normalizeName(name, 'Imported topology'),
            document,
        });
    }

    async persistDraft({ source, name, document }) {
        if (typeof this.repository.createDraft !== 'function') {
            throw new TypeError('Topology transfer draft repository cannot create drafts');
        }
        const draft = {
            draftId: this.idFactory(),
            status: DRAFT_STATUS,
            source,
            name,
            document,
            counts: countsFor(document),
        };
        const created = await this.repository.createDraft(draft);
        return projectDraft(created);
    }
}

function createTopologyTransferDraftService({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    RelayL2tpState,
    RelayL2tpTopologyTransferDraft,
    Repository = TopologyTransferDraftRepository,
    idFactory,
    validator,
    compiler,
} = {}) {
    const repository = new Repository({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        RelayL2tpState,
        RelayL2tpTopologyTransferDraft,
    });
    return new TopologyTransferDraftService({
        repository,
        ...(idFactory === undefined ? {} : { idFactory }),
        ...(validator === undefined ? {} : { validator }),
        ...(compiler === undefined ? {} : { compiler }),
    });
}

module.exports = {
    DRAFT_STATUS,
    PUBLIC_DRAFT_FIELDS,
    TopologyTransferDraftInputError,
    TopologyTransferDraftNotFoundError,
    TopologyTransferDraftService,
    TopologyTransferValidationError,
    compilerInput,
    countsFor,
    createTopologyTransferDraftService,
    normalizeName,
    projectDraft,
    validateDocumentTopology,
};
