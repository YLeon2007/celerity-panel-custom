'use strict';

const { buildCandidate, TopologyDraftError } = require('../domain/topologyDraft');
const { compileTopology } = require('../domain/topologyCompiler');
const { validateTopology } = require('../domain/topologyValidator');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');

class TopologyDraftWriteError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyDraftWriteError';
        this.code = code;
        Object.assign(this, details);
    }
}

function assertRevision(revision) {
    if (!Number.isSafeInteger(revision) || revision < 0) {
        throw new TopologyDraftWriteError(
            'INVALID_TOPOLOGY_REVISION',
            'An explicit non-negative integer topology revision is required',
            { expectedTopologyRevision: revision },
        );
    }
}

class TopologyDraftWriteService {
    constructor({
        repository,
        validator = validateTopology,
        compiler = compileTopology,
    } = {}) {
        if (!repository || typeof repository.commitDraft !== 'function') {
            throw new TypeError('Topology draft writes require repository.commitDraft');
        }
        if (typeof validator !== 'function') {
            throw new TypeError('Topology draft writes require a topology validator');
        }
        if (typeof compiler !== 'function') {
            throw new TypeError('Topology draft writes require a topology compiler');
        }
        this.repository = repository;
        this.validator = validator;
        this.compiler = compiler;
    }

    async commit(expectedTopologyRevision, mutation) {
        assertRevision(expectedTopologyRevision);
        const result = await this.repository.commitDraft({
            expectedRevision: expectedTopologyRevision,
            prepare: async snapshot => {
                let prepared;
                try {
                    prepared = buildCandidate(snapshot, mutation);
                } catch (error) {
                    if (error instanceof TopologyDraftError) {
                        const details = { ...error };
                        delete details.name;
                        delete details.code;
                        throw new TopologyDraftWriteError(error.code, error.message, details);
                    }
                    throw error;
                }
                const validation = this.validator(prepared.candidate);
                if (!validation?.valid) {
                    throw new TopologyDraftWriteError(
                        'INVALID_TOPOLOGY_DRAFT',
                        'The candidate topology draft is invalid',
                        { errors: validation?.errors || [] },
                    );
                }
                const compiled = this.compiler({
                    ...prepared.candidate,
                    healthByPathKey: {},
                });
                if (!compiled?.valid) {
                    throw new TopologyDraftWriteError(
                        'INVALID_TOPOLOGY_DRAFT',
                        'The candidate topology draft could not be compiled',
                        { errors: compiled?.errors || [] },
                    );
                }
                return { mutation: prepared.mutation };
            },
        });
        // Cascade roles are pure operator state. The panel NEVER rewrites a
        // node's role automatically — not on link create, update or delete.
        return result;
    }

    createLink({ expectedTopologyRevision, link } = {}) {
        return this.commit(expectedTopologyRevision, {
            kind: 'link.create',
            document: { ...link },
        });
    }

    updateLink({ expectedTopologyRevision, linkId, changes } = {}) {
        const { _id, id, ...safeChanges } = changes || {};
        return this.commit(expectedTopologyRevision, {
            kind: 'link.update',
            id: linkId,
            changes: safeChanges,
        });
    }

    deleteLink({ expectedTopologyRevision, linkId } = {}) {
        return this.commit(expectedTopologyRevision, {
            kind: 'link.delete',
            id: linkId,
        });
    }

    createRouteGroup({ expectedTopologyRevision, routeGroup } = {}) {
        return this.commit(expectedTopologyRevision, {
            kind: 'group.create',
            document: { ...routeGroup },
        });
    }

    updateRouteGroup({ expectedTopologyRevision, routeGroupId, changes } = {}) {
        const { _id, id, ...safeChanges } = changes || {};
        return this.commit(expectedTopologyRevision, {
            kind: 'group.update',
            id: routeGroupId,
            changes: safeChanges,
        });
    }

    deleteRouteGroup({ expectedTopologyRevision, routeGroupId } = {}) {
        return this.commit(expectedTopologyRevision, {
            kind: 'group.delete',
            id: routeGroupId,
        });
    }
}

function createTopologyDraftWriteService({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    CascadeTopologyState,
    RelayL2tpState,
    transactionRunner,
    Repository = TopologyDraftRepository,
    validator = validateTopology,
    compiler = compileTopology,
} = {}) {
    const repository = new Repository({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        CascadeTopologyState,
        RelayL2tpState,
        transactionRunner,
    });
    return new TopologyDraftWriteService({
        repository,
        validator,
        compiler,
    });
}

module.exports = {
    createTopologyDraftWriteService,
    TopologyDraftWriteError,
    TopologyDraftWriteService,
};
