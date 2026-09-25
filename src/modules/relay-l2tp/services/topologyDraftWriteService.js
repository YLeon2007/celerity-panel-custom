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
        recalculateRoles,
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
        this.recalculateRoles = recalculateRoles;
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
        // Creating or updating a link may bring new nodes into the chain, so
        // their cascade roles are assigned from the resulting graph. Deleting
        // a link must NEVER recalculate roles: the remaining graph is
        // incomplete by definition (e.g. portal→relay after relay→bridge is
        // removed would make the relay look like a bridge). Roles are
        // operator state and survive link removal until reassigned explicitly
        // or by a new link.
        if (
            result !== null
            && typeof this.recalculateRoles === 'function'
            && (mutation?.kind === 'link.create' || mutation?.kind === 'link.update')
        ) {
            await this.recalculateRoles();
        }
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

// Mirrors cascadeService._updateNodeRoles: a node's cascade role derives
// from the links it participates in. Deleting links never downgrades a node
// to standalone — roles are operator state and stay until reassigned
// explicitly or by a new link.
async function recalculateNodeRoles(HyNode, CascadeLink) {
    const links = await CascadeLink.find({ active: true }).lean();
    const portalSet = new Set(links.map(link => String(link.portalNode)));
    const bridgeSet = new Set(links.map(link => String(link.bridgeNode)));
    const allNodes = await HyNode.find({ active: true, type: { $ne: 'virtual' } })
        .select('_id cascadeRole')
        .lean();
    const bulkOps = [];
    for (const node of allNodes) {
        const id = String(node._id);
        const isPortal = portalSet.has(id);
        const isBridge = bridgeSet.has(id);
        let role = node.cascadeRole || 'standalone';
        if (isPortal && isBridge) role = 'relay';
        else if (isPortal) role = 'portal';
        else if (isBridge) role = 'bridge';
        if (node.cascadeRole !== role) {
            bulkOps.push({
                updateOne: {
                    filter: { _id: node._id },
                    update: { $set: { cascadeRole: role } },
                },
            });
        }
    }
    if (bulkOps.length > 0) {
        await HyNode.bulkWrite(bulkOps, { ordered: false });
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
    const recalculateRoles = (HyNode && CascadeLink)
        ? () => recalculateNodeRoles(HyNode, CascadeLink)
        : undefined;
    return new TopologyDraftWriteService({
        repository,
        validator,
        compiler,
        ...(recalculateRoles ? { recalculateRoles } : {}),
    });
}

module.exports = {
    createTopologyDraftWriteService,
    TopologyDraftWriteError,
    TopologyDraftWriteService,
    recalculateNodeRoles,
};
