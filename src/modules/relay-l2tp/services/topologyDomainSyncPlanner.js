'use strict';

/**
 * Topology domain sync planner: reusable partition/planner for the manual
 * "Sync" operation across multiple independent topology domains.
 *
 * The legacy deploy path composes ONE connected component per operation and
 * rejects multi-domain graphs; this planner instead partitions the desired
 * graph into domains (connected components) and plans each one separately,
 * so a manual Sync can diagnose/reconcile every domain in a single pass
 * without an unrelated incomplete or pending link blocking healthy domains.
 *
 * The planner is pure: it takes an already pinned snapshot plus hydrated
 * node/link metadata and returns a frozen per-domain report. Route and
 * coordinator wiring (HTTP API, operation records, worker dispatch) is the
 * integration layer's responsibility.
 *
 * Deployed baseline: links carry a per-link deploy `status`
 * ('pending'|'deployed'|'online'|'offline'|'error'). Only confirmed-deployed
 * links form the baseline partition; draft/pending links are still planned
 * (and diagnosed) in the desired partition but never enter the baseline.
 * Legacy rows without a status are treated as deployed to preserve
 * pre-domain behavior.
 */

const {
    computeTopologyDomains,
    sliceTopologyToDomain,
} = require('../domain/topologyDomains');
const { validateTopology } = require('../domain/topologyValidator');
const { compileTopology } = require('../domain/topologyCompiler');
const {
    projectGroups,
    projectLinks,
    projectNodes,
} = require('../domain/topologyDraft');
const {
    composeFrozenTopologyDeploymentPlan,
} = require('./frozenTopologyDeploymentPlanComposer');

const DEPLOYED_LINK_STATUSES = Object.freeze(['deployed', 'online']);
const SAFE_VALIDATION_ERROR_FIELDS = Object.freeze([
    'code',
    'groupId',
    'pathKey',
    'linkId',
    'nodeId',
    'sourceNodeId',
    'targetNodeId',
]);

class TopologyDomainSyncPlannerError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyDomainSyncPlannerError';
        this.code = code;
        Object.assign(this, details);
    }
}

/**
 * Default baseline membership policy: a link belongs to the deployed
 * baseline only when it is active and confirmed deployed. Links without any
 * status predate per-link deploy tracking and count as deployed.
 */
function defaultIsDeployedLink(link) {
    if (link?.active === false) return false;
    if (link?.status === undefined || link?.status === null) return true;
    return DEPLOYED_LINK_STATUSES.includes(String(link.status));
}

/** Deterministic per-domain scope key for revision fencing/idempotency. */
function domainScopeKey(topologyRevision, domainKey) {
    return `topology:${topologyRevision}:domain:${domainKey}`;
}

function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
}

function compareIds(left, right) {
    return left.localeCompare(right, 'en');
}

function projectTopology(snapshot) {
    return {
        nodes: projectNodes(snapshot.nodes)
            .sort((left, right) => compareIds(left.id, right.id)),
        links: projectLinks(snapshot.links)
            .sort((left, right) => compareIds(left.id, right.id)),
        groups: projectGroups(snapshot.groups)
            .sort((left, right) => compareIds(left._id, right._id)),
    };
}

function sanitizeValidationErrors(errors) {
    const sanitized = (Array.isArray(errors) ? errors : []).map(error => {
        const projected = {};
        for (const field of SAFE_VALIDATION_ERROR_FIELDS) {
            if (error?.[field] !== undefined) projected[field] = error[field];
        }
        return projected;
    }).filter(error => typeof error.code === 'string');
    if (sanitized.length === 0) {
        sanitized.push({ code: 'INVALID_TOPOLOGY' });
    }
    return sanitized;
}

function publicDomain(domain) {
    return {
        key: domain.key,
        label: domain.label,
        nodeIds: [...domain.nodeIds],
        linkIds: [...domain.linkIds],
        portals: [...domain.portals],
        relays: [...domain.relays],
        bridges: [...domain.bridges],
    };
}

function composeFailure(error) {
    return {
        code: typeof error?.code === 'string' ? error.code : 'DOMAIN_PLAN_FAILED',
        message: typeof error?.message === 'string' && error.message.length > 0
            ? error.message
            : 'The domain deployment plan could not be composed',
    };
}

class TopologyDomainSyncPlanner {
    constructor({
        validator = validateTopology,
        compiler = compileTopology,
        composePlan = composeFrozenTopologyDeploymentPlan,
    } = {}) {
        if (typeof validator !== 'function' || typeof compiler !== 'function'
            || typeof composePlan !== 'function') {
            throw new TypeError('Topology domain sync planner requires callable policies');
        }
        this.validator = validator;
        this.compiler = compiler;
        this.composePlan = composePlan;
    }

    /**
     * Partition the desired graph into domains and plan each one.
     *
     * @param {object} input
     * @param {object} input.snapshot - pinned snapshot {revision, nodes, links, groups}
     * @param {Array}  input.nodeMetadata - hydrated node metadata (all domains)
     * @param {Array}  input.linkMetadata - hydrated link metadata (all domains)
     * @param {number} [input.expectedTopologyRevision] - optional revision fence
     * @param {Function} [input.isDeployedLink] - baseline membership policy
     * @returns {object} frozen report:
     *   { topologyRevision, status: 'ready'|'partial'|'blocked'|'empty',
     *     domains: [ per-domain planned|blocked entries sorted by key ],
     *     baseline: { linkIds, domains } }
     */
    planManualSync({
        snapshot,
        nodeMetadata = [],
        linkMetadata = [],
        expectedTopologyRevision,
        isDeployedLink = defaultIsDeployedLink,
    } = {}) {
        if (!snapshot || typeof snapshot !== 'object'
            || !Array.isArray(snapshot.nodes) || !Array.isArray(snapshot.links)
            || !Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0) {
            throw new TopologyDomainSyncPlannerError(
                'INVALID_TOPOLOGY_SNAPSHOT',
                'A pinned topology snapshot with a revision, nodes and links is required',
            );
        }
        if (typeof isDeployedLink !== 'function'
            || !Array.isArray(nodeMetadata) || !Array.isArray(linkMetadata)) {
            throw new TopologyDomainSyncPlannerError(
                'INVALID_TOPOLOGY_SNAPSHOT',
                'Hydrated node/link metadata arrays and a link policy are required',
            );
        }
        const topologyRevision = snapshot.revision;
        if (expectedTopologyRevision !== undefined) {
            if (!Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0) {
                throw new TopologyDomainSyncPlannerError(
                    'INVALID_TOPOLOGY_REVISION',
                    'expectedTopologyRevision must be a non-negative safe integer',
                    { expectedTopologyRevision },
                );
            }
            if (expectedTopologyRevision !== topologyRevision) {
                throw new TopologyDomainSyncPlannerError(
                    'STALE_TOPOLOGY_REVISION',
                    'The topology revision changed before the sync could be planned',
                    { expectedTopologyRevision, topologyRevision },
                );
            }
        }

        const topology = projectTopology(snapshot);

        // Deployed baseline: only confirmed-deployed links. A pending draft
        // hop must not redefine what "currently deployed" means.
        const baselineLinks = projectLinks(
            snapshot.links.filter(link => link.active !== false && isDeployedLink(link)),
        ).sort((left, right) => compareIds(left.id, right.id));
        const baselineDomains = computeTopologyDomains({
            nodes: topology.nodes,
            links: baselineLinks,
        }).map(publicDomain);

        const domains = computeTopologyDomains({
            nodes: topology.nodes,
            links: topology.links,
        }).map(domain => this.planDomain({
            topology,
            domain,
            nodeMetadata,
            linkMetadata,
            topologyRevision,
        }));

        const planned = domains.filter(domain => domain.status === 'planned').length;
        const status = domains.length === 0 ? 'empty'
            : planned === domains.length ? 'ready'
                : planned > 0 ? 'partial'
                    : 'blocked';

        return deepFreeze({
            topologyRevision,
            status,
            domains,
            baseline: {
                linkIds: baselineLinks.map(link => link.id),
                domains: baselineDomains,
            },
        });
    }

    planDomain({ topology, domain, nodeMetadata, linkMetadata, topologyRevision }) {
        const base = publicDomain(domain);
        const sliced = sliceTopologyToDomain(topology, domain);

        const validation = this.validator(sliced);
        if (validation?.valid !== true) {
            return { ...base, status: 'blocked', errors: sanitizeValidationErrors(validation?.errors) };
        }
        const compiledTopology = this.compiler({ ...sliced, healthByPathKey: {} });
        if (compiledTopology?.valid !== true) {
            return { ...base, status: 'blocked', errors: sanitizeValidationErrors(compiledTopology?.errors) };
        }

        try {
            const plan = this.composePlan({
                snapshot: sliced,
                nodeMetadata,
                linkMetadata,
                compiledTopology,
            });
            return {
                ...base,
                status: 'planned',
                mode: plan.mode,
                revision: topologyRevision,
                scope: { domainKey: domain.key, topologyRevision },
                scopeKey: domainScopeKey(topologyRevision, domain.key),
                plan,
            };
        } catch (error) {
            // A structurally broken domain (incomplete chain, missing
            // metadata, ambiguous egress) is diagnosed per-domain; it never
            // aborts the planning of unrelated domains.
            return { ...base, status: 'blocked', errors: [composeFailure(error)] };
        }
    }
}

module.exports = {
    DEPLOYED_LINK_STATUSES,
    TopologyDomainSyncPlanner,
    TopologyDomainSyncPlannerError,
    defaultIsDeployedLink,
    domainScopeKey,
};
