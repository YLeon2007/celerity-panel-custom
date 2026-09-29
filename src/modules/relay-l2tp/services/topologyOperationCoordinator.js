'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { compileTopology } = require('../domain/topologyCompiler');
const {
    projectGroups,
    projectLinks,
    projectNodes,
} = require('../domain/topologyDraft');
const { validateTopology } = require('../domain/topologyValidator');
const { computeTopologyDomains } = require('../domain/topologyDomains');
const { deriveReplacementTopology } = require('../domain/topologyReplacement');
const {
    TEST_TOPOLOGY_HOST_IDENTITY,
    TEST_TOPOLOGY_TARGET,
} = require('./topologyOperationPlanMaterializer');

const ACTIVE_OPERATION_STATUSES = new Set([
    'queued',
    'preparing',
    'committing',
    'rolling_back',
]);
const OPERATION_STATUSES = new Set([
    ...ACTIVE_OPERATION_STATUSES,
    'succeeded',
    'failed',
    'rolled_back',
]);
const NODE_STATES = new Set(['pending', 'prepared', 'committed', 'failed', 'rolled_back']);
const SAFE_VALIDATION_ERROR_FIELDS = Object.freeze([
    'code',
    'path',
    'groupId',
    'pathKey',
    'linkId',
    'nodeId',
    'sourceNodeId',
    'targetNodeId',
    'groupMode',
    'linkMode',
    'modes',
]);

class TopologyOperationCoordinatorError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyOperationCoordinatorError';
        this.code = code;
        Object.assign(this, details);
    }
}

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
}

function entityId(value) {
    const id = value !== null && typeof value === 'object'
        ? value._id ?? value.id ?? value.node
        : value;
    return id === null || id === undefined ? '' : String(id);
}

function idFromIdempotencyKey(idempotencyKey) {
    return createHash('sha256').update(idempotencyKey).digest('hex').slice(0, 24);
}

const SCOPED_OPERATION_KINDS = new Set(['link.apply', 'domain.reconcile', 'link.replace']);
// Baseline members of a scoped operation must be physically applied already:
// deployed/online are fully confirmed, staged means a link.apply finished
// applying the link to its endpoints but the component is not client-ready
// yet. Anything else (pending, error, offline) is never a valid baseline.
const CONFIRMED_BASELINE_LINK_STATUSES = new Set(['deployed', 'online', 'staged']);

function normalizeOperationScope(scope) {
    if (scope === undefined) return null;
    if (!scope || typeof scope !== 'object' || Array.isArray(scope)
        || !Object.keys(scope).every(key => (scope.kind === 'link.replace'
            ? ['kind', 'linkId', 'linkIds', 'oldLinkId', 'groupId', 'pathKey']
            : ['kind', 'linkId', 'linkIds']).includes(key))
        || !SCOPED_OPERATION_KINDS.has(scope.kind)
        || typeof scope.linkId !== 'string' || scope.linkId.length === 0
        || !Array.isArray(scope.linkIds) || scope.linkIds.length === 0
        || scope.linkIds.some(linkId => typeof linkId !== 'string' || linkId.length === 0)
        || new Set(scope.linkIds).size !== scope.linkIds.length
        || !scope.linkIds.includes(scope.linkId)
        || (scope.kind === 'link.replace' && (
            !['oldLinkId', 'groupId', 'pathKey'].every(key =>
                typeof scope[key] === 'string' && scope[key].length > 0)
            || scope.oldLinkId === scope.linkId
            || scope.linkIds.includes(scope.oldLinkId)))) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_REQUEST',
            'A scoped topology operation requires kind, a linkId contained in unique linkIds',
        );
    }
    return {
        kind: scope.kind,
        linkId: scope.linkId,
        linkIds: [...scope.linkIds].sort((left, right) => left.localeCompare(right, 'en')),
        ...(scope.kind === 'link.replace' ? {
            oldLinkId: scope.oldLinkId, groupId: scope.groupId, pathKey: scope.pathKey,
        } : {}),
    };
}

function assertQueueInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || !Object.hasOwn(input, 'expectedTopologyRevision')
        || !Object.keys(input).every(key => ['expectedTopologyRevision', 'scope'].includes(key))) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_REQUEST',
            'Only expectedTopologyRevision and an optional scope are accepted',
        );
    }
    if (!Number.isSafeInteger(input.expectedTopologyRevision)
        || input.expectedTopologyRevision < 0) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
            { expectedTopologyRevision: input.expectedTopologyRevision },
        );
    }
    return normalizeOperationScope(input.scope);
}

function sanitizeValidationErrors(errors) {
    return (Array.isArray(errors) ? errors : []).map(error => {
        const projected = {};
        for (const field of SAFE_VALIDATION_ERROR_FIELDS) {
            if (error?.[field] !== undefined) projected[field] = error[field];
        }
        return projected;
    });
}

function safeQueueError(error, operationId, expectedTopologyRevision) {
    if (error instanceof TopologyOperationCoordinatorError) return error;
    if (error?.code === 'TOPOLOGY_REPLACEMENT_RESERVED') {
        return new TopologyOperationCoordinatorError(
            'TOPOLOGY_REPLACEMENT_RESERVED',
            'A topology replacement owns the deployment pin fence',
            { operationId, expectedTopologyRevision },
        );
    }
    if (error?.code === 'STALE_TOPOLOGY_REVISION') {
        return new TopologyOperationCoordinatorError(
            'STALE_TOPOLOGY_REVISION',
            'The topology revision changed before the operation could be pinned',
            {
                operationId,
                expectedTopologyRevision,
                topologyRevision: Number.isSafeInteger(error.topologyRevision)
                    ? error.topologyRevision
                    : null,
            },
        );
    }
    if (error?.name === 'TopologyReplacementError') {
        return new TopologyOperationCoordinatorError(
            'INVALID_TOPOLOGY_DEPLOYMENT',
            'The pinned replacement is not a complete installed path',
            { operationId, causeCode: error.code },
        );
    }
    // Plan validation failures (incomplete chain, bad roles, unsupported
    // metadata) are client-visible 422s, not opaque 500 queue failures.
    if (error?.name === 'FrozenTopologyDeploymentPlanError') {
        return new TopologyOperationCoordinatorError(
            'INVALID_TOPOLOGY_DEPLOYMENT',
            error.message || 'The pinned topology is invalid',
            {
                operationId,
                expectedTopologyRevision,
                causeCode: error?.code,
            },
        );
    }
    return new TopologyOperationCoordinatorError(
        'TOPOLOGY_OPERATION_QUEUE_FAILED',
        'The topology operation could not be queued',
        {
            operationId,
            expectedTopologyRevision,
        },
    );
}

function projectTopology(snapshot) {
    return {
        nodes: projectNodes(snapshot.nodes)
            .sort((left, right) => left.id.localeCompare(right.id, 'en')),
        links: projectLinks(snapshot.links)
            .sort((left, right) => left.id.localeCompare(right.id, 'en')),
        groups: projectGroups(snapshot.groups)
            .sort((left, right) => left._id.localeCompare(right._id, 'en')),
    };
}

// Scoped reconcile: the effective graph is exactly the requested link plus the
// links the caller proved deployed. Anything else — in particular preexisting
// pending links — must stay out of the plan, even on shared relays.
function applyScopeToTopology(topology, scope, operationId, rawLinks = []) {
    const wanted = new Set(scope.linkIds);
    const available = new Set(topology.links.map(link => link.id));
    const rawById = new Map(rawLinks.map(link => [entityId(link._id ?? link.id), link]));
    if (scope.kind === 'domain.reconcile') {
        const anchor = rawById.get(scope.linkId);
        if (!CONFIRMED_BASELINE_LINK_STATUSES.has(anchor?.status)) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'A domain Sync requires a confirmed applied anchor',
                { operationId, causeCode: 'SCOPE_LINK_UNCONFIRMED' },
            );
        }
        // Recompute membership from the pinned revision, not the route's
        // earlier read. Pending links do not join components; omitted or
        // foreign confirmed links make caller-supplied scope ambiguous.
        const confirmed = topology.links.filter(link =>
            CONFIRMED_BASELINE_LINK_STATUSES.has(rawById.get(link.id)?.status));
        const domain = computeTopologyDomains({ nodes: topology.nodes, links: confirmed })
            .find(component => component.linkIds.includes(scope.linkId));
        if (!domain || domain.linkIds.length !== wanted.size
            || domain.linkIds.some(linkId => !wanted.has(linkId))) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'The selected domain scope does not match the pinned topology',
                { operationId, causeCode: 'SCOPE_DOMAIN_AMBIGUOUS' },
            );
        }
    }
    for (const linkId of wanted) {
        if (!available.has(linkId)) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'A scoped link is missing from the pinned topology',
                { operationId, causeCode: 'SCOPE_LINK_MISSING', linkId },
            );
        }
        // A request may activate only its own explicit link. Every other
        // member must already be confirmed deployed; never trust caller-supplied
        // linkIds to pull an old active/pending edge into a new candidate.
        if (linkId !== scope.linkId) {
            const status = rawById.get(linkId)?.status;
            if (!CONFIRMED_BASELINE_LINK_STATUSES.has(status)) {
                throw new TopologyOperationCoordinatorError(
                    'INVALID_TOPOLOGY_DEPLOYMENT',
                    'A scoped baseline link is not confirmed deployed',
                    { operationId, causeCode: 'SCOPE_LINK_UNCONFIRMED', linkId },
                );
            }
        }
    }
    const links = topology.links.filter(link => wanted.has(link.id));
    const nodeIds = new Set(links.flatMap(link => [link.source, link.target]));
    const nodes = topology.nodes.filter(node => nodeIds.has(node.id));
    const groups = [];
    for (const group of topology.groups) {
        const referenced = new Set(
            (group.paths || []).flatMap(path => path.linkIds || []),
        );
        const inside = [...referenced].filter(linkId => wanted.has(linkId));
        if (inside.length === 0) continue;
        if (inside.length !== referenced.size) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'A route group straddles the scoped component boundary',
                { operationId, causeCode: 'SCOPE_GROUP_CONFLICT', groupId: group._id },
            );
        }
        groups.push(group);
    }
    return { nodes, links, groups };
}

function nodeIdsByRef(topology) {
    const nodes = new Map(topology.nodes.map(node => [node.id, node]));
    const outgoing = new Map();
    const incoming = new Set();
    const geoTargets = new Set();
    for (const link of topology.links) {
        if (!nodes.has(link.source) || !nodes.has(link.target)) {
            throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Invalid node ref endpoint');
        }
        if (link.geo === true) {
            if (geoTargets.has(link.target)) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Ambiguous geo node ref');
            }
            geoTargets.add(link.target);
        } else {
            if (outgoing.has(link.source)) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Ambiguous node ref path');
            }
            outgoing.set(link.source, link.target);
            incoming.add(link.target);
        }
    }
    // Mirror the composer's ordering: portal sources sorted by id, then
    // relays in first-seen portal-path order, then the shared default sink.
    const portals = topology.nodes.filter(node => node.role === 'portal' && outgoing.has(node.id) && !incoming.has(node.id))
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    const paths = portals.map(portal => {
        const path = [];
        const seen = new Set();
        let id = portal.id;
        while (id) {
            if (seen.has(id)) {
                throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Invalid cyclic node ref path');
            }
            seen.add(id);
            path.push(id);
            id = outgoing.get(id);
        }
        return path;
    });
    const fanIn = portals.length > 1;
    const ordered = fanIn
        ? [...portals.map(portal => portal.id), ...paths.flatMap(path => path.slice(1))]
        : (paths[0] || []);
    const visited = new Set();
    const result = new Map();
    let portalIndex = 0;
    let relayIndex = 0;
    for (const id of ordered) {
        if (visited.has(id)) continue;
        visited.add(id);
        const role = nodes.get(id).role;
        const ref = role === 'portal' ? (fanIn ? `portal-${++portalIndex}` : 'portal')
            : role === 'relay' ? `relay-${++relayIndex}` : 'bridge';
        if (result.has(ref)) {
            throw new TopologyOperationCoordinatorError('INVALID_TOPOLOGY_DEPLOYMENT', 'Ambiguous node ref role');
        }
        result.set(ref, id);
    }
    // Composer numbers geo bridge leaves by sorted id, starting at 2.
    const geoBridges = topology.nodes.filter(node => geoTargets.has(node.id) && !visited.has(node.id))
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    geoBridges.forEach((node, index) => result.set(`bridge-${index + 2}`, node.id));
    return result;
}

function operationPlan({ operationId, topologyRevision, priorDeployedRevision, topology, plan }) {
    const idsByRef = nodeIdsByRef(topology);
    const seenRefs = new Set();
    const seenIds = new Set();
    const rolesById = new Map(topology.nodes.map(node => [node.id, node.role]));
    const nodes = plan.nodes.map(node => {
        const nodeId = idsByRef.get(node.nodeRef);
        const candidateHash = node.candidateHash ?? node.candidate?.sha256;
        if (!nodeId || (entityId(node.node) && entityId(node.node) !== nodeId)
            || rolesById.get(nodeId) !== node.role
            || seenRefs.has(node.nodeRef) || seenIds.has(nodeId)
            || typeof candidateHash !== 'string' || candidateHash.length === 0) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'The frozen topology operation plan is invalid',
                { operationId },
            );
        }
        seenRefs.add(node.nodeRef);
        seenIds.add(nodeId);
        return {
            ...node,
            node: nodeId,
            candidateHash,
        };
    });
    return deepFreeze({
        operationId,
        topologyRevision,
        priorDeployedRevision,
        nodes,
    });
}

function projectTopologyOperationStatus(operation = {}) {
    const operationId = entityId(operation.operationId ?? operation._id ?? operation.id);
    const topologyRevision = operation.topologyRevision;
    const status = operation.status;
    const projected = {};
    if (operationId) projected.operationId = operationId;
    if (Number.isSafeInteger(topologyRevision) && topologyRevision >= 0) {
        projected.topologyRevision = topologyRevision;
    }
    if (OPERATION_STATUSES.has(status)) projected.status = status;
    if (Array.isArray(operation.nodes)) {
        projected.nodes = operation.nodes.map(node => ({
            nodeId: entityId(node?.node),
            state: node?.state,
        })).filter(node => node.nodeId && NODE_STATES.has(node.state))
            .sort((left, right) => left.nodeId.localeCompare(right.nodeId, 'en'));
    }
    return projected;
}

class TopologyOperationCoordinator {
    constructor({
        topologyRepository,
        planMaterializer,
        operationRepository,
        operationWorker,
        validator = validateTopology,
        compiler = compileTopology,
        idFactory = idFromIdempotencyKey,
        onWorkerError = () => {},
    } = {}) {
        if (!topologyRepository || typeof topologyRepository.admitTopology !== 'function') {
            throw new TypeError('Topology operation coordinator requires topologyRepository.admitTopology');
        }
        if (!planMaterializer || typeof planMaterializer.materialize !== 'function') {
            throw new TypeError('Topology operation coordinator requires planMaterializer.materialize');
        }
        if (!operationRepository || typeof operationRepository.createFrozen !== 'function') {
            throw new TypeError('Topology operation coordinator requires operationRepository.createFrozen');
        }
        if (operationWorker !== undefined && typeof operationWorker?.run !== 'function') {
            throw new TypeError('Topology operation coordinator requires operationWorker.run');
        }
        if (typeof validator !== 'function' || typeof compiler !== 'function'
            || typeof idFactory !== 'function' || typeof onWorkerError !== 'function') {
            throw new TypeError('Topology operation coordinator requires callable policies');
        }
        this.topologyRepository = topologyRepository;
        this.planMaterializer = planMaterializer;
        this.operationRepository = operationRepository;
        this.operationWorker = operationWorker;
        this.validator = validator;
        this.compiler = compiler;
        this.idFactory = idFactory;
        this.onWorkerError = onWorkerError;
        this.operationsByIdempotencyKey = new Map();
    }

    projectStatus(operation) {
        return projectTopologyOperationStatus(operation);
    }

    async queue(input) {
        const scope = assertQueueInput(input);
        const { expectedTopologyRevision } = input;
        // A scoped reconcile gets its own idempotency key so it can never be
        // collapsed with (or satisfied by) a legacy full-sync operation.
        const idempotencyKey = scope
            ? `topology:${TEST_TOPOLOGY_TARGET}:revision-${expectedTopologyRevision}:${scope.kind}:${scope.linkId}`
                + (scope.kind === 'link.replace'
                    ? `:${createHash('sha256').update(JSON.stringify({
                        groupId: scope.groupId, pathKey: scope.pathKey,
                        oldLinkId: scope.oldLinkId, linkIds: scope.linkIds,
                    })).digest('hex')}` : '')
            : `topology:${TEST_TOPOLOGY_TARGET}:revision-${expectedTopologyRevision}`;
        const existing = this.operationsByIdempotencyKey.get(idempotencyKey);
        if (existing) {
            const settled = await existing.then(operation => operation, () => null);
            if (!settled) {
                this.operationsByIdempotencyKey.delete(idempotencyKey);
            } else if (typeof this.operationRepository.findPublicById === 'function') {
                const persisted = await this.operationRepository.findPublicById(settled.operationId);
                // A live or successful operation satisfies the idempotency key.
                // A terminally failed one (failed/rolled_back) must not block a
                // retry of the same revision — re-queue with a fresh run id.
                if (persisted && persisted.status !== 'failed' && persisted.status !== 'rolled_back') {
                    return existing;
                }
                this.operationsByIdempotencyKey.delete(idempotencyKey);
            } else {
                return existing;
            }
        }

        const queued = this.queueOnce({ expectedTopologyRevision, scope, idempotencyKey });
        this.operationsByIdempotencyKey.set(idempotencyKey, queued);
        try {
            return await queued;
        } catch (error) {
            this.operationsByIdempotencyKey.delete(idempotencyKey);
            throw error;
        }
    }

    deploy(input) {
        return this.queue(input);
    }

    async queueOnce({ expectedTopologyRevision, scope, idempotencyKey }) {
        // Unique run suffix: node-side runner state is keyed by operation id,
        // so a re-queued revision must never reuse a previous operation id.
        const runIdempotencyKey = `${idempotencyKey}:${randomUUID()}`;
        const operationId = entityId(this.idFactory(runIdempotencyKey));
        if (!operationId) {
            throw new TopologyOperationCoordinatorError(
                'TOPOLOGY_OPERATION_QUEUE_FAILED',
                'The topology operation could not be queued',
            );
        }
        let pinned;
        let scopedIdentity;
        let admissionFingerprint;
        let admittedPriorDeployedRevision;
        try {
            pinned = await this.topologyRepository.admitTopology({
                expectedRevision: expectedTopologyRevision,
                prepare: async (snapshot, session) => {
                    // Legacy full-sync finalization marks every active link
                    // deployed. Never let it silently claim an unrelated
                    // pending draft alongside already deployed links.
                    if (!scope) {
                        const active = snapshot.links.filter(link => link.active !== false);
                        const hasPending = active.some(link => link.status === 'pending');
                        const hasConfirmed = active.some(link => link.status === 'deployed'
                            || link.status === 'online' || link.status === 'staged'
                            || link.status == null);
                        if (hasPending && hasConfirmed) {
                            throw new TopologyOperationCoordinatorError(
                                'INVALID_TOPOLOGY_DEPLOYMENT',
                                'Mixed pending and deployed links require an explicit scoped operation',
                                { operationId, causeCode: 'UNCONFIRMED_LINK_IN_FULL_DEPLOY' },
                            );
                        }
                    }
                    const projected = projectTopology(snapshot);
                    // Scoped reconcile: plan only the caller-declared
                    // component (deployed links + the requested link). This
                    // selects the scope of coordination only — it never marks
                    // a link physically applied by itself.
                    const replacement = scope?.kind === 'link.replace'
                        ? deriveReplacementTopology(snapshot, {
                            groupId: scope.groupId, pathKey: scope.pathKey,
                            oldLinkId: scope.oldLinkId, newLinkId: scope.linkId,
                        }) : null;
                    const topology = replacement ? replacement.topology
                        : scope ? applyScopeToTopology(projected, scope, operationId, snapshot.links)
                            : projected;
                    if (scope?.kind === 'link.replace'
                        && (topology.links.length !== scope.linkIds.length
                            || topology.links.some(link => !scope.linkIds.includes(link.id)))) {
                        throw new TopologyOperationCoordinatorError(
                            'INVALID_TOPOLOGY_DEPLOYMENT', 'Replacement scope differs from its pinned graph',
                            { operationId, causeCode: 'SCOPE_DOMAIN_AMBIGUOUS' },
                        );
                    }
                    const validation = this.validator(topology);
                    if (validation?.valid !== true) {
                        throw new TopologyOperationCoordinatorError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The pinned topology is invalid',
                            { operationId, errors: sanitizeValidationErrors(validation?.errors) },
                        );
                    }
                    const compiled = this.compiler({ ...topology, healthByPathKey: {} });
                    if (compiled?.valid !== true) {
                        throw new TopologyOperationCoordinatorError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The pinned topology could not be compiled',
                            { operationId, errors: sanitizeValidationErrors(compiled?.errors) },
                        );
                    }
                    const frozenPlan = await this.planMaterializer.materialize({
                        target: TEST_TOPOLOGY_TARGET,
                        hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
                        operationKind: scope?.kind,
                        session,
                        pinnedSnapshot: deepFreeze({
                            revision: snapshot.revision,
                            topology,
                            compiled,
                        }),
                    });
                    return { topology, frozenPlan,
                        ...(replacement ? { oldPathLinkIds: replacement.oldPathLinkIds,
                            ownerNodeId: replacement.ownerNodeId } : {}) };
                },
                admit: async (admitted, session) => {
                    admittedPriorDeployedRevision = admitted.deployedRevision;
                    const plan = operationPlan({
                        operationId,
                        topologyRevision: admitted.revision,
                        priorDeployedRevision: admitted.deployedRevision,
                        topology: admitted.topology,
                        plan: admitted.frozenPlan,
                    });
                    scopedIdentity = scope
                        ? { kind: scope.kind, linkId: scope.linkId, linkIds: [...scope.linkIds],
                            ...(scope.kind === 'link.apply'
                                ? { staged: admitted.frozenPlan.staged === true } : {}),
                            ...(scope.kind === 'link.replace' ? {
                                oldLinkId: scope.oldLinkId,
                                groupId: scope.groupId,
                                pathKey: scope.pathKey,
                                ownerNodeId: admitted.ownerNodeId,
                                oldPathLinkIds: [...admitted.oldPathLinkIds],
                            } : {}) }
                        : {};
                    admissionFingerprint = createHash('sha256').update(JSON.stringify({
                        operationId,
                        topologyRevision: admitted.revision,
                        priorDeployedRevision: admitted.deployedRevision,
                        nodes: plan.nodes,
                        ...scopedIdentity,
                    })).digest('hex');
                    await this.operationRepository.createFrozen({
                        operationId,
                        idempotencyKey: runIdempotencyKey,
                        topologyRevision: admitted.revision,
                        priorDeployedRevision: admitted.deployedRevision,
                        nodes: plan.nodes,
                        ...scopedIdentity,
                        heldTopologyAdmission: true,
                        admissionFingerprint,
                        session,
                    });
                },
            });
        } catch (error) {
            if (admissionFingerprint
                && error?.hasErrorLabel?.('UnknownTransactionCommitResult') === true
                && typeof this.operationRepository.findAdmissionById === 'function') {
                try {
                    const found = await this.operationRepository.findAdmissionById(operationId);
                    if (found && String(found._id) === operationId
                        && found.topologyRevision === expectedTopologyRevision
                        && found.heldTopologyAdmission === true
                        && found.admissionFingerprint === admissionFingerprint
                        && found.priorDeployedRevision === admittedPriorDeployedRevision
                        && OPERATION_STATUSES.has(found.status)) {
                        // A confirmed commit is left to the gated recovery scan;
                        // never start a worker on an ambiguous response path.
                        return Object.freeze({ operationId,
                            topologyRevision: found.topologyRevision,
                            status: found.status, ...scopedIdentity });
                    }
                } catch {
                    // An unavailable readback cannot establish a safe commit.
                }
            }
            throw safeQueueError(error, operationId, expectedTopologyRevision);
        }
        if (this.operationWorker) {
            Promise.resolve(this.operationWorker.run(operationId)).catch(() => {
                this.onWorkerError({ operationId });
            });
        }
        return Object.freeze({
            operationId,
            topologyRevision: pinned.revision,
            status: 'queued',
            ...scopedIdentity,
        });
    }
}

module.exports = {
    ACTIVE_OPERATION_STATUSES,
    OPERATION_STATUSES,
    TopologyOperationCoordinator,
    TopologyOperationCoordinatorError,
    assertQueueInput,
    deepFreeze,
    idFromIdempotencyKey,
    nodeIdsByRef,
    projectTopologyOperationStatus,
};
