'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { compileTopology } = require('../domain/topologyCompiler');
const {
    projectGroups,
    projectLinks,
    projectNodes,
} = require('../domain/topologyDraft');
const { validateTopology } = require('../domain/topologyValidator');
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

const SCOPED_OPERATION_KINDS = new Set(['link.apply', 'domain.reconcile']);

function normalizeOperationScope(scope) {
    if (scope === undefined) return null;
    if (!scope || typeof scope !== 'object' || Array.isArray(scope)
        || !Object.keys(scope).every(key => ['kind', 'linkId', 'linkIds'].includes(key))
        || !SCOPED_OPERATION_KINDS.has(scope.kind)
        || typeof scope.linkId !== 'string' || scope.linkId.length === 0
        || !Array.isArray(scope.linkIds) || scope.linkIds.length === 0
        || scope.linkIds.some(linkId => typeof linkId !== 'string' || linkId.length === 0)
        || new Set(scope.linkIds).size !== scope.linkIds.length
        || !scope.linkIds.includes(scope.linkId)) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_REQUEST',
            'A scoped topology operation requires kind, a linkId contained in unique linkIds',
        );
    }
    return {
        kind: scope.kind,
        linkId: scope.linkId,
        linkIds: [...scope.linkIds].sort((left, right) => left.localeCompare(right, 'en')),
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
        `The topology operation could not be queued: ${error?.message || 'unknown error'}`,
        {
            operationId,
            expectedTopologyRevision,
            causeCode: error?.code,
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
            if (status !== undefined && status !== null
                && status !== 'deployed' && status !== 'online' && status !== 'staged') {
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
    // Walk the MAIN chain only: at a branching node (relay with geo-routing
    // leaf links) a collapsed map would follow whatever link sorted last and
    // bind the wrong bridge to the 'bridge' ref.
    const outgoing = new Map(
        topology.links.filter(link => link.geo !== true).map(link => [link.source, link.target]),
    );
    const portal = topology.nodes.find(node => node.role === 'portal');
    const result = new Map();
    let current = portal?.id;
    let relayIndex = 0;
    const visited = new Set();
    while (current && nodes.has(current) && !visited.has(current)) {
        visited.add(current);
        const node = nodes.get(current);
        const ref = node.role === 'relay' ? `relay-${++relayIndex}` : node.role;
        result.set(ref, current);
        current = outgoing.get(current);
    }
    // Geo-routing branch bridges never appear in the main chain walk; they get
    // suffixed refs in the same deterministic order the plan composer uses.
    const geoBridges = topology.nodes
        .filter(node => node.role === 'bridge' && !visited.has(node.id))
        .sort((left, right) => left.id.localeCompare(right.id, 'en'));
    geoBridges.forEach((node, index) => result.set(`bridge-${index + 2}`, node.id));
    return result;
}

function operationPlan({ operationId, topologyRevision, priorDeployedRevision, topology, plan }) {
    const idsByRef = nodeIdsByRef(topology);
    const nodes = plan.nodes.map(node => {
        const nodeId = entityId(node.node) || idsByRef.get(node.nodeRef) || '';
        const candidateHash = node.candidateHash ?? node.candidate?.sha256;
        if (!nodeId || typeof candidateHash !== 'string' || candidateHash.length === 0) {
            throw new TopologyOperationCoordinatorError(
                'INVALID_TOPOLOGY_DEPLOYMENT',
                'The frozen topology operation plan is invalid',
                { operationId },
            );
        }
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
        if (!topologyRepository || typeof topologyRepository.pinTopology !== 'function') {
            throw new TypeError('Topology operation coordinator requires topologyRepository.pinTopology');
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
        try {
            pinned = await this.topologyRepository.pinTopology({
                expectedRevision: expectedTopologyRevision,
                prepare: async snapshot => {
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
                    const topology = scope
                        ? applyScopeToTopology(projected, scope, operationId, snapshot.links)
                        : projected;
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
                        pinnedSnapshot: deepFreeze({
                            revision: snapshot.revision,
                            topology,
                            compiled,
                        }),
                    });
                    return { topology, frozenPlan };
                },
            });
        } catch (error) {
            throw safeQueueError(error, operationId, expectedTopologyRevision);
        }
        const plan = operationPlan({
            operationId,
            topologyRevision: pinned.revision,
            priorDeployedRevision: pinned.deployedRevision,
            topology: pinned.topology,
            plan: pinned.frozenPlan,
        });
        const scopedIdentity = scope
            ? { kind: scope.kind, linkId: scope.linkId, linkIds: [...scope.linkIds] }
            : {};
        try {
            await this.operationRepository.createFrozen({
                operationId,
                idempotencyKey: runIdempotencyKey,
                topologyRevision: pinned.revision,
                priorDeployedRevision: pinned.deployedRevision,
                nodes: plan.nodes,
                ...scopedIdentity,
            });
        } catch (error) {
            if ((error?.code === 11000 || error?.code === 11001)
                && typeof this.operationRepository.findPublicById === 'function') {
                const existing = await this.operationRepository.findPublicById(operationId);
                if (existing) {
                    return Object.freeze({
                        operationId,
                        topologyRevision: pinned.revision,
                        status: existing.status ?? 'queued',
                        ...scopedIdentity,
                    });
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
