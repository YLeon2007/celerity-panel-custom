'use strict';

const { createHash } = require('node:crypto');
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

function assertQueueInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || Object.keys(input).length !== 1
        || !Object.hasOwn(input, 'expectedTopologyRevision')) {
        throw new TopologyOperationCoordinatorError(
            'INVALID_REQUEST',
            'Only expectedTopologyRevision is accepted',
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
    return new TopologyOperationCoordinatorError(
        'TOPOLOGY_OPERATION_QUEUE_FAILED',
        'The topology operation could not be queued',
        { operationId, expectedTopologyRevision },
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

function nodeIdsByRef(topology) {
    const nodes = new Map(topology.nodes.map(node => [node.id, node]));
    const outgoing = new Map(topology.links.map(link => [link.source, link.target]));
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
        assertQueueInput(input);
        const { expectedTopologyRevision } = input;
        const idempotencyKey = `topology:${TEST_TOPOLOGY_TARGET}:revision-${expectedTopologyRevision}`;
        const existing = this.operationsByIdempotencyKey.get(idempotencyKey);
        if (existing) {
            const settled = await existing.then(operation => operation, () => null);
            if (!settled) {
                this.operationsByIdempotencyKey.delete(idempotencyKey);
            } else if (typeof this.operationRepository.findPublicById === 'function') {
                const persisted = await this.operationRepository.findPublicById(settled.operationId);
                if (persisted) return existing;
                // The operation record was purged (undeploy): re-queue from scratch.
                this.operationsByIdempotencyKey.delete(idempotencyKey);
            } else {
                return existing;
            }
        }

        const queued = this.queueOnce({ expectedTopologyRevision, idempotencyKey });
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

    async queueOnce({ expectedTopologyRevision, idempotencyKey }) {
        const operationId = entityId(this.idFactory(idempotencyKey));
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
                    const topology = projectTopology(snapshot);
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
        try {
            await this.operationRepository.createFrozen({
                operationId,
                idempotencyKey,
                topologyRevision: pinned.revision,
                priorDeployedRevision: pinned.deployedRevision,
                nodes: plan.nodes,
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
    projectTopologyOperationStatus,
};
