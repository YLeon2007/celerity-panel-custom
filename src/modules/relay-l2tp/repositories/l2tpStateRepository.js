'use strict';

const STATE_SAFE_SELECT = '-pskEncrypted';

const OPERATION_SAFE_FIELDS = Object.freeze([
    '_id',
    'node',
    'user',
    'kind',
    'status',
    'idempotencyKey',
    'step',
    'progress',
    'attempts',
    'logs',
    'backupId',
    'errorCode',
    'errorMessage',
    'requestedBy',
    'startedAt',
    'finishedAt',
    'topologyRevision',
    'routeGroupId',
    'plan',
    'createdAt',
    'updatedAt',
]);

const OPERATION_SAFE_SELECT = OPERATION_SAFE_FIELDS.join(' ');

const OPERATION_PLAN_FIELDS = Object.freeze([
    'ok',
    'operationId',
    'topologyRevision',
    'relayId',
    'routeGroupId',
    'selectedPathKey',
    'nextHopNodeId',
]);

const OPERATION_PLAN_DESIRED_FIELDS = Object.freeze([
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
    'credentialRevision',
]);

function pickDefined(source, fields) {
    return fields.reduce((result, field) => {
        if (source[field] !== undefined) result[field] = source[field];
        return result;
    }, {});
}

function sanitizeOperationPlan(plan) {
    if (!plan || typeof plan !== 'object' || Array.isArray(plan)) return undefined;

    const sanitized = pickDefined(plan, OPERATION_PLAN_FIELDS);
    if (plan.error && typeof plan.error === 'object' && !Array.isArray(plan.error)) {
        sanitized.error = pickDefined(plan.error, ['code']);
    }
    if (plan.desired && typeof plan.desired === 'object' && !Array.isArray(plan.desired)) {
        sanitized.desired = pickDefined(plan.desired, OPERATION_PLAN_DESIRED_FIELDS);
    }
    if (Array.isArray(plan.steps)) {
        sanitized.steps = plan.steps
            .filter(step => step && typeof step === 'object' && !Array.isArray(step))
            .map(step => {
                const sanitizedStep = pickDefined(step, ['type']);
                if (Array.isArray(step.artifacts)) {
                    sanitizedStep.artifacts = step.artifacts
                        .filter(artifact => (
                            artifact
                            && typeof artifact === 'object'
                            && !Array.isArray(artifact)
                        ))
                        .map(artifact => pickDefined(artifact, ['type', 'path']));
                }
                return sanitizedStep;
            });
    }
    return sanitized;
}

function sanitizeOperation(operation) {
    if (!operation) return operation;

    const safeOperation = pickDefined(
        operation,
        OPERATION_SAFE_FIELDS.filter(field => field !== 'plan' && field !== 'logs'),
    );
    if (operation.plan !== undefined) {
        safeOperation.plan = sanitizeOperationPlan(operation.plan);
    }
    if (Array.isArray(operation.logs)) {
        safeOperation.logs = operation.logs
            .filter(entry => entry && typeof entry === 'object' && !Array.isArray(entry))
            .map(entry => pickDefined(entry, ['at', 'level', 'code', 'message']));
    }
    return safeOperation;
}

const NODE_SAFE_SELECT = [
    '-obfs.password',
    '-outbounds.password',
    '-ssh.password',
    '-ssh.privateKey',
    '-statsSecret',
    '-xray.accessLogs.ingestTokenEncrypted',
    '-xray.agentToken',
    '-xray.manualKey',
    '-xray.realityPrivateKey',
].join(' ');

function createL2tpServiceRepositoryAdapters(repository) {
    return {
        nodeRepository: {
            findById: nodeId => repository.findNodeById(nodeId),
        },
        stateRepository: {
            findByNodeId: nodeId => repository.findByNodeId(nodeId),
            findRouteGroupById: routeGroupId => repository.findRouteGroupById(routeGroupId),
            getTopologyRevision: () => repository.getTopologyRevision(),
            getRelayGroupPlan: (nodeId, routeGroupId) => (
                repository.getRelayGroupPlan(nodeId, routeGroupId)
            ),
        },
        operationRepository: {
            findById: operationId => repository.findOperation(operationId),
            create: operation => repository.createQueuedOperation(operation),
        },
    };
}

class L2tpStateRepository {
    constructor({
        HyNode,
        RelayL2tpState,
        CascadeRouteGroup,
        CascadeTopologyState,
        L2tpOperation,
        compilerData,
        topologyRuntime,
    }) {
        this.HyNode = HyNode;
        this.RelayL2tpState = RelayL2tpState;
        this.CascadeRouteGroup = CascadeRouteGroup;
        this.CascadeTopologyState = CascadeTopologyState;
        this.L2tpOperation = L2tpOperation;
        this.compilerData = compilerData;
        this.topologyRuntime = topologyRuntime;
    }

    async findNodeById(nodeId) {
        return this.HyNode.findById(nodeId)
            .select(NODE_SAFE_SELECT)
            .lean();
    }

    async findByNodeId(nodeId) {
        return this.RelayL2tpState.findOne({ node: nodeId })
            .select(STATE_SAFE_SELECT)
            .lean();
    }

    async findRouteGroupById(routeGroupId) {
        return this.CascadeRouteGroup.findById(routeGroupId).lean();
    }

    async getTopologyRevision() {
        const topologyState = await this.CascadeTopologyState.findById('singleton')
            .select('revision')
            .lean();
        return topologyState?.revision ?? 0;
    }

    async getRelayGroupPlan(nodeId, routeGroupId) {
        if (this.topologyRuntime) {
            return this.topologyRuntime.getRelayGroupPlan(nodeId, routeGroupId);
        }
        const relay = this.compilerData.relays.find(
            entry => String(entry.nodeId) === String(nodeId),
        );
        return relay?.routeGroups.find(
            entry => String(entry.groupId) === String(routeGroupId),
        ) ?? null;
    }

    async findOperation(operationId) {
        const operation = await this.L2tpOperation.findById(operationId)
            .select(OPERATION_SAFE_SELECT)
            .lean();
        return sanitizeOperation(operation);
    }

    async createQueuedOperation({
        _id,
        node,
        kind,
        idempotencyKey,
        requestedBy,
        topologyRevision,
        routeGroupId,
        plan,
    }) {
        return this.L2tpOperation.create({
            ...(_id === undefined ? {} : { _id }),
            node,
            kind,
            status: 'queued',
            idempotencyKey,
            requestedBy,
            ...(topologyRevision === undefined ? {} : { topologyRevision }),
            ...(routeGroupId === undefined ? {} : { routeGroupId }),
            plan: sanitizeOperationPlan(plan),
        });
    }
}

module.exports = {
    createL2tpServiceRepositoryAdapters,
    L2tpStateRepository,
    NODE_SAFE_SELECT,
    OPERATION_SAFE_SELECT,
    STATE_SAFE_SELECT,
};
