'use strict';

const { randomBytes } = require('node:crypto');

class L2tpServiceError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'L2tpServiceError';
        this.code = code;
        Object.assign(this, details);
    }
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function nodeRole(node) {
    return node?.role ?? node?.cascadeRole ?? null;
}

function installDesired(state, input) {
    return {
        ...state,
        credentialRevision: state?.secretRevision,
        ...(input.clientCidr === undefined ? {} : { clientCidr: input.clientCidr }),
        ...(input.dnsServers === undefined ? {} : { dnsServers: input.dnsServers }),
        routeGroup: input.routeGroupId,
    };
}

class L2tpService {
    constructor({
        nodeRepository,
        stateRepository,
        operationRepository,
        planBuilder,
        operationMaterializer,
        preflightRunner,
        clock,
    }) {
        this.nodeRepository = nodeRepository;
        this.stateRepository = stateRepository;
        this.operationRepository = operationRepository;
        this.planBuilder = planBuilder;
        this.operationMaterializer = operationMaterializer;
        this.preflightRunner = preflightRunner;
        this.clock = clock;
    }

    async getStatus(nodeId) {
        return this.status(nodeId);
    }

    async status(nodeId) {
        const node = await this.nodeRepository.findById(nodeId);
        if (!node) {
            throw new L2tpServiceError(
                'NODE_NOT_FOUND',
                'L2TP node was not found',
                { nodeId: String(nodeId) },
            );
        }
        const state = await this.stateRepository.findByNodeId(nodeId);

        return {
            nodeId: entityId(node),
            role: nodeRole(node),
            desiredState: state?.desiredState ?? 'absent',
            status: state?.status ?? 'not_installed',
            routeGroupId: entityId(state?.routeGroup),
            operationId: entityId(state?.operationId),
            appliedTopologyRevision: state?.appliedTopologyRevision ?? null,
            lastErrorCode: state?.lastErrorCode ?? '',
        };
    }

    async preflight(nodeId, input) {
        const context = await this._loadInstallContext(nodeId, input);

        return this.preflightRunner(context);
    }

    async install(nodeId, input) {
        const context = await this._loadInstallContext(nodeId, input);
        const preflightResult = await this.preflightRunner(context);
        if (preflightResult?.ok !== true) {
            throw new L2tpServiceError(
                'PREFLIGHT_FAILED',
                'L2TP install preflight failed',
                {
                    nodeId: String(nodeId),
                    failureCode: preflightResult?.error?.code ?? 'PREFLIGHT_FAILED',
                    checks: preflightResult?.checks ?? [],
                },
            );
        }

        const operationId = randomBytes(12).toString('hex');
        const topologyRevision = context.topologyRevision;
        const plan = await this.planBuilder({
            operationId,
            topologyRevision,
            relay: context.relay,
            routeGroup: context.routeGroup,
            relayGroupPlan: context.relayGroupPlan,
            desired: context.desired,
        });
        if (plan?.ok !== true) {
            const code = plan?.error?.code === 'NO_HEALTHY_PATH'
                ? 'NO_HEALTHY_PATH'
                : 'INSTALL_PLAN_REJECTED';
            throw new L2tpServiceError(
                code,
                'L2TP install plan was rejected',
                {
                    nodeId: String(nodeId),
                    routeGroupId: entityId(context.routeGroup),
                },
            );
        }

        const materialized = await this.operationMaterializer({
            plan,
            desired: context.desired,
        });
        const persistedPlan = materialized?.persistedPlan;
        if (!persistedPlan || typeof persistedPlan !== 'object') {
            throw new L2tpServiceError(
                'INSTALL_PLAN_REJECTED',
                'L2TP install plan materialization failed',
                { nodeId: String(nodeId) },
            );
        }

        const operationDocument = {
            _id: operationId,
            node: entityId(context.node),
            kind: 'install',
            status: 'queued',
            idempotencyKey: `install:${entityId(context.node)}:revision-${topologyRevision}`,
            progress: 0,
            attempts: 0,
            plan: persistedPlan,
            createdAt: this.clock.now(),
        };
        try {
            await this.operationRepository.create(operationDocument);
        } catch (error) {
            // A terminal operation keeps the unique idempotency key forever,
            // which used to block every retry at the same topology revision.
            // Active duplicates stay idempotent; terminal ones are replaced.
            if (error?.code !== 11000) throw error;
            const existing = await this.operationRepository.findByIdempotencyKey(
                operationDocument.idempotencyKey,
            );
            if (!existing) throw error;
            const existingId = entityId(existing._id ?? existing.id);
            if (['queued', 'claimed', 'running'].includes(existing.status)) {
                return { operationId: existingId };
            }
            await this.operationRepository.deleteById(existingId);
            await this.operationRepository.create(operationDocument);
        }

        return { operationId };
    }

    async _loadInstallContext(nodeId, input) {
        const node = await this.nodeRepository.findById(nodeId);
        if (!node) {
            throw new L2tpServiceError(
                'NODE_NOT_FOUND',
                'L2TP node was not found',
                { nodeId: String(nodeId) },
            );
        }
        const role = nodeRole(node);
        if (role !== 'relay') {
            throw new L2tpServiceError(
                'NODE_NOT_RELAY',
                'L2TP can only be managed on relay nodes',
                { nodeId: String(nodeId), role },
            );
        }
        const state = await this.stateRepository.findByNodeId(nodeId);
        if (state?.desiredState !== 'installed') {
            throw new L2tpServiceError(
                'DESIRED_STATE_NOT_INSTALLED',
                'L2TP desired state must be installed',
                { nodeId: String(nodeId), desiredState: state?.desiredState ?? null },
            );
        }
        const requestedRouteGroupId = entityId(input.routeGroupId);
        if (!requestedRouteGroupId) {
            throw new L2tpServiceError(
                'ROUTE_GROUP_REQUIRED',
                'An L2TP route group is required',
                { nodeId: String(nodeId) },
            );
        }
        if (
            !Number.isSafeInteger(input.expectedTopologyRevision)
            || input.expectedTopologyRevision < 0
        ) {
            throw new L2tpServiceError(
                'INVALID_TOPOLOGY_REVISION',
                'An explicit integer topology revision is required',
                {
                    nodeId: String(nodeId),
                    expectedTopologyRevision: input.expectedTopologyRevision,
                },
            );
        }
        const routeGroup = await this.stateRepository.findRouteGroupById(input.routeGroupId);
        if (!routeGroup) {
            throw new L2tpServiceError(
                'ROUTE_GROUP_NOT_FOUND',
                'The L2TP route group was not found',
                {
                    nodeId: String(nodeId),
                    routeGroupId: requestedRouteGroupId,
                },
            );
        }
        const topologyRevision = await this.stateRepository.getTopologyRevision();
        if (input.expectedTopologyRevision !== topologyRevision) {
            throw new L2tpServiceError(
                'STALE_TOPOLOGY_REVISION',
                'The L2TP topology revision is stale',
                {
                    nodeId: String(nodeId),
                    expectedTopologyRevision: input.expectedTopologyRevision,
                    topologyRevision,
                },
            );
        }
        const relayGroupPlan = await this.stateRepository.getRelayGroupPlan(
            nodeId,
            input.routeGroupId,
        );
        if (!relayGroupPlan) {
            throw new L2tpServiceError(
                'PREFLIGHT_FAILED',
                'An L2TP relay-group plan is required',
                {
                    nodeId: String(nodeId),
                    routeGroupId: requestedRouteGroupId,
                    failureCode: 'RELAY_GROUP_PLAN_REQUIRED',
                },
            );
        }

        return {
            node,
            relay: { ...node, role: nodeRole(node) },
            state,
            desired: installDesired(state, input),
            routeGroup,
            relayGroupPlan,
            topologyRevision,
            input,
        };
    }

    async getOperation(operationId) {
        const operation = await this.operationRepository.findById(operationId);
        if (!operation) {
            throw new L2tpServiceError(
                'OPERATION_NOT_FOUND',
                'L2TP operation was not found',
                { operationId: String(operationId) },
            );
        }
        return operation;
    }
}

module.exports = {
    L2tpService,
    L2tpServiceError,
};
