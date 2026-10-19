'use strict';

const { randomBytes } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

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
        remoteAdmissionRepository,
        lockService,
        enableInstallAdmission = false,
        clock,
    }) {
        this.nodeRepository = nodeRepository;
        this.stateRepository = stateRepository;
        this.operationRepository = operationRepository;
        this.planBuilder = planBuilder;
        this.operationMaterializer = operationMaterializer;
        this.preflightRunner = preflightRunner;
        this.remoteAdmissionRepository = remoteAdmissionRepository;
        this.lockService = lockService;
        this.enableInstallAdmission = enableInstallAdmission === true;
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
        // Standalone preflight has its own counted admission and exact node lock;
        // no remote work is allowed without both fences.
        const context = await this._loadInstallContext(nodeId, input);
        const admissions = this.remoteAdmissionRepository;
        if (!admissions || typeof admissions.acquire !== 'function'
            || typeof admissions.release !== 'function'
            || typeof admissions.markRecoveryRequired !== 'function'
            || !this.lockService || typeof this.lockService.acquire !== 'function'
            || typeof this.lockService.releaseVerified !== 'function') {
            throw new L2tpServiceError('REMOTE_ADMISSION_UNAVAILABLE', 'Remote admission is unavailable');
        }
        const id = await admissions.acquire({ nodeId: entityId(context.node) });
        const owner = `standalone-preflight:${randomBytes(8).toString('hex')}`;
        const operationId = `preflight:${entityId(context.node)}:${randomBytes(8).toString('hex')}`;
        let lock;
        let verifiedComplete = false;
        let result;
        let runnerError;
        let acquired;
        try {
            try {
                acquired = await this.lockService.acquire({
                    node: entityId(context.node),
                    owner,
                    operationId,
                    leaseMs: 15 * 60 * 1000,
                });
            } catch (error) {
                await admissions.markRecoveryRequired(id);
                throw error;
            }
            if (!acquired?.ok || !acquired.lock) {
                try {
                    await admissions.release(id);
                } catch (error) {
                    try { await admissions.markRecoveryRequired(id); } catch { /* preserve fence */ }
                    throw error;
                }
                throw new L2tpServiceError('NODE_OPERATION_LOCK_CONFLICT',
                    'The relay is busy with another operation');
            }
            lock = acquired.lock;
            try {
                result = await this.preflightRunner({ ...context,
                    onVerifiedRemoteComplete: () => { verifiedComplete = true; },
                });
            } catch (error) {
                runnerError = error;
            }
            const validResult = result && typeof result === 'object'
                && typeof result.ok === 'boolean'
                && result.error?.code !== 'PREFLIGHT_RESPONSE_INVALID';
            if (!verifiedComplete || runnerError || !validResult) {
                await admissions.markRecoveryRequired(id);
                if (runnerError) throw runnerError;
                return result;
            }
            const released = await this.lockService.releaseVerified(lock);
            if (released?.ok !== true) {
                await admissions.markRecoveryRequired(id);
                throw new L2tpServiceError('PREFLIGHT_FENCE_RELEASE_FAILED',
                    'The preflight completed but its exact node fence could not be released');
            }
            try {
                await admissions.release(id);
            } catch (error) {
                try { await admissions.markRecoveryRequired(id); } catch { /* preserve counted fence */ }
                throw error;
            }
            return result;
        } catch (error) {
            // Any path without a verified remote result intentionally retains the
            // node lock and counted admission for recovery; never release here.
            throw error;
        }
    }

    async install(nodeId, input) {
        const context = await this._loadInstallContext(nodeId, input);
        // TEST execution opt-in and counted admission must be enabled together;
        // an unsupported install fails before remote transport.
        const admissions = this.remoteAdmissionRepository;
        if (!this.enableInstallAdmission || !admissions
            || typeof admissions.acquireInstall !== 'function'
            || typeof admissions.queueInstall !== 'function'
            || typeof admissions.release !== 'function'
            || typeof admissions.markRecoveryRequired !== 'function'
            || !this.lockService || typeof this.lockService.acquire !== 'function'
            || typeof this.lockService.releaseVerified !== 'function') {
            throw new L2tpServiceError('REMOTE_ADMISSION_UNAVAILABLE', 'Install admission is unavailable');
        }
        const admissionId = await admissions.acquireInstall({ nodeId: entityId(context.node) });
        // Admission excludes drains/replacement but is not a node lock. A topology
        // worker can win the node between admission and this insert-only claim.
        // Use a distinct preflight identity: never hand this lock to the worker.
        let acquired;
        try {
            acquired = await this.lockService.acquire({
                node: entityId(context.node),
                owner: `install-preflight:${randomBytes(8).toString('hex')}`,
                operationId: `preflight:${entityId(context.node)}:${randomBytes(8).toString('hex')}`,
                leaseMs: 15 * 60 * 1000,
            });
        } catch (error) {
            // The insert may have committed. Retain both fences for recovery.
            try { await admissions.markRecoveryRequired(admissionId); } catch { /* keep count */ }
            throw error;
        }
        if (acquired?.ok === false) {
            try {
                await admissions.release(admissionId);
            } catch (error) {
                try { await admissions.markRecoveryRequired(admissionId); } catch { /* keep count */ }
                throw error;
            }
            throw new L2tpServiceError('NODE_OPERATION_LOCK_CONFLICT',
                'The relay is busy with another operation');
        }
        if (acquired?.ok !== true || !acquired.lock) {
            // A malformed/absent claim result is not evidence of non-acquisition.
            try { await admissions.markRecoveryRequired(admissionId); } catch { /* keep count */ }
            throw new L2tpServiceError('NODE_LOCK_UNAVAILABLE',
                'The install preflight node fence could not be verified');
        }
        const preflightLock = acquired.lock;
        let verifiedComplete = false;
        let preflightResult;
        let runnerError;
        try {
            preflightResult = await this.preflightRunner({
                ...context,
                onVerifiedRemoteComplete: () => { verifiedComplete = true; },
            });
        } catch (error) {
            runnerError = error;
        }
        const validResult = preflightResult && typeof preflightResult === 'object'
            && typeof preflightResult.ok === 'boolean'
            && preflightResult.error?.code !== 'PREFLIGHT_RESPONSE_INVALID';
        if (!verifiedComplete || runnerError || !validResult) {
            await admissions.markRecoveryRequired(admissionId);
            if (runnerError) throw runnerError;
            throw new L2tpServiceError('PREFLIGHT_RESPONSE_INVALID', 'Install preflight was not verified');
        }
        // Only an attested, validated remote completion authorizes exact release.
        // The counted admission stays live through planning and queue handoff;
        // worker execution obtains its own independent node-lock generation.
        try {
            const released = await this.lockService.releaseVerified(preflightLock);
            if (released?.ok !== true) {
                throw new L2tpServiceError('PREFLIGHT_FENCE_RELEASE_FAILED',
                    'The preflight completed but its exact node fence could not be released');
            }
        } catch (error) {
            try { await admissions.markRecoveryRequired(admissionId); } catch { /* keep count */ }
            throw error;
        }
        if (preflightResult.ok === false) {
            await admissions.release(admissionId);
            throw new L2tpServiceError(
                'PREFLIGHT_FAILED',
                'L2TP install preflight failed',
                {
                    nodeId: String(nodeId),
                    failureCode: preflightResult.error?.code ?? 'PREFLIGHT_FAILED',
                    checks: preflightResult.checks ?? [],
                },
            );
        }

        const operationId = randomBytes(12).toString('hex');
        const topologyRevision = context.topologyRevision;
        let operationDocument;
        try {
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
            const materialized = await this.operationMaterializer({ plan, desired: context.desired });
            const persistedPlan = materialized?.persistedPlan;
            if (!persistedPlan || typeof persistedPlan !== 'object') {
                throw new L2tpServiceError(
                    'INSTALL_PLAN_REJECTED',
                    'L2TP install plan materialization failed',
                    { nodeId: String(nodeId) },
                );
            }
            operationDocument = {
                _id: operationId,
                node: entityId(context.node),
                kind: 'install',
                status: 'queued',
                idempotencyKey: `install:${entityId(context.node)}:revision-${topologyRevision}:attempt-${operationId}`,
                progress: 0,
                attempts: 0,
                plan: persistedPlan,
                createdAt: this.clock.now(),
            };
        } catch (error) {
            // This is after attested remote completion but before any queue write.
            await admissions.release(admissionId);
            throw error;
        }
        // A queue rejection may be an ambiguous transaction commit. Neither
        // release nor retry with another ID: keep the admission counted.
        try {
            await admissions.queueInstall({ admissionId, operationDocument });
        } catch (error) {
            // Only the exact committed admission/operation pair proves an
            // ambiguous handoff. Missing readback, a different admission or an
            // uncounted legacy operation must never authorize a success.
            let handoff;
            if (typeof admissions.findInstallHandoff === 'function') {
                try {
                    handoff = await admissions.findInstallHandoff({ admissionId, operationId });
                } catch { /* The original queue error remains the failure. */ }
            }
            const admission = handoff?.admission;
            const operation = handoff?.operation;
            if (entityId(admission) === String(admissionId)
                && admission.nodeId === operationDocument.node
                && admission.kind === 'install'
                && admission.phase === 'queued'
                && String(admission.operationId) === operationId
                && entityId(operation) === operationId
                && String(operation.admissionId) === String(admissionId)
                && operation.node === operationDocument.node
                && operation.kind === 'install'
                && operation.status === 'queued'
                && operation.idempotencyKey === operationDocument.idempotencyKey
                && isDeepStrictEqual(operation.plan,
                    JSON.parse(JSON.stringify(operationDocument.plan)))) {
                return { operationId };
            }
            if (error?.code === 11000) {
                if (error.installQueuePreCommitAbort === true) {
                    try {
                        // release() is an exact unlinked-admission CAS in one
                        // transaction with the singleton count. A queued or
                        // ambiguously committed handoff cannot match it.
                        await admissions.release(admissionId);
                    } catch {
                        try { await admissions.markRecoveryRequired(admissionId); } catch { /* count stays fenced */ }
                        throw new L2tpServiceError('REMOTE_ADMISSION_RECOVERY_REQUIRED',
                            'Install admission could not be safely released',
                            { nodeId: String(nodeId), operationId, admissionId });
                    }
                }
                throw new L2tpServiceError('INSTALL_OPERATION_CONFLICT',
                    'An install operation already holds the idempotency key',
                    { nodeId: String(nodeId), operationId, admissionId });
            }
            throw error;
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
