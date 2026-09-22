'use strict';

const INSTALL_PLAN_ERROR_CODES = new Set([
    'INSTALL_PLAN_REJECTED',
    'INVALID_INSTALL_PLAN',
]);
const XRAY_CANDIDATE_ARTIFACT = Object.freeze({
    stepType: 'compose_xray_fragment',
    type: 'xrayCandidate',
    path: 'xray-candidate.json',
});

function candidateBuildError() {
    const error = new Error('Failed to build the L2TP Xray candidate');
    error.code = 'XRAY_CANDIDATE_FAILED';
    return error;
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function secretFreeStep(step) {
    const reference = { type: step.type };
    if (Array.isArray(step.artifacts)) {
        reference.artifacts = step.artifacts.map(artifact => ({
            type: artifact.type,
            path: artifact.path,
        }));
    }
    return reference;
}

function attachRemoteArtifacts(plan, remoteArtifacts) {
    if (!Array.isArray(remoteArtifacts)) {
        throw new TypeError('L2TP operation materializer must return remote artifacts');
    }

    const byReference = new Map();
    for (const artifact of remoteArtifacts) {
        if (
            !artifact
            || typeof artifact !== 'object'
            || typeof artifact.stepType !== 'string'
            || typeof artifact.type !== 'string'
            || typeof artifact.path !== 'string'
            || typeof artifact.content !== 'string'
        ) {
            throw new TypeError('L2TP operation materializer returned an invalid artifact');
        }
        const key = `${artifact.stepType}\u0000${artifact.type}\u0000${artifact.path}`;
        if (byReference.has(key)) {
            throw new TypeError('L2TP operation materializer returned a duplicate artifact');
        }
        byReference.set(key, artifact.content);
    }

    const consumed = new Set();
    const steps = plan.steps.map(step => {
        if (!Array.isArray(step.artifacts) || step.artifacts.length === 0) {
            return { type: step.type };
        }

        return {
            type: step.type,
            artifacts: step.artifacts.map(reference => {
                const key = `${step.type}\u0000${reference.type}\u0000${reference.path}`;
                if (!byReference.has(key)) {
                    throw new TypeError('L2TP operation materializer omitted a referenced artifact');
                }
                consumed.add(key);
                return {
                    type: reference.type,
                    path: reference.path,
                    content: byReference.get(key),
                };
            }),
        };
    });

    if (consumed.size !== byReference.size) {
        throw new TypeError('L2TP operation materializer returned an unreferenced artifact');
    }
    return steps;
}

class L2tpOperationWorker {
    constructor({
        operationRepository,
        lockService,
        executor,
        secretResolver,
        stateReconciler,
        candidateService,
        operationMaterializer,
        workerId,
        leaseMs,
        clock,
        timer = globalThis,
        renewalIntervalMs,
    }) {
        this.operationRepository = operationRepository;
        this.lockService = lockService;
        this.executor = executor;
        this.secretResolver = secretResolver;
        this.stateReconciler = stateReconciler;
        this.candidateService = candidateService;
        this.operationMaterializer = operationMaterializer;
        this.workerId = workerId;
        this.leaseMs = leaseMs;
        this.clock = clock;
        Object.defineProperty(this, 'timer', {
            value: timer,
            writable: true,
            configurable: true,
            enumerable: false,
        });
        this.renewalIntervalMs = renewalIntervalMs
            ?? Math.max(1, Math.floor(leaseMs / 3));
    }

    async failClaimedOperation({ operationId, errorCode, errorMessage }) {
        const finishedAt = this.clock.now();
        await this.operationRepository.setStatus({
            operationId,
            status: 'failed',
            progress: 0,
            errorCode,
            errorMessage,
            finishedAt,
            journal: {
                at: finishedAt,
                level: 'error',
                code: errorCode,
                message: errorMessage,
            },
        });
        return { claimed: true, operationId, status: 'failed' };
    }

    async prepareInstallPlan(operation) {
        if (typeof this.operationMaterializer !== 'function') {
            return {
                errorCode: 'INSTALL_PLAN_REJECTED',
                errorMessage: 'L2TP install plan materialization is unavailable',
            };
        }

        try {
            const prepared = await this.operationMaterializer({ plan: operation.plan });
            if (!prepared?.persistedPlan || typeof prepared.persistedPlan !== 'object') {
                throw new TypeError('L2TP operation materializer returned no durable plan');
            }
            return { plan: prepared.persistedPlan };
        } catch (error) {
            const errorCode = INSTALL_PLAN_ERROR_CODES.has(error?.code)
                ? error.code
                : 'INSTALL_PLAN_REJECTED';
            return {
                errorCode,
                errorMessage: errorCode === 'INVALID_INSTALL_PLAN'
                    ? 'The claimed L2TP install plan is invalid'
                    : 'The claimed L2TP install plan was rejected',
            };
        }
    }

    async buildInstallCandidate(plan) {
        try {
            if (typeof this.candidateService?.buildCandidate !== 'function') {
                throw new TypeError('L2TP Xray candidate service is unavailable');
            }
            const candidate = await this.candidateService.buildCandidate({ plan });
            if (
                !candidate
                || typeof candidate !== 'object'
                || candidate.operationId !== plan.operationId
                || typeof candidate.content !== 'string'
            ) {
                throw new TypeError('L2TP Xray candidate service returned an invalid candidate');
            }
            return candidate.content;
        } catch {
            throw candidateBuildError();
        }
    }

    async materializeInstallSteps({ operation, operationId, plan, candidateContent }) {
        if (typeof this.secretResolver !== 'function') {
            throw new TypeError('L2TP operation secret resolver is unavailable');
        }
        const resolutionRequest = {
            operationId,
            kind: operation.kind,
            nodeId: entityId(operation.node),
            credentialRevision: plan.desired?.credentialRevision,
        };
        const secrets = await this.secretResolver({
            ...resolutionRequest,
            secret: 'psk',
        });
        const materialized = await this.operationMaterializer({
            plan,
            secrets,
        });
        if (!materialized?.persistedPlan || typeof materialized.persistedPlan !== 'object') {
            throw new TypeError('L2TP operation materializer returned no durable plan');
        }
        return attachRemoteArtifacts(
            materialized.persistedPlan,
            [
                ...materialized.remoteArtifacts,
                { ...XRAY_CANDIDATE_ARTIFACT, content: candidateContent },
            ],
        );
    }

    createLeaseHeartbeat({ operationId, node }) {
        let intervalId;
        let inFlight = null;
        let renewalError = null;
        let stopped = false;

        const clear = () => {
            if (intervalId === undefined) return;
            this.timer.clearInterval(intervalId);
            intervalId = undefined;
        };
        const renew = async () => {
            const operationRenewed = await this.operationRepository.renewLease({
                operationId,
                owner: this.workerId,
                leaseMs: this.leaseMs,
                now: this.clock.now(),
            });
            if (!operationRenewed) {
                const error = new Error('L2TP operation lease is no longer owned by this worker');
                error.code = 'L2TP_OPERATION_LEASE_LOST';
                throw error;
            }

            const lockRenewed = await this.lockService.renew({
                node,
                owner: this.workerId,
                operationId,
                leaseMs: this.leaseMs,
            });
            if (!lockRenewed?.ok) {
                const error = new Error('L2TP node operation lock is no longer owned by this worker');
                error.code = lockRenewed?.error?.code || 'NODE_OPERATION_LOCK_LOST';
                throw error;
            }
        };
        const tick = () => {
            if (stopped || renewalError) return inFlight || Promise.resolve();
            if (inFlight) return inFlight;

            inFlight = renew()
                .catch(error => {
                    renewalError = error;
                    clear();
                })
                .finally(() => {
                    inFlight = null;
                });
            return inFlight;
        };

        intervalId = this.timer.setInterval(tick, this.renewalIntervalMs);

        return {
            renewNow: tick,
            async waitForIdle() {
                if (inFlight) await inFlight;
            },
            getError() {
                return renewalError;
            },
            stop: async () => {
                stopped = true;
                clear();
                if (inFlight) await inFlight;
            },
        };
    }

    async runOnce() {
        const operation = await this.operationRepository.claimNext({
            owner: this.workerId,
            leaseMs: this.leaseMs,
            now: this.clock.now(),
        });

        if (!operation) return { claimed: false };

        const operationId = String(operation._id ?? operation.id);
        let preparedInstallPlan = null;
        if (operation.kind === 'install') {
            const prepared = await this.prepareInstallPlan(operation);
            if (prepared.errorCode) {
                return this.failClaimedOperation({
                    operationId,
                    errorCode: prepared.errorCode,
                    errorMessage: prepared.errorMessage,
                });
            }
            preparedInstallPlan = prepared.plan;
        }

        const steps = preparedInstallPlan?.steps ?? operation.plan?.steps;
        const hasVerifyStep = Array.isArray(steps)
            && steps.some(step => step?.type === 'verify');

        if (!hasVerifyStep) {
            const errorMessage = 'L2TP operation plan must include a verify step';
            const finishedAt = this.clock.now();
            await this.operationRepository.setStatus({
                operationId,
                status: 'failed',
                progress: 0,
                errorCode: 'VERIFY_STEP_REQUIRED',
                errorMessage,
                finishedAt,
                journal: {
                    at: finishedAt,
                    level: 'error',
                    code: 'VERIFY_STEP_REQUIRED',
                    message: errorMessage,
                },
            });
            return { claimed: true, operationId, status: 'failed' };
        }

        let candidateContent = null;
        if (preparedInstallPlan) {
            try {
                candidateContent = await this.buildInstallCandidate(preparedInstallPlan);
            } catch {
                return this.failClaimedOperation({
                    operationId,
                    errorCode: 'XRAY_CANDIDATE_FAILED',
                    errorMessage: 'Failed to build the L2TP Xray candidate',
                });
            }
        }

        const lockRequest = {
            node: operation.node,
            owner: this.workerId,
            operationId,
            leaseMs: this.leaseMs,
        };
        const lock = await this.lockService.acquire(lockRequest);

        if (!lock?.ok) {
            const errorCode = lock?.error?.code || 'NODE_LOCK_UNAVAILABLE';
            const errorMessage = 'Could not acquire node operation lock';
            const finishedAt = this.clock.now();
            await this.operationRepository.setStatus({
                operationId,
                status: 'failed',
                progress: 0,
                errorCode,
                errorMessage,
                finishedAt,
                journal: {
                    at: finishedAt,
                    level: 'error',
                    code: errorCode,
                    message: errorMessage,
                },
            });
            return { claimed: true, operationId, status: 'failed' };
        }

        const heartbeat = this.createLeaseHeartbeat({
            operationId,
            node: operation.node,
        });
        const leaseLostResult = () => ({
            claimed: true,
            operationId,
            status: 'running',
            stopped: true,
            errorCode: heartbeat.getError()?.code || 'L2TP_LEASE_RENEWAL_FAILED',
        });

        try {
            let executionSteps = preparedInstallPlan?.steps ?? operation.plan.steps;
            if (preparedInstallPlan) {
                await heartbeat.renewNow();
                if (heartbeat.getError()) return leaseLostResult();
                try {
                    executionSteps = await this.materializeInstallSteps({
                        operation,
                        operationId,
                        plan: preparedInstallPlan,
                        candidateContent,
                    });
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                } catch {
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    await heartbeat.stop();
                    return this.failClaimedOperation({
                        operationId,
                        errorCode: 'SECRET_RESOLUTION_FAILED',
                        errorMessage: 'Failed to resolve L2TP operation secrets',
                    });
                }
            }
            const completedSteps = [];

            for (const [index, step] of executionSteps.entries()) {
                await heartbeat.renewNow();
                if (heartbeat.getError()) return leaseLostResult();

                const stepType = step.type;
                const startingProgress = Math.round((index / executionSteps.length) * 100);
                const completedProgress = Math.round(((index + 1) / executionSteps.length) * 100);

                await this.operationRepository.recordStep({
                    operationId,
                    step: stepType,
                    progress: startingProgress,
                    journal: {
                        at: this.clock.now(),
                        level: 'info',
                        code: 'L2TP_STEP_STARTED',
                        message: `Started L2TP operation step: ${stepType}`,
                    },
                });

                try {
                    await this.executor.executeStep({ operation, step });
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                } catch (error) {
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    await heartbeat.stop();

                    const errorCode = error.code || 'EXECUTOR_FAILED';
                    const errorMessage = error.message || 'L2TP operation executor failed';
                    await this.operationRepository.setStatus({
                        operationId,
                        status: 'rolling_back',
                        step: stepType,
                        progress: startingProgress,
                        errorCode,
                        errorMessage,
                        journal: {
                            at: this.clock.now(),
                            level: 'error',
                            code: 'L2TP_STEP_FAILED',
                            message: `L2TP operation step failed: ${stepType}`,
                        },
                    });

                    try {
                        await this.executor.rollback({
                            operation,
                            completedSteps: [...completedSteps],
                            failedStep: secretFreeStep(step),
                            error,
                        });
                    } catch (rollbackError) {
                        const rollbackErrorCode = rollbackError.code || 'ROLLBACK_FAILED';
                        const rollbackErrorMessage = rollbackError.message
                            || 'L2TP operation rollback failed';
                        const finishedAt = this.clock.now();
                        await this.operationRepository.setStatus({
                            operationId,
                            status: 'failed',
                            step: stepType,
                            progress: startingProgress,
                            errorCode: rollbackErrorCode,
                            errorMessage: rollbackErrorMessage,
                            finishedAt,
                            journal: {
                                at: finishedAt,
                                level: 'error',
                                code: 'L2TP_ROLLBACK_FAILED',
                                message: 'Failed to roll back L2TP operation',
                            },
                        });

                        return { claimed: true, operationId, status: 'failed' };
                    }

                    const finishedAt = this.clock.now();
                    await this.operationRepository.setStatus({
                        operationId,
                        status: 'rolled_back',
                        step: stepType,
                        progress: startingProgress,
                        errorCode,
                        errorMessage,
                        finishedAt,
                        journal: {
                            at: finishedAt,
                            level: 'warn',
                            code: 'L2TP_OPERATION_ROLLED_BACK',
                            message: 'Rolled back L2TP operation after executor failure',
                        },
                    });

                    return { claimed: true, operationId, status: 'rolled_back' };
                }

                completedSteps.push(secretFreeStep(step));
                await this.operationRepository.recordStep({
                    operationId,
                    step: stepType,
                    progress: completedProgress,
                    journal: {
                        at: this.clock.now(),
                        level: 'info',
                        code: 'L2TP_STEP_SUCCEEDED',
                        message: `Completed L2TP operation step: ${stepType}`,
                    },
                });
            }

            await heartbeat.stop();
            const finishedAt = this.clock.now();
            const finalStep = executionSteps[executionSteps.length - 1].type;
            if (operation.kind === 'install') {
                try {
                    if (typeof this.stateReconciler !== 'function') {
                        throw new TypeError('L2TP state reconciler is unavailable');
                    }
                    await this.stateReconciler({ operation, verifiedAt: finishedAt });
                } catch {
                    const errorCode = 'STATE_RECONCILIATION_FAILED';
                    const errorMessage = 'Failed to reconcile verified L2TP state';
                    const reconciliationError = Object.assign(new Error(errorMessage), {
                        code: errorCode,
                    });
                    await this.operationRepository.setStatus({
                        operationId,
                        status: 'rolling_back',
                        step: finalStep,
                        progress: 100,
                        errorCode,
                        errorMessage,
                        journal: {
                            at: finishedAt,
                            level: 'error',
                            code: 'L2TP_STATE_RECONCILIATION_FAILED',
                            message: errorMessage,
                        },
                    });

                    try {
                        await this.executor.rollback({
                            operation,
                            completedSteps: [...completedSteps],
                            failedStep: { type: 'state_reconciliation' },
                            error: reconciliationError,
                        });
                    } catch (rollbackError) {
                        const rollbackErrorCode = rollbackError.code || 'ROLLBACK_FAILED';
                        const rollbackErrorMessage = rollbackError.message
                            || 'L2TP operation rollback failed';
                        const rollbackFinishedAt = this.clock.now();
                        await this.operationRepository.setStatus({
                            operationId,
                            status: 'failed',
                            step: finalStep,
                            progress: 100,
                            errorCode: rollbackErrorCode,
                            errorMessage: rollbackErrorMessage,
                            finishedAt: rollbackFinishedAt,
                            journal: {
                                at: rollbackFinishedAt,
                                level: 'error',
                                code: 'L2TP_ROLLBACK_FAILED',
                                message: 'Failed to roll back L2TP operation',
                            },
                        });
                        return { claimed: true, operationId, status: 'failed' };
                    }

                    const rollbackFinishedAt = this.clock.now();
                    await this.operationRepository.setStatus({
                        operationId,
                        status: 'rolled_back',
                        step: finalStep,
                        progress: 100,
                        errorCode,
                        errorMessage,
                        finishedAt: rollbackFinishedAt,
                        journal: {
                            at: rollbackFinishedAt,
                            level: 'warn',
                            code: 'L2TP_OPERATION_ROLLED_BACK',
                            message: 'Rolled back L2TP operation after state reconciliation failure',
                        },
                    });
                    return { claimed: true, operationId, status: 'rolled_back' };
                }
            }
            await this.operationRepository.setStatus({
                operationId,
                status: 'succeeded',
                step: finalStep,
                progress: 100,
                errorCode: '',
                errorMessage: '',
                finishedAt,
                journal: {
                    at: finishedAt,
                    level: 'info',
                    code: 'L2TP_OPERATION_SUCCEEDED',
                    message: 'L2TP operation succeeded after verification',
                },
            });

            return { claimed: true, operationId, status: 'succeeded' };
        } finally {
            await heartbeat.stop();
            await this.lockService.release({
                node: operation.node,
                owner: this.workerId,
                operationId,
            });
            this.executor.releaseOperation?.(operation);
        }
    }
}

module.exports = {
    L2tpOperationWorker,
};
