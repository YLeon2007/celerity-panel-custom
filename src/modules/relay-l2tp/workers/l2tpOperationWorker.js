'use strict';

class L2tpOperationWorker {
    constructor({
        operationRepository,
        lockService,
        executor,
        workerId,
        leaseMs,
        clock,
        timer = globalThis,
        renewalIntervalMs,
    }) {
        this.operationRepository = operationRepository;
        this.lockService = lockService;
        this.executor = executor;
        this.workerId = workerId;
        this.leaseMs = leaseMs;
        this.clock = clock;
        this.timer = timer;
        this.renewalIntervalMs = renewalIntervalMs
            ?? Math.max(1, Math.floor(leaseMs / 3));
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
        const steps = operation.plan?.steps;
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
            const steps = operation.plan.steps;
            const completedSteps = [];

            for (const [index, step] of steps.entries()) {
                await heartbeat.renewNow();
                if (heartbeat.getError()) return leaseLostResult();

                const stepType = step.type;
                const startingProgress = Math.round((index / steps.length) * 100);
                const completedProgress = Math.round(((index + 1) / steps.length) * 100);

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
                            failedStep: step,
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

                completedSteps.push(step);
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
            const finalStep = steps[steps.length - 1].type;
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
        }
    }
}

module.exports = {
    L2tpOperationWorker,
};
