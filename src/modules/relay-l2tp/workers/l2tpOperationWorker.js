'use strict';

const {
    materializeSyncUsersOperation,
} = require('../services/l2tpOperationMaterializer');

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

function verifiedUsersAttestation(result, plan, resolvedUsers) {
    const expectedKeys = [
        'ok',
        'credentialRevision',
        'enabledUserCount',
        'managedUserCount',
        'code',
    ];
    const enabledUserCount = resolvedUsers.filter(user => user.enabled === true).length;
    if (
        !result
        || typeof result !== 'object'
        || Array.isArray(result)
        || Object.keys(result).sort().join('\0') !== expectedKeys.sort().join('\0')
        || result.ok !== true
        || result.code !== 'USERS_VERIFIED'
        || result.credentialRevision !== plan.desired.credentialRevision
        || !Number.isSafeInteger(result.enabledUserCount)
        || result.enabledUserCount !== enabledUserCount
        || !Number.isSafeInteger(result.managedUserCount)
        || result.managedUserCount !== enabledUserCount
    ) {
        const error = new Error('L2TP user verification attestation was rejected');
        error.code = 'USER_SYNC_VERIFICATION_FAILED';
        throw error;
    }
    return {
        ok: true,
        credentialRevision: result.credentialRevision,
        enabledUserCount: result.enabledUserCount,
        managedUserCount: result.managedUserCount,
        code: result.code,
    };
}

function lostClaim() {
    const error = new Error('L2TP operation generation or lease was lost');
    error.code = 'L2TP_OPERATION_LEASE_LOST';
    return error;
}

class L2tpOperationWorker {
    constructor({
        operationRepository,
        remoteAdmissionRepository,
        // Test-only opt-in. Production must not consume counted admissions
        // without the explicit TEST composition predicate.
        enableUnsafeExecutionForTests = false,
        lockService,
        executor,
        secretResolver,
        userSnapshotResolver,
        userSyncReconciler,
        stateReconciler,
        candidateService,
        operationMaterializer,
        afterInstallSucceeded,
        workerId,
        leaseMs,
        clock,
        timer = globalThis,
        renewalIntervalMs,
    }) {
        this.operationRepository = operationRepository;
        this.remoteAdmissionRepository = remoteAdmissionRepository;
        this.enableUnsafeExecutionForTests = enableUnsafeExecutionForTests === true;
        this.nextClaimKind = 'install';
        this.lockService = lockService;
        this.executor = executor;
        this.secretResolver = secretResolver;
        this.userSnapshotResolver = userSnapshotResolver;
        this.userSyncReconciler = userSyncReconciler;
        this.stateReconciler = stateReconciler;
        this.candidateService = candidateService;
        this.operationMaterializer = operationMaterializer;
        this.afterInstallSucceeded = afterInstallSucceeded;
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

    async writeClaimed(method, claim, fields = {}) {
        const matched = await this.operationRepository[method]({
            ...claim, now: this.clock.now(), ...fields,
        });
        if (matched !== true) throw lostClaim();
    }

    async failClaimedOperation({ claim, operation, lockGeneration, heartbeat, errorCode, errorMessage }) {
        const finishedAt = this.clock.now();
        await this.writeClaimed('transitionClaimed', claim, {
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
        const admissionSettled = await this.completeTerminalAdmission(operation, claim,
            { lockGeneration, heartbeat });
        return {
            claimed: true,
            operationId: claim.operationId,
            status: 'failed',
            ...(admissionSettled ? {} : {
                stopped: true,
                errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED',
            }),
        };
    }

    async completeTerminalAdmission(operation, claim, { lockGeneration, heartbeat } = {}) {
        const admissions = this.remoteAdmissionRepository;
        if (lockGeneration) {
            await heartbeat?.stop();
            try {
                const released = await this.lockService.releaseVerified({
                    node: operation.node,
                    owner: claim.owner,
                    operationId: claim.operationId,
                    generation: lockGeneration,
                });
                if (released?.ok !== true) throw new Error('Exact node lock release not confirmed');
            } catch {
                await this.retainAdmissionForRecovery(operation, claim);
                return false;
            }
        }
        if (typeof admissions?.completeTerminalOperation !== 'function') return true;
        try {
            const completed = await admissions.completeTerminalOperation({
                admissionId: operation?.admissionId,
                operationId: claim.operationId,
                nodeId: entityId(operation?.node),
                owner: claim.owner,
                ownerGeneration: claim.ownerGeneration,
                kind: operation?.kind,
            });
            return completed === true;
        } catch {
            try {
                await admissions.markOperationRecoveryRequired({
                    admissionId: operation?.admissionId,
                    operationId: claim.operationId,
                    nodeId: entityId(operation?.node),
                    owner: claim.owner,
                    ownerGeneration: claim.ownerGeneration,
                    kind: operation?.kind,
                });
            } catch { /* preserve the counted fence for authoritative recovery */ }
            return false;
        }
    }

    async retainAdmissionForRecovery(operation, claim) {
        const admissions = this.remoteAdmissionRepository;
        if (typeof admissions?.markOperationRecoveryRequired !== 'function') return true;
        try {
            return await admissions.markOperationRecoveryRequired({
                admissionId: operation?.admissionId,
                operationId: claim.operationId,
                nodeId: entityId(operation?.node),
                owner: claim.owner,
                ownerGeneration: claim.ownerGeneration,
                kind: operation?.kind,
            }) === true;
        } catch {
            return false;
        }
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

    async prepareSyncUsersPlan(operation) {
        try {
            const prepared = materializeSyncUsersOperation({ operation, plan: operation.plan });
            return { plan: prepared.persistedPlan };
        } catch {
            return {
                errorCode: 'INVALID_SYNC_USERS_PLAN',
                errorMessage: 'The claimed L2TP sync_users plan is invalid',
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

    async resolveSyncUsersSnapshot({ operation, operationId, plan }) {
        if (typeof this.userSnapshotResolver !== 'function') {
            throw new TypeError('L2TP user snapshot resolver is unavailable');
        }
        return this.userSnapshotResolver({
            operationId,
            kind: operation.kind,
            nodeId: entityId(operation.node),
            credentialRevision: plan.desired?.credentialRevision,
        });
    }

    materializeSyncUsersSteps({ operation, plan, snapshot }) {
        const materialized = materializeSyncUsersOperation({ operation, plan, snapshot });
        return attachRemoteArtifacts(
            materialized.persistedPlan,
            materialized.remoteArtifacts,
        );
    }

    createLeaseHeartbeat({ claim, node, lockGeneration }) {
        let intervalId;
        let inFlight = null;
        let renewalError = null;
        let stopped = false;
        let paused = false;
        let activeClaim = claim;

        const clear = () => {
            if (intervalId === undefined) return;
            this.timer.clearInterval(intervalId);
            intervalId = undefined;
        };
        const renew = async () => {
            const operationRenewed = await this.operationRepository.renewClaimed({
                ...activeClaim,
                leaseMs: this.leaseMs,
                now: this.clock.now(),
            });
            if (!operationRenewed) throw lostClaim();

            const lockRenewed = await this.lockService.renew({
                node,
                owner: this.workerId,
                operationId: claim.operationId,
                generation: lockGeneration,
                leaseMs: this.leaseMs,
            });
            if (!lockRenewed?.ok) {
                const error = new Error('L2TP node operation lock is no longer owned by this worker');
                error.code = lockRenewed?.error?.code || 'NODE_OPERATION_LOCK_LOST';
                throw error;
            }
        };
        const tick = () => {
            if (stopped || paused || renewalError) return inFlight || Promise.resolve();
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
            // Serialize the status CAS with renewals: no tick may use the
            // running fence after the operation enters rolling_back.
            async switchToRollback(transition) {
                paused = true;
                if (inFlight) await inFlight;
                if (renewalError) return false;
                await transition();
                activeClaim = { ...claim, expectedStatus: 'rolling_back' };
                paused = false;
                await tick();
                return !renewalError;
            },
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
        // A crash after exact lock release but before admission completion can
        // leave a terminal operation counted. Reconcile durable terminal proof
        // before admitting the next queued operation; never recover an active
        // SSH attempt merely because its lease expired.
        if (this.enableUnsafeExecutionForTests
            && typeof this.remoteAdmissionRepository?.recoverSettledAdmissions === 'function') {
            await this.remoteAdmissionRepository.recoverSettledAdmissions();
        }
        let claimedId;
        let claimedStatus = 'running';
        try {
            return await this.runClaimedOperation((id, status = 'running') => {
                claimedId = id;
                claimedStatus = status;
            });
        } catch (error) {
            if (error?.code !== 'L2TP_OPERATION_LEASE_LOST' || !claimedId) throw error;
            return { claimed: true, operationId: claimedId, status: claimedStatus,
                stopped: true, errorCode: error.code };
        }
    }

    async runClaimedOperation(rememberClaim) {
        // Never consume counted admission while execution/finalization is not
        // fenced. Missing transactional claims are likewise not a reason to
        // fall back to the generic (uncounted) operation repository.
        if (!this.enableUnsafeExecutionForTests
            || typeof this.remoteAdmissionRepository?.claimQueuedInstall !== 'function'
            || typeof this.remoteAdmissionRepository?.claimQueuedSyncUsers !== 'function') {
            return { claimed: false, unavailable: true };
        }
        const request = {
            owner: this.workerId,
            leaseMs: this.leaseMs,
            now: this.clock.now(),
        };
        const firstKind = this.nextClaimKind;
        const secondKind = firstKind === 'install' ? 'sync_users' : 'install';
        const claimQueued = kind => kind === 'install'
            ? this.remoteAdmissionRepository.claimQueuedInstall(request)
            : this.remoteAdmissionRepository.claimQueuedSyncUsers(request);
        const operation = await claimQueued(firstKind) || await claimQueued(secondKind);

        if (!operation) return { claimed: false };

        // A malformed/injected claim must never reach lock acquisition or SSH.
        if (!['install', 'sync_users'].includes(operation.kind)
            || operation.status !== 'running'
            || operation.leaseOwner !== this.workerId
            || !operation.admissionId
            || !Number.isSafeInteger(operation.ownerGeneration)
            || operation.ownerGeneration < 1) {
            return { claimed: false, unavailable: true };
        }
        this.nextClaimKind = operation.kind === 'install' ? 'sync_users' : 'install';

        const operationId = String(operation._id ?? operation.id);
        rememberClaim(operationId);
        const claim = Object.freeze({ operationId, owner: this.workerId,
            ownerGeneration: operation.ownerGeneration, expectedStatus: 'running' });
        const rollbackClaim = Object.freeze({ ...claim, expectedStatus: 'rolling_back' });
        let preparedInstallPlan = null;
        let preparedSyncUsersPlan = null;
        if (operation.kind === 'install') {
            const prepared = await this.prepareInstallPlan(operation);
            if (prepared.errorCode) {
                return this.failClaimedOperation({
                    claim,
                    operation,
                    errorCode: prepared.errorCode,
                    errorMessage: prepared.errorMessage,
                });
            }
            preparedInstallPlan = prepared.plan;
        } else if (operation.kind === 'sync_users') {
            const prepared = await this.prepareSyncUsersPlan(operation);
            if (prepared.errorCode) {
                return this.failClaimedOperation({
                    claim,
                    operation,
                    errorCode: prepared.errorCode,
                    errorMessage: prepared.errorMessage,
                });
            }
            preparedSyncUsersPlan = prepared.plan;
        }

        const steps = preparedInstallPlan?.steps
            ?? preparedSyncUsersPlan?.steps
            ?? operation.plan?.steps;
        const requiredVerifyStep = operation.kind === 'sync_users' ? 'verify_users' : 'verify';
        const hasVerifyStep = Array.isArray(steps)
            && steps.some(step => step?.type === requiredVerifyStep);

        if (!hasVerifyStep) {
            const errorMessage = 'L2TP operation plan must include a verify step';
            const finishedAt = this.clock.now();
            await this.writeClaimed('transitionClaimed', claim, {
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
            const admissionSettled = await this.completeTerminalAdmission(operation, claim);
            return {
                claimed: true,
                operationId,
                status: 'failed',
                ...(admissionSettled ? {} : {
                    stopped: true,
                    errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED',
                }),
            };
        }

        let candidateContent = null;
        if (preparedInstallPlan) {
            try {
                candidateContent = await this.buildInstallCandidate(preparedInstallPlan);
            } catch {
                return this.failClaimedOperation({
                    claim,
                    operation,
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
        let lock;
        try {
            lock = await this.lockService.acquire(lockRequest);
        } catch {
            const retained = await this.retainAdmissionForRecovery(operation, claim);
            return {
                claimed: true,
                operationId,
                status: 'running',
                stopped: true,
                errorCode: retained
                    ? 'NODE_OPERATION_LOCK_UNCERTAIN'
                    : 'REMOTE_ADMISSION_RECOVERY_FAILED',
            };
        }

        if (!lock?.ok) {
            const errorCode = lock?.error?.code || 'NODE_LOCK_UNAVAILABLE';
            const errorMessage = 'Could not acquire node operation lock';
            const finishedAt = this.clock.now();
            await this.writeClaimed('transitionClaimed', claim, {
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
            const admissionSettled = await this.completeTerminalAdmission(operation, claim);
            return {
                claimed: true,
                operationId,
                status: 'failed',
                ...(admissionSettled ? {} : {
                    stopped: true,
                    errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED',
                }),
            };
        }

        if (typeof lock.lock?.generation !== 'string' || !lock.lock.generation) {
            // A lock without its distinct UUID fence cannot be renewed or released.
            // It remains remote-uncertain; never execute SSH on this claim.
            const retained = await this.retainAdmissionForRecovery(operation, claim);
            return { claimed: true, operationId, status: 'running', stopped: true,
                errorCode: retained ? 'NODE_OPERATION_LOCK_LOST' : 'REMOTE_ADMISSION_RECOVERY_FAILED' };
        }
        const lockGeneration = lock.lock.generation;
        const heartbeat = this.createLeaseHeartbeat({
            claim,
            node: operation.node,
            lockGeneration,
        });
        let currentStatus = 'running';
        const leaseLostResult = async (fenceErrorCode) => {
            const retained = await this.retainAdmissionForRecovery(operation, claim);
            return {
                claimed: true,
                operationId,
                status: currentStatus,
                stopped: true,
                errorCode: retained
                    ? fenceErrorCode || heartbeat.getError()?.code || 'L2TP_LEASE_RENEWAL_FAILED'
                    : 'REMOTE_ADMISSION_RECOVERY_FAILED',
            };
        };
        const enterRollback = async fields => heartbeat.switchToRollback(async () => {
            await this.writeClaimed('transitionClaimed', claim, fields);
            currentStatus = 'rolling_back';
            rememberClaim(operationId, 'rolling_back');
        });
        const rollbackLeaseValid = async () => {
            await heartbeat.waitForIdle();
            if (heartbeat.getError()) return false;
            await heartbeat.renewNow();
            return !heartbeat.getError();
        };
        try {
            let executionSteps = preparedInstallPlan?.steps
                ?? preparedSyncUsersPlan?.steps
                ?? operation.plan.steps;
            let resolvedSyncUsers = null;
            let userVerification = null;
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
                        claim,
                        operation,
                        lockGeneration,
                        heartbeat,
                        errorCode: 'SECRET_RESOLUTION_FAILED',
                        errorMessage: 'Failed to resolve L2TP operation secrets',
                    });
                }
            } else if (preparedSyncUsersPlan) {
                await heartbeat.renewNow();
                if (heartbeat.getError()) return leaseLostResult();
                let snapshot;
                try {
                    snapshot = await this.resolveSyncUsersSnapshot({
                        operation,
                        operationId,
                        plan: preparedSyncUsersPlan,
                    });
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    await heartbeat.renewNow();
                    if (heartbeat.getError()) return leaseLostResult();
                    executionSteps = this.materializeSyncUsersSteps({
                        operation,
                        plan: preparedSyncUsersPlan,
                        snapshot,
                    });
                    resolvedSyncUsers = snapshot.users;
                } catch {
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    await heartbeat.stop();
                    return this.failClaimedOperation({
                        claim,
                        operation,
                        lockGeneration,
                        heartbeat,
                        errorCode: 'USER_SNAPSHOT_RESOLUTION_FAILED',
                        errorMessage: 'Failed to resolve the current L2TP user snapshot',
                    });
                }
            }
            const completedSteps = [];

            for (const [index, step] of executionSteps.entries()) {
                const stepType = step.type;
                const startingProgress = Math.round((index / executionSteps.length) * 100);
                const completedProgress = Math.round(((index + 1) / executionSteps.length) * 100);

                await this.writeClaimed('recordClaimedStep', claim, {
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

                await heartbeat.renewNow();
                if (heartbeat.getError()) return leaseLostResult();

                try {
                    const stepResult = await this.executor.executeStep({ operation, step });
                    if (preparedSyncUsersPlan && stepType === 'verify_users') {
                        userVerification = verifiedUsersAttestation(
                            stepResult,
                            preparedSyncUsersPlan,
                            resolvedSyncUsers,
                        );
                    }
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                } catch (error) {
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    // The SSH call may have timed out locally while its remote
                    // command keeps running. Rollback cannot prove quiescence.
                    if (error?.remoteOutcomeUncertain === true) {
                        await this.retainAdmissionForRecovery(operation, claim);
                        return { claimed: true, operationId: claim.operationId,
                            status: 'running', stopped: true,
                            errorCode: 'REMOTE_COMMAND_OUTCOME_UNCERTAIN' };
                    }
                    const errorCode = error.code || 'EXECUTOR_FAILED';
                    const errorMessage = error.message || 'L2TP operation executor failed';
                    if (!await enterRollback({
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
                    })) return leaseLostResult();

                    try {
                        await this.executor.rollback({
                            operation,
                            completedSteps: [...completedSteps],
                            failedStep: secretFreeStep(step),
                            error,
                        });
                    } catch (rollbackError) {
                        if (!await rollbackLeaseValid()) return leaseLostResult();
                        const rollbackErrorCode = rollbackError.code || 'ROLLBACK_FAILED';
                        const rollbackErrorMessage = rollbackError.message
                            || 'L2TP operation rollback failed';
                        const finishedAt = this.clock.now();
                        await this.writeClaimed('transitionClaimed', rollbackClaim, {
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

                        const retained = await this.retainAdmissionForRecovery(operation, rollbackClaim);
                        return {
                            claimed: true,
                            operationId,
                            status: 'failed',
                            ...(retained ? {} : {
                                stopped: true,
                                errorCode: 'REMOTE_ADMISSION_RECOVERY_FAILED',
                            }),
                        };
                    }

                    if (!await rollbackLeaseValid()) return leaseLostResult();
                    const finishedAt = this.clock.now();
                    await this.writeClaimed('transitionClaimed', rollbackClaim, {
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

                    const admissionSettled = await this.completeTerminalAdmission(operation, rollbackClaim,
                        { lockGeneration, heartbeat });
                    return {
                        claimed: true,
                        operationId,
                        status: 'rolled_back',
                        ...(admissionSettled ? {} : {
                            stopped: true,
                            errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED',
                        }),
                    };
                }

                completedSteps.push(secretFreeStep(step));
                await this.writeClaimed('recordClaimedStep', claim, {
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

            if (operation.kind === 'sync_users') {
                await heartbeat.renewNow();
                if (heartbeat.getError()) return leaseLostResult();
            }
            const verifiedAt = this.clock.now();
            const finalStep = executionSteps[executionSteps.length - 1].type;
            if (operation.kind === 'install') {
                try {
                    if (typeof this.stateReconciler !== 'function') {
                        throw new TypeError('L2TP state reconciler is unavailable');
                    }
                    await this.stateReconciler({ operation, verifiedAt, claim, lockGeneration });
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    await heartbeat.renewNow();
                    if (heartbeat.getError()) return leaseLostResult();
                } catch (reconciliationFailure) {
                    // A stale owner must not issue rollback SSH after losing its fence.
                    if (['L2TP_OPERATION_FENCE_REJECTED', 'L2TP_NODE_FENCE_REJECTED']
                        .includes(reconciliationFailure?.code)) {
                        return leaseLostResult(reconciliationFailure.code);
                    }
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    const errorCode = 'STATE_RECONCILIATION_FAILED';
                    const errorMessage = 'Failed to reconcile verified L2TP state';
                    const reconciliationError = Object.assign(new Error(errorMessage), {
                        code: errorCode,
                    });
                    if (!await enterRollback({
                        operationId,
                        status: 'rolling_back',
                        step: finalStep,
                        progress: 100,
                        errorCode,
                        errorMessage,
                        journal: {
                            at: verifiedAt,
                            level: 'error',
                            code: 'L2TP_STATE_RECONCILIATION_FAILED',
                            message: errorMessage,
                        },
                    })) return leaseLostResult();

                    try {
                        await this.executor.rollback({
                            operation,
                            completedSteps: [...completedSteps],
                            failedStep: { type: 'state_reconciliation' },
                            error: reconciliationError,
                        });
                    } catch (rollbackError) {
                        if (!await rollbackLeaseValid()) return leaseLostResult();
                        const rollbackErrorCode = rollbackError.code || 'ROLLBACK_FAILED';
                        const rollbackErrorMessage = rollbackError.message
                            || 'L2TP operation rollback failed';
                        const rollbackFinishedAt = this.clock.now();
                        await this.writeClaimed('transitionClaimed', rollbackClaim, {
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
                        const retained = await this.retainAdmissionForRecovery(operation, rollbackClaim);
                        return {
                            claimed: true,
                            operationId,
                            status: 'failed',
                            ...(retained ? {} : {
                                stopped: true,
                                errorCode: 'REMOTE_ADMISSION_RECOVERY_FAILED',
                            }),
                        };
                    }

                    if (!await rollbackLeaseValid()) return leaseLostResult();
                    const rollbackFinishedAt = this.clock.now();
                    await this.writeClaimed('transitionClaimed', rollbackClaim, {
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
                    const admissionSettled = await this.completeTerminalAdmission(operation, rollbackClaim,
                        { lockGeneration, heartbeat });
                    return {
                        claimed: true,
                        operationId,
                        status: 'rolled_back',
                        ...(admissionSettled ? {} : {
                            stopped: true,
                            errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED',
                        }),
                    };
                }
            } else if (operation.kind === 'sync_users') {
                try {
                    if (typeof this.userSyncReconciler?.finalizeClaimedVerifiedSync !== 'function') {
                        const unavailable = new Error('L2TP user sync reconciler is unavailable');
                        unavailable.code = 'L2TP_USER_SYNC_RECONCILER_UNAVAILABLE';
                        throw unavailable;
                    }
                    const finalized = await this.userSyncReconciler.finalizeClaimedVerifiedSync({
                        operation,
                        resolvedUsers: resolvedSyncUsers,
                        verification: userVerification,
                        workerId: this.workerId,
                        ownerGeneration: claim.ownerGeneration,
                    });
                    if (finalized?.ok !== true) throw lostClaim();
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    await heartbeat.renewNow();
                    if (heartbeat.getError()) return leaseLostResult();
                } catch (error) {
                    if (error?.code === 'L2TP_OPERATION_LEASE_LOST') throw error;
                    await heartbeat.waitForIdle();
                    if (heartbeat.getError()) return leaseLostResult();
                    const errorCode = 'USER_SYNC_FINALIZATION_FAILED';
                    const errorMessage = 'Failed to finalize verified L2TP user sync';
                    const finalizationError = Object.assign(new Error(errorMessage), {
                        code: errorCode,
                    });
                    if (!await enterRollback({
                        operationId,
                        status: 'rolling_back',
                        step: finalStep,
                        progress: 100,
                        errorCode,
                        errorMessage,
                        journal: {
                            at: verifiedAt,
                            level: 'error',
                            code: 'L2TP_USER_SYNC_FINALIZATION_FAILED',
                            message: errorMessage,
                        },
                    })) return leaseLostResult();

                    try {
                        await this.executor.rollback({
                            operation,
                            completedSteps: [...completedSteps],
                            failedStep: { type: 'user_sync_finalization' },
                            error: finalizationError,
                        });
                    } catch (rollbackError) {
                        if (!await rollbackLeaseValid()) return leaseLostResult();
                        const rollbackErrorCode = rollbackError.code || 'ROLLBACK_FAILED';
                        const rollbackErrorMessage = rollbackError.message
                            || 'L2TP operation rollback failed';
                        const rollbackFinishedAt = this.clock.now();
                        await this.writeClaimed('transitionClaimed', rollbackClaim, {
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
                        const retained = await this.retainAdmissionForRecovery(operation, rollbackClaim);
                        return {
                            claimed: true,
                            operationId,
                            status: 'failed',
                            ...(retained ? {} : {
                                stopped: true,
                                errorCode: 'REMOTE_ADMISSION_RECOVERY_FAILED',
                            }),
                        };
                    }

                    if (!await rollbackLeaseValid()) return leaseLostResult();
                    const rollbackFinishedAt = this.clock.now();
                    await this.writeClaimed('transitionClaimed', rollbackClaim, {
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
                            message: 'Rolled back L2TP operation after user sync finalization failure',
                        },
                    });
                    const admissionSettled = await this.completeTerminalAdmission(operation, rollbackClaim,
                        { lockGeneration, heartbeat });
                    return {
                        claimed: true,
                        operationId,
                        status: 'rolled_back',
                        ...(admissionSettled ? {} : {
                            stopped: true,
                            errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED',
                        }),
                    };
                }
            }
            const finishedAt = this.clock.now();
            await this.writeClaimed('succeedGenerationClaimed', claim, {
                now: finishedAt,
                step: finalStep,
                journal: {
                    at: finishedAt,
                    level: 'info',
                    code: 'L2TP_OPERATION_SUCCEEDED',
                    message: 'L2TP operation succeeded after verification',
                },
            });

            // The remote executor is quiescent and the exact node generation
            // must be released before lifting the counted topology fence.
            // A failed release keeps admission held for manual recovery.
            await heartbeat.stop();
            let released;
            try {
                released = await this.lockService.releaseVerified?.({
                    node: operation.node,
                    owner: this.workerId,
                    operationId,
                    generation: lockGeneration,
                });
            } catch { /* Keep the counted admission held. */ }
            if (released?.ok !== true) {
                await this.retainAdmissionForRecovery(operation, claim);
                return { claimed: true, operationId, status: 'succeeded', stopped: true,
                    errorCode: 'NODE_LOCK_RELEASE_FAILED' };
            }
            if (typeof this.remoteAdmissionRepository.completeVerifiedOperation !== 'function') {
                return { claimed: true, operationId, status: 'succeeded', stopped: true,
                    errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED' };
            }
            try {
                const completed = await this.remoteAdmissionRepository.completeVerifiedOperation({
                    admissionId: operation.admissionId,
                    operationId,
                    nodeId: entityId(operation.node),
                    owner: this.workerId,
                    ownerGeneration: claim.ownerGeneration,
                    kind: operation.kind,
                });
                if (completed !== true) throw new Error('Admission completion not confirmed');
            } catch {
                await this.retainAdmissionForRecovery(operation, claim);
                return { claimed: true, operationId, status: 'succeeded', stopped: true,
                    errorCode: 'REMOTE_ADMISSION_COMPLETION_FAILED' };
            }

            // The install may have advanced the topology revision (route-group
            // paths rebuilt for the relay). Queue a topology deploy right away
            // so relay ingress listeners appear without a manual chain sync.
            // Best effort: a failed auto-deploy must not fail the install.
            if (operation.kind === 'install' && typeof this.afterInstallSucceeded === 'function') {
                try {
                    await this.afterInstallSucceeded({ operationId, node: operation.node });
                } catch { /* manual chain sync remains available */ }
            }

            return { claimed: true, operationId, status: 'succeeded' };
        } finally {
            await heartbeat.stop();
            // Counted locks remain remote-uncertain. There is no attested
            // remote-completion API to clear that bit, so retain the UUID lock
            // even after a verified operation succeeds.
            this.executor.releaseOperation?.(operation);
        }
    }
}

module.exports = {
    L2tpOperationWorker,
};
