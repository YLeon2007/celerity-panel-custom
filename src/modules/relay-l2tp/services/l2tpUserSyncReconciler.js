'use strict';

const FINALIZE_REJECTED = Object.freeze({
    ok: false,
    error: Object.freeze({
        code: 'L2TP_USER_SYNC_FINALIZE_REJECTED',
        message: 'Verified L2TP user sync could not be finalized',
    }),
});

function finalizeRejected() {
    return {
        ok: FINALIZE_REJECTED.ok,
        error: { ...FINALIZE_REJECTED.error },
    };
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function operationSnapshot(operation) {
    return {
        operationId: entityId(operation?._id ?? operation?.id),
        relayNode: entityId(operation?.node),
        credentialRevision: operation?.plan?.desired?.credentialRevision,
    };
}

function secretFreeUserSnapshot(user) {
    return {
        id: entityId(user),
        relayNode: entityId(user?.relayNode),
        login: user?.login,
        ip: user?.ip,
        enabled: user?.enabled,
        desiredRevision: user?.desiredRevision,
    };
}

function safeVerification(verification) {
    return {
        ok: verification?.ok,
        credentialRevision: verification?.credentialRevision,
        enabledUserCount: verification?.enabledUserCount,
        managedUserCount: verification?.managedUserCount,
        code: verification?.code,
    };
}

function safeSuccess(finalized, expectedOperationId, expectedUserCount) {
    if (
        !finalized
        || entityId(finalized.operationId) !== expectedOperationId
        || finalized.reconciledUserCount !== expectedUserCount
        || !(finalized.finalizedAt instanceof Date)
        || !Number.isFinite(finalized.finalizedAt.getTime())
    ) {
        return null;
    }
    return {
        ok: true,
        operationId: expectedOperationId,
        reconciledUserCount: expectedUserCount,
        finalizedAt: finalized.finalizedAt,
    };
}

class L2tpUserSyncReconciler {
    constructor({ repository, clock } = {}) {
        if (!repository || typeof repository.finalizeVerifiedSync !== 'function') {
            throw new TypeError('L2TP user sync reconciliation repository is required');
        }
        if (!clock || typeof clock.now !== 'function') {
            throw new TypeError('L2TP user sync reconciliation clock is required');
        }
        this.repository = repository;
        this.clock = clock;
    }

    async finalizeVerifiedSync(request = {}) {
        if (request && (Object.hasOwn(request, 'ownerGeneration')
            || request.operation && (request.operation.ownerGeneration != null
                || request.operation.admissionId != null))) return finalizeRejected();
        return this._finalizeVerifiedSync(request, false);
    }

    async finalizeClaimedVerifiedSync(request = {}) {
        if (!Number.isSafeInteger(request?.ownerGeneration) || request.ownerGeneration < 1) {
            return finalizeRejected();
        }
        return this._finalizeVerifiedSync(request, true);
    }

    async _finalizeVerifiedSync({ operation, resolvedUsers, verification, workerId, ownerGeneration } = {}, claimed) {
        try {
            const snapshot = operationSnapshot(operation);
            const repositoryMethod = claimed ? 'finalizeClaimedVerifiedSync' : 'finalizeVerifiedSync';
            if (typeof this.repository[repositoryMethod] !== 'function') return finalizeRejected();
            const finalized = await this.repository[repositoryMethod]({
                ...snapshot,
                resolvedUsers: resolvedUsers.map(secretFreeUserSnapshot),
                verification: safeVerification(verification),
                workerId,
                ...(claimed ? { ownerGeneration } : {}),
                now: this.clock.now(),
            });
            return safeSuccess(finalized, snapshot.operationId, resolvedUsers.length)
                ?? finalizeRejected();
        } catch {
            return finalizeRejected();
        }
    }
}

module.exports = {
    FINALIZE_REJECTED,
    L2tpUserSyncReconciler,
};
