'use strict';

const RESULT_CODES = Object.freeze({
    ACQUIRED: 'NODE_OPERATION_LOCK_ACQUIRED',
    RENEWED: 'NODE_OPERATION_LOCK_RENEWED',
    CONFLICT: 'NODE_OPERATION_LOCK_CONFLICT',
    RELEASED: 'NODE_OPERATION_LOCK_RELEASED',
    NOT_OWNED: 'NODE_OPERATION_LOCK_NOT_OWNED',
    BATCH_ACQUIRED: 'NODE_OPERATION_LOCK_BATCH_ACQUIRED',
});

class NodeOperationLockService {
    constructor({ repository, clock }) {
        this.repository = repository;
        this.clock = clock;
    }

    async acquire({ node, owner, operationId, leaseMs }) {
        const now = this.clock.now();
        const lease = {
            node,
            owner,
            operationId,
            leaseUntil: new Date(now.getTime() + leaseMs),
        };
        const claim = await this.repository.acquireLease({
            ...lease,
            now,
        });

        if (!claim?.acquired) {
            const currentLock = claim?.currentLock;
            return {
                ok: false,
                error: {
                    code: RESULT_CODES.CONFLICT,
                    node,
                    owner: currentLock?.owner,
                    operationId: currentLock?.operationId,
                    leaseUntil: currentLock?.leaseUntil,
                },
            };
        }

        const previousLock = claim.previousLock;
        const isRenewal = Boolean(previousLock)
            && previousLock.leaseUntil.getTime() > now.getTime()
            && String(previousLock.owner) === String(owner)
            && String(previousLock.operationId) === String(operationId);

        return {
            ok: true,
            code: isRenewal ? RESULT_CODES.RENEWED : RESULT_CODES.ACQUIRED,
            lock: lease,
        };
    }

    async renew({ node, owner, operationId, leaseMs }) {
        const now = this.clock.now();
        const leaseUntil = new Date(now.getTime() + leaseMs);
        const renewed = await this.repository.renewLease({
            node,
            owner,
            operationId,
            now,
            leaseUntil,
        });

        if (!renewed) {
            return {
                ok: false,
                error: {
                    code: RESULT_CODES.NOT_OWNED,
                    node,
                },
            };
        }

        return {
            ok: true,
            code: RESULT_CODES.RENEWED,
            lock: {
                node,
                owner,
                operationId,
                leaseUntil,
            },
        };
    }

    async acquireMany({ nodeIds, owner, operationId, leaseMs }) {
        const sortedNodeIds = [...nodeIds].sort((left, right) => {
            const leftKey = String(left);
            const rightKey = String(right);
            if (leftKey < rightKey) return -1;
            if (leftKey > rightKey) return 1;
            return 0;
        });
        const results = [];

        for (const node of sortedNodeIds) {
            results.push(await this.acquire({ node, owner, operationId, leaseMs }));
        }

        return {
            ok: true,
            code: RESULT_CODES.BATCH_ACQUIRED,
            results,
        };
    }

    async release({ node, owner, operationId }) {
        const released = await this.repository.deleteOwned({
            node,
            owner,
            operationId,
        });

        if (!released) {
            return {
                ok: false,
                error: {
                    code: RESULT_CODES.NOT_OWNED,
                    node,
                },
            };
        }

        return {
            ok: true,
            code: RESULT_CODES.RELEASED,
            node,
        };
    }
}

module.exports = {
    NodeOperationLockService,
    RESULT_CODES,
};
