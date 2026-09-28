'use strict';

function lean(query) {
    return query && typeof query.lean === 'function' ? query.lean() : query;
}

class NodeOperationLockRepository {
    constructor({ model }) {
        if (!model) {
            throw new TypeError('NodeOperationLockRepository requires model');
        }
        Object.defineProperty(this, 'model', {
            value: model,
            enumerable: false,
        });
    }

    findByNode(node) {
        return lean(this.model.findOne({ node }));
    }

    async acquireLease({ node, owner, operationId, generation, leaseUntil }) {
        if (!generation) throw new TypeError('acquireLease requires generation');
        try {
            const lock = await this.model.create({
                node, owner, operationId, generation, leaseUntil, remoteUncertain: true,
            });

            return {
                acquired: true,
                lock: typeof lock.toObject === 'function' ? lock.toObject() : lock,
            };
        } catch (error) {
            if (error?.code !== 11000) throw error;

            return {
                acquired: false,
                currentLock: await this.findByNode(node),
            };
        }
    }

    save() {
        throw new Error('Unsafe lock save is disabled; use insert-only acquireLease');
    }

    async renewLease({ node, owner, operationId, generation, now, leaseUntil }) {
        if (!generation) return false;
        const result = await this.model.updateOne({
            node,
            owner,
            operationId,
            generation,
            leaseUntil: { $gt: now },
        }, {
            $set: { leaseUntil },
        }, { runValidators: true });

        return result.matchedCount === 1;
    }

    async deleteVerifiedOwned({ node, owner, operationId, generation }) {
        if (!generation) return false;
        const result = await this.model.deleteOne({
            node,
            owner,
            operationId,
            generation,
            remoteUncertain: true,
        });
        return result.deletedCount === 1;
    }

    async deleteOwned({ node, owner, operationId, generation }) {
        if (!generation) return false;
        const result = await this.model.deleteOne({
            node,
            owner,
            operationId,
            generation,
            remoteUncertain: false,
        });
        return result.deletedCount === 1;
    }

    deleteByNode() {
        throw new Error('Unsafe lock deleteByNode is disabled');
    }
}

module.exports = {
    NodeOperationLockRepository,
};
