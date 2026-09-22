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

    save({ node, owner, operationId, leaseUntil }) {
        return lean(this.model.findOneAndUpdate(
            { node },
            {
                $set: {
                    owner,
                    operationId,
                    leaseUntil,
                },
            },
            {
                upsert: true,
                new: true,
                runValidators: true,
                setDefaultsOnInsert: true,
            },
        ));
    }

    async renewLease({ node, owner, operationId, now, leaseUntil }) {
        const result = await this.model.updateOne({
            node,
            owner,
            operationId,
            leaseUntil: { $gt: now },
        }, {
            $set: { leaseUntil },
        }, { runValidators: true });

        return result.matchedCount === 1;
    }

    async deleteByNode(node) {
        const result = await this.model.deleteOne({ node });
        return result.deletedCount === 1;
    }
}

module.exports = {
    NodeOperationLockRepository,
};
