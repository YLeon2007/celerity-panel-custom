'use strict';

class L2tpOperationRepository {
    constructor({ model }) {
        this.model = model;
    }

    async claimNext({ owner, leaseMs, now }) {
        const leaseUntil = new Date(now.getTime() + leaseMs);

        return this.model.findOneAndUpdate({
            $or: [
                { status: 'queued' },
                {
                    status: 'running',
                    leaseUntil: { $lte: now },
                },
            ],
        }, {
            $set: {
                status: 'running',
                leaseOwner: owner,
                leaseUntil,
            },
            $inc: { attempts: 1 },
        }, {
            new: true,
            sort: { createdAt: 1, _id: 1 },
            runValidators: true,
        });
    }

    async recordStep({ operationId, step, progress, journal }) {
        return this.model.updateOne({ _id: operationId }, {
            $set: { step, progress },
            $push: {
                logs: {
                    $each: [journal],
                    $slice: -100,
                },
            },
        }, { runValidators: true });
    }

    async setStatus({
        operationId,
        status,
        step,
        progress,
        errorCode,
        errorMessage,
        finishedAt,
        journal,
    }) {
        const fields = { status };
        if (step !== undefined) fields.step = step;
        if (progress !== undefined) fields.progress = progress;
        if (errorCode !== undefined) fields.errorCode = errorCode;
        if (errorMessage !== undefined) fields.errorMessage = errorMessage;
        if (finishedAt !== undefined) fields.finishedAt = finishedAt;

        return this.model.updateOne({ _id: operationId }, {
            $set: fields,
            $push: {
                logs: {
                    $each: [journal],
                    $slice: -100,
                },
            },
        }, { runValidators: true });
    }
}

module.exports = {
    L2tpOperationRepository,
};
