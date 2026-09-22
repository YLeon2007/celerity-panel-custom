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

    async renewLease({ operationId, owner, leaseMs, now }) {
        const leaseUntil = new Date(now.getTime() + leaseMs);
        const result = await this.model.updateOne({
            _id: operationId,
            status: 'running',
            leaseOwner: owner,
            leaseUntil: { $gt: now },
        }, {
            $set: { leaseUntil },
        }, { runValidators: true });

        return result.matchedCount === 1;
    }

    /**
     * Atomically marks a claimed operation successful only while `owner` still
     * owns its running, unexpired lease at `now`. On success, `now` is also the
     * terminal timestamp and the supplied journal entry is appended.
     *
     * @param {object} input
     * @param {*} input.operationId Durable operation identity.
     * @param {string} input.owner Expected lease owner.
     * @param {Date} input.now Lease-fence time and persisted `finishedAt`.
     * @param {string} input.step Final verified step.
     * @param {object} input.journal Sanitized terminal journal entry.
     * @returns {Promise<boolean>} `true` when the CAS transition matched;
     * `false` when ownership, status, lease validity, or identity did not match.
     */
    async succeedClaimed({ operationId, owner, now, step, journal }) {
        const result = await this.model.updateOne({
            _id: operationId,
            status: 'running',
            leaseOwner: owner,
            leaseUntil: { $gt: now },
        }, {
            $set: {
                status: 'succeeded',
                step,
                progress: 100,
                errorCode: '',
                errorMessage: '',
                finishedAt: now,
            },
            $push: {
                logs: {
                    $each: [journal],
                    $slice: -100,
                },
            },
        }, { runValidators: true });

        return result.matchedCount === 1;
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
