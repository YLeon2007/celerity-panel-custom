'use strict';

const TOPOLOGY_STATE_SELECT = 'revision deployedRevision';

class TopologyDeploymentRepositoryError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyDeploymentRepositoryError';
        this.code = code;
        Object.assign(this, details);
    }
}

function staleRevision(expectedRevision, actualRevision) {
    return new TopologyDeploymentRepositoryError(
        'STALE_TOPOLOGY_REVISION',
        'The topology revision changed before deployment could be fenced',
        {
            expectedTopologyRevision: expectedRevision,
            topologyRevision: actualRevision,
        },
    );
}

function defaultTransactionRunner(CascadeTopologyState) {
    const connection = CascadeTopologyState?.db;
    if (!connection || typeof connection.transaction !== 'function') return null;
    return work => connection.transaction(work);
}

function withSession(query, session) {
    return session === undefined ? query : query.session(session);
}

class TopologyDeploymentRepository {
    constructor({ snapshotReader, CascadeTopologyState, transactionRunner } = {}) {
        if (!snapshotReader || typeof snapshotReader.readDraft !== 'function') {
            throw new TypeError('Topology deployment repository requires snapshotReader.readDraft');
        }
        if (!CascadeTopologyState
            || typeof CascadeTopologyState.findOneAndUpdate !== 'function') {
            throw new TypeError('Topology deployment repository requires CascadeTopologyState');
        }
        const runTransaction = transactionRunner
            ?? defaultTransactionRunner(CascadeTopologyState);
        if (typeof runTransaction !== 'function') {
            throw new TypeError('Topology deployment repository requires a transaction runner');
        }
        this.snapshotReader = snapshotReader;
        this.CascadeTopologyState = CascadeTopologyState;
        this.transactionRunner = runTransaction;
    }

    async pinTopology({ expectedRevision, prepare }) {
        if (typeof prepare !== 'function') {
            throw new TypeError('Topology deployment pin requires a prepare function');
        }
        try {
            return await this.transactionRunner(async session => {
                const snapshot = await this.snapshotReader.readDraft(session);
                if (snapshot.revision !== expectedRevision) {
                    throw staleRevision(expectedRevision, snapshot.revision);
                }
                const prepared = await prepare(snapshot);
                const update = { $set: { revision: expectedRevision } };
                if (expectedRevision === 0) update.$setOnInsert = { deployedRevision: 0 };
                const state = await withSession(
                    this.CascadeTopologyState.findOneAndUpdate(
                        { _id: 'singleton', revision: expectedRevision },
                        update,
                        {
                            new: true,
                            runValidators: true,
                            session,
                            timestamps: false,
                            upsert: expectedRevision === 0,
                        },
                    ).select(TOPOLOGY_STATE_SELECT),
                    session,
                ).lean();
                if (!state) throw staleRevision(expectedRevision, null);
                return {
                    revision: state.revision,
                    deployedRevision: state.deployedRevision ?? 0,
                    ...prepared,
                };
            });
        } catch (error) {
            if (expectedRevision === 0 && (error?.code === 11000 || error?.code === 11001)) {
                throw staleRevision(expectedRevision, null);
            }
            throw error;
        }
    }

    async markDeployed({ expectedRevision, expectedDeployedRevision }) {
        const state = await this.CascadeTopologyState.findOneAndUpdate(
            {
                _id: 'singleton',
                revision: expectedRevision,
                deployedRevision: expectedDeployedRevision,
            },
            { $set: { deployedRevision: expectedRevision } },
            {
                new: true,
                runValidators: true,
                timestamps: false,
            },
        )
            .select(TOPOLOGY_STATE_SELECT)
            .lean();
        if (!state) throw staleRevision(expectedRevision, null);
        return {
            revision: state.revision,
            deployedRevision: state.deployedRevision,
        };
    }
}

module.exports = {
    TOPOLOGY_STATE_SELECT,
    TopologyDeploymentRepository,
    TopologyDeploymentRepositoryError,
    staleRevision,
};
