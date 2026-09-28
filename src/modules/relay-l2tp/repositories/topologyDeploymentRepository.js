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
    constructor({ snapshotReader, CascadeTopologyState, TopologyOperation, transactionRunner } = {}) {
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
        this.TopologyOperation = TopologyOperation;
        this.usesDefaultRunner = transactionRunner === undefined;
    }

    // Admission is separate from the legacy pin API: a caller cannot accidentally
    // acknowledge a pin without committing its frozen operation in the same tx.
    async admitTopology({ expectedRevision, prepare, admit }) {
        if (typeof prepare !== 'function' || typeof admit !== 'function') {
            throw new TypeError('Topology admission requires prepare and admit callbacks');
        }
        const connection = this.CascadeTopologyState.db;
        const participatingModels = [this.TopologyOperation,
            this.snapshotReader.HyNode, this.snapshotReader.CascadeLink,
            this.snapshotReader.CascadeRouteGroup, this.snapshotReader.RelayL2tpState];
        if (this.usesDefaultRunner && (!connection
            || participatingModels.some(model => model?.db !== connection))) {
            throw new TypeError('Topology admission requires models on one transactional connection');
        }
        if (connection && participatingModels.some(model => model?.db !== connection)) {
            throw new TypeError('Topology admission requires models on one transactional connection');
        }
        return this.transactionRunner(async session => {
            if (!session || typeof session.inTransaction !== 'function'
                || session.inTransaction() !== true) {
                throw new TypeError('Topology admission requires an active Mongo transaction');
            }
            const snapshot = await this.snapshotReader.readDraft(session);
            if (snapshot.revision !== expectedRevision) {
                throw staleRevision(expectedRevision, snapshot.revision);
            }
            if (snapshot.replacementReservation) {
                throw new TopologyDeploymentRepositoryError(
                    'TOPOLOGY_REPLACEMENT_RESERVED',
                    'A topology replacement owns the deployment fence',
                );
            }
            const prepared = await prepare(snapshot, session);
            // Never upsert or infer that a legacy singleton's missing counter is
            // zero. This real write conflicts with a concurrent reservation CAS.
            const state = await withSession(this.CascadeTopologyState.findOneAndUpdate(
                {
                    _id: 'singleton',
                    revision: expectedRevision,
                    replacementReservation: { $exists: false },
                    topologyAdmissionCount: 0,
                },
                { $inc: { topologyAdmissionCount: 1 } },
                { new: true, runValidators: true, session, timestamps: false, upsert: false },
            ).select(TOPOLOGY_STATE_SELECT), session).lean();
            if (!state) {
                throw new TopologyDeploymentRepositoryError(
                    'TOPOLOGY_ADMISSION_UNAVAILABLE',
                    'Topology admission is unavailable or the topology fence changed',
                );
            }
            const pinned = {
                revision: state.revision,
                deployedRevision: state.deployedRevision ?? 0,
                ...prepared,
            };
            await admit(pinned, session);
            return pinned;
        });
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
                if (snapshot.replacementReservation) {
                    throw new TopologyDeploymentRepositoryError(
                        'TOPOLOGY_REPLACEMENT_RESERVED',
                        'A topology replacement owns the deployment pin fence',
                    );
                }
                const prepared = await prepare(snapshot);
                const update = { $set: { revision: expectedRevision } };
                if (expectedRevision === 0) update.$setOnInsert = { deployedRevision: 0 };
                const state = await withSession(
                    this.CascadeTopologyState.findOneAndUpdate(
                        {
                            _id: 'singleton',
                            revision: expectedRevision,
                            replacementReservation: { $exists: false },
                        },
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
