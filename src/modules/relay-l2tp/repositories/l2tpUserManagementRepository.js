'use strict';

const { randomBytes } = require('node:crypto');

const SAFE_USER_FIELDS = Object.freeze([
    '_id',
    'relayNode',
    'login',
    'ip',
    'enabled',
    'desiredRevision',
    'appliedRevision',
    'syncStatus',
    'syncOperationId',
    'lastSyncedAt',
    'lastErrorCode',
    'createdAt',
    'updatedAt',
]);
const SAFE_USER_SELECT = SAFE_USER_FIELDS.join(' ');
const CREATE_USER_FIELDS = Object.freeze([
    'relayNode',
    'login',
    'ip',
    'enabled',
    'passwordEncrypted',
    'desiredRevision',
]);
const UPDATE_USER_FIELDS = Object.freeze([
    'login',
    'ip',
    'enabled',
    'passwordEncrypted',
    'desiredRevision',
]);

function pickDefined(source, fields) {
    return fields.reduce((result, field) => {
        if (source?.[field] !== undefined) result[field] = source[field];
        return result;
    }, {});
}

function toPlainObject(value) {
    if (value && typeof value.toObject === 'function') return value.toObject();
    return value;
}

function safeRecord(value) {
    const plain = toPlainObject(value);
    if (!plain || typeof plain !== 'object') return plain;
    return pickDefined(plain, SAFE_USER_FIELDS);
}

function syncPlan({ operationId, relayNode, credentialRevision }) {
    return {
        ok: true,
        operationId,
        relayId: String(relayNode),
        desired: { credentialRevision },
        steps: [
            { type: 'backup' },
            {
                type: 'sync_users',
                artifacts: [{ type: 'desired', path: 'desired.json' }],
            },
            { type: 'verify' },
        ],
    };
}

function repositoryError(code, message) {
    return Object.assign(new Error(message), {
        name: 'L2tpUserManagementRepositoryError',
        code,
    });
}

class L2tpUserManagementRepository {
    constructor({
        HyNode,
        L2tpUser,
        RelayL2tpState,
        L2tpOperation,
        operationIdFactory = () => randomBytes(12).toString('hex'),
        transactionRunner,
    } = {}) {
        if (!HyNode || typeof HyNode.findById !== 'function') {
            throw new TypeError('L2TP user management requires HyNode.findById');
        }
        if (
            !L2tpUser
            || typeof L2tpUser.find !== 'function'
            || typeof L2tpUser.findOne !== 'function'
            || typeof L2tpUser.findOneAndUpdate !== 'function'
            || typeof L2tpUser.create !== 'function'
        ) {
            throw new TypeError('L2TP user management requires the L2tpUser model');
        }
        if (!RelayL2tpState || typeof RelayL2tpState.findOneAndUpdate !== 'function') {
            throw new TypeError('L2TP user management requires RelayL2tpState.findOneAndUpdate');
        }
        this.HyNode = HyNode;
        this.L2tpUser = L2tpUser;
        this.RelayL2tpState = RelayL2tpState;
        this.L2tpOperation = L2tpOperation;
        this.operationIdFactory = operationIdFactory;
        this.transactionRunner = transactionRunner
            ?? (typeof RelayL2tpState.db?.transaction === 'function'
                ? work => RelayL2tpState.db.transaction(work)
                : null);
    }

    async findRelayNodeById(nodeId) {
        return this.HyNode.findById(nodeId)
            .select('_id cascadeRole')
            .lean();
    }

    async listByRelay(relayNode) {
        return this.L2tpUser.find({ relayNode })
            .select(SAFE_USER_SELECT)
            .sort({ login: 1, _id: 1 })
            .lean();
    }

    async findByRelayAndId(relayNode, userId) {
        return this.L2tpUser.findOne({ relayNode, _id: userId })
            .select(SAFE_USER_SELECT)
            .lean();
    }

    async findConflict(relayNode, { login, ip }, excludeUserId) {
        const filter = { relayNode };
        if (excludeUserId !== undefined) filter._id = { $ne: excludeUserId };
        filter.$or = [{ login }, { ip }];
        return this.L2tpUser.findOne(filter)
            .select('_id')
            .lean();
    }

    async reserveCredentialRevision(relayNode, session) {
        const state = await this.RelayL2tpState.findOneAndUpdate(
            { node: relayNode },
            { $inc: { secretRevision: 1 } },
            {
                new: true,
                runValidators: true,
                ...(session === undefined ? {} : { session }),
            },
        )
            .select('secretRevision')
            .lean();
        return state?.secretRevision ?? null;
    }

    async createUserAndQueueSync(fields) {
        if (
            !this.L2tpOperation
            || typeof this.L2tpOperation.create !== 'function'
            || typeof this.transactionRunner !== 'function'
        ) {
            throw repositoryError(
                'L2TP_USER_SYNC_QUEUE_UNAVAILABLE',
                'Transactional L2TP user sync queuing is unavailable',
            );
        }
        const operationId = this.operationIdFactory();

        return this.transactionRunner(async session => {
            const desiredRevision = await this.reserveCredentialRevision(fields.relayNode, session);
            if (!Number.isSafeInteger(desiredRevision) || desiredRevision < 1) {
                throw repositoryError(
                    'L2TP_NOT_CONFIGURED',
                    'The relay L2TP desired state is not configured',
                );
            }
            const documents = [{
                ...pickDefined(fields, CREATE_USER_FIELDS),
                desiredRevision,
                appliedRevision: 0,
                syncStatus: 'pending',
                lastErrorCode: '',
                lastError: '',
            }];
            const createdUsers = await this.L2tpUser.create(documents, { session });
            const operationDocuments = [{
                _id: operationId,
                node: fields.relayNode,
                kind: 'sync_users',
                status: 'queued',
                idempotencyKey: `sync-users:${fields.relayNode}:revision-${desiredRevision}`,
                progress: 0,
                attempts: 0,
                plan: syncPlan({
                    operationId,
                    relayNode: fields.relayNode,
                    credentialRevision: desiredRevision,
                }),
            }];
            await this.L2tpOperation.create(operationDocuments, { session });
            return {
                user: safeRecord(createdUsers[0]),
                operationId,
            };
        });
    }

    async createUser(fields) {
        const created = await this.L2tpUser.create({
            ...pickDefined(fields, CREATE_USER_FIELDS),
            appliedRevision: 0,
            syncStatus: 'pending',
            lastErrorCode: '',
            lastError: '',
        });
        return safeRecord(created);
    }

    async updateUserAndQueueSync(relayNode, userId, expectedRevision, fields) {
        if (
            !this.L2tpOperation
            || typeof this.L2tpOperation.create !== 'function'
            || typeof this.transactionRunner !== 'function'
        ) {
            throw repositoryError(
                'L2TP_USER_SYNC_QUEUE_UNAVAILABLE',
                'Transactional L2TP user sync queuing is unavailable',
            );
        }
        const operationId = this.operationIdFactory();

        return this.transactionRunner(async session => {
            const desiredRevision = await this.reserveCredentialRevision(relayNode, session);
            if (!Number.isSafeInteger(desiredRevision) || desiredRevision < 1) {
                throw repositoryError(
                    'L2TP_NOT_CONFIGURED',
                    'The relay L2TP desired state is not configured',
                );
            }
            const user = await this.L2tpUser.findOneAndUpdate(
                { relayNode, _id: userId, desiredRevision: expectedRevision },
                {
                    $set: {
                        ...pickDefined(fields, UPDATE_USER_FIELDS),
                        desiredRevision,
                        syncStatus: 'pending',
                        lastErrorCode: '',
                        lastError: '',
                    },
                },
                { new: true, runValidators: true, session },
            )
                .select(SAFE_USER_SELECT)
                .lean();
            if (!user) {
                throw repositoryError(
                    'L2TP_USER_CHANGED',
                    'The L2TP user changed before the update could be queued',
                );
            }
            const operationDocuments = [{
                _id: operationId,
                node: relayNode,
                kind: 'sync_users',
                status: 'queued',
                idempotencyKey: `sync-users:${relayNode}:revision-${desiredRevision}`,
                progress: 0,
                attempts: 0,
                plan: syncPlan({ operationId, relayNode, credentialRevision: desiredRevision }),
            }];
            await this.L2tpOperation.create(operationDocuments, { session });
            return { user: safeRecord(user), operationId };
        });
    }

    async updateUser(relayNode, userId, fields) {
        return this.L2tpUser.findOneAndUpdate(
            { relayNode, _id: userId },
            {
                $set: {
                    ...pickDefined(fields, UPDATE_USER_FIELDS),
                    syncStatus: 'pending',
                    syncOperationId: null,
                    lastErrorCode: '',
                    lastError: '',
                },
            },
            { new: true, runValidators: true },
        )
            .select(SAFE_USER_SELECT)
            .lean();
    }
}

module.exports = {
    CREATE_USER_FIELDS,
    L2tpUserManagementRepository,
    SAFE_USER_FIELDS,
    SAFE_USER_SELECT,
    UPDATE_USER_FIELDS,
    safeRecord,
};
