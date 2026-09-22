'use strict';

const CURRENT_USER_SELECT = '_id relayNode login ip enabled desiredRevision';
const OPERATION_GUARD_SELECT = '_id node kind status leaseOwner leaseUntil plan.desired.credentialRevision';
const STATE_GUARD_SELECT = 'node desiredState status secretRevision';
const REJECTED = Symbol('L2TP_USER_SYNC_RECONCILIATION_REJECTED');

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function positiveRevision(value) {
    return Number.isSafeInteger(value) && value > 0;
}

function reject() {
    throw REJECTED;
}

function assertRequest(request) {
    if (
        !request
        || typeof request !== 'object'
        || !entityId(request.operationId)
        || !entityId(request.relayNode)
        || !positiveRevision(request.credentialRevision)
        || typeof request.workerId !== 'string'
        || request.workerId.length === 0
        || !(request.now instanceof Date)
        || !Number.isFinite(request.now.getTime())
        || !Array.isArray(request.resolvedUsers)
    ) {
        reject();
    }
}

function assertVerification(verification, credentialRevision, users) {
    const enabledCount = users.filter(user => user.enabled === true).length;
    if (
        !verification
        || typeof verification !== 'object'
        || verification.ok !== true
        || verification.code !== 'USERS_VERIFIED'
        || verification.credentialRevision !== credentialRevision
        || verification.enabledUserCount !== enabledCount
        || verification.managedUserCount !== enabledCount
    ) {
        reject();
    }
}

function assertResolvedUsers(users, relayNode, credentialRevision) {
    const ids = new Set();
    const logins = new Set();
    const ips = new Set();
    for (const user of users) {
        const id = entityId(user);
        if (
            !user
            || typeof user !== 'object'
            || !id
            || entityId(user.relayNode) !== relayNode
            || typeof user.login !== 'string'
            || user.login.length === 0
            || typeof user.ip !== 'string'
            || user.ip.length === 0
            || typeof user.enabled !== 'boolean'
            || !positiveRevision(user.desiredRevision)
            || user.desiredRevision > credentialRevision
            || ids.has(id)
            || logins.has(user.login)
            || ips.has(user.ip)
        ) {
            reject();
        }
        ids.add(id);
        logins.add(user.login);
        ips.add(user.ip);
    }
}

function assertCurrentUsers(currentUsers, resolvedUsers, relayNode) {
    if (!Array.isArray(currentUsers) || currentUsers.length !== resolvedUsers.length) reject();
    const currentById = new Map(currentUsers.map(user => [entityId(user), user]));
    if (currentById.size !== currentUsers.length) reject();

    for (const snapshot of resolvedUsers) {
        const current = currentById.get(entityId(snapshot));
        if (
            !current
            || entityId(current.relayNode) !== relayNode
            || current.login !== snapshot.login
            || current.ip !== snapshot.ip
            || current.enabled !== snapshot.enabled
            || current.desiredRevision !== snapshot.desiredRevision
        ) {
            reject();
        }
    }
}

function defaultTransactionRunner(L2tpOperation, RelayL2tpState, L2tpUser) {
    const connection = L2tpOperation?.db;
    if (
        !connection
        || RelayL2tpState?.db !== connection
        || L2tpUser?.db !== connection
        || typeof connection.transaction !== 'function'
    ) {
        return null;
    }
    return work => connection.transaction(work);
}

class L2tpUserSyncRepository {
    constructor({
        L2tpOperation,
        RelayL2tpState,
        L2tpUser,
        transactionRunner,
    } = {}) {
        if (!L2tpOperation || typeof L2tpOperation.findOneAndUpdate !== 'function') {
            throw new TypeError('L2TP user sync reconciliation requires L2tpOperation');
        }
        if (!RelayL2tpState || typeof RelayL2tpState.findOneAndUpdate !== 'function') {
            throw new TypeError('L2TP user sync reconciliation requires RelayL2tpState');
        }
        if (
            !L2tpUser
            || typeof L2tpUser.find !== 'function'
            || typeof L2tpUser.bulkWrite !== 'function'
        ) {
            throw new TypeError('L2TP user sync reconciliation requires L2tpUser');
        }
        const runTransaction = transactionRunner
            ?? defaultTransactionRunner(L2tpOperation, RelayL2tpState, L2tpUser);
        if (typeof runTransaction !== 'function') {
            throw new TypeError('L2TP user sync reconciliation requires a transaction runner');
        }
        this.L2tpOperation = L2tpOperation;
        this.RelayL2tpState = RelayL2tpState;
        this.L2tpUser = L2tpUser;
        this.transactionRunner = runTransaction;
    }

    async finalizeVerifiedSync(request) {
        try {
            assertRequest(request);
            const operationId = entityId(request.operationId);
            const relayNode = entityId(request.relayNode);
            const {
                credentialRevision,
                workerId,
                now,
                resolvedUsers,
                verification,
            } = request;

            assertResolvedUsers(resolvedUsers, relayNode, credentialRevision);
            assertVerification(verification, credentialRevision, resolvedUsers);

            return await this.transactionRunner(async session => {
                const operation = await this.L2tpOperation.findOneAndUpdate(
                    {
                        _id: operationId,
                        node: relayNode,
                        kind: 'sync_users',
                        status: 'running',
                        leaseOwner: workerId,
                        leaseUntil: { $gt: now },
                        'plan.operationId': operationId,
                        'plan.relayId': relayNode,
                        'plan.desired.credentialRevision': credentialRevision,
                    },
                    { $set: { step: 'user_sync_reconciled' } },
                    { new: true, runValidators: true, session },
                )
                    .select(OPERATION_GUARD_SELECT)
                    .lean();
                if (!operation) reject();

                const state = await this.RelayL2tpState.findOneAndUpdate(
                    {
                        node: relayNode,
                        desiredState: 'installed',
                        status: 'installed',
                        secretRevision: credentialRevision,
                    },
                    { $set: { lastSyncAt: now } },
                    { new: true, runValidators: true, session },
                )
                    .select(STATE_GUARD_SELECT)
                    .lean();
                if (!state) reject();

                const currentUsers = await this.L2tpUser.find(
                    { relayNode },
                    CURRENT_USER_SELECT,
                    { session },
                )
                    .sort({ login: 1, _id: 1 })
                    .lean();
                assertCurrentUsers(currentUsers, resolvedUsers, relayNode);

                if (currentUsers.length > 0) {
                    const result = await this.L2tpUser.bulkWrite(
                        currentUsers.map(user => ({
                            updateOne: {
                                filter: {
                                    _id: user._id,
                                    relayNode: user.relayNode,
                                    login: user.login,
                                    ip: user.ip,
                                    enabled: user.enabled,
                                    desiredRevision: user.desiredRevision,
                                },
                                update: {
                                    $set: {
                                        appliedRevision: user.desiredRevision,
                                        syncStatus: 'synced',
                                        syncOperationId: operationId,
                                        lastSyncedAt: now,
                                        lastErrorCode: '',
                                        lastError: '',
                                    },
                                },
                            },
                        })),
                        { ordered: true, session },
                    );
                    if (result?.matchedCount !== currentUsers.length) reject();
                }

                return {
                    operationId,
                    reconciledUserCount: currentUsers.length,
                    finalizedAt: now,
                };
            });
        } catch (error) {
            if (error === REJECTED) return null;
            throw error;
        }
    }
}

module.exports = {
    CURRENT_USER_SELECT,
    L2tpUserSyncRepository,
    OPERATION_GUARD_SELECT,
    STATE_GUARD_SELECT,
};
