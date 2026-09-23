'use strict';

const defaultSecretBox = require('./secretBoxService');

const LOGIN_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;
const MAX_PASSWORD_LENGTH = 1024;
const SAFE_SYNC_FAILURE_CODE = 'L2TP_USER_SYNC_FAILED';
const CREATE_INPUT_FIELDS = Object.freeze(['login', 'ip', 'password', 'enabled']);
const UPDATE_INPUT_FIELDS = Object.freeze(['login', 'ip', 'password', 'enabled']);
const SAFE_USER_FIELDS = Object.freeze([
    'login',
    'ip',
    'enabled',
    'desiredRevision',
    'appliedRevision',
    'syncStatus',
    'lastSyncedAt',
    'createdAt',
    'updatedAt',
]);

class L2tpUserManagementError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'L2tpUserManagementError';
        this.code = code;
    }
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function isCanonicalIpv4(value) {
    if (typeof value !== 'string') return false;
    const octets = value.split('.');
    return octets.length === 4
        && octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
}

function safeUser(user) {
    if (!user || typeof user !== 'object') return user;
    const result = {};
    const id = entityId(user);
    const relayNode = entityId(user.relayNode);
    if (id !== null) result.id = id;
    if (relayNode !== null) result.relayNode = relayNode;
    for (const field of SAFE_USER_FIELDS) {
        if (user[field] !== undefined) result[field] = user[field];
    }
    if (user.syncOperationId !== undefined) {
        result.syncOperationId = entityId(user.syncOperationId);
    }
    if (user.syncStatus === 'error') {
        result.lastErrorCode = SAFE_SYNC_FAILURE_CODE;
    } else if (user.lastErrorCode !== undefined) {
        result.lastErrorCode = '';
    }
    return result;
}

function validateNodeId(nodeId) {
    if (typeof nodeId !== 'string' || nodeId.length === 0 || nodeId.length > 128 || /[\r\n\0]/.test(nodeId)) {
        throw new L2tpUserManagementError('INVALID_NODE_ID', 'A valid relay node is required');
    }
    return nodeId;
}

function validateLogin(login) {
    if (typeof login !== 'string' || !LOGIN_PATTERN.test(login)) {
        throw new L2tpUserManagementError(
            'INVALID_L2TP_LOGIN',
            'login must use 1 to 64 safe characters',
        );
    }
}

function validateIp(ip) {
    if (!isCanonicalIpv4(ip)) {
        throw new L2tpUserManagementError(
            'INVALID_L2TP_IP',
            'ip must be a canonical IPv4 address',
        );
    }
}

function validatePassword(password) {
    if (
        typeof password !== 'string'
        || password.length === 0
        || password.length > MAX_PASSWORD_LENGTH
        || /[\r\n\0]/.test(password)
    ) {
        throw new L2tpUserManagementError(
            'INVALID_L2TP_PASSWORD',
            'password must be a non-empty safe credential of at most 1024 characters',
        );
    }
}

function validateEnabled(enabled) {
    if (typeof enabled !== 'boolean') {
        throw new L2tpUserManagementError(
            'INVALID_L2TP_ENABLED',
            'enabled must be a boolean',
        );
    }
}

function assertAllowedInput(input, allowedFields, { requireField = false } = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new L2tpUserManagementError('INVALID_L2TP_USER', 'L2TP user input is required');
    }
    const fields = Object.keys(input);
    if (
        (requireField && fields.length === 0)
        || fields.some(field => !allowedFields.includes(field))
    ) {
        throw new L2tpUserManagementError(
            'INVALID_L2TP_USER',
            'L2TP user input contains unsupported fields',
        );
    }
}

function validateUserId(userId) {
    if (typeof userId !== 'string' || userId.length === 0 || userId.length > 128 || /[\r\n\0]/.test(userId)) {
        throw new L2tpUserManagementError('INVALID_L2TP_USER_ID', 'A valid L2TP user id is required');
    }
    return userId;
}

function conflictError() {
    return new L2tpUserManagementError(
        'L2TP_USER_CONFLICT',
        'An L2TP user with that login or IP already exists for this relay',
    );
}

function notFoundError() {
    return new L2tpUserManagementError('L2TP_USER_NOT_FOUND', 'The L2TP user was not found');
}

function encryptionError() {
    return new L2tpUserManagementError(
        'L2TP_USER_ENCRYPTION_FAILED',
        'The L2TP user password could not be encrypted',
    );
}

function configuredRevision(revision) {
    if (!Number.isSafeInteger(revision) || revision < 1) {
        throw new L2tpUserManagementError(
            'L2TP_NOT_CONFIGURED',
            'The relay L2TP desired state is not configured',
        );
    }
    return revision;
}

function isDuplicateKeyError(error) {
    return error?.code === 11000 || error?.code === 11001;
}

class L2tpUserManagementService {
    constructor({ repository, secretBox = defaultSecretBox, secretKey } = {}) {
        if (!repository) throw new TypeError('L2TP user management repository is required');
        if (!secretBox || typeof secretBox.encrypt !== 'function') {
            throw new TypeError('L2TP user management requires secretBox.encrypt');
        }
        if (typeof secretKey !== 'string' || secretKey.trim().length === 0) {
            throw new TypeError('L2TP user management requires a non-empty secretKey');
        }
        this.repository = repository;
        this.secretBox = secretBox;
        this.secretKey = secretKey;
    }

    async assertRelay(nodeId) {
        const relayNode = validateNodeId(nodeId);
        const node = await this.repository.findRelayNodeById(relayNode);
        if (!node) {
            throw new L2tpUserManagementError('NODE_NOT_FOUND', 'The L2TP node was not found');
        }
        if ((node.cascadeRole ?? node.role) !== 'relay') {
            throw new L2tpUserManagementError(
                'NODE_NOT_RELAY',
                'L2TP users can only be managed for relay nodes',
            );
        }
        return relayNode;
    }

    async createUser(nodeId, input) {
        const relayNode = await this.assertRelay(nodeId);
        assertAllowedInput(input, CREATE_INPUT_FIELDS);
        validateLogin(input.login);
        validateIp(input.ip);
        validatePassword(input.password);
        const enabled = input.enabled === undefined ? true : input.enabled;
        validateEnabled(enabled);

        const conflict = await this.repository.findConflict(relayNode, {
            login: input.login,
            ip: input.ip,
        });
        if (conflict) throw conflictError();

        let passwordEncrypted;
        try {
            passwordEncrypted = this.secretBox.encrypt(input.password, this.secretKey);
        } catch {
            throw encryptionError();
        }
        let result;
        try {
            result = await this.repository.createUserAndQueueSync({
                relayNode,
                login: input.login,
                ip: input.ip,
                enabled,
                passwordEncrypted,
            });
        } catch (error) {
            if (isDuplicateKeyError(error)) throw conflictError();
            throw error;
        }
        const desiredRevision = configuredRevision(result?.user?.desiredRevision);
        const syncOperationId = entityId(result?.operationId);
        if (!syncOperationId) {
            throw new L2tpUserManagementError(
                'L2TP_USER_SYNC_QUEUE_FAILED',
                'The L2TP user sync operation could not be queued',
            );
        }
        return safeUser({
            ...result.user,
            desiredRevision,
            syncOperationId,
        });
    }

    async listUsers(nodeId) {
        const relayNode = await this.assertRelay(nodeId);
        const users = await this.repository.listByRelay(relayNode);
        if (!Array.isArray(users)) {
            throw new L2tpUserManagementError(
                'L2TP_USER_QUERY_FAILED',
                'The L2TP users could not be loaded',
            );
        }
        return users.map(safeUser);
    }

    async updateUser(nodeId, userId, input) {
        const relayNode = await this.assertRelay(nodeId);
        const selectedUserId = validateUserId(userId);
        assertAllowedInput(input, UPDATE_INPUT_FIELDS, { requireField: true });
        if (input.login !== undefined) validateLogin(input.login);
        if (input.ip !== undefined) validateIp(input.ip);
        if (input.password !== undefined) validatePassword(input.password);
        if (input.enabled !== undefined) validateEnabled(input.enabled);

        const existing = await this.repository.findByRelayAndId(relayNode, selectedUserId);
        if (!existing) throw notFoundError();

        const nextLogin = input.login ?? existing.login;
        const nextIp = input.ip ?? existing.ip;
        const identityChanged = nextLogin !== existing.login || nextIp !== existing.ip;
        if (identityChanged) {
            const conflict = await this.repository.findConflict(
                relayNode,
                { login: nextLogin, ip: nextIp },
                selectedUserId,
            );
            if (conflict) throw conflictError();
        }

        const fields = {};
        if (input.login !== undefined && input.login !== existing.login) fields.login = input.login;
        if (input.ip !== undefined && input.ip !== existing.ip) fields.ip = input.ip;
        if (input.enabled !== undefined && input.enabled !== existing.enabled) fields.enabled = input.enabled;
        if (input.password !== undefined) {
            try {
                fields.passwordEncrypted = this.secretBox.encrypt(input.password, this.secretKey);
            } catch {
                throw encryptionError();
            }
        }
        if (Object.keys(fields).length === 0) return safeUser(existing);

        let result;
        try {
            result = await this.repository.updateUserAndQueueSync(
                relayNode,
                selectedUserId,
                existing.desiredRevision,
                fields,
            );
        } catch (error) {
            if (isDuplicateKeyError(error)) throw conflictError();
            throw error;
        }
        if (!result?.user) throw notFoundError();
        configuredRevision(result.user.desiredRevision);
        const syncOperationId = entityId(result.operationId);
        if (!syncOperationId) {
            throw new L2tpUserManagementError(
                'L2TP_USER_SYNC_QUEUE_FAILED',
                'The L2TP user sync operation could not be queued',
            );
        }
        return safeUser({ ...result.user, syncOperationId });
    }

    disableUser(nodeId, userId) {
        return this.updateUser(nodeId, userId, { enabled: false });
    }

    async deleteUser(nodeId, userId) {
        const relayNode = await this.assertRelay(nodeId);
        const selectedUserId = validateUserId(userId);
        const existing = await this.repository.findByRelayAndId(relayNode, selectedUserId);
        if (!existing) throw notFoundError();

        let result;
        try {
            result = await this.repository.deleteUserAndQueueSync(
                relayNode,
                selectedUserId,
                existing.desiredRevision,
            );
        } catch (error) {
            if (error?.code === 'L2TP_USER_CHANGED') {
                throw new L2tpUserManagementError(
                    'L2TP_USER_STALE_REVISION',
                    'The L2TP user changed before the deletion could be queued',
                );
            }
            throw error;
        }
        const syncOperationId = entityId(result?.operationId);
        if (!syncOperationId) {
            throw new L2tpUserManagementError(
                'L2TP_USER_SYNC_QUEUE_FAILED',
                'The L2TP user sync operation could not be queued',
            );
        }
        return { deleted: true, syncOperationId };
    }

    // Imports an already-encrypted credential onto another relay without
    // queueing a sync operation (used to fan accounts out before install,
    // where the install operation itself carries the user snapshot).
    async importUser(nodeId, input) {
        const relayNode = await this.assertRelay(nodeId);
        validateLogin(input?.login);
        validateIp(input?.ip);
        if (typeof input.passwordEncrypted !== 'string' || input.passwordEncrypted.length === 0) {
            throw new L2tpUserManagementError(
                'L2TP_USER_ENCRYPTION_FAILED',
                'An encrypted L2TP user password is required',
            );
        }
        const enabled = input.enabled === undefined ? true : input.enabled;
        validateEnabled(enabled);
        const desiredRevision = configuredRevision(input.desiredRevision);

        const conflict = await this.repository.findConflict(relayNode, {
            login: input.login,
            ip: input.ip,
        });
        if (conflict) throw conflictError();

        let created;
        try {
            created = await this.repository.createUser({
                relayNode,
                login: input.login,
                ip: input.ip,
                enabled,
                passwordEncrypted: input.passwordEncrypted,
                desiredRevision,
            });
        } catch (error) {
            if (isDuplicateKeyError(error)) throw conflictError();
            throw error;
        }
        return safeUser(created);
    }
}

module.exports = {
    LOGIN_PATTERN,
    L2tpUserManagementError,
    L2tpUserManagementService,
    MAX_PASSWORD_LENGTH,
    SAFE_SYNC_FAILURE_CODE,
    SAFE_USER_FIELDS,
    isCanonicalIpv4,
    safeUser,
};
