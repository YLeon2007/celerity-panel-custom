'use strict';

const LOGIN_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;

class L2tpUserResolutionError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'L2tpUserResolutionError';
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

function invalidUser() {
    return new L2tpUserResolutionError(
        'INVALID_L2TP_USER',
        'An enabled L2TP user is invalid for execution',
    );
}

class L2tpUserResolver {
    constructor({ repository, secretBox, secretKey } = {}) {
        if (!repository || typeof repository.findEnabledByRelayNode !== 'function') {
            throw new TypeError('L2TP user execution repository is required');
        }
        if (!secretBox || typeof secretBox.decrypt !== 'function') {
            throw new TypeError('L2TP user resolver requires secretBox.decrypt');
        }
        if (typeof secretKey !== 'string' || secretKey.trim().length === 0) {
            throw new TypeError('L2TP user resolver requires a non-empty secretKey');
        }
        this.repository = repository;
        this.secretBox = secretBox;
        this.secretKey = secretKey;
    }

    async resolve(operation) {
        if (!operation || typeof operation !== 'object' || operation.kind !== 'install') {
            throw new L2tpUserResolutionError(
                'INVALID_OPERATION_KIND',
                'L2TP users can only be resolved for install execution',
            );
        }
        const nodeId = entityId(operation.nodeId ?? operation.node);
        if (!nodeId) {
            throw new L2tpUserResolutionError(
                'INVALID_OPERATION_NODE',
                'The L2TP operation does not identify a relay node',
            );
        }
        if (!Number.isSafeInteger(operation.credentialRevision) || operation.credentialRevision < 1) {
            throw new L2tpUserResolutionError(
                'CREDENTIAL_REVISION_MISMATCH',
                'The L2TP operation credential revision is invalid',
            );
        }

        const rows = await this.repository.findEnabledByRelayNode(nodeId);
        if (!Array.isArray(rows)) {
            throw new L2tpUserResolutionError(
                'L2TP_USER_QUERY_FAILED',
                'The enabled L2TP users could not be loaded',
            );
        }

        const logins = new Set();
        const ips = new Set();
        return rows.map(row => {
            if (
                !row
                || typeof row !== 'object'
                || entityId(row.relayNode) !== nodeId
                || typeof row.login !== 'string'
                || !LOGIN_PATTERN.test(row.login)
                || !isCanonicalIpv4(row.ip)
                || row.enabled !== true
                || !Number.isSafeInteger(row.desiredRevision)
                || row.desiredRevision < 1
                || typeof row.passwordEncrypted !== 'string'
                || row.passwordEncrypted.length === 0
                || logins.has(row.login)
                || ips.has(row.ip)
            ) {
                throw invalidUser();
            }

            let password;
            try {
                password = this.secretBox.decrypt(row.passwordEncrypted, this.secretKey);
            } catch {
                throw new L2tpUserResolutionError(
                    'L2TP_USER_DECRYPTION_FAILED',
                    'An L2TP user password could not be decrypted',
                );
            }
            if (
                typeof password !== 'string'
                || password.length === 0
                || /[\r\n\0]/.test(password)
            ) {
                throw new L2tpUserResolutionError(
                    'L2TP_USER_DECRYPTION_FAILED',
                    'An L2TP user password could not be decrypted',
                );
            }

            logins.add(row.login);
            ips.add(row.ip);
            return {
                login: row.login,
                password,
                ip: row.ip,
            };
        });
    }
}

module.exports = {
    L2tpUserResolutionError,
    L2tpUserResolver,
};
