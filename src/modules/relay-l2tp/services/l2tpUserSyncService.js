'use strict';

const MANAGED_BLOCK_BEGIN = '# BEGIN CELERITY MANAGED L2TP USERS';
const MANAGED_BLOCK_END = '# END CELERITY MANAGED L2TP USERS';
const LOGIN_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;

class L2tpUserSyncError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'L2tpUserSyncError';
        this.code = code;
        Object.assign(this, details);
    }
}

function invalidDesiredUser(userIndex, field) {
    return new L2tpUserSyncError(
        'INVALID_DESIRED_USER',
        `Invalid desired L2TP user field: ${field}`,
        { userIndex, field },
    );
}

function assertSafePppCredential(value, userIndex, field) {
    if (typeof value !== 'string' || /[\r\n\0]/.test(value)) {
        throw invalidDesiredUser(userIndex, field);
    }
}

function isCanonicalIpv4(value) {
    if (typeof value !== 'string') return false;
    const octets = value.split('.');
    return octets.length === 4
        && octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
}

function assertDesiredUser(user, userIndex) {
    if (user === null || typeof user !== 'object' || Array.isArray(user)) {
        throw invalidDesiredUser(userIndex, 'user');
    }
    if (typeof user.login !== 'string' || !LOGIN_PATTERN.test(user.login)) {
        throw invalidDesiredUser(userIndex, 'login');
    }
    if (typeof user.password !== 'string' || user.password.length === 0) {
        throw invalidDesiredUser(userIndex, 'password');
    }
    assertSafePppCredential(user.login, userIndex, 'login');
    assertSafePppCredential(user.password, userIndex, 'password');
    if (!isCanonicalIpv4(user.ipAddress)) {
        throw invalidDesiredUser(userIndex, 'ipAddress');
    }
    if (typeof user.enabled !== 'boolean') {
        throw invalidDesiredUser(userIndex, 'enabled');
    }
}

function assertUniqueDesiredLogins(desiredUsers) {
    const firstIndexByLogin = new Map();
    desiredUsers.forEach((user, userIndex) => {
        if (firstIndexByLogin.has(user.login)) {
            throw new L2tpUserSyncError(
                'DUPLICATE_DESIRED_LOGIN',
                `Duplicate desired L2TP login: ${user.login}`,
                {
                    login: user.login,
                    userIndexes: [firstIndexByLogin.get(user.login), userIndex],
                },
            );
        }
        firstIndexByLogin.set(user.login, userIndex);
    });
}

function inspectManagedBlock(existingContent) {
    const beginMarkers = [];
    const endMarkers = [];
    let offset = 0;

    while (offset < existingContent.length) {
        const lineStart = offset;
        while (
            offset < existingContent.length
            && existingContent[offset] !== '\r'
            && existingContent[offset] !== '\n'
        ) {
            offset += 1;
        }
        const line = existingContent.slice(lineStart, offset);
        if (existingContent[offset] === '\r' && existingContent[offset + 1] === '\n') {
            offset += 2;
        } else if (offset < existingContent.length) {
            offset += 1;
        }

        const marker = { start: lineStart, end: offset };
        if (line === MANAGED_BLOCK_BEGIN) beginMarkers.push(marker);
        if (line === MANAGED_BLOCK_END) endMarkers.push(marker);
    }

    const hasNoMarkers = beginMarkers.length === 0 && endMarkers.length === 0;
    const hasOneOrderedBlock = beginMarkers.length === 1
        && endMarkers.length === 1
        && beginMarkers[0].start < endMarkers[0].start;

    if (!hasNoMarkers && !hasOneOrderedBlock) {
        throw new L2tpUserSyncError(
            'MANAGED_BLOCK_CONFLICT',
            'The existing chap-secrets managed block is duplicate or malformed',
            {
                beginMarkerCount: beginMarkers.length,
                endMarkerCount: endMarkers.length,
            },
        );
    }

    return hasOneOrderedBlock
        ? { start: beginMarkers[0].start, end: endMarkers[0].end }
        : null;
}

function renderPppQuotedToken(value) {
    return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function reconcileChapSecrets(existingContent, desiredUsers) {
    if (!Array.isArray(desiredUsers)) {
        throw new L2tpUserSyncError(
            'INVALID_DESIRED_USERS',
            'Desired L2TP users must be an array',
        );
    }
    desiredUsers.forEach(assertDesiredUser);
    assertUniqueDesiredLogins(desiredUsers);
    const existingBlock = inspectManagedBlock(existingContent);
    const enabledUsers = desiredUsers.filter(user => user.enabled);
    const lines = enabledUsers
        .sort((left, right) => left.login.localeCompare(right.login))
        .map(user => `${renderPppQuotedToken(user.login)} l2tpd ${renderPppQuotedToken(user.password)} ${user.ipAddress}`);
    const managedBlock = [MANAGED_BLOCK_BEGIN, ...lines, MANAGED_BLOCK_END, ''].join('\n');
    const metadata = {
        managedUserCount: enabledUsers.length,
        disabledUserCount: desiredUsers.length - enabledUsers.length,
    };
    if (existingBlock) {
        return {
            content: existingContent.slice(0, existingBlock.start)
                + managedBlock
                + existingContent.slice(existingBlock.end),
            metadata,
        };
    }

    const separator = existingContent.length > 0 && !/[\r\n]$/.test(existingContent) ? '\n' : '';
    return { content: `${existingContent}${separator}${managedBlock}`, metadata };
}

module.exports = {
    MANAGED_BLOCK_BEGIN,
    MANAGED_BLOCK_END,
    reconcileChapSecrets,
};
