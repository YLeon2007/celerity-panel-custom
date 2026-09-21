'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { reconcileChapSecrets } = require('../services/l2tpUserSyncService');

test('builds a deterministic managed block for enabled desired users', () => {
    const desiredUsers = [
        { login: 'zeta', password: 'zeta-secret', ipAddress: '10.77.0.11', enabled: true },
        { login: 'alpha', password: 'alpha-secret', ipAddress: '10.77.0.10', enabled: true },
    ];

    const first = reconcileChapSecrets('', desiredUsers);
    const second = reconcileChapSecrets('', [...desiredUsers].reverse());

    assert.equal(first.content, `# BEGIN CELERITY MANAGED L2TP USERS
"alpha" l2tpd "alpha-secret" 10.77.0.10
"zeta" l2tpd "zeta-secret" 10.77.0.11
# END CELERITY MANAGED L2TP USERS
`);
    assert.equal(second.content, first.content);
});

test('replaces the managed block while preserving unmanaged bytes', () => {
    const existingContent = '# local header\r\n'
        + '"legacy" * "leave me alone" *\r\n'
        + '# BEGIN CELERITY MANAGED L2TP USERS\n'
        + '"old" l2tpd "old-secret" 10.77.0.99\n'
        + '# END CELERITY MANAGED L2TP USERS\n'
        + '# local tail\r\n';

    const result = reconcileChapSecrets(existingContent, [
        { login: 'alice', password: 'new-secret', ipAddress: '10.77.0.10', enabled: true },
    ]);

    assert.equal(result.content, '# local header\r\n'
        + '"legacy" * "leave me alone" *\r\n'
        + '# BEGIN CELERITY MANAGED L2TP USERS\n'
        + '"alice" l2tpd "new-secret" 10.77.0.10\n'
        + '# END CELERITY MANAGED L2TP USERS\n'
        + '# local tail\r\n');
});

test('omits disabled users from the managed block', () => {
    const result = reconcileChapSecrets('', [
        { login: 'active', password: 'active-secret', ipAddress: '10.77.0.10', enabled: true },
        { login: 'disabled', password: 'disabled-secret', ipAddress: '10.77.0.11', enabled: false },
    ]);

    assert.match(result.content, /"active" l2tpd "active-secret" 10\.77\.0\.10/);
    assert.doesNotMatch(result.content, /disabled/);
});

test('rejects duplicate desired logins with a structured error', () => {
    assert.throws(
        () => reconcileChapSecrets('', [
            { login: 'alice', password: 'first-secret', ipAddress: '10.77.0.10', enabled: true },
            { login: 'alice', password: 'second-secret', ipAddress: '10.77.0.11', enabled: false },
        ]),
        error => {
            assert.equal(error.name, 'L2tpUserSyncError');
            assert.equal(error.code, 'DUPLICATE_DESIRED_LOGIN');
            assert.equal(error.login, 'alice');
            assert.deepEqual(error.userIndexes, [0, 1]);
            assert.doesNotMatch(error.message, /secret/);
            return true;
        },
    );
});

test('rejects duplicate or malformed managed markers with a structured conflict', () => {
    const begin = '# BEGIN CELERITY MANAGED L2TP USERS';
    const end = '# END CELERITY MANAGED L2TP USERS';
    const conflictingContents = [
        `${begin}\n"leaked-secret" l2tpd "one" 10.77.0.10\n`,
        `${end}\n`,
        `${end}\n${begin}\n`,
        `${begin}\n${begin}\n${end}\n`,
        `${begin}\n${end}\n${begin}\n${end}\n`,
    ];

    for (const existingContent of conflictingContents) {
        assert.throws(
            () => reconcileChapSecrets(existingContent, []),
            error => {
                assert.equal(error.name, 'L2tpUserSyncError');
                assert.equal(error.code, 'MANAGED_BLOCK_CONFLICT');
                assert.equal(typeof error.beginMarkerCount, 'number');
                assert.equal(typeof error.endMarkerCount, 'number');
                assert.doesNotMatch(error.message, /leaked-secret|"one"/);
                return true;
            },
        );
    }
});

test('renders PPP quoted credentials without shell escaping', () => {
    const password = 'space quote" slash\\ dollar$ backtick` hash#';
    const result = reconcileChapSecrets('', [
        { login: 'alice', password, ipAddress: '10.77.0.10', enabled: true },
    ]);

    assert.equal(
        result.content.split('\n')[1],
        '"alice" l2tpd "space quote\\" slash\\\\ dollar$ backtick` hash#" 10.77.0.10',
    );
});

test('rejects CR, LF, and NUL in PPP credentials', () => {
    const unsafeCredentials = [
        { field: 'login', value: 'alice\nroot' },
        { field: 'password', value: 'secret\rnext-line' },
        { field: 'password', value: 'secret\0suffix' },
    ];

    for (const { field, value } of unsafeCredentials) {
        const user = {
            login: 'alice',
            password: 'safe-secret',
            ipAddress: '10.77.0.10',
            enabled: true,
            [field]: value,
        };
        assert.throws(
            () => reconcileChapSecrets('', [user]),
            {
                name: 'L2tpUserSyncError',
                code: 'INVALID_DESIRED_USER',
                userIndex: 0,
                field,
            },
        );
    }
});

test('validates each desired login, password, IP, and enabled mapping', () => {
    const validUser = {
        login: 'alice',
        password: 'safe-secret',
        ipAddress: '10.77.0.10',
        enabled: true,
    };
    const invalidMappings = [
        { user: null, field: 'user' },
        { user: { ...validUser, login: 'bad login' }, field: 'login' },
        { user: { ...validUser, password: '' }, field: 'password' },
        { user: { ...validUser, ipAddress: '10.77.0.999' }, field: 'ipAddress' },
        { user: { ...validUser, ipAddress: '10.077.0.10' }, field: 'ipAddress' },
        { user: { ...validUser, enabled: 'yes' }, field: 'enabled' },
    ];

    for (const { user, field } of invalidMappings) {
        assert.throws(
            () => reconcileChapSecrets('', [user]),
            {
                name: 'L2tpUserSyncError',
                code: 'INVALID_DESIRED_USER',
                userIndex: 0,
                field,
            },
        );
    }
});

test('returns secret-free reconciliation metadata', () => {
    const result = reconcileChapSecrets('', [
        { login: 'active', password: 'active-secret', ipAddress: '10.77.0.10', enabled: true },
        { login: 'disabled', password: 'disabled-secret', ipAddress: '10.77.0.11', enabled: false },
    ]);

    assert.deepEqual(result.metadata, {
        managedUserCount: 1,
        disabledUserCount: 1,
    });
    assert.doesNotMatch(JSON.stringify(result.metadata), /secret|password/i);
});
