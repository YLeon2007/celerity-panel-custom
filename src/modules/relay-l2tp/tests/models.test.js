const assert = require('assert');
const mongoose = require('mongoose');

const RelayL2tpState = require('../models/relayL2tpStateModel');
const L2tpUser = require('../models/l2tpUserModel');

const DESIRED_STATES = ['absent', 'installed'];
const STATUSES = [
    'not_installed',
    'queued',
    'preflight',
    'installing',
    'installed',
    'degraded',
    'drifted',
    'removing',
    'error',
    'role_lost',
];

function objectId() {
    return new mongoose.Types.ObjectId();
}

function assertValid(document, message) {
    assert.strictEqual(document.validateSync(), undefined, message);
}

{
    const nodePath = RelayL2tpState.schema.path('node');
    assert.strictEqual(nodePath.instance, 'ObjectId');
    assert.strictEqual(nodePath.options.ref, 'HyNode');
    assert.strictEqual(nodePath.options.required, true);

    const nodeIndex = RelayL2tpState.schema.indexes().find(([fields]) => fields.node === 1);
    assert.ok(nodeIndex, 'node index exists');
    assert.strictEqual(nodeIndex[1].unique, true, 'node index is unique');
}

{
    const desiredStatePath = RelayL2tpState.schema.path('desiredState');
    const statusPath = RelayL2tpState.schema.path('status');

    assert.deepStrictEqual(desiredStatePath.enumValues, DESIRED_STATES);
    assert.deepStrictEqual(statusPath.enumValues, STATUSES);

    const invalidDesired = new RelayL2tpState({
        node: objectId(),
        desiredState: 'present',
        status: 'not_installed',
    }).validateSync();
    assert.strictEqual(invalidDesired.errors.desiredState.kind, 'enum');

    const invalidStatus = new RelayL2tpState({
        node: objectId(),
        desiredState: 'absent',
        status: 'unknown',
    }).validateSync();
    assert.strictEqual(invalidStatus.errors.status.kind, 'enum');
}

{
    const pskPath = RelayL2tpState.schema.path('pskEncrypted');
    assert.strictEqual(pskPath.options.select, false);
}

{
    const missingRouteGroup = new RelayL2tpState({
        node: objectId(),
        desiredState: 'installed',
        status: 'installing',
    }).validateSync();
    assert.strictEqual(missingRouteGroup.errors.routeGroup.kind, 'required');

    const observedInstalledWithoutRoute = new RelayL2tpState({
        node: objectId(),
        desiredState: 'absent',
        status: 'installed',
    }).validateSync();
    assert.strictEqual(observedInstalledWithoutRoute.errors.routeGroup.kind, 'required');

    assertValid(new RelayL2tpState({
        node: objectId(),
        desiredState: 'installed',
        status: 'installed',
        routeGroup: objectId(),
    }), 'installed state with an explicit route group is valid');

    assertValid(new RelayL2tpState({
        node: objectId(),
        desiredState: 'absent',
        status: 'not_installed',
    }), 'absent state does not require a route group');
}

{
    const relayNodePath = L2tpUser.schema.path('relayNode');
    assert.strictEqual(relayNodePath.instance, 'ObjectId');
    assert.strictEqual(relayNodePath.options.ref, 'HyNode');
    assert.strictEqual(relayNodePath.options.required, true);

    const identityIndex = L2tpUser.schema.indexes().find(([fields]) => (
        fields.relayNode === 1 && fields.login === 1
    ));
    assert.ok(identityIndex, 'relayNode/login index exists');
    assert.strictEqual(identityIndex[1].unique, true, 'relayNode/login index is unique');
}

{
    const passwordPath = L2tpUser.schema.path('passwordEncrypted');
    assert.strictEqual(passwordPath.options.select, false);
}

{
    const ipPath = L2tpUser.schema.path('ip');
    assert.strictEqual(ipPath.options.required, true);

    assertValid(new L2tpUser({
        relayNode: objectId(),
        login: 'canonical-ip',
        ip: '10.77.0.10',
        passwordEncrypted: 'v1:iv:tag:ciphertext',
        desiredRevision: 1,
    }));

    for (const ip of [undefined, '', '10.077.0.10', '10.77.0.999', '2001:db8::1']) {
        const error = new L2tpUser({
            relayNode: objectId(),
            login: 'invalid-ip',
            ip,
            passwordEncrypted: 'v1:iv:tag:ciphertext',
            desiredRevision: 1,
        }).validateSync();
        assert.ok(error.errors.ip, `IP ${JSON.stringify(ip)} is rejected`);
    }
}

{
    const validLogins = [
        'alice',
        'Alice_01',
        'first.last',
        'name@example.com',
        'user-name',
        'a'.repeat(64),
    ];

    for (const login of validLogins) {
        assertValid(new L2tpUser({
            relayNode: objectId(),
            login,
            ip: '10.77.0.10',
            passwordEncrypted: 'v1:iv:tag:ciphertext',
        }), `login ${login} is accepted`);
    }

    const invalidLogins = [
        '',
        'contains space',
        'contains/slash',
        'line\nbreak',
        'a'.repeat(65),
    ];

    for (const login of invalidLogins) {
        const error = new L2tpUser({
            relayNode: objectId(),
            login,
            passwordEncrypted: 'v1:iv:tag:ciphertext',
        }).validateSync();
        assert.ok(error.errors.login, `login ${JSON.stringify(login)} is rejected`);
    }
}

{
    const user = new L2tpUser({
        relayNode: objectId(),
        login: 'enabled-by-default',
        passwordEncrypted: 'v1:iv:tag:ciphertext',
    });
    assert.strictEqual(user.enabled, true);
}

console.log('relay-l2tp model tests: OK');
