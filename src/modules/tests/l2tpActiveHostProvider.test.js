'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createL2tpActiveHostProvider,
    createL2tpRouteBindings,
} = require('../l2tpActiveHostProvider');

function createHost(marker = 'active') {
    return {
        runtime: {
            service: {
                async getStatus() { return marker; },
                async preflight() { return marker; },
                async install() { return marker; },
                async getOperation() { return marker; },
            },
            stateManagementService: {
                async configureRelay() { return marker; },
            },
            userManagementService: {
                async createUser() { return marker; },
                async listUsers() { return marker; },
                async updateUser() { return marker; },
                async disableUser() { return marker; },
            },
        },
        async loadPanelOverview() { return marker; },
    };
}

test('active host provider validates before atomic install and clears only the exact host', () => {
    const provider = createL2tpActiveHostProvider();
    const host = createHost();
    const otherHost = createHost('other');

    assert.equal(provider.getActiveHost(), null);
    assert.throws(
        () => provider.installActiveHost({ runtime: {} }),
        /runtime service requires getStatus/,
    );
    assert.equal(provider.getActiveHost(), null);

    assert.strictEqual(provider.installActiveHost(host), host);
    assert.strictEqual(provider.getActiveHost(), host);
    assert.throws(
        () => provider.installActiveHost(otherHost),
        /already installed/,
    );
    assert.strictEqual(provider.getActiveHost(), host);
    assert.equal(provider.clearActiveHost(otherHost), false);
    assert.strictEqual(provider.getActiveHost(), host);
    assert.equal(provider.clearActiveHost(host), true);
    assert.equal(provider.getActiveHost(), null);
});

test('route bindings resolve the current host per call and fail closed while dormant', async () => {
    const provider = createL2tpActiveHostProvider();
    const bindings = createL2tpRouteBindings(provider);

    assert.throws(
        () => bindings.l2tpService.preflight('relay-a', {}),
        error => error.code === 'L2TP_RUNTIME_UNAVAILABLE',
    );
    assert.throws(
        () => bindings.userManagementService.listUsers('relay-a'),
        error => error.code === 'L2TP_RUNTIME_UNAVAILABLE',
    );

    const host = createHost('active-host');
    provider.installActiveHost(host);
    assert.equal(
        await bindings.stateManagementService.configureRelay('relay-a', {}),
        'active-host',
    );
    assert.equal(
        await bindings.l2tpService.preflight('relay-a', {}),
        'active-host',
    );
    assert.equal(
        await bindings.userManagementService.listUsers('relay-a'),
        'active-host',
    );
    assert.equal(await bindings.loadPanelOverview(), 'active-host');

    provider.clearActiveHost(host);
    assert.throws(
        () => bindings.stateManagementService.configureRelay('relay-a', {}),
        error => error.code === 'L2TP_RUNTIME_UNAVAILABLE',
    );
    assert.throws(
        () => bindings.userManagementService.createUser('relay-a', {}),
        error => error.code === 'L2TP_RUNTIME_UNAVAILABLE',
    );
});
