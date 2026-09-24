'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    L2tpSimpleService,
    autoDesiredInput,
    allocateIpv4,
    buildTeardownScript,
} = require('../services/l2tpSimpleService');

function chainable(rows) {
    const query = {
        select() { return query; },
        sort() { return query; },
        lean: async () => rows,
        then: resolve => resolve(rows),
    };
    return query;
}

function createModels({ nodes = [], states = [], users = [], groups = [], links = [] } = {}) {
    const stateStore = states.map(state => ({ ...state }));
    const userStore = users.map(user => ({ ...user }));
    return {
        HyNode: {
            find: filter => chainable(
                nodes.filter(node => !filter?.cascadeRole || node.cascadeRole === filter.cascadeRole),
            ),
            findById: id => {
                const node = nodes.find(entry => String(entry._id) === String(id)) ?? null;
                return {
                    lean: async () => node,
                    then: resolve => resolve(node),
                };
            },
        },
        RelayL2tpState: {
            find: () => chainable(stateStore),
            findOne: filter => {
                const state = stateStore.find(
                    entry => String(entry.node) === String(filter?.node),
                ) ?? null;
                return { lean: async () => state, then: resolve => resolve(state) };
            },
            findOneAndUpdate: async (filter, update) => {
                const state = stateStore.find(
                    entry => String(entry.node) === String(filter?.node),
                );
                if (state && update?.$set) Object.assign(state, update.$set);
                return state ?? null;
            },
            _store: stateStore,
        },
        L2tpUser: {
            find: filter => chainable(
                userStore.filter(user => !filter?.login || user.login === filter.login),
            ),
            findOne: filter => {
                const user = userStore.find(
                    entry => String(entry.relayNode) === String(filter?.relayNode)
                        && (!filter?.login || entry.login === filter.login),
                ) ?? null;
                return {
                    select: () => ({ lean: async () => user }),
                    lean: async () => user,
                    then: resolve => resolve(user),
                };
            },
            deleteOne: async filter => {
                const index = userStore.findIndex(
                    entry => String(entry._id) === String(filter?._id),
                );
                if (index >= 0) userStore.splice(index, 1);
            },
            _store: userStore,
        },
        CascadeRouteGroup: {
            find: () => chainable(groups),
            create: async document => ({ _id: 'group-auto', ...document }),
        },
        CascadeLink: {
            find: () => chainable(links),
        },
    };
}

function createService(overrides = {}, models = createModels()) {
    return new L2tpSimpleService({
        ...models,
        l2tpService: {
            install: async () => ({ operationId: 'op-1' }),
            getOperation: async () => ({}),
            ...overrides.l2tpService,
        },
        stateManagementService: {
            configureRelay: async () => ({}),
            revealPsk: async () => ({ psk: 'psk-relay' }),
            ...overrides.stateManagementService,
        },
        userManagementService: {
            createUser: async () => ({}),
            deleteUser: async () => ({ deleted: true, syncOperationId: 'sync-1' }),
            importUser: async () => ({}),
            ...overrides.userManagementService,
        },
        stateRepository: {
            getTopologyRevision: async () => 7,
            ...overrides.stateRepository,
        },
        nodeSSHFactory: overrides.nodeSSHFactory ?? (() => ({
            exec: async () => ({ code: 0, stdout: 'TEARDOWN_OK' }),
            disconnect: () => {},
        })),
        secretBox: overrides.secretBox ?? null,
        secretKey: overrides.secretKey ?? null,
    });
}

const RELAY = { _id: 'relay-1', name: 'Relay One', cascadeRole: 'relay', status: 'online' };
const STATE = {
    node: 'relay-1',
    desiredState: 'installed',
    status: 'installed',
    clientCidr: '10.255.30.0/24',
    localAddress: '10.255.30.1',
    poolStart: '10.255.30.10',
    poolEnd: '10.255.30.20',
    dnsServers: ['1.1.1.1'],
    tproxyPort: 12345,
    fwmark: 100,
    routeTable: 100,
    routeGroup: 'group-a',
    secretRevision: 3,
    pskEncrypted: 'v1:enc',
};

test('entityId handles bson ObjectId self-referencing getters', async () => {
    const objectIdLike = { toHexString: () => '64b0f0f0f0f0f0f0f0f0f0f0' };
    const models = createModels({ nodes: [{ ...RELAY, _id: objectIdLike }], states: [] });
    const service = createService({}, models);
    const overview = await service.overview();
    assert.equal(overview.relays[0].id, '64b0f0f0f0f0f0f0f0f0f0f0');
});

test('autoDesiredInput generates a deterministic collision-free subnet', () => {
    const first = autoDesiredInput('relay-a', [], 'group-a');
    const repeat = autoDesiredInput('relay-a', [], 'group-a');
    assert.equal(first.clientCidr, repeat.clientCidr);
    assert.match(first.clientCidr, /^10\.255\.\d+\.0\/24$/);
    assert.equal(first.localAddress, first.clientCidr.replace('0/24', '1'));
    assert.equal(first.generatePsk, true);

    const taken = [{ clientCidr: first.clientCidr }];
    const second = autoDesiredInput('relay-b', taken, 'group-a');
    assert.notEqual(second.clientCidr, first.clientCidr);
});

test('allocateIpv4 returns the first free pool address and skips the local address', () => {
    const state = {
        poolStart: '10.255.30.1',
        poolEnd: '10.255.30.4',
        localAddress: '10.255.30.1',
    };
    assert.equal(allocateIpv4(state, new Set()), '10.255.30.2');
    assert.equal(allocateIpv4(state, new Set(['10.255.30.2'])), '10.255.30.3');
    assert.throws(
        () => allocateIpv4(state, new Set(['10.255.30.2', '10.255.30.3', '10.255.30.4'])),
        error => error?.code === 'POOL_EXHAUSTED',
    );
});

test('buildTeardownScript removes services, firewall state, files and the xray inbound', () => {
    const script = buildTeardownScript({ routeTable: 100 });
    for (const marker of [
        'systemctl stop xl2tpd.service strongswan-starter.service',
        'nft delete table inet celerity_l2tp',
        'ip -4 rule del priority 10077',
        'ip -4 route flush table 100',
        '/etc/ipsec.secrets',
        '/etc/ppp/chap-secrets',
        'base64 -d | python3',
        'TEARDOWN_OK',
    ]) {
        assert.ok(script.includes(marker), `missing ${marker}`);
    }
    const payload = script.match(/printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d/);
    assert.ok(payload, 'xray strip payload missing');
    const python = Buffer.from(payload[1], 'base64').toString('utf8');
    assert.ok(python.includes('relay-l2tp-'));
    assert.ok(python.includes('/usr/local/etc/xray/config.json'));
});

test('overview groups accounts by login and reveals the PSK per installed relay', async () => {
    const models = createModels({
        nodes: [RELAY],
        states: [STATE],
        users: [
            { _id: 'u1', relayNode: 'relay-1', login: 'alice', ip: '10.255.30.10', enabled: true, syncStatus: 'synced' },
            { _id: 'u2', relayNode: 'relay-1', login: 'bob', ip: '10.255.30.11', enabled: true, syncStatus: 'pending' },
        ],
    });
    const service = createService({}, models);

    const overview = await service.overview();

    assert.equal(overview.relays.length, 1);
    assert.equal(overview.relays[0].installed, true);
    assert.equal(overview.relays[0].psk, 'psk-relay');
    assert.equal(overview.accounts.length, 2);
    assert.equal(overview.accounts[0].login, 'alice');
    assert.equal(overview.accounts[1].pending, true);
    assert.equal(overview.accounts[0].relays[0].name, 'Relay One');
});

test('installRelay auto-configures defaults, inherits accounts and queues install', async () => {
    const models = createModels({
        nodes: [RELAY, { _id: 'relay-2', name: 'Two', cascadeRole: 'relay', status: 'online' }],
        states: [{ ...STATE, node: 'relay-2' }],
        users: [{
            _id: 'u1',
            relayNode: 'relay-2',
            login: 'alice',
            ip: '10.255.30.10',
            enabled: true,
            passwordEncrypted: 'v1:pw',
        }],
        groups: [{ _id: 'group-a', name: 'g' }],
    });
    const calls = { configure: [], importUser: [], install: [] };
    const service = createService({
        stateManagementService: {
            configureRelay: async (nodeId, input) => {
                calls.configure.push({ nodeId, input });
                models.RelayL2tpState._store.push({
                    node: nodeId,
                    desiredState: 'installed',
                    status: 'not_installed',
                    clientCidr: input.clientCidr,
                    localAddress: input.localAddress,
                    poolStart: input.poolStart,
                    poolEnd: input.poolEnd,
                    routeGroup: input.routeGroupId,
                    secretRevision: 1,
                });
            },
        },
        userManagementService: {
            createUser: async () => ({}),
            deleteUser: async () => ({}),
            importUser: async (nodeId, input) => { calls.importUser.push({ nodeId, input }); },
        },
        l2tpService: {
            install: async (nodeId, input) => {
                calls.install.push({ nodeId, input });
                return { operationId: 'op-9' };
            },
            getOperation: async () => ({}),
        },
    }, models);

    const result = await service.installRelay('relay-1');

    assert.deepEqual(result, { operationId: 'op-9' });
    assert.equal(calls.configure.length, 1);
    assert.equal(calls.configure[0].input.routeGroupId, 'group-a');
    assert.equal(calls.configure[0].input.generatePsk, true);
    assert.match(calls.configure[0].input.clientCidr, /^10\.255\.\d+\.0\/24$/);
    assert.equal(calls.importUser.length, 1);
    assert.equal(calls.importUser[0].input.login, 'alice');
    assert.equal(calls.importUser[0].input.passwordEncrypted, 'v1:pw');
    assert.ok(
        calls.importUser[0].input.ip.startsWith(
            calls.configure[0].input.poolStart.slice(0, calls.configure[0].input.poolStart.lastIndexOf('.')),
        ),
        'inherited account must get an address from the new relay pool',
    );
    assert.equal(calls.install[0].input.routeGroupId, 'group-a');
    assert.equal(calls.install[0].input.expectedTopologyRevision, 7);
});

test('installRelay reconfigures a state reset by uninstall before installing', async () => {
    const models = createModels({
        nodes: [RELAY],
        states: [{ ...STATE, desiredState: 'not_installed', status: 'not_installed' }],
        groups: [{ _id: 'group-a', name: 'g' }],
    });
    const calls = { configure: [], install: [] };
    const service = createService({
        stateManagementService: {
            configureRelay: async (nodeId, input) => {
                calls.configure.push({ nodeId, input });
            },
        },
        userManagementService: {
            createUser: async () => ({}),
            deleteUser: async () => ({}),
            importUser: async () => ({}),
        },
        l2tpService: {
            install: async (nodeId, input) => {
                calls.install.push({ nodeId, input });
                return { operationId: 'op-reinstall' };
            },
            getOperation: async () => ({}),
        },
    }, models);

    const result = await service.installRelay('relay-1');

    assert.deepEqual(result, { operationId: 'op-reinstall' });
    assert.equal(calls.configure.length, 1);
    assert.equal(calls.configure[0].input.generatePsk, true);
    assert.equal(calls.install.length, 1);
});

test('installRelay auto-creates a route group from a linear cascade chain', async () => {
    const models = createModels({
        nodes: [RELAY],
        links: [{ _id: 'link-1', portalNode: 'relay-1', bridgeNode: 'bridge-1' }],
    });
    models.HyNode.findById = id => {
        const node = String(id) === 'bridge-1'
            ? { _id: 'bridge-1', cascadeRole: 'bridge' }
            : RELAY;
        return { lean: async () => node, then: resolve => resolve(node) };
    };
    let createdGroup;
    models.CascadeRouteGroup.create = async document => {
        createdGroup = document;
        return { _id: 'group-auto' };
    };
    const service = createService({
        stateManagementService: {
            configureRelay: async (nodeId, input) => {
                models.RelayL2tpState._store.push({
                    node: nodeId,
                    desiredState: 'installed',
                    status: 'not_installed',
                    clientCidr: input.clientCidr,
                    localAddress: input.localAddress,
                    poolStart: input.poolStart,
                    poolEnd: input.poolEnd,
                    routeGroup: input.routeGroupId,
                    secretRevision: 1,
                });
            },
        },
    }, models);

    await service.installRelay('relay-1');

    assert.equal(createdGroup.name, 'auto-l2tp');
    assert.equal(createdGroup.mode, 'reverse');
    assert.deepEqual(createdGroup.paths[0].linkIds.map(String), ['link-1']);
});

test('installRelay rejects a branching cascade when no route group exists', async () => {
    const models = createModels({
        nodes: [RELAY],
        links: [
            { _id: 'link-1', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
            { _id: 'link-2', portalNode: 'relay-1', bridgeNode: 'bridge-2' },
        ],
    });
    const service = createService({}, models);

    await assert.rejects(
        () => service.installRelay('relay-1'),
        error => error?.code === 'ROUTE_GROUP_AMBIGUOUS',
    );
});

test('createAccount fans out to every installed relay with per-relay addresses', async () => {
    const models = createModels({
        nodes: [RELAY, { _id: 'relay-2', name: 'Two', cascadeRole: 'relay', status: 'online' }],
        states: [
            STATE,
            {
                ...STATE,
                node: 'relay-2',
                clientCidr: '10.255.31.0/24',
                localAddress: '10.255.31.1',
                poolStart: '10.255.31.10',
                poolEnd: '10.255.31.20',
            },
        ],
    });
    const created = [];
    const service = createService({
        userManagementService: {
            createUser: async (nodeId, input) => { created.push({ nodeId, input }); },
            deleteUser: async () => ({}),
            importUser: async () => ({}),
        },
    }, models);

    const result = await service.createAccount({ login: 'alice', password: 'secret-pw' });

    assert.equal(created.length, 2);
    assert.equal(created[0].input.ip, '10.255.30.10');
    assert.equal(created[1].input.ip, '10.255.31.10');
    assert.equal(created[0].input.password, 'secret-pw');
    assert.equal(result.password, 'secret-pw');
    assert.equal(result.results.every(entry => entry.created), true);
});

test('createAccount generates a password when none is provided', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    const created = [];
    const service = createService({
        userManagementService: {
            createUser: async (nodeId, input) => { created.push({ nodeId, input }); },
            deleteUser: async () => ({}),
            importUser: async () => ({}),
        },
    }, models);

    const result = await service.createAccount({ login: 'bob' });

    assert.equal(created.length, 1);
    assert.match(created[0].input.password, /^[A-Za-z0-9_-]{16}$/);
    assert.equal(result.password, created[0].input.password);
});

test('overview reveals account passwords through the secret box', async () => {
    const models = createModels({
        nodes: [RELAY],
        states: [STATE],
        users: [{
            _id: 'u1',
            relayNode: 'relay-1',
            login: 'alice',
            ip: '10.255.30.10',
            enabled: true,
            syncStatus: 'synced',
            passwordEncrypted: 'v1:sealed',
        }],
    });
    const service = createService({
        secretBox: { decrypt: envelope => (envelope === 'v1:sealed' ? 'plain-pw' : null) },
        secretKey: 'key',
    }, models);

    const overview = await service.overview();

    assert.equal(overview.accounts.length, 1);
    assert.equal(overview.accounts[0].password, 'plain-pw');
});

test('createAccount requires at least one installed relay', async () => {
    const service = createService({}, createModels({ nodes: [RELAY] }));
    await assert.rejects(
        () => service.createAccount({ login: 'alice', password: 'pw' }),
        error => error?.code === 'NO_INSTALLED_RELAYS',
    );
});

test('deleteAccount queues sync on installed relays and purges stale records elsewhere', async () => {
    const models = createModels({
        nodes: [RELAY],
        states: [STATE],
        users: [
            { _id: 'u1', relayNode: 'relay-1', login: 'alice', ip: '10.255.30.10' },
            { _id: 'u2', relayNode: 'relay-9', login: 'alice', ip: '10.255.99.10' },
        ],
    });
    const deleted = [];
    const service = createService({
        userManagementService: {
            createUser: async () => ({}),
            deleteUser: async (nodeId, userId) => {
                deleted.push({ nodeId, userId });
                return { deleted: true, syncOperationId: 'sync-1' };
            },
            importUser: async () => ({}),
        },
    }, models);

    const result = await service.deleteAccount('alice');

    assert.deepEqual(deleted, [{ nodeId: 'relay-1', userId: 'u1' }]);
    assert.equal(
        models.L2tpUser._store.some(user => user._id === 'u2'),
        false,
        'stale record on the uninstalled relay must be purged',
    );
    assert.equal(
        models.L2tpUser._store.some(user => user._id === 'u1'),
        true,
        'installed-relay deletion is delegated to userManagementService',
    );
    assert.equal(result.results.length, 2);
});

test('uninstallRelay runs the teardown over SSH and resets the desired state', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    let script;
    const service = createService({
        nodeSSHFactory: () => ({
            exec: async command => {
                script = command;
                return { code: 0, stdout: 'TEARDOWN_OK\n' };
            },
            disconnect: () => {},
        }),
    }, models);

    const result = await service.uninstallRelay('relay-1');

    assert.equal(result.ok, true);
    assert.ok(script.includes('celerity_l2tp'));
    const state = models.RelayL2tpState._store[0];
    assert.equal(state.desiredState, 'not_installed');
    assert.equal(state.status, 'not_installed');
});

test('uninstallRelay keeps the state when the node cannot be reached', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    const service = createService({
        nodeSSHFactory: () => ({
            exec: async () => { throw new Error('ssh down'); },
            disconnect: () => {},
        }),
    }, models);

    await assert.rejects(
        () => service.uninstallRelay('relay-1'),
        error => error?.code === 'UNINSTALL_FAILED',
    );
    assert.equal(models.RelayL2tpState._store[0].desiredState, 'installed');
});
