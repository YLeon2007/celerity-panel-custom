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
        session() { return query; },
        lean: async () => rows,
        then: resolve => resolve(rows),
    };
    return query;
}

function createModels({ nodes = [], states = [], users = [], groups = [], links = [] } = {}) {
    const stateStore = states.map(state => ({ ...state }));
    const userStore = users.map(user => ({ ...user }));
    const db = { transaction: work => work({}) };
    const models = {
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
                return { session() { return this; }, lean: async () => state,
                    then: resolve => resolve(state) };
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
            findById: id => ({
                session() { return this; },
                lean: async () => groups.find(entry => String(entry._id) === String(id)) ?? null,
            }),
            create: async documents => [{ _id: 'group-auto', ...documents[0] }],
            updateOne: async (filter, update) => {
                const group = groups.find(entry => String(entry._id) === String(filter._id));
                if (group && update?.$set) Object.assign(group, update.$set);
                return { matchedCount: group ? 1 : 0 };
            },
            findByIdAndUpdate: async (id, update) => {
                const group = groups.find(entry => String(entry._id) === String(id));
                if (group && update?.$set) Object.assign(group, update.$set);
                return group ?? null;
            },
            _store: groups,
        },
        CascadeLink: {
            find: () => chainable(links),
        },
        CascadeTopologyState: {
            findById: () => chainable({ revision: 7 }),
            findOneAndUpdate: () => chainable({ revision: 8 }),
        },
    };
    for (const model of Object.values(models)) model.db = db;
    return models;
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
        remoteAdmissionRepository: overrides.remoteAdmissionRepository ?? {
            acquire: async () => 'admission-1',
            release: async () => true,
        },
        lockService: overrides.lockService ?? {
            acquire: async ({ node, owner, operationId }) => ({ ok: true,
                lock: { node, owner, operationId, generation: 'generation-1' } }),
            releaseVerified: async () => ({ ok: true }),
        },
        allowRemoteExecution: overrides.allowRemoteExecution ?? true,
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

test('prepares the pinned uninstalled relay ingress before final pending link autoDeploy', async () => {
    const nodeId = '507f1f77bcf86cd799439034';
    const bridgeId = '507f1f77bcf86cd799439032';
    const groupId = '507f1f77bcf86cd799439099';
    const linkId = '507f1f77bcf86cd799439098';
    const models = createModels({
        nodes: [{ _id: nodeId, cascadeRole: 'relay' }, { _id: bridgeId, cascadeRole: 'bridge' }],
        states: [{ node: nodeId, desiredState: 'absent', status: 'not_installed',
            routeGroup: groupId, secretRevision: 7 }],
        links: [{ _id: linkId, portalNode: nodeId, bridgeNode: bridgeId,
            active: true, status: 'pending', mode: 'reverse' }],
    });
    let created;
    models.CascadeRouteGroup.create = async docs => { [created] = docs; return docs; };
    const service = createService({}, models);
    const result = await service.prepareConfiguredRelayIngress({
        linkId, expectedTopologyRevision: 7,
    });
    assert.equal(result.revision, 8);
    assert.equal(result.routeGroupId, groupId);
    assert.equal(created._id.toString(), groupId);
    assert.deepEqual(created.paths[0].linkIds.map(String), [linkId]);
    assert.equal(models.RelayL2tpState._store[0].desiredState, 'absent');
});

test('preparation defers an incomplete suffix without changing the pinned group or revision', async () => {
    const relay = '507f1f77bcf86cd799439034';
    const downstream = '507f1f77bcf86cd799439035';
    const groupId = '507f1f77bcf86cd799439099';
    const linkId = '507f1f77bcf86cd799439098';
    const models = createModels({
        nodes: [{ _id: relay, cascadeRole: 'relay' }, { _id: downstream, cascadeRole: 'relay' }],
        states: [{ node: relay, desiredState: 'absent', status: 'not_installed', routeGroup: groupId }],
        links: [{ _id: linkId, portalNode: relay, bridgeNode: downstream,
            active: true, status: 'pending' }],
    });
    models.CascadeRouteGroup.create = async () => { throw new Error('must not write'); };
    models.CascadeTopologyState.findOneAndUpdate = () => { throw new Error('must not increment'); };
    const result = await createService({}, models).prepareConfiguredRelayIngress({
        linkId, expectedTopologyRevision: 7,
    });
    assert.equal(result.revision, 7);
    assert.equal(result.deferred, true);
});

test('preparation excludes unrelated pending or disabled links from the relay suffix', async () => {
    const relay = '507f1f77bcf86cd799439034';
    const bridge = '507f1f77bcf86cd799439032';
    const groupId = '507f1f77bcf86cd799439099';
    const linkId = '507f1f77bcf86cd799439098';
    const models = createModels({
        nodes: [{ _id: relay, cascadeRole: 'relay' }, { _id: bridge, cascadeRole: 'bridge' }],
        states: [{ node: relay, desiredState: 'absent', status: 'not_installed', routeGroup: groupId }],
        links: [
            { _id: linkId, portalNode: relay, bridgeNode: bridge, active: true, status: 'pending' },
            { _id: '507f1f77bcf86cd799439097', portalNode: relay, bridgeNode: bridge,
                active: true, status: 'pending' },
            { _id: '507f1f77bcf86cd799439096', portalNode: relay, bridgeNode: bridge,
                active: false, status: 'deployed' },
        ],
    });
    let created;
    models.CascadeRouteGroup.create = async docs => { [created] = docs; return docs; };
    const result = await createService({}, models).prepareConfiguredRelayIngress({
        linkId, linkIds: [linkId, '507f1f77bcf86cd799439097'],
        expectedTopologyRevision: 7,
    });
    assert.equal(result.revision, 8);
    assert.deepEqual(created.paths[0].linkIds.map(String), [linkId]);
});

test('preparation refuses installed relay path mutation without writing', async () => {
    const relay = '507f1f77bcf86cd799439034';
    const bridge = '507f1f77bcf86cd799439032';
    const groupId = '507f1f77bcf86cd799439099';
    const linkId = '507f1f77bcf86cd799439098';
    const models = createModels({
        nodes: [{ _id: relay, cascadeRole: 'relay' }, { _id: bridge, cascadeRole: 'bridge' }],
        states: [{ node: relay, desiredState: 'installed', status: 'not_installed', routeGroup: groupId }],
        links: [{ _id: linkId, portalNode: relay, bridgeNode: bridge,
            active: true, status: 'pending' }],
    });
    models.CascadeRouteGroup.create = async () => { throw new Error('must not write'); };
    models.CascadeTopologyState.findOneAndUpdate = () => { throw new Error('must not increment'); };
    await assert.rejects(
        createService({}, models).prepareConfiguredRelayIngress({ linkId, expectedTopologyRevision: 7 }),
        { code: 'PREPARED_INGRESS_REQUIRED' },
    );
});

test('preparation rejects a stale revision before publishing ingress', async () => {
    const models = createModels();
    models.CascadeRouteGroup.create = async () => { throw new Error('must not write'); };
    await assert.rejects(
        createService({}, models).prepareConfiguredRelayIngress({
            linkId: '507f1f77bcf86cd799439098', expectedTopologyRevision: 6,
        }),
        { code: 'SIMPLE_TOPOLOGY_CONFLICT' },
    );
});

test('preparation preserves a retained old main path and allocates a distinct new path key', async () => {
    const relay = '507f1f77bcf86cd799439034';
    const bridge = '507f1f77bcf86cd799439032';
    const groupId = '507f1f77bcf86cd799439099';
    const oldLinkId = '507f1f77bcf86cd799439097';
    const linkId = '507f1f77bcf86cd799439098';
    const group = { _id: groupId, name: 'auto-l2tp', paths: [
        { pathKey: 'main', linkIds: [oldLinkId], enabled: true, priority: 100 },
    ] };
    const models = createModels({
        nodes: [{ _id: relay, cascadeRole: 'relay' }, { _id: bridge, cascadeRole: 'bridge' }],
        states: [{ node: relay, desiredState: 'absent', status: 'not_installed', routeGroup: groupId }],
        groups: [group],
        links: [{ _id: oldLinkId, portalNode: relay, bridgeNode: bridge,
            active: true, status: 'deployed', mode: 'reverse' },
        { _id: linkId, portalNode: relay, bridgeNode: bridge,
            active: true, status: 'pending' }],
    });
    const result = await createService({}, models).prepareConfiguredRelayIngress({
        linkId, expectedTopologyRevision: 7,
    });
    assert.equal(result.revision, 8);
    assert.deepEqual(group.paths.map(path => path.pathKey), ['main', `main-${relay.slice(-6)}`]);
    assert.deepEqual(group.paths[1].linkIds.map(String), [linkId]);
});

test('simple install never borrows another relay group when state has no pinned group', async () => {
    const models = createModels({ nodes: [RELAY, { _id: 'bridge-1', cascadeRole: 'bridge' }],
        links: [{ _id: 'link-1', portalNode: RELAY._id, bridgeNode: 'bridge-1',
            active: true, status: 'online' }],
        groups: [
        { _id: 'foreign-group', name: 'auto-l2tp', paths: [] },
    ] });
    let created;
    models.CascadeRouteGroup.create = async docs => {
        created = { ...docs[0], _id: docs[0]._id ?? '507f1f77bcf86cd799439099' };
        return [created];
    };
    const groupId = await createService({}, models).ensureRouteGroup(RELAY._id);
    assert.ok(created, 'a private group must be created');
    assert.equal(String(created._id), groupId);
    assert.notEqual(groupId, 'foreign-group');
});

test('simple install recreates the exact pinned group id after deletion', async () => {
    const groupId = '507f1f77bcf86cd799439099';
    const models = createModels({ nodes: [RELAY, { _id: 'bridge-1', cascadeRole: 'bridge' }],
        links: [{ _id: 'link-1', portalNode: RELAY._id, bridgeNode: 'bridge-1',
            active: true, status: 'online' }],
        states: [
        { node: RELAY._id, status: 'not_installed', desiredState: 'absent', routeGroup: groupId },
    ] });
    let created;
    models.CascadeRouteGroup.create = async docs => { [created] = docs; return docs; };
    const result = await createService({}, models).ensureRouteGroup(RELAY._id);
    assert.equal(result, groupId);
    assert.equal(String(created._id), groupId);
});

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
        'xray_status=',
        'systemctl restart xray.service',
        'unit_status()',
        'TEARDOWN_OK',
    ]) {
        assert.ok(script.includes(marker), `missing ${marker}`);
    }
    const payload = script.match(/printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d/);
    assert.ok(payload, 'xray strip payload missing');
    const python = Buffer.from(payload[1], 'base64').toString('utf8');
    assert.ok(python.includes('relay-l2tp-'));
    assert.ok(python.includes('/usr/local/etc/xray/config.json'));
    assert.ok(python.includes('except FileNotFoundError'));
    assert.ok(python.includes('raise'));
    assert.match(script, /unit_status\(\) \{/);
    assert.match(script, /systemctl show --no-pager --property=LoadState,ActiveState,UnitFileState --value/);
    assert.match(script, /nft_tables=\"\$\(nft list tables\)\"/);
    assert.ok(script.includes("case $'\\n'\"$nft_tables\"$'\\n' in"));
    assert.ok(script.includes("case $'\\n'\"$ip_rule_output\"$'\\n' in"));
    assert.doesNotMatch(script, /systemctl is-enabled/);
    assert.doesNotMatch(script, /grep -q/);
    assert.doesNotMatch(script, /! systemctl is-active/);
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
        nodes: [RELAY, { _id: 'relay-2', name: 'Two', cascadeRole: 'relay', status: 'online' },
            { _id: 'bridge-1', cascadeRole: 'bridge', status: 'online' }],
        links: [{ _id: 'link-1', portalNode: RELAY._id, bridgeNode: 'bridge-1',
            active: true, status: 'online' }],
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
    assert.equal(calls.configure[0].input.routeGroupId, 'group-auto');
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
    assert.equal(calls.install[0].input.routeGroupId, 'group-auto');
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
    assert.equal(calls.configure[0].input.reusePsk, true,
        'reinstall reuses the stored PSK instead of rotating it');
    assert.equal(
        calls.configure[0].input.clientCidr,
        STATE.clientCidr,
        'reinstall after uninstall must reuse the relay network layout so pinned account IPs stay valid',
    );
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
    models.CascadeRouteGroup.create = async documents => {
        createdGroup = documents[0];
        return [{ _id: 'group-auto' }];
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

test('installRelay rebuilds paths of an existing route group left empty by link deletion', async () => {
    const models = createModels({
        nodes: [RELAY],
        states: [{
            ...STATE,
            desiredState: 'not_installed',
            status: 'not_installed',
            routeGroup: 'group-empty',
        }],
        groups: [{ _id: 'group-empty', name: 'auto-l2tp', mode: 'reverse', paths: [] }],
        links: [
            { _id: 'link-1', portalNode: 'relay-1', bridgeNode: 'relay-2' },
            { _id: 'link-2', portalNode: 'relay-2', bridgeNode: 'bridge-1' },
        ],
    });
    const service = createService({}, models);

    await service.installRelay('relay-1');

    const group = models.CascadeRouteGroup._store.find(entry => entry._id === 'group-empty');
    assert.equal(group.paths.length, 1);
    assert.deepEqual(group.paths[0].linkIds.map(String), ['link-1', 'link-2']);
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

test('installRelay follows the default hop past a geoRouting branch', async () => {
    const models = createModels({
        nodes: [RELAY],
        links: [
            { _id: 'link-geo', portalNode: 'relay-1', bridgeNode: 'bridge-ru', geoRouting: { enabled: true, domains: ['category-ru'], geoip: ['ru'] } },
            { _id: 'link-main', portalNode: 'relay-1', bridgeNode: 'bridge-1' },
        ],
    });
    let createdGroup;
    models.CascadeRouteGroup.create = async documents => {
        createdGroup = documents[0];
        return [{ _id: 'group-auto' }];
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

    assert.ok(createdGroup, 'expected the auto route group to be created');
    assert.deepEqual(createdGroup.paths[0].linkIds.map(String), ['link-main']);
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

test('deleteAccount purges the record when the pinned node lost its relay role', async () => {
    const models = createModels({
        nodes: [RELAY],
        states: [STATE],
        users: [{ _id: 'u1', relayNode: 'relay-1', login: 'bob', ip: '10.255.30.10' }],
    });
    const service = createService({
        userManagementService: {
            createUser: async () => ({}),
            deleteUser: async () => {
                const error = new Error('L2TP users can only be managed for relay nodes');
                error.code = 'NODE_NOT_RELAY';
                throw error;
            },
            importUser: async () => ({}),
        },
    }, models);

    const result = await service.deleteAccount('bob');

    assert.equal(
        models.L2tpUser._store.some(user => user._id === 'u1'),
        false,
        'orphaned account record must be purged',
    );
    assert.deepEqual(result.results, [{ nodeId: 'relay-1', deleted: true, orphaned: true }]);
});

test('overview keeps listing re-roled nodes that still hold L2TP state', async () => {
    const models = createModels({
        nodes: [{ ...RELAY, cascadeRole: 'bridge' }],
        states: [STATE],
    });
    const service = createService({}, models);

    const nodes = await service.listRelayNodes();

    assert.deepEqual(nodes.map(node => String(node._id)), ['relay-1'],
        'a node with installed L2TP state stays manageable after re-role');
});

test('overview drops re-roled nodes once their L2TP state is uninstalled', async () => {
    const models = createModels({
        nodes: [{ ...RELAY, cascadeRole: 'bridge' }],
        states: [{ ...STATE, status: 'not_installed', desiredState: 'not_installed' }],
    });
    const service = createService({}, models);

    const nodes = await service.listRelayNodes();

    assert.deepEqual(nodes, [], 'uninstalled re-roled nodes must leave the list');
});

test('installRelay reuses the stored PSK instead of rotating it on reinstall', async () => {
    const models = createModels({
        nodes: [RELAY],
        // State left behind by uninstall: layout survives, desired is not_installed.
        states: [{ ...STATE, desiredState: 'not_installed', status: 'not_installed' }],
        groups: [{ _id: 'group-a', name: 'g', paths: [] }],
    });
    const calls = { configure: [], install: [] };
    const service = createService({
        stateManagementService: {
            configureRelay: async (nodeId, input) => {
                calls.configure.push({ nodeId, input });
            },
        },
        l2tpService: {
            install: async (nodeId, options) => {
                calls.install.push({ nodeId, options });
                return { operationId: 'op-1' };
            },
        },
    }, models);

    await service.installRelay(RELAY._id);

    assert.equal(calls.configure.length, 1, 'layout reuse must reconfigure desired state');
    assert.equal(calls.configure[0].input.reusePsk, true,
        'reinstall must keep the stored PSK so clients are not stranded');
    assert.equal(calls.configure[0].input.generatePsk, undefined,
        'reinstall must not rotate the PSK');
});

test('uninstallRelay still tears down after the node lost its relay role', async () => {
    const models = createModels({
        nodes: [{ ...RELAY, cascadeRole: 'bridge' }],
        states: [STATE],
    });
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
    assert.ok(script, 'teardown script must run on the re-roled node');
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

test('uninstallRelay does not decrement admission when exact lock release is not confirmed', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    let admissionRelease = 0;
    const service = createService({
        nodeSSHFactory: () => ({
            exec: async () => ({ code: 0, stdout: 'TEARDOWN_OK\n' }),
            disconnect: () => {},
        }),
        remoteAdmissionRepository: {
            acquire: async () => 'admission-release-failed',
            release: async () => { admissionRelease += 1; },
        },
        lockService: {
            acquire: async () => ({ ok: true, lock: { node: 'relay-1', owner: 'owner',
                operationId: 'op', generation: 'generation-1' } }),
            releaseVerified: async () => ({ ok: false }),
        },
    }, models);

    await assert.rejects(
        () => service.uninstallRelay('relay-1'),
        error => error?.code === 'UNINSTALL_FENCE_RELEASE_FAILED'
            && error.remoteOutcomeUncertain === true,
    );
    assert.equal(admissionRelease, 0);
});

test('uninstallRelay keeps the state when the node cannot be reached', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    let admissionRelease = 0;
    let lockRelease = 0;
    const service = createService({
        nodeSSHFactory: () => ({
            exec: async () => { throw new Error('ssh down'); },
            disconnect: () => {},
        }),
        remoteAdmissionRepository: { acquire: async () => 'admission-1', release: async () => { admissionRelease += 1; } },
        lockService: {
            acquire: async () => ({ ok: true, lock: { node: 'relay-1', owner: 'owner',
                operationId: 'op', generation: 'generation-1' } }),
            releaseVerified: async () => { lockRelease += 1; },
        },
    }, models);

    await assert.rejects(
        () => service.uninstallRelay('relay-1'),
        error => error?.code === 'UNINSTALL_UNCERTAIN' && error.remoteOutcomeUncertain === true,
    );
    assert.equal(admissionRelease, 0);
    assert.equal(lockRelease, 0);
    assert.equal(models.RelayL2tpState._store[0].desiredState, 'installed');
});

test('simple install and uninstall are blocked before any state or SSH mutation outside TEST', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    let sshCalls = 0;
    const service = createService({
        allowRemoteExecution: false,
        nodeSSHFactory: () => ({
            exec: async () => { sshCalls += 1; },
            disconnect: () => {},
        }),
    }, models);

    await assert.rejects(() => service.installRelay('relay-1'), { code: 'REMOTE_EXECUTION_DISABLED' });
    await assert.rejects(() => service.uninstallRelay('relay-1'), { code: 'REMOTE_EXECUTION_DISABLED' });
    assert.equal(sshCalls, 0);
    assert.equal(models.RelayL2tpState._store[0].status, 'installed');
});

test('uninstallRelay retains admission when lock acquisition is uncertain', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    let admissionRelease = 0;
    let sshCalls = 0;
    const service = createService({
        remoteAdmissionRepository: {
            acquire: async () => 'admission-lock-uncertain',
            release: async () => { admissionRelease += 1; },
        },
        lockService: {
            acquire: async () => { throw new Error('lock write timeout'); },
            releaseVerified: async () => ({ ok: true }),
        },
        nodeSSHFactory: () => ({
            exec: async () => { sshCalls += 1; },
            disconnect: () => {},
        }),
    }, models);

    await assert.rejects(
        () => service.uninstallRelay('relay-1'),
        error => error?.message === 'lock write timeout' && error.remoteOutcomeUncertain === true,
    );
    assert.equal(admissionRelease, 0);
    assert.equal(sshCalls, 0);
});

test('uninstallRelay retains fences when teardown exits without proof of cleanup', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    let admissionRelease = 0;
    let lockRelease = 0;
    const service = createService({
        nodeSSHFactory: () => ({
            exec: async () => ({ code: 1, stdout: 'partial cleanup\\n' }),
            disconnect: () => {},
        }),
        remoteAdmissionRepository: {
            acquire: async () => 'admission-teardown-uncertain',
            release: async () => { admissionRelease += 1; },
        },
        lockService: {
            acquire: async () => ({ ok: true, lock: { node: 'relay-1', owner: 'owner',
                operationId: 'op', generation: 'generation-1' } }),
            releaseVerified: async () => { lockRelease += 1; return { ok: true }; },
        },
    }, models);

    await assert.rejects(
        () => service.uninstallRelay('relay-1'),
        error => error?.code === 'UNINSTALL_UNCERTAIN' && error.remoteOutcomeUncertain === true,
    );
    assert.equal(admissionRelease, 0);
    assert.equal(lockRelease, 0);
    assert.equal(models.RelayL2tpState._store[0].status, 'installed');
});

test('uninstallRelay treats TEARDOWN_OK without an exit code as uncertain', async () => {
    const models = createModels({ nodes: [RELAY], states: [STATE] });
    let admissionRelease = 0;
    let lockRelease = 0;
    const service = createService({
        nodeSSHFactory: () => ({
            exec: async () => ({ stdout: 'TEARDOWN_OK\\n' }),
            disconnect: () => {},
        }),
        remoteAdmissionRepository: {
            acquire: async () => 'admission-missing-exit-code',
            release: async () => { admissionRelease += 1; },
        },
        lockService: {
            acquire: async () => ({ ok: true, lock: { node: 'relay-1', owner: 'owner',
                operationId: 'op', generation: 'generation-1' } }),
            releaseVerified: async () => { lockRelease += 1; return { ok: true }; },
        },
    }, models);

    await assert.rejects(
        () => service.uninstallRelay('relay-1'),
        error => error?.code === 'UNINSTALL_UNCERTAIN' && error.remoteOutcomeUncertain === true,
    );
    assert.equal(admissionRelease, 0);
    assert.equal(lockRelease, 0);
    assert.equal(models.RelayL2tpState._store[0].status, 'installed');
});
