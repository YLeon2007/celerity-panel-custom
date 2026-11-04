'use strict';

// Local service/gate orchestration only. Persistence, SSH and service state are
// explicitly modeled; actual composer, ingress Python and PPP transport run.
process.env.PANEL_DOMAIN ||= 'panel.example.test';
process.env.ACME_EMAIL ||= 'admin@example.test';
process.env.ENCRYPTION_KEY ||= '01234567890123456789012345678901';
process.env.SESSION_SECRET ||= 'test-session-secret';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { L2tpSimpleService } = require('../services/l2tpSimpleService');
const { TopologyAttachIngressGate } = require('../services/topologyAttachIngressGate');
const { createTopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const { deriveAttachTopology, deriveReplacementTopology } = require('../domain/topologyReplacement');
const { projectGroups } = require('../domain/topologyDraft');
const { compileTopology } = require('../domain/topologyCompiler');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
const generator = require('../../../services/configGenerator');

const SYNC = 'abcdef012345abcdef012345';
const query = read => ({ select() { return this; }, session() { return this; },
    sort() { return this; }, async lean() { return structuredClone(await read()); } });
function freeze(value) {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
}
function compose(topology, staged) {
    const result = composeFrozenTopologyDeploymentPlan({ snapshot: topology,
        compiledTopology: compileTopology(topology), staged,
        nodeMetadata: topology.nodes.map((node, i) => ({ ...node, type: 'xray', active: true,
            ip: `192.0.2.${i + 1}`, domain: `${node.id}.example.test`, port: 24000 + i,
            xray: { apiPort: 61000 + i, inboundTag: `client-${node.id}`, transport: 'tcp', security: 'none' } })),
        linkMetadata: topology.links.map((link, i) => ({ ...link, tunnelPort: 12000 + i,
            tunnelUuid: `uuid-${link.id}`, tunnelDomain: 'reverse.example.test',
            tunnelProtocol: 'vless', tunnelSecurity: 'none', tunnelTransport: 'tcp' })),
    });
    // Explicit hydration seam; production coordinator owns this identity binding.
    const ids = { portal: 'p', 'relay-1': 'r', bridge: 'b' };
    return result.nodes.map(node => ({ ...node, node: ids[node.nodeRef] }));
}
function fixture({ attaching = false, sourceLess = true, mode = 'reverse', noExit = false } = {}) {
    const calls = [];
    const snapshot = {
        nodes: [{ _id: 'r', cascadeRole: 'relay' }, { _id: 'b', cascadeRole: 'bridge' },
            ...(!sourceLess ? [{ _id: 'p', cascadeRole: 'portal' }] : [])],
        links: [...(!sourceLess ? [{ _id: 'input', portalNode: 'p', bridgeNode: 'r', mode,
            active: true, status: 'online' }] : []),
        ...(!attaching ? [{ _id: 'old', portalNode: 'r', bridgeNode: 'b', mode,
            active: true, status: 'online' }] : []),
        { _id: 'new', portalNode: 'r', bridgeNode: 'b', mode, active: true, status: 'pending' }],
        groups: [{ _id: 'g', name: 'kept name', mode, strategy: 'priority-failover', paths: [
            { pathKey: 'mine', linkIds: attaching ? [] : ['old'], priority: 4, enabled: true },
            { pathKey: 'peer', linkIds: [], priority: 17, enabled: false }],
        }], activeRouteGroupIds: ['g'], installedRouteGroupIds: ['g'],
        installedRouteOwners: [{ groupId: 'g', nodeId: 'r', pathKey: 'mine' }],
    };
    const state = { node: 'r', status: 'installed', desiredState: 'installed', routeGroup: 'g',
        activePathKey: 'mine', appliedTopologyRevision: 7, secretRevision: 41,
        pskEncrypted: 'synthetic-preserved-psk', clientCidr: '10.255.30.0/24',
        localAddress: '10.255.30.1', poolStart: '10.255.30.10', poolEnd: '10.255.30.250',
        dnsServers: ['1.1.1.1'], tproxyPort: 12345, fwmark: 100, routeTable: 100 };
    const users = [{ _id: 'user', relayNode: 'r', login: 'preserved-user', passwordEncrypted: 'synthetic-secret',
        ip: '10.255.30.10', enabled: true, desiredRevision: 41, appliedRevision: 41,
        syncStatus: 'synced', syncOperationId: SYNC }];
    let topology;
    let nodes;
    if (noExit) {
        topology = { nodes: [{ id: 'p', role: 'portal' }, { id: 'r', role: 'relay' }],
            links: [{ id: 'input', source: 'p', target: 'r', mode }],
            groups: projectGroups(snapshot.groups).map(group => ({ ...group,
                paths: group.paths.map(path => path.pathKey === 'mine' ? { ...path, linkIds: [] } : path) })) };
        nodes = compose({ ...topology, groups: [] }, true);
        // Real shipped ingress primitive + real staged block candidate. The
        // composer owner must integrate this empty-path composition itself.
        const relay = nodes.find(node => node.node === 'r');
        const config = JSON.parse(Buffer.from(relay.candidate.bytes));
        generator.applyCascadePathIngress(config, [{ pathKey: 'mine',
            port: cascadePathIngressPort('g', 'mine'), egressTag: 'block' }]);
        // Block PPP before the existing reverse-handshake domain rule. The
        // production composer must preserve this ordering for empty paths.
        config.routing.rules.unshift(config.routing.rules.pop());
        const content = `${JSON.stringify(config)}\n`;
        const sha256 = require('node:crypto').createHash('sha256').update(content).digest('hex');
        relay.candidate = { ...relay.candidate, bytes: [...Buffer.from(content)], sha256 };
        relay.candidateHash = sha256;
    } else {
        ({ topology } = attaching ? deriveAttachTopology(snapshot, { groupId: 'g', pathKey: 'mine', linkId: 'new' })
            : deriveReplacementTopology(snapshot, { groupId: 'g', pathKey: 'mine', oldLinkId: 'old', newLinkId: 'new' }));
        nodes = compose(topology, sourceLess);
    }
    const plan = { operationId: 'operation-1', topologyRevision: 9,
        kind: noExit ? 'link.delete' : attaching ? 'link.attach' : 'link.replace',
        linkId: noExit ? 'old' : 'new', groupId: 'g', pathKey: 'mine', ownerNodeId: 'r',
        ownerTopologyRevision: 7, ownerCredentialRevision: 41,
        oldPathLinkIds: attaching ? [] : ['old'], newPathLinkIds: noExit ? [] : ['new'],
        effectiveTopology: topology, nodes, ...(sourceLess || noExit ? { staged: true } : {}),
        ...(noExit ? { routeState: 'no_bridge_exit' } : {}) };
    const port = cascadePathIngressPort('g', 'mine');
    const main = {
        inbounds: [{ tag: 'relay-l2tp-g', listen: '0.0.0.0', port: 12345, protocol: 'dokodemo-door',
            settings: { network: 'tcp,udp', followRedirect: true }, streamSettings: { sockopt: { tproxy: 'tproxy' } } }],
        outbounds: [{ tag: 'cascade-mine', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port }] } }],
        routing: { rules: [{ type: 'field', inboundTag: ['relay-l2tp-g'], outboundTag: 'cascade-mine' }] },
    };
    const options = { main, active: true, readback: { ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
        enabledUserCount: 1, managedUserCount: 1 } };
    const models = {
        HyNode: { find: () => query(() => snapshot.nodes), findById: node => query(() => ({ _id: node,
            type: 'xray', active: true, cascadeRole: 'relay', ssh: {} })) },
        RelayL2tpState: { find: () => query(() => { calls.push('owners'); return options.owners || [state]; }),
            findOne: () => query(() => { calls.push('state'); return state; }) },
        L2tpUser: { find: () => query(() => { calls.push('users'); return users; }) },
        CascadeRouteGroup: { find: () => query(() => snapshot.groups),
            findById: () => query(() => { calls.push('group'); return snapshot.groups[0]; }) },
        L2tpOperation: { findOne: () => query(() => options.noSync ? null : { _id: SYNC,
            node: 'r', kind: 'sync_users', status: 'succeeded', plan: { operationId: SYNC, relayId: 'r',
                desired: { credentialRevision: 41 } } }) },
    };
    const ingressGate = new TopologyAttachIngressGate({ nodeExecutionResolver: { async resolve(input) {
        calls.push(['ingress-resolve', input]);
        return { async connect() {}, disconnect() {}, async exec(command, execOptions) {
            calls.push(['ingress', command]);
            const setup = `import builtins, io, subprocess\nbuiltins.open = lambda *a, **k: io.StringIO(${JSON.stringify(JSON.stringify(options.main))})\nsubprocess.run = lambda *a, **k: type('Result', (), {'returncode': ${options.active ? 0 : 3}, 'stdout': ${JSON.stringify(options.active ? 'active\n' : 'inactive\n')}, 'stderr': ''})()\n`;
            const result = spawnSync('python3', ['-'], { input: setup + execOptions.stdin, encoding: 'utf8' });
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        } };
    } } });
    const pppGate = createTopologyPppReadinessGate({ ...models, executionContext: TEST, readOnly: true,
        NodeSSH: class ModeledReadOnlySSH {
            async exec(command) {
                calls.push(['ppp', command]);
                if (options.onReadback) options.onReadback();
                return { code: options.readback.ok ? 0 : 65, stderr: '', stdout: `${JSON.stringify(options.readback)}\n` };
            }
        } });
    const forbidden = () => { throw new Error('No install/uninstall/configure/user/path/publication writes permitted'); };
    const service = new L2tpSimpleService({ ...models,
        l2tpService: { install: forbidden, getOperation: forbidden },
        stateManagementService: { configureRelay: forbidden, revealPsk: forbidden },
        userManagementService: { createUser: forbidden, deleteUser: forbidden, importUser: forbidden },
        stateRepository: { getTopologyRevision: forbidden }, nodeSSHFactory: forbidden,
        allowRemoteExecution: true, topologyIngressGate: ingressGate, topologyPppReadinessGate: pppGate });
    return { service, plan, snapshot, state, users, calls, options, ingressGate, pppGate };
}

test('installed attach can prepare an absent owned path without inserting/publishing it', async () => {
    const f = fixture({ attaching: true });
    f.snapshot.groups[0].paths = f.snapshot.groups[0].paths.filter(path => path.pathKey !== 'mine');
    // Existing pure derivation defines the insert proposal; the service must
    // not turn that private projection into an eager group update.
    f.plan.effectiveTopology = deriveAttachTopology(f.snapshot,
        { groupId: 'g', pathKey: 'mine', linkId: 'new' }).topology;
    f.plan.nodes = compose(f.plan.effectiveTopology, true);
    const before = structuredClone(f.snapshot);
    const result = await f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) });
    assert.equal(result.ingressPrepared, true);
    assert.deepEqual(f.snapshot, before);
});

test('operation-owned installed one-hop preparation reuses ingress and preserves installed data without publication', async () => {
    const f = fixture();
    const before = structuredClone({ snapshot: f.snapshot, state: f.state, users: f.users });
    const result = await f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) });
    assert.equal(result.ingressPrepared, true);
    assert.equal(result.routeGroupId, 'g');
    assert.equal(result.ownerCredentialRevision, 41);
    assert.deepEqual(result.newPathLinkIds, ['new']);
    assert.equal(f.calls.filter(call => call[0] === 'ingress').length, 1);
    assert.equal(f.calls.filter(call => call[0] === 'ppp').length, 1);
    assert.deepEqual({ snapshot: f.snapshot, state: f.state, users: f.users }, before);
});

test('explicit last-exit delete retains users/ingress and reports blocked, never PPP Internet ready', async () => {
    const f = fixture({ sourceLess: false, noExit: true });
    const before = structuredClone({ snapshot: f.snapshot, state: f.state, users: f.users });
    const plan = freeze(f.plan);
    assert.equal(require('../services/topologyAttachIngressGate').ownedIngressRouteState(plan), 'no_bridge_exit',
        JSON.stringify(JSON.parse(Buffer.from(plan.nodes.find(node => node.node === 'r').candidate.bytes))));
    assert.deepEqual((await f.pppGate.verifyPlan(plan)).routeOutcome,
        { state: 'no_bridge_exit', internetProof: 'not_applicable', blockedOwnerNodeId: 'r' });
    const result = await f.service.prepareConfiguredRelayIngress({ operationPlan: plan });
    assert.equal(result.routeState, 'no_bridge_exit');
    assert.equal(result.pppInternetProof, 'not_applicable');
    assert.deepEqual(result.newPathLinkIds, []);
    assert.deepEqual({ snapshot: f.snapshot, state: f.state, users: f.users }, before);
});

function rewriteCandidate(plan, edit) {
    const relay = plan.nodes.find(node => node.node === plan.ownerNodeId);
    const config = JSON.parse(Buffer.from(relay.candidate.bytes));
    edit(config);
    const content = `${JSON.stringify(config)}\n`;
    const sha256 = require('node:crypto').createHash('sha256').update(content).digest('hex');
    relay.candidate = { ...relay.candidate, bytes: [...Buffer.from(content)], sha256 };
    relay.candidateHash = sha256;
}

for (const sourceLess of [true, false]) for (const attaching of [true, false]) for (const mode of ['forward', 'reverse']) {
    test(`installed ${attaching ? 'attach' : 'replacement'} ${sourceLess ? 'source-less' : 'with portal'} ${mode} prepares without route publication`, async () => {
        const f = fixture({ attaching, sourceLess, mode });
        const before = structuredClone({ state: f.state, users: f.users, snapshot: f.snapshot });
        const result = await f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) });
        assert.equal(result.ingressPrepared, true);
        assert.equal(result.pppInternetProof, 'unverified', 'node users are not an Internet probe');
        assert.ok(f.calls.some(call => call[0] === 'ppp'));
        assert.ok(f.calls.some(call => call[0] === 'ingress'));
        assert.deepEqual({ state: f.state, users: f.users, snapshot: f.snapshot }, before);
    });
}

for (const [label, change, code] of [
    ['foreign owner', f => { f.plan.ownerNodeId = 'foreign'; }, 'INVALID_INGRESS_OPERATION'],
    ['missing epoch', f => { delete f.plan.ownerCredentialRevision; }, 'INVALID_INGRESS_OPERATION'],
    ['credential drift', f => { f.state.secretRevision += 1; }, 'INGRESS_OWNER_CONFLICT'],
    ['topology drift', f => { f.state.appliedTopologyRevision += 1; }, 'INGRESS_OWNER_CONFLICT'],
    ['other path key', f => { f.state.activePathKey = 'peer'; }, 'INGRESS_OWNER_CONFLICT'],
    ['uninstalled state', f => { f.state.status = 'not_installed'; }, 'INGRESS_OWNER_CONFLICT'],
    ['changed old path', f => { f.snapshot.groups[0].paths[0].linkIds = ['other']; }, 'INGRESS_PATH_CONFLICT'],
    ['duplicate path', f => { f.snapshot.groups[0].paths.push({ ...f.snapshot.groups[0].paths[0] }); }, 'INGRESS_PATH_CONFLICT'],
    ['changed peer policy', f => { f.plan.effectiveTopology.groups[0].paths[1].priority += 1; }, 'INGRESS_PATH_CONFLICT'],
    ['changed group policy', f => { f.plan.effectiveTopology.groups[0].strategy = 'weighted'; }, 'INGRESS_PATH_CONFLICT'],
    ['disconnected suffix', f => { f.plan.effectiveTopology.links.find(link => link.id === 'new').source = 'b'; }, 'INVALID_INGRESS_OPERATION'],
    ['not a bridge', f => { f.plan.effectiveTopology.nodes.find(node => node.id === 'b').role = 'relay'; }, 'INVALID_INGRESS_OPERATION'],
]) {
    test(`owner preparation rejects ${label} before node transport`, async () => {
        const f = fixture(); change(f);
        await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }), { code });
        assert.ok(!f.calls.some(call => Array.isArray(call)));
    });
}

for (const [label, change] of [
    ['missing sync proof', f => { f.options.noSync = true; }],
    ['unsynced user', f => { f.users[0].syncStatus = 'pending'; }],
    ['applied mismatch', f => { f.users[0].appliedRevision = 40; }],
    ['wrong user count', f => { f.options.readback.managedUserCount = 0; }],
    ['stale credential during readback', f => { f.options.onReadback = () => { f.state.secretRevision += 1; }; }],
    ['owner changed during readback', f => { f.options.onReadback = () => { f.state.activePathKey = 'peer'; }; }],
]) {
    test(`source-less installed preparation retains PPP checks: ${label}`, async () => {
        const f = fixture(); change(f);
        await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }),
            { code: 'INGRESS_PPP_UNVERIFIED' });
    });
}

for (const [label, edit] of [
    ['direct rule', config => { config.routing.rules[0].outboundTag = 'direct'; }],
    ['renamed freedom outbound', config => { config.outbounds.find(out => out.tag === 'block').protocol = 'freedom'; }],
    ['missing ingress', config => { config.inbounds = []; }],
    ['wrong port', config => { config.inbounds[0].port += 1; }],
    ['conditional block', config => { config.routing.rules[0].domain = ['blocked.test']; }],
    ['duplicate ingress rule', config => { config.routing.rules.push({ ...config.routing.rules[0] }); }],
    ['preempting reverse domain', config => { config.routing.rules.push(config.routing.rules.shift()); }],
]) {
    test(`explicit no-exit rejects ${label} as blocking evidence before PPP/node work`, async () => {
        const f = fixture({ sourceLess: false, noExit: true }); rewriteCandidate(f.plan, edit);
        const plan = freeze(f.plan);
        assert.equal((await f.ingressGate.verifyPlan(plan)).ok, false);
        assert.equal((await f.pppGate.verifyPlan(plan)).ok, false);
        await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: plan }),
            { code: 'INVALID_INGRESS_OPERATION' });
        assert.ok(!f.calls.some(call => Array.isArray(call)));
    });
}

for (const [label, edit] of [
    ['inactive MAIN', f => { f.options.active = false; }],
    ['wrong MAIN port', f => { f.options.main.outbounds[0].settings.servers[0].port += 1; }],
    ['wrong MAIN routing', f => { f.options.main.routing.rules[0].outboundTag = 'direct'; }],
    ['duplicate MAIN inbound', f => { f.options.main.inbounds.push({ ...f.options.main.inbounds[0] }); }],
]) {
    test(`existing node ingress verification refuses ${label}`, async () => {
        const f = fixture(); edit(f);
        await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }),
            { code: 'INGRESS_UNVERIFIED' });
        assert.ok(!f.calls.some(call => call[0] === 'ppp'));
    });
}

test('ordinary apply/staged flags cannot authorize last-exit blocking success', async () => {
    const f = fixture({ noExit: true, sourceLess: false }); f.plan.kind = 'link.apply';
    assert.equal((await f.pppGate.verifyPlan(freeze(f.plan))).ok, false);
    await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: f.plan }),
        { code: 'INVALID_INGRESS_OPERATION' });
});

test('operation preparation refuses mutable or mixed draft-session requests and absent gates', async () => {
    const f = fixture();
    await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: f.plan }),
        { code: 'INVALID_INGRESS_OPERATION' });
    freeze(f.plan);
    await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: f.plan, session: {} }),
        { code: 'INVALID_INGRESS_OPERATION' });
    f.service.topologyIngressGate = undefined;
    await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: f.plan }),
        { code: 'INVALID_INGRESS_OPERATION' });
});

test('shared-group peer drift during node proof prevents a preparation receipt', async () => {
    const f = fixture(); f.options.onReadback = () => { f.snapshot.groups[0].paths[1].priority += 1; };
    await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }),
        { code: 'INGRESS_OWNER_CONFLICT' });
});

test('real user resync preserves subscription identity for installed changes and no-exit delete', async () => {
    const { TopologyUserResync } = require('../services/topologyUserResync');
    for (const noExit of [false, true]) {
        const f = fixture({ sourceLess: !noExit, noExit });
        const users = [{ userId: 'subscription-user', xrayUuid: 'synthetic-unchanged-uuid', flow: 'xtls-rprx-vision' }];
        const pushes = [];
        const resync = new TopologyUserResync({ HyNode: { findById: id => query(() => ({ _id: id, type: 'xray' })) },
            syncService: { async _getUsersForNode() { return structuredClone(users); },
                async addXrayUser(node, user) { pushes.push([node._id, user]); return true; } }, attempts: 1 });
        assert.equal((await resync.resyncPlan(freeze(f.plan))).ok, true);
        assert.deepEqual(pushes, f.plan.nodes.map(node => [node.node, users[0]]));
        assert.equal((await f.service.prepareConfiguredRelayIngress({ operationPlan: f.plan })).ingressPrepared, true);
    }
});

test('no-exit success never skips installed PPP sync/user readback checks', async () => {
    for (const change of [f => { f.options.noSync = true; },
        f => { f.users[0].appliedRevision = 40; },
        f => { f.options.readback.managedUserCount = 0; }]) {
        const f = fixture({ noExit: true, sourceLess: false }); change(f);
        await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }),
            { code: 'INGRESS_PPP_UNVERIFIED' });
    }
});

test('no-exit proof does not require a portal or a bridge, but still verifies its installed owner', async () => {
    const f = fixture({ noExit: true, sourceLess: false });
    f.plan.effectiveTopology.nodes = f.plan.effectiveTopology.nodes.filter(node => node.role === 'relay');
    f.plan.effectiveTopology.links = [];
    f.plan.nodes = f.plan.nodes.filter(node => node.role === 'relay');
    const result = await f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) });
    assert.equal(result.routeState, 'no_bridge_exit');
    assert.equal(result.pppInternetProof, 'not_applicable');
    assert.ok(f.calls.some(call => call[0] === 'ppp'));
});

test('malformed candidate JSON fails ingress evidence closed without node transport', async () => {
    const f = fixture();
    const relay = f.plan.nodes.find(node => node.node === 'r');
    relay.candidate = { ...relay.candidate, bytes: [...Buffer.from('null')] };
    assert.deepEqual(await f.ingressGate.verifyPlan(freeze(f.plan)), { ok: false });
    assert.ok(!f.calls.some(call => Array.isArray(call)));
});

test('an unchanged nonempty peer path and installed peer owner remain preservation-only', async () => {
    const f = fixture();
    const peer = { ...structuredClone(f.state), node: 'peer-r', activePathKey: 'peer', secretRevision: 17 };
    f.options.owners = [f.state, peer];
    const peerPath = f.snapshot.groups[0].paths[1];
    Object.assign(peerPath, { linkIds: ['peer-exit'], enabled: true });
    f.plan.effectiveTopology.groups[0].paths[1] = projectGroups(f.snapshot.groups)[0].paths[1];
    f.plan.effectiveTopology.nodes.push({ id: 'peer-r', role: 'relay' }, { id: 'peer-b', role: 'bridge' });
    f.plan.effectiveTopology.links.push({ id: 'peer-exit', source: 'peer-r', target: 'peer-b', mode: 'reverse', geo: false });
    // Only the changed component has candidates. This is service preservation
    // evidence, not acceptance of the separately owned multi-component composer.
    const before = structuredClone({ groups: f.snapshot.groups, owners: f.options.owners });
    assert.equal((await f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) })).ingressPrepared, true);
    assert.deepEqual({ groups: f.snapshot.groups, owners: f.options.owners }, before);
    assert.ok(!f.calls.some(call => call[0] === 'ingress-resolve' && call[1].nodeId === 'peer-r'));
});

test('duplicate installed owner/path bindings refuse before node work', async () => {
    const f = fixture(); f.options.owners = [f.state, { ...f.state, node: 'foreign-r' }];
    await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }),
        { code: 'INGRESS_OWNER_CONFLICT' });
    assert.ok(!f.calls.some(call => Array.isArray(call)));
});

test('PPP drift is handed back as the checked gate reason, not an automatic sync or install', async () => {
    const f = fixture(); f.users[0].appliedRevision = 40;
    await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }), error => {
        assert.deepEqual(error.pppReadiness, { ok: false, verifiedRelayCount: 0, reason: 'PPP_DRIFT',
            relayNode: 'r', credentialRevision: 41 });
        return error.code === 'INGRESS_PPP_UNVERIFIED';
    });
});

test('no-exit ingress refuses MAIN routes that bypass its SOCKS ingress', async () => {
    for (const rule of [
        { type: 'field', ip: ['203.0.113.0/24'], outboundTag: 'direct' },
        { type: 'field', inboundTag: ['relay-l2tp-g'], domain: ['bypass.example.test'], outboundTag: 'direct' },
    ]) {
        const f = fixture({ noExit: true, sourceLess: false });
        f.options.main.outbounds.push({ tag: 'direct', protocol: 'freedom' });
        f.options.main.routing.rules.unshift(rule);
        await assert.rejects(f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) }),
            { code: 'INGRESS_UNVERIFIED' });
        assert.ok(!f.calls.some(call => call[0] === 'ppp'));
    }
});

test('owner drift during a failed node readback is not sync-eligible PPP drift', async () => {
    const f = fixture();
    f.options.readback = { ok: false, code: 'MANAGED_USERS_MISSING', credentialRevision: 41,
        enabledUserCount: 1, managedUserCount: 0 };
    f.options.onReadback = () => { f.state.activePathKey = 'peer'; };
    assert.equal((await f.pppGate.verifyPlan(freeze(f.plan))).reason, 'PPP_UNKNOWN');
});

test('explicit no-exit can retain an applied relay prefix rather than require an empty after-graph', async () => {
    const f = fixture({ noExit: true, sourceLess: false });
    f.snapshot.groups[0].paths[0].linkIds = ['retained-hop', 'old'];
    f.plan.oldPathLinkIds = ['retained-hop', 'old'];
    f.plan.effectiveTopology.nodes.push({ id: 'transit', role: 'relay' });
    f.plan.effectiveTopology.links.push({ id: 'retained-hop', source: 'r', target: 'transit', mode: 'reverse', geo: false });
    // The owner candidate is blocked; the graph/composer slice separately owns
    // candidates/readback for the retained/detached transit profiles.
    assert.equal((await f.service.prepareConfiguredRelayIngress({ operationPlan: freeze(f.plan) })).routeState,
        'no_bridge_exit');
    assert.deepEqual(f.snapshot.groups[0].paths[0].linkIds, ['retained-hop', 'old']);
});

test('installed PPP refuses frozen credential drift even when the newest sync succeeded', async () => {
    const f = fixture();
    f.plan.ownerCredentialRevision = 40;
    assert.equal((await f.pppGate.verifyPlan(freeze(f.plan))).ok, false);
    assert.ok(!f.calls.some(call => call[0] === 'ppp'));
});
