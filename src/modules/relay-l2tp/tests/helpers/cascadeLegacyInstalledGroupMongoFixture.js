'use strict';
// REAL fresh Mongo persistence/transactions and public producers/consumers.
// MODELED pre-existing inventory and physical/SSH/systemd/Xray/PPP IO only.
// No module-loader override or disconnected/query-shaped database adapter.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { spawnSync, spawn } = require('node:child_process');
const mongoose = require('mongoose');
// Use the actual opt-in settings reader solely to keep logger IO in owned
// scratch; restore the harness env after its documented env replacement.
const harnessEnvironment = { ...process.env };
require('../../../../classicSettings');
Object.assign(process.env, harnessEnvironment);
const generator = require('../../../../services/configGenerator');
const { finishClassicConfigRouting } = require('../../../../services/classicL2tpConfigComposition');
const { buildL2tpXrayFragment } = require('../../services/l2tpXrayFragmentProvider');
const { projectGroups } = require('../../domain/topologyDraft');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../domain/topologyExecutionContext');
const { TopologyConfigTransfer } = require('../../../../services/topologyConfigTransfer');
const { fixture: mongoFixture } = require('./installedEditMongoFixture');
const id = n => n.toString(16).padStart(24, '0');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const copy = value => structuredClone(value);
const key = (node, profile) => `${node}:${profile}`;
const profileFor = node => node.role === 'portal' ? 'xray-main' : 'xray-bridge';
const { freeze, runnerRequest } = require('./topologyV2Fixture');
const { fakeRunner } = require('./topologyTerminalFakeRunner');
const { TopologyDraftRepository } = require('../../repositories/topologyDraftRepository');
const { TopologyDeploymentRepository } = require('../../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../../repositories/topologyOperationRepository');
const { TopologyOperationCoordinator } = require('../../services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../../services/topologyOperationPlanMaterializer');
const { TopologyOperationWorker } = require('../../workers/topologyOperationWorker');
const { TopologyOperationExecutor } = require('../../services/topologyOperationExecutor');
const { TopologyOperationFinalizer } = require('../../services/topologyOperationFinalizer');
const { TopologyOperationFinalizationRepository } = require('../../repositories/topologyOperationFinalizationRepository');
const { TopologyExecutionBindingStore } = require('../../repositories/topologyExecutionBindingStore');
const { TopologyExecutionAuthorityLifecycle } = require('../../runtime/topologyExecutionAuthorityLifecycle');
const { NodeOperationLockRepository } = require('../../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../../services/nodeOperationLockService');
const { TopologyIntentService, linkDesiredVersion } = require('../../services/topologyIntentService');
const { TopologyIntentConsumer } = require('../../services/topologyIntentConsumer');
const { TopologyAttachIngressGate } = require('../../services/topologyAttachIngressGate');
const { createTopologyPppReadinessGate } = require('../../services/topologyPppReadinessGate');
const { L2tpSimpleService } = require('../../services/l2tpSimpleService');
const { TopologyUserResync } = require('../../services/topologyUserResync');
function evidence(value) {
    if (process.env.C3_EVIDENCE_RUN) fs.appendFileSync(path.join(process.env.C3_EVIDENCE_RUN, 'lifecycle.jsonl'), JSON.stringify(value) + '\n');
}
const targets = { 'xray-main': { config: 'usr/local/etc/xray/config.json', unit: 'etc/systemd/system/xray.service', service: 'xray.service' },
    'xray-bridge': { config: 'usr/local/etc/xray-bridge/config.json', unit: 'etc/systemd/system/xray-bridge.service', service: 'xray-bridge.service' } };
const PRIVATE = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath';
const oid = value => new mongoose.Types.ObjectId(String(value));
// Generated canonical JSON may reorder object keys; arrays/order and values
// remain significant. Exact whole-profile/no-op checks still compare raw bytes.
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
const semanticHash = value => sha(JSON.stringify(canonical(value)));
function addUnrelated(config, index) {
    (config.inbounds ||= []).push({ tag: 'unrelated-client', port: 27000 + index, protocol: 'vless',
        settings: { decryption: 'none', clients: [{ id: '99999999-9999-4999-8999-999999999999', email: 'kept@invalid' }] } });
    config.outbounds.push({ tag: 'unrelated-out', protocol: 'freedom' });
    config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-client'], outboundTag: 'unrelated-out' });
    config.policy = { levels: { 0: { statsUserUplink: true } } };
    return config;
}
function legacyInventory(context = TEST) {
    const nodes = ['portal', 'relay', 'bridge'].map((role, i) => ({ id: id(i + 1), role, type: 'xray', active: true,
        ip: `192.0.2.${i + 1}`, port: 24443 + i,
        xray: { protocol: 'vless', security: 'none', transport: 'tcp', inboundTag: 'client-in', extraInbounds: [] } }));
    const links = nodes.slice(1).map((node, i) => ({ id: id(10 + i), source: nodes[i].id, target: node.id,
        mode: 'reverse', active: true, tunnelProtocol: 'vless', tunnelSecurity: 'none', tunnelTransport: 'tcp',
        tunnelPort: 25000 + i, tunnelUuid: `${i + 1}`.repeat(8) + '-1111-4111-8111-111111111111',
        tunnelDomain: 'legacy-group.invalid', priority: 1 }));
    const group = { _id: id(60), name: 'modeled-preexisting-group', mode: 'reverse', strategy: 'priority-failover',
        paths: [{ pathKey: 'legacy-main', linkIds: [links[1].id], priority: 4, enabled: true }] };
    const groups = projectGroups([group]), path = groups[0].paths[0];
    const metadata = node => ({ ...node, _id: node.id, cascadeRole: node.role });
    const populated = links.map(link => ({ ...link, _id: link.id,
        portalNode: metadata(nodes.find(node => node.id === link.source)),
        bridgeNode: metadata(nodes.find(node => node.id === link.target)) }));
    for (const [index, node] of nodes.entries()) {
        let config;
        if (node.role === 'portal') {
            config = JSON.parse(generator.generateXrayConfig(metadata(node), []));
            config.inbounds.find(row => row.tag === 'client-in').settings.clients.push({
                id: '88888888-8888-4888-8888-888888888888', email: 'legacy@invalid' });
            generator.applyReversePortal(config, [populated[0]], ['client-in']);
        } else if (node.role === 'relay') {
            // Match the REAL classic writer order. The fourth generator argument
            // would move ingress before IPv6 refusal and is NOT equivalent.
            config = JSON.parse(generator.generateRelayConfig(populated[0], populated[0].portalNode, [populated[1]]));
            generator.applyCascadePathIngress(config, [{ pathKey: path.pathKey, port: path.cascadePathIngress.port,
                egressTag: `portal-down-${links[1].id.slice(-8)}` }]);
            finishClassicConfigRouting(config);
        } else config = JSON.parse(generator.generateCombinedBridgeConfig([populated[1]]));
        node.profileConfig = JSON.stringify(addUnrelated(config, index), null, 2) + '\n';
    }
    const topology = { nodes, links, groups };
    // These state/users/sync rows are MODELED PRE-EXISTING LEGACY INVENTORY.
    // They are NOT generated by adoption or a fabricated topology settlement.
    const state = { _id: id(70), node: id(2), routeGroup: group._id, activePathKey: path.pathKey,
        status: 'installed', desiredState: 'installed', secretRevision: 41, appliedTopologyRevision: 7,
        pskEncrypted: 'synthetic-fixture-private-psk', clientCidr: '10.255.30.0/24', localAddress: '10.255.30.1',
        poolStart: '10.255.30.10', poolEnd: '10.255.30.250', dnsServers: ['1.1.1.1'],
        tproxyPort: 12345, fwmark: 100, routeTable: 100, mtu: 1400, mru: 1400 };
    const users = [{ _id: id(80), relayNode: id(2), login: 'synthetic-fixture-user', passwordEncrypted: 'synthetic-fixture-private',
        ip: '10.255.30.10', enabled: true, desiredRevision: 41, appliedRevision: 41, syncStatus: 'synced', syncOperationId: id(81) }];
    const syncFacts = [{ _id: id(81), node: id(2), kind: 'sync_users', status: 'succeeded',
        plan: { operationId: id(81), relayId: id(2), desired: { credentialRevision: 41 } } }];
    const physical = new Map();
    for (const [index, node] of nodes.entries()) {
        physical.set(key(node.id, profileFor(node)), { config: node.profileConfig, unit: `modeled-selected-unit-${index}\n`, active: 'active', enabled: 'enabled' });
        const other = profileFor(node) === 'xray-main' ? 'xray-bridge' : 'xray-main';
        const fragment = node.role !== 'relay' ? [] : [buildL2tpXrayFragment({
            plan: { relay: { controlPlaneIps: [node.ip] }, group: { id: group._id }, selectedPathKey: path.pathKey,
                paths: [{ pathKey: path.pathKey, healthy: true, outboundTag: path.cascadePathIngress.tag }] },
            tags: { inbound: `relay-l2tp-${group._id}`, blockOutbound: 'block' }, tproxyPort: state.tproxyPort })];
        const config = JSON.parse(generator.generateXrayConfig(metadata(node), [], { fragments: fragment }));
        config.inbounds.find(row => row.tag === 'client-in').settings.clients.push({
            id: '77777777-7777-4777-8777-777777777777', email: 'independent@invalid' });
        finishClassicConfigRouting(config);
        physical.set(key(node.id, other), { config: JSON.stringify(addUnrelated(config, 10 + index), null, 2) + '\n',
            unit: `modeled-independent-unit-${index}\n`, active: 'active', enabled: 'enabled' });
    }
    const desiredLinks = links.map(({ id: _id, source, target, ...rest }) =>
        ({ ...copy(rest), _id, portalNode: source, bridgeNode: target, status: 'online' }));
    const inventory = { label: 'MODELED_PREEXISTING_LEGACY_INVENTORY', groups: [group,
        { _id: id(61), name: 'unrelated-preserved-group', mode: 'reverse', strategy: 'priority-failover', paths: [] }],
        states: [state], users, syncFacts,
        nodes: nodes.map(({ id: _id, role: cascadeRole, profileConfig, ...rest }) => ({ ...copy(rest), _id, cascadeRole })),
        links: [...desiredLinks,
            { ...copy(desiredLinks[0]), _id: id(90), status: 'pending', tunnelPort: 25990 },
            { ...copy(desiredLinks[0]), _id: id(91), active: false, status: 'offline', tunnelPort: 25991 }] };
    return { context, topology, inventory, physical };
}

async function lifecycleFixture(t, mongo) {
    await mongo.reset();
    const f = legacyInventory();
    // Additional nonempty protected installation identity, fixed BEFORE models,
    // adoption, enrollment or native work. Still pre-existing modeled inventory.
    Object.assign(f.inventory.states[0], { managedVersion: 'MODELED-legacy-v1', configFingerprint: sha('MODELED-installed-L2TP'),
        backupId: 'MODELED-original-install-backup', operationId: id(82), installedAt: new Date('2026-01-01T00:00:00Z'),
        lastVerifiedAt: new Date('2026-01-02T00:00:00Z'), lastSyncAt: new Date('2026-01-03T00:00:00Z'), routingMode: 'route-group' });
    Object.assign(f, { fixtureId: randomUUID(), stage: 'construct', driverEvents: [], dispatches: [], children: [], options: { prepares: [], prepareErrors: [], gateCalls: [], userPushes: 0 } });
    const models = mongo.models;
    for (const Model of Object.values(models)) assert.ok(Model.db === mongo.connection, 'real same-connection model');
    await models.HyNode.create(f.inventory.nodes.map(row => ({ ...copy(row), name: 'MODELED-' + row.cascadeRole,
        ssh: { port: 22, username: 'synthetic', privateKey: 'MODELED-NOT-A-KEY' } })));
    await models.CascadeLink.create(f.inventory.links.map(row => ({ ...copy(row), name: 'MODELED-existing-link' })));
    await models.CascadeRouteGroup.create(f.inventory.groups);
    await models.RelayL2tpState.create(f.inventory.states);
    await models.L2tpUser.create(f.inventory.users);
    // Schema-valid sync fact belonging to MODELED PREEXISTING inventory only.
    await models.L2tpOperation.create(f.inventory.syncFacts.map(row => ({ ...copy(row), idempotencyKey: 'MODELED-preexisting-sync-41', plan: { ...row.plan, ok: true,
        steps: [{ type: 'backup' }, { type: 'sync_users', artifacts: [{ type: 'desired', path: 'desired.json' }] }, { type: 'verify_users' }] } })));
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 0, remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
    const data = async () => Object.fromEntries(await Promise.all(Object.entries(models).map(async ([name, Model]) =>
        [name, await Model.find({}).select(name === 'RelayL2tpState' ? '+pskEncrypted' : name === 'L2tpUser' ? '+passwordEncrypted'
            : name === 'TopologyConfigOwner' ? '+legacyAppliedTopology' : '').sort({ _id: 1 }).lean()])));
    const hosts = new Map();
    for (const [index, node] of f.topology.nodes.entries()) {
        const boot = randomUUID(), root = fakeRunner(t, boot), profile = profileFor(node);
        const host = { ...root, node, profile, boot, maintenance: randomUUID(),
            identity: freeze({ machineId: String(index + 1).repeat(32), sshHostKeySha256: String(index + 1).repeat(64) }),
            endpoint: freeze({ ip: node.ip, port: 22, username: 'synthetic' }) };
        hosts.set(node.id, host);
        for (const [name, target] of Object.entries(targets)) {
            const original = f.physical.get(key(node.id, name)); root.put(target.config, original.config); root.put(target.unit, original.unit);
        }
        root.put('services.json', JSON.stringify(Object.fromEntries(Object.values(targets).map((target, i) => [target.service,
            { active: 'active', enabled: 'enabled', restarts: 0, pid: 100 + index * 2 + i, start: `MODELED-initial-${index}-${i}` }]))));
        root.put('usr/bin/systemctl', `#!/usr/bin/python3
import os,sys,json
r=os.environ['CELERITY_TOPOLOGY_ROOT']; p=r+'/services.json'; s=json.load(open(p)); a=sys.argv[1:]; v=s[a[-1]]
if a[0]=='restart':
 v['restarts']+=1; v['pid']+=1000; v['start']='MODELED-restart-'+str(v['restarts']); v['active']='active'; json.dump(s,open(p,'w'))
elif a[0]=='stop': v['active']='inactive'; json.dump(s,open(p,'w'))
elif a[0]=='show': print('Job=\\nActiveState='+v['active']+'\\nSubState='+('running' if v['active']=='active' else 'dead'))
elif a[0]=='is-active': sys.exit(0 if v['active']=='active' else 3)
else: sys.exit(64)
`, 0o700);
        root.put('usr/bin/ss', `#!/usr/bin/python3
import os,sys,json
r=os.environ['CELERITY_TOPOLOGY_ROOT']; port=int(sys.argv[-1].split(':')[-1])
for d in ('xray','xray-bridge'):
 c=json.load(open(r+'/usr/local/etc/'+d+'/config.json'))
 if any(i.get('port')==port for i in c.get('inbounds',[])): print('LISTEN 0 128 127.0.0.1:'+str(port))
`, 0o700);
        host.execute = async (command, options = {}) => {
            const request = runnerRequest(command); f.dispatches.push({ node: node.id, command: request.command });
            const child = spawn('bash', [path.join(__dirname, '../../node-artifacts/topology/runner.sh'), ...command.split(' ').slice(1)], {
                env: { ...process.env, CELERITY_TOPOLOGY_ROOT: host.root }, stdio: ['pipe', 'pipe', 'pipe'] });
            const entry = { kind: 'typed-runner', pid: child.pid, root: host.root, closed: false,
                startTicks: fs.readFileSync(`/proc/${child.pid}/stat`, 'utf8').split(') ').at(-1).split(' ')[19] };
            f.children.push(entry);
            const result = await new Promise((resolve, reject) => {
                let stdout = '', stderr = '';
                child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
                child.once('error', reject); child.once('close', (code, signal) => {
                    Object.assign(entry, { code, signal, closed: true, pidAbsent: !fs.existsSync(`/proc/${child.pid}`) });
                    evidence({ fixtureId: f.fixtureId, stage: 'child-reaped', ...entry }); resolve({ code, stdout, stderr });
                });
                child.stdin.end(options.stdin);
            });
            assert.equal(entry.pidAbsent, true); return result;
        };
    }
    const readPhysical = (nodeId, profile) => {
        const host = hosts.get(nodeId), target = targets[profile], file = path.join(host.root, target.config);
        return { config: fs.readFileSync(file, 'utf8'), inode: fs.statSync(file).ino,
            unit: fs.readFileSync(path.join(host.root, target.unit), 'utf8'),
            ...JSON.parse(fs.readFileSync(path.join(host.root, 'services.json')))[target.service] };
    };
    const transfer = new TopologyConfigTransfer({ executionContext: f.context, TopologyConfigOwner: models.TopologyConfigOwner,
        async withVerifiedMaintenance({ binding }, work) {
            const observed = readPhysical(binding.node, binding.profile);
            return work({ status: 'verified', authority: 'external-maintenance-v1', binding: copy(binding),
                proofId: randomUUID(), maintenanceId: hosts.get(binding.node).maintenance, maintenance: 'held', allWriters: 'drained',
                oldBackend: { instanceId: 'MODELED-legacy', pid: 42, processStartTime: 'MODELED-start', processTree: 'stopped', dispatch: 'disabled' },
                readback: { source: 'node-readback', configSha256: sha(observed.config), unitSha256: sha(observed.unit),
                    serviceActive: observed.active, serviceEnabled: observed.enabled } });
        } });
    const adopt = async (node, proposed = f.topology) => {
        const host = hosts.get(node.id);
        const classic = await transfer.initializeClassic({ node: node.id, profile: host.profile, nodeIdentity: host.identity });
        return transfer.adopt({ node: node.id, profile: host.profile, generation: classic.generation,
            proofRef: 'MODELED-preexisting-legacy-readback', legacyTopology: proposed });
    };
    let held = false;
    const assertHeld = async () => assert.equal(held, true, 'explicit modeled external hold across worker');
    const authority = async (challenge, work) => {
        await assertHeld(); const host = hosts.get(challenge.enrollment.nodeId); assert.ok(host);
        assert.equal(challenge.enrollment.targetProfile, host.profile);
        let predecessor;
        const journalPath = path.join(host.root, `var/lib/celerity/topology/fences/${host.profile}/journal.json`);
        if (challenge.predecessor) {
            const previous = await models.TopologyExecutionBinding.findById(challenge.predecessor.bindingId).lean();
            const journal = JSON.parse(fs.readFileSync(journalPath));
            const generation = journal.generations[previous.generation]; assert.equal(generation.phase, 'closed');
            const receipt = Object.values(generation.commands).find(item => item.command === 'close').receipt;
            const parts = ['runner', '--command', 'status'];
            for (const [k, flag] of Object.entries({ operationId: 'operation-id', nodeId: 'node-id', candidateHash: 'candidate-hash', backupId: 'backup-id',
                targetProfile: 'target-profile', executionContext: 'execution-context', attemptId: 'attempt-id', generation: 'generation', predecessorGeneration: 'predecessor-generation' })) parts.push('--' + flag, receipt[k]);
            parts.push('--command-id', receipt.commandId); const actual = await host.execute(parts.join(' ')); assert.equal(actual.code, 0);
            predecessor = { bindingId: previous._id, generation: receipt.generation, headGeneration: journal.head, bootId: host.boot, status: 'terminal', receipt: JSON.parse(actual.stdout) };
        } else if (challenge.action === 'enroll') {
            assert.equal(fs.existsSync(journalPath), false);
            predecessor = { generation: 'none', bootId: host.boot, status: 'empty', protocolVersion: 2, journal: 'absent', legacyState: 'absent', writers: 'excluded' };
        } else predecessor = { generation: 'none', bootId: host.boot, status: 'pre-enrolled' };
        const result = await work({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge: copy(challenge), proofId: randomUUID(),
            maintenanceId: host.maintenance, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded', physicalIdentity: copy(host.identity), owner: 'topology',
            oldBackend: { instanceId: 'MODELED-legacy', pid: 42, processStartTime: 'MODELED-start', processTree: 'stopped', dispatch: 'disabled' }, predecessor,
            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: copy(host.endpoint), physicalIdentity: copy(host.identity),
                maintenanceId: host.maintenance, aliases: 'excluded', hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' } });
        await assertHeld(); return result;
    };
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: f.context, controller: { executionContext: f.context,
        async withHeldAuthority(context, work) { assert.equal(held, false); held = true;
            try { return await work({ assertHeld, withVerifiedAuthority: authority }); } finally { held = false; } } } });
    const store = new TopologyExecutionBindingStore({ executionContext: f.context, Operation: models.TopologyOperation, Lock: models.NodeOperationLock,
        Owner: models.TopologyConfigOwner, Enrollment: models.TopologyExecutionEnrollment, Binding: models.TopologyExecutionBinding, HyNode: models.HyNode,
        withVerifiedAuthority: (challenge, work) => lifecycle.withVerifiedAuthority(challenge, work), assertAuthorityHeld: () => lifecycle.assertHeld() });
    const executor = new TopologyOperationExecutor({ ...f.context, executionBindingReader: store,
        RunnerBootstrapper: class { async ensureRunner() { await lifecycle.assertHeld(); } },
        nodeExecutionResolver: { async resolve({ nodeId }, connection) { const host = hosts.get(nodeId); assert.ok(host);
            assert.equal(sha(JSON.stringify(connection)), sha(JSON.stringify({ expectedEndpoint: host.endpoint, expectedHostKeySha256: host.identity.sshHostKeySha256 })));
            return { exec: async (command, options) => { await lifecycle.assertHeld(); return host.execute(command, options); },
                writeFile: async () => assert.fail('No bootstrap/upload permitted in preinstalled modeled fixture') }; } } });
    const draft = new TopologyDraftRepository(models);
    const deployment = new TopologyDeploymentRepository({ ...models, snapshotReader: draft });
    const operations = new TopologyOperationRepository({ model: models.TopologyOperation, topologyStateModel: models.CascadeTopologyState, selectedTopologyRepository: deployment });
    const coordinator = new TopologyOperationCoordinator({ executionContext: f.context, topologyRepository: deployment,
        operationRepository: operations, planMaterializer: new TopologyOperationPlanMaterializer(models) });
    const ingress = new TopologyAttachIngressGate({ nodeExecutionResolver: { async resolve() { return {
        async connect() {}, disconnect() {}, async exec(command, options) {
            assert.equal(command, 'python3 -'); f.options.gateCalls.push('MAIN');
            const observed = readPhysical(id(2), 'xray-main');
            const main = JSON.parse(observed.config);
            const setup = `import builtins,io,subprocess\nbuiltins.open=lambda *a,**k:io.StringIO(${JSON.stringify(JSON.stringify(main))})\nsubprocess.run=lambda *a,**k:type('R',(),{'returncode':${observed.active === 'active' ? 0 : 3},'stdout':'active\\n','stderr':''})()\n`;
            if (f.options.unreadableMain) return { code: 65, stdout: '', stderr: '' };
            const result = spawnSync('python3', ['-'], { input: setup + options.stdin, encoding: 'utf8', timeout: 10000 });
            f.children.push({ kind: 'MAIN-python', code: result.status, signal: result.signal });
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        } }; } } });
    // Independent pre-existing modeled PPP node fact, never derived from a
    // later desired/user/state row or the request's expected credential epoch.
    const pppNode = freeze({ credentialRevision: 41, enabledUserCount: 1, managedUserCount: 1 });
    const ppp = createTopologyPppReadinessGate({ ...models, executionContext: f.context, readOnly: true,
        NodeSSH: class { async exec(command) {
            assert.match(command, /verify-users/); f.options.gateCalls.push('PPP');
            await f.options.onPpp?.();
            return { code: f.options.unreadablePpp ? 65 : 0, stderr: '', stdout: JSON.stringify({ ok: true, code: 'USERS_VERIFIED', ...pppNode,
                ...(f.options.wrongCredential ? { credentialRevision: 42 } : {}), ...(f.options.wrongUsers ? { managedUserCount: 0 } : {}) }) + '\n' };
        } } });
    const forbidden = () => assert.fail('Forbidden migration install/configure/user/PSK mutation or repair-sync');
    const service = new L2tpSimpleService({ ...models, allowRemoteExecution: true, topologyIngressGate: ingress, topologyPppReadinessGate: ppp,
        l2tpService: { install: forbidden, getOperation: forbidden }, stateManagementService: { configureRelay: forbidden, revealPsk: forbidden },
        userManagementService: { createUser: forbidden, deleteUser: forbidden, importUser: forbidden }, stateRepository: { getTopologyRevision: forbidden }, nodeSSHFactory: forbidden });
    const clock = { now: () => new Date() };
    const finalization = new TopologyOperationFinalizationRepository({ ...models, selectedTopologyRepository: deployment });
    const worker = new TopologyOperationWorker({ executionContext: f.context, operationRepository: operations, executor,
        selectedTopologyRepository: deployment, bindingProvisioner: store, bindingLifecycle: lifecycle, allowUnprovenTestExecution: false,
        workerId: 'real-Mongo-installed-group-worker', leaseMs: 120000, clock,
        lockService: new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model: models.NodeOperationLock }), clock }),
        finalizer: new TopologyOperationFinalizer({ repository: finalization, clock }),
        userResync: new TopologyUserResync({ HyNode: models.HyNode, attempts: 1, syncService: {
            async _getUsersForNode(node) {
                await lifecycle.assertHeld();
                const accepted = JSON.parse(originals.physical.get(key(String(node._id), 'xray-main')).config);
                return accepted.inbounds.filter(item => item.tag === 'client-in').flatMap(item => item.settings.clients)
                    .map(item => ({ xrayUuid: item.id, userId: item.email }));
            },
            async addXrayUser(node, user) {
                await lifecycle.assertHeld(); f.options.userPushes++;
                const current = JSON.parse(readPhysical(String(node._id), 'xray-main').config);
                return current.inbounds.flatMap(item => item.settings?.clients || []).some(item => item.id === user.xrayUuid && item.email === user.userId);
            },
        } }),
        pppReadinessGate: ppp,
        installedIngressPreparer: async ({ operationPlan }) => { await lifecycle.assertHeld(); f.stage = 'installed-prepare';
            const published = (await data()).CascadeRouteGroup.find(group => String(group._id) === operationPlan.groupId);
            assert.deepEqual(published.paths.find(p => p.pathKey === operationPlan.pathKey).linkIds.map(String), operationPlan.oldPathLinkIds, 'no path publication before actual MAIN/PPP readiness');
            assert.equal((await data()).RelayL2tpState[0].appliedTopologyRevision, operationPlan.ownerTopologyRevision);
            try { const proof = await service.prepareConfiguredRelayIngress({ operationPlan }); f.options.prepares.push(proof); await f.options.afterPrepare?.(); return proof; }
            catch (error) { f.options.prepareErrors.push(error.code || 'UNKNOWN'); throw error; } } });
    const dependencies = { ...models, executionContext: f.context,
        intentDraftWriter: draft.createIntentDraftWriter({ selectedTopologyRepository: deployment }),
        deleteIntentWriter: require('../../../../models/cascadeLinkModel').createDeleteIntentWriter({ CascadeLink: models.CascadeLink }),
        intentOperationAdmission: { db: mongo.connection, queue: input => coordinator.queueIntent(input) },
        resolveIntentResources: input => coordinator.resolveIntentResourcesForQueue(input) };
    const freshIntentService = () => new TopologyIntentService(dependencies);
    const consumer = new TopologyIntentConsumer(dependencies);
    const revision = async () => (await models.CascadeTopologyState.findById('singleton').lean()).revision;
    const operation = value => models.TopologyOperation.findById(value).select(PRIVATE).lean();
    const protectedState = row => Object.fromEntries(Object.entries(row).filter(([k]) => !['appliedTopologyRevision', 'replacementFence', 'updatedAt'].includes(k)));
    const originals = { physical: new Map([...hosts].flatMap(([nodeId]) => Object.keys(targets).map(p => [key(nodeId, p), readPhysical(nodeId, p)]))),
        state: sha(JSON.stringify(protectedState((await data()).RelayL2tpState[0]))), users: sha(JSON.stringify((await data()).L2tpUser)), sync: sha(JSON.stringify((await data()).L2tpOperation)),
        otherGroup: sha(JSON.stringify((await data()).CascadeRouteGroup[1])),
        unrelatedLinks: sha(JSON.stringify((await data()).CascadeLink.filter(row => [id(90), id(91)].includes(String(row._id))))),
        groupPolicy: semanticHash(require('../../domain/topologyDraft').projectGroups([(await data()).CascadeRouteGroup[0]])
            .map(group => ({ ...group, paths: group.paths.map(p => ({ ...p, linkIds: [] })) }))), import: null };
    const physicalFingerprint = () => sha(JSON.stringify([...hosts].map(([nodeId, host]) => [nodeId, readPhysical(nodeId, host.profile)])));
    const assertPreserved = async () => {
        assert.equal(sha(JSON.stringify(protectedState((await data()).RelayL2tpState[0]))), originals.state, 'all protected installed-state fields preserved');
        assert.equal(sha(JSON.stringify((await data()).L2tpUser)), originals.users, 'entire PPP identities/password/IP/enabled/revisions membership preserved');
        assert.equal(sha(JSON.stringify((await data()).L2tpOperation)), originals.sync, 'no repair-sync or invented successful sync');
        assert.equal(sha(JSON.stringify((await data()).CascadeRouteGroup[1])), originals.otherGroup, 'unrelated group preserved');
        assert.equal(sha(JSON.stringify((await data()).CascadeLink.filter(row => [id(90), id(91)].includes(String(row._id))))), originals.unrelatedLinks, 'pending/inactive save-only neighbors unchanged');
        assert.equal(semanticHash(require('../../domain/topologyDraft').projectGroups([(await data()).CascadeRouteGroup[0]])
            .map(group => ({ ...group, paths: group.paths.map(p => ({ ...p, linkIds: [] })) }))), originals.groupPolicy, 'G/K/mode/strategy/priority/enable/ingress identity preserved');
        assert.equal(sha(JSON.stringify((await data()).TopologyConfigOwner.map(row => ({ generation: row.generation, originalSnapshot: row.originalSnapshot,
            adoptionReceipt: row.adoptionReceipt, legacyAppliedTopology: row.legacyAppliedTopology })))), originals.import, 'original import/receipt/generation immutable');
        for (const [nodeId, host] of hosts) for (const profile of Object.keys(targets)) {
            const actual = readPhysical(nodeId, profile), old = originals.physical.get(key(nodeId, profile));
            assert.equal(sha(actual.unit), sha(old.unit)); assert.equal(actual.active, old.active); assert.equal(actual.enabled, old.enabled);
            if (profile !== host.profile) assert.equal(sha(JSON.stringify(actual)), sha(JSON.stringify(old)), 'nonempty independent profile bytes/inode/service state unchanged');
            else {
                const a = JSON.parse(actual.config), b = JSON.parse(old.config);
                for (const section of ['inbounds', 'outbounds']) assert.equal(semanticHash(a[section].filter(item => item.tag?.startsWith('unrelated-'))), semanticHash(b[section].filter(item => item.tag?.startsWith('unrelated-'))));
                assert.equal(semanticHash(a.policy), semanticHash(b.policy));
                assert.equal(semanticHash(a.routing.rules.filter(item => item.inboundTag?.includes('unrelated-client'))), semanticHash(b.routing.rules.filter(item => item.inboundTag?.includes('unrelated-client'))));
                if (host.node.role === 'portal') assert.equal(semanticHash(a.inbounds.find(item => item.tag === 'client-in').settings.clients), semanticHash(b.inbounds.find(item => item.tag === 'client-in').settings.clients));
            }
        }
        evidence({ fixtureId: f.fixtureId, stage: 'preservation-verified', protectedStateSha256: originals.state,
            protectedUsersSha256: originals.users, preexistingSyncSha256: originals.sync, immutableImportSha256: originals.import,
            unrelatedGroupSha256: originals.otherGroup, groupPolicySha256: originals.groupPolicy,
            selectedPhysicalSha256: physicalFingerprint(), independentProfilesUnchanged: true });
    };
    const read = async linkId => {
        const connection = await mongoose.createConnection(mongo.connection.getClient().s.url, { maxPoolSize: 2,
            serverSelectionTimeoutMS: 5000, autoCreate: false, autoIndex: false }).asPromise();
        try {
            const freshModels = Object.fromEntries(Object.entries(models).map(([name, Model]) =>
                [name, connection.model(name, Model.schema.clone(), Model.collection.name)]));
            const snapshotReader = new TopologyDraftRepository(freshModels);
            return await new TopologyDeploymentRepository({ ...freshModels, snapshotReader })
                .readSelected({ snapshot: await snapshotReader.readDraft(), scope: { kind: 'link.apply', linkId }, executionContext: f.context });
        } finally { await connection.close(); }
    };
    const assertFresh = async (linkId, links, suffix) => {
        f.stage = 'fresh-reader'; const selected = await read(linkId);
        assert.deepEqual(selected.baselineTopology.links.map(item => item.id).sort(), [...links].sort());
        assert.deepEqual(selected.baselineTopology.groups[0].paths[0].linkIds, suffix);
        for (const node of selected.baselineTopology.nodes) assert.equal(sha(node.profileConfig), sha(readPhysical(node.id, profileFor(node)).config), 'fresh reader uses actual committed candidate, not historical import');
        evidence({ fixtureId: f.fixtureId, stage: 'fresh-read-verified', linkIds: [...links].sort(), suffix, routeState: selected.routeState,
            profileHashes: selected.baselineTopology.nodes.map(node => ({ node: node.id, sha256: sha(node.profileConfig) })) });
    };
    t.after(() => {
        const rootsAbsent = [...hosts.values()].every(host => !fs.existsSync(host.root));
        assert.equal(rootsAbsent, true, 'all exact owned fake roots removed by fixture cleanup');
        assert.ok(f.children.every(child => Number.isInteger(child.code) && child.signal === null), 'all owned finite children naturally exited');
        evidence({ fixtureId: f.fixtureId, stage: 'cleanup', rootsAbsent, childCount: f.children.length, listenersCreated: 0 });
    });
    return Object.assign(f, { data, mongo, finalization, deployment, draft, transfer, adopt, models, hosts, readPhysical, store, worker, coordinator, consumer, dependencies, freshIntentService, operation, read,
        physicalFingerprint, assertPreserved, assertFresh,
        corruptMain(change) { const host = hosts.get(id(2)), config = JSON.parse(readPhysical(id(2), 'xray-main').config); change(config);
            fs.writeFileSync(path.join(host.root, targets['xray-main'].config), JSON.stringify(config)); },
        deactivateMain() { const host = hosts.get(id(2)), file = path.join(host.root, 'services.json'), services = JSON.parse(fs.readFileSync(file));
            services['xray.service'].active = 'inactive'; fs.writeFileSync(file, JSON.stringify(services)); },
        async adoptAndEnroll() {
            f.stage = 'public-adopt'; for (const node of f.topology.nodes) await adopt(node);
            originals.import = sha(JSON.stringify((await data()).TopologyConfigOwner.map(row => ({ generation: row.generation, originalSnapshot: row.originalSnapshot,
                adoptionReceipt: row.adoptionReceipt, legacyAppliedTopology: row.legacyAppliedTopology }))));
            f.stage = 'public-preEnroll'; await lifecycle.run(async () => { for (const host of hosts.values()) {
                const owner = await models.TopologyConfigOwner.findOne({ node: host.node.id, profile: host.profile }).lean();
                await store.preEnroll(freeze({ nodeId: host.node.id, targetProfile: host.profile, endpoint: host.endpoint, nodeIdentity: host.identity,
                    ownerGeneration: owner.generation, predecessorGeneration: 'none', bootId: host.boot }));
            } });
        },
        async assertInitial() {
            assert.equal(f.inventory.label, 'MODELED_PREEXISTING_LEGACY_INVENTORY'); assert.equal((await data()).TopologyOperation.length, 0);
            assert.equal((await data()).TopologyConfigOwner.every(row => row.lastSettledOperation === undefined), true);
            assert.equal(f.dispatches.length, 0); assert.equal((await data()).NodeOperationLock.length, 0);
            assert.equal((await data()).TopologyExecutionEnrollment.length, 3);
            const main = JSON.parse(readPhysical(id(2), 'xray-main').config), tag = `relay-l2tp-${id(60)}`;
            const guard = main.routing.rules.findIndex(rule => rule.inboundTag?.includes(tag) && rule.ip?.includes('geoip:private') && rule.outboundTag === 'block');
            const route = main.routing.rules.findIndex(rule => rule.inboundTag?.includes(tag) && rule.outboundTag === 'cascade-legacy-main');
            assert.ok(guard >= 0 && route > guard, 'real generated MAIN retains scoped private-network refusal before L2TP-to-SOCKS route');
            for (const host of hosts.values()) for (const profile of Object.keys(targets)) {
                const config = JSON.parse(readPhysical(host.node.id, profile).config);
                assert.ok(config.inbounds.length && config.outbounds.length, 'every selected and independent profile is nonempty at import');
            }
            const selected = await read(id(11)); assert.deepEqual(selected.baselineTopology, f.topology);
            assert.deepEqual(selected.installedPath.oldPathLinkIds, [id(11)]); await assertPreserved();
        },
        async advanceRevision() { const rev = await revision(); await models.CascadeTopologyState.updateOne({ _id: 'singleton', revision: rev }, { $inc: { revision: 1 } }); assert.equal(await revision(), rev + 1); },
        async request(kind, linkId, requestKey) { const link = await models.CascadeLink.findById(linkId).lean(); assert.ok(link); return {
            version: 2, kind, expectedTopologyRevision: await revision(), requestKey, linkId, desiredVersion: linkDesiredVersion(link) }; },
        async createRequest(oldId, requestKey) {
            const old = f.inventory.links.find(row => row._id === oldId); assert.ok(old);
            const { _id, status, ...link } = copy(old); link.tunnelPort += 100; link.name = 'C-public-new-link';
            return { version: 2, kind: 'link.create', expectedTopologyRevision: await revision(), requestKey, link };
        },
        async accept(input) { f.stage = 'public-intent-accept'; return freshIntentService().accept(input); },
        async consume(job) {
            f.stage = 'durable-claim'; const claimed = await consumer.claim(); assert.equal(String(claimed?._id), job.jobId);
            f.stage = 'selected-admission'; const queued = await consumer.consumeVersioned(claimed);
            f.stage = 'actual-worker'; const result = await worker.run(queued.operationId); f.lastResult = result;
            const completed = await operation(queued.operationId);
            evidence({ fixtureId: f.fixtureId, stage: 'worker-result', publicKind: job.kind, linkId: job.linkId,
                operationId: String(completed._id), result, operationStatus: completed.status, heldTopologyAdmission: completed.heldTopologyAdmission,
                lockCount: (await data()).NodeOperationLock.length, currentSuffix: (await data()).CascadeRouteGroup[0].paths[0].linkIds.map(String),
                topologyEpoch: (await data()).RelayL2tpState[0].appliedTopologyRevision, credentialEpoch: (await data()).RelayL2tpState[0].secretRevision,
                prepareErrors: [...f.options.prepareErrors], gateCalls: [...f.options.gateCalls], userPushes: f.options.userPushes,
                terminalState: completed.v2Terminal?.state, terminalProofCount: completed.v2Terminal?.proofs?.length || 0,
                candidates: completed.nodes.map(node => ({ node: String(node.node), profile: node.targetProfile, sha256: node.candidateHash, state: node.state })) });
            if (result.status === 'succeeded') { assert.equal(await consumer.settle(await models.TopologyCreateIntent.findById(job.jobId).lean()), true);
                assert.equal((await freshIntentService().get(job.jobId)).status, 'succeeded'); }
            return completed;
        },
        assertBlocked() { const config = JSON.parse(readPhysical(id(2), 'xray-bridge').config), tag = 'cascade-legacy-main';
            assert.equal(config.inbounds.filter(i => i.tag === tag).length, 1);
            assert.deepEqual(config.routing.rules.filter(r => r.inboundTag?.includes(tag)), [{ type: 'field', inboundTag: [tag], outboundTag: 'block' }]);
            const index = config.routing.rules.findIndex(r => r.inboundTag?.includes(tag));
            assert.equal(config.routing.rules.slice(0, index).some(r => !r.inboundTag && r.outboundTag?.startsWith('tunnel-')), false);
        },
        assertSuffix() { const config = JSON.parse(readPhysical(id(2), 'xray-bridge').config);
            const rules = config.routing.rules.filter(r => r.inboundTag?.includes('cascade-legacy-main')); assert.ok(rules.length);
            assert.notEqual(rules.at(-1).outboundTag, 'block'); assert.notEqual(rules.at(-1).outboundTag, 'direct'); },
        assertRetired(linkId, port) { for (const host of hosts.values()) {
            const config = JSON.parse(readPhysical(host.node.id, host.profile).config);
            assert.equal(config.inbounds.some(i => i.port === port), false);
            assert.equal(JSON.stringify(config).includes(linkId.slice(-8)), false, 'retired tunnel/tag/domain absent');
        } },
    });
}
module.exports = { lifecycleFixture, mongoFixture, id, sha, evidence };
