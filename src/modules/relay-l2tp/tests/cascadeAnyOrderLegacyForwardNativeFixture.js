'use strict';
// Real Mongo/models/public producers and real path-rebased runner. ONLY the
// external exclusion, SSH, Xray validation/runtime users, listeners and systemd
// are MODELED; real user-resync logic consumes independent original clients.
// No physical controller, real Xray/client traffic or production authority.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { forwardFixture, generator, context, copy, sha, targets, freeze } = require('./cascadeAnyOrderLegacyForwardFixture');
const { fixture: mongoFixture } = require('./helpers/installedEditMongoFixture');
const { fakeRunner } = require('./helpers/topologyTerminalFakeRunner');
const { runnerRequest } = require('./helpers/topologyV2Fixture');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
const { TopologyNodeExecutionResolver } = require('../services/topologyNodeExecutionResolver');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const { TopologyIntentService, linkDesiredVersion } = require('../services/topologyIntentService');
const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
const { prepareIntentLink } = require('../../../routes/cascadeLinks');
const PRIVATE_OPERATION = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath';
const oldBackend = freeze({ instanceId: 'MODELED-classic', pid: 42, processStartTime: 'MODELED-start', processTree: 'stopped', dispatch: 'disabled' });
const startTicks = pid => fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ').at(-1).split(' ')[19];
function evidence(name, value) {
    if (process.env.C3_FORWARD_NATIVE_EVIDENCE) {
        fs.mkdirSync(process.env.C3_FORWARD_NATIVE_EVIDENCE, { recursive: true });
        fs.appendFileSync(path.join(process.env.C3_FORWARD_NATIVE_EVIDENCE, `${name}.jsonl`), JSON.stringify(value) + '\n');
    }
}
function layout(mode = 'reverse', security = 'none') {
    const f = forwardFixture(security);
    if (mode === 'reverse') {
        f.link.mode = 'reverse'; f.link.tunnelDomain = 'native-control.invalid';
        const populated = { ...copy(f.link), _id: f.link.id,
            portalNode: { ...copy(f.nodes[0]), _id: f.nodes[0].id },
            bridgeNode: { ...copy(f.nodes[1]), _id: f.nodes[1].id } };
        for (const node of f.nodes) {
            let config;
            if (node.role === 'portal') {
                config = copy(f.bases.get(node.id)); generator.applyReversePortal(config, [populated], ['client-in']);
            } else {
                config = JSON.parse(generator.generateCombinedBridgeConfig([populated]));
                const base = f.bases.get(node.id);
                config.inbounds ||= [];
                config.inbounds.push(copy(base.inbounds.find(item => item.tag === 'unrelated-ingress')));
                config.outbounds.push(copy(base.outbounds.find(item => item.tag === 'unrelated-out')));
                config.routing.rules.push(copy(base.routing.rules.find(item => item.outboundTag === 'unrelated-out')));
                config.policy = copy(base.policy);
            }
            node.profileConfig = JSON.stringify(config, null, 2) + '\n';
        }
    }
    return f;
}
async function nativeFixture(t, mongo, { mode = 'reverse', security = 'none' } = {}) {
    await mongo.reset();
    const models = mongo.models, f = layout(mode, security), hosts = new Map(), events = [], children = [];
    const profileFor = node => mode === 'forward' || node.role === 'portal' ? 'xray-main' : 'xray-bridge';
    const readProfile = (host, profile) => {
        const target = targets[profile];
        return { config: fs.readFileSync(path.join(host.root, target.configPath), 'utf8'),
            unit: fs.readFileSync(path.join(host.root, target.serviceUnitPath), 'utf8'),
            ...JSON.parse(fs.readFileSync(path.join(host.root, 'services.json')))[target.serviceUnit] };
    };
    for (const [index, node] of f.nodes.entries()) {
        const boot = randomUUID(), runner = fakeRunner(t, boot);
        const host = { ...runner, boot, node, profile: profileFor(node),
            identity: freeze({ machineId: String(index + 1).repeat(32), sshHostKeySha256: String(index + 1).repeat(64) }),
            endpoint: freeze({ ip: node.ip, port: 22, username: 'synthetic' }), maintenance: randomUUID() };
        hosts.set(node.id, host);
        for (const profile of Object.keys(targets)) {
            const state = copy(f.physical.get(`${node.id}:${profile}`));
            if (profile === host.profile) state.config = node.profileConfig;
            runner.put(targets[profile].configPath, state.config);
            runner.put(targets[profile].serviceUnitPath, state.unit);
        }
        runner.put('services.json', JSON.stringify(Object.fromEntries(Object.values(targets).map(target => [target.serviceUnit,
            { active: 'active', enabled: 'enabled', restarts: 0 }]))));
        runner.put('usr/bin/systemctl', `#!/usr/bin/python3
import os,sys,json
r=os.environ['CELERITY_TOPOLOGY_ROOT']; p=r+'/services.json'; s=json.load(open(p)); a=sys.argv[1:]; unit=a[-1]
with open(r+'/systemctl.log','a') as log: log.write(' '.join(a)+'\\n')
v=s[unit]
if a[0]=='restart': v['restarts']+=1; v['active']='active'; json.dump(s,open(p,'w'))
elif a[0]=='stop': v['active']='inactive'; json.dump(s,open(p,'w'))
elif a[0]=='show': print('Job=\\nActiveState='+v['active']+'\\nSubState='+('running' if v['active']=='active' else 'dead'))
elif a[0]=='is-active': sys.exit(0 if v['active']=='active' else 3)
else: sys.exit(64)
`, 0o700);
        runner.put('usr/bin/ss', `#!/usr/bin/python3
import os,sys,json
r=os.environ['CELERITY_TOPOLOGY_ROOT']; port=int(sys.argv[-1].split(':')[-1]); s=json.load(open(r+'/services.json'))
for d,u in [('xray','xray.service'),('xray-bridge','xray-bridge.service')]:
 if s[u]['active']=='active':
  c=json.load(open(r+'/usr/local/etc/'+d+'/config.json'))
  if any(i.get('port')==port for i in c['inbounds']): print('LISTEN 0 128 127.0.0.1:'+str(port))
`, 0o700);
        host.original = Object.fromEntries(Object.keys(targets).map(profile => [profile, readProfile(host, profile)]));
        for (const state of Object.values(host.original)) {
            const config = JSON.parse(state.config); assert.ok(config.inbounds.length); assert.ok(config.outbounds.length);
        }
        // Use the existing runner bytes, but register/reap every async direct child.
        host.execute = async (command, options = {}) => {
            const child = spawn('bash', [path.join(__dirname, '../node-artifacts/topology/runner.sh'), ...command.split(' ').slice(1)], {
                env: { ...process.env, CELERITY_TOPOLOGY_ROOT: host.root }, stdio: ['pipe', 'pipe', 'pipe'] });
            const entry = { pid: child.pid, root: host.root, closed: false, startTicks: null };
            children.push(entry);
            const complete = new Promise((resolve, reject) => {
                let stdout = '', stderr = '';
                child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
                child.once('error', reject);
                child.once('close', (code, signal) => {
                    Object.assign(entry, { code, signal, closed: true, pidAbsent: !fs.existsSync(`/proc/${entry.pid}`) });
                    evidence('runner-processes', entry); resolve({ code, stdout, stderr });
                });
            });
            try { entry.startTicks = startTicks(child.pid); }
            catch (error) { child.kill('SIGTERM'); await complete; throw error; }
            child.stdin.end(options.stdin);
            const result = await complete; assert.equal(entry.pidAbsent, true); return result;
        };
    }
    // Capture cleanup after the helper has removed each owned fake root.
    t.after(() => {
        for (const entry of children) assert.equal(entry.closed, true, `unreaped runner child ${entry.pid}`);
        for (const host of hosts.values()) {
            assert.equal(fs.existsSync(host.root), false);
            evidence('cleanup', { root: host.root, absent: true, children: children.filter(p => p.root === host.root) });
        }
    });
    const assertUntouched = () => {
        for (const host of hosts.values()) for (const profile of Object.keys(targets)) {
            const actual = readProfile(host, profile), original = host.original[profile];
            assert.equal(actual.unit, original.unit); assert.equal(actual.active, 'active'); assert.equal(actual.enabled, 'enabled');
            if (profile !== host.profile) assert.deepEqual(actual, original, 'independent nonselected profile bytes/state/restarts preserved');
        }
    };
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 3, remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
    await models.HyNode.create(f.nodes.map(({ id, role, profileConfig, ...fields }) => ({ ...fields, _id: id, cascadeRole: role,
        name: `MODELED-${role}`, ssh: { port: 22, username: 'synthetic', privateKey: 'not-an-ssh-key' } })));
    const { id, source, target, ...linkFields } = f.link;
    await models.CascadeLink.create({ ...linkFields, _id: id, name: 'original installed link', portalNode: source, bridgeNode: target, status: 'online' });
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: models.TopologyConfigOwner,
        async withVerifiedMaintenance({ binding, proofRef }, work) {
            assert.equal(proofRef, 'MODELED-exact-original'); const host = hosts.get(binding.node);
            assert.ok(host); assert.equal(binding.profile, host.profile); assert.deepEqual(binding.nodeIdentity, host.identity);
            const actual = readProfile(host, host.profile);
            await work({ authority: 'external-maintenance-v1', status: 'verified', binding: copy(binding), proofId: randomUUID(),
                maintenanceId: host.maintenance, maintenance: 'held', allWriters: 'drained', oldBackend,
                readback: { source: 'node-readback', configSha256: sha(actual.config), unitSha256: sha(actual.unit),
                    serviceActive: actual.active, serviceEnabled: actual.enabled } });
        } });
    const adopt = async () => {
        for (const host of hosts.values()) {
            const classic = await transfer.initializeClassic({ node: host.node.id, profile: host.profile, nodeIdentity: host.identity });
            assert.equal(classic.owner, 'classic'); assert.equal(classic.adoptionReceipt, undefined);
            await transfer.adopt({ node: host.node.id, profile: host.profile, generation: classic.generation,
                proofRef: 'MODELED-exact-original', legacyTopology: f.topology });
        }
    };
    let held = false;
    const assertHeld = async () => { assert.equal(held, true, 'modeled external hold must encompass worker and store'); };
    const authority = async (challenge, work) => {
        await assertHeld();
        const host = hosts.get(challenge.enrollment.nodeId); assert.ok(host);
        assert.equal(challenge.enrollment.targetProfile, host.profile);
        const journalPath = path.join(host.root, `var/lib/celerity/topology/fences/${host.profile}/journal.json`);
        let predecessor;
        if (challenge.predecessor) {
            const journal = JSON.parse(fs.readFileSync(journalPath));
            const previous = await models.TopologyExecutionBinding.findById(challenge.predecessor.bindingId).lean();
            const generation = journal.generations[previous.generation]; assert.equal(generation.phase, 'closed');
            const close = Object.values(generation.commands).find(item => item.command === 'close');
            const receipt = close.receipt;
            const parts = ['runner', '--command', 'status'];
            for (const [key, flag] of Object.entries({ operationId: 'operation-id', nodeId: 'node-id', candidateHash: 'candidate-hash', backupId: 'backup-id',
                targetProfile: 'target-profile', executionContext: 'execution-context', attemptId: 'attempt-id', generation: 'generation', predecessorGeneration: 'predecessor-generation' })) parts.push('--' + flag, receipt[key]);
            parts.push('--command-id', receipt.commandId);
            const observed = await host.execute(parts.join(' ')); assert.equal(observed.code, 0, observed.stderr);
            predecessor = { bindingId: previous._id, generation: receipt.generation, headGeneration: journal.head, bootId: host.boot,
                status: 'terminal', receipt: JSON.parse(observed.stdout) };
        } else if (challenge.action === 'enroll') {
            assert.equal(fs.existsSync(journalPath), false);
            assert.equal(fs.existsSync(path.join(host.root, 'var/lib/celerity/topology/operations')), false);
            predecessor = { generation: 'none', bootId: host.boot, status: 'empty', protocolVersion: 2, journal: 'absent', legacyState: 'absent', writers: 'excluded' };
        } else predecessor = { generation: 'none', bootId: host.boot, status: 'pre-enrolled' };
        const result = await work({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge: copy(challenge),
            proofId: randomUUID(), maintenanceId: host.maintenance, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded',
            physicalIdentity: copy(host.identity), owner: 'topology', oldBackend, predecessor,
            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: copy(host.endpoint), physicalIdentity: copy(host.identity),
                maintenanceId: host.maintenance, aliases: 'excluded', hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' } });
        await assertHeld(); return result;
    };
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: context,
        controller: { executionContext: context, async withHeldAuthority(selected, work) {
            assert.deepEqual(selected, context); assert.equal(held, false); held = true;
            try { return await work({ assertHeld, withVerifiedAuthority: authority }); } finally { held = false; }
        } } });
    const store = new TopologyExecutionBindingStore({ executionContext: context, Operation: models.TopologyOperation, Lock: models.NodeOperationLock,
        Owner: models.TopologyConfigOwner, Enrollment: models.TopologyExecutionEnrollment, Binding: models.TopologyExecutionBinding, HyNode: models.HyNode,
        withVerifiedAuthority: (challenge, work) => lifecycle.withVerifiedAuthority(challenge, work), assertAuthorityHeld: () => lifecycle.assertHeld() });
    const enroll = () => lifecycle.run(async () => {
        for (const host of hosts.values()) {
            const owner = await models.TopologyConfigOwner.findOne({ node: host.node.id, profile: host.profile }).lean();
            await store.preEnroll(freeze({ nodeId: host.node.id, targetProfile: host.profile, endpoint: host.endpoint, nodeIdentity: host.identity,
                ownerGeneration: owner.generation, predecessorGeneration: 'none', bootId: host.boot }));
        }
    });
    class LocalSSH {
        constructor(node, connection) {
            this.host = hosts.get(String(node._id)); assert.ok(this.host);
            assert.deepEqual(connection, { expectedEndpoint: this.host.endpoint, expectedHostKeySha256: this.host.identity.sshHostKeySha256 });
        }
        async writeFile() { assert.fail('preinstalled local runner never uploads/bootstrap-writes'); }
        async exec(command, options) {
            await lifecycle.assertHeld(); const request = runnerRequest(command); events.push({ node: this.host.node.id, ...request });
            assert.equal(request.targetProfile, this.host.profile);
            return this.host.execute(command, options);
        }
    }
    // Installation is explicitly modeled as preinstalled, not a new operational controller.
    class Preinstalled { async ensureRunner() { await lifecycle.assertHeld(); } }
    const executor = new TopologyOperationExecutor({ ...context, executionBindingReader: store,
        nodeExecutionResolver: new TopologyNodeExecutionResolver({ ...context, HyNode: models.HyNode, NodeSSH: LocalSSH }), RunnerBootstrapper: Preinstalled });
    const draft = new TopologyDraftRepository(models);
    const deployment = new TopologyDeploymentRepository({ ...models, snapshotReader: draft });
    const operations = new TopologyOperationRepository({ model: models.TopologyOperation, topologyStateModel: models.CascadeTopologyState, selectedTopologyRepository: deployment });
    const coordinator = new TopologyOperationCoordinator({ executionContext: context, topologyRepository: deployment,
        operationRepository: operations, planMaterializer: new TopologyOperationPlanMaterializer(models) });
    const clock = { now: () => new Date() };
    const worker = new TopologyOperationWorker({ executionContext: context, operationRepository: operations, executor,
        finalizer: new TopologyOperationFinalizer({ repository: new TopologyOperationFinalizationRepository({ ...models, selectedTopologyRepository: deployment }), clock }),
        lockService: new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model: models.NodeOperationLock }), clock }),
        workerId: `native-acceptance-${process.pid}`, leaseMs: 120000, clock, bindingProvisioner: store, bindingLifecycle: lifecycle,
        selectedTopologyRepository: deployment, allowUnprovenTestExecution: false,
        pppReadinessGate: new (require('../services/topologyPppReadinessGate').TopologyPppReadinessGate)({ ...models,
            transportResolver: async () => { assert.fail('no PPP nodes or transport in this acceptance'); } }),
        userResync: new (require('../services/topologyUserResync').TopologyUserResync)({ HyNode: models.HyNode,
            syncService: {
                async _getUsersForNode(node) {
                    await lifecycle.assertHeld();
                    const host = hosts.get(String(node._id));
                    // Independently accepted original MAIN clients, not the runner challenge.
                    return JSON.parse(host.original['xray-main'].config).inbounds.filter(inbound => inbound.tag === 'client-in')
                        .flatMap(inbound => inbound.settings?.clients || [])
                        .map(client => ({ xrayUuid: client.id, userId: client.email }));
                },
                async addXrayUser(node, user) {
                    await lifecycle.assertHeld();
                    const host = hosts.get(String(node._id));
                    // MODELED runtime-user transport: fail if the independently
                    // modeled MAIN config no longer contains the original user.
                    const clients = JSON.parse(readProfile(host, 'xray-main').config).inbounds.flatMap(inbound => inbound.settings?.clients || []);
                    return clients.some(client => client.id === user.xrayUuid && client.email === user.userId);
                },
            }, attempts: 1 }) });
    const revision = async () => (await models.CascadeTopologyState.findById('singleton').lean()).revision;
    const operation = value => models.TopologyOperation.findById(value).select(PRIVATE_OPERATION).lean();
    const read = linkId => new TopologyDeploymentRepository({ ...models, snapshotReader: new TopologyDraftRepository(models) })
        .readSelected({ scope: { kind: 'link.apply', linkId }, executionContext: context });
    const run = async operationId => {
        const result = await worker.run(operationId);
        if (result.status !== 'succeeded') evidence('worker-failure', { result,
            operation: await operation(operationId),
            locks: await models.NodeOperationLock.find({}).lean(),
            owners: await models.TopologyConfigOwner.find({}).select('+legacyAppliedTopology +profileTargetPin').lean(),
            enrollments: await models.TopologyExecutionEnrollment.find({}).lean(),
            bindings: await models.TopologyExecutionBinding.find({}).lean() });
        assert.equal(result.status, 'succeeded', JSON.stringify(result)); return operation(operationId);
    };
    const apply = async (linkId = f.link.id) => {
        const queued = await coordinator.queue({ expectedTopologyRevision: await revision(), scope: { kind: 'link.apply', linkId, linkIds: [linkId] } });
        return run(queued.operationId);
    };
    const joined = draft.createIntentDraftWriter({ selectedTopologyRepository: deployment });
    const dependencies = { ...models, executionContext: context, prepareLink: prepareIntentLink,
        deleteIntentWriter: models.CascadeLink.createDeleteIntentWriter({ CascadeLink: models.CascadeLink }), intentDraftWriter: joined,
        intentOperationAdmission: { db: mongo.connection, queue: input => coordinator.queueIntent(input) },
        resolveIntentResources: input => coordinator.resolveIntentResourcesForQueue(input) };
    const service = new TopologyIntentService(dependencies), consumer = new TopologyIntentConsumer(dependencies);
    const consume = async job => {
        const claimed = await consumer.claim(); assert.equal(String(claimed._id), job.jobId);
        const queued = await consumer.consumeVersioned(claimed);
        await run(queued.operationId);
        assert.equal(await consumer.settle(await models.TopologyCreateIntent.findById(job.jobId).lean()), true);
        assert.equal((await service.get(job.jobId)).status, 'succeeded'); return operation(queued.operationId);
    };
    const remove = async () => {
        const link = await models.CascadeLink.findById(f.link.id).lean();
        return consume(await service.acceptVersioned({ kind: 'link.delete', expectedTopologyRevision: await revision(), requestKey: randomUUID(),
            linkId: f.link.id, desiredVersion: linkDesiredVersion(link) }));
    };
    const recreate = async () => {
        const job = await service.acceptVersioned({ kind: 'link.create', expectedTopologyRevision: await revision(), requestKey: randomUUID(),
            link: { name: 'recreated forward', portalNode: source, bridgeNode: target, mode, tunnelPort: f.link.tunnelPort,
                tunnelSecurity: security, tunnelTransport: 'tcp', active: true, priority: 1 } });
        const op = await consume(job); return { op, link: await models.CascadeLink.findById(job.createdLinkId).select('+realityPrivateKey').lean() };
    };
    return { models, ...f, hosts, events, lifecycle, store, transfer, adopt, enroll, worker, coordinator, read, apply, remove, recreate,
        operation, revision, readProfile, assertUntouched, profileFor, mongo };
}
module.exports = { nativeFixture, mongoFixture, layout, context, sha, evidence, PRIVATE_OPERATION };
