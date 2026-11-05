'use strict';
// LOCAL ONLY. Actual schemas/casting/BSON/public producers and all topology
// consumers; persistence/transactions/physical authority/systemd/Xray/PPP modeled.
// Compose the immutable corrected A fixture; extend ONLY this dedicated driver.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { isDeepStrictEqual: same } = require('node:util');
const mongoose = require('mongoose');
const sift = require('sift').default;
const { installedGroupFixture, id, sha, copy, bson, key, profileFor } = require('./cascadeLegacyInstalledGroupFixture');
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
const get = (row, dotted) => dotted.split('.').reduce((v, k) => v?.[k], row);
const typed = v => v === undefined ? 'missing' : v === null ? 'null' : v instanceof Date ? 'date'
    : v?._bsontype === 'ObjectId' ? 'objectId' : Array.isArray(v) ? 'array' : typeof v === 'number' ? 'double'
        : typeof v === 'boolean' ? 'bool' : typeof v === 'object' ? 'object' : typeof v;
function expression(value, row) {
    if (typeof value === 'string' && value.startsWith('$')) return get(row, value.slice(1));
    if (Array.isArray(value)) return value.map(item => expression(item, row));
    if (!value || typeof value !== 'object' || value instanceof Date || value._bsontype) return value;
    const entries = Object.entries(value);
    if (entries.length !== 1) throw Error('Unsupported modeled expression');
    const [op, args] = entries[0];
    if (op === '$literal') return args;
    if (op === '$type') return typed(expression(args, row));
    if (op === '$and') return args.every(arg => expression(arg, row));
    if (op === '$or') return args.some(arg => expression(arg, row));
    if (op === '$eq') { const [a, b] = expression(args, row); return same(a, b); }
    if (op === '$in') { const [a, b] = expression(args, row); return b.some(v => same(a, v)); }
    if (op === '$toString') return String(expression(args, row));
    if (op === '$concat') return expression(args, row).join('');
    if (op === '$regexMatch') return new RegExp(expression(args.regex, row)).test(expression(args.input, row));
    if (op === '$convert') {
        const v = expression(args.input, row);
        if (v == null) return args.onNull;
        if (args.to === 'long') return Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : args.onError;
        if (args.to === 'string') return ['string', 'number', 'boolean'].includes(typeof v) ? String(v) : args.onError;
    }
    throw Error(`Unsupported modeled expression ${op}`);
}
function matches(row, filter) {
    return Object.entries(filter).every(([k, v]) => {
        if (k === '$expr') return Boolean(expression(v, row));
        if (k === '$and') return v.every(item => matches(row, item));
        if (k === '$or') return v.some(item => matches(row, item));
        if (k === '$nor') return v.every(item => !matches(row, item));
        if (v && typeof v === 'object' && Object.hasOwn(v, '$type')) {
            const { $type, ...rest } = v;
            if (!(Array.isArray($type) ? $type : [$type]).includes(typed(get(row, k)))) return false;
            return !Object.keys(rest).length || matches(row, { [k]: rest });
        }
        // Preserve BSON embedded-document and Date equality from corrected F1.
        if (!k.includes('.') && v !== null && (!v || typeof v !== 'object' || !Object.keys(v).some(x => x.startsWith('$')))) return same(row[k], v);
        return sift({ [k]: v })(row);
    });
}
function extendDriver(f, Model, name) {
    const native = Model.collection.collection, rows = f.data[name];
    const cast = (v, options) => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(v,
        { ignoreUndefined: options?.ignoreUndefined ?? false }));
    const selected = (filter, options) => {
        filter = cast(filter, options);
        f.driverEvents.push({ name, filter });
        let found = rows.filter(row => matches(row, filter));
        if (options?.sort) found = [...found].sort((a, b) => {
            for (const [k, direction] of Object.entries(options.sort)) {
                const x = get(a, k), y = get(b, k); if (x < y) return -direction; if (x > y) return direction;
            } return 0;
        });
        if (options?.limit) found = found.slice(0, options.limit);
        return found;
    };
    const projected = (row, options) => row ? native.findOne({ _id: row._id }, options) : null;
    const set = (row, dotted, value, filter) => {
        let parts = dotted.split('.'), obj = row;
        for (const part of parts.slice(0, -1)) {
            if (part === '$') {
                const wanted = filter['nodes.node'] || filter.nodes?.$elemMatch?.node;
                obj = obj.find(item => same(item.node, wanted)); assert.ok(obj, 'positional native update has exact match');
            } else obj = obj[part] ||= {};
        }
        if (value === undefined) delete obj[parts.at(-1)]; else obj[parts.at(-1)] = bson({ v: value }).v;
    };
    const update = (row, change, filter) => {
        for (const [k, v] of Object.entries(change.$set || {})) set(row, k, v, filter);
        for (const [k, v] of Object.entries(change.$inc || {})) set(row, k, (get(row, k) || 0) + v, filter);
        for (const k of Object.keys(change.$unset || {})) set(row, k, undefined, filter);
        for (const op of Object.keys(change)) assert.ok(['$set', '$inc', '$unset', '$setOnInsert'].includes(op), `modeled update supports ${op}`);
    };
    const insert = doc => {
        const value = bson(doc);
        if (rows.some(row => same(row._id, value._id)) || name === 'NodeOperationLock' && rows.some(row => same(row.node, value.node))) throw Object.assign(Error('modeled unique collision'), { code: 11000 });
        rows.push(value); return value;
    };
    Model.collection.collection = { ...native,
        async findOne(filter = {}, options = {}) { return projected(selected(filter, options)[0], options); },
        find(filter = {}, options = {}) { return { toArray: async () => Promise.all(selected(filter, options).map(row => projected(row, options))) }; },
        async countDocuments(filter = {}, options = {}) { return selected(filter, options).length; },
        async insertOne(doc) { insert(doc); return { acknowledged: true, insertedId: doc._id }; },
        async insertMany(docs) { docs.forEach(insert); return { acknowledged: true, insertedCount: docs.length, insertedIds: Object.fromEntries(docs.map((doc, i) => [i, doc._id])) }; },
        async updateOne(filter, change, options) { const row = selected(filter, options)[0]; if (row) update(row, cast(change, options), cast(filter, options)); return { acknowledged: true, matchedCount: row ? 1 : 0, modifiedCount: row ? 1 : 0 }; },
        async updateMany(filter, change, options) { const found = selected(filter, options); for (const row of found) update(row, cast(change, options), cast(filter, options)); return { acknowledged: true, matchedCount: found.length, modifiedCount: found.length }; },
        async findOneAndUpdate(filter, change, options = {}) { const row = selected(filter, options)[0]; if (!row) return null; const before = bson(row); update(row, cast(change, options), cast(filter, options));
            if (options.returnDocument === 'after') return projected(row, options);
            // Ordinary callers request new:true. Retain exact preimage otherwise.
            const current = bson(row); Object.keys(row).forEach(k => delete row[k]); Object.assign(row, before);
            const result = await projected(row, options); Object.keys(row).forEach(k => delete row[k]); Object.assign(row, current); return result; },
        async deleteOne(filter, options) { const row = selected(filter, options)[0]; if (row) rows.splice(rows.indexOf(row), 1); return { acknowledged: true, deletedCount: row ? 1 : 0 }; },
    };
}

async function lifecycleFixture(t) {
    const f = installedGroupFixture();
    // Additional nonempty protected installation identity, fixed BEFORE models,
    // adoption, enrollment or native work. Still pre-existing modeled inventory.
    Object.assign(f.inventory.states[0], { managedVersion: 'MODELED-legacy-v1', configFingerprint: sha('MODELED-installed-L2TP'),
        backupId: 'MODELED-original-install-backup', operationId: id(82), installedAt: new Date('2026-01-01T00:00:00Z'),
        lastVerifiedAt: new Date('2026-01-02T00:00:00Z'), lastSyncAt: new Date('2026-01-03T00:00:00Z'), routingMode: 'route-group' });
    Object.assign(f, { fixtureId: randomUUID(), stage: 'construct', driverEvents: [], dispatches: [], children: [], options: { prepares: [], prepareErrors: [], gateCalls: [], userPushes: 0 } });
    // Model only the client metadata required by the dormant real store; NO DB
    // connection, wire command, server or native Mongo claim is made here.
    const client = { options: { directConnection: false }, topology: { description: { type: 'ReplicaSetWithPrimary' } },
        db: () => ({ command: async command => { assert.equal(command.commitTransaction, 1); return { ok: 1 }; } }) };
    class ModeledSession {
        constructor() { this.client = client; this.transaction = { transition() {} }; }
        inTransaction() { return true; } startTransaction() {} async commitTransaction() {} async abortTransaction() {} async endSession() {}
    }
    f.session = new ModeledSession(); f.connection.getClient = () => client;
    f.connection.startSession = async () => new ModeledSession();
    const transactionRunner = async work => {
        const before = Object.fromEntries(Object.entries(f.data).map(([name, rows]) => [name, rows.map(bson)]));
        try { return await work(f.session); }
        catch (error) { for (const [name, rows] of Object.entries(before)) f.data[name].splice(0, f.data[name].length, ...rows); throw error; }
    };
    f.connection.transaction = transactionRunner;
    const bind = (name, source, rows = []) => f.model(name, require(source), rows);
    const models = {
        TopologyConfigOwner: f.Owner,
        HyNode: bind('HyNode', '../../../../models/hyNodeModel', f.inventory.nodes.map(row => ({ ...copy(row), _id: oid(row._id),
            ssh: { port: 22, username: 'synthetic', privateKey: 'MODELED-NOT-A-KEY' } }))),
        CascadeLink: bind('CascadeLink', '../../../../models/cascadeLinkModel', f.inventory.links.map(row => ({ ...copy(row), _id: oid(row._id), portalNode: oid(row.portalNode), bridgeNode: oid(row.bridgeNode) }))),
        CascadeRouteGroup: bind('CascadeRouteGroup', '../../models/cascadeRouteGroupModel', f.inventory.groups.map(row => ({ ...copy(row), _id: oid(row._id), paths: row.paths.map(p => ({ ...copy(p), linkIds: p.linkIds.map(oid) })) }))),
        RelayL2tpState: bind('RelayL2tpState', '../../models/relayL2tpStateModel', f.inventory.states.map(row => ({ ...copy(row), _id: oid(row._id), node: oid(row.node), routeGroup: oid(row.routeGroup) }))),
        L2tpUser: bind('L2tpUser', '../../models/l2tpUserModel', f.inventory.users.map(row => ({ ...copy(row), _id: oid(row._id), relayNode: oid(row.relayNode), syncOperationId: oid(row.syncOperationId) }))),
        L2tpOperation: bind('L2tpOperation', '../../models/l2tpOperationModel', f.inventory.syncFacts.map(row => ({ ...copy(row), _id: oid(row._id), node: oid(row.node) }))),
        CascadeTopologyState: bind('CascadeTopologyState', '../../models/cascadeTopologyStateModel', [{ _id: 'singleton', revision: 7, deployedRevision: 0, remoteAdmissionCount: 0, topologyAdmissionCount: 0 }]),
        TopologyOperation: bind('TopologyOperation', '../../models/topologyOperationModel'),
        NodeOperationLock: bind('NodeOperationLock', '../../models/nodeOperationLockModel'),
        TopologyExecutionEnrollment: bind('TopologyExecutionEnrollment', '../../models/topologyExecutionEnrollmentModel'),
        TopologyExecutionBinding: bind('TopologyExecutionBinding', '../../models/topologyExecutionBindingModel'),
        TopologyCreateIntent: bind('TopologyCreateIntent', '../../models/topologyCreateIntentModel'),
        TopologyIntentQueueState: bind('TopologyIntentQueueState', '../../models/topologyIntentQueueStateModel'),
    };
    for (const [name, Model] of Object.entries(models)) extendDriver(f, Model, name);
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
        const execute = host.execute;
        host.execute = (command, options) => {
            const request = runnerRequest(command); f.dispatches.push({ node: node.id, command: request.command });
            const result = execute(command, options); assert.ok(Number.isInteger(result.code), 'owned finite runner naturally exited');
            f.children.push({ kind: 'typed-runner', code: result.code, signal: null }); return result;
        };
    }
    const readPhysical = (nodeId, profile) => {
        const host = hosts.get(nodeId), target = targets[profile], file = path.join(host.root, target.config);
        return { config: fs.readFileSync(file, 'utf8'), inode: fs.statSync(file).ino,
            unit: fs.readFileSync(path.join(host.root, target.unit), 'utf8'),
            ...JSON.parse(fs.readFileSync(path.join(host.root, 'services.json')))[target.service] };
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
            parts.push('--command-id', receipt.commandId); const actual = host.execute(parts.join(' ')); assert.equal(actual.code, 0);
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
    const draft = new TopologyDraftRepository({ ...models, transactionRunner });
    const deployment = new TopologyDeploymentRepository({ ...models, snapshotReader: draft, transactionRunner });
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
            f.options.onPpp?.();
            return { code: f.options.unreadablePpp ? 65 : 0, stderr: '', stdout: JSON.stringify({ ok: true, code: 'USERS_VERIFIED', ...pppNode,
                ...(f.options.wrongCredential ? { credentialRevision: 42 } : {}), ...(f.options.wrongUsers ? { managedUserCount: 0 } : {}) }) + '\n' };
        } } });
    const forbidden = () => assert.fail('Forbidden migration install/configure/user/PSK mutation or repair-sync');
    const service = new L2tpSimpleService({ ...models, allowRemoteExecution: true, topologyIngressGate: ingress, topologyPppReadinessGate: ppp,
        l2tpService: { install: forbidden, getOperation: forbidden }, stateManagementService: { configureRelay: forbidden, revealPsk: forbidden },
        userManagementService: { createUser: forbidden, deleteUser: forbidden, importUser: forbidden }, stateRepository: { getTopologyRevision: forbidden }, nodeSSHFactory: forbidden });
    const clock = { now: () => new Date() };
    const worker = new TopologyOperationWorker({ executionContext: f.context, operationRepository: operations, executor,
        selectedTopologyRepository: deployment, bindingProvisioner: store, bindingLifecycle: lifecycle, allowUnprovenTestExecution: false,
        workerId: 'C-modeled-worker', leaseMs: 120000, clock,
        lockService: new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model: models.NodeOperationLock }), clock }),
        finalizer: new TopologyOperationFinalizer({ repository: new TopologyOperationFinalizationRepository({ ...models, selectedTopologyRepository: deployment, transactionRunner }), clock }),
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
            const published = f.data.CascadeRouteGroup.find(group => String(group._id) === operationPlan.groupId);
            assert.deepEqual(published.paths.find(p => p.pathKey === operationPlan.pathKey).linkIds.map(String), operationPlan.oldPathLinkIds, 'no path publication before actual MAIN/PPP readiness');
            assert.equal(f.data.RelayL2tpState[0].appliedTopologyRevision, operationPlan.ownerTopologyRevision);
            try { const proof = await service.prepareConfiguredRelayIngress({ operationPlan }); f.options.prepares.push(proof); f.options.afterPrepare?.(); return proof; }
            catch (error) { f.options.prepareErrors.push(error.code || 'UNKNOWN'); throw error; } } });
    const dependencies = { ...models, executionContext: f.context, transactionRunner,
        intentDraftWriter: draft.createIntentDraftWriter({ selectedTopologyRepository: deployment }),
        deleteIntentWriter: require('../../../../models/cascadeLinkModel').createDeleteIntentWriter({ CascadeLink: models.CascadeLink }),
        intentOperationAdmission: { db: f.connection, queue: input => coordinator.queueIntent(input) },
        resolveIntentResources: input => coordinator.resolveIntentResourcesForQueue(input) };
    const freshIntentService = () => new TopologyIntentService(dependencies);
    const consumer = new TopologyIntentConsumer(dependencies);
    const revision = async () => (await models.CascadeTopologyState.findById('singleton').lean()).revision;
    const operation = value => models.TopologyOperation.findById(value).select(PRIVATE).lean();
    const protectedState = row => Object.fromEntries(Object.entries(row).filter(([k]) => !['appliedTopologyRevision', 'replacementFence', 'updatedAt'].includes(k)));
    const originals = { physical: new Map([...hosts].flatMap(([nodeId]) => Object.keys(targets).map(p => [key(nodeId, p), readPhysical(nodeId, p)]))),
        state: sha(JSON.stringify(protectedState(f.data.RelayL2tpState[0]))), users: sha(JSON.stringify(f.data.L2tpUser)), sync: sha(JSON.stringify(f.data.L2tpOperation)),
        otherGroup: sha(JSON.stringify(f.data.CascadeRouteGroup[1])),
        unrelatedLinks: sha(JSON.stringify(f.data.CascadeLink.filter(row => [id(90), id(91)].includes(String(row._id))))),
        groupPolicy: semanticHash(require('../../domain/topologyDraft').projectGroups([f.data.CascadeRouteGroup[0]])
            .map(group => ({ ...group, paths: group.paths.map(p => ({ ...p, linkIds: [] })) }))), import: null };
    const physicalFingerprint = () => sha(JSON.stringify([...hosts].map(([nodeId, host]) => [nodeId, readPhysical(nodeId, host.profile)])));
    const assertPreserved = async () => {
        assert.equal(sha(JSON.stringify(protectedState(f.data.RelayL2tpState[0]))), originals.state, 'all protected installed-state fields preserved');
        assert.equal(sha(JSON.stringify(f.data.L2tpUser)), originals.users, 'entire PPP identities/password/IP/enabled/revisions membership preserved');
        assert.equal(sha(JSON.stringify(f.data.L2tpOperation)), originals.sync, 'no repair-sync or invented successful sync');
        assert.equal(sha(JSON.stringify(f.data.CascadeRouteGroup[1])), originals.otherGroup, 'unrelated group preserved');
        assert.equal(sha(JSON.stringify(f.data.CascadeLink.filter(row => [id(90), id(91)].includes(String(row._id))))), originals.unrelatedLinks, 'pending/inactive save-only neighbors unchanged');
        assert.equal(semanticHash(require('../../domain/topologyDraft').projectGroups([f.data.CascadeRouteGroup[0]])
            .map(group => ({ ...group, paths: group.paths.map(p => ({ ...p, linkIds: [] })) }))), originals.groupPolicy, 'G/K/mode/strategy/priority/enable/ingress identity preserved');
        assert.equal(sha(JSON.stringify(f.data.TopologyConfigOwner.map(row => ({ generation: row.generation, originalSnapshot: row.originalSnapshot,
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
        const snapshotReader = new TopologyDraftRepository(models);
        return new TopologyDeploymentRepository({ ...models, snapshotReader })
            .readSelected({ snapshot: await snapshotReader.readDraft(), scope: { kind: 'link.apply', linkId }, executionContext: f.context });
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
    return Object.assign(f, { models, hosts, readPhysical, store, worker, coordinator, consumer, dependencies, freshIntentService, operation, read,
        physicalFingerprint, assertPreserved, assertFresh,
        corruptMain(change) { const host = hosts.get(id(2)), config = JSON.parse(readPhysical(id(2), 'xray-main').config); change(config);
            fs.writeFileSync(path.join(host.root, targets['xray-main'].config), JSON.stringify(config)); },
        deactivateMain() { const host = hosts.get(id(2)), file = path.join(host.root, 'services.json'), services = JSON.parse(fs.readFileSync(file));
            services['xray.service'].active = 'inactive'; fs.writeFileSync(file, JSON.stringify(services)); },
        async adoptAndEnroll() {
            f.stage = 'public-adopt'; for (const node of f.topology.nodes) await f.adopt(node);
            originals.import = sha(JSON.stringify(f.data.TopologyConfigOwner.map(row => ({ generation: row.generation, originalSnapshot: row.originalSnapshot,
                adoptionReceipt: row.adoptionReceipt, legacyAppliedTopology: row.legacyAppliedTopology }))));
            f.stage = 'public-preEnroll'; await lifecycle.run(async () => { for (const host of hosts.values()) {
                const owner = await models.TopologyConfigOwner.findOne({ node: host.node.id, profile: host.profile }).lean();
                await store.preEnroll(freeze({ nodeId: host.node.id, targetProfile: host.profile, endpoint: host.endpoint, nodeIdentity: host.identity,
                    ownerGeneration: owner.generation, predecessorGeneration: 'none', bootId: host.boot }));
            } });
        },
        async assertInitial() {
            assert.equal(f.inventory.label, 'MODELED_PREEXISTING_LEGACY_INVENTORY'); assert.equal(f.data.TopologyOperation.length, 0);
            assert.equal(f.data.TopologyConfigOwner.every(row => row.lastSettledOperation === undefined), true);
            assert.equal(f.dispatches.length, 0); assert.equal(f.data.NodeOperationLock.length, 0);
            assert.equal(f.data.TopologyExecutionEnrollment.length, 3);
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
                lockCount: f.data.NodeOperationLock.length, currentSuffix: f.data.CascadeRouteGroup[0].paths[0].linkIds.map(String),
                topologyEpoch: f.data.RelayL2tpState[0].appliedTopologyRevision, credentialEpoch: f.data.RelayL2tpState[0].secretRevision,
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
module.exports = { lifecycleFixture, id, extendDriver, expression, matches };
