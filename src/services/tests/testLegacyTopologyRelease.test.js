'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const IDS = ['6ab189dc63913ebd4a917399', '6ab18adc63913ebd4a917471', '6ab18d9c63913ebd4a917670',
    '6ab4b53bc4c0304573e06c72', '6ab93ad2646b4b7d2f43c907'];
const ENV = { PANEL_DOMAIN: 'lm1.infograd.online', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false' };
const COLLECTION = 'testlegacytopologyreleases';
function api() {
    let found;
    try { found = require('../testLegacyTopologyRelease'); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; }
    assert.equal(typeof found?.TestLegacyTopologyRelease, 'function', 'finite TEST legacy release service must exist');
    return found;
}
function fixture() {
    const { ObjectId, BSON } = require('mongodb');
    const copy = v => BSON.deserialize(BSON.serialize({ v })).v;
    const data = {
        hynodes: IDS.map((id, i) => ({ _id: new ObjectId(id), ip: `127.0.0.${i + 1}`, ssh: { port: 22, password: 'PRIVATE-fixture' },
            xray: { agentToken: 'PRIVATE-agent' }, status: 'online' })),
        topologyoperations: [{ _id: new ObjectId(), status: 'failed', heldTopologyAdmission: false,
            nodes: IDS.map(node => ({ node: new ObjectId(node), state: 'prepared' })), privateCandidate: Buffer.from('PRIVATE-config') }],
        cascadetopologystates: [{ _id: 'singleton', topologyAdmissionCount: 0, remoteAdmissionCount: 0 }],
        topologyintentqueuestates: [{ _id: 'create-v1', outstanding: 0 }],
    };
    const calls = [], deployment = { setName: 'rs0', replicaSetId: '6ab3717b28a9e4d82b5ee86a', database: 'hysteria' };
    const db = { databaseName: deployment.database,
        listCollections(filter) { return { toArray: async () => Object.hasOwn(data, filter.name) ? [{ name: filter.name }] : [] }; },
        admin: () => ({ command: async command => {
            calls.push(['command', command]);
            return { config: { _id: deployment.setName, settings: { replicaSetId: new ObjectId(deployment.replicaSetId) } } };
        } }),
        collection(name) { return {
            find(filter, options) { calls.push(['find', name, filter, options]); return { toArray: async () => copy(data[name] || []) }; },
            async insertOne(row) { calls.push(['insert', name]); if ((data[name] || []).length) throw new Error('duplicate');
                data[name] = [copy(row)]; return { acknowledged: true }; },
        }; },
        async createCollection(name, options) { calls.push(['create', name, options]); if (Object.hasOwn(data, name)) throw new Error('exists'); data[name] = []; },
    };
    const baseline = IDS.map(node => ({ node, nodeIdentity: { machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) },
        profiles: ['xray-main', 'xray-bridge'].map((profile, i) => ({ profile,
            config: i ? { state: 'absent' } : { state: 'present', sha256: '3'.repeat(64), uid: 0, gid: 0, mode: 420 },
            unit: { state: 'present', sha256: '4'.repeat(64), uid: 0, gid: 0, mode: 420 },
            additionalUnitFiles: i ? [] : [{ path: '/etc/systemd/system/xray.service.d/override.conf',
                artifact: { state: 'present', sha256: '5'.repeat(64), uid: 0, gid: 0, mode: 420 } }],
            serviceActive: i ? 'inactive' : 'active', serviceEnabled: 'enabled' })) }));
    let held = false, checks = 0;
    const authority = async ({ binding }, work) => {
        held = true;
        try { return await work({ authority: 'test-legacy-maintenance-v1', binding, proofId: randomUUID(), maintenanceId: randomUUID(),
            oldBackend: { instanceId: 'simulated-backend', pid: 42, processStartTime: '100', processTree: 'stopped', dispatch: 'disabled' },
            async recheck(challenge) { assert.equal(held, true); assert.deepEqual(challenge, binding); checks++; return copy(baseline); } });
        } finally { held = false; }
    };
    const env = { ...ENV };
    const service = (options = {}) => new (api().TestLegacyTopologyRelease)({ db, executionContext: TEST,
        expectedDeployment: deployment, acceptedBaseline: baseline, env, withVerifiedMaintenance: authority, ...options });
    return { db, data, calls, deployment, baseline, authority, service, env, get checks() { return checks; } };
}

test('accepted CURRENT baseline retires exact TEST history without changing a single original document', async () => {
    const f = fixture(); const before = require('mongodb').BSON.serialize({ rows: f.data.topologyoperations });
    const receipt = await f.service().retire();
    assert.equal(receipt._id, 'test-legacy-current-v1');
    assert.deepEqual(receipt.acceptedBaseline, f.baseline);
    assert.ok(f.checks >= 4, 'fresh checks bracket provisioning, insertion, confirmation and exit');
    assert.deepEqual(require('mongodb').BSON.serialize({ rows: f.data.topologyoperations }), before);
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), true);
    assert.equal(f.calls.filter(c => c[0] === 'create').length, 1);
    assert.equal(f.calls.filter(c => c[0] === 'insert').length, 1);
    assert.equal(JSON.stringify(receipt).includes('PRIVATE'), false);
});
module.exports = { api, fixture, IDS, ENV, COLLECTION, TEST };

for (const [name, mutate] of [
    ['nonterminal history', f => { f.data.topologyoperations[0].status = 'committing'; }],
    ['retained topology admission', f => { f.data.topologyoperations[0].heldTopologyAdmission = true; }],
    ['foreign history context', f => { f.data.topologyoperations[0].executionContext = { target: 'production', hostIdentity: ENV.PANEL_DOMAIN }; }],
    ['foreign node in history', f => { f.data.topologyoperations[0].nodes[0].node = 'f'.repeat(24); }],
    ['native owner', f => { f.data.topologyconfigowners = [{ owner: 'topology' }]; }],
    ['invalid native owner', f => { f.data.topologyconfigowners = [{}]; }],
    ['native enrollment', f => { f.data.topologyexecutionenrollments = [{}]; }],
    ['native binding', f => { f.data.topologyexecutionbindings = [{}]; }],
    ['held lock including expired', f => { f.data.nodeoperationlocks = [{ leaseUntil: new Date(0) }]; }],
    ['missing admission counter', f => { delete f.data.cascadetopologystates[0].remoteAdmissionCount; }],
    ['remote drain', f => { f.data.cascadetopologystates[0].remoteDrain = {}; }],
    ['replacement reservation', f => { f.data.cascadetopologystates[0].replacementReservation = {}; }],
    ['active remote writer', f => { f.data.remoteadmissions = [{ phase: 'running' }]; f.data.cascadetopologystates[0].remoteAdmissionCount = 1; }],
    ['queued L2TP work', f => { f.data.l2tpoperations = [{ status: 'queued' }]; }],
    ['queued intent', f => { f.data.topologycreateintents = [{ status: 'pending' }]; }],
    ['queue work', f => { f.data.topologyintentqueuestates[0].outstanding = 1; }],
]) test('retirement refuses ' + name + ' without DDL or receipt', async () => {
    const f = fixture(); mutate(f);
    await assert.rejects(f.service().retire(), /TEST_LEGACY_RELEASE/);
    assert.deepEqual(f.calls.filter(c => ['insert', 'create'].includes(c[0])), []);
});

test('no receipt means unchanged veto, no DDL and no fabricated baseline', async () => {
    const f = fixture();
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), false);
    assert.deepEqual(f.calls.map(c => c[0]), ['find']);
});

for (const [name, mutate] of [
    ['foreign deployment', f => { f.deployment.replicaSetId = 'b'.repeat(24); }],
    ['foreign database', f => { f.db.databaseName = 'foreign_database'; }],
    ['new operation', f => { f.data.topologyoperations.push({ status: 'failed', heldTopologyAdmission: false }); }],
    ['edited unprojected history', f => { f.data.topologyoperations[0].privateCandidate = Buffer.from('changed'); }],
    ['deleted history', f => { f.data.topologyoperations = []; }],
    ['endpoint mutation', f => { f.data.hynodes[0].ip = '127.0.1.1'; }],
    ['credential mutation', f => { f.data.hynodes[0].ssh.password = 'different'; }],
    ['native owner', f => { f.data.topologyconfigowners = [{ owner: 'topology' }]; }],
    ['native malformed state', f => { f.data.topologyexecutionbindings = [{}]; }],
    ['new active writer', f => { f.data.remoteadmissions = [{ phase: 'running', nodeId: IDS[0] }]; f.data.cascadetopologystates[0].remoteAdmissionCount = 1; }],
    ['new nonterminal history', f => { f.data.topologyoperations[0].status = 'preparing'; }],
    ['new held operation', f => { f.data.topologyoperations[0].heldTopologyAdmission = true; }],
    ['receipt context', f => { f.data[COLLECTION][0].executionContext.target = 'production'; }],
    ['receipt extra field', f => { f.data[COLLECTION][0].ready = true; }],
    ['receipt baseline permission', f => { f.data[COLLECTION][0].acceptedBaseline[0].profiles[0].config.mode = [420]; }],
    ['receipt array digest', f => { f.data[COLLECTION][0].historySha256 = [f.data[COLLECTION][0].historySha256]; }],
    ['receipt duplicate', f => { f.data[COLLECTION].push(f.data[COLLECTION][0]); }],
]) test('consumption refuses ' + name, async () => {
    const f = fixture(); await f.service().retire(); mutate(f);
    await assert.rejects(api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }));
});

test('future generated config and service telemetry changes do not revoke historical handoff', async () => {
    const f = fixture(); await f.service().retire();
    f.data.hynodes[0].status = 'offline'; f.data.hynodes[0].xray.transport = 'grpc';
    f.data.hynodes[0].lastSync = new Date(); f.data.hynodes[0].customConfig = 'new ordinary config';
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), true);
});

test('foreign node, host and flags cannot recognize a release', async () => {
    const f = fixture(); await f.service().retire();
    for (const env of [{ ...ENV, TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' },
        { ...ENV, TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: undefined }, { ...ENV, PANEL_DOMAIN: 'unknown' }]) {
        assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env }), false);
    }
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: 'f'.repeat(24), env: ENV }), false);
    await assert.rejects(api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: { ...ENV, PANEL_DOMAIN: TEST.hostIdentity } }));
});

test('strict constructor rejects declarations, foreign contexts and missing independently accepted baseline', () => {
    const f = fixture();
    for (const options of [{ executionContext: undefined }, { executionContext: { ...TEST, extra: true } },
        { executionContext: { target: 'production', hostIdentity: ENV.PANEL_DOMAIN } },
        { acceptedBaseline: undefined }, { withVerifiedMaintenance: true },
        { expectedDeployment: { ...f.deployment, replicaSetId: [f.deployment.replicaSetId] } }]) {
        assert.throws(() => f.service(options), /TEST_LEGACY_RELEASE/);
    }
});

test('failed live attestation and unverified boolean return cannot mint a receipt', async () => {
    for (const withVerifiedMaintenance of [async () => true,
        async (challenge, work) => work({ authority: 'test-legacy-maintenance-v1', binding: challenge.binding,
            recheck: async () => { throw new Error('live authority lost'); } })]) {
        const f = fixture();
        await assert.rejects(f.service({ withVerifiedMaintenance }).retire());
        assert.deepEqual(f.calls.filter(c => ['insert', 'create'].includes(c[0])), []);
    }
});

test('escaped callback and non-awaited callback cannot persist after maintenance scope exit', async () => {
    const f = fixture(); let escaped;
    await assert.rejects(f.service({ withVerifiedMaintenance: async (_, work) => { escaped = work; } }).retire());
    assert.throws(() => escaped({}), /TEST_LEGACY_RELEASE/);
    assert.deepEqual(f.calls.filter(c => ['insert', 'create'].includes(c[0])), []);
    const g = fixture();
    await assert.rejects(g.service({ withVerifiedMaintenance: async (challenge, work) => {
        void g.authority(challenge, work).catch(() => {});
    } }).retire());
    assert.equal(g.data[COLLECTION]?.length || 0, 0);
});

test('pre-insert live guard loss is sticky and produces no release document', async () => {
    const f = fixture(); let checks = 0;
    const withVerifiedMaintenance = (challenge, work) => f.authority(challenge, proof => work({ ...proof,
        recheck: async binding => { const observed = await proof.recheck(binding); checks++;
            if (checks === 5) throw new Error('actual held guard lost'); return observed; } }));
    await assert.rejects(f.service({ withVerifiedMaintenance }).retire(), /guard lost/);
    assert.equal(f.data[COLLECTION]?.length || 0, 0);
});

test('proof copied from a different challenge cannot authorize DDL', async () => {
    const f = fixture();
    await assert.rejects(f.service({ withVerifiedMaintenance: (challenge, work) => f.authority(challenge,
        proof => work({ ...proof, binding: { ...proof.binding, nonce: randomUUID() } })) }).retire());
    assert.deepEqual(f.calls.filter(c => ['insert', 'create'].includes(c[0])), []);
});

test('accepted drop-in unit files are strict baseline evidence, not optional ignored metadata', async () => {
    const f = fixture();
    const receipt = await f.service().retire();
    assert.deepEqual(receipt.acceptedBaseline[0].profiles[0].additionalUnitFiles, f.baseline[0].profiles[0].additionalUnitFiles);
    for (const change of [p => { delete p.additionalUnitFiles; },
        p => { p.additionalUnitFiles[0].path = '/etc/passwd'; },
        p => { p.additionalUnitFiles.push(p.additionalUnitFiles[0]); }]) {
        const baseline = structuredClone(f.baseline); change(baseline[0].profiles[0]);
        assert.throws(() => f.service({ acceptedBaseline: baseline }));
    }
});

test('constructor cannot generalize this slice to another accepted deployment', () => {
    const f = fixture();
    assert.throws(() => f.service({ expectedDeployment: { ...f.deployment, replicaSetId: 'a'.repeat(24) } }));
});

test('actual ownership guard consumes only exact TEST receipt; preserves native and active-operation vetoes', async t => {
    const f = fixture(); const mongoose = require('mongoose');
    const Operation = require('../../modules/relay-l2tp/models/topologyOperationModel');
    const { topologyManagesNodeConfig } = require('../topologyConfigOwnership');
    const oldDb = mongoose.connection.db; mongoose.connection.db = f.db;
    t.after(() => { mongoose.connection.db = oldDb; });
    t.mock.method(Operation, 'exists', async query => f.data.topologyoperations.find(require('sift').default(query)) || null);
    const target = { _id: f.data.hynodes[0]._id };
    assert.equal(await topologyManagesNodeConfig(target, ENV), true, 'failed/prepared requires verified retirement');
    await f.service().retire();
    assert.equal(await topologyManagesNodeConfig(target, ENV), false, 'accepted current handoff is recognized');
    f.data.topologyconfigowners = [{ owner: 'topology' }];
    await assert.rejects(topologyManagesNodeConfig(target, ENV));
    f.data.topologyconfigowners = [];
    f.data.topologyoperations[0].status = 'preparing';
    assert.equal(await topologyManagesNodeConfig(target, ENV), true, 'active operation is never waived');
    f.data.topologyoperations[0].status = 'failed'; f.data.topologyoperations[0].heldTopologyAdmission = true;
    assert.equal(await topologyManagesNodeConfig(target, ENV), true, 'terminal held admission is never waived');
});

test('flags changed during final pre-insert physical recheck refuse before persistence', async () => {
    const f = fixture(); let checks = 0;
    await assert.rejects(f.service({ withVerifiedMaintenance: (challenge, work) => f.authority(challenge, proof => work({ ...proof,
        recheck: async binding => { const value = await proof.recheck(binding); if (++checks === 6) f.env.TOPOLOGY_TEST_EXECUTION_ENABLED = 'true'; return value; } })) }).retire());
    assert.equal(f.calls.filter(c => c[0] === 'insert').length, 0);
});

test('swallowed duplicate callback poisons completion even after a confirmed insert', async () => {
    const f = fixture();
    await assert.rejects(f.service({ withVerifiedMaintenance: (challenge, work) => f.authority(challenge, async proof => {
        await work(proof); try { await work(proof); } catch {};
    }) }).retire());
    assert.equal(f.data[COLLECTION].length, 1, 'unknown retained: never delete a possibly committed receipt');
});

for (const state of ['prepared', 'committed', 'failed']) test('settled failed/' + state + ' is released only by actual maintenance callback', async () => {
    const f = fixture(); f.data.topologyoperations[0].nodes.forEach(n => { n.state = state; });
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), false);
    await f.service().retire();
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), true);
});

test('real server-owned L2TP held scope permits its own admission, not a competing or escaped writer', async () => {
    const f = fixture(); await f.service().retire();
    const { NodeOperationLockService } = require('../../modules/relay-l2tp/services/nodeOperationLockService');
    const { withHeldL2tpNodeConfigWrite } = require('../classicNodeConfigWrite');
    const lock = { node: IDS[0], owner: 'worker', operationId: 'operation-1', generation: randomUUID(),
        remoteUncertain: true, leaseUntil: new Date(Date.now() + 60000) };
    f.data.nodeoperationlocks = [lock];
    f.data.remoteadmissions = [{ nodeId: IDS[0], phase: 'running', operationId: lock.operationId }];
    f.data.cascadetopologystates[0].remoteAdmissionCount = 1;
    const clock = { now: () => new Date() };
    const lockService = new NodeOperationLockService({ clock, repository: { findByNode: async () => f.data.nodeoperationlocks[0] } });
    const read = () => api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV });
    await assert.rejects(read(), /SCOPE_CLOSED/);
    await withHeldL2tpNodeConfigWrite({ lock, lockService, clock }, async () => {
        assert.equal(await read(), true);
        f.data.remoteadmissions[0].operationId = 'competitor';
        await assert.rejects(read(), /TEST_LEGACY_RELEASE/);
        f.data.remoteadmissions[0].operationId = lock.operationId;
    });
    await assert.rejects(read(), /SCOPE_CLOSED/);
    assert.equal(f.data.nodeoperationlocks.length, 1, 'reader never deletes locks');
});

test('native replica-set identity array cannot masquerade as the exact TEST deployment', async () => {
    const f = fixture(); const command = f.db.admin().command;
    f.db.admin = () => ({ command: async query => { const result = await command(query);
        result.config.settings.replicaSetId = [result.config.settings.replicaSetId]; return result; } });
    await assert.rejects(f.service().retire());
    assert.deepEqual(f.calls.filter(c => ['insert', 'create'].includes(c[0])), []);
});

test('an existing empty release namespace must never be silently adopted by createCollection', async () => {
    const f = fixture(); f.data[COLLECTION] = [];
    // Mongo create can acknowledge compatible existing namespaces. The service
    // must detect this itself, not infer exclusive creation from ok:1.
    f.db.createCollection = async () => { f.calls.push(['create-compatible-existing']); };
    await assert.rejects(f.service().retire());
    assert.equal(f.calls.filter(c => c[0] === 'insert').length, 0);
});
