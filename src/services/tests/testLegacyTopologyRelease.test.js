'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const { api, fixture, IDS, ENV, COLLECTION } = require('./fixtures/legacyReleaseSimulation');

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
// B2: both mint and recognition must bind BSON types BEFORE default promotions.
for (const [from, to] of [['Int32', 'Double'], ['Double', 'Long'], ['Long', 'Int32']]) {
    const number = type => new (require('mongodb').BSON[type])(1);
    test(`lossless BSON recognition refuses ${from}(1) -> ${to}(1)`, async () => {
        const f = fixture(); f.data.topologyoperations[0].topologyRevision = number(from);
        await f.service().retire();
        assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), true);
        const before = require('mongodb').BSON.serialize(f.data.topologyoperations[0]);
        f.data.topologyoperations[0].topologyRevision = number(to);
        assert.notDeepEqual(require('mongodb').BSON.serialize(f.data.topologyoperations[0]), before);
        await assert.rejects(api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }));
    });
    test(`lossless BSON mint refuses mid-maintenance ${from}(1) -> ${to}(1)`, async () => {
        const f = fixture(); f.data.topologyoperations[0].topologyRevision = number(from);
        await assert.rejects(f.service({ withVerifiedMaintenance: (challenge, work) => {
            f.data.topologyoperations[0].topologyRevision = number(to);
            return f.authority(challenge, work);
        } }).retire());
        assert.deepEqual(f.calls.filter(c => ['insert', 'create'].includes(c[0])), []);
    });
}
test('lossless BSON normalizes document/key order, not array order/types or extra fields', async () => {
    const { BSON } = require('mongodb'); const f = fixture();
    f.data.topologyoperations[0].typed = { z: new BSON.Int32(1), a: new BSON.Double(1),
        array: [new BSON.Long(1), new BSON.Int32(2)], regex: new BSON.BSONRegExp('a', 'i') };
    f.data.topologyoperations.push({ ...f.data.topologyoperations[0], _id: new BSON.ObjectId() });
    await f.service().retire();
    const reverse = row => Object.fromEntries(Object.entries(row).reverse());
    f.data.topologyoperations.reverse();
    f.data.topologyoperations = f.data.topologyoperations.map(row => reverse({ ...row, typed: reverse(row.typed) }));
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), true);
    f.data.topologyoperations[0].typed.array.reverse();
    await assert.rejects(api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }));
    f.data.topologyoperations[0].typed.array.reverse();
    f.data.topologyoperations[0].unprojected = new BSON.Double(1);
    await assert.rejects(api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }));
});
test('lossless BSON mint accepts document/key-order-only changes under maintenance', async () => {
    const f = fixture(), { BSON } = require('mongodb');
    f.data.topologyoperations[0].typed = { z: new BSON.Long(1), a: new BSON.Double(1) };
    f.data.topologyoperations.push({ ...f.data.topologyoperations[0], _id: new BSON.ObjectId() });
    const receipt = await f.service({ withVerifiedMaintenance: (challenge, work) => {
        f.data.topologyoperations.reverse();
        f.data.topologyoperations = f.data.topologyoperations.map(row => Object.fromEntries(
            Object.entries({ ...row, typed: { a: row.typed.a, z: row.typed.z } }).reverse()));
        return f.authority(challenge, work);
    } }).retire();
    assert.equal(receipt._id, 'test-legacy-current-v1');
    assert.equal(await api().hasTestLegacyTopologyRelease({ db: f.db, nodeId: IDS[0], env: ENV }), true);
});
