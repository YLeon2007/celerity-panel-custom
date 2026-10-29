'use strict';
// Real disposable MongoDB replica set; only the remote core is stubbed.
// Never load a production URI or mutate a configured panel database.
Object.assign(process.env, { PANEL_DOMAIN: 'lm1.infograd.online', ACME_EMAIL: 'fixture@example.invalid',
    ENCRYPTION_KEY: 'local-fixture-key-not-for-production-00000000', SESSION_SECRET: 'local-fixture-session-not-for-production' });
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');
const { registerModels } = require('../../modules/relay-l2tp');
const CascadeLink = require('../../models/cascadeLinkModel');
const HyNode = require('../../models/hyNodeModel');
const { createClassicScopedCascadeDeploymentService } = require('../classicScopedCascadeDeploymentService');
const { issueClassicLifecycleGrant } = require('../classicLifecycleAuthorization');
const { withClassicNodeConfigWrite, assertHeldL2tpNodeConfigWrite } = require('../classicNodeConfigWrite');
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to a local disposable MongoDB binary' };
const source = '507f1f77bcf86cd799439031', bridge = '507f1f77bcf86cd799439032';
const otherPortal = '507f1f77bcf86cd799439033';
const linkId = '507f1f77bcf86cd799439021', oldId = '507f1f77bcf86cd799439022';
const groupId = '507f1f77bcf86cd799439051';
const env = Object.freeze({ PANEL_DOMAIN: 'lm1.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false',
    CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true', CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: linkId });
let models, child, directory, calls;
async function until(work) {
    let last;
    for (let i = 0; i < 250; i++) {
        try { return await work(); } catch (error) { last = error; }
        await new Promise(resolve => setTimeout(resolve, 40));
    }
    throw last;
}
test.before(async () => {
    if (!process.env.C3_MONGOD) return;
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'classic-deploy-mongo-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(() => resolve(p)); });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'classicScopedScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/classic_scoped_scratch?directConnection=true`;
    const client = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'classicScopedScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await client.close(); }
    await mongoose.connect(uri);
    models = { ...registerModels(), CascadeLink, HyNode };
    await Promise.all(Object.values(models).map(model => model.init()));
});
test.after(async () => {
    require('../sshPoolService').closeAll();
    await mongoose.disconnect();
    if (child && child.exitCode === null) {
        const ended = new Promise(resolve => child.once('exit', resolve));
        child.kill('SIGTERM'); await ended;
    }
    if (directory) await fs.rm(directory, { recursive: true, force: true });
});
async function reset({ installed = false, group = false } = {}) {
    assert.equal(mongoose.connection.name, 'classic_scoped_scratch');
    for (const model of Object.values(models)) await model.collection.deleteMany({});
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 4, deployedRevision: 0,
        replacementEpoch: 0, topologyAdmissionCount: 0, remoteAdmissionCount: 0 });
    await HyNode.collection.insertMany([source, bridge, otherPortal].map((_id, i) => ({
        _id: new mongoose.Types.ObjectId(_id), name: `fixture-${i}`, type: 'xray', active: true,
        cascadeRole: i === 1 ? 'bridge' : 'relay', ip: `192.0.2.${i + 1}`,
    })));
    await CascadeLink.create([{ _id: linkId, name: 'selected', portalNode: source, bridgeNode: bridge,
        tunnelUuid: 'local-selected', tunnelPort: 10096, mode: 'reverse', active: true, status: 'pending' },
    { _id: oldId, name: 'preserved', portalNode: otherPortal, bridgeNode: bridge,
        tunnelUuid: 'local-preserved', tunnelPort: 10086, mode: 'reverse', active: true, status: 'online' }]);
    if (group) await models.CascadeRouteGroup.create({ _id: groupId, name: 'retained-inactive-l2tp', mode: 'forward',
        strategy: 'priority-failover', paths: [{ pathKey: 'pilot-main', linkIds: [linkId], priority: 1, enabled: true }] });
    await models.RelayL2tpState.collection.insertOne({ node: new mongoose.Types.ObjectId(source),
        status: installed ? 'installed' : 'not_installed', desiredState: installed ? 'installed' : 'not_installed',
        ...(group && { routeGroup: new mongoose.Types.ObjectId(groupId) }) });
    calls = 0;
}
const input = () => ({ expectedTopologyRevision: 4, scope: { kind: 'link.apply', linkId, linkIds: [linkId, oldId] } });
const state = () => models.CascadeTopologyState.findById('singleton').lean();
function receipt() {
    const profile = (nodeId, file) => ({ nodeId, path: file, beforeSha256: 'a'.repeat(64), sha256: 'b'.repeat(64) });
    return { success: true, remoteQuiescent: true, receipt: { kind: 'classic-scoped-reverse', linkId,
        topologyRevision: 4, nodeIds: [source, bridge].sort(), preservedLinkIds: [oldId], tunnelEstablished: true,
        profiles: [profile(source, '/usr/local/etc/xray/config.json'), profile(bridge, '/usr/local/etc/xray-bridge/config.json'),
            profile(bridge, '/usr/local/etc/xray/config.json')],
        preservedProfiles: [{ nodeId: source, path: '/usr/local/etc/xray-bridge/config.json', sha256: 'c'.repeat(64) }] } };
}
function service(work = async () => receipt()) {
    return createClassicScopedCascadeDeploymentService({ ...models, env,
        cascadeService: { async deployScopedClassicLink(args) { calls++; return work(args); } } });
}
test('real Mongo success holds reservation and both exact node generations, preserving topology revisions', local, async () => {
    await reset();
    const selected = service(async args => {
        assert.deepEqual(args.baselineLinkIds, [oldId]);
        assert.match((await state()).replacementReservation.ownerToken, /^classic-deploy:/);
        let value;
        await withClassicNodeConfigWrite({ nodeId: source, kind: 'fixture', env }, async () => {
            await withClassicNodeConfigWrite({ nodeId: bridge, kind: 'fixture', env }, async () => {
                await assertHeldL2tpNodeConfigWrite(source); await assertHeldL2tpNodeConfigWrite(bridge);
                const rows = await models.NodeOperationLock.find().lean();
                assert.equal(rows.length, 2); assert(rows.every(row => row.remoteUncertain === true));
                value = receipt(); return true;
            }); return true;
        }); return value;
    });
    assert.deepEqual(await selected.queue(input()), { status: 'succeeded', executionMode: 'classic', topologyRevision: 4 });
    const row = await state(); assert.equal(row.revision, 4); assert.equal(row.deployedRevision, 0);
    assert.equal(row.replacementEpoch, 1); assert.equal(row.replacementReservation, undefined);
    assert.equal(await models.NodeOperationLock.countDocuments(), 0); assert.equal(calls, 1);
});
test('real Mongo stale revision and counted admission refuse before claim or dispatch', local, async () => {
    await reset(); const s = service();
    await assert.rejects(s.queue({ ...input(), expectedTopologyRevision: 3 }), { code: 'STALE_TOPOLOGY_REVISION' });
    assert.equal((await state()).replacementEpoch, 0);
    await models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $set: { remoteAdmissionCount: 1 } });
    await assert.rejects(s.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
    assert.equal((await state()).replacementReservation, undefined); assert.equal(calls, 0);
});
test('real Mongo active orphan operation vetoes even when counters are zero', local, async () => {
    await reset(); await models.TopologyOperation.collection.insertOne({ status: 'committing', heldTopologyAdmission: false });
    await assert.rejects(service().queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
    assert.equal((await state()).replacementEpoch, 0); assert.equal(calls, 0);
});
test('real Mongo uncertain dispatch retains nonexpiring reservation and refuses a successor', local, async () => {
    await reset(); const s = service(async () => { throw Error('injected transport loss'); });
    await assert.rejects(s.queue(input()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    const held = (await state()).replacementReservation; assert(held.ownerToken); assert.equal(held.epoch, 1);
    await assert.rejects(s.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
    assert.deepEqual((await state()).replacementReservation, held); assert.equal(calls, 1);
});
test('real Mongo concurrent request cannot acquire the held reservation', local, async () => {
    await reset(); let competing;
    const s = service(async () => { competing = service(); await assert.rejects(competing.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' }); return receipt(); });
    assert.equal((await s.queue(input())).status, 'succeeded'); assert.equal(calls, 1);
});
test('real Mongo installed path veto remains despite classic opt-in', local, async () => {
    await reset({ installed: true, group: true });
    await assert.rejects(service().queue(input()), { code: 'CLASSIC_DEPLOY_IN_USE' });
    assert.equal(calls, 0); assert.equal((await state()).replacementReservation, undefined);
});
test('real Mongo positively attributed retained UNINSTALLED group is not installed-path authority', local, async () => {
    await reset({ group: true });
    assert.equal((await service().queue(input())).status, 'succeeded');
    const group = await models.CascadeRouteGroup.findById(groupId).lean(); assert.equal(group.mode, 'forward');
    assert.deepEqual(group.paths[0].linkIds.map(String), [linkId]); assert.equal(calls, 1);
});
test('real Mongo ambiguous owner history vetoes without dispatch', local, async () => {
    await reset(); await mongoose.connection.db.collection('topologyconfigowners').insertOne({ node: new mongoose.Types.ObjectId(source), owner: 'topology', profile: 'xray-main' });
    await assert.rejects(service().queue(input())); assert.equal(calls, 0); assert.equal((await state()).replacementReservation, undefined);
    await mongoose.connection.db.collection('topologyconfigowners').deleteMany({});
});
test('real Mongo wrong completion receipt retains ownership', local, async () => {
    await reset(); const s = service(async () => ({ success: true, remoteQuiescent: true }));
    await assert.rejects(s.queue(input()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' }); assert((await state()).replacementReservation);
});
test('real Mongo stale owner cannot release a newer epoch/token', local, async () => {
    await reset(); const s = service(async () => {
        await models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $set: {
            replacementEpoch: 2, replacementReservation: { ownerToken: 'fixture-new-owner', epoch: 2 } } });
        return receipt();
    });
    await assert.rejects(s.queue(input()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
    assert.equal((await state()).replacementReservation.ownerToken, 'fixture-new-owner');
});
test('real Mongo non-allowlisted target is rejected before reservation acquisition', local, async () => {
    await reset(); const request = input(); request.scope.linkId = oldId;
    await assert.rejects(service().queue(request)); assert.equal(calls, 0);
    assert.equal((await state()).replacementEpoch, 0); assert.equal((await state()).replacementReservation, undefined);
});

test('real Mongo classic selector and queue retain an offline established neighbor', local, async () => {
    await reset(); await CascadeLink.updateOne({ _id: oldId }, { $set: { status: 'offline' } });
    const s = service(); const links = await CascadeLink.find().lean();
    const ids = s.selectBaselineLinkIds({ links, linkId });
    assert.deepEqual(ids, [oldId]);
    assert.equal((await s.queue({ expectedTopologyRevision: 4,
        scope: { kind: 'link.apply', linkId, linkIds: [linkId, ...ids] } })).status, 'succeeded');
    assert.equal((await CascadeLink.findById(oldId).lean()).status, 'offline');
});

const lifecycleEnv = { ...env, CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: undefined,
    CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'true', CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: 'ab'.repeat(32) };
const deletion = () => ({ expectedTopologyRevision: 4, linkId });
function removalReceipt() {
    const result = receipt();
    result.receipt.kind = 'classic-scoped-reverse-removal';
    delete result.receipt.tunnelEstablished;
    result.receipt.targetAbsent = true;
    result.receipt.profiles.forEach(p => { p.changed = true; });
    result.receipt.preservedProfiles.forEach(p => { p.beforeSha256 = p.sha256; p.changed = false; });
    return result;
}
function removalService(work = async () => removalReceipt(), options = {}) {
    return createClassicScopedCascadeDeploymentService({ ...models, env, ...options,
        cascadeService: { async removeScopedClassicLink(args) { calls++; return work(args); } } });
}

test('real Mongo saved durable grant survives reconstruction and never admits an unsigned pending link', local, async () => {
    await reset();
    const make = () => createClassicScopedCascadeDeploymentService({ ...models, env: lifecycleEnv,
        cascadeService: { async deployScopedClassicLink() { calls++; return receipt(); } } });
    await assert.rejects(make().queue(input()), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    assert.equal((await state()).replacementEpoch, 0); assert.equal(calls, 0);
    const link = await CascadeLink.findById(linkId).lean();
    // Native fixture persistence: issuing and hiding this field belong to the ingress/model slice.
    await CascadeLink.collection.updateOne({ _id: link._id }, { $set: {
        classicLifecycleGrant: issueClassicLifecycleGrant(link, lifecycleEnv),
    } });
    assert.equal((await make().queue(input())).status, 'succeeded');
    assert.equal((await make().queue(input())).status, 'succeeded');
    assert.equal(calls, 2); assert.equal((await state()).replacementEpoch, 2);
    const settled = (await state()).classicLifecycleLastSettlement;
    assert.equal(settled.action, 'link.apply'); assert.equal(settled.phase, 'succeeded');
    assert.deepEqual(settled.nodeIds, [source, bridge]);
});

test('real Mongo DELETE holds link through remote then atomically deletes retained paths and increments only revision', local, async () => {
    await reset({ group: true });
    const s = removalService(async args => {
        assert.deepEqual(args, { linkId, expectedTopologyRevision: 4, baselineLinkIds: [oldId] });
        assert(await CascadeLink.exists({ _id: linkId }));
        const held = await state();
        assert.equal(held.classicLifecycleAttempt.action, 'link.delete');
        assert.equal(held.classicLifecycleAttempt.phase, 'dispatching');
        assert.equal(held.replacementReservation.ownerToken, `classic-deploy:${held.classicLifecycleAttempt.operationId}`);
        return removalReceipt();
    });
    assert.deepEqual(await s.deleteLink(deletion()), { revision: 5, deployedRevision: 0 });
    assert.equal(await CascadeLink.exists({ _id: linkId }), null);
    assert(await CascadeLink.exists({ _id: oldId }));
    assert.equal(await models.CascadeRouteGroup.exists({ _id: groupId }), null);
    const row = await state();
    assert.equal(row.revision, 5); assert.equal(row.deployedRevision, 0);
    assert.equal(row.replacementReservation, undefined); assert.equal(row.classicLifecycleAttempt, undefined);
    assert.equal(row.classicLifecycleLastSettlement.action, 'link.delete');
    assert.equal(row.classicLifecycleLastSettlement.revision, 5); assert.equal(calls, 1);
});

test('real Mongo DELETE rollback after draft deletion restores link/groups and retains exact ownership', local, async () => {
    await reset({ group: true });
    const original = models.CascadeTopologyState.findOneAndUpdate;
    const beforeLinks = await CascadeLink.find().lean(), beforeGroups = await models.CascadeRouteGroup.find().lean();
    models.CascadeTopologyState.findOneAndUpdate = function(filter, update, options) {
        if (update.$unset && options.session) return { async lean() { return null; } };
        return original.call(this, filter, update, options);
    };
    try {
        await assert.rejects(removalService().deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
    } finally { models.CascadeTopologyState.findOneAndUpdate = original; }
    assert.deepEqual(await CascadeLink.find().lean(), beforeLinks);
    assert.deepEqual(await models.CascadeRouteGroup.find().lean(), beforeGroups);
    const row = await state(); assert.equal(row.revision, 4);
    assert.equal(row.classicLifecycleAttempt.action, 'link.delete'); assert.equal(row.classicLifecycleAttempt.phase, 'dispatching');
    assert.equal(row.replacementReservation.ownerToken, `classic-deploy:${row.classicLifecycleAttempt.operationId}`);
    assert.equal(row.classicLifecycleLastSettlement, undefined); assert.equal(calls, 1);
});

test('real Mongo DELETE unknown remote result survives reconstruction and blocks both successors', local, async () => {
    await reset();
    await assert.rejects(removalService(async () => ({ success: true })).deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    const held = await state();
    await assert.rejects(removalService().deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_BUSY' });
    await assert.rejects(service().queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
    assert.deepEqual(await state(), held); assert(await CascadeLink.exists({ _id: linkId })); assert.equal(calls, 1);
});

test('real Mongo DELETE lost postcommit acknowledgement preserves durable settlement without redispatch', local, async () => {
    await reset();
    const connection = models.CascadeTopologyState.db;
    const original = connection.transaction;
    let transactions = 0;
    connection.transaction = async function(...args) {
        const result = await original.apply(this, args);
        if (++transactions === 2) throw Error('simulated lost settlement acknowledgement');
        return result;
    };
    try {
        await assert.rejects(removalService().deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    } finally { connection.transaction = original; }
    const row = await state();
    assert.equal(row.revision, 5); assert.equal(row.replacementReservation, undefined);
    assert.equal(row.classicLifecycleLastSettlement.action, 'link.delete');
    assert.equal(await CascadeLink.exists({ _id: linkId }), null);
    await assert.rejects(removalService().deleteLink({ ...deletion(), expectedTopologyRevision: 5 }), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    assert.equal((await state()).replacementEpoch, 1); assert.equal(calls, 1);
});

test('real Mongo DELETE pending link stays present and excludes competing apply/delete during remote work', local, async () => {
    await reset();
    const s = removalService(async () => {
        assert(await CascadeLink.exists({ _id: linkId }));
        await assert.rejects(removalService().deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_BUSY' });
        await assert.rejects(service().queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
        return removalReceipt();
    });
    assert.deepEqual(await s.deleteLink(deletion()), { revision: 5, deployedRevision: 0 }); assert.equal(calls, 1);
});

test('real Mongo DELETE installed state, stale revision and owner veto never acquire a new fence', local, async () => {
    await reset({ installed: true, group: true });
    await assert.rejects(removalService().deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_IN_USE' });
    assert.equal((await state()).replacementEpoch, 0);
    await reset();
    await assert.rejects(removalService().deleteLink({ ...deletion(), expectedTopologyRevision: 3 }), { code: 'STALE_TOPOLOGY_REVISION' });
    await assert.rejects(removalService(undefined, { topologyManagesNodeConfig: async () => true }).deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_OWNER_VETO' });
    assert.equal((await state()).replacementEpoch, 0); assert.equal(calls, 0);
});

test('real Mongo select:false grant is explicitly selected by the service', local, async () => {
    await reset();
    // Dependency-schema fixture models the separately owned server-only field;
    // no global schema or production model is changed by this projection probe.
    const schema = CascadeLink.schema.clone();
    schema.add({ classicLifecycleGrant: { type: String, select: false } });
    const ProjectedLink = mongoose.model('ClassicLifecycleProjectedLinkFixture', schema, CascadeLink.collection.name);
    const link = await CascadeLink.findById(linkId).lean();
    await CascadeLink.collection.updateOne({ _id: link._id }, { $set: {
        classicLifecycleGrant: issueClassicLifecycleGrant(link, lifecycleEnv),
    } });
    assert.equal((await ProjectedLink.findById(linkId).lean()).classicLifecycleGrant, undefined);
    const s = createClassicScopedCascadeDeploymentService({ ...models, CascadeLink: ProjectedLink, env: lifecycleEnv,
        cascadeService: { async deployScopedClassicLink() { calls++; return receipt(); } } });
    assert.equal((await s.queue(input())).status, 'succeeded'); assert.equal(calls, 1);
});

test('real Mongo DELETE postcommit readback failure reports refusal without inventing a second remote attempt', local, async () => {
    await reset();
    const original = models.CascadeTopologyState.findOne;
    models.CascadeTopologyState.findOne = function(filter) {
        const q = original.call(this, filter);
        if (filter['classicLifecycleLastSettlement.operationId']) q.lean = async () => { throw Error('injected readback loss'); };
        return q;
    };
    try {
        await assert.rejects(removalService().deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    } finally { models.CascadeTopologyState.findOne = original; }
    const row = await state();
    assert.equal(row.revision, 5); assert.equal(row.classicLifecycleLastSettlement.action, 'link.delete');
    assert.equal(row.replacementReservation, undefined); assert.equal(await CascadeLink.exists({ _id: linkId }), null);
    assert.equal(calls, 1);
});

test('real Mongo DELETE current grant is reverified under fence before dispatch', local, async () => {
    await reset();
    const link = await CascadeLink.findById(linkId).lean();
    await CascadeLink.collection.updateOne({ _id: link._id }, { $set: {
        classicLifecycleGrant: issueClassicLifecycleGrant(link, lifecycleEnv),
    } });
    const connection = models.CascadeTopologyState.db, original = connection.transaction;
    connection.transaction = async function(...args) {
        const result = await original.apply(this, args);
        await CascadeLink.collection.updateOne({ _id: link._id }, { $unset: { classicLifecycleGrant: '' } });
        return result;
    };
    try {
        await assert.rejects(removalService(undefined, { env: lifecycleEnv }).deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    } finally { connection.transaction = original; }
    assert.equal(calls, 0); assert(await CascadeLink.exists({ _id: linkId }));
    assert((await state()).replacementReservation); assert((await state()).classicLifecycleAttempt);
});

test('real Mongo durable saved grant supports manual replay, checked DELETE and separately saved recreation', local, async () => {
    await reset();
    const originalLink = await CascadeLink.findById(linkId).lean();
    await CascadeLink.collection.updateOne({ _id: originalLink._id }, { $set: {
        classicLifecycleGrant: issueClassicLifecycleGrant(originalLink, lifecycleEnv),
    } });
    const make = revision => createClassicScopedCascadeDeploymentService({ ...models, env: lifecycleEnv,
        cascadeService: {
            async deployScopedClassicLink() { calls++; const r = receipt(); r.receipt.topologyRevision = revision; return r; },
            async removeScopedClassicLink() { calls++; const r = removalReceipt(); r.receipt.topologyRevision = revision; return r; },
        } });
    await make(4).queue(input());
    await make(4).queue(input());
    assert.deepEqual(await make(4).deleteLink(deletion()), { revision: 5, deployedRevision: 0 });
    assert.equal(await CascadeLink.exists({ _id: linkId }), null);
    // Model the parent-owned atomic draft save, not an HTTP/create implementation.
    await models.CascadeTopologyState.db.transaction(async session => {
        const recreated = { ...originalLink, status: 'pending' };
        delete recreated.__v;
        recreated.classicLifecycleGrant = issueClassicLifecycleGrant(recreated, lifecycleEnv);
        await CascadeLink.collection.insertOne(recreated, { session });
        const update = await models.CascadeTopologyState.updateOne({ _id: 'singleton', revision: 5,
            replacementReservation: { $exists: false } }, { $inc: { revision: 1 } }, { session });
        assert.equal(update.modifiedCount, 1);
    });
    assert.equal((await make(6).queue({ ...input(), expectedTopologyRevision: 6 })).status, 'succeeded');
    assert.deepEqual(await make(6).deleteLink({ ...deletion(), expectedTopologyRevision: 6 }), { revision: 7, deployedRevision: 0 });
    assert.equal(calls, 5); assert.equal((await state()).replacementEpoch, 5);
    assert(await CascadeLink.exists({ _id: oldId }));
});
