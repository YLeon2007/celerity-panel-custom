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
        cascadeRole: i ? 'bridge' : 'relay', ip: `192.0.2.${i + 1}`,
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
    assert.equal(calls, 0); assert((await state()).replacementReservation);
});
test('real Mongo positively attributed retained UNINSTALLED group is not installed-path authority', local, async () => {
    await reset({ group: true });
    assert.equal((await service().queue(input())).status, 'succeeded');
    const group = await models.CascadeRouteGroup.findById(groupId).lean(); assert.equal(group.mode, 'forward');
    assert.deepEqual(group.paths[0].linkIds.map(String), [linkId]); assert.equal(calls, 1);
});
test('real Mongo ambiguous owner history vetoes without dispatch', local, async () => {
    await reset(); await mongoose.connection.db.collection('topologyconfigowners').insertOne({ node: new mongoose.Types.ObjectId(source), owner: 'topology', profile: 'xray-main' });
    await assert.rejects(service().queue(input())); assert.equal(calls, 0); assert((await state()).replacementReservation);
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
