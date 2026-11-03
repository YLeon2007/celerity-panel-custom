'use strict';
// Real private Mongo replica set and production lock/repository implementations.
// SSH preview and the remote core are explicitly modeled; no physical claims.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const fixturePath = path.resolve(__dirname, 'classicScopedCascadeDeploymentMongo.test.js');
const text = fs.readFileSync(fixturePath, 'utf8');
const boundary = "test('real Mongo occupied source port";
assert.equal(text.split(boundary).length, 2);
const fixture = new Module(fixturePath, module);
fixture.filename = fixturePath; fixture.paths = Module._nodeModulePaths(path.dirname(fixturePath));
fixture._compile(text.split(boundary)[0] + `\nmodule.exports = { get models(){return models}, reset, state, receipt, input, source, bridge, otherPortal, linkId, oldId, env, mongoose, HyNode, CascadeLink };`, fixturePath);
const f = fixture.exports;
const { createClassicScopedCascadeDeploymentService } = require('../classicScopedCascadeDeploymentService');
const { createClassicPortalBridgePhase } = require('../classicPortalBridgePhase');
const { AsyncResource } = require('node:async_hooks');
const { createTopologyDraftWriteService } = require('../../modules/relay-l2tp/services/topologyDraftWriteService');
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to a private disposable MongoDB binary' };
const outside = '507f1f77bcf86cd799439040';
class Preview {
    async connect() { assert.equal(await f.models.NodeOperationLock.countDocuments({ node: { $in: [f.source, f.bridge, f.otherPortal] } }), 3); }
    disconnect() {}
    async exec(command) {
        assert.doesNotMatch(command, /\.stage|restart|ufw|firewall-cmd|\bmv\b/);
        const marker = command.match(/C3_PORT_READ_[a-f0-9]+/)[0];
        const value = command.includes('C3_READ_CONFIG') ? JSON.stringify({ inbounds: [] }) : '';
        return { code: 0, stdout: `${value}\n${marker}\n`, stderr: '' };
    }
}
async function setup() {
    await f.reset();
    await f.HyNode.updateMany({ _id: { $in: [f.source, f.otherPortal] } }, { $set: { cascadeRole: 'portal' } });
    await f.HyNode.collection.insertOne({ _id: new f.mongoose.Types.ObjectId(outside), name: 'disjoint-private-fixture', type: 'xray', active: true, cascadeRole: 'relay', ip: '192.0.2.40', ssh: { password: 'fixture-only' } });
    await f.models.NodeOperationLock.collection.insertOne({ node: new f.mongoose.Types.ObjectId(outside), owner: 'fixture-unrelated', operationId: 'fixture-unrelated-op', generation: 'fixture-unrelated-generation', remoteUncertain: true, leaseUntil: new Date(Date.now() + 120000) });
    await f.models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' }, { $set: { replacementEpoch: 9, topologyAdmissionCount: 2, remoteAdmissionCount: 7, replacementReservation: { ownerToken: 'fixture-unrelated', epoch: 9 } } });
}
function service(work) {
    return createClassicScopedCascadeDeploymentService({ ...f.models, env: f.env, NodeSSH: Preview,
        cascadeService: { async deployScopedClassicLink(args) { return work(args); } } });
}
async function foreign() { return f.models.NodeOperationLock.findOne({ node: outside }).lean(); }
test('native Mongo independent apply preserves unrelated busy state and locks across an unrelated revision change', local, async () => {
    await setup(); const before = await f.state(), lock = await foreign();
    const result = await service(async args => {
        await args.scopedExecutionContext.verify();
        assert.equal(await f.models.NodeOperationLock.countDocuments(), 4);
        await f.models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $inc: { revision: 1 } }, { timestamps: false });
        await args.scopedExecutionContext.verify();
        return f.receipt();
    }).queue(f.input());
    assert.deepEqual(result, { status: 'succeeded', executionMode: 'classic', topologyRevision: 4 });
    assert.deepEqual(await f.state(), { ...before, revision: 5 });
    assert.deepEqual(await foreign(), lock);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
});
test('native Mongo same-component conflict leaves the competing and disjoint generations intact', local, async () => {
    await setup(); const state = await f.state(), lock = await foreign(); let called = false;
    await f.models.NodeOperationLock.collection.insertOne({ node: new f.mongoose.Types.ObjectId(f.bridge), owner: 'fixture-other-writer', operationId: 'fixture-same-node', generation: 'fixture-same-generation', remoteUncertain: true, leaseUntil: new Date(Date.now() + 120000) });
    const other = await f.models.NodeOperationLock.findOne({ node: f.bridge }).lean();
    await assert.rejects(service(async () => { called = true; return f.receipt(); }).queue(f.input()), { code: 'CLASSIC_DEPLOY_NODE_BUSY' });
    assert.equal(called, false); assert.deepEqual(await f.state(), state);
    assert.deepEqual(await foreign(), lock);
    assert.deepEqual(await f.models.NodeOperationLock.findOne({ node: f.bridge }).lean(), other);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 2);
});
test('native Mongo private core no-write provenance releases only this component, allowing retry', local, async () => {
    await setup(); const state = await f.state(), lock = await foreign();
    await assert.rejects(service(async args => {
        throw createClassicPortalBridgePhase({ beforeRemoteMutation: args.beforeRemoteMutation }).failure(Object.assign(new Error('modeled private preview failure'), { code: 'CLASSIC_SCOPED_SERVICE_LAYOUT_UNSUPPORTED' }));
    }).queue(f.input()), { code: 'CLASSIC_DEPLOY_PREFLIGHT_FAILED' });
    assert.deepEqual(await f.state(), state); assert.deepEqual(await foreign(), lock);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
    assert.equal((await service(async () => f.receipt()).queue(f.input())).status, 'succeeded');
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
});
test('native Mongo independent request cannot edit a deployment-held component and receives a safe busy code', local, async () => {
    await setup(); const original = await f.CascadeLink.findById(f.linkId).lean();
    // Represents a separately accepted HTTP request, not trusted reentrant work.
    const request = new AsyncResource('private-independent-draft-request');
    const drafts = createTopologyDraftWriteService({ ...f.models, deploymentEnv: f.env,
        // This case isolates real admission/DB serialization; domain validity is
        // exercised separately by route/physical acceptance, not by these stubs.
        validator: () => ({ valid: true }), compiler: () => ({ valid: true }),
    });
    let draftError;
    try {
        const result = await service(async () => {
            try {
                await request.runInAsyncScope(() => drafts.updateLink({ expectedTopologyRevision: 4,
                    linkId: f.linkId, changes: { name: 'racing edit must not persist' } }));
            } catch (error) { draftError = error; }
            return f.receipt();
        }).queue(f.input());
        assert.equal(result.status, 'succeeded');
        assert.equal(draftError?.code, 'CLASSIC_DEPLOY_NODE_BUSY', draftError?.message);
        assert.deepEqual((await f.CascadeLink.findById(f.linkId).lean()).name, original.name);
        assert.equal(await f.models.NodeOperationLock.countDocuments(), 1);
    } finally { request.emitDestroy(); }
});
test('native Mongo possible remote mutation retains only this component and never the unrelated singleton slot', local, async () => {
    await setup(); const state = await f.state(), lock = await foreign();
    await assert.rejects(service(async args => {
        await args.beforeRemoteMutation({ nodeId: f.source, phase: 'modeled-stage-dispatch' });
        throw new Error('modeled unknown remote outcome');
    }).queue(f.input()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    assert.deepEqual(await f.state(), state); assert.deepEqual(await foreign(), lock);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 4);
    const own = await f.models.NodeOperationLock.find({ node: { $in: [f.source, f.bridge, f.otherPortal] } }).lean();
    assert.equal(own.length, 3); assert.ok(own.every(row => row.remoteUncertain === true));
});
