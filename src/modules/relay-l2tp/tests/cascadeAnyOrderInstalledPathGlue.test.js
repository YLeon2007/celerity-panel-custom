'use strict';
// Actual selected reader/coordinator/materializer/worker/finalizer; persistence
// and node transport modeled by the shared installed publication fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const { installedFixture, apply, remove } = require('./cascadeAnyOrderInstalledPublication.test');
const { id } = require('./cascadeAnyOrderSelectedApply.test');
for (const mode of ['forward', 'reverse']) test(`installed-path glue carries an absent ${mode} path without inventing old membership`, async () => {
    const f = installedFixture({ absent: true, mode });
    const before = structuredClone(f.group), users = structuredClone(f.users), state = structuredClone(f.state);
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 7,
        scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } });
    const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    assert.deepEqual(f.group, before, 'queue does not publish or fabricate the absent path');
    assert.equal(operation.baselineTopology.groups[0].paths.some(path => path.pathKey === 'mine'), false);
    assert.deepEqual(operation.installedPath.oldPathLinkIds, []);
    assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, [id(10)]);
    const template = structuredClone(f.CascadeLink.rows[0]);
    const deletion = await remove(f, id(10));
    assert.equal((await f.worker.run(deletion.operationId)).status, 'succeeded');
    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, []);
    f.CascadeLink.rows.push({ ...template, status: 'pending', tunnelPort: template.tunnelPort + 100 });
    f.CascadeTopologyState.rows[0].revision++;
    await apply(f, id(10));
    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'peer'), before.paths[0]);
    assert.deepEqual(f.users, users);
    for (const key of ['pskEncrypted', 'secretRevision', 'clientCidr', 'poolStart', 'poolEnd', 'routeGroup', 'activePathKey']) assert.deepEqual(f.state[key], state[key]);
});
