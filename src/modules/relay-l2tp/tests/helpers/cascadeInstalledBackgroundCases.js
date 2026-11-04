'use strict';
// Bounded joined scenarios, reusing the existing background/runtime and
// installed service/gate adapters. No topology success or sidecar is seeded.
module.exports = function installedBackgroundCases({ test, assert, assembled, withEnv, request, settleTick, id, copy, key, MAIN, BRIDGE,
    randomUUID, modeledInstalledMain, configEffects, deferred }) {
    async function create(f, target = id(2), extra = {}) {
        const reply = await request(f.http, 'POST', '/links', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
            name: 'installed native suffix', portalNodeId: id(1), bridgeNodeId: target, mode: 'reverse',
            tunnelPort: target === id(2) ? 25201 : 25204, tunnelSecurity: 'none', autoDeploy: true, ...extra }, randomUUID());
        assert.equal(reply.status, 202, JSON.stringify(reply.body));
        const job = f.data.TopologyCreateIntent.find(row => row._id === reply.body.job.jobId);
        return { jobId: job._id, linkId: job.linkId };
    }
    const group = f => f.data.CascadeRouteGroup.find(row => row._id === id(60));
    const config = f => JSON.parse(f.files.get(key(id(1), BRIDGE)));
    function settledLink(f, linkId) {
        const owner = f.data.TopologyConfigOwner.find(row => row.node === id(1) && row.profile === 'xray-bridge');
        const operation = f.data.TopologyOperation.find(row => row._id === owner?.lastSettledOperation);
        assert.equal(operation?.status, 'succeeded');
        const link = operation.effectiveTopology.links.find(row => row.id === linkId);
        assert.ok(link, 'applied descriptor must come from the actual settled owner, not a missing link-local field');
        return copy(link);
    }
    function chooseMainPath(f, pathKey) {
        // External installed MAIN/state selection is explicitly modeled;
        // sidecar listeners/rules still require actual job publication.
        f.installed.state.activePathKey = pathKey;
        f.files.set(key(id(1), MAIN), JSON.stringify(modeledInstalledMain(f.installed.state)));
    }
    async function background(f) {
        const files = copy(f.nativeFiles()), groups = copy(f.data.CascadeRouteGroup), users = copy(f.data.L2tpUser);
        const states = copy(f.data.RelayL2tpState), locks = copy(f.data.NodeOperationLock);
        assert.equal((await f.bg.logs.reconcileNode(f.data.HyNode[1], f.bg.settings)).status, 'error');
        assert.equal(f.data.HyNode[1].xray.accessLogs.appliedFingerprint, undefined);
        assert.equal(await f.bg.sync.updateXrayNodeConfig(f.data.HyNode[0]), true);
        await f.bg.cascade.healthCheckAll();
        const result = await f.maintenance(); // actual function, NOT HTTP's no-op hook
        assert.equal(result.updated, 0); assert.equal(result.revision, null);
        assert.ok(result.deferred.every(entry => ['CHAIN_INCOMPLETE', 'REPLACEMENT_REQUIRES_PREPARED_INGRESS'].includes(entry.reason)), JSON.stringify(result));
        assert.deepEqual(f.data.CascadeRouteGroup, groups);
        assert.deepEqual(f.data.RelayL2tpState, states); assert.deepEqual(f.data.L2tpUser, users);
        assert.deepEqual(f.data.NodeOperationLock, locks); assert.deepEqual(f.nativeFiles(), files);
        assert.equal(f.pending.status, 'pending');
        for (const node of f.topology.nodes) assert.deepEqual(configEffects(f, node.id), []);
        return result;
    }
    test('installed PPP public jobs delete-to-blocked/recreate preserve nonempty users, epochs and produced geo peer during actual background calls', { timeout: 10000 }, async () => withEnv(async () => {
        const f = await assembled({ installed: true }), entered = deferred(), release = deferred();
        let tick;
        try {
            assert.equal(f.data.TopologyOperation.length, 0);
            assert.equal(f.files.get(key(id(1), BRIDGE)), '{}', 'no seeded current sidecar/profile success');
            const keptUsers = copy(f.data.L2tpUser), keptSync = copy(f.data.L2tpOperation), keptState = copy(f.installed.state);
            assert.equal(keptUsers.length, 1); assert.equal(keptUsers[0].desiredRevision, 41);
            group(f).paths.find(row => row.pathKey === 'peer').enabled = true;
            chooseMainPath(f, 'peer');
            const peer = await create(f, id(4)); await f.drain(peer.jobId);
            assert.deepEqual(group(f).paths.find(row => row.pathKey === 'peer').linkIds, [peer.linkId]);
            chooseMainPath(f, 'mine');
            const policy = { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
                geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] }, autoDeploy: true };
            const editKey = randomUUID(), appliedBefore = copy(f.nativeFiles()), groupBefore = copy(group(f));
            const priorOwners = copy(f.data.TopologyConfigOwner), priorOperations = f.data.TopologyOperation.length;
            const oldDescriptor = settledLink(f, peer.linkId), priorGateCount = f.installed.options.gateCalls.length;
            assert.notEqual(oldDescriptor.geoRouting?.enabled, true);
            const geo = await request(f.http, 'PUT', `/links/${peer.linkId}`, policy, editKey);
            assert.equal(geo.status, 202, JSON.stringify(geo.body));
            assert.equal(geo.body.desiredSaved, true); assert.equal(geo.body.job.kind, 'link.apply');
            assert.deepEqual(f.nativeFiles(), appliedBefore); assert.deepEqual(group(f), groupBefore);
            assert.deepEqual(f.data.TopologyConfigOwner, priorOwners);
            assert.equal(f.data.TopologyOperation.length, priorOperations, 'PUT admits desired+intent, never dispatches');
            const desired = f.data.CascadeLink.find(row => row._id === peer.linkId);
            assert.deepEqual(desired.geoRouting, policy.geoRouting); assert.deepEqual(settledLink(f, peer.linkId), oldDescriptor);
            const replay = await request(f.http, 'PUT', `/links/${peer.linkId}`, { ...policy, expectedTopologyRevision: 0 }, editKey);
            assert.deepEqual(replay.body.job, geo.body.job);
            const editEntered = deferred(), editRelease = deferred();
            // Always release this finite hold if an assertion above dispatch fails.
            release.promise.then(() => editRelease.resolve());
            f.setPause(async () => { editEntered.resolve(); await editRelease.promise; });
            tick = f.timer.tick(); await editEntered.promise;
            assert.deepEqual(f.nativeFiles(), appliedBefore); assert.deepEqual(group(f), groupBefore);
            assert.deepEqual(f.data.TopologyConfigOwner, priorOwners);
            assert.ok(f.data.NodeOperationLock.length > 0);
            editRelease.resolve(); await tick; tick = undefined; f.setPause(undefined);
            const appliedEdit = await f.drain(geo.body.job.jobId);
            assert.ok(oldDescriptor.tunnelUuid, 'the pre-existing transport key is nonempty');
            assert.deepEqual(settledLink(f, peer.linkId), { ...oldDescriptor, geoRouting: policy.geoRouting });
            assert.equal(appliedEdit.installedPath.ownerCredentialRevision, 41);
            const newGateCalls = f.installed.options.gateCalls.slice(priorGateCount);
            assert.ok(newGateCalls.includes('ingress') && newGateCalls.includes('users'));
            assert.deepEqual(f.data.L2tpUser, keptUsers);
            const readback = await request(f.http, 'GET', `/links/auto-deploy-jobs/${geo.body.job.jobId}`);
            assert.equal(readback.status, 200); assert.equal(readback.body.job.status, 'succeeded');
            const finishedReplay = await request(f.http, 'PUT', `/links/${peer.linkId}`, policy, editKey);
            assert.equal(finishedReplay.body.job.jobId, geo.body.job.jobId);
            assert.equal(finishedReplay.body.job.status, 'succeeded');
            const target = await create(f); await f.drain(target.jobId);
            await background(f);
            const before = config(f), protectedPeer = copy(group(f).paths.find(row => row.pathKey === 'peer'));
            const peerRules = before.routing.rules.filter(row => row.inboundTag?.includes('cascade-peer'));
            assert.ok(peerRules.length > 0);
            const geoRules = before.routing.rules.filter(row => row.ip?.includes('geoip:ru') || row.domain?.includes('geosite:category-ru'));
            assert.ok(geoRules.length > 0, 'real geo policy is installed');
            f.setPause(async () => { entered.resolve(); await release.promise; });
            const deletion = await f.accept(target.linkId, 'DELETE'); tick = f.timer.tick(); await entered.promise;
            const held = copy(f.data.NodeOperationLock), owners = copy(f.data.TopologyConfigOwner);
            assert.ok(held.length > 0);
            assert.ok((await background(f)).deferred.length > 0, 'maintenance cannot publish inferred path during held operation');
            assert.deepEqual(f.data.TopologyConfigOwner, owners);
            assert.deepEqual(group(f).paths.find(row => row.pathKey === 'mine').linkIds, [target.linkId]);
            release.resolve(); await tick; f.setPause(undefined);
            const deleted = await f.drain(deletion), blocked = config(f);
            assert.equal(deleted.kind, 'link.delete');
            assert.deepEqual(group(f).paths.find(row => row.pathKey === 'mine').linkIds, []);
            assert.deepEqual(blocked.routing.rules.filter(row => row.inboundTag?.includes('cascade-mine')),
                [{ type: 'field', inboundTag: ['cascade-mine'], outboundTag: 'block' }]);
            assert.deepEqual(blocked.inbounds.filter(row => row.tag === 'cascade-peer'), before.inbounds.filter(row => row.tag === 'cascade-peer'));
            assert.deepEqual(blocked.routing.rules.filter(row => row.inboundTag?.includes('cascade-peer')), peerRules);
            assert.deepEqual(group(f).paths.find(row => row.pathKey === 'peer'), protectedPeer);
            assert.equal(f.installed.options.prepares.at(-1).pppInternetProof, 'not_applicable');
            await background(f);
            const recreated = await create(f); await f.drain(recreated.jobId);
            assert.notEqual(recreated.linkId, target.linkId);
            const after = config(f);
            for (const pathKey of ['mine', 'peer']) assert.equal(after.inbounds.filter(row => row.tag === `cascade-${pathKey}`).length, 1);
            assert.deepEqual(after.routing.rules.filter(row => row.inboundTag?.includes('cascade-peer')), peerRules);
            assert.equal(after.routing.rules.some(row => row.inboundTag?.includes('cascade-mine') && row.outboundTag === 'block'), false);
            await background(f);
            assert.deepEqual(f.data.L2tpUser, keptUsers); assert.deepEqual(f.data.L2tpOperation, keptSync);
            for (const field of ['secretRevision', 'pskEncrypted', 'clientCidr', 'localAddress', 'poolStart', 'poolEnd', 'dnsServers', 'routeGroup', 'activePathKey'])
                assert.deepEqual(f.installed.state[field], keptState[field]);
            assert.ok(f.installed.options.gateCalls.includes('ingress') && f.installed.options.gateCalls.includes('users'));
            assert.equal(f.installed.options.prepares.at(-1).pppInternetProof, 'unverified');
            assert.equal(f.data.NodeOperationLock.length, 0);
        } finally { release.resolve(); if (tick) await tick; await f.close(); }
    }));
    test('installed policy save-only stays unapplied through background ticks until explicit public Deploy', { timeout: 10000 }, async () => withEnv(async () => {
        const f = await assembled({ installed: true });
        try {
            const target = await create(f); await f.drain(target.jobId);
            const files = copy(f.nativeFiles()), groups = copy(f.data.CascadeRouteGroup), owners = copy(f.data.TopologyConfigOwner);
            const users = copy(f.data.L2tpUser), state = copy(f.data.RelayL2tpState);
            const priorJobs = f.data.TopologyCreateIntent.length, priorOps = f.data.TopologyOperation.length;
            const linkBefore = settledLink(f, target.linkId);
            const saved = await request(f.http, 'PUT', `/links/${target.linkId}`, {
                expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
                geoRouting: { enabled: true, domains: ['saved.invalid'], geoip: ['ru'] }, priority: 23,
            }, randomUUID());
            assert.equal(saved.status, 200, JSON.stringify(saved.body));
            assert.equal(saved.body.desiredSaved, true); assert.equal(saved.body.job, undefined);
            assert.equal(f.data.CascadeLink.find(row => row._id === target.linkId).autoDeploy, true, 'persisted metadata is not opt-in');
            assert.deepEqual(f.data.CascadeLink.find(row => row._id === target.linkId).geoRouting,
                { enabled: true, domains: ['saved.invalid'], geoip: ['ru'] });
            for (let i = 0; i < 3; i++) await settleTick(f);
            await background(f);
            assert.equal(f.data.TopologyCreateIntent.length, priorJobs); assert.equal(f.data.TopologyOperation.length, priorOps);
            assert.deepEqual(f.nativeFiles(), files); assert.deepEqual(f.data.CascadeRouteGroup, groups);
            assert.deepEqual(f.data.TopologyConfigOwner, owners); assert.deepEqual(f.data.RelayL2tpState, state);
            assert.deepEqual(settledLink(f, target.linkId), linkBefore);
            const operation = await f.drain(await f.accept(target.linkId));
            assert.deepEqual(operation.effectiveTopology.links.find(row => row.id === target.linkId).geoRouting,
                { enabled: true, domains: ['saved.invalid'], geoip: ['ru'] });
            assert.deepEqual(config(f).routing.rules.filter(row => row.inboundTag?.includes('cascade-mine')),
                [{ type: 'field', inboundTag: ['cascade-mine'], outboundTag: 'block' }]);
            assert.deepEqual(group(f).paths.find(row => row.pathKey === 'mine').linkIds, [], 'a geo-only exit never becomes a default');
            assert.equal(f.installed.options.prepares.at(-1).pppInternetProof, 'not_applicable');
            assert.deepEqual(f.data.L2tpUser, users);
        } finally { await f.close(); }
    }));
    for (const failure of ['unknown-users', 'main-readback', 'credential-epoch']) test(`installed public policy PUT ${failure} cannot publish after dispatch`, { timeout: 10000 }, async () => withEnv(async () => {
        const f = await assembled({ installed: true });
        try {
            const target = await create(f); await f.drain(target.jobId);
            // Model a changed desired epoch, NOT successful credential readback:
            // the fixed node observation and PPP sync still report epoch 41.
            if (failure === 'credential-epoch') f.installed.state.secretRevision = 42;
            const groups = copy(f.data.CascadeRouteGroup), owners = copy(f.data.TopologyConfigOwner);
            const users = copy(f.data.L2tpUser), state = copy(f.data.RelayL2tpState);
            const applied = settledLink(f, target.linkId);
            if (failure === 'unknown-users') f.installed.options.onUsers = () => { throw Error('modeled unknown user-runner readback'); };
            else if (failure === 'main-readback') f.installed.options.changeMain = main => { main.routing.rules = []; };
            const reply = await request(f.http, 'PUT', `/links/${target.linkId}`, {
                expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
                geoRouting: { enabled: true, domains: ['failed.invalid'], geoip: [] }, autoDeploy: true,
            }, randomUUID());
            assert.equal(reply.status, 202, JSON.stringify(reply.body));
            for (let i = 0; i < 3; i++) await settleTick(f);
            const job = f.data.TopologyCreateIntent.find(row => row._id === reply.body.job.jobId);
            const op = f.data.TopologyOperation.find(row => row._id === job.operationId);
            assert.equal(op.status, 'committing'); assert.equal(op.heldTopologyAdmission, true);
            if (failure === 'credential-epoch') assert.equal(op.installedPath.ownerCredentialRevision, 42);
            assert.ok(op.nodes.every(row => row.state === 'committed'));
            const locks = copy(f.data.NodeOperationLock); assert.ok(locks.length > 0);
            assert.ok(locks.every(row => row.remoteUncertain && row.operationId === op._id));
            assert.deepEqual(f.data.CascadeRouteGroup, groups); assert.deepEqual(f.data.TopologyConfigOwner, owners);
            assert.deepEqual(f.data.L2tpUser, users); assert.deepEqual(f.data.RelayL2tpState, state);
            assert.deepEqual(settledLink(f, target.linkId), applied);
            assert.notEqual(job.status, 'succeeded'); await background(f); assert.deepEqual(f.data.NodeOperationLock, locks);
        } finally { await f.close(); }
    }));
    test('installed public policy PUT known verification failure restores old bytes without publishing desired policy', { timeout: 10000 }, async () => withEnv(async () => {
        const f = await assembled({ installed: true });
        try {
            const target = await create(f); await f.drain(target.jobId);
            const files = copy(f.nativeFiles()), groups = copy(f.data.CascadeRouteGroup), owners = copy(f.data.TopologyConfigOwner);
            const users = copy(f.data.L2tpUser), state = copy(f.data.RelayL2tpState), applied = settledLink(f, target.linkId);
            f.failVerify = true;
            const reply = await request(f.http, 'PUT', `/links/${target.linkId}`, {
                expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
                geoRouting: { enabled: true, domains: ['rolled-back.invalid'], geoip: [] }, autoDeploy: true,
            }, randomUUID());
            assert.equal(reply.status, 202, JSON.stringify(reply.body));
            await f.drain(reply.body.job.jobId, 'rolled_back');
            assert.deepEqual(f.nativeFiles(), files); assert.deepEqual(f.data.CascadeRouteGroup, groups);
            assert.deepEqual(f.data.TopologyConfigOwner, owners); assert.deepEqual(f.data.RelayL2tpState, state);
            assert.deepEqual(f.data.L2tpUser, users); assert.deepEqual(settledLink(f, target.linkId), applied);
            assert.equal(f.data.CascadeLink.find(row => row._id === target.linkId).geoRouting.enabled, true, 'failed apply does not erase saved desired');
            assert.ok(f.calls.some(([kind]) => kind === 'rollback')); await background(f);
        } finally { await f.close(); }
    }));
    for (const failure of ['unknown-users', 'main-readback']) test(`installed PPP ${failure} after actual dispatch refuses publication and retains generations`, { timeout: 5000 }, async () => withEnv(async () => {
        const f = await assembled({ installed: true });
        try {
            const target = await create(f); await f.drain(target.jobId);
            const beforeGroup = copy(group(f)), users = copy(f.data.L2tpUser), state = copy(f.data.RelayL2tpState);
            const owners = copy(f.data.TopologyConfigOwner);
            if (failure === 'unknown-users') f.installed.options.onUsers = () => { throw Error('modeled unknown user-runner readback'); };
            else f.installed.options.changeMain = main => { main.routing.rules = []; };
            const jobId = await f.accept(target.linkId, 'DELETE');
            for (let i = 0; i < 3; i++) await settleTick(f);
            const job = f.data.TopologyCreateIntent.find(row => row._id === jobId);
            const op = f.data.TopologyOperation.find(row => row._id === job.operationId);
            assert.equal(op.status, 'committing'); assert.equal(op.heldTopologyAdmission, true);
            assert.ok(op.nodes.every(row => row.state === 'committed'), 'failure reaches actual post-dispatch gate');
            const locks = copy(f.data.NodeOperationLock); assert.ok(locks.length > 0);
            assert.ok(locks.every(row => row.operationId === op._id && row.remoteUncertain));
            assert.deepEqual(group(f), beforeGroup); assert.deepEqual(f.data.TopologyConfigOwner, owners);
            assert.deepEqual(f.data.L2tpUser, users); assert.deepEqual(f.data.RelayL2tpState, state);
            assert.equal(f.data.CascadeLink.find(row => row._id === target.linkId).lifecycle.deleteJobId, jobId);
            await background(f); assert.deepEqual(f.data.NodeOperationLock, locks);
            assert.notEqual(job.status, 'succeeded');
        } finally { await f.close(); }
    }));
};
