'use strict';
// G4-G7 acceptance through the SAME default host/HTTP/job/consumer/coordinator/
// materializer/worker/finalizer as RuntimeHttp. Persistence, ownership inventory,
// executor and subscription RPC are MODELED. No Mongo/SSH/Xray/PPP traffic proof.
// Run with NODE_PATH pointing at existing deps; C3_ANYORDER_EXTENDED_REPORT may
// name a scratch JSON output. All enumerated cases are attempted; acceptance
// stays RED rather than characterizing unsupported behavior as success.
// G6 has only two distinct edge orders. Repeat-deploy byte/identity checks do
// not prove physical no-restart behavior because the executor is modeled.
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, app, request, settleTick, id, copy, sha, provider } = require('./cascadeAnyOrderRuntimeFixture');
test.after(() => require('../../../services/sshPoolService').closeAll());
const GRAPHS = [
    { name: 'G4', edges: [ ['P1R', 1, 2], ['P2R', 4, 2], ['RB', 2, 3] ],
        orders: { 'input-first': [0, 1, 2], 'output-first': [2, 1, 0], interleaved: [0, 2, 1] } },
    { name: 'G5', edges: [ ['PR1', 1, 2], ['R1R2', 2, 4], ['R2B', 4, 3] ],
        orders: { 'input-first': [0, 1, 2], 'output-first': [2, 1, 0], interleaved: [1, 0, 2] } },
    // G6 has only two edges; the interleaved branch order duplicates input-first.
    // Enumerate its two distinct orders, not three inflated copies.
    { name: 'G6', edges: [ ['P1B', 1, 3], ['P2B', 4, 3] ],
        orders: { 'input-first/interleaved': [0, 1], 'output-first': [1, 0] } },
];
const MODES = ['forward', 'reverse', 'mixed'];
const STRATEGIES = ['auto', 'save-then-manual', 'alternating'];
const MATRIX = GRAPHS.flatMap(graph => Object.entries(graph.orders).flatMap(([orderName, order]) =>
    MODES.flatMap(mode => STRATEGIES.map(strategy => ({ graph, orderName, order, mode, strategy,
        label: `${graph.name}/${orderName}/${mode}/${strategy}` })))));
const credentialPin = link => sha(JSON.stringify(Object.fromEntries(Object.entries(link)
    .filter(([key]) => /^(tunnel|reality|mode|portalNode|bridgeNode)/.test(key)))));
function makeFixture(graph, overrides = {}) {
    const f = fixture({ roles: ['portal', 'relay', 'bridge', 'portal', 'bridge', 'portal', 'bridge'] });
    f.graph = graph;
    if (graph.name === 'G5') {
        f.data.HyNode[3].cascadeRole = 'relay';
        f.data.TopologyConfigOwner[3].profile = 'xray-bridge';
    }
    for (const node of f.data.HyNode.filter(n => n.cascadeRole === 'relay')) {
        f.data.RelayL2tpState.push({ node: node._id, status: 'not_installed', desiredState: 'absent', secretRevision: 0 });
    }
    const host = f.host(typeof overrides === 'function' ? overrides(f) : overrides); provider.installActiveHost(host);
    f.runtimeUsers = Object.fromEntries(f.data.HyNode.map(node => [node._id, [
        { userId: `fixture-user-${node._id}`, xrayUuid: `00000000-0000-4000-8000-${node._id.slice(-12)}` },
    ]]));
    f.usersBefore = copy(f.runtimeUsers); f.userPushes = [];
    f.http = app(f); f.hostInstance = host; f.prepared = []; f.trace = [];
    const accept = host.selectedTopologyIntentService.acceptVersioned.bind(host.selectedTopologyIntentService);
    host.selectedTopologyIntentService.acceptVersioned = async (...args) => {
        try { return await accept(...args); }
        catch (error) { f.trace.push({ acceptance: { code: error.code, message: error.message } }); throw error; }
    };
    const worker = f.deployments[0].operationWorker;
    worker.userResync._syncService = {
        _getUsersForNode: async node => copy(f.runtimeUsers[node._id]),
        addXrayUser: async (node, user) => {
            assert.deepEqual(user, f.usersBefore[node._id][0], 'existing subscription identity is preserved');
            f.userPushes.push(node._id); return true;
        },
    };
    const run = worker.run.bind(worker);
    worker.run = async (...args) => { const result = await run(...args); f.trace.push({ worker: result }); return result; };
    const verifyPlan = worker.pppReadinessGate.verifyPlan.bind(worker.pppReadinessGate);
    worker.pppReadinessGate.verifyPlan = async plan => {
        const result = await verifyPlan(plan);
        f.trace.push({ ppp: result, staged: plan.staged, routeState: plan.routeState }); return result;
    };
    if (f.installedReads) {
        const prepareIngress = worker.installedIngressPreparer;
        worker.installedIngressPreparer = async input => {
            const plan = input.operationPlan;
            const entry = { installed: { kind: plan.kind, routeState: plan.routeState,
                ingressState: require('../services/topologyAttachIngressGate').ownedIngressRouteState(plan),
                ownerNodeId: plan.ownerNodeId, groupId: plan.groupId, pathKey: plan.pathKey,
                linkId: plan.linkId, oldPathLinkIds: plan.oldPathLinkIds, newPathLinkIds: plan.newPathLinkIds,
                ownerRoutingRules: JSON.parse(Buffer.from(plan.nodes.find(node => node.node === plan.ownerNodeId).candidate.bytes)).routing.rules } };
            f.trace.push(entry);
            try { const result = await prepareIngress(input); entry.installed.result = result; return result; }
            catch (error) { entry.installed.errorCode = error.code; entry.installed.message = error.message; throw error; }
        };
    }
    const executor = worker.executor;
    const prepare = executor.prepare.bind(executor);
    executor.prepare = async input => { f.prepared.push(copy(input)); return prepare(input); };
    return f;
}
async function close(f) { provider.clearActiveHost(f.hostInstance); await f.hostInstance.stop(); }
function body(f, edge, mode, autoDeploy = true) {
    const index = f.graph.edges.indexOf(edge);
    return { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
        name: edge[0], portalNodeId: id(edge[1]), bridgeNodeId: id(edge[2]),
        tunnelPort: 24000 + index, tunnelSecurity: 'none',
        mode: mode === 'mixed' ? index % 2 ? 'reverse' : 'forward' : mode, autoDeploy };
}
function diagnostic(f, label) {
    return JSON.stringify({ label, jobs: f.data.TopologyCreateIntent.map(j => ({ id: j._id, status: j.status, errorCode: j.errorCode,
        waitingReason: j.waitingReason, attempts: j.attempts, operationId: j.operationId })),
    operations: f.data.TopologyOperation.map(op => ({ id: op._id, linkId: op.linkId, kind: op.kind,
        status: op.status, phase: op.phase, error: op.error, errorCode: op.errorCode,
        routeState: op.routeState, admission: op.heldTopologyAdmission, nodes: op.nodes?.map(n => ({ node: n.node, status: n.status })) })),
    locks: f.data.NodeOperationLock, trace: f.trace, errors: f.errors, installedReads: f.installedReads,
    ...(f.protectedPin ? { installedProtectedIntact: f.protectedPin() === f.beforeProtectedPin } : {}) });
}
async function drain(f, accepted, label) {
    assert.equal(accepted.status, 202, `${label}: ${JSON.stringify(accepted.body)}`);
    const jobId = accepted.body.job.jobId;
    // Only the actual lifecycle timer consumes, binds and executes this job.
    f.hostInstance.start();
    for (let attempt = 0; attempt < 8; attempt++) {
        await settleTick(f);
        const job = f.data.TopologyCreateIntent.find(row => String(row._id) === jobId);
        if (['succeeded', 'failed', 'blocked'].includes(job?.status)) break;
        if (f.data.TopologyOperation.some(op => op._id === job?.operationId && ['failed', 'rolled_back'].includes(op.status))) {
            await settleTick(f); break;
        }
    }
    const polled = await request(f.http, 'GET', `/links/auto-deploy-jobs/${jobId}`);
    assert.equal(polled.body.job.status, 'succeeded', diagnostic(f, label));
    const operation = f.data.TopologyOperation.find(op => op._id === polled.body.job.operationId);
    assert.equal(operation?.status, 'succeeded', diagnostic(f, label));
    assert.equal(operation.heldTopologyAdmission, false, label);
    assert.equal(f.data.NodeOperationLock.some(lock => lock.operationId === operation._id), false, label);
    assert.deepEqual(f.runtimeUsers, f.usersBefore, 'modeled RPC preserves the installed subscription snapshot');
    if (f.protectedPin) assert.equal(f.protectedPin(), f.beforeProtectedPin, 'installed credential/settings/user/peer fingerprints remain unchanged after each mutation');
    assert.ok(f.prepared.length > 0, 'real worker must reach executor');
    return operation;
}
async function create(f, edge, mode, auto, key) {
    const response = await request(f.http, 'POST', '/links', body(f, edge, mode, auto), sha(key));
    assert.equal(response.status, auto ? 202 : 201, `${key}: ${JSON.stringify(response.body)}`);
    return { response, linkId: auto ? response.body.linkId : response.body.createdLinkId };
}
async function manual(f, linkId, key) {
    return request(f.http, 'POST', '/topology/deploy', {
        expectedTopologyRevision: f.data.CascadeTopologyState[0].revision, linkId,
    }, sha(key));
}
function connectedApplied(f, applied, selected) {
    const links = f.data.CascadeLink.filter(link => applied.has(link._id));
    const ids = new Set([selected]), nodes = new Set();
    const seed = links.find(link => link._id === selected);
    nodes.add(seed.portalNode); nodes.add(seed.bridgeNode);
    let changed;
    do { changed = false; for (const link of links) if (nodes.has(link.portalNode) || nodes.has(link.bridgeNode)) {
        if (!ids.has(link._id)) changed = true;
        ids.add(link._id); nodes.add(link.portalNode); nodes.add(link.bridgeNode);
    } } while (changed);
    return ids;
}
function assertPlanHonesty(operation) {
    if (operation.staged) assert.notEqual(operation.routeState, 'complete');
    assert.notEqual(operation.clientReadiness, 'verified', 'modeled node completion is not client proof');
    if (!operation.staged) return;
    for (const node of operation.nodes) {
        // A genuine terminal bridge may exit; staging can mean only that its
        // portal input is absent. The no-direct contract concerns ingress/transit.
        if (node.role === 'bridge') continue;
        const config = JSON.parse(Buffer.from(node.candidate.bytes));
        assert.equal(config.routing.rules.some(rule => rule.outboundTag === 'direct' && !rule.ip && !rule.domain), false,
            `staged ${node.nodeRef} must not supply unrestricted direct egress`);
    }
}
async function runCreation(c, overrides) {
    const f = makeFixture(c.graph, overrides);
    const created = new Map(), applied = new Set();
    try {
        for (const [position, index] of c.order.entries()) {
            const edge = c.graph.edges[index];
            const auto = c.strategy === 'auto' || c.strategy === 'alternating' && position % 2 === 0;
            const callsBefore = f.calls.length, operationsBefore = f.data.TopologyOperation.length;
            const accepted = await create(f, edge, c.mode, auto, `${c.label}/create/${edge[0]}`);
            assert.equal(f.calls.length, callsBefore, 'HTTP saves/accepts only, never executes synchronously');
            assert.equal(f.data.TopologyOperation.length, operationsBefore, 'HTTP never manually binds a job-operation pair');
            created.set(index, accepted.linkId);
            if (auto) {
                applied.add(accepted.linkId);
                const op = await drain(f, accepted.response, `${c.label}/${edge[0]}`);
                assertPlanHonesty(op);
                assert.deepEqual(new Set(op.effectiveTopology.links.map(link => link.id)), connectedApplied(f, applied, accepted.linkId),
                    'only explicitly applied connected edges may enter candidate');
            } else {
                assert.equal(f.data.CascadeLink.find(link => link._id === accepted.linkId).status, 'pending');
            }
        }
        for (const index of [...c.order].reverse()) {
            const linkId = created.get(index);
            if (applied.has(linkId)) continue;
            const accepted = await manual(f, linkId, `${c.label}/manual/${index}`);
            applied.add(linkId);
            const op = await drain(f, accepted, `${c.label}/manual/${index}`);
            assertPlanHonesty(op);
            assert.deepEqual(new Set(op.effectiveTopology.links.map(link => link.id)), connectedApplied(f, applied, linkId));
        }
        const operation = f.data.TopologyOperation.at(-1);
        assert.equal(operation.routeState, 'complete', diagnostic(f, c.label));
        assert.notEqual(operation.staged, true);
        assert.deepEqual(f.data.CascadeLink.map(link => link.mode), c.order.map(index =>
            c.mode === 'mixed' ? index % 2 ? 'reverse' : 'forward' : c.mode));
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
        const before = new Map(f.data.CascadeLink.map(link => [link._id, credentialPin(link)]));
        const replayKey = `${c.label}/repeat`;
        const repeated = await manual(f, operation.linkId, replayKey);
        const repeatedOperation = await drain(f, repeated, replayKey);
        assert.deepEqual(repeatedOperation.nodes.map(node => [node.node, node.candidateHash]).sort(),
            operation.nodes.map(node => [node.node, node.candidateHash]).sort(), 'repeat Deploy generates the same selected bytes');
        const operationCount = f.data.TopologyOperation.length;
        const replay = await manual(f, operation.linkId, replayKey);
        assert.equal(replay.body.job.jobId, repeated.body.job.jobId, 'same key replays the actual persisted job');
        await drain(f, replay, `${replayKey}/same-key`);
        assert.equal(f.data.TopologyOperation.length, operationCount, 'same key cannot bind a duplicate operation');
        assert.deepEqual(new Map(f.data.CascadeLink.map(link => [link._id, credentialPin(link)])), before);
        assert.equal(f.data.CascadeTopologyState[0].deployedRevision, 3, 'selected lifecycle never invokes fullSync');
        return f;
    } catch (error) { error.lifecycleEvidence = JSON.parse(diagnostic(f, c.label)); await close(f); throw error; }
}

const results = [];
function record(label, error, evidence) {
    const result = { label, status: error ? 'failed' : 'passed', ...(error ? {
        message: error.message, evidence: error.lifecycleEvidence || evidence } : { evidence }) };
    results.push(result);
    if (process.env.C3_ANYORDER_EXTENDED_REPORT) require('node:fs').writeFileSync(process.env.C3_ANYORDER_EXTENDED_REPORT,
        JSON.stringify({ level: 'local HTTP/runtime with modeled persistence/executor/RPC', matrix: ALL_CASE_LABELS, results }, null, 2));
    return result;
}
function firstFailures(failures) {
    const classes = new Map();
    for (const failure of failures) {
        const trace = failure.evidence?.trace || [];
        const ppp = trace.findLast(row => row.ppp);
        const worker = trace.findLast(row => row.worker)?.worker;
        const job = failure.evidence?.jobs?.at(-1);
        const acceptance = trace.findLast(row => row.acceptance)?.acceptance;
        const key = JSON.stringify({ ppp: ppp?.ppp?.reason, routeState: ppp?.routeState,
            worker: worker?.errorCode, job: job?.errorCode || job?.waitingReason, acceptance: acceptance?.code,
            ...(ppp || worker || job?.errorCode || acceptance?.code ? {} : { error: failure.message.split('\n')[0] }) });
        if (!classes.has(key)) classes.set(key, { label: failure.label, error: failure.message });
    }
    return [...classes.values()];
}
test('finite G4-G6 matrix is unique and programmatically enumerated (72 creation cases)', t => {
    assert.equal(MATRIX.length, 72);
    assert.equal(new Set(MATRIX.map(c => c.label)).size, MATRIX.length);
    for (const c of MATRIX) t.diagnostic(c.label);
});
for (const graph of GRAPHS) test(`${graph.name}: all finite creation orders/modes/Auto/manual/alternating via real runtime`, async t => {
    const failures = [], cases = MATRIX.filter(c => c.graph === graph);
    for (const c of cases) {
        try { const f = await runCreation(c); record(c.label, null, JSON.parse(diagnostic(f, c.label))); await close(f); }
        catch (error) { failures.push(record(c.label, error)); }
    }
    t.diagnostic(`${cases.length} executed; ${cases.length - failures.length} passed; ${failures.length} failed`);
    assert.deepEqual(firstFailures(failures), [], 'first attributable failure per runtime class (all cases retained in optional JSON report)');
});

const DELETE_CASES = GRAPHS.flatMap(graph => MODES.flatMap(mode => graph.edges.map(edge => ({ graph, mode, edge,
    label: `${graph.name}/delete-recreate/${mode}/${edge[0]}` }))));
const DELETE_ALL_CASES = GRAPHS.flatMap(graph => MODES.flatMap(mode => ['input-first', 'output-first'].map(direction => ({
    graph, mode, direction, order: direction === 'input-first'
        ? graph.edges.map((_, i) => i) : graph.edges.map((_, i) => i).reverse(),
    label: `${graph.name}/delete-all/${mode}/${direction}`,
}))));
function completeCase(graph, mode) {
    return MATRIX.find(c => c.graph === graph && c.orderName.startsWith('output-first') && c.mode === mode && c.strategy === 'auto');
}
async function remove(f, linkId, label) {
    const pins = new Map(f.data.CascadeLink.filter(link => link._id !== linkId).map(link => [link._id, credentialPin(link)]));
    const accepted = await request(f.http, 'DELETE', `/links/${linkId}`, {
        expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
    }, sha(label));
    assert.equal(accepted.status, 202, `${label}: ${JSON.stringify(accepted.body)}`);
    assert.equal(f.data.CascadeLink.find(link => link._id === linkId).lifecycle.state, 'deleting');
    const executor = f.deployments[0].operationWorker.executor, verify = executor.verify;
    let readbacks = 0;
    executor.verify = async input => {
        assert.ok(f.data.CascadeLink.some(link => link._id === linkId), 'the real finalizer, not HTTP, removes a readback-confirmed tombstone');
        readbacks++; return verify(input);
    };
    let operation;
    try { operation = await drain(f, accepted, label); } finally { executor.verify = verify; }
    assert.equal(operation.kind, 'link.delete');
    assert.ok(readbacks > 0);
    assert.equal(f.data.CascadeLink.some(link => link._id === linkId), false);
    assert.deepEqual(new Map(f.data.CascadeLink.map(link => [link._id, credentialPin(link)])), pins,
        'each edge deletion preserves all sibling tunnel/REALITY credentials');
    assertPlanHonesty(operation);
    return operation;
}
async function exercise(label, work) {
    let f;
    try { f = await work(value => { f = value; }); return record(label, null, JSON.parse(diagnostic(f, label))); }
    catch (error) { return record(label, error, f && JSON.parse(diagnostic(f, label))); }
    finally { if (f) await close(f); }
}
test('finite cleanup enumeration contains every G4-G6 edge and both full-delete directions', t => {
    assert.equal(DELETE_CASES.length, 24); assert.equal(DELETE_ALL_CASES.length, 18);
    for (const c of [...DELETE_CASES, ...DELETE_ALL_CASES]) t.diagnostic(c.label);
});
for (const graph of GRAPHS) test(`${graph.name}: HTTP delete each edge from real applied graph and recreate in every mode`, async t => {
    const outcomes = [];
    for (const c of DELETE_CASES.filter(c => c.graph === graph)) outcomes.push(await exercise(c.label, async retain => {
        const f = await runCreation(completeCase(graph, c.mode)); retain(f);
        const link = copy(f.data.CascadeLink.find(link => link.name === c.edge[0]));
        await remove(f, link._id, c.label);
        const recreated = await create(f, c.edge, c.mode, true, `${c.label}/recreate`);
        assert.notEqual(recreated.linkId, link._id);
        const operation = await drain(f, recreated.response, `${c.label}/recreate`);
        assert.equal(operation.routeState, 'complete');
        assert.deepEqual(new Set(operation.effectiveTopology.links.map(link => link.id)), new Set(f.data.CascadeLink.map(link => link._id)));
        return f;
    }));
    const failures = outcomes.filter(result => result.status === 'failed');
    t.diagnostic(`${outcomes.length} executed; ${outcomes.length - failures.length} passed; ${failures.length} failed`);
    assert.deepEqual(firstFailures(failures), [], 'first attributable real cleanup/recreate failure per class');
});
for (const graph of GRAPHS) test(`${graph.name}: HTTP deletes every edge sequentially in both directions without DB repair`, async t => {
    const outcomes = [];
    for (const c of DELETE_ALL_CASES.filter(c => c.graph === graph)) outcomes.push(await exercise(c.label, async retain => {
        const f = await runCreation(completeCase(graph, c.mode)); retain(f);
        const links = new Map(f.data.CascadeLink.map(link => [link.name, link._id]));
        for (const index of c.order) await remove(f, links.get(graph.edges[index][0]), `${c.label}/${index}`);
        assert.equal(f.data.CascadeLink.length, 0);
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
        assert.deepEqual((await request(f.http, 'GET', '/links')).body.links, []);
        return f;
    }));
    const failures = outcomes.filter(result => result.status === 'failed');
    t.diagnostic(`${outcomes.length} executed; ${outcomes.length - failures.length} passed; ${failures.length} failed`);
    assert.deepEqual(firstFailures(failures), [], 'first attributable real sequential deletion failure per class');
});
for (const graph of GRAPHS) test(`${graph.name}: shared-node pending neighbour and independent applied sibling remain excluded and unchanged`, async () => {
    const f = await runCreation(completeCase(graph, 'mixed'));
    try {
        const peer = ['peer', 6, 7];
        const peerCreated = await create(f, peer, 'reverse', true, `${graph.name}/peer`);
        const peerOp = await drain(f, peerCreated.response, `${graph.name}/peer`);
        const peerBefore = copy(f.data.CascadeLink.find(link => link._id === peerCreated.linkId));
        const peerOwners = copy(f.data.TopologyConfigOwner.filter(row => [id(6), id(7)].includes(row.node)));
        const pending = ['saved-neighbour', 6, graph.name === 'G6' ? 3 : 2];
        const before = { calls: f.calls.length, operations: f.data.TopologyOperation.length, jobs: f.data.TopologyCreateIntent.length };
        const saved = await create(f, pending, 'forward', false, `${graph.name}/pending`);
        assert.equal(f.calls.length, before.calls);
        assert.equal(f.data.TopologyOperation.length, before.operations);
        assert.equal(f.data.TopologyCreateIntent.length, before.jobs);
        const selected = f.data.CascadeLink.find(link => link.name === graph.edges[0][0]);
        const pins = new Map(f.data.CascadeLink.map(link => [link._id, credentialPin(link)]));
        const pushes = f.userPushes.length;
        const operation = await drain(f, await manual(f, selected._id, `${graph.name}/selected-only`), `${graph.name}/selected-only`);
        assert.equal(operation.effectiveTopology.links.some(link => link.id === saved.linkId), false);
        assert.equal(operation.effectiveTopology.links.some(link => link.id === peerCreated.linkId), false);
        assert.equal(operation.nodes.some(node => [id(6), id(7)].includes(node.node)), false);
        assert.equal(f.userPushes.slice(pushes).some(node => [id(6), id(7)].includes(node)), false);
        assert.equal(f.data.CascadeLink.find(link => link._id === saved.linkId).status, 'pending');
        assert.deepEqual(f.data.CascadeLink.find(link => link._id === peerCreated.linkId), peerBefore);
        assert.deepEqual(f.data.TopologyConfigOwner.filter(row => [id(6), id(7)].includes(row.node)), peerOwners);
        assert.equal(peerOp.status, 'succeeded');
        assert.deepEqual(new Map(f.data.CascadeLink.map(link => [link._id, credentialPin(link)])), pins);
        record(`${graph.name}/pending-peer`, null, JSON.parse(diagnostic(f, graph.name)));
    } catch (error) { record(`${graph.name}/pending-peer`, error, JSON.parse(diagnostic(f, graph.name))); throw error; }
    finally { await close(f); }
});

for (const mode of ['forward', 'reverse']) test(`G7 ${mode}: unrelated installed L2TP does not block independent HTTP apply/delete/recreate`, async () => {
    const graph = { name: 'G7', edges: [['independent', 6, 7]] }, f = makeFixture(graph);
    const state = f.data.RelayL2tpState[0];
    Object.assign(state, { status: 'installed', desiredState: 'installed', secretRevision: 9, routeGroup: id(80),
        activePathKey: 'ppp-kept', settingsFingerprint: 'synthetic-settings-pin' });
    f.data.L2tpUser.push({ _id: id(81), relayNode: id(2), enabled: true, login: 'fixture-ppp-user',
        passwordEncrypted: 'synthetic-only', desiredRevision: 9, appliedRevision: 9 });
    f.data.CascadeRouteGroup.push({ _id: id(80), name: 'installed-outside-operation', mode,
        strategy: 'priority-failover', paths: [{ pathKey: 'ppp-kept', linkIds: [], priority: 4, enabled: true }] });
    const protectedBefore = copy({ state: f.data.RelayL2tpState, users: f.data.L2tpUser, groups: f.data.CascadeRouteGroup });
    try {
        const selected = await create(f, graph.edges[0], mode, true, `G7/${mode}/independent`);
        const operation = await drain(f, selected.response, `G7/${mode}/independent`);
        assert.equal(operation.routeState, 'complete');
        assert.deepEqual(operation.nodes.map(node => node.node).sort(), [id(6), id(7)]);
        await remove(f, selected.linkId, `G7/${mode}/delete`);
        const recreated = await create(f, graph.edges[0], mode, true, `G7/${mode}/recreate`);
        await drain(f, recreated.response, `G7/${mode}/recreate`);
        assert.deepEqual({ state: f.data.RelayL2tpState, users: f.data.L2tpUser, groups: f.data.CascadeRouteGroup }, protectedBefore);
        assert.equal(f.userPushes.some(node => node === id(2)), false);
        record(`G7/${mode}/unrelated-installed-L2TP`, null, JSON.parse(diagnostic(f, 'G7')));
    } catch (error) { record(`G7/${mode}/unrelated-installed-L2TP`, error, JSON.parse(diagnostic(f, 'G7'))); throw error; }
    finally { await close(f); }
});
for (const mode of ['forward', 'reverse']) test(`G7 ${mode}: actual uncertain worker blocks same-node successor but not independent tail`, async () => {
    const graph = { name: 'G7', edges: [['uncertain', 1, 3], ['conflicting', 6, 3], ['independent', 4, 5]] };
    const f = makeFixture(graph);
    Object.assign(f.data.RelayL2tpState[0], { status: 'installed', desiredState: 'installed', secretRevision: 9 });
    f.data.L2tpUser.push({ _id: id(81), relayNode: id(2), enabled: true, login: 'fixture-ppp-user', passwordEncrypted: 'synthetic-only' });
    const protectedBefore = copy({ state: f.data.RelayL2tpState, users: f.data.L2tpUser });
    try {
        f.setPause(async () => { throw new Error('modeled external dispatch outcome unknown'); });
        await create(f, graph.edges[0], mode, true, `G7/${mode}/uncertain`);
        f.hostInstance.start(); await settleTick(f); await settleTick(f);
        const uncertain = f.data.TopologyOperation[0];
        assert.equal(uncertain.heldTopologyAdmission, true, diagnostic(f, 'uncertain predecessor'));
        assert.ok(f.data.NodeOperationLock.length > 0);
        const locks = copy(f.data.NodeOperationLock);
        f.setPause(null);
        const conflict = await create(f, graph.edges[1], mode, true, `G7/${mode}/same-node`);
        const independent = await create(f, graph.edges[2], mode, true, `G7/${mode}/independent-tail`);
        const prepared = f.prepared.length;
        const operation = await drain(f, independent.response, `G7/${mode}/independent-tail`);
        assert.equal(operation.routeState, 'complete');
        assert.deepEqual(new Set(operation.nodes.map(node => node.node)), new Set([id(4), id(5)]));
        assert.deepEqual(f.data.NodeOperationLock, locks, 'the real foreign/uncertain exact generations survive');
        assert.ok(f.prepared.slice(prepared).every(input => [id(4), id(5)].includes(input.node.node)));
        const conflictingJob = await request(f.http, 'GET', `/links/auto-deploy-jobs/${conflict.response.body.job.jobId}`);
        assert.notEqual(conflictingJob.body.job.status, 'succeeded');
        assert.equal(f.data.TopologyOperation.some(op => op.linkId === conflict.linkId && op.status === 'succeeded'), false);
        assert.equal(uncertain.heldTopologyAdmission, true);
        assert.deepEqual({ state: f.data.RelayL2tpState, users: f.data.L2tpUser }, protectedBefore);
        record(`G7/${mode}/uncertainty-local-conflict-independent-tail`, null, JSON.parse(diagnostic(f, 'G7')));
    } catch (error) { record(`G7/${mode}/uncertainty-local-conflict-independent-tail`, error, JSON.parse(diagnostic(f, 'G7'))); throw error; }
    finally { await close(f); }
});

function installedIntermediateRuntime(f) {
    const groupId = id(80), pathKey = 'kept', revision = 9, syncId = id(82);
    const state = f.data.RelayL2tpState.find(row => row.node === id(2));
    f.data.HyNode.find(row => row._id === id(2)).ssh = { port: 22, username: 'fixture', password: 'synthetic-local-only' };
    Object.assign(state, { _id: id(70), status: 'installed', desiredState: 'installed', secretRevision: revision,
        routeGroup: groupId, activePathKey: pathKey, appliedTopologyRevision: 0,
        pskEncrypted: 'synthetic-kept-psk', clientCidr: '10.255.30.0/24', localAddress: '10.255.30.1',
        poolStart: '10.255.30.10', poolEnd: '10.255.30.250', dnsServers: ['192.0.2.53'],
        tproxyPort: 12345, fwmark: 100, routeTable: 100 });
    f.data.CascadeRouteGroup.push({ _id: groupId, name: 'installed-R1', mode: 'reverse', strategy: 'priority-failover', paths: [
        { pathKey, linkIds: [], priority: 4, enabled: true }, { pathKey: 'peer-kept', linkIds: [], priority: 17, enabled: false },
    ] });
    for (const enabled of [true, false]) f.data.L2tpUser.push({ _id: id(enabled ? 83 : 84), relayNode: id(2), enabled,
        login: `fixture-${enabled}`, passwordEncrypted: `synthetic-${enabled}`, ip: enabled ? '10.255.30.10' : '10.255.30.11',
        desiredRevision: revision, appliedRevision: revision, syncStatus: 'synced', syncOperationId: syncId });
    f.data.L2tpOperation.push({ _id: syncId, node: id(2), kind: 'sync_users', status: 'succeeded',
        plan: { operationId: syncId, relayId: id(2), desired: { credentialRevision: revision } } });
    f.installedReads = [];
    f.protectedPin = () => {
        const { appliedTopologyRevision, replacementFence, ...credentials } = state;
        const group = f.data.CascadeRouteGroup.find(row => row._id === groupId);
        return sha(JSON.stringify({ credentials, users: f.data.L2tpUser, group: { ...group,
            paths: group.paths.map(path => path.pathKey === pathKey ? { ...path, linkIds: [] } : path) } }));
    };
    f.beforeProtectedPin = f.protectedPin();
    const deny = () => assert.fail('installed preservation never provisions/reinstalls/changes users or runs a full Sync');
    f.models.CascadeTopologyState.db.startSession = deny;
    const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
    return {
        // Keep the independent installer/sync queue dormant; topology recovery
        // and its installed SimpleService/gates still use the real default host.
        createWorkerLifecycle: () => ({ start: () => ({ enabled: false }), stop: async () => ({ enabled: false }) }),
        workerLifecycle: { enabled: true, timer: f.timer, intervalMs: 30000,
            logger: { error: (...args) => f.errors.push(args) } },
        NodeTransport: class {},
        createPreflightRunner: () => deny, createCandidateService: () => ({ buildCandidate: deny }),
        candidateNodeResolver: deny, candidateUserResolver: deny, configGenerator: deny, fragmentProvider: deny,
        operationMaterializer: deny, createUserSnapshotResolver: () => deny,
        createUserSyncReconciler: () => ({ finalizeVerifiedSync: deny }),
        secretBox: { encrypt: deny, decrypt: deny }, secretKey: 'synthetic-local-only',
        NodeSSH: class {
            async connect() {} disconnect() {}
            async exec(command, options) {
                if (!options?.stdin) {
                    f.installedReads.push('ppp-users');
                    return { code: 0, stderr: '', stdout: JSON.stringify({ ok: true, code: 'USERS_VERIFIED',
                        credentialRevision: revision, enabledUserCount: 1, managedUserCount: 1 }) + '\n' };
                }
                f.installedReads.push('main-ingress');
                // Real ingress verifier Python, but explicit modeled filesystem/systemd readbacks.
                const main = { inbounds: [{ tag: `relay-l2tp-${groupId}`, listen: '0.0.0.0', port: 12345,
                    protocol: 'dokodemo-door', settings: { network: 'tcp,udp', followRedirect: true },
                    streamSettings: { sockopt: { tproxy: 'tproxy' } } }],
                outbounds: [{ tag: `cascade-${pathKey}`, protocol: 'socks', settings: { servers: [
                    { address: '127.0.0.1', port: cascadePathIngressPort(groupId, pathKey) }] } }],
                routing: { rules: [{ type: 'field', inboundTag: [`relay-l2tp-${groupId}`], outboundTag: `cascade-${pathKey}` }] } };
                const setup = `import builtins,io,subprocess\nbuiltins.open=lambda *a,**k:io.StringIO(${JSON.stringify(JSON.stringify(main))})\nsubprocess.run=lambda *a,**k:type('Result',(),{'returncode':0,'stdout':'active\\n','stderr':''})()\n`;
                const result = require('node:child_process').spawnSync('python3', ['-'], { input: setup + options.stdin, encoding: 'utf8' });
                return { code: result.status, stdout: result.stdout, stderr: result.stderr };
            }
        },
    };
}
const INSTALLED_CASES = MATRIX.filter(c => c.graph.name === 'G5').map(c => ({ ...c,
    label: c.label.replace('G5/', 'G5/installed/') }));
const INSTALLED_DELETE_CASES = DELETE_CASES.filter(c => c.graph.name === 'G5').map(c => ({ ...c,
    label: c.label.replace('G5/', 'G5/installed/') }));
const INSTALLED_DELETE_ALL_CASES = DELETE_ALL_CASES.filter(c => c.graph.name === 'G5').map(c => ({ ...c,
    label: c.label.replace('G5/', 'G5/installed/') }));
const ALL_CASE_LABELS = [...MATRIX, ...DELETE_CASES, ...DELETE_ALL_CASES, ...INSTALLED_CASES,
    ...INSTALLED_DELETE_CASES, ...INSTALLED_DELETE_ALL_CASES].map(c => c.label).concat(
    GRAPHS.map(g => `${g.name}/pending-peer`),
    ['forward', 'reverse'].flatMap(mode => [`G7/${mode}/unrelated-installed-L2TP`, `G7/${mode}/uncertainty-local-conflict-independent-tail`]));
test('G5 installed R1: all finite orders/modes/Auto/manual/alternating preserve PPP users and installed path through default runtime', async t => {
    const outcomes = [];
    for (const c of INSTALLED_CASES) outcomes.push(await exercise(c.label, async retain => {
        const f = await runCreation(c, installedIntermediateRuntime); retain(f);
        assert.equal(f.protectedPin(), f.beforeProtectedPin);
        assert.ok(f.installedReads.includes('main-ingress') && f.installedReads.includes('ppp-users'));
        return f;
    }));
    const failures = outcomes.filter(result => result.status === 'failed');
    t.diagnostic(`${outcomes.length} executed; ${outcomes.length - failures.length} passed; ${failures.length} failed`);
    assert.deepEqual(firstFailures(failures), [], 'first attributable installed G5 runtime failure per class');
});
test('G5 installed R1: HTTP delete/recreate every edge preserves PPP identity and stable owned ingress', async t => {
    const outcomes = [];
    for (const c of INSTALLED_DELETE_CASES) outcomes.push(await exercise(c.label, async retain => {
        const f = await runCreation(completeCase(c.graph, c.mode), installedIntermediateRuntime); retain(f);
        const selected = f.data.CascadeLink.find(link => link.name === c.edge[0]);
        await remove(f, selected._id, c.label);
        const recreated = await create(f, c.edge, c.mode, true, `${c.label}/recreate`);
        await drain(f, recreated.response, `${c.label}/recreate`);
        assert.equal(f.data.TopologyOperation.at(-1).routeState, 'complete');
        return f;
    }));
    const failures = outcomes.filter(result => result.status === 'failed');
    t.diagnostic(`${outcomes.length} executed; ${outcomes.length - failures.length} passed; ${failures.length} failed`);
    assert.deepEqual(firstFailures(failures), [], 'first attributable installed G5 deletion/recreate failure per class');
});
test('G5 installed R1: sequential HTTP deletion blocks empty owned ingress without changing PPP users', async t => {
    const outcomes = [];
    for (const c of INSTALLED_DELETE_ALL_CASES) outcomes.push(await exercise(c.label, async retain => {
        const f = await runCreation(completeCase(c.graph, c.mode), installedIntermediateRuntime); retain(f);
        const links = new Map(f.data.CascadeLink.map(link => [link.name, link._id]));
        for (const index of c.order) await remove(f, links.get(c.graph.edges[index][0]), `${c.label}/${index}`);
        assert.equal(f.data.CascadeLink.length, 0);
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
        return f;
    }));
    const failures = outcomes.filter(result => result.status === 'failed');
    t.diagnostic(`${outcomes.length} executed; ${outcomes.length - failures.length} passed; ${failures.length} failed`);
    assert.deepEqual(firstFailures(failures), [], 'first attributable installed G5 sequential deletion failure per class');
});

test('all 163 finite acceptance cases were actually attempted and recorded exactly once', t => {
    assert.equal(ALL_CASE_LABELS.length, 163);
    assert.equal(new Set(ALL_CASE_LABELS).size, ALL_CASE_LABELS.length);
    assert.equal(results.length, ALL_CASE_LABELS.length);
    assert.deepEqual(results.map(row => row.label).sort(), [...ALL_CASE_LABELS].sort());
    const summary = {};
    for (const result of results) {
        const parts = result.label.split('/');
        const group = parts[0] + (parts[1] === 'installed' ? '/installed' : '') +
            (result.label.includes('delete-recreate') ? '/delete-recreate' : result.label.includes('delete-all') ? '/delete-all'
                : result.label.includes('pending-peer') ? '/pending-peer' : parts[0] === 'G7' ? '/independent' : '/create');
        const counts = summary[group] ||= { passed: 0, failed: 0 };
        counts[result.status]++;
    }
    t.diagnostic(JSON.stringify(summary));
});



