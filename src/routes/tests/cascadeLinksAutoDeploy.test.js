'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');

const {
    createCascadeLinksRouter,
    selectLinkApplyBaselineLinkIds,
} = require('../cascadeLinks');

const PORTAL_A = '507f1f77bcf86cd799439031';
const PORTAL_B = '507f1f77bcf86cd799439033';
const RELAY_A = '507f1f77bcf86cd799439034';
const RELAY_B = '507f1f77bcf86cd799439035';
const BRIDGE_A = '507f1f77bcf86cd799439032';
const FOREIGN_PORTAL = '507f1f77bcf86cd799439036';
const FOREIGN_BRIDGE = '507f1f77bcf86cd799439037';

const LINK_DEPLOYED_PORTAL_TO_RELAY = '507f1f77bcf86cd799439041';
const LINK_PENDING_SHARED_RELAY = '507f1f77bcf86cd799439042';
const LINK_ONLINE_RELAY_TO_RELAY = '507f1f77bcf86cd799439043';
const LINK_DISABLED_DEPLOYED = '507f1f77bcf86cd799439044';
const LINK_FOREIGN_DEPLOYED = '507f1f77bcf86cd799439045';
const LINK_STAGED_FIRST_HOP = '507f1f77bcf86cd799439046';

function queryResult(result) {
    return {
        populate() { return this; },
        sort() { return this; },
        select() { return this; },
        async lean() { return result; },
    };
}

async function request(router, { method = 'GET', path = '/', body } = {}) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
        req.session = { authenticated: true };
        next();
    });
    app.use(router);
    const server = await new Promise(resolve => {
        const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
    });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method,
            headers: body === undefined ? {} : { 'content-type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await response.text();
        return { status: response.status, body: text ? JSON.parse(text) : null };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

function nodeRef(id) {
    return { _id: id, name: `node-${id.slice(-4)}` };
}

function createBody(overrides = {}) {
    return {
        expectedTopologyRevision: 8,
        name: 'Relay to bridge',
        portalNodeId: RELAY_B,
        bridgeNodeId: BRIDGE_A,
        mode: 'reverse',
        tunnelPort: 10087,
        autoDeploy: true,
        ...overrides,
    };
}

// A realistic post-create snapshot: one deployed chain portal->relayA->relayB,
// an OLD pending link from a second portal onto the same shared relayB (the
// pre-upgrade rev112 record that must never be silently activated), a disabled
// deployed link, and a deployed link in a completely separate component.
function componentLinks() {
    return [
        {
            _id: LINK_DEPLOYED_PORTAL_TO_RELAY,
            portalNode: nodeRef(PORTAL_A),
            bridgeNode: nodeRef(RELAY_A),
            active: true,
            status: 'deployed',
        },
        {
            _id: LINK_ONLINE_RELAY_TO_RELAY,
            portalNode: nodeRef(RELAY_A),
            bridgeNode: nodeRef(RELAY_B),
            active: true,
            status: 'online',
        },
        {
            _id: LINK_PENDING_SHARED_RELAY,
            portalNode: nodeRef(PORTAL_B),
            bridgeNode: nodeRef(RELAY_B),
            active: true,
            status: 'pending',
        },
        {
            _id: LINK_DISABLED_DEPLOYED,
            portalNode: nodeRef(PORTAL_B),
            bridgeNode: nodeRef(RELAY_A),
            active: false,
            status: 'deployed',
        },
        {
            _id: LINK_FOREIGN_DEPLOYED,
            portalNode: nodeRef(FOREIGN_PORTAL),
            bridgeNode: nodeRef(FOREIGN_BRIDGE),
            active: true,
            status: 'online',
        },
    ];
}

function createAutoDeployHarness({
    links = componentLinks(),
    coordinator,
    maintenanceRevision = 9,
} = {}) {
    const calls = { queue: [] };
    let storedLinks = links.map(link => ({ ...link }));
    const Link = {
        find() { return queryResult(storedLinks); },
        async findOne() { return null; },
    };
    const Node = {
        async findById(id) { return { _id: id, name: `node-${String(id).slice(-4)}` }; },
    };
    const topologyDraftWriteService = {
        async createLink(input) {
            calls.createLink = input;
            // The draft write persists the new link with the model default
            // status 'pending'; it is NOT part of the deployed baseline.
            storedLinks = [...storedLinks, { ...input.link, status: 'pending' }];
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const resolvedCoordinator = coordinator ?? {
        async queue(input) {
            calls.queue.push(input);
            return { operationId: 'op-auto-1', topologyRevision: input.expectedTopologyRevision, status: 'queued' };
        },
    };
    const router = createCascadeLinksRouter({
        Link,
        Node,
        topologyDraftWriteService,
        maintainAutoL2tpPathsFn: async () => (
            maintenanceRevision === null ? undefined : { updated: 1, revision: maintenanceRevision }
        ),
        invalidateSubscriptions: async () => {},
        invalidateTopology: async () => {},
        topologyCoordinator: resolvedCoordinator,
    });
    return { calls, router };
}

test('baseline selection walks only confirmed deployed active links of the component', () => {
    const baseline = selectLinkApplyBaselineLinkIds({
        links: componentLinks(),
        linkId: '507f1f77bcf86cd799439099',
        portalNodeId: RELAY_B,
        bridgeNodeId: BRIDGE_A,
    });
    assert.deepEqual(baseline, [
        LINK_DEPLOYED_PORTAL_TO_RELAY,
        LINK_ONLINE_RELAY_TO_RELAY,
    ].sort());
    assert.ok(!baseline.includes(LINK_PENDING_SHARED_RELAY),
        'the old pending shared-relay link must never enter the baseline');
    assert.ok(!baseline.includes(LINK_DISABLED_DEPLOYED),
        'a user-disabled link is not part of the deployed component');
    assert.ok(!baseline.includes(LINK_FOREIGN_DEPLOYED),
        'a deployed link of another component is never pulled in');
});

test('baseline selection starts from both endpoints of the new link', () => {
    const baseline = selectLinkApplyBaselineLinkIds({
        links: [{
            _id: LINK_DEPLOYED_PORTAL_TO_RELAY,
            portalNode: nodeRef(BRIDGE_A),
            bridgeNode: nodeRef(FOREIGN_BRIDGE),
            active: true,
            status: 'online',
        }],
        linkId: '507f1f77bcf86cd799439099',
        portalNodeId: RELAY_B,
        bridgeNodeId: BRIDGE_A,
    });
    assert.deepEqual(baseline, [LINK_DEPLOYED_PORTAL_TO_RELAY]);
});

test('POST with autoDeploy queues a scoped link.apply with the post-maintenance revision', async () => {
    const { calls, router } = createAutoDeployHarness();
    const response = await request(router, { method: 'POST', body: createBody() });

    assert.equal(response.status, 201);
    assert.equal(calls.queue.length, 1, 'autoDeploy opt-in must enqueue exactly one scoped operation');
    const queued = calls.queue[0];
    assert.equal(queued.expectedTopologyRevision, 9,
        'the queue must pin the revision after L2TP path maintenance, not the pre-maintenance one');
    assert.equal(queued.scope.kind, 'link.apply');
    assert.equal(queued.scope.linkId, response.body.createdLinkId);
    assert.deepEqual([...queued.scope.linkIds].sort(), [
        response.body.createdLinkId,
        LINK_DEPLOYED_PORTAL_TO_RELAY,
        LINK_ONLINE_RELAY_TO_RELAY,
    ].sort(), 'scope = requested link + confirmed deployed component baseline only');
    assert.ok(!queued.scope.linkIds.includes(LINK_PENDING_SHARED_RELAY),
        'the old pending shared-relay link must never be queued');
});

test('POST with autoDeploy returns autoDeployOperation and never claims ready on queue', async () => {
    const { router } = createAutoDeployHarness();
    const response = await request(router, { method: 'POST', body: createBody() });

    assert.equal(response.status, 201);
    // The versioned snapshot shape the UI mutator relies on is preserved.
    assert.equal(response.body.topologyRevision, 9);
    assert.equal(response.body.deployedRevision, 5);
    assert.ok(Array.isArray(response.body.links));
    assert.ok(response.body.createdLinkId);
    assert.deepEqual(response.body.autoDeployOperation, {
        operationId: 'op-auto-1',
        topologyRevision: 9,
        status: 'queued',
    });
    assert.notEqual(response.body.autoDeployOperation.status, 'ready',
        'a queued operation is not a ready chain');
    assert.equal(response.body.autoDeployStatus, undefined,
        'a successful queue must not be reported as blocked');
});

test('POST with the old pending shared relay never enqueues it even when it shares the new link endpoint', async () => {
    const { calls, router } = createAutoDeployHarness({
        links: [{
            _id: LINK_PENDING_SHARED_RELAY,
            portalNode: nodeRef(PORTAL_B),
            bridgeNode: nodeRef(RELAY_B),
            active: true,
            status: 'pending',
        }],
    });
    const response = await request(router, { method: 'POST', body: createBody() });

    assert.equal(response.status, 201);
    assert.equal(calls.queue.length, 1);
    assert.deepEqual(calls.queue[0].scope.linkIds, [response.body.createdLinkId],
        'with no confirmed deployed baseline the scope is exactly the requested link');
});

test('POST without the autoDeploy opt-in never queues a scoped operation', async () => {
    const { calls, router } = createAutoDeployHarness();
    const body = createBody({ autoDeploy: false });
    const response = await request(router, { method: 'POST', body });

    assert.equal(response.status, 201);
    assert.equal(calls.queue.length, 0,
        'a disabled opt-in must stay an explicit operator choice: no self-activation');
    assert.equal(response.body.autoDeployOperation, undefined);
    assert.equal(response.body.autoDeployStatus, undefined);
    assert.equal(response.body.topologyRevision, 9);
});

test('baseline selection treats a persisted staged link as physically applied, never pending', () => {
    const links = [
        {
            // The previous link.apply finished applying portal->relayA to its
            // endpoints; the component is not client-ready yet, but the link
            // IS a valid baseline for the next auto-deployed hop.
            _id: LINK_STAGED_FIRST_HOP,
            portalNode: nodeRef(PORTAL_A),
            bridgeNode: nodeRef(RELAY_B),
            active: true,
            status: 'staged',
        },
        {
            _id: LINK_PENDING_SHARED_RELAY,
            portalNode: nodeRef(PORTAL_B),
            bridgeNode: nodeRef(RELAY_B),
            active: true,
            status: 'pending',
        },
    ];
    const baseline = selectLinkApplyBaselineLinkIds({
        links,
        linkId: '507f1f77bcf86cd799439099',
        portalNodeId: RELAY_B,
        bridgeNodeId: BRIDGE_A,
    });
    assert.deepEqual(baseline, [LINK_STAGED_FIRST_HOP]);
});

test('POST auto-deploy of the completing hop queues the staged first hop as baseline', async () => {
    const { calls, router } = createAutoDeployHarness({
        links: [{
            _id: LINK_STAGED_FIRST_HOP,
            portalNode: nodeRef(PORTAL_A),
            bridgeNode: nodeRef(RELAY_B),
            active: true,
            status: 'staged',
        }],
    });
    const response = await request(router, { method: 'POST', body: createBody() });

    assert.equal(response.status, 201);
    assert.equal(calls.queue.length, 1);
    assert.deepEqual([...calls.queue[0].scope.linkIds].sort(), [
        response.body.createdLinkId,
        LINK_STAGED_FIRST_HOP,
    ].sort(), 'a staged first hop is applied baseline; the new hop completes the chain');
    assert.equal(response.body.autoDeployOperation.status, 'queued');
});

test('POST surfaces a queue failure as blocked with a safe code, keeping the created snapshot', async () => {
    const queueError = new Error('A scoped baseline link is not confirmed deployed');
    queueError.code = 'INVALID_TOPOLOGY_DEPLOYMENT';
    const { calls, router } = createAutoDeployHarness({
        coordinator: {
            async queue(input) {
                calls.queue.push(input);
                throw queueError;
            },
        },
    });
    const response = await request(router, { method: 'POST', body: createBody() });

    assert.equal(response.status, 201,
        'the link was already created; the auto-deploy failure must not masquerade as a create failure');
    assert.equal(response.body.autoDeployOperation, undefined,
        'no operation id may be reported when the queue did not succeed');
    assert.equal(response.body.autoDeployStatus, 'blocked');
    assert.equal(response.body.autoDeployError.code, 'INVALID_TOPOLOGY_DEPLOYMENT');
    assert.equal(response.body.topologyRevision, 9);
    assert.ok(response.body.createdLinkId);
});

test('POST queue failure never reflects free-form backend credentials', async () => {
    const queueError = new Error('password=short-secret must not leave server');
    queueError.code = 'INVALID_TOPOLOGY_DEPLOYMENT';
    const { router } = createAutoDeployHarness({
        coordinator: { async queue() { throw queueError; } },
    });
    const response = await request(router, { method: 'POST', body: createBody() });
    assert.equal(response.status, 201);
    assert.equal(response.body.autoDeployStatus, 'blocked');
    assert.equal(response.body.autoDeployError.code, 'INVALID_TOPOLOGY_DEPLOYMENT');
    assert.doesNotMatch(JSON.stringify(response.body), /short-secret/);
});

test('POST reports blocked when the scoped coordinator is unavailable', async () => {
    const { router } = createAutoDeployHarness({
        coordinator: {
            // Mirrors unavailableTopologyDeploymentService: no queue capability.
            async deploy() {
                const error = new Error('Topology deployment capabilities are unavailable');
                error.code = 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE';
                throw error;
            },
        },
    });
    const response = await request(router, { method: 'POST', body: createBody() });

    assert.equal(response.status, 201);
    assert.equal(response.body.autoDeployOperation, undefined);
    assert.equal(response.body.autoDeployStatus, 'blocked');
    assert.equal(response.body.autoDeployError.code, 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
});

test('POST does not claim a queued operation when coordinator reports a terminal failure', async () => {
    const { router } = createAutoDeployHarness({
        coordinator: { async queue() { return { operationId: 'op-failed', topologyRevision: 9, status: 'failed' }; } },
    });
    const response = await request(router, { method: 'POST', body: createBody() });
    assert.equal(response.status, 201);
    assert.equal(response.body.autoDeployOperation, undefined);
    assert.equal(response.body.autoDeployStatus, 'blocked');
    assert.equal(response.body.autoDeployError.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
});

test('POST reports blocked when the coordinator resolves to a malformed queue result', async () => {
    const { router } = createAutoDeployHarness({
        coordinator: { async queue() { return { status: 'queued' }; } },
    });
    const response = await request(router, { method: 'POST', body: createBody() });

    assert.equal(response.status, 201);
    assert.equal(response.body.autoDeployOperation, undefined,
        'a queue result without an operation id is not a success');
    assert.equal(response.body.autoDeployStatus, 'blocked');
    assert.equal(response.body.autoDeployError.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
});
