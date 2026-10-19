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
const LINK_EDITED = '507f1f77bcf86cd799439047';

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
    prepareL2tpIngressFn,
    editedLink,
    updateError,
} = {}) {
    const calls = { queue: [] };
    let storedLinks = links.map(link => ({ ...link }));
    if (editedLink) storedLinks.push({ ...editedLink });
    const Link = {
        find() { return queryResult(storedLinks); },
        async findById(id) { return storedLinks.find(link => String(link._id) === String(id)) || null; },
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
        async updateLink(input) {
            calls.updateLink = input;
            if (updateError) throw updateError;
            const link = storedLinks.find(candidate => String(candidate._id) === String(input.linkId));
            if (!link) {
                const error = new Error('The cascade link was not found');
                error.code = 'CASCADE_LINK_NOT_FOUND';
                throw error;
            }
            Object.assign(link, input.changes);
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
        prepareL2tpIngressFn: prepareL2tpIngressFn ?? (async ({ expectedTopologyRevision }) => ({
            revision: expectedTopologyRevision,
        })),
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








function editedLink(overrides = {}) {
    return {
        _id: LINK_EDITED,
        portalNode: nodeRef(RELAY_B),
        bridgeNode: nodeRef(BRIDGE_A),
        active: true,
        autoDeploy: false,
        status: 'pending',
        ...overrides,
    };
}

function editBody(overrides = {}) {
    return { expectedTopologyRevision: 8, name: 'Edited hop', ...overrides };
}

async function putEdit(router, body = editBody()) {
    return request(router, { method: 'PUT', path: `/${LINK_EDITED}`, body });
}

test('PUT prepares L2TP ingress before freezing the explicit autoDeploy operation', async () => {
    const order = [];
    const { router } = createAutoDeployHarness({
        editedLink: editedLink(),
        prepareL2tpIngressFn: async ({ expectedTopologyRevision }) => {
            order.push('prepare');
            return { revision: expectedTopologyRevision };
        },
        coordinator: { async queue(input) {
            order.push('queue');
            return { operationId: 'op-auto-1', topologyRevision: input.expectedTopologyRevision, status: 'queued' };
        } },
    });
    const response = await putEdit(router, editBody({ autoDeploy: true }));
    assert.equal(response.status, 200);
    assert.deepEqual(order, ['prepare', 'queue']);
});

test('PUT explicit autoDeploy true queues only the edited enabled link and confirmed baseline after maintenance', async () => {
    const { calls, router } = createAutoDeployHarness({ editedLink: editedLink() });
    const response = await putEdit(router, editBody({ autoDeploy: true }));

    assert.equal(response.status, 200);
    assert.deepEqual(calls.updateLink.changes, { name: 'Edited hop', autoDeploy: true });
    assert.equal(calls.queue.length, 1);
    assert.deepEqual(calls.queue[0], {
        expectedTopologyRevision: 9,
        scope: {
            kind: 'link.apply',
            linkId: LINK_EDITED,
            linkIds: [LINK_EDITED, LINK_DEPLOYED_PORTAL_TO_RELAY, LINK_ONLINE_RELAY_TO_RELAY],
        },
    });
    assert.deepEqual(response.body.autoDeployOperation, {
        operationId: 'op-auto-1', topologyRevision: 9, status: 'queued',
    });
    assert.equal(response.body.topologyRevision, 9);
    assert.equal(response.body.deployedRevision, 5);
    assert.ok(Array.isArray(response.body.links));
});

test('PUT without explicit autoDeploy never queues even when stored autoDeploy is true', async () => {
    const { calls, router } = createAutoDeployHarness({ editedLink: editedLink({ autoDeploy: true }) });
    const response = await putEdit(router);
    assert.equal(response.status, 200);
    assert.equal(calls.queue.length, 0);
    assert.equal(response.body.autoDeployOperation, undefined);
    assert.equal(response.body.autoDeployStatus, undefined);
});

test('PUT explicit autoDeploy false never queues even when stored autoDeploy is true', async () => {
    const { calls, router } = createAutoDeployHarness({ editedLink: editedLink({ autoDeploy: true }) });
    const response = await putEdit(router, editBody({ autoDeploy: false }));
    assert.equal(response.status, 200);
    assert.equal(calls.updateLink.changes.autoDeploy, false);
    assert.equal(calls.queue.length, 0);
    assert.equal(response.body.autoDeployOperation, undefined);
});

test('PUT cannot auto-deploy a link explicitly disabled in the same mutation', async () => {
    const { calls, router } = createAutoDeployHarness({ editedLink: editedLink() });
    const response = await putEdit(router, editBody({ autoDeploy: true, active: false }));
    assert.equal(response.status, 200);
    assert.equal(calls.queue.length, 0);
    assert.equal(response.body.autoDeployOperation, undefined);
    assert.equal(response.body.links.find(link => link._id === LINK_EDITED).active, false);
});

test('PUT cannot auto-deploy a previously disabled link without enabling it', async () => {
    const { calls, router } = createAutoDeployHarness({ editedLink: editedLink({ active: false }) });
    const response = await putEdit(router, editBody({ autoDeploy: true }));
    assert.equal(response.status, 200);
    assert.equal(calls.queue.length, 0);
    assert.equal(response.body.autoDeployOperation, undefined);
});

test('PUT explicit opt-in uses the draft revision when maintenance does not advance it', async () => {
    const { calls, router } = createAutoDeployHarness({
        editedLink: editedLink(), maintenanceRevision: null,
    });
    const response = await putEdit(router, editBody({ autoDeploy: true }));
    assert.equal(response.status, 200);
    assert.equal(calls.queue[0].expectedTopologyRevision, 8);
    assert.equal(response.body.autoDeployOperation.topologyRevision, 8);
});

test('PUT stale revision never mutates or queues despite explicit opt-in', async () => {
    const error = new Error('Revision changed');
    error.code = 'STALE_TOPOLOGY_REVISION';
    const { calls, router } = createAutoDeployHarness({ editedLink: editedLink(), updateError: error });
    const response = await putEdit(router, editBody({ autoDeploy: true }));
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, 'STALE_TOPOLOGY_REVISION');
    assert.equal(calls.queue.length, 0);
});

test('PUT rejects malformed opt-in before mutating or queuing', async () => {
    const { calls, router } = createAutoDeployHarness({ editedLink: editedLink() });
    const response = await putEdit(router, editBody({ autoDeploy: 'yes' }));
    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, 'INVALID_AUTO_DEPLOY');
    assert.equal(calls.updateLink, undefined);
    assert.equal(calls.queue.length, 0);
});

test('PUT queue errors remain blocked with safe codes and preserve the edited snapshot', async () => {
    const error = new Error('password=secret-value');
    error.code = 'CREDENTIAL_SECRET';
    const { router } = createAutoDeployHarness({
        editedLink: editedLink(),
        coordinator: { async queue() { throw error; } },
    });
    const response = await putEdit(router, editBody({ autoDeploy: true }));
    assert.equal(response.status, 200);
    assert.equal(response.body.topologyRevision, 9);
    assert.equal(response.body.links.find(link => link._id === LINK_EDITED).name, 'Edited hop');
    assert.equal(response.body.autoDeployOperation, undefined);
    assert.equal(response.body.autoDeployStatus, 'blocked');
    assert.equal(response.body.autoDeployError.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
    assert.doesNotMatch(JSON.stringify(response.body), /secret-value|CREDENTIAL_SECRET/);
});

test('PUT malformed queue result fails closed rather than claiming a queued operation', async () => {
    const { router } = createAutoDeployHarness({
        editedLink: editedLink(),
        coordinator: { async queue() { return { operationId: 'op-wrong-revision', topologyRevision: 8, status: 'queued' }; } },
    });
    const response = await putEdit(router, editBody({ autoDeploy: true }));
    assert.equal(response.status, 200);
    assert.equal(response.body.autoDeployOperation, undefined);
    assert.equal(response.body.autoDeployStatus, 'blocked');
    assert.equal(response.body.autoDeployError.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
});
