'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const mongoose = require('mongoose');

const {
    createCascadeLinksRouter,
} = require('../cascadeLinks');

const LINK_A = '507f1f77bcf86cd799439021';
const PORTAL_A = '507f1f77bcf86cd799439031';
const BRIDGE_A = '507f1f77bcf86cd799439032';
const CASCADE_ROUTE_SOURCE = fs.readFileSync(path.resolve(__dirname, '../cascade.js'), 'utf8');

function queryResult(result, calls = {}, prefix = '') {
    return {
        populate(path, select) {
            (calls[`${prefix}populate`] ||= []).push({ path, select });
            return this;
        },
        sort(value) {
            calls[`${prefix}sort`] = value;
            return this;
        },
        select(value) {
            calls[`${prefix}select`] = value;
            return this;
        },
        async lean() {
            calls[`${prefix}lean`] = true;
            return result;
        },
    };
}

async function request(router, {
    method = 'GET',
    path = '/',
    body,
} = {}) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
        req.session = { authenticated: true };
        next();
    });
    app.use(router);

    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });

    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method,
            headers: body === undefined ? {} : { 'content-type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await response.text();
        return {
            status: response.status,
            body: text ? JSON.parse(text) : null,
        };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

function validCreateBody(overrides = {}) {
    return {
        expectedTopologyRevision: 7,
        name: 'Portal to bridge',
        portalNodeId: PORTAL_A,
        bridgeNodeId: BRIDGE_A,
        mode: 'forward',
        tunnelPort: 10086,
        tunnelProtocol: 'vless',
        tunnelSecurity: 'none',
        tunnelTransport: 'tcp',
        autoDeploy: true,
        ...overrides,
    };
}

test('cascade API mounts the versioned links router without legacy CRUD or reconnect mutation routes', () => {
    assert.match(
        CASCADE_ROUTE_SOURCE,
        /const cascadeLinksRoutes = require\('\.\/cascadeLinks'\);/,
    );
    assert.match(CASCADE_ROUTE_SOURCE, /router\.use\('\/links', cascadeLinksRoutes\);/);
    assert.doesNotMatch(
        CASCADE_ROUTE_SOURCE,
        /router\.(?:post|put|patch|delete)\('\/links(?:\/:id(?:\/reconnect)?)?'/,
    );
    assert.doesNotMatch(
        CASCADE_ROUTE_SOURCE,
        /CascadeLink\.(?:create|findByIdAndUpdate|findByIdAndDelete)\(/,
    );
});

test('GET returns the versioned link snapshot used by network clients', async () => {
    const calls = {};
    const links = [{ _id: LINK_A, name: 'Portal to bridge' }];
    const Link = {
        find(filter) {
            calls.filter = filter;
            return queryResult(links, calls, 'link');
        },
    };
    const TopologyState = {
        findById(id) {
            calls.topologyId = id;
            return queryResult({ revision: 21, deployedRevision: 18 }, calls, 'topology');
        },
    };
    const router = createCascadeLinksRouter({ Link, TopologyState });

    const response = await request(router);

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        topologyRevision: 21,
        deployedRevision: 18,
        links,
    });
    assert.deepEqual(calls.filter, {});
    assert.equal(calls.topologyId, 'singleton');
});

test('GET by id preserves the populated cascade link contract', async () => {
    const calls = {};
    const link = { _id: LINK_A, name: 'Portal to bridge' };
    const Link = {
        findById(id) {
            calls.id = id;
            return queryResult(link, calls, 'single');
        },
    };
    const router = createCascadeLinksRouter({ Link });

    const response = await request(router, { path: `/${LINK_A}` });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, link);
    assert.equal(calls.id, LINK_A);
});

test('POST creates a versioned draft link and returns the revised snapshot without deployment', async () => {
    const calls = { deployment: 0, subscriptionInvalidation: 0, topologyInvalidation: 0 };
    let links = [];
    const Link = {
        find(filter) {
            calls.linkFilter = filter;
            return queryResult(links, calls, 'link');
        },
        async findOne(filter) {
            calls.portConflictFilter = filter;
            return null;
        },
        async create() {
            throw new Error('route must not create the link model directly');
        },
    };
    const Node = {
        async findById(id) {
            if (id === PORTAL_A) return { _id: id, name: 'Portal' };
            if (id === BRIDGE_A) return { _id: id, name: 'Bridge' };
            return null;
        },
    };
    const topologyDraftWriteService = {
        async createLink(input) {
            calls.createLink = input;
            links = [{ ...input.link }];
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const router = createCascadeLinksRouter({
        Link,
        Node,
        topologyDraftWriteService,
        async invalidateSubscriptions() { calls.subscriptionInvalidation += 1; },
        async invalidateTopology() { calls.topologyInvalidation += 1; },
        deploymentService: {
            deployLink() { calls.deployment += 1; },
            deployChain() { calls.deployment += 1; },
            undeployLink() { calls.deployment += 1; },
        },
    });

    const response = await request(router, { method: 'POST', body: validCreateBody() });

    assert.equal(response.status, 201);
    assert.equal(calls.createLink.expectedTopologyRevision, 7);
    assert.ok(calls.createLink.link._id instanceof mongoose.Types.ObjectId);
    assert.deepEqual(
        { ...calls.createLink.link, _id: String(calls.createLink.link._id) },
        {
            _id: String(calls.createLink.link._id),
            name: 'Portal to bridge',
            mode: 'forward',
            portalNode: PORTAL_A,
            bridgeNode: BRIDGE_A,
            tunnelUuid: calls.createLink.link.tunnelUuid,
            tunnelPort: 10086,
            tunnelDomain: 'reverse.tunnel.internal',
            tunnelProtocol: 'vless',
            tunnelSecurity: 'none',
            tunnelTransport: 'tcp',
            tcpFastOpen: true,
            tcpKeepAlive: 100,
            tcpNoDelay: true,
            wsPath: '/cascade',
            wsHost: '',
            grpcServiceName: 'cascade',
            xhttpPath: '/cascade',
            xhttpHost: '',
            xhttpMode: 'auto',
            muxEnabled: false,
            muxConcurrency: 8,
            priority: 100,
        },
    );
    assert.match(calls.createLink.link.tunnelUuid, /^[0-9a-f-]{36}$/i);
    assert.equal(calls.deployment, 0);
    assert.equal(calls.subscriptionInvalidation, 1);
    assert.equal(calls.topologyInvalidation, 1);
    assert.equal(response.body.topologyRevision, 8);
    assert.equal(response.body.deployedRevision, 5);
    assert.equal(response.body.links.length, 1);
    assert.equal(response.body.links[0]._id, String(calls.createLink.link._id));
    assert.equal(response.body.links[0].autoDeploy, undefined);
});

test('PUT updates allowlisted settings through the versioned draft boundary without redeployment', async () => {
    const calls = { deployment: 0, subscriptionInvalidation: 0, topologyInvalidation: 0 };
    let links = [{
        _id: LINK_A,
        name: 'Old link',
        mode: 'forward',
        portalNode: PORTAL_A,
        bridgeNode: BRIDGE_A,
        tunnelPort: 10086,
        tunnelSecurity: 'none',
        tunnelTransport: 'tcp',
        active: true,
    }];
    const Link = {
        find() {
            return queryResult(links, calls, 'link');
        },
        async findById(id) {
            calls.findById = id;
            return links.find(link => link._id === id) || null;
        },
        async findOne(filter) {
            calls.portConflictFilter = filter;
            return null;
        },
        async findByIdAndUpdate() {
            throw new Error('route must not update the link model directly');
        },
    };
    const topologyDraftWriteService = {
        async updateLink(input) {
            calls.updateLink = input;
            links = links.map(link => (
                link._id === input.linkId ? { ...link, ...input.changes } : link
            ));
            return { revision: 13, deployedRevision: 10 };
        },
    };
    const router = createCascadeLinksRouter({
        Link,
        topologyDraftWriteService,
        async invalidateSubscriptions() { calls.subscriptionInvalidation += 1; },
        async invalidateTopology() { calls.topologyInvalidation += 1; },
        deploymentService: {
            deployLink() { calls.deployment += 1; },
            deployChain() { calls.deployment += 1; },
            undeployLink() { calls.deployment += 1; },
        },
    });

    const response = await request(router, {
        method: 'PUT',
        path: `/${LINK_A}`,
        body: {
            expectedTopologyRevision: 12,
            name: 'Updated link',
            tunnelPort: '11000',
            tunnelSecurity: 'none',
            tunnelTransport: 'grpc',
            geoRouting: {
                enabled: true,
                domains: ['example.com'],
                geoip: ['private'],
            },
            autoRedeploy: true,
            portalNode: 'attacker-controlled',
            createdAt: 'attacker-controlled',
        },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(calls.updateLink, {
        expectedTopologyRevision: 12,
        linkId: LINK_A,
        changes: {
            name: 'Updated link',
            tunnelPort: 11000,
            tunnelSecurity: 'none',
            tunnelTransport: 'grpc',
            'geoRouting.enabled': true,
            'geoRouting.domains': ['example.com'],
            'geoRouting.geoip': ['private'],
        },
    });
    assert.equal(calls.deployment, 0);
    assert.equal(calls.subscriptionInvalidation, 1);
    assert.equal(calls.topologyInvalidation, 1);
    assert.equal(response.body.topologyRevision, 13);
    assert.equal(response.body.deployedRevision, 10);
    assert.equal(response.body.links[0].name, 'Updated link');
    assert.doesNotMatch(JSON.stringify(calls.updateLink), /autoRedeploy|attacker-controlled|createdAt/);
});

test('DELETE removes a link through the versioned draft boundary without undeployment', async () => {
    const calls = { deployment: 0, subscriptionInvalidation: 0, topologyInvalidation: 0 };
    let links = [{
        _id: LINK_A,
        name: 'Deployed link',
        portalNode: PORTAL_A,
        bridgeNode: BRIDGE_A,
        status: 'online',
    }];
    const Link = {
        find() {
            return queryResult(links, calls, 'link');
        },
        async findByIdAndDelete() {
            throw new Error('route must not delete the link model directly');
        },
    };
    const topologyDraftWriteService = {
        async deleteLink(input) {
            calls.deleteLink = input;
            links = links.filter(link => link._id !== input.linkId);
            return { revision: 15, deployedRevision: 10 };
        },
    };
    const router = createCascadeLinksRouter({
        Link,
        topologyDraftWriteService,
        async invalidateSubscriptions() { calls.subscriptionInvalidation += 1; },
        async invalidateTopology() { calls.topologyInvalidation += 1; },
        deploymentService: {
            deployLink() { calls.deployment += 1; },
            deployChain() { calls.deployment += 1; },
            undeployLink() { calls.deployment += 1; },
        },
    });

    const response = await request(router, {
        method: 'DELETE',
        path: `/${LINK_A}`,
        body: { expectedTopologyRevision: 14 },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(calls.deleteLink, {
        expectedTopologyRevision: 14,
        linkId: LINK_A,
    });
    assert.equal(calls.deployment, 0);
    assert.equal(calls.subscriptionInvalidation, 1);
    assert.equal(calls.topologyInvalidation, 1);
    assert.deepEqual(response.body, {
        topologyRevision: 15,
        deployedRevision: 10,
        links: [],
    });
});

test('POST rejects an unsupported tunnel protocol before writing the draft', async () => {
    let writes = 0;
    const router = createCascadeLinksRouter({
        Link: {
            async findOne() { return null; },
        },
        Node: {
            async findById(id) { return { _id: id, name: id }; },
        },
        topologyDraftWriteService: {
            async createLink() {
                writes += 1;
                throw new Error('draft write must not be reached');
            },
        },
    });

    const response = await request(router, {
        method: 'POST',
        body: validCreateBody({ tunnelProtocol: 'socks' }),
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, 'INVALID_REQUEST');
    assert.match(response.body.error.message, /tunnelProtocol/);
    assert.equal(writes, 0);
});

test('POST rejects an explicit out-of-range tunnel port before writing the draft', async () => {
    let writes = 0;
    const router = createCascadeLinksRouter({
        Link: {
            async findOne() { return null; },
        },
        Node: {
            async findById(id) { return { _id: id, name: id }; },
        },
        topologyDraftWriteService: {
            async createLink() {
                writes += 1;
                throw new Error('draft write must not be reached');
            },
        },
    });

    const response = await request(router, {
        method: 'POST',
        body: validCreateBody({ tunnelPort: 0 }),
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, 'INVALID_REQUEST');
    assert.match(response.body.error.message, /tunnelPort/);
    assert.equal(writes, 0);
});
