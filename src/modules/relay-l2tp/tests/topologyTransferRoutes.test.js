'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const express = require('express');

const {
    createTopologyTransferDraftsRouter,
} = require('../../../routes/topologyTransferDrafts');

const ROOT_ENTRY_SOURCE = fs.readFileSync(path.resolve(__dirname, '../../../../index.js'), 'utf8');

async function request(router, { method = 'GET', path, body, headers = {} }) {
    const app = express();
    app.use(express.json());
    app.use(router);
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method,
            headers: {
                ...(body === undefined ? {} : { 'content-type': 'application/json' }),
                ...headers,
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await response.text();
        let responseBody;
        if (text) {
            try {
                responseBody = JSON.parse(text);
            } catch {
                responseBody = text;
            }
        }
        return {
            status: response.status,
            body: responseBody,
        };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

function authHarness(calls) {
    return {
        requireAuth(req, res, next) {
            calls.push('auth');
            if (req.headers['x-test-auth'] === 'api') {
                req.apiKey = { keyPrefix: 'ck_test', scopes: ['nodes:read', 'nodes:write'] };
                return next();
            }
            if (req.headers['x-test-auth'] === 'session') {
                req.session = { authenticated: true };
                return next();
            }
            return res.status(401).json({ error: 'authentication required' });
        },
        requireScope(scope) {
            return (req, res, next) => {
                calls.push(`scope:${scope}`);
                next();
            };
        },
        csrf(req, res, next) {
            calls.push('csrf');
            if (req.headers['x-test-csrf'] !== 'valid') {
                return res.status(403).json({ error: 'csrf rejected' });
            }
            return next();
        },
        issueCsrf(req) {
            calls.push('issueCsrf');
            assert.equal(req.session.authenticated, true);
            return 'session-csrf-token';
        },
    };
}

function emptyTransfer(kind = 'relay-l2tp-topology-transfer') {
    return {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind,
        topology: { nodes: [], links: [], routeGroups: [], relayStates: [] },
    };
}

test('mounts the protected router at the explicit topology transfer drafts path', () => {
    assert.match(
        ROOT_ENTRY_SOURCE,
        /const topologyTransferDraftsRoutes = require\('\.\/src\/routes\/topologyTransferDrafts'\);/,
    );
    assert.match(
        ROOT_ENTRY_SOURCE,
        /app\.use\('\/api\/cascade\/topology-transfer-drafts', topologyTransferDraftsRoutes\);/,
    );
});

test('protects current export with authentication and nodes:read scope', async () => {
    const calls = [];
    const auth = authHarness(calls);
    const service = {
        async exportCurrentTopology() {
            calls.push('exportCurrentTopology');
            return emptyTransfer();
        },
    };
    const router = createTopologyTransferDraftsRouter({ service, ...auth });

    const unauthorized = await request(router, { path: '/export' });
    assert.equal(unauthorized.status, 401);
    assert.deepEqual(calls, ['auth']);

    calls.length = 0;
    const response = await request(router, {
        path: '/export',
        headers: { 'x-test-auth': 'api' },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, emptyTransfer());
    assert.deepEqual(calls, ['auth', 'scope:nodes:read', 'exportCurrentTopology']);
});

test('creates export DRAFTs only with nodes:write and session-only CSRF', async () => {
    const calls = [];
    const auth = authHarness(calls);
    const service = {
        async createExportDraft(input) {
            calls.push({ method: 'createExportDraft', input });
            return {
                draftId: '4ac7d68f-5c40-47e7-a329-6daf108b09dd',
                status: 'DRAFT',
                source: 'export',
                name: input.name,
                document: emptyTransfer(),
                counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
            };
        },
    };
    const router = createTopologyTransferDraftsRouter({ service, ...auth });
    const body = {
        name: 'Current safe topology',
        apply: true,
        deploy: true,
        secret: 'must-not-reach-service',
    };

    const blocked = await request(router, {
        method: 'POST',
        path: '/export',
        headers: { 'x-test-auth': 'session' },
        body,
    });
    assert.equal(blocked.status, 403);
    assert.deepEqual(calls, ['auth', 'scope:nodes:write', 'csrf']);

    calls.length = 0;
    const response = await request(router, {
        method: 'POST',
        path: '/export',
        headers: { 'x-test-auth': 'api' },
        body,
    });
    assert.equal(response.status, 201);
    assert.equal(response.body.status, 'DRAFT');
    assert.deepEqual(calls, [
        'auth',
        'scope:nodes:write',
        { method: 'createExportDraft', input: { name: body.name } },
    ]);
});

test('requires session CSRF for import but lets scoped API keys use non-cookie auth', async () => {
    const calls = [];
    const auth = authHarness(calls);
    const service = {
        async importTopologyDraft(input) {
            calls.push({ method: 'importTopologyDraft', input });
            return {
                draftId: '19ff16e6-2f6d-482a-aa52-90fb1dc618de',
                status: 'DRAFT',
                source: 'import',
                name: input.name,
                document: { ...input.document, kind: 'relay-l2tp-topology-import-draft' },
                counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
            };
        },
    };
    const router = createTopologyTransferDraftsRouter({ service, ...auth });
    const body = {
        name: 'Imported topology',
        document: emptyTransfer(),
        apply: true,
        deploy: true,
        rawCommand: 'must-not-reach-service',
    };

    const blocked = await request(router, {
        method: 'POST',
        path: '/import',
        headers: { 'x-test-auth': 'session' },
        body,
    });
    assert.equal(blocked.status, 403);
    assert.deepEqual(calls, ['auth', 'scope:nodes:write', 'csrf']);

    calls.length = 0;
    const sessionResponse = await request(router, {
        method: 'POST',
        path: '/import',
        headers: { 'x-test-auth': 'session', 'x-test-csrf': 'valid' },
        body,
    });
    assert.equal(sessionResponse.status, 201);
    assert.deepEqual(calls, [
        'auth',
        'scope:nodes:write',
        'csrf',
        { method: 'importTopologyDraft', input: { name: body.name, document: body.document } },
    ]);

    calls.length = 0;
    const apiResponse = await request(router, {
        method: 'POST',
        path: '/import',
        headers: { 'x-test-auth': 'api' },
        body,
    });
    assert.equal(apiResponse.status, 201);
    assert.deepEqual(calls, [
        'auth',
        'scope:nodes:write',
        { method: 'importTopologyDraft', input: { name: body.name, document: body.document } },
    ]);
});

test('supports scoped DRAFT list/read and session CSRF token discovery', async () => {
    const calls = [];
    const auth = authHarness(calls);
    const draft = {
        draftId: '19ff16e6-2f6d-482a-aa52-90fb1dc618de',
        status: 'DRAFT',
        source: 'import',
        name: 'Imported topology',
        counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
    };
    const service = {
        async listDrafts() {
            calls.push('listDrafts');
            return [draft];
        },
        async getDraft(draftId) {
            calls.push({ method: 'getDraft', draftId });
            return { ...draft, document: emptyTransfer('relay-l2tp-topology-import-draft') };
        },
    };
    const router = createTopologyTransferDraftsRouter({ service, ...auth });

    const listed = await request(router, {
        path: '/drafts',
        headers: { 'x-test-auth': 'api' },
    });
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.body, [draft]);

    const read = await request(router, {
        path: `/drafts/${draft.draftId}`,
        headers: { 'x-test-auth': 'api' },
    });
    assert.equal(read.status, 200);
    assert.equal(read.body.draftId, draft.draftId);

    const csrfToken = await request(router, {
        path: '/csrf-token',
        headers: { 'x-test-auth': 'session' },
    });
    assert.equal(csrfToken.status, 200);
    assert.deepEqual(csrfToken.body, {
        csrfRequired: true,
        csrfToken: 'session-csrf-token',
    });

    const apiCsrf = await request(router, {
        path: '/csrf-token',
        headers: { 'x-test-auth': 'api' },
    });
    assert.equal(apiCsrf.status, 200);
    assert.deepEqual(apiCsrf.body, { csrfRequired: false });
    assert.deepEqual(calls, [
        'auth',
        'scope:nodes:read',
        'listDrafts',
        'auth',
        'scope:nodes:read',
        { method: 'getDraft', draftId: draft.draftId },
        'auth',
        'scope:nodes:read',
        'issueCsrf',
        'auth',
        'scope:nodes:read',
    ]);
});

test('exposes no topology apply, mutation, deployment, or deletion route', async () => {
    const calls = [];
    const auth = authHarness(calls);
    const router = createTopologyTransferDraftsRouter({ service: {}, ...auth });

    for (const path of ['/apply', '/deploy', '/drafts/id']) {
        const response = await request(router, {
            method: 'DELETE',
            path,
            headers: { 'x-test-auth': 'api' },
        });
        assert.equal(response.status, 404, path);
    }
});
