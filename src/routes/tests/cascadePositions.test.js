'use strict';

const assert = require('node:assert/strict');
const { IncomingMessage, ServerResponse } = require('node:http');
const { Duplex } = require('node:stream');
const test = require('node:test');
const express = require('express');
const requireAuth = require('../../middleware/auth');
const ApiKey = require('../../models/apiKeyModel');
const HyNode = require('../../models/hyNodeModel');
const Settings = require('../../models/settingsModel');
const cache = require('../../services/cacheService');
const sshPool = require('../../services/sshPoolService');
const cascadeRoutes = require('../cascade');
const { routerForRebuild } = require('../cascadeRebuild');
const { createCascadeTopologyDeployRouter } = require('../cascadeTopologyDeploy');
const { issuePanelCsrfToken } = require('../panel/csrf');

test.after(() => sshPool.closeAll()); // Stop the pool's import-time cleanup timer; it has no connections.

const id = '507F1F77BCF86CD799439011';
const nodePosition = { id, x: 27.34, y: -14.26 };
const internet = { id: 'internet', x: -6.78, y: 4.22 };
const validBody = { positions: [nodePosition, internet] };
const host = 'panel.example.invalid';
const origin = `http://${host}`;
const url = '/api/cascade/topology/positions';

function fixture(t, rebuild) {
    const savedMode = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = String(rebuild);
    t.after(() => {
        if (savedMode === undefined) delete process.env.C3_REBUILD_ENABLED;
        else process.env.C3_REBUILD_ENABLED = savedMode;
    });

    const writes = [];
    t.mock.method(HyNode, 'bulkWrite', async (...args) => { writes.push(['nodes', ...args]); });
    t.mock.method(Settings, 'findByIdAndUpdate', async (...args) => { writes.push(['settings', ...args]); });
    t.mock.method(ApiKey, 'findByKey', async key => {
        if (!['read', 'write'].includes(key)) return null;
        return { _id: key, keyPrefix: key, scopes: [`nodes:${key}`] };
    });
    t.mock.method(ApiKey, 'findByIdAndUpdate', async () => {}); // Auth's unrelated usage accounting.
    t.mock.method(cache, 'checkApiKeyRateLimit', async () => ({ allowed: true, limit: 10, count: 1 }));

    const session = { authenticated: true };
    const token = issuePanelCsrfToken({ session });
    const app = express();
    app.use(express.json(), express.urlencoded({ extended: true }));
    app.use((req, _res, next) => {
        if (req.headers.cookie === 'fixture=admin') req.session = session;
        next();
    });
    // Same cascade mount order as index.js, without entry-point startup or I/O.
    if (rebuild) app.use('/api/cascade', requireAuth, routerForRebuild({ service: {} }));
    app.use('/api/cascade/topology', createCascadeTopologyDeployRouter());
    app.use('/api/cascade', requireAuth, cascadeRoutes);

    function post(body, { raw = false, headers = {} } = {}) {
        return new Promise((resolve, reject) => {
            const chunks = [];
            const wire = new Duplex({ read() {}, write(chunk, _encoding, done) { chunks.push(chunk); done(); } });
            const bytes = raw ? body : JSON.stringify(body) ?? '';
            const req = new IncomingMessage(wire);
            Object.assign(req, { method: 'POST', url, complete: true, headers: {
                host, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(bytes)), ...headers,
            } });
            const res = new ServerResponse(req);
            res.assignSocket(wire);
            res.once('error', reject);
            res.once('finish', () => {
                const response = Buffer.concat(chunks).toString();
                const body = response.slice(response.indexOf('\r\n\r\n') + 4);
                resolve({ status: res.statusCode, body: res.getHeader('content-type')?.includes('application/json')
                    ? JSON.parse(body) : body });
                wire.destroy();
            });
            if (bytes) req.push(bytes);
            req.push(null);
            app(req, res);
        });
    }
    const admin = { cookie: 'fixture=admin', origin };
    return { post, admin, sessionHeaders: { ...admin, 'x-csrf-token': token }, token, writes };
}

for (const rebuild of [false, true]) {
    const mode = rebuild ? 'Rebuild' : 'Classic';

    test(`${mode}: normalized positions reach only the existing map writes`, async t => {
        const { post, sessionHeaders, admin, writes } = fixture(t, rebuild);
        assert.deepEqual(await post({ ...validBody, ignored: true }, { headers: rebuild ? sessionHeaders : admin }),
            { status: 200, body: { success: true } });
        assert.deepEqual(writes, [
            ['nodes', [{ updateOne: { filter: { _id: id.toLowerCase() },
                update: { $set: { 'mapPosition.x': 27.3, 'mapPosition.y': -14.3 } } } }], { ordered: false }],
            ['settings', 'settings', { $set: { 'networkMap.internetPosition': { x: -6.8, y: 4.2 } } }, { upsert: true }],
        ]);
        writes.length = 0;
        assert.deepEqual(await post({ positions: [] }, { headers: sessionHeaders }),
            { status: 200, body: { success: true } });
        assert.deepEqual(writes, []);
    });

    test(`${mode}: invalid bodies and mixed batches make no map writes`, async t => {
        const { post, sessionHeaders: headers, writes } = fixture(t, rebuild);
        const mixed = [
            ['extra dotted field', { ...nodePosition, 'mapPosition.x': 12 }, 'positions.2'],
            ['null row', null, 'positions.2'],
            ['dot in ID', { ...nodePosition, id: `${id.slice(0, -1)}.` }, 'positions.2.id'],
            ['object ID', { ...nodePosition, id: {} }, 'positions.2.id'],
            ['padded ID', { ...nodePosition, id: ` ${id}` }, 'positions.2.id'],
            ['unknown virtual ID', { ...internet, id: 'Internet' }, 'positions.2.id'],
            ['numeric string', { ...nodePosition, x: '12' }, 'positions.2.x'],
            ['NaN serialized as null', { ...nodePosition, x: NaN }, 'positions.2.x'],
            ['missing y', { ...nodePosition, y: undefined }, 'positions.2.y'],
            ['positive bounds', { ...nodePosition, x: 1e6 + 1 }, 'positions.2.x'],
            ['negative bounds', { ...nodePosition, y: -1e6 - 1 }, 'positions.2.y'],
        ];
        const cases = [
            ...mixed.map(([name, row, where]) => [name, { positions: [...validBody.positions, row] }, where]),
            ['missing body', undefined, 'positions'],
            ['array body', [], 'body'],
            ['not an array', { positions: {} }, 'positions'],
            ['null positions', { positions: null }, 'positions'],
            ['over limit', { positions: Array(1001).fill(nodePosition) }, 'positions'],
        ];

        for (const [name, body, where] of cases) {
            const response = await post(body, { headers });
            assert.deepEqual(writes, [], `${name}: nothing written`);
            assert.deepEqual(response, { status: 400, body: { error: `invalid ${where}` } }, name);
        }
        // JSON.parse accepts scientific notation which overflows to Infinity.
        const overflow = `{"positions":[${JSON.stringify(nodePosition)}, {"id":"internet","x":1e400,"y":0}]}`;
        assert.deepEqual(await post(overflow, { raw: true, headers }),
            { status: 400, body: { error: 'invalid positions.1.x' } });
        assert.deepEqual(writes, []);
    });

    test(`${mode}: the existing route requires authentication and nodes:write`, async t => {
        const { post, writes } = fixture(t, rebuild);
        assert.equal((await post(validBody)).status, 401);
        assert.deepEqual(await post(validBody, { headers: { 'x-api-key': 'read' } }),
            { status: 403, body: { error: 'Insufficient permissions', required: 'nodes:write' } });
        assert.deepEqual(writes, []);
        assert.deepEqual(await post({ positions: [nodePosition] }, { headers: { 'x-api-key': 'write' } }),
            { status: 200, body: { success: true } });
        assert.equal(writes.length, 1);
    });
}

test('Rebuild: session writes pass the actual panel CSRF guard before validation', async t => {
    const { post, admin, sessionHeaders, token, writes } = fixture(t, true);
    for (const [headers, code] of [
        [admin, 'CSRF_TOKEN_INVALID'],
        [{ ...sessionHeaders, 'x-csrf-token': issuePanelCsrfToken({ session: { authenticated: true } }) }, 'CSRF_TOKEN_INVALID'],
        [{ ...sessionHeaders, origin: 'http://other.example.invalid' }, 'CSRF_ORIGIN_INVALID'],
    ]) {
        assert.deepEqual(await post({}, { headers }), { status: 403, body: { error: 'CSRF validation failed', code } });
        assert.deepEqual(writes, []);
    }
    assert.deepEqual(await post({ positions: [internet], _csrf: token }, { headers: admin }),
        { status: 200, body: { success: true } });
    assert.deepEqual(writes, [
        ['settings', 'settings', { $set: { 'networkMap.internetPosition': { x: -6.8, y: 4.2 } } }, { upsert: true }],
    ]);
});

test('real schema handles non-JSON numbers and accepts exact limits', () => {
    const { parsePositionsBody, MAX_POSITIONS, MAX_COORD } = require('../../utils/cascadeTopology');
    const boundary = { id, x: MAX_COORD, y: -MAX_COORD };
    const valid = parsePositionsBody({ positions: Array(MAX_POSITIONS).fill(boundary) });
    assert.equal(valid.ok, true);
    assert.equal(valid.positions.length, 1000);
    assert.deepEqual(valid.positions[0], { ...boundary, id: id.toLowerCase() });
    for (const x of [NaN, Infinity, -Infinity, undefined]) {
        assert.deepEqual(parsePositionsBody({ positions: [{ ...boundary, x }] }),
            { ok: false, error: 'invalid positions.0.x' });
    }
    assert.deepEqual(parsePositionsBody(null), { ok: false, error: 'invalid body' });
});
