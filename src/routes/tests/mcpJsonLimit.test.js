'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const test = require('node:test');
const express = require('express');
const requireAuth = require('../../middleware/auth');
const ApiKey = require('../../models/apiKeyModel');
const cache = require('../../services/cacheService');
const logger = require('../../utils/logger');
const mcp = require('../../services/mcpService');

const entry = require.resolve('../../../index');
const source = readFileSync(entry, 'utf8');
const requireFromEntry = createRequire(entry);
const limit = 100 * 1024;
const small = JSON.stringify({ jsonrpc: '2.0', id: 'fixture-id', method: 'tools/list' });
const pad = (body, size) => body + ' '.repeat(size - Buffer.byteLength(body));
const authHeader = { authorization: 'Bearer synthetic-mcp-key' };

test.after(() => require('../../services/sshPoolService').closeAll());

async function fixture(t) {
    const list = t.mock.method(mcp, 'listTools', () => []);
    const lookup = t.mock.method(ApiKey, 'findByKey', async () => ({
        _id: 'a'.repeat(24), scopes: ['mcp:enabled'], keyPrefix: 'fixture', rateLimit: 9,
    }));
    t.mock.method(ApiKey, 'findByIdAndUpdate', async () => {});
    let rateAllowed = true;
    const rate = t.mock.method(cache, 'checkApiKeyRateLimit', async () => ({ allowed: rateAllowed, count: 1, limit: 9 }));
    const log = t.mock.method(logger, 'error', () => {});

    // Run the actual entry's parser registration and terminal error handling,
    // not a second implementation or a copy of the production limits.
    const parsers = source.slice(source.indexOf('app.use(express.json());'), source.indexOf('let sessionMiddleware'));
    const errorHandler = source.slice(source.indexOf('// Error handler\n'), source.indexOf('// ==================== START SERVER'));
    assert.match(parsers, /app\.use\(express\.urlencoded/);
    assert.match(errorHandler, /app\.use\(\(err, req, res, next\)/);
    const app = express();
    new Function('app', 'express', 'require', parsers)(app, express, requireFromEntry);
    const mcpRoutes = require('../mcp');
    assert.match(source, /app\.use\('\/api\/mcp', requireAuth, mcpRoutes\);/);
    app.use('/api/mcp', requireAuth, mcpRoutes);
    const other = t.mock.fn((_req, res) => res.json({ ok: true }));
    app.post('/api/mcp-other', requireAuth, other);
    new Function('app', 'logger', errorHandler)(app, logger);

    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise(resolve => server.close(resolve)));
    const post = async (body, { path = '/api/mcp', headers = authHeader, type = 'application/json' } = {}) => {
        const res = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method: 'POST', headers: { 'content-type': type, ...headers }, body,
        });
        assert.match(res.headers.get('content-type'), /^application\/json\b/);
        return { status: res.status, body: await res.json(), rateLimit: res.headers.get('x-ratelimit-limit') };
    };
    return { post, list, lookup, rate, log, other, rateDeny: () => { rateAllowed = false; } };
}

test('MCP permits a small request and the original exact limit, but rejects one extra byte before auth or dispatch', async t => {
    const f = await fixture(t);
    const expected = { status: 200, body: { jsonrpc: '2.0', id: 'fixture-id', result: { tools: [] } }, rateLimit: '9' };
    assert.deepEqual(await f.post(small), expected);
    assert.deepEqual(await f.post(pad(small, limit)), expected);
    assert.equal(f.list.mock.callCount(), 2);
    assert.equal(f.lookup.mock.callCount(), 2);
    assert.equal(f.rate.mock.callCount(), 2);

    const messages = [
        ['en-US', 'The MCP JSON request body is too large. Send a smaller request.'],
        ['ru-RU', 'Тело запроса MCP JSON слишком большое. Отправьте запрос меньшего размера.'],
        ['zh-Hans', 'MCP JSON 请求体过大。请发送更小的请求。'],
    ];
    for (const [language, message] of messages) {
        const denied = await f.post(pad(small, limit + 1), {
            headers: { ...authHeader, 'accept-language': language, accept: 'text/event-stream' },
        });
        assert.deepEqual(denied, { status: 413, rateLimit: null,
            body: { jsonrpc: '2.0', id: null, error: { code: -32000, message } } });
    }
    assert.equal(f.lookup.mock.callCount(), 2);
    assert.equal(f.rate.mock.callCount(), 2);
    assert.equal(f.list.mock.callCount(), 2);
    assert.equal(f.log.mock.callCount(), 0);
});

test('unrelated parser errors and existing authentication/rate limit responses keep their status', async t => {
    const f = await fixture(t);
    assert.equal((await f.post(small, { headers: {} })).status, 401);
    f.rateDeny();
    assert.equal((await f.post(small)).status, 429);
    assert.equal(f.list.mock.callCount(), 0);
    assert.equal(f.lookup.mock.callCount(), 1);
    assert.equal(f.rate.mock.callCount(), 1);

    for (const [body, options] of [
        [pad(small, limit + 1), { path: '/api/mcp-other' }],
        [pad(small, limit + 1), { path: '/api/mcp/messages' }],
        ['padding=' + 'x'.repeat(limit), { type: 'application/x-www-form-urlencoded' }],
        ['{', {}],
    ]) {
        const denied = await f.post(body, options);
        assert.equal(denied.status, 500);
        assert.equal(denied.body.jsonrpc, undefined);
        assert.equal(denied.rateLimit, null);
    }
    assert.equal(f.other.mock.callCount(), 0);
    assert.equal(f.lookup.mock.callCount(), 1);
    assert.equal(f.rate.mock.callCount(), 1);
    assert.equal(f.list.mock.callCount(), 0);
});
