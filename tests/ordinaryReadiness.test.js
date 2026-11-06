'use strict';
// Execute the actual registration/handler bytes; DB/cache timing is explicitly
// modeled here. The companion integration test supplies real entry/DB evidence.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const route = source.slice(source.indexOf('// A separate opt-in serving witness:'), source.indexOf("app.get('/health'"));
const READY = 'c3-classic-ready-v1\n', NOT_READY = 'c3-classic-not-ready-v1\n';
function fixture(options = {}) {
    let handler;
    const calls = [];
    const scope = { classicSettings: null, classicStartupComplete: true, shutdownPromise: undefined,
        process: { env: { C3_TEST_CLASSIC_READY: 'true' } }, config: { PANEL_DOMAIN: 'test.infograd.online' },
        app: { get(url, fn) { assert.equal(url, '/classic-ready'); handler = fn; } },
        mongoose: { connection: { readyState: 1, db: { async command(value, limits) { calls.push(['mongo', value, limits]); return { ok: 1 }; } } } },
        cacheService: { redis: { status: 'ready', async ping() { calls.push(['redis']); return 'PONG'; } } },
        ...options };
    vm.createContext(scope); vm.runInContext(route, scope);
    return { scope, calls, get handler() { return handler; }, async invoke(req = {}) {
        assert.ok(handler, 'real route must be registered');
        const response = { headers: {}, set(k, v) { this.headers[k] = v; return this; },
            status(code) { this.code = code; return this; }, type(v) { this.contentType = v; return this; }, end(body) { this.body = body; return this; } };
        // Keep a conventional initial code separate from the response status method.
        response.code = 200;
        await handler(req, response); return response;
    } };
}
function expect(r, ready) {
    assert.equal(r.code, ready ? 200 : 503); assert.equal(r.body, ready ? READY : NOT_READY);
    assert.equal(r.headers['Cache-Control'], 'no-store'); assert.equal(r.contentType, 'text/plain');
}
test('ordinary opt-in executes the identical current Mongo and Redis PING witness', async () => {
    const f = fixture(); expect(await f.invoke(), true);
    assert.equal(f.calls.length, 2);
    assert.equal(JSON.stringify(f.calls), JSON.stringify([['mongo', { ping: 1 }, { timeoutMS: 1000 }], ['redis']]));
});
for (const [name, env, domain] of [
    ['absent flag', {}, 'test.infograd.online'], ['false flag', { C3_TEST_CLASSIC_READY: 'false' }, 'test.infograd.online'],
    ['nonliteral flag', { C3_TEST_CLASSIC_READY: 'TRUE' }, 'test.infograd.online'],
    ['foreign identity', { C3_TEST_CLASSIC_READY: 'true' }, 'other.invalid'],
    ['production identity', { C3_TEST_CLASSIC_READY: 'true' }, 'lm1.infograd.online'],
]) test('no ordinary endpoint for ' + name, () => {
    assert.equal(fixture({ process: { env }, config: { PANEL_DOMAIN: domain } }).handler, undefined);
});
test('existing fresh mode is independent of the ordinary TEST flag', async () => {
    const f = fixture({ classicSettings: {}, process: { env: {} } }); expect(await f.invoke(), true);
});
for (const [name, change] of [
    ['boot incomplete', f => { f.scope.classicStartupComplete = false; }],
    ['shutdown started', f => { f.scope.shutdownPromise = Promise.resolve(); }],
    ['Mongo disconnected', f => { f.scope.mongoose.connection.readyState = 0; }],
    ['Mongo connecting', f => { f.scope.mongoose.connection.readyState = 2; }],
    ['Redis missing', f => { f.scope.cacheService.redis = null; }],
    ['Redis not ready', f => { f.scope.cacheService.redis.status = 'reconnecting'; }],
]) test(name + ' returns 503 before either PING', async () => {
    const f = fixture(); change(f); expect(await f.invoke(), false); assert.deepEqual(f.calls, []);
});
for (const which of ['mongo', 'redis']) test(which + ' PING rejection fails closed', async () => {
    const f = fixture(); const reject = async () => { throw Error('modeled dependency refusal'); };
    if (which === 'mongo') f.scope.mongoose.connection.db.command = reject;
    else f.scope.cacheService.redis.ping = reject;
    expect(await f.invoke(), false);
});
for (const which of ['mongo', 'redis']) test('shutdown while ' + which + ' PING is pending cannot emit 200', async () => {
    const f = fixture(); let release;
    const pending = new Promise(resolve => { release = resolve; });
    if (which === 'mongo') f.scope.mongoose.connection.db.command = () => pending;
    else f.scope.cacheService.redis.ping = () => pending;
    const response = f.invoke();
    f.scope.shutdownPromise = new Promise(() => {});
    // New requests refuse immediately, even while the previous PING/drain waits.
    expect(await f.invoke(), false);
    release(); expect(await response, false);
});
test('request inputs and later environment edits cannot change route exposure', async () => {
    const f = fixture(); f.scope.process.env.C3_TEST_CLASSIC_READY = 'false';
    expect(await f.invoke({ query: { C3_TEST_CLASSIC_READY: 'false' }, headers: { host: 'other.invalid' } }), true);
    const disabled = fixture({ process: { env: {} } }); disabled.scope.process.env.C3_TEST_CLASSIC_READY = 'true';
    assert.equal(disabled.handler, undefined);
});
