'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const Module = require('node:module');
const { EventEmitter } = require('node:events');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'index.js'), 'utf8');
function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    // Like Mongoose's automatic init, retain a rejection observer while exposing
    // the original rejected promise for the application's all-settled drain.
    promise.catch(() => {});
    return { promise, resolve, reject };
}
async function flush() { for (let i = 0; i < 40; i++) await Promise.resolve(); }
function harness({ classic = true, signalAtConnect = false, stopError = null, disconnectError = null,
    lateInit = null, admitted = true } = {}) {
    const calls = [], errors = [], imports = [], timers = new Set(), immediates = [];
    const init = deferred();
    const originalFailure = new Error('route importer failed');
    const process = new EventEmitter(); process.env = { NODE_ENV: 'production', PANEL_DOMAIN: 'lm1.infograd.online' };
    process.exit = code => calls.push(`exit:${code}`);
    const forbiddenInit = () => { calls.push('fresh-init'); throw new Error('cleanup must not admit DDL'); };
    const mongoose = {
        models: { Admitted: { $init: init.promise, init: forbiddenInit }, Dormant: { init: forbiddenInit } },
        async connect() { calls.push('connect'); if (signalAtConnect) process.emit('SIGTERM'); },
        async disconnect() {
            calls.push('disconnect');
            // Real Mongoose disconnect deletes $init. A snapshot taken after
            // this boundary cannot recover or join the admitted promises.
            for (const model of Object.values(this.models)) delete model.$init;
            if (disconnectError) throw disconnectError;
        },
    };
    if (!admitted) delete mongoose.models.Admitted.$init;
    const lifecycle = { async stop() { calls.push('worker-stop'); if (stopError) throw stopError; } };
    const fakes = {
        './src/classicSettings': classic ? {} : null,
        mongoose,
        './config': { MONGO_URI: 'fake://no-io' },
        './src/utils/logger': { info() {}, warn() {}, error(...args) { errors.push(args); } },
        './src/modules/l2tpRuntimeLifecycleHook': { createL2tpRootLifecycle: () => lifecycle, productionSchemaConnectionOptions: () => ({}) },
        './src/modules/relay-l2tp': { registerModels() {} },
        express() { calls.push('http-published'); throw new Error('must not construct HTTP'); },
        cors() {}, compression() {}, 'cookie-parser'() {}, 'node-cron': {}, 'express-session'() {},
        'connect-redis': { default: class {} }, path: require('node:path'), fs: {}, ws: {},
        './src/middleware/auth': { requireScope() {} }, './src/middleware/i18n': {}, './src/middleware/rpsCounter': {},
    };
    const localRequire = name => {
        imports.push(name);
        if (name === './src/middleware/auth' && lateInit) {
            assert.ok(calls.includes('connect'), 'late model admission must follow early database startup');
            mongoose.models.LateImported = { $init: lateInit.promise, init: forbiddenInit };
            calls.push('late-init-admitted');
        }
        if (name.startsWith('./src/models/')) return {};
        if (name === './src/services/syncService') { calls.push('import-failed'); throw originalFailure; }
        assert.ok(Object.hasOwn(fakes, name), `unexpected dependency (no physical I/O allowed): ${name}`);
        return fakes[name];
    };
    const context = {
        process, console,
        setImmediate(fn) { immediates.push(fn); },
        setTimeout(fn, delay) { const handle = { fn, delay }; timers.add(handle); return handle; },
        clearTimeout(handle) { timers.delete(handle); },
    };
    const entry = vm.runInNewContext(Module.wrap(source), context, { filename: path.join(root, 'index.js') });
    entry({}, localRequire, { exports: {} }, path.join(root, 'index.js'), root);
    return { calls, errors, imports, timers, init, mongoose, process, originalFailure,
        async pump() {
            for (let i = 0; i < 15; i++) { await flush(); for (const fn of immediates.splice(0)) fn(); }
            await flush();
        },
    };
}

test('actual entry importer failure joins admitted automatic init before disconnect and exit', async () => {
    const h = harness(); await h.pump();
    try {
        assert.ok(h.calls.includes('import-failed'), 'must execute the actual entry past its async import yields');
        assert.equal(h.calls.includes('disconnect'), false, h.calls.join(','));
        assert.equal(h.calls.some(call => call.startsWith('exit:')), false, h.calls.join(','));
    } finally { h.init.resolve(); await h.pump(); }
    assert.deepEqual(h.calls, ['connect', 'import-failed', 'worker-stop', 'disconnect', 'exit:1']);
    assert.ok(h.errors.some(args => args.includes(h.originalFailure)), 'preserve the original assembly failure object');
    assert.equal(h.timers.size, 0);
});

test('actual entry joins a pending sibling even when the first admitted init rejected', async () => {
    const h = harness();
    const first = deferred(); const initFailure = new Error('first index failed');
    first.reject(initFailure);
    h.mongoose.models = { FirstRejected: { $init: first.promise }, ...h.mongoose.models };
    await h.pump();
    try {
        assert.equal(h.calls.includes('disconnect'), false, h.calls.join(','));
        assert.equal(h.calls.some(call => call.startsWith('exit:')), false, h.calls.join(','));
    } finally { h.init.resolve(); await h.pump(); }
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.ok(h.errors.some(args => args.includes(h.originalFailure)));
    assert.ok(h.errors.some(args => args.includes(initFailure)));
});

test('actual entry snapshots models admitted after connection during asynchronous import assembly', async () => {
    const late = deferred(); const h = harness({ lateInit: late });
    h.init.resolve(); await h.pump();
    try {
        assert.ok(h.calls.includes('late-init-admitted'));
        assert.equal(h.calls.includes('disconnect'), false, h.calls.join(','));
        assert.equal(h.calls.some(call => call.startsWith('exit:')), false);
    } finally { late.resolve(); await h.pump(); }
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.equal(h.calls.includes('fresh-init'), false);
});

test('actual entry early SIGTERM uses the bounded drain without importing or publishing HTTP', async () => {
    const h = harness({ signalAtConnect: true }); await h.pump();
    try {
        assert.equal(h.imports.includes('express'), false);
        assert.equal(h.calls.includes('http-published'), false);
        assert.equal(h.calls.includes('fresh-init'), false);
        assert.equal(h.calls.includes('disconnect'), false);
        assert.equal(h.calls.some(call => call.startsWith('exit:')), false);
        assert.deepEqual([...h.timers].map(timer => timer.delay), [30 * 60 * 1000]);
        h.process.emit('SIGINT'); h.process.emit('SIGTERM'); await h.pump();
        assert.equal(h.calls.filter(call => call === 'worker-stop').length, 1);
    } finally { h.init.resolve(); await h.pump(); }
    assert.deepEqual(h.calls, ['connect', 'worker-stop', 'disconnect', 'exit:0']);
    assert.equal(h.timers.size, 0);
});

test('actual entry bootstrap deadline reports uncertainty and never disconnects even after a late init settles', async () => {
    const h = harness({ signalAtConnect: true }); await h.pump();
    const deadlines = [...h.timers];
    assert.equal(deadlines.length, 1, 'bootstrap must be bounded');
    deadlines[0].fn(); await h.pump();
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.equal(h.calls.includes('disconnect'), false);
    assert.ok(h.errors.some(args => args.some(value => typeof value === 'string' && value.includes('completion is uncertain'))));
    h.init.resolve(); await h.pump();
    assert.equal(h.calls.includes('disconnect'), false);
    assert.equal(h.calls.filter(call => call.startsWith('exit:')).length, 1);
    assert.equal(h.timers.size, 0);
});

test('actual entry assembly-failure deadline remains referenced and refuses disconnect after expiry', async () => {
    const h = harness(); await h.pump();
    try {
        assert.deepEqual([...h.timers].map(timer => timer.delay), [30 * 60 * 1000]);
        [...h.timers][0].fn(); await h.pump();
        assert.equal(h.calls.at(-1), 'exit:1');
        assert.equal(h.calls.includes('disconnect'), false);
        assert.ok(h.errors.some(args => args.includes(h.originalFailure)));
    } finally { h.init.resolve(); await h.pump(); }
    assert.equal(h.calls.includes('disconnect'), false);
    assert.equal(h.calls.filter(call => call.startsWith('exit:')).length, 1);
    assert.equal(h.timers.size, 0);
});

test('actual ordinary production assembly failure never initializes dormant models', async () => {
    const h = harness({ classic: false, admitted: false }); await h.pump();
    assert.deepEqual(h.calls, ['import-failed', 'worker-stop', 'disconnect', 'exit:1']);
    assert.equal(h.imports.includes('./src/modules/relay-l2tp'), false, 'ordinary environment startup must keep its existing model registration');
    assert.ok(h.errors.some(args => args.includes(h.originalFailure)));
    assert.equal(h.timers.size, 0);
});

test('actual entry runtime-stop rejection still joins admitted init and preserves the primary importer failure', async () => {
    const cleanupFailure = new Error('stop failed');
    const h = harness({ stopError: cleanupFailure }); await h.pump();
    try {
        assert.equal(h.calls.some(call => call.startsWith('exit:')), false);
        assert.equal(h.calls.includes('disconnect'), false);
    } finally { h.init.resolve(); await h.pump(); }
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.equal(h.calls.includes('disconnect'), false, 'failed runtime join must not close its persistence');
    assert.ok(h.errors.some(args => args.includes(h.originalFailure)));
    assert.ok(h.errors.some(args => args.includes(cleanupFailure)));
    assert.equal(h.timers.size, 0);
});

test('actual entry disconnect failure cannot mask the original importer failure or escape the drain', async () => {
    const cleanupFailure = new Error('disconnect failed');
    const h = harness({ disconnectError: cleanupFailure }); h.init.resolve(); await h.pump();
    assert.equal(h.calls.at(-1), 'exit:1');
    assert.ok(h.errors.some(args => args.includes(h.originalFailure)));
    assert.ok(h.errors.some(args => args.includes(cleanupFailure)));
    assert.equal(h.timers.size, 0);
});
