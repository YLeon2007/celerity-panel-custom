'use strict';

const assert = require('node:assert/strict');
const { EventEmitter, once } = require('node:events');
const { readFileSync } = require('node:fs');
const { IncomingMessage, ServerResponse } = require('node:http');
const { createRequire } = require('node:module');
const { dirname, resolve } = require('node:path');
const { Duplex } = require('node:stream');
const test = require('node:test');
const { compileFunction } = require('node:vm');
const express = require('express');

const entry = resolve(__dirname, '../../../index.js');

test('the app sends Referrer-Policy: same-origin on the panel redirect', { timeout: 5000 }, async t => {
    const entryRequire = createRequire(entry);
    const Settings = entryRequire('./src/models/settingsModel');
    t.mock.method(Settings, 'get', async () => ({}));
    const sshPool = entryRequire('./src/services/sshPoolService');
    t.after(() => sshPool.closeAll()); // Dispose the import-time idle cleanup timer.

    // Run the unchanged entry, observing the real Express app. Keep startup
    // parked at Mongo connect, before Redis, listeners or background jobs.
    const mongoose = Object.create(entryRequire('mongoose'));
    let app, connectCalls = 0;
    mongoose.connect = () => { connectCalls += 1; return new Promise(() => {}); };
    const fixtureProcess = Object.assign(new EventEmitter(), { env: process.env });
    const load = name => {
        if (name === 'mongoose') return mongoose;
        if (name === 'express') return Object.assign(() => (app = express()), express);
        return entryRequire(name);
    };
    compileFunction(readFileSync(entry, 'utf8'), ['require', 'module', '__dirname', 'process'], { filename: entry })(
        load, { exports: {} }, dirname(entry), fixtureProcess,
    );
    assert.equal(connectCalls, 1);
    assert.ok(app);

    const chunks = [];
    const socket = new Duplex({ read() {}, write(chunk, _encoding, done) { chunks.push(chunk); done(); } });
    const req = new IncomingMessage(socket);
    Object.assign(req, { method: 'GET', url: '/panel', complete: true, headers: { host: 'panel.example.test' } });
    req.push(null);
    const res = new ServerResponse(req);
    res.assignSocket(socket);
    const finished = once(res, 'finish');
    app(req, res);
    await finished;
    const [headers] = Buffer.concat(chunks).toString('latin1').split('\r\n\r\n', 1);
    assert.equal(res.statusCode, 302);
    assert.equal(res.getHeader('location'), '/panel/login');
    assert.match(headers, /^Referrer-Policy: same-origin\r?$/mi);
    assert.doesNotMatch(headers, /^(Content-Security-Policy|Cross-Origin-Embedder-Policy):/mi);
});
