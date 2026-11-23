'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const { resolve } = require('node:path');
const express = require('express');
const { issuePanelCsrfToken } = require('../csrf');
const { i18nMiddleware } = require('../../../middleware/i18n');

const id = 'a'.repeat(24);
const url = `/panel/rebuild/relays/${id}/l2tp/install/recover`;
const privateFixture = 'PRIVATE_INSTALL_RECOVERY_FIXTURE';
const unconfirmed = { error: { code: 'REBUILD_L2TP_INSTALL_RECOVERY_UNCONFIRMED', retryAllowed: false } };

function request(app, url, { method = 'POST', session, sessionID, headers, raw = '{}', ip = '192.0.2.10' } = {}) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { chunks.push(chunk.toString()); done(); } });
        socket.remoteAddress = ip;
        const req = new IncomingMessage(socket);
        Object.assign(req, { method, url, session, sessionID, apiKey: { scopes: ['nodes:write'] }, complete: true,
            headers: { host: 'fixture.invalid', ...headers,
                ...(method === 'POST' && { 'content-length': String(Buffer.byteLength(raw)) }) } });
        if (method === 'POST' && raw) req.push(Buffer.from(raw));
        req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            resolve({ status: res.statusCode, headers: res.getHeaders(), body: chunks.join('').split('\r\n\r\n').slice(1).join('\r\n\r\n') });
            socket.destroy();
        });
        app(req, res);
    });
}

function mount(t, { enabled = true } = {}) {
    const config = require('../../../../config');
    const Settings = require('../../../models/settingsModel');
    const { invalidateOnboardingCache } = require('../helpers');
    t.mock.method(Settings, 'get', async () => ({ deployment: { completed: f.onboarded } }));
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: async () => {
        if (f.onboardingError) throw new Error(privateFixture);
        return { deployment: { completed: f.onboarded } };
    } }) }));
    const env = { C3_REBUILD_ENABLED: String(enabled), C3_REBUILD_L2TP_INSTALL_ENABLED: 'true' };
    const originals = { mode: process.env.C3_REBUILD_ENABLED, whitelist: config.PANEL_IP_WHITELIST };
    process.env.C3_REBUILD_ENABLED = env.C3_REBUILD_ENABLED;
    config.PANEL_IP_WHITELIST = '192.0.2.10';
    invalidateOnboardingCache();
    t.after(() => {
        if (originals.mode === undefined) delete process.env.C3_REBUILD_ENABLED;
        else process.env.C3_REBUILD_ENABLED = originals.mode;
        config.PANEL_IP_WHITELIST = originals.whitelist;
        invalidateOnboardingCache();
    });

    const f = { calls: [], loads: 0, constructs: 0, reads: 0, limits: 0, onboarded: true,
        result: { status: 'can_install_again', backupId: privateFixture, token: privateFixture } };
    const rejectEffect = () => assert.fail('Unexpected real effect in wiring test');
    const deps = { env, Link: {}, Node: {}, State: {}, L2tpUser: {},
        locks: { run: rejectEffect }, relayGrantStore: { snapshot: rejectEffect },
        createRelayDirect: rejectEffect, assertNoRelayAccountIntent: rejectEffect, cache: {}, sync: {} };
    const service = require('../../../services/rebuildService');
    const create = service.createRebuildService;
    t.mock.method(service, 'createRebuildService', () => { f.constructs++; return create(deps); });
    const load = Module._load;
    t.mock.method(Module, '_load', function (name, parent, ...args) {
        if (name !== './rebuildRelayInstallRecovery' || !parent?.filename.endsWith('/services/rebuildService.js')) {
            return load.call(this, name, parent, ...args);
        }
        f.loads++;
        if (f.missing) throw Object.assign(new Error(privateFixture), { code: 'MODULE_NOT_FOUND' });
        return { createRebuildRelayInstallRecovery: backendDeps => async (...ids) => {
            f.calls.push({ ids, backendDeps });
            if (f.failure) throw f.failure;
            return f.result;
        } };
    });
    const app = express();
    app.set('view engine', 'ejs');
    app.set('views', resolve(__dirname, '../../../../views'));
    if (enabled) app.use(require('../rebuildL2tp').rebuildL2tpIngress);
    app.use(require('cors')({ origin: 'http://fixture.invalid', credentials: true }));
    app.use(express.json());
    app.use(i18nMiddleware);
    app.use('/panel', require('../index').createPanelRouter({
        l2tpRateLimiter: (_req, _res, next) => { f.limits++; next(); },
        rebuildL2tpOverview: { overview: async () => {
            f.reads++;
            return { relays: [{ id, status: 'installing', bound: true, grantSource: 'db', canRecoverInstall: true,
                name: 'Fixture', ip: '192.0.2.20', backupId: privateFixture, token: privateFixture }], accounts: [],
                canManageAccounts: false };
        } },
    }));
    const session = { authenticated: true, adminUsername: 'fixture-admin' };
    const headers = { 'accept-language': 'ru', 'content-type': 'application/json', 'x-csrf-token': issuePanelCsrfToken({ session }) };
    f.send = (path = url, options = {}) => request(app, path, { session, sessionID: 'fixture-session', headers, ...options });
    return Object.assign(f, { env, deps, session, headers });
}

function checked(response, status) {
    assert.equal(response.status, status);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.ok(!response.body.includes(privateFixture), 'response exposed private backend data');
    return response;
}

test('render, refresh, view queries and non-POST methods never construct or invoke a recovery writer', async t => {
    const f = mount(t);
    for (const path of ['/panel/l2tp', '/panel/l2tp', `/panel/l2tp?recover=${id}`]) {
        const { body } = checked(await f.send(path, { method: 'GET' }), 200);
        assert.match(body, /Проверить и продолжить/);
        assert.ok(body.includes(url));
        assert.doesNotMatch(body, /data-install-url=/);
    }
    const review = checked(await f.send(`/panel/l2tp?identityChanged=${id}`, { method: 'GET' }), 200);
    assert.doesNotMatch(review.body, /data-install-recovery-url=/);
    assert.doesNotMatch(checked(await f.send('/panel/l2tp?view=only', { method: 'GET' }), 200).body,
        /data-install-recovery-url=/);
    assert.doesNotMatch(checked(await f.send('/panel/l2tp', { method: 'GET', sessionID: undefined }), 200).body,
        /data-install-recovery-url=/);
    for (const method of ['GET', 'HEAD', 'PUT', 'DELETE']) {
        assert.equal(checked(await f.send(url, { method }), 405).headers.allow, 'POST');
    }
    checked(await f.send(url, { method: 'OPTIONS', headers: { origin: 'http://fixture.invalid' } }), 204);
    assert.equal(f.reads, 6);
    assert.equal(f.constructs + f.loads + f.calls.length, 0);
});

test('mounted progress is an authenticated no-store read and never loads an install writer', async t => {
    const f = mount(t);
    const State = require('../../../modules/relay-l2tp/models/relayL2tpStateModel');
    const at = new Date('2026-01-01T00:00:00.000Z');
    let reads = 0;
    t.mock.method(State.collection, 'findOne', async (filter, opts) => {
        reads++;
        assert.equal(String(filter.node), id);
        assert.deepEqual(filter.status, { $in: ['installing', 'installed'] });
        assert.equal(filter.desiredState, 'installed');
        assert.deepEqual(opts.projection, { status: 1, installProgress: 1, _id: 0 });
        assert.equal(opts.readConcern.level, 'majority');
        return { status: 'installing', backupId: privateFixture, installProgress: { stage: 'reserve', percent: 10, at } };
    });
    const progressUrl = url.replace('/recover', '/progress');
    checked(await f.send(progressUrl, { method: 'GET', ip: '192.0.2.11' }), 403);
    checked(await f.send(progressUrl, { method: 'GET', session: undefined }), 302);
    checked(await f.send(progressUrl, { method: 'GET', sessionID: undefined }), 403);
    checked(await f.send(`${progressUrl}?token=fixture`, { method: 'GET' }), 400);
    assert.equal(reads, 0);
    assert.deepEqual(JSON.parse(checked(await f.send(progressUrl, { method: 'GET' }), 200).body),
        { nodeId: id, installProgress: { stage: 'reserve', percent: 10, at: at.toISOString() } });
    assert.equal(reads, 1);
    assert.equal(f.constructs + f.loads, 0);
});

test('recovery requires the panel admin session, header CSRF and an empty JSON object without query inputs', async t => {
    const f = mount(t);
    checked(await f.send(url, { session: undefined }), 302);
    checked(await f.send(url, { sessionID: undefined }), 403);
    checked(await f.send(url, { ip: '192.0.2.11' }), 403);
    checked(await f.send(url, { session: { ...f.session, adminUsername: '' } }), 403);
    checked(await f.send(url, { headers: { 'content-type': 'application/json' } }), 403);
    for (const headers of [{ ...f.headers, origin: 'http://elsewhere.invalid' },
        { ...f.headers, 'x-csrf-token': 'x'.repeat(43) }]) checked(await f.send(url, { headers }), 403);
    for (const raw of ['', 'null', '[]', '{', '{"backupId":"fixture"}', '{"token":"fixture"}',
        '{"actor":"fixture-admin"}', '{"_csrf":"fixture"}', '{"__proto__":{}}', '{"token":1,"token":2}', `{${' '.repeat(1024)}}`]) {
        checked(await f.send(url, { raw }), 400);
    }
    checked(await f.send(url, { headers: { ...f.headers, 'content-type': 'application/x-www-form-urlencoded' } }), 400);
    for (const bad of [url + '?', url + '?backupId=fixture', url + '?token=fixture',
        url.replace(id, '%61' + id.slice(1)), url.replace(id, id.toUpperCase()), url.replace(id, 'short')]) {
        checked(await f.send(bad), 400);
    }
    f.onboarded = false;
    checked(await f.send(), 302);
    f.onboardingError = true;
    checked(await f.send(), 503);
    assert.equal(f.constructs + f.loads + f.calls.length, 0);
});

test('service fails closed when Install or rebuild mode is disabled, including after route mount', async t => {
    const f = mount(t);
    f.env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'false';
    checked(await f.send(), 409);
    f.env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'true';
    f.env.C3_REBUILD_ENABLED = 'false';
    checked(await f.send(), 409);
    f.env.C3_REBUILD_ENABLED = 'true';
    f.env.L2TP_EXECUTION_ENABLED = 'true';
    checked(await f.send(), 409);
    assert.equal(f.loads + f.calls.length, 0);
});

test('recovery route is not mounted outside rebuild mode', async t => {
    const f = mount(t, { enabled: false });
    assert.equal((await f.send()).status, 404);
    assert.equal(f.constructs + f.loads + f.calls.length, 0);
});

test('explicit POST hands only the relay ID to the recovery factory with Install dependencies; receipts are projected', async t => {
    const f = mount(t);
    let acknowledge;
    f.result = new Promise(resolve => { acknowledge = resolve; });
    let responded = false;
    const reply = f.send(url, { raw: '{ \n }' }).then(result => { responded = true; return result; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(responded, false);
    assert.equal(f.calls.length, 1);
    acknowledge({ status: 'can_install_again', token: privateFixture, backupId: privateFixture });
    assert.deepEqual(JSON.parse(checked(await reply, 200).body), { executionMode: 'rebuild', status: 'can_install_again', nodeId: id });
    const [{ ids, backendDeps }] = f.calls;
    assert.deepEqual(ids, [id]);
    for (const key of ['Link', 'Node', 'State', 'L2tpUser', 'env', 'relayGrantStore', 'createRelayDirect']) {
        assert.equal(backendDeps[key], f.deps[key]);
    }
    assert.equal(backendDeps.actor, f.session.adminUsername);
    assert.equal(typeof backendDeps.locks.run, 'function');
    assert.notEqual(backendDeps.locks.run, f.deps.locks.run, 'uses the guarded Install lock');
    assert.equal(f.limits, 1);
    assert.equal(f.reads, 0);
});

test('a missing backend, grant or role refusal, lost acknowledgement and non-success statuses never unlock Install', async t => {
    const f = mount(t);
    f.missing = true;
    assert.deepEqual(JSON.parse(checked(await f.send(), 503).body), unconfirmed);
    assert.equal(f.calls.length, 0);
    f.missing = false;
    for (const code of ['REBUILD_L2TP_IDENTITY_CHANGED', 'REBUILD_L2TP_GRANT_UNAVAILABLE',
        'REBUILD_L2TP_NOT_FRESH_RELAY', 'REBUILD_LOCK_LOST', privateFixture]) {
        f.failure = Object.assign(new Error(privateFixture), { code, detail: privateFixture });
        const response = checked(await f.send(), code === 'REBUILD_L2TP_IDENTITY_CHANGED' ? 409 : 503);
        assert.deepEqual(JSON.parse(response.body), unconfirmed);
    }
    f.failure = undefined;
    for (const result of [undefined, { status: 'installed' }, { status: 'unknown' },
        { status: 'can_install_again', nodeId: 'b'.repeat(24) }, { status: 'can_install_again', retryAllowed: false },
        { status: 'can_install_again', error: { outcome: 'unknown', detail: privateFixture } }]) {
        f.result = result;
        assert.deepEqual(JSON.parse(checked(await f.send(), 503).body), unconfirmed);
    }
    assert.equal(f.loads, 12);
    assert.equal(f.calls.length, 11);
});

test('proved empty recovery reports its own 409, without unlocking Install', async t => {
    const f = mount(t);
    const code = 'REBUILD_L2TP_INSTALL_RECOVERY_NO_STATE';
    f.failure = Object.assign(new Error(privateFixture), { code, retryAllowed: false, detail: privateFixture });
    assert.deepEqual(JSON.parse(checked(await f.send(), 409).body), { error: { code, retryAllowed: false } });
    for (const patch of [{ outcome: 'unknown' }, { retryAllowed: true }]) {
        f.failure = Object.assign(new Error(privateFixture), { code, retryAllowed: false, ...patch });
        assert.deepEqual(JSON.parse(checked(await f.send(), 503).body), unconfirmed);
    }
});

test('fresh Install binds the same admin from the session, not the submitted payload', async t => {
    const f = mount(t);
    const service = require('../../../services/rebuildService');
    const calls = [];
    service.createRebuildService.mock.mockImplementation(() => ({ installRelay: async (...args) => {
        calls.push(args);
        return { status: 'installed' };
    } }));
    const installUrl = url.slice(0, -'/recover'.length);
    checked(await f.send(installUrl, { raw: '{"actor":"someone-else"}' }), 400);
    checked(await f.send(installUrl), 200);
    assert.deepEqual(calls, [[id, { actor: f.session.adminUsername }]]);
    assert.equal(f.loads, 0);
});

test('mounted default Install and Recovery preserve the reservation on zero dispatch, then permit a new explicit POST',
    { skip: !process.env.C3_MONGOD, timeout: 30000 }, async t => {
        const { networkInterfaces, tmpdir } = require('node:os');
        const { mkdtemp, rm } = require('node:fs/promises');
        const { spawn } = require('node:child_process');
        const { once, EventEmitter } = require('node:events');
        const { setTimeout: sleep } = require('node:timers/promises');
        const { createServer } = require('node:net');
        const { isDeepStrictEqual } = require('node:util');
        const mongoose = require('mongoose');
        assert.deepEqual(Object.keys(networkInterfaces()), ['lo']);
        assert.ok(process.env.TMPDIR);
        const dir = await mkdtemp(resolve(tmpdir(), 'relay-recovery-mongo-'));
        const listener = createServer().listen(0, '127.0.0.1');
        await once(listener, 'listening');
        const { port } = listener.address();
        await new Promise(done => listener.close(done));
        const mongod = spawn(process.env.C3_MONGOD, ['--dbpath', dir, '--bind_ip', '127.0.0.1', '--port', String(port),
            '--nounixsocket', '--replSet', 'recoveryFixture', '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32',
            '--logpath', resolve(dir, 'mongo.log')], { stdio: 'ignore' });
        const exited = once(mongod, 'exit');
        exited.catch(() => {});
        const client = new mongoose.mongo.MongoClient(`mongodb://127.0.0.1:${port}/?directConnection=true`,
            { serverSelectionTimeoutMS: 2000 });
        t.after(async () => {
            try { await mongoose.disconnect(); await client.close(); }
            finally {
                mongod.kill('SIGTERM');
                try { assert.deepEqual(await exited, [0, null]); }
                finally { await rm(dir, { recursive: true }); }
            }
        });
        const admin = client.db('admin');
        await admin.command({ replSetInitiate: { _id: 'recoveryFixture', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        let ready;
        for (let attempt = 0; attempt < 100 && !ready; attempt++) {
            ready = (await admin.command({ hello: 1 })).isWritablePrimary;
            if (!ready) await sleep(50);
        }
        assert.equal(ready, true);
        await mongoose.connect(`mongodb://127.0.0.1:${port}/?directConnection=true`,
            { dbName: 'install_recovery_fixture', retryWrites: true, serverSelectionTimeoutMS: 2000, monitorCommands: true });
        const db = mongoose.connection;
        const Node = require('../../../models/hyNodeModel');
        const Settings = require('../../../models/settingsModel');
        const State = require('../../../modules/relay-l2tp/models/relayL2tpStateModel');
        const User = require('../../../modules/relay-l2tp/models/l2tpUserModel');
        const NodeSSH = require('../../../services/nodeSSH');
        const { createRelayGrantStore } = require('../../../services/rebuildRelayGrantStore');
        const config = require('../../../../config');
        const previousEnv = { ...process.env }, whitelist = config.PANEL_IP_WHITELIST;
        t.after(() => {
            for (const key of Object.keys(process.env)) if (!Object.hasOwn(previousEnv, key)) delete process.env[key];
            Object.assign(process.env, previousEnv);
            config.PANEL_IP_WHITELIST = whitelist;
            require('../helpers').invalidateOnboardingCache();
        });
        Object.assign(process.env, { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
            ENCRYPTION_KEY: 'synthetic-recovery-key-for-private-fixture-only', PANEL_DOMAIN: 'fixture.invalid' });
        config.PANEL_IP_WHITELIST = '192.0.2.10';
        const actor = 'fixture-admin', machineId = 'b'.repeat(32), packagePreparation = 'c'.repeat(64);
        const binding = { nodeId: id, host: '192.0.2.19', port: 22, username: 'root', machineId, sshHostKeySha256: 'd'.repeat(64) };
        const _id = new mongoose.Types.ObjectId(id);
        const locks = db.collection('c3_rebuild_locks');
        const lockRow = () => locks.findOne({ _id: 'apply' });
        const stateRow = () => State.collection.findOne({ node: _id });
        const copyRows = () => User.collection.find({ relayNode: _id }).toArray();
        const snapshot = async () => [await lockRow(), await stateRow(), await copyRows()];
        const assertSame = (a, b, message) => assert.ok(isDeepStrictEqual(a, b), message);
        const claimWrites = [];
        db.getClient().on('commandStarted', ({ command }) => {
            if (command.update !== 'c3_rebuild_locks') return;
            for (const op of command.updates) {
                if (op.u.$set?.installRecoveryClaim) claimWrites.push(['claim', op.multi, command.autocommit]);
                if (Object.hasOwn(op.u.$unset ?? {}, 'installRecoveryClaim')) claimWrites.push(['release', op.multi, command.writeConcern?.w]);
            }
        });
        await Settings.collection.insertOne({ _id: 'settings', deployment: { completed: true } });
        await Node.collection.insertOne({ _id, active: true, type: 'xray', cascadeRole: 'relay', ip: binding.host,
            ssh: { port: 22, username: 'root' } });
        const Link = require('../../../models/cascadeLinkModel');
        const { appliedLink } = require('../../../services/rebuildAppliedLink');
        const bridgeNode = new mongoose.Types.ObjectId('f'.repeat(24));
        await Node.collection.insertOne({ _id: bridgeNode, active: true, type: 'xray', cascadeRole: 'bridge', ip: '192.0.2.20' });
        const appliedMain = 'a'.repeat(64);
        const link = { portalNode: _id, bridgeNode, active: true, mode: 'forward', status: 'deployed',
            tunnelProtocol: 'vless', tunnelPort: 21443, tunnelUuid: 'fixture-tunnel-id' };
        await Link.collection.insertOne({ ...link, rebuildApplied: appliedLink(link), rebuildApplyEpoch: 'e'.repeat(32),
            rebuildAppliedMainSha256: appliedMain });
        await createRelayGrantStore({ db, env: process.env }).mutate({ action: 'grant', binding, actor });
        let mode = 'install', opens = 0, writes = 0, originalBackup;
        const seen = [];
        // Only the SSH client and its channels are modeled. Run the pinned
        // NodeSSH wrapper, DIRECT codecs, real router and every default factory.
        t.mock.method(NodeSSH.prototype, '_openDirectClient', async function () {
            assert.equal(this.usePool, false);
            assert.equal(this.node.ip, binding.host);
            opens++;
            if (mode === 'unavailable') throw new Error('fixture connect refused');
            const peer = new EventEmitter();
            peer.end = () => {};
            peer.exec = (command, callback) => {
                const isAttest = command === '/usr/bin/head -c 34 /etc/machine-id';
                if (!isAttest && mode === 'channel refusal') return callback(new Error('fixture channel refused'));
                const channel = new EventEmitter();
                channel.stderr = new EventEmitter();
                channel.destroy = () => {};
                const chunks = [];
                const reply = text => {
                    channel.emit('data', Buffer.from(text));
                    channel.stderr.emit('end');
                    channel.emit('close', 0);
                };
                channel.write = chunk => {
                    chunks.push(chunk);
                    if (mode === 'lost first write') {
                        writes++;
                        throw Object.assign(new Error('fixture transport lost'), { noRequestSent: true });
                    }
                    return true;
                };
                channel.end = done => {
                    const wire = JSON.parse(Buffer.concat(chunks));
                    seen.push(wire.action);
                    queueMicrotask(() => {
                        done();
                        if (wire.action === 'prove-applied-main') return reply(`${JSON.stringify({ applied: wire.appliedMain === appliedMain })}\n`);
                        if (wire.action === 'preflight') return reply(`${JSON.stringify({ machineId, packagePreparation })}\n`);
                        if (wire.action === 'prepare-packages') {
                            originalBackup = wire.backupId;
                            return peer.emit('close'); // Original Install already submitted its first write.
                        }
                        assert.equal(wire.action, 'reconcile-install');
                        writes++;
                        assert.equal(wire.nodeId, id);
                        assert.equal(wire.backupId, originalBackup);
                        assert.equal(wire.packagePreparation, packagePreparation);
                        reply(`${JSON.stringify({ nodeId: id, backupId: originalBackup, machineId, challenge: wire.challenge, result: 'absent' })}\n`);
                    });
                };
                if (!isAttest && mode === 'local guard veto') process.env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'false';
                callback(null, channel);
                if (isAttest) queueMicrotask(() => reply(`${mode === 'machine mismatch' ? 'e'.repeat(32) : machineId}\n`));
            };
            return peer;
        });
        const app = express();
        app.set('view engine', 'ejs');
        app.set('views', resolve(__dirname, '../../../../views'));
        app.use(require('../rebuildL2tp').rebuildL2tpIngress);
        app.use(express.json());
        app.use(i18nMiddleware);
        app.use('/panel', require('../index').createPanelRouter({ l2tpRateLimiter: (_req, _res, next) => next() }));
        const session = { authenticated: true, adminUsername: actor };
        const headers = { 'content-type': 'application/json', 'x-csrf-token': issuePanelCsrfToken({ session }) };
        const send = (path = url, options = {}) => request(app, path, { session, sessionID: 'fixture-session', headers, ...options });
        const install = url.slice(0, -'/recover'.length);
        const begin = async () => {
            mode = 'install';
            const initial = await send(install);
            assert.equal(JSON.parse(initial.body).error?.retryAllowed, false);
            const before = await snapshot();
            assert.equal(before[0]?.installRecovery?.phase, 'ready');
            assert.equal(before[0]?.installRecovery?.actor, actor);
            assert.equal(before[1]?.backupId, originalBackup);
            assert.equal(before[2].length, 1);
            return before;
        };
        const before = await begin();
        assert.deepEqual(seen, ['prove-applied-main', 'preflight', 'prove-applied-main', 'prepare-packages']);
        const wrongActor = { ...session, adminUsername: 'other-admin' };
        assert.deepEqual(JSON.parse(checked(await send(url, { session: wrongActor }), 503).body), unconfirmed);
        assert.equal(opens, 1);
        assertSame(await snapshot(), before, 'foreign actor changed the reservation');
        for (mode of ['unavailable', 'machine mismatch', 'channel refusal', 'local guard veto']) {
            const at = claimWrites.length;
            try { assert.deepEqual(JSON.parse(checked(await send(), 503).body), unconfirmed); }
            finally { process.env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'true'; }
            assert.equal(writes, 0);
            assertSame(await snapshot(), before, `${mode} must not strand a recovery claim`);
            assert.deepEqual(claimWrites.slice(at), [['claim', true, false], ['release', true, 'majority']]);
        }
        mode = 'available';
        const refresh = checked(await send('/panel/l2tp', { method: 'GET' }), 200);
        assert.ok(refresh.body.includes(`data-install-recovery-url="${url}"`));
        assert.doesNotMatch(refresh.body, /data-install-url=/);
        assert.equal(writes, 0, 'refresh must not send recovery');
        assertSame(await snapshot(), before, 'refresh changed the reservation');
        assert.deepEqual(JSON.parse(checked(await send(url), 200).body), { executionMode: 'rebuild', status: 'can_install_again', nodeId: id });
        assert.equal(writes, 1);
        assert.deepEqual(await snapshot(), [null, null, []]);

        const pending = await begin();
        mode = 'lost first write';
        checked(await send(), 503);
        assert.equal(writes, 2);
        const after = await snapshot();
        const { installRecoveryClaim, ...held } = after[0];
        assert.ok(installRecoveryClaim);
        assertSame([held, after[1], after[2]], pending, 'a lost write changed more than the temporary claim');
        const count = opens;
        mode = 'available';
        checked(await send(), 503);
        assert.equal(opens, count);
        assert.equal(writes, 2);
        assertSame(await snapshot(), after, 'the subsequent POST changed an unresolved claim');
    });

test.after(() => require('../../../services/sshPoolService').closeAll());
