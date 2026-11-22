'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { IncomingMessage, ServerResponse } = require('node:http');
const { Socket } = require('node:net');
const { Duplex } = require('node:stream');
const { isDeepStrictEqual: equal } = require('node:util');
const express = require('express');
const mongoose = require('mongoose');
const { Client } = require('ssh2');
const { issuePanelCsrfToken } = require('../csrf');

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), host = '192.0.2.4';
const key = Buffer.from('synthetic-admission-host-key');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const pin = hash(key);
const sshPassword = 'joined-fixture-ssh-password', privateError = 'joined-fixture-private-error';
const actor = 'admin.fixture', sessionID = 'joined-fixture-admin-session';
const base = `/panel/rebuild/relays/${nodeId}/l2tp`;
const GRANTS = 'c3_rebuild_l2tp_relay_grants', AUDIT = 'c3_rebuild_l2tp_relay_grant_audit';
const STATES = 'relayl2tpstates', USERS = 'l2tpusers', LOCK = 'c3_rebuild_locks', DIRECTORY = 'c3_rebuild_relay_accounts';
const oid = new mongoose.Types.ObjectId(nodeId);
const copy = value => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(value));

// Model the driver API, not the workflow, grant store, Mongoose queries, or
// Install reservations. Raw collection reads and Mongoose see the same rows.
function mongoFixture(t) {
    // Seed the same encrypted representation that saving the node card writes.
    const password = require('../../../services/cryptoService').encrypt(sshPassword);
    const tables = new Map([
        ['settings', [{ _id: 'settings', deployment: { completed: true } }]],
        ['hynodes', [{ _id: oid, name: 'Joined relay', ip: host, type: 'xray', active: true, cascadeRole: 'relay',
            ssh: { port: 22, username: 'root', password } }]],
        ...[GRANTS, AUDIT, STATES, USERS, LOCK, DIRECTORY, 'l2tpoperations', 'remoteadmissions',
            'nodeoperationlocks', 'cascadelinks'].map(name => [name, []]),
    ]);
    const writes = [], commits = [];
    let grantIndexes = [];
    const get = (row, key) => key.split('.').reduce((v, k) => v?.[k], row);
    const match = (row, where) => Object.entries(where).every(([key, value]) => {
        if (key === '$or') return value.some(part => match(row, part));
        const current = get(row, key);
        if (value && Object.getPrototypeOf(value) === Object.prototype) {
            return Object.entries(value).every(([op, expected]) => {
                switch (op) {
                case '$ne': return !equal(current, expected);
                case '$eq': return equal(current, expected);
                case '$exists': return (current !== undefined) === expected;
                case '$in': return expected.some(member => equal(current, member));
                case '$nin': return expected.every(member => !equal(current, member));
                default: assert.fail(`Unsupported fixture query operator: ${op}`);
                }
            });
        }
        return equal(current, value);
    });
    const project = (row, projection = {}) => {
        const include = Object.keys(projection).filter(key => projection[key] === 1);
        if (!include.length) {
            const result = copy(row);
            for (const [key, flag] of Object.entries(projection)) {
                assert.ok(!key.includes('.') && flag === 0);
                delete result[key];
            }
            return result;
        }
        const result = projection._id === 0 || row._id === undefined ? {} : { _id: row._id };
        for (const key of include) {
            const value = get(row, key);
            if (value === undefined) continue;
            const path = key.split('.');
            const last = path.pop();
            path.reduce((parent, part) => parent[part] ??= {}, result)[last] = value;
        }
        return copy(result);
    };
    class Session {
        transaction = { transition: state => {
            assert.equal(state, 'TRANSACTION_COMMITTED');
            this.view = null;
        } };
        startTransaction(options) {
            assert.equal(options.readConcern.level, 'snapshot');
            assert.equal(options.writeConcern.w, 'majority');
            this.view = new Map([...tables].map(([name, rows]) => [name, rows.map(copy)]));
            this.modified = new Set();
        }
        inTransaction() { return Boolean(this.view); }
        commit() {
            assert.ok(this.inTransaction());
            const kind = this.modified.has(GRANTS) ? (this.grantAction ?? 'grant') : 'install';
            if (this.modified.has(GRANTS)) assert.deepEqual([...this.modified], [GRANTS, AUDIT]);
            commits.push([kind, ...this.modified]);
            for (const name of this.modified) tables.set(name, this.view.get(name));
            return { ok: 1 };
        }

        async abortTransaction() { this.view = null; }
        async endSession() { assert.equal(this.inTransaction(), false); }
    }
    const collection = name => {
        assert.ok(tables.has(name), `Unexpected fixture collection: ${name}`);
        const rows = session => {
            if (session) assert.ok(session.inTransaction());
            return (session?.view ?? tables).get(name);
        };
        const write = (operation, options) => {
            const { session } = options ?? {};
            writes.push(name);
            session?.modified.add(name);
            return operation(rows(session));
        };
        return {
            collectionName: name,
            async createIndexes(specs, options) {
                assert.equal(name, GRANTS);
                assert.equal(options.writeConcern.w, 'majority');
                grantIndexes = specs.filter(spec => spec.unique).map(spec => Object.keys(spec.key));
                return specs.map(spec => spec.name);
            },
            find(where, { projection, session, limit } = {}) {
                return { limit(n) { limit = n; return this; },
                    async toArray() { return rows(session).filter(row => match(row, where)).slice(0, limit)
                        .map(row => project(row, projection)); } };
            },
            async findOne(where, { projection, session } = {}) {
                const row = rows(session).find(candidate => match(candidate, where));
                return row ? project(row, projection) : null;
            },
            async insertOne(row, options) {
                return write(data => {
                    if (name === GRANTS) {
                        assert.ok(options.session);
                        assert.deepEqual(grantIndexes, [['nodeId'], ['machineId'], ['sshHostKeySha256'], ['host', 'port']]);
                    }
                    assert.ok(row._id === undefined || !data.some(other => equal(other._id, row._id)));
                    data.push(copy(row));
                    return { acknowledged: true };
                }, options);
            },
            async updateOne(where, update, options) {
                assert.equal(name, GRANTS);
                assert.ok(options.session);
                const [original] = tables.get(GRANTS);
                assert.deepEqual(where, { nodeId: original.nodeId, generation: original.generation });
                options.session.grantAction = 'reconfirm';
                return write(data => {
                    const row = data.find(candidate => match(candidate, where));
                    if (row) Object.assign(row, copy(update.$set));
                    return { acknowledged: true, matchedCount: Number(Boolean(row)) };
                }, options);
            },
            async updateMany(where, update, options) {
                return write(data => {
                    assert.ok(options.session);
                    const selected = data.filter(row => match(row, where));
                    assert.ok(selected.length <= 1);
                    if (selected.length) Object.assign(selected[0], copy(update.$set));
                    else if (options.upsert) data.push(copy(update.$setOnInsert));
                    return { acknowledged: true, matchedCount: selected.length, upsertedCount: Number(!selected.length && options.upsert) };
                }, options);
            },
            async deleteMany(where, options) {
                return write(data => {
                    const index = data.findIndex(row => match(row, where));
                    if (index !== -1) data.splice(index, 1);
                    return { acknowledged: true, deletedCount: Number(index !== -1) };
                }, options);
            },
        };
    };
    const db = mongoose.connection;
    const { db: originalDb, _readyState } = db;
    db.db = { collection, async createCollection(name) { return collection(name); } };
    db._readyState = 1; // No connection, events, automatic collection creation or index startup.
    t.after(() => {
        db.db = originalDb;
        db._readyState = _readyState;
        for (const handle of Object.values(db.collections)) handle.collection = null;
    });
    t.mock.method(db, 'startSession', async () => new Session());
    t.mock.method(db, 'getClient', () => ({ db(database) {
        assert.equal(database, 'admin');
        return { async command(command, { session }) {
            assert.equal(command.commitTransaction, 1);
            assert.equal(command.writeConcern.w, 'majority');
            return session.commit();
        } };
    } }));
    return { rows: name => tables.get(name).map(copy), commits, writes: () => writes.splice(0), password };
}

function hostFixture(t, mongo) {
    const bindWire = require('../../../services/tests/helpers/rebuildRelayInstallJoined')({ wireOnly: true });
    const ready = { machineId, ppp: true, masked: false, unitsLoaded: true };
    const main = JSON.stringify({ inbounds: [{ tag: 'fwd-hop-a', protocol: 'vless', port: 443 }],
        outbounds: [{ tag: 'block', protocol: 'blackhole' }], routing: { rules: [
            { type: 'field', ruleTag: 'rebuild-policy-default', inboundTag: ['fwd-hop-a'], outboundTag: 'block' },
        ] } });
    const remote = { key, machineId, checks: [], effects: [] };
    let candidate, installedId;
    const frames = bindWire(t, [{ id: nodeId, relay: { ip: host }, get key() { return remote.key; },
        get machineId() { return remote.machineId; }, applyHandlers: new Map(), execute(command, stdin) {
        const req = JSON.parse(stdin);
        assert.equal(req.machineId, machineId);
        assert.equal(mongo.rows(LOCK).length, 1);
        assert.ok(!command.includes(sshPassword));
        const ok = body => ({ status: 0, stdout: JSON.stringify(body) + '\n', stderr: '' });
        switch (req.action) {
        case 'preflight':
            if (remote.machineId !== machineId) return { status: 70, stdout: '', stderr: 'DIRECT_IDENTITY\n' };
            return ok({ ...ready, pppPreparation: true });
        case 'prepare': return ok({ ...ready, main, bridge: null, mainSha256: hash(main), bridgeSha256: null, baseline: 'd'.repeat(64) });
        case 'check':
            assert.deepEqual(mongo.rows(STATES), []);
            assert.deepEqual(mongo.rows(USERS), []);
            candidate = hash(stdin.replace('"check"', '"install"'));
            break;
        case 'install':
            assert.equal(hash(stdin), candidate);
            assert.deepEqual(mongo.rows(STATES).map(s => [s.status, s.backupId, s.rebuildMachineId]), [['installing', req.backupId, machineId]]);
            assert.deepEqual(mongo.rows(USERS).map(u => [u.login, u.syncStatus]), [['relay-bootstrap', 'pending']]);
            assert.equal(installedId, undefined);
            installedId = req.backupId;
            remote.effects.push(req.action);
            break;
        case 'verify':
            assert.equal(req.backupId, installedId);
            assert.equal(mongo.rows(STATES)[0].status, 'installing');
            break;
        case 'check-apply-network': {
            const [state] = mongo.rows(STATES);
            assert.equal(state.status, 'installed');
            assert.ok(installedId);
            assert.deepEqual(req, { action: 'check-apply-network', machineId, backupId: installedId,
                network: { clientCidr: state.clientCidr, tproxyPort: state.tproxyPort, fwmark: state.fwmark, routeTable: state.routeTable } });
            return remote.ownerUnproved ? { status: 70, stdout: '', stderr: 'DIRECT_ROLLBACK_DRIFT\n' }
                : ok({ ok: true, backupId: installedId, proof: 'e'.repeat(64) });
        }
        default: assert.fail(`Unexpected DIRECT action: ${req.action}`);
        }
        return ok({ ok: true, backupId: req.backupId });
    } }]);
    // The same synthetic host also provides the isolated discovery and pinned
    // machine-id channel; no real connect, shell or package command runs.
    const sockets = new Set(), probes = new WeakSet();
    t.mock.method(Socket.prototype, 'connect', function (options) {
        assert.deepEqual(options, { host, port: 22 });
        sockets.add(this);
        return this;
    });
    const connectInstall = Client.prototype.connect, execInstall = Client.prototype.exec;
    t.mock.method(Client.prototype, 'connect', function (options) {
        if (!options.sock) return connectInstall.call(this, options);
        assert.ok(sockets.has(options.sock));
        assert.equal(options.host, host);
        assert.equal(options.username, 'root');
        assert.ok(!Object.hasOwn(options, 'password') && !Object.hasOwn(options, 'privateKey'));
        probes.add(this);
        const pinned = options.hostVerifier(remote.key);
        remote.checks.push(pinned ? 'pinned' : 'key-only');
        if (pinned) {
            this.emit('handshake');
            const auth = options.authHandler();
            assert.ok(auth?.type === 'password' && auth.password === sshPassword);
            this.emit('ready');
        } else assert.equal(options.authHandler(), false);
        return this;
    });
    t.mock.method(Client.prototype, 'exec', function (command, callback) {
        if (!probes.has(this)) return execInstall.call(this, command, callback);
        assert.equal(command, '/usr/bin/head -c 34 /etc/machine-id');
        const channel = new EventEmitter();
        channel.stderr = new EventEmitter();
        channel.destroy = channel.stderr.destroy = () => {};
        channel.end = () => queueMicrotask(() => {
            remote.checks.push('machine');
            if (remote.error) channel.emit('error', new Error(privateError));
            else {
                channel.emit('data', Buffer.from(remote.machineId + '\n'));
                channel.stderr.emit('end');
                channel.emit('close', 0);
            }
        });
        callback(null, channel);
    });
    t.after(() => assert.ok([...sockets].every(socket => socket.destroyed), 'all admission sockets closed'));
    return { remote, frames };
}

function configure(t) {
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
        C3_REBUILD_L2TP_RELAYS_JSON: undefined, C3_REBUILD_L2TP_RELAY_ID: undefined, C3_REBUILD_L2TP_RELAY_MACHINE_ID: undefined,
        C3_REBUILD_L2TP_SSH_SHA256: undefined, ENCRYPTION_KEY: 'joined-fixture-encryption-key'.repeat(2),
        PANEL_DOMAIN: 'panel.fixture.invalid', ACME_EMAIL: 'admin@fixture.invalid', SESSION_SECRET: 'joined-fixture-session-signing' };
    const original = Object.fromEntries(Object.keys(env).map(name => [name, process.env[name]]));
    const set = values => { for (const [key, value] of Object.entries(values)) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
    } };
    set(env);
    const config = require('../../../../config');
    const whitelist = config.PANEL_IP_WHITELIST;
    config.PANEL_IP_WHITELIST = '192.0.2.10';
    t.after(() => { set(original); config.PANEL_IP_WHITELIST = whitelist; });
    mongoose.set('bufferCommands', false);
    mongoose.set('autoCreate', false);
    mongoose.set('autoIndex', false);
    // Compile the panel's models while disconnected; only fixture collections
    // are available once the Mongo API boundary is attached.
    return require('../index');
}

function mount(panel, mongo) {
    panel.l2tpRateLimiter.resetKey('192.0.2.10');
    const app = express();
    app.use(require('../rebuildL2tp').rebuildL2tpIngress);
    app.use(express.json());
    // Default production composition; no injected admission or Install service.
    app.use('/panel', panel.createPanelRouter());
    const session = { authenticated: true, adminUsername: actor };
    const csrf = issuePanelCsrfToken({ session });
    const send = (action, body = {}, { csrfToken = csrf, expected = 200 } = {}) => new Promise((resolve, reject) => {
        const payload = Buffer.from(JSON.stringify(body)), wire = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { wire.push(chunk.toString()); done(); } });
        socket.remoteAddress = '192.0.2.10';
        const req = new IncomingMessage(socket);
        Object.assign(req, { method: 'POST', url: `${base}/${action}`, session, sessionID, complete: true, headers: {
            host: 'panel.fixture.invalid', 'content-type': 'application/json', 'content-length': String(payload.length), 'x-csrf-token': csrfToken,
        } });
        req.push(payload);
        req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            socket.destroy();
            try {
                const raw = wire.join('');
                assert.ok([sshPassword, mongo.password, privateError, sessionID, csrf].every(secret => !raw.includes(secret)), 'redacted HTTP response');
                assert.equal(res.getHeader('cache-control'), 'no-store');
                const result = JSON.parse(raw.slice(raw.indexOf('\r\n\r\n') + 4));
                assert.equal(res.statusCode, expected, `${action}: ${result.error?.code ?? 'unexpected response'}`);
                resolve(result);
            } catch (error) { reject(error); }
        });
        app(req, res);
    });
    return { send, admission: (action, ...args) => send(`admission/${action}`, ...args) };
}

function audit(mongo, expected) {
    const rows = mongo.rows(AUDIT);
    assert.deepEqual(rows.map(row => [row.action, row.outcome, row.code]), expected);
    for (const row of rows) {
        assert.deepEqual(Object.keys(row).sort(), ['action', 'actor', 'at', 'code', 'nodeId', 'outcome']);
        assert.equal(row.actor, actor);
        assert.equal(row.nodeId, nodeId);
        assert.ok(row.at instanceof Date);
    }
}
const ok = action => [action, 'success', 'OK'];
const CHALLENGE = 'REBUILD_L2TP_ADMISSION_CHALLENGE_INVALID';
const CHANGED = 'REBUILD_L2TP_IDENTITY_CHANGED';
const CONFLICT = 'REBUILD_L2TP_GRANT_CONFLICT';
const refused = code => ({ error: { code } });

function joined(t) {
    const panel = configure(t);
    const mongo = mongoFixture(t);
    const wire = hostFixture(t, mongo);
    const app = mount(panel, mongo);
    const probe = () => app.admission('probe');
    const verify = challenge => app.admission('verify', { challenge });
    const confirm = (challenge, expected) => app.admission('confirm', { challenge }, { expected });
    return { ...app, mongo, ...wire, probe, verify, confirm };
}

test('guarded DB-only admission joins Install and refuses replay and installed revoke', { timeout: 5000 }, async t => {
    const f = joined(t);
    const blocked = await f.admission('probe', {}, { csrfToken: 'invalid', expected: 403 });
    assert.deepEqual(blocked, { error: 'CSRF validation failed', code: 'CSRF_TOKEN_INVALID' });
    assert.deepEqual(f.mongo.writes(), []);
    assert.deepEqual(f.remote.checks, []);

    const pre = await f.send('install', {}, { expected: 409 });
    assert.equal(pre.error.outcome, 'refused');
    assert.deepEqual(f.mongo.writes(), []);
    assert.deepEqual(f.frames, []);
    const binding = { nodeId, host, port: 22, username: 'root', sshHostKeySha256: pin };
    const { challenge: discovered, ...discovery } = await f.probe();
    assert.match(discovered, /^[0-9a-f]{64}$/);
    assert.deepEqual(discovery, binding);
    assert.deepEqual(f.remote.checks, ['key-only']);
    const { challenge: verified, ...proof } = await f.verify(discovered);
    assert.deepEqual(proof, { ...binding, machineId });
    assert.notEqual(verified, discovered);
    assert.match(verified, /^[0-9a-f]{64}$/);
    assert.deepEqual(f.remote.checks, ['key-only', 'pinned', 'machine']);
    assert.deepEqual(f.mongo.writes(), [AUDIT, AUDIT]);
    assert.deepEqual(f.mongo.rows(GRANTS), []);
    assert.deepEqual(f.mongo.commits, []);

    assert.deepEqual(await f.confirm(verified), proof);
    assert.deepEqual(f.remote.checks, ['key-only', 'pinned', 'machine', 'pinned', 'machine']);
    const [grant] = f.mongo.rows(GRANTS);
    assert.deepEqual(Object.fromEntries(Object.keys(proof).map(key => [key, grant[key]])), proof);
    assert.match(grant.generation, /^[0-9a-f-]{36}$/);
    assert.deepEqual(f.mongo.commits, [['grant', GRANTS, AUDIT]]);
    assert.deepEqual(f.mongo.writes(), [LOCK, GRANTS, AUDIT, LOCK]);
    assert.deepEqual(f.frames, []);
    assert.deepEqual(f.remote.effects, []);
    assert.equal(process.env.C3_REBUILD_L2TP_RELAYS_JSON, undefined);

    const checks = [...f.remote.checks];
    assert.deepEqual(await f.confirm(verified, 409), refused(CHALLENGE));
    assert.deepEqual(f.remote.checks, checks);
    assert.deepEqual(f.mongo.writes(), [AUDIT]);
    assert.deepEqual(f.mongo.rows(GRANTS), [grant]);

    // Install must recheck the confirmed machine, not just trust the saved grant.
    f.remote.machineId = 'c'.repeat(32);
    assert.deepEqual(await f.send('install', {}, { expected: 409 }), {
        error: { code: CHANGED, outcome: 'refused', retryAllowed: false },
    });
    assert.deepEqual(f.frames, [], 'changed machine received no DIRECT payload');
    assert.deepEqual(f.mongo.writes(), [LOCK, LOCK]);
    assert.deepEqual(f.mongo.commits, [['grant', GRANTS, AUDIT]]);
    assert.deepEqual(f.remote.effects, []);
    assert.deepEqual(f.mongo.rows(GRANTS), [grant]);
    for (const name of [STATES, USERS, DIRECTORY, LOCK]) assert.deepEqual(f.mongo.rows(name), []);

    f.remote.machineId = machineId;
    assert.deepEqual(await f.send('install'), { executionMode: 'rebuild', status: 'installed', nodeId });
    assert.deepEqual(f.frames.map(([, action]) => action), ['preflight', 'preflight', 'prepare', 'check', 'install', 'verify']);
    assert.deepEqual(f.remote.effects, ['install']);
    assert.deepEqual(f.mongo.commits, [['grant', GRANTS, AUDIT], ['install', STATES, USERS], ['install', USERS, DIRECTORY, STATES]]);
    const states = f.mongo.rows(STATES), accounts = f.mongo.rows(USERS), directory = f.mongo.rows(DIRECTORY);
    assert.deepEqual(states.map(s => [s.status, s.desiredState, s.rebuildMachineId]), [['installed', 'installed', machineId]]);
    assert.deepEqual(accounts.map(row => [String(row.relayNode), row.login, row.syncStatus, row.appliedRevision, row.desiredRevision]),
        [[nodeId, 'relay-bootstrap', 'synced', 1, 1]]);
    assert.deepEqual(directory.map(doc => [doc._id, doc.accounts.map(account => account.login)]), [['directory', ['relay-bootstrap']]]);
    assert.deepEqual(f.mongo.rows(LOCK), []);
    assert.equal(process.env.C3_REBUILD_L2TP_RELAYS_JSON, undefined);
    f.mongo.writes();

    assert.deepEqual(await f.admission('revoke', {}, { expected: 409 }), refused(CONFLICT));
    assert.deepEqual(f.mongo.writes(), [LOCK, LOCK, AUDIT]);
    assert.deepEqual(f.mongo.rows(LOCK), []);
    assert.deepEqual(f.mongo.rows(GRANTS), [grant]);
    assert.deepEqual([f.mongo.rows(STATES), f.mongo.rows(USERS), f.mongo.rows(DIRECTORY)], [states, accounts, directory]);
    assert.equal(f.frames.length, 6);
    assert.deepEqual(f.remote.effects, ['install']);
    assert.deepEqual(f.remote.checks, checks);
    audit(f.mongo, [ok('probe'), ok('verify'), ok('grant'), ['confirm', 'denied', CHALLENGE], ['revoke', 'denied', CONFLICT]]);
});

test('installed pin rotation checks the original receipt, commits only grant and audit, and leaves host state alone', { timeout: 5000 }, async t => {
    const f = joined(t);
    const approve = async () => f.verify((await f.probe()).challenge);
    await f.confirm((await approve()).challenge);
    await f.send('install');
    const before = [STATES, USERS, DIRECTORY].map(name => f.mongo.rows(name));
    const [grant] = f.mongo.rows(GRANTS);
    const frameStart = f.frames.length;
    f.remote.key = Buffer.from('rotated synthetic host key');

    const denied = await approve();
    f.mongo.writes();
    f.remote.ownerUnproved = true;
    assert.deepEqual(await f.confirm(denied.challenge, 409), refused(CONFLICT));
    assert.deepEqual(f.mongo.writes(), [LOCK, LOCK, AUDIT]);
    assert.deepEqual(f.mongo.rows(GRANTS), [grant]);

    f.remote.ownerUnproved = false;
    const { challenge, ...proposal } = await approve();
    f.mongo.writes();
    assert.deepEqual(await f.confirm(challenge), proposal);
    const [next] = f.mongo.rows(GRANTS);
    assert.equal(next.sshHostKeySha256, hash(f.remote.key));
    assert.notEqual(next.generation, grant.generation);
    for (const field of ['nodeId', 'host', 'port', 'username', 'machineId']) assert.equal(next[field], grant[field]);
    assert.deepEqual(f.mongo.writes(), [LOCK, GRANTS, AUDIT, LOCK]);
    assert.deepEqual(f.mongo.commits.at(-1), ['reconfirm', GRANTS, AUDIT]);
    assert.deepEqual(f.mongo.rows(AUDIT).slice(-4).map(row => [row.action, row.outcome, row.code]),
        [['confirm', 'denied', CONFLICT], ok('probe'), ok('verify'), ok('reconfirm')]);
    assert.deepEqual([STATES, USERS, DIRECTORY].map(name => f.mongo.rows(name)), before);
    assert.deepEqual(f.frames.slice(frameStart), [[nodeId, 'check-apply-network'], [nodeId, 'check-apply-network']]);
    assert.deepEqual(f.remote.effects, ['install']);
});

for (const mismatch of ['key', 'machineId', 'error']) {
    test(`guarded confirm refuses ${mismatch} after verify without business writes`, { timeout: 5000 }, async t => {
        const f = joined(t);
        const { challenge: discovered } = await f.probe();
        const { challenge: verified } = await f.verify(discovered);
        f.mongo.writes();
        f.remote[mismatch] = { key: Buffer.from('changed fixture key'), machineId: 'c'.repeat(32), error: true }[mismatch];
        const expected = mismatch === 'error' ? 503 : 409;
        const result = await f.confirm(verified, expected);
        const code = mismatch === 'error' ? 'REBUILD_L2TP_IDENTITY_UNAVAILABLE' : CHANGED;
        assert.deepEqual(result, refused(mismatch === 'error' ? 'REBUILD_L2TP_ADMISSION_UNAVAILABLE' : CHANGED));
        assert.deepEqual(await f.confirm(verified, 409), refused(CHALLENGE));
        assert.deepEqual(f.remote.checks.slice(3), mismatch === 'key' ? ['key-only'] : ['pinned', 'machine']);
        assert.deepEqual(f.mongo.writes(), [LOCK, LOCK, AUDIT, AUDIT]);
        assert.deepEqual(f.mongo.commits, []);
        for (const name of [GRANTS, STATES, USERS, DIRECTORY, LOCK]) assert.deepEqual(f.mongo.rows(name), []);
        assert.deepEqual(f.frames, []);
        assert.deepEqual(f.remote.effects, []);
        audit(f.mongo, [ok('probe'), ok('verify'), ['confirm', 'denied', code], ['confirm', 'denied', CHALLENGE]]);
    });
}

test.after(() => require('../../../services/sshPoolService').closeAll());
