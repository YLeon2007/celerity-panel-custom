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
const unusedId = 'c'.repeat(24), unusedMachine = 'd'.repeat(32), unusedHost = '192.0.2.5';
const unusedKey = Buffer.from('synthetic unused relay key');
const GRANTS = 'c3_rebuild_l2tp_relay_grants', AUDIT = 'c3_rebuild_l2tp_relay_grant_audit';
const STATES = 'relayl2tpstates', USERS = 'l2tpusers', LOCK = 'c3_rebuild_locks', DIRECTORY = 'c3_rebuild_relay_accounts';
const copy = value => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(value));

// Model the driver API, not the workflow, grant store, Mongoose queries, or
// Install reservations. Raw collection reads and Mongoose see the same rows.
function mongoFixture(t) {
    // Seed the same encrypted representation that saving the node card writes.
    const password = require('../../../services/cryptoService').encrypt(sshPassword);
    const tables = new Map([
        ['settings', [{ _id: 'settings', deployment: { completed: true } }]],
        ['hynodes', [[nodeId, host], [unusedId, unusedHost]].map(([id, ip]) => ({
            _id: new mongoose.Types.ObjectId(id), name: 'Joined relay', ip, type: 'xray', active: true, cascadeRole: 'relay',
            ssh: { port: 22, username: 'root', password },
        }))],
        ...[GRANTS, AUDIT, STATES, USERS, LOCK, DIRECTORY, 'c3_rebuild_l2tp_retired_relays', 'l2tpoperations', 'remoteadmissions',
            'nodeoperationlocks', 'cascadelinks', 'servergroups'].map(name => [name, []]),
    ]);
    const writes = [], commits = [];
    let grantIndexes = [];
    const get = (row, key) => key.split('.').reduce((v, k) => v?.[k], row);
    const match = (row, where) => Object.entries(where).every(([key, value]) => {
        if (key === '$or') return value.some(part => match(row, part));
        if (key === '$nor') return !value.some(part => match(row, part));
        if (key === '$expr') {
            assert.equal(value.$eq[0], '$$ROOT');
            return equal(row, value.$eq[1].$literal);
        }
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
                assert.equal(flag, 0);
                const parts = key.split('.'), leaf = parts.pop();
                const parent = parts.reduce((value, part) => value?.[part], result);
                if (parent) delete parent[leaf];
            }
            return result;
        }
        const result = projection._id === 0 || row._id === undefined ? {} : { _id: row._id };
        for (const key of include) {
            if (key.startsWith('relays.') && Array.isArray(row.relays)) {
                result.relays ??= row.relays.map(() => ({}));
                const field = key.slice('relays.'.length);
                row.relays.forEach((relay, i) => { if (Object.hasOwn(relay, field)) result.relays[i][field] = relay[field]; });
                continue;
            }
            const value = get(row, key);
            if (value === undefined) continue;
            const path = key.split('.');
            const last = path.pop();
            path.reduce((parent, part) => parent[part] ??= {}, result)[last] = value;
        }
        return copy(result);
    };
    const faults = {};
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
            faults.afterCommit?.(this.modified);
            this.committed = true;
            return { ok: 1 };
        }

        async abortTransaction() { this.view = null; }
        async endSession() {
            assert.equal(this.inTransaction(), false);
            if (this.committed) faults.afterAcknowledgedCommit?.(this.modified);
        }
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
                // The joined consumers sort the resulting inventories themselves.
                return { limit(n) { limit = n; return this; }, sort() { return this; },
                    async toArray() { return rows(session).filter(row => match(row, where)).slice(0, limit)
                        .map(row => project(row, projection)); } };
            },
            async findOne(where, { projection, session } = {}) {
                if (name === STATES && where.$nor) {
                    assert.ok(session?.inTransaction(), 'singleton downgrade check runs in the grant transaction');
                    assert.equal(tables.get(LOCK).length, 1, 'singleton downgrade check holds the global writer lock');
                }
                const row = rows(session).find(candidate => match(candidate, where));
                return row ? project(row, projection) : null;
            },
            async countDocuments(where) { return rows().filter(row => match(row, where)).length; },
            async insertOne(row, options) {
                return write(data => {
                    if (name === GRANTS) {
                        assert.ok(options.session);
                        assert.deepEqual(grantIndexes, [['nodeId'], ['machineId'], ['sshHostKeySha256'], ['host', 'port']]);
                    }
                    if (name === LOCK && data.some(other => other._id === row._id)) {
                        throw Object.assign(new Error('duplicate fixture lock'), { code: 11000 });
                    }
                    assert.ok(row._id === undefined || !data.some(other => equal(other._id, row._id)));
                    data.push(copy(row));
                    return { acknowledged: true };
                }, options);
            },
            async insertMany(documents, options) {
                assert.equal(name, USERS);
                assert.ok(options.session);
                for (const row of documents) await this.insertOne(row, options);
                return { acknowledged: true, insertedCount: documents.length };
            },
            async countDocuments(where) { return rows().filter(row => match(row, where)).length; },
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
                    const selected = data.filter(row => match(row, where));
                    assert.ok(selected.length <= 1);
                    if (selected.length) {
                        if (update.$set) Object.assign(selected[0], copy(update.$set));
                        for (const key of Object.keys(update.$unset ?? {})) delete selected[0][key];
                    } else if (options.upsert) {
                        const equality = Object.fromEntries(Object.entries(where).filter(([k, v]) => !k.startsWith('$') && (v === null || typeof v !== 'object')));
                        data.push(copy({ ...equality, ...update.$setOnInsert }));
                    }
                    return { acknowledged: true, matchedCount: selected.length, upsertedCount: Number(!selected.length && !!options.upsert) };
                }, options);
            },
            async deleteOne(where, options) {
                assert.equal(name, GRANTS);
                assert.ok(options.session);
                options.session.grantAction = 'revoke';
                return this.deleteMany(where, options);
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
    return { rows: name => tables.get(name).map(copy), commits, writes: () => writes.splice(0), password, faults };
}

function hostFixture(t, mongo) {
    const bindWire = require('../../../services/tests/helpers/rebuildRelayInstallJoined')({ wireOnly: true });
    const ready = { machineId, ppp: true, masked: false, unitsLoaded: true };
    const main = JSON.stringify({ inbounds: [{ tag: 'fwd-hop-a', protocol: 'vless', port: 443 }],
        outbounds: [{ tag: 'block', protocol: 'blackhole' }], routing: { rules: [
            { type: 'field', ruleTag: 'rebuild-policy-default', inboundTag: ['fwd-hop-a'], outboundTag: 'block' },
        ] } });
    const remote = { key, machineId, checks: [], effects: [] };
    let candidate, installedId, chapLogins;
    const census = 'f'.repeat(64);
    const logins = users => users.map(user => user.login).sort();
    const frames = bindWire(t, [{ id: nodeId, relay: { ip: host }, get key() { return remote.key; },
        get machineId() { return remote.machineId; }, applyHandlers: new Map(), execute(command, stdin) {
        const req = JSON.parse(stdin);
        assert.equal(req.machineId, machineId);
        assert.equal(mongo.rows(LOCK).length, 1);
        assert.ok(!command.includes(sshPassword));
        const ok = body => ({ status: 0, stdout: JSON.stringify(body) + '\n', stderr: '' });
        if (req.action === remote.staleRead) return { status: 70, stdout: '', stderr: 'DIRECT_RUNTIME_REATTEST_REQUIRED\n' };
        if (req.action === 'reattest-runtime') {
            assert.equal(req.backupId, installedId);
            return remote.reattestReply;
        }
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
            chapLogins = ['relay-bootstrap'];
            remote.effects.push(req.action);
            if (remote.loseInstallReply) return { status: 255, stdout: '', stderr: '' };
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
        case 'check-chap':
        case 'sync-chap': {
            assert.equal(req.backupId, installedId);
            assert.deepEqual(logins(req.currentUsers), chapLogins);
            if (req.action === 'sync-chap') {
                assert.ok(mongo.rows(DIRECTORY).some(row => row._id === 'pending'));
                chapLogins = logins(req.desiredUsers);
                remote.effects.push(req.action);
                if (remote.loseChapReply) return { status: 255, stdout: '', stderr: '' };
            }
            return ok({ ok: true, backupId: installedId, changed: true });
        }
        case 'session-count':
        case 'prepare-remove':
        case 'remove': {
            assert.equal(req.backupId, installedId);
            assert.deepEqual(logins(req.currentUsers), chapLogins);
            if (req.action === 'session-count') return ok({ activeSessions: 0, activeIpsec: 0, census });
            if (req.action === 'prepare-remove') return ok({ ok: true, backupId: installedId, machineId, baseline: '9'.repeat(64) });
            assert.equal(req.expectedCensus, census);
            assert.equal(mongo.rows(STATES)[0].status, 'removing');
            remote.effects.push(req.action);
            installedId = undefined;
            chapLogins = undefined;
            if (remote.loseRemoveReply) return { status: 255, stdout: '', stderr: '' };
            return ok({ ok: true, backupId: req.backupId, removed: true });
        }
        default: assert.fail(`Unexpected DIRECT action: ${req.action}`);
        }
        return ok({ ok: true, backupId: req.backupId });
    } }, { id: unusedId, relay: { ip: unusedHost }, machineId: unusedMachine, key: unusedKey,
        applyHandlers: new Map(), execute() { assert.fail('Unused relay received a DIRECT payload'); } }]);
    // The same synthetic host also provides the isolated discovery and pinned
    // machine-id channel; no real connect, shell or package command runs.
    const sockets = new Set(), probes = new WeakMap(), directHosts = new WeakMap(), absence = [];
    t.mock.method(Socket.prototype, 'connect', function (options) {
        assert.ok([host, unusedHost].includes(options.host));
        assert.equal(options.port, 22);
        sockets.add(this);
        return this;
    });
    const connectInstall = Client.prototype.connect, execInstall = Client.prototype.exec;
    t.mock.method(Client.prototype, 'connect', function (options) {
        if (!options.sock) {
            directHosts.set(this, options.host);
            return connectInstall.call(this, options);
        }
        assert.ok(sockets.has(options.sock));
        const target = options.host === unusedHost ? { key: unusedKey, machineId: unusedMachine } : remote;
        assert.equal(options.username, 'root');
        assert.ok(!Object.hasOwn(options, 'password') && !Object.hasOwn(options, 'privateKey'));
        probes.set(this, target);
        const pinned = options.hostVerifier(target.key);
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
        const target = probes.get(this);
        const absenceCheck = command.startsWith('/usr/bin/timeout -k 1s 15s /usr/bin/python3 -I -B -c ');
        if (!target && !absenceCheck) return execInstall.call(this, command, callback);
        if (absenceCheck) {
            assert.equal(directHosts.get(this), unusedHost);
            assert.ok(command.endsWith(' no-record'));
            assert.equal(mongo.rows(LOCK).length, 1);
            absence.push('observed');
        } else assert.equal(command, '/usr/bin/head -c 34 /etc/machine-id');
        const channel = new EventEmitter();
        channel.stderr = new EventEmitter();
        channel.destroy = channel.stderr.destroy = () => {};
        const finish = () => queueMicrotask(() => {
            if (!absenceCheck) remote.checks.push('machine');
            if (target?.error) channel.emit('error', new Error(privateError));
            else {
                channel.emit('data', Buffer.from(absenceCheck ? `absent:${unusedMachine}\n` : `${target.machineId}\n`));
                channel.stderr.emit('end');
                channel.emit('close', 0);
            }
        });
        channel.end = finish;
        callback(null, channel);
        if (absenceCheck) finish(); // The absence witness has no stdin.
    });
    t.after(() => assert.ok([...sockets].every(socket => socket.destroyed), 'all admission sockets closed'));
    return { remote, frames, absence };
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
    app.set('views', require('node:path').resolve(__dirname, '../../../../views'));
    app.set('view engine', 'ejs');
    app.use(require('../../../middleware/i18n').i18nMiddleware);
    app.use(require('../rebuildL2tp').rebuildL2tpIngress);
    app.use(express.json());
    // Default production composition; no injected admission or Install service.
    app.use('/panel', panel.createPanelRouter());
    const session = { authenticated: true, adminUsername: actor };
    const csrf = issuePanelCsrfToken({ session });
    const send = (action, body = {}, { csrfToken = csrf, expected = 200, id = nodeId, html = false } = {}) => new Promise((resolve, reject) => {
        const payload = Buffer.from(JSON.stringify(body)), wire = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { wire.push(chunk.toString()); done(); } });
        socket.remoteAddress = '192.0.2.10';
        const req = new IncomingMessage(socket);
        const path = action.startsWith('accounts/') ? 'l2tp' : `${id}/l2tp`;
        const url = action.startsWith('/') ? action : `/panel/rebuild/relays/${path}/${action}`;
        Object.assign(req, { method: 'POST', url, session, sessionID, complete: true, headers: {
            host: 'panel.fixture.invalid', 'content-type': 'application/json', 'content-length': String(payload.length), 'x-csrf-token': csrfToken,
            ...(html && { accept: 'text/html', 'accept-language': 'ru' }),
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
                const result = html ? res.getHeader('location') : JSON.parse(raw.slice(raw.indexOf('\r\n\r\n') + 4));
                assert.equal(res.statusCode, expected, `${action}: ${result?.error?.code ?? 'unexpected response'}`);
                resolve(result);
            } catch (error) { reject(error); }
        });
        app(req, res);
    });
    const preview = async () => {
        const estimate = await require('../../../services/rebuildService').createRebuildService().previewRemoveRelay(nodeId);
        assert.equal(estimate.confirmable, true);
        return require('../rebuildRelayRemove').issueRemovalTicket({ method: 'GET', headers: {}, session, sessionID,
            params: { id: nodeId } }, estimate);
    };
    const get = (url, lang = 'ru') => require('../../../services/tests/helpers/rebuildPanelRequest').request(app, url, {
        method: 'GET', session: { ...session, lang }, sessionID, headers: { 'accept-language': lang },
    });
    return { send, get, session, preview, admission: (action, ...args) => send(`admission/${action}`, ...args) };
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
        error: { code: CHANGED, outcome: 'refused' },
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
    // The reservation binds the recovery receipt to the held Install lock in the same transaction.
    assert.deepEqual(f.mongo.commits, [['grant', GRANTS, AUDIT], ['install', STATES, USERS, LOCK], ['install', USERS, DIRECTORY, STATES]]);
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

for (const cut of ['lost reservation acknowledgement', 'identity after reservation', 'lost host reply', 'lost finish acknowledgement',
    'reservation cleanup failure', 'finish cleanup failure']) {
    test(`admitted Install reports its phase without replay: ${cut}`, { timeout: 5000 }, async t => {
        const f = joined(t);
        await f.confirm((await f.verify((await f.probe()).challenge)).challenge);
        const identity = cut === 'identity after reservation';
        const lostReservation = cut === 'lost reservation acknowledgement';
        const lostFinish = cut === 'lost finish acknowledgement';
        const reservationCleanup = cut === 'reservation cleanup failure', finishCleanup = cut === 'finish cleanup failure';
        const noDispatch = identity || lostReservation || reservationCleanup;
        const finished = lostFinish || finishCleanup;
        f.mongo.faults.afterCommit = modified => {
            if (modified.has(STATES) && modified.has(USERS) && !modified.has(DIRECTORY)) {
                if (identity) f.remote.machineId = 'c'.repeat(32);
                if (lostReservation) throw Error(privateError);
            }
            if (lostFinish && modified.has(DIRECTORY)) throw Error(privateError);
        };
        f.mongo.faults.afterAcknowledgedCommit = modified => {
            if ((reservationCleanup && modified.has(STATES) && !modified.has(DIRECTORY))
                || (finishCleanup && modified.has(DIRECTORY))) throw Error(privateError);
        };
        f.remote.loseInstallReply = cut === 'lost host reply';
        const code = identity ? CHANGED : lostReservation ? 'REBUILD_L2TP_RESERVATION_FAILED'
            : lostFinish ? 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN' : reservationCleanup ? 'REBUILD_L2TP_RESERVATION_CLEANUP_FAILED'
                : finishCleanup ? 'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED' : 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN';
        assert.deepEqual(await f.send('install', {}, { expected: 409 }), {
            error: { code, outcome: finishCleanup ? 'installed' : 'unknown', retryAllowed: false },
        });
        assert.deepEqual(f.remote.effects, noDispatch ? [] : ['install']);
        assert.equal(f.mongo.rows(STATES)[0].status, finished ? 'installed' : 'installing');
        assert.equal(f.mongo.rows(USERS)[0].syncStatus, finished ? 'synced' : 'pending');
        const names = [LOCK, STATES, USERS, DIRECTORY];
        const before = names.map(f.mongo.rows), frames = [...f.frames];
        assert.equal(before[0].length, finishCleanup ? 0 : 1);
        assert.equal((await f.send('install', {}, { expected: 409 })).error.code,
            finishCleanup ? 'REBUILD_L2TP_NOT_FRESH_RELAY' : 'REBUILD_BUSY');
        assert.deepEqual(names.map(f.mongo.rows), before);
        assert.deepEqual(f.frames, frames);
    });
}

for (const cut of ['identity before reservation', 'identity after reservation', 'lost host reply', 'lost reservation acknowledgement',
    'lost finish acknowledgement', 'reservation cleanup failure', 'finish cleanup failure', 'success']) {
    test(`admitted Remove reports its phase without replay: ${cut}`, { timeout: 5000 }, async t => {
        const f = joined(t);
        await f.confirm((await f.verify((await f.probe()).challenge)).challenge);
        await f.send('install');
        const ticket = await f.preview(), secondTicket = await f.preview();
        const beforeAccounts = f.mongo.rows(USERS);
        const pre = cut === 'identity before reservation', identity = cut === 'identity after reservation';
        const lostReservation = cut === 'lost reservation acknowledgement', lostFinish = cut === 'lost finish acknowledgement';
        const reservationCleanup = cut === 'reservation cleanup failure', finishCleanup = cut === 'finish cleanup failure';
        const success = cut === 'success', finished = success || lostFinish || finishCleanup;
        if (pre) f.remote.machineId = 'c'.repeat(32);
        f.mongo.faults.afterCommit = modified => {
            const state = f.mongo.rows(STATES)[0].status;
            if (modified.has(STATES) && state === 'removing') {
                if (identity) f.remote.machineId = 'c'.repeat(32);
                if (lostReservation) throw Error(privateError);
            }
            if (lostFinish && modified.has(STATES) && state === 'not_installed') throw Error(privateError);
        };
        f.mongo.faults.afterAcknowledgedCommit = modified => {
            const state = f.mongo.rows(STATES)[0].status;
            if (modified.has(STATES) && ((reservationCleanup && state === 'removing')
                || (finishCleanup && state === 'not_installed'))) throw Error(privateError);
        };
        f.remote.loseRemoveReply = cut === 'lost host reply';
        if (lostReservation || lostFinish || reservationCleanup) {
            const code = reservationCleanup ? 'RESERVATION_CLEANUP_FAILED'
                : lostReservation ? 'RESERVATION_OUTCOME_UNKNOWN' : 'FINISH_OUTCOME_UNKNOWN';
            assert.deepEqual(await f.send('remove', { decision: 'confirm', ticket }, { expected: 409 }), {
                error: { code: `REBUILD_L2TP_REMOVE_${code}`, outcome: 'unknown', retryAllowed: false },
            });
        } else {
            assert.equal(await f.send('remove', { decision: 'confirm', ticket }, { expected: 303, html: true }), pre
                ? `/panel/l2tp?identityChanged=${nodeId}#relay-${nodeId}` : success ? `/panel/nodes/${nodeId}`
                    : finishCleanup ? '/panel/l2tp?view=remove-cleanup' : '/panel/l2tp?view=remove-unconfirmed');
        }
        assert.deepEqual(f.remote.effects, pre || identity || lostReservation || reservationCleanup ? ['install'] : ['install', 'remove']);
        assert.deepEqual(f.mongo.rows(USERS), finished ? [] : beforeAccounts);
        assert.equal(f.mongo.rows(STATES)[0].status, pre ? 'installed' : finished ? 'not_installed' : 'removing');
        assert.equal(f.mongo.rows(LOCK).length, pre || success || finishCleanup ? 0 : 1);
        if (!pre && !success && !finishCleanup) {
            const saved = f.mongo.rows(LOCK), frames = [...f.frames];
            assert.equal((await f.send('remove', { decision: 'confirm', ticket: secondTicket }, { expected: 409 })).error.code, 'REBUILD_BUSY');
            assert.deepEqual(f.mongo.rows(LOCK), saved);
            assert.deepEqual(f.frames, frames);
        }
    });
}

test('admitted account POSTs leave a prior uncertain intent untouched', { timeout: 5000 }, async t => {
    const f = joined(t);
    await f.confirm((await f.verify((await f.probe()).challenge)).challenge);
    await f.send('install');
    const path = '/panel/rebuild/relays/l2tp/accounts';
    const credentials = { login: 'fixture-new', password: 'fixture-password' };
    f.remote.loseChapReply = true;
    assert.deepEqual(await f.send(`${path}/create`, credentials, { expected: 409 }), {
        error: { code: 'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN', retryAllowed: false },
    });
    assert.deepEqual(f.remote.effects, ['install', 'sync-chap']);
    const read = () => [DIRECTORY, STATES, USERS, LOCK].map(f.mongo.rows);
    const before = read(), frames = [...f.frames], commits = [...f.mongo.commits];
    assert.equal(before[0].filter(row => row._id === 'pending').length, 1);
    assert.deepEqual(before.at(-1), []);
    for (const [action, input] of [['create', credentials], ['disable', { login: 'another-fixture' }]]) {
        assert.deepEqual(await f.send(`${path}/${action}`, input, { expected: 409 }), {
            error: { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED', retryAllowed: false },
        });
        assert.deepEqual(read(), before);
        assert.deepEqual(f.frames, frames);
        assert.deepEqual(f.mongo.commits, commits);
    }
});

const foreignCode = 'REBUILD_L2TP_RUNTIME_FOREIGN_CHANGE';
const foreignRu = 'Конфигурация L2TP на релее изменена вне панели';
const foreignFrame = { status: 70, stdout: '', stderr: 'DIRECT_RUNTIME_FOREIGN_CHANGE\n' };
const lostFrame = { status: 75, stdout: '', stderr: '' };
const observationFrame = { status: 70, stdout: '', stderr: 'DIRECT_NETWORK_OBSERVATION_REQUIRED\n' };
const notReady = { code: 'REBUILD_L2TP_HOST_NOT_READY', check: 'NETWORK_OBSERVATION_REQUIRED', retryAllowed: false };

test('network observation refusal shows localized server-not-ready on the real census card and blocks Remove', { timeout: 5000 }, async t => {
    const f = joined(t);
    await f.confirm((await f.verify((await f.probe()).challenge)).challenge);
    await f.send('install');
    const url = `/panel/nodes/${nodeId}`;
    const issue = async () => (await f.get(url)).body.match(/name="ticket" value="([a-f0-9]{64})"/)[1];
    const censusTicket = await issue();
    const prepareTicket = await issue();
    const preserved = [STATES, USERS, DIRECTORY].map(f.mongo.rows);
    const start = f.frames.length;
    f.remote.staleRead = 'session-count';
    f.remote.reattestReply = observationFrame;
    const texts = new Set();
    for (const lang of ['ru', 'en', 'zh-CN']) {
        const { status, body } = await f.get(url, lang);
        const { nodes, rebuildL2tp: copy } = require(`../../../locales/${lang}.json`);
        assert.equal(status, 200);
        assert.match(body, /id="rebuild-l2tp-remove" open>/);
        assert.ok(body.includes(`<p role="status">${copy.messages.runtimeNetworkNotReady}</p>`));
        assert.ok(body.includes(nodes.rebuildRelayCounts.replace('{accounts}', '1')
            .replace('{sessions}', nodes.rebuildCountUnavailable).replace('{ipsec}', nodes.rebuildCountUnavailable)));
        assert.ok(body.includes(copy.installChecks[notReady.check]));
        assert.doesNotMatch(body, /name="ticket"|DIRECT_NETWORK_OBSERVATION_REQUIRED/);
        assert.ok(!body.includes(copy.messages.runtimeForeignChange));
        texts.add(copy.messages.runtimeNetworkNotReady);
    }
    assert.equal(texts.size, 3);
    require('../index').l2tpRateLimiter.resetKey('192.0.2.10');
    assert.deepEqual(await f.send('remove', { decision: 'confirm', ticket: censusTicket }, { expected: 409 }), { error: notReady });
    f.remote.staleRead = 'prepare-remove';
    const notice = await f.get(await f.send('remove', { decision: 'confirm', ticket: prepareTicket }, { html: true, expected: 303 }));
    assert.equal(notice.status, 200);
    assert.ok(notice.body.includes(require('../../../locales/ru.json').rebuildL2tp.messages.runtimeNetworkNotReady));
    assert.doesNotMatch(notice.body, /data-(?:install-url|account-action|remove-link|reconcile-url)=/);
    assert.deepEqual(f.frames.slice(start).map(([id, action]) => { assert.equal(id, nodeId); return action; }), [
        ...Array.from({ length: 4 }, () => ['session-count', 'reattest-runtime']).flat(),
        'session-count', 'prepare-remove', 'reattest-runtime',
    ]);
    assert.deepEqual([STATES, USERS, DIRECTORY].map(f.mongo.rows), preserved);
    assert.deepEqual(f.remote.effects, ['install']);
});

test('runtime foreign change reaches the real node card and normal Remove without a new ticket', { timeout: 5000 }, async t => {
    const f = joined(t);
    await f.confirm((await f.verify((await f.probe()).challenge)).challenge);
    await f.send('install');
    const cardUrl = `/panel/nodes/${nodeId}`;
    const ticket = async () => {
        f.remote.staleRead = undefined;
        const card = await f.get(cardUrl);
        assert.equal(card.status, 200, card.body.slice(0, 300));
        const match = card.body.match(/name="ticket" value="([a-f0-9]{64})"/);
        assert.ok(match, 'normal card renders a real confirmation ticket');
        return match[1];
    };
    const assertFrames = (start, ...names) => assert.deepEqual(f.frames.slice(start), names.map(action => [nodeId, action]));
    const preserved = [STATES, USERS, DIRECTORY].map(f.mongo.rows);
    const censusTicket = await ticket();
    const originalFrames = f.frames.length;
    f.remote.staleRead = 'session-count';
    f.remote.reattestReply = foreignFrame;
    const card = await f.get(cardUrl);
    assert.equal(card.status, 200);
    assert.match(card.body, /id="rebuild-l2tp-remove" open>/);
    assert.match(card.body, new RegExp(`<p role="status">${foreignRu}</p>`));
    assert.doesNotMatch(card.body, /name="ticket"|DIRECT_RUNTIME_FOREIGN_CHANGE/);
    assertFrames(originalFrames, 'session-count', 'reattest-runtime');
    assert.deepEqual(await f.send('remove', { decision: 'confirm', ticket: censusTicket }, { expected: 409 }),
        { error: { code: foreignCode, retryAllowed: false } });
    assertFrames(originalFrames + 2, 'session-count', 'reattest-runtime');

    const prepareTicket = await ticket();
    const startPrepare = f.frames.length;
    f.remote.staleRead = 'prepare-remove';
    const location = await f.send('remove', { decision: 'confirm', ticket: prepareTicket }, { html: true, expected: 303 });
    const notice = await f.get(location);
    assert.equal(notice.status, 200);
    assert.match(notice.body, new RegExp(`data-action-status role="status">${foreignRu}<`));
    assert.doesNotMatch(notice.body, /data-(?:install-url|account-action|remove-link|reconcile-url)=/);
    assertFrames(startPrepare, 'session-count', 'prepare-remove', 'reattest-runtime');
    assert.deepEqual(await f.send('remove', { decision: 'confirm', ticket: prepareTicket }, { expected: 409 }),
        { error: { code: 'REBUILD_L2TP_REMOVE_CONFIRMATION_REQUIRED' } });

    require('../index').l2tpRateLimiter.resetKey('192.0.2.10');
    const lostTicket = await ticket();
    const startLost = f.frames.length;
    f.remote.staleRead = 'session-count';
    f.remote.reattestReply = lostFrame;
    const unconfirmed = await f.get(cardUrl);
    assert.equal(unconfirmed.status, 303);
    assert.equal(unconfirmed.headers.location, '/panel/l2tp?view=remove-unconfirmed');
    assert.deepEqual(await f.send('remove', { decision: 'confirm', ticket: lostTicket }, { expected: 409 }),
        { error: { code: 'REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN', outcome: 'unknown', retryAllowed: false } });
    assertFrames(startLost, 'session-count', 'reattest-runtime', 'session-count', 'reattest-runtime');
    assert.deepEqual([STATES, USERS, DIRECTORY].map(f.mongo.rows), preserved);
    assert.deepEqual(f.remote.effects, ['install']);
});

test('runtime refusals and unknown ACK reach the real CHAP reconciliation route with intent still pending', { timeout: 5000 }, async t => {
    const f = joined(t);
    await f.confirm((await f.verify((await f.probe()).challenge)).challenge);
    await f.send('install');
    f.remote.loseChapReply = true;
    await f.send('accounts/create', { login: 'fixture-new', password: 'fixture-password' }, { expected: 409 });
    const preserved = [STATES, USERS, DIRECTORY].map(f.mongo.rows);
    assert.ok(preserved[2].some(row => row._id === 'pending'));
    f.remote.staleRead = 'inspect-chap';
    const start = f.frames.length;
    const overview = await f.get('/panel/l2tp');
    assert.equal(overview.status, 200);
    assert.match(overview.body, /data-reconcile disabled/);
    const entities = { '&#34;': '"', '&#39;': "'", '&amp;': '&', '&lt;': '<', '&gt;': '>' };
    const attribute = name => overview.body.match(new RegExp(`data-${name}="([^"]+)"`))[1]
        .replace(/&#34;|&#39;|&amp;|&lt;|&gt;/g, match => entities[match]);
    const source = require('node:fs').readFileSync(require('node:path').resolve(__dirname, '../../../../public/js/rebuild-l2tp.js'), 'utf8');
    const unknown = { code: 'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN', outcome: 'unknown', retryAllowed: false };
    for (const [wire, error] of [
        [foreignFrame, { code: foreignCode, retryAllowed: false }],
        [observationFrame, notReady],
        [lostFrame, unknown],
        [{ ...observationFrame, stderr: observationFrame.stderr + privateError }, unknown],
    ]) {
        f.remote.reattestReply = wire;
        let click, request;
        const status = { textContent: '' }, refresh = { hidden: true };
        const reconcile = { disabled: true, addEventListener: (_, handler) => { click = handler; } };
        const page = {
            dataset: { csrf: attribute('csrf'), messages: attribute('messages'), reconcileUrl: attribute('reconcile-url'),
                installChecks: attribute('install-checks') },
            querySelector: key => ({ '[data-action-status]': status, '[data-refresh]': refresh, '[data-reconcile]': reconcile })[key] ?? null,
            querySelectorAll: () => [],
        };
        require('node:vm').runInNewContext(source, {
            document: { getElementById: () => page }, window: { addEventListener() {} }, fetch(url, options) {
                assert.equal(url, '/panel/rebuild/relays/l2tp/accounts/reconcile');
                assert.equal(options.method, 'POST');
                request = f.send(url, JSON.parse(options.body), { expected: 409, csrfToken: options.headers['x-csrf-token'] });
                return request.then(data => ({ status: 409, ok: false, json: async () => data }));
            },
        });
        assert.equal(request, undefined);
        assert.equal(reconcile.disabled, false);
        click();
        assert.deepEqual(await request, { error });
        await new Promise(resolve => setImmediate(resolve));
        const copy = require('../../../locales/ru.json').rebuildL2tp;
        assert.equal(status.textContent, wire === foreignFrame ? foreignRu : wire === observationFrame
            ? `${copy.messages.runtimeNetworkNotReady} ${copy.installChecks[notReady.check]}` : copy.messages.reconcileUnconfirmed);
        assert.equal(refresh.hidden, false);
        assert.equal(reconcile.disabled, true);
        click(); // A stale control must not post again, even if invoked directly.
        assert.deepEqual([STATES, USERS, DIRECTORY].map(f.mongo.rows), preserved);
    }
    assert.deepEqual(f.frames.slice(start), Array.from({ length: 4 }, () => [
        [nodeId, 'inspect-chap'], [nodeId, 'reattest-runtime'],
    ]).flat());
    assert.deepEqual(f.remote.effects, ['install', 'sync-chap']);
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
        assert.deepEqual(result, mismatch === 'error' ? refused(code) : { error: { code, outcome: 'refused' } });
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

test('last DB grant cannot strand a legacy singleton, but is revocable after Remove leaves only the directory', { timeout: 5000 }, async t => {
    const f = joined(t);
    const { createRebuildService } = require('../../../services/rebuildService');
    const { createRelayGrantStore } = require('../../../services/rebuildRelayGrantStore');
    const { issueRemovalTicket } = require('../rebuildRelayRemove');
    const grants = createRelayGrantStore({ db: mongoose.connection });
    const listKey = 'C3_REBUILD_L2TP_RELAYS_JSON';
    Object.assign(process.env, { C3_REBUILD_L2TP_RELAY_ID: nodeId,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: pin });
    assert.equal(Object.hasOwn((await grants.snapshot()).env, listKey), false);
    assert.deepEqual(await f.send('install'), { executionMode: 'rebuild', status: 'installed', nodeId });
    assert.deepEqual(f.mongo.commits, [], 'legacy Install does not require a transaction');
    assert.deepEqual(f.mongo.rows(DIRECTORY), []);

    const other = { id: unusedId };
    const { challenge: discovered } = await f.admission('probe', {}, other);
    const { challenge: verified } = await f.admission('verify', { challenge: discovered }, other);
    assert.equal((await f.admission('confirm', { challenge: verified }, other)).nodeId, unusedId);
    assert.equal(f.mongo.rows(GRANTS).length, 1);
    assert.equal(Object.hasOwn((await grants.snapshot()).env, listKey), true);
    const login = 'fixture-shared';
    assert.deepEqual(await f.send('accounts/create', { login, password: 'fixture-only' }, { expected: 201 }),
        { executionMode: 'rebuild', status: 'created', login, relayCount: 1 });
    assert.deepEqual(f.mongo.rows(USERS).map(row => [String(row.relayNode), row.login]).sort(),
        [[nodeId, login], [nodeId, 'relay-bootstrap']]);
    const before = [GRANTS, STATES, USERS, DIRECTORY].map(name => f.mongo.rows(name));
    const commits = f.mongo.commits.length, frames = f.frames.length;
    f.mongo.writes();
    const blocked = 'REBUILD_L2TP_GRANT_LEGACY_SINGLETON_IN_USE';
    assert.deepEqual(await f.admission('revoke', {}, { ...other, expected: 409 }), refused(blocked));
    assert.deepEqual(f.absence, ['observed'], 'unused relay passed the ordinary host absence gate');
    assert.ok(equal([GRANTS, STATES, USERS, DIRECTORY].map(name => f.mongo.rows(name)), before), 'business records are unchanged');
    assert.equal(f.mongo.commits.length, commits);
    assert.equal(f.frames.length, frames);
    assert.deepEqual(f.mongo.writes(), [LOCK, LOCK, AUDIT]);
    assert.deepEqual(f.mongo.rows(AUDIT).slice(-1).map(row => [row.nodeId, row.action, row.outcome, row.code]),
        [[unusedId, 'revoke', 'denied', blocked]]);
    assert.equal(Object.hasOwn((await grants.snapshot()).env, listKey), true);

    const estimate = await createRebuildService().previewRemoveRelay(nodeId);
    assert.deepEqual(estimate, { nodeId, accountCount: 2, activeSessions: 0, activeIpsec: 0, confirmable: true });
    const ticket = issueRemovalTicket({ method: 'GET', session: f.session, sessionID, params: { id: nodeId }, headers: {} }, estimate);
    assert.ok(ticket);
    assert.deepEqual(await f.send('remove', { decision: 'confirm', ticket }), { executionMode: 'rebuild', status: 'not_installed', nodeId });
    assert.deepEqual(f.mongo.rows(USERS), []);
    assert.deepEqual(f.mongo.rows(STATES).map(row => [row.status, row.desiredState]), [['not_installed', 'absent']]);
    const directory = before[3];
    assert.deepEqual(directory.map(row => row.accounts.map(account => account.login)), [[login, 'relay-bootstrap']]);
    assert.ok(equal(f.mongo.rows(DIRECTORY), directory), 'Remove preserves the logical directory');

    assert.deepEqual(await f.admission('revoke', {}, other), { nodeId: unusedId });
    assert.deepEqual(f.mongo.rows(GRANTS), []);
    assert.deepEqual(f.mongo.commits.at(-1), ['revoke', GRANTS, AUDIT]);
    assert.ok(equal(f.mongo.rows(DIRECTORY), directory), 'safe revoke preserves the logical directory');
    const snapshot = await grants.snapshot();
    assert.equal(snapshot.sourceFor(nodeId), 'env');
    assert.equal(Object.hasOwn(snapshot.env, listKey), false);
    assert.deepEqual(f.remote.effects, ['install', 'sync-chap', 'remove']);
    assert.deepEqual(f.mongo.rows(LOCK), []);
});

const lockNotes = {
    pending: ['Installation is unavailable: the panel is waiting for an operation to finish.', 'Установка недоступна: панель ожидает завершения операции.'],
    protected: ['Installation is unavailable: a protective lock is in place.', 'Установка недоступна: действует защитная блокировка.'],
    unspecified: ['Installation is unavailable: a lock is in place, but its purpose is unclear.', 'Установка недоступна: сохранена блокировка, но её назначение не подтверждено.'],
    unreadable: ['Installation is unavailable: the panel could not read the lock status.', 'Установка недоступна: панели не удалось прочитать состояние блокировки.'],
};
for (const [cut, reason] of [['ordinary Apply', 'pending'], ['protected', 'protected'], ['legacy', 'unspecified'],
    ['malformed', 'unspecified'], ['read failure', 'unreadable'], ['confirmed prewrite refusal', null]]) {
    test(`Install availability note on fresh GET: ${cut}`, async t => {
        const panel = configure(t), mongo = mongoFixture(t), db = mongoose.connection;
        process.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([{ nodeId, host, port: 22, username: 'root', machineId, sshHostKeySha256: pin }]);
        const State = require('../../../modules/relay-l2tp/models/relayL2tpStateModel');
        const pristine = new State({ node: nodeId, routingVersion: null, rebuildMachineId: '', rebuildInstallToken: '' }).toObject();
        await db.collection(STATES).insertOne(pristine);
        const expressApp = express();
        expressApp.set('views', require('node:path').resolve(__dirname, '../../../../views'));
        expressApp.set('view engine', 'ejs');
        expressApp.use(require('../../../middleware/i18n').i18nMiddleware);
        expressApp.use('/panel', panel.createPanelRouter());
        const request = require('../../../services/tests/helpers/rebuildPanelRequest').request;
        const first = { authenticated: true }, other = { authenticated: true };
        let token = 'fixture-private-lock-token';
        const page = async (lang, session, note) => {
            const p = await request(expressApp, '/panel/l2tp', { method: 'GET', session, sessionID: session === first ? 'first' : 'other',
                headers: { 'accept-language': lang } });
            assert.equal(p.status, 200); assert.equal(p.headers['cache-control'], 'no-store');
            assert.ok(!p.body.includes(token) && !p.body.includes(privateError));
            const card = id => p.body.match(new RegExp(`<tr id="relay-${id}">[\\s\\S]*?</tr>`))?.[0];
            const row = card(nodeId), unrelated = card(unusedId); assert.ok(row && unrelated);
            const locale = require(`../../../locales/${lang}.json`).rebuildL2tp;
            assert.ok(row.includes(`>${locale.status.not_installed}</span>`));
            assert.equal(row.includes(`data-install-url="/panel/rebuild/relays/${nodeId}/l2tp/install"`), !note);
            assert.deepEqual([...row.matchAll(/data-install-blocked>([^<]*)<\/p>/g)].map(m => m[1]), note ? [lockNotes[note][lang === 'en' ? 0 : 1]] : []);
            assert.ok(!unrelated.includes('data-install-blocked') && !unrelated.includes('data-install-url'));
        };
        await page('ru', first, null);
        const store = db.collection(LOCK);
        async function checkPages() {
            const saved = mongo.rows(LOCK); mongo.writes();
            if (saved.length) token = saved[0].token;
            const read = store.findOne.bind(store), reads = [];
            t.mock.method(store, 'findOne', async (filter, options) => {
                reads.push([filter, options]);
                if (cut === 'read failure') throw Error(privateError);
                return read(filter, options);
            });
            for (const lang of ['ru', 'en']) for (const session of [first, other]) await page(lang, session, reason);
            assert.equal(reads.length, 4);
            for (const [filter, options] of reads) {
                assert.deepEqual(filter, { _id: 'apply' });
                assert.deepEqual(options.projection, { _id: 1, allowStaleUnlock: 1 });
                assert.equal(options.readConcern.level, 'majority');
                assert.equal(options.readPreference, 'primary');
            }
            assert.deepEqual(mongo.rows(LOCK), saved); assert.deepEqual(mongo.writes(), []);
        }
        if (cut === 'ordinary Apply') {
            return require('../../../services/rebuildService').createRebuildService().locks.run(async verify => {
                await verify(); await checkPages();
            });
        }
        if (!reason) {
            let checks = 0;
            const service = require('../../../services/rebuildService').createRebuildService({ createRelayDirect: () => ({
                preflight: async () => { checks++; return { machineId, ppp: false, masked: false, unitsLoaded: true }; }, close: async () => {},
            }) });
            mongo.writes();
            await assert.rejects(service.installRelay(nodeId), { code: 'REBUILD_L2TP_HOST_NOT_READY', outcome: 'refused' });
            assert.equal(checks, 1); assert.deepEqual(mongo.writes(), [LOCK, LOCK]); assert.deepEqual(mongo.rows(LOCK), []);
        } else if (cut !== 'read failure') {
            const marker = { protected: false, malformed: [true] };
            await store.insertOne({ _id: 'apply', token, heartbeat: new Date(0), ...(cut !== 'legacy' && { allowStaleUnlock: marker[cut] }) });
        }
        await checkPages();
    });
}

test.after(() => require('../../../services/sshPoolService').closeAll());
