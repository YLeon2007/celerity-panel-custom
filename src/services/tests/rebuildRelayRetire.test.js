'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { IncomingMessage, ServerResponse } = require('node:http');
const { Duplex } = require('node:stream');
const { EventEmitter } = require('node:events');
const { performance } = require('node:perf_hooks');
const { mongo: { BSON }, Types: { ObjectId } } = require('mongoose');
const { createRebuildService } = require('../rebuildService');
const { createRebuildRelayRetire } = require('../rebuildRelayRetire');
const { fingerprintLinks, retirementScope } = require('../rebuildCoordinator');
const { makeLocks } = require('../rebuildLocks');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const generator = require('../configGenerator');
const NodeSSH = require('../nodeSSH');
const { MAIN, BRIDGE } = require('../classicAppliedConfig');
const { GRANTS, RETIRED } = require('../rebuildRelayGrantStore');
const { collectionName: DIRECTORY } = require('../rebuildRelayDirectory');
const { rebuildApplyMachineGuard } = require('./helpers/rebuildApplyMachineGuard');

const id = 'a'.repeat(24), portal = 'b'.repeat(24), exit = 'c'.repeat(24);
const machineId = '1'.repeat(32), backupId = '2'.repeat(32), census = '3'.repeat(64);
const fault = (code, extra) => Object.assign(new Error('untrusted transport text: ECONNREFUSED'), { code, ...extra });
const sameBson = (a, b) => BSON.serialize({ value: a }).equals(BSON.serialize({ value: b }));
const nativeNode = row => ({ ...row, _id: new ObjectId(row._id) });
const at = (row, path) => path.reduce((parent, key) => parent?.[key], row);
// Only the Mongo expression subset emitted by the retirement projection and
// CAS. Missing paths are omitted in computed objects, not materialized as null.
function expression(input, vars) {
    const evaluate = value => expression(value, vars);
    if (typeof input === 'string' && input.startsWith('$$')) return at(vars, input.slice(2).split('.'));
    if (Array.isArray(input)) return input.map(evaluate);
    if (!input || Object.getPrototypeOf(input) !== Object.prototype) return input;
    const [operator] = Object.keys(input);
    switch (operator) {
    case '$literal': return input.$literal;
    case '$cond': return evaluate(input.$cond[evaluate(input.$cond[0]) ? 1 : 2]);
    case '$in': return evaluate(input.$in[1]).some(value => sameBson(value, evaluate(input.$in[0])));
    case '$isArray': return Array.isArray(evaluate(input.$isArray));
    case '$map': {
        const { input: array, as, in: mapping } = input.$map;
        return evaluate(array).map(item => expression(mapping, { ...vars, [as]: item }));
    }
    case '$type': {
        const value = evaluate(input.$type);
        if (value === undefined) return 'missing';
        if (value === null) return 'null';
        if (value instanceof ObjectId) return 'objectId';
        if (value instanceof Date) return 'date';
        if (Array.isArray(value)) return 'array';
        if (typeof value === 'boolean') return 'bool';
        if (typeof value === 'number') {
            return Number.isInteger(value) && value >= -2147483648 && value <= 2147483647 ? 'int' : 'double';
        }
        return typeof value;
    }
    case '$eq': return sameBson(...input.$eq.map(evaluate));
    default:
        assert.ok(!operator?.startsWith('$'), `unmodeled Mongo expression: ${operator}`);
        return Object.fromEntries(Object.entries(input).map(([key, value]) => [key, evaluate(value)])
            .filter(([, value]) => value !== undefined));
    }
}
const fields = (row, projection) => {
    if (!projection || !Object.keys(projection).length) return row;
    const entries = Object.entries(projection);
    const inclusion = entries.some(([key, flag]) => key !== '_id' && flag !== 0) || projection._id === 1 && entries.length === 1;
    function pick(value, spec) {
        return Object.fromEntries(Object.entries(value).flatMap(([key, field]) => {
            const rule = spec[key];
            const descendants = Object.fromEntries(Object.entries(spec).filter(([path]) => path.startsWith(`${key}.`))
                .map(([path, flag]) => [path.slice(key.length + 1), flag]));
            if (Object.keys(descendants).length && field && Object.getPrototypeOf(field) === Object.prototype) {
                return [[key, pick(field, descendants)]];
            }
            return (inclusion ? rule === 1 : rule !== 0) ? [[key, field]] : [];
        }));
    }
    return Object.assign(pick(row, { ...(inclusion && { _id: 1 }), ...projection }),
        Object.fromEntries(entries.filter(([, flag]) => typeof flag === 'object')
            .map(([key, value]) => [key, expression(value, { ROOT: row })]).filter(([, value]) => value !== undefined)));
};
const matches = (row, filter) => Object.entries(filter).every(([key, value]) => {
    if (key === '$or') return value.some(item => matches(row, item));
    if (key === '$expr') {
        assert.ok(Object.hasOwn(value.$eq?.[1] ?? {}, '$literal'), 'CAS must treat the expected image as data');
        return expression(value, { ROOT: row });
    }
    const actual = at(row, key.split('.'));
    if (Array.isArray(value?.$in)) return [actual].flat().some(item => value.$in.some(term => String(item) === String(term)));
    if (Object.hasOwn(value ?? {}, '$eq')) return require('node:util').isDeepStrictEqual(actual, value.$eq) && (!value.$exists || actual !== undefined);
    if (Object.hasOwn(value ?? {}, '$exists')) return (actual !== undefined) === value.$exists;
    if (Object.hasOwn(value ?? {}, '$ne')) return actual !== value.$ne;
    return String(actual) === String(value);
});
const ok = (stdout = '') => ({ code: 0, stdout, stderr: '' });
const steps = f => f.trace.map(event => event[0]);
const effects = f => f.trace.filter(([step]) => ['reserve', 'remove', 'stage', 'put', 'begin', 'delete', 'commit'].includes(step));
const noEffects = f => assert.deepEqual(effects(f), []);
const noTarget = f => {
    assert.deepEqual(f.trace.filter(([step, node]) => node === id || ['agent', 'census', 'remove', 'reserve'].includes(step)), []);
};

test.before(() => test.mock.method(require('node:net').Socket.prototype, 'connect', () => assert.fail('fixture must not open sockets')));
test.after(() => require('../sshPoolService').closeAll());

function fixture(t, { installed = true, realSshAdmission = false } = {}) {
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const nodes = [[portal, 'portal'], [id, 'relay'], [exit, 'bridge']].map(([_id, cascadeRole], i) => ({
        _id, name: cascadeRole, cascadeRole, active: true, type: 'xray', ip: `192.0.2.${i + 1}`, port: 12010 + i,
        ssh: { port: 22, username: 'root', password: 'fixture-private-value' },
        xray: { security: 'none', apiPort: 15000 + i, inboundTag: `client-${i}`, agentToken: 'fixture-private-value' },
    }));
    const links = [[portal, id], [id, exit]].map(([portalNode, bridgeNode], i) => ({
        _id: `${i + 1}`.repeat(24), portalNode, bridgeNode, active: true, mode: 'forward',
        tunnelEncryption: 'none', tunnelPort: 14000 + i, tunnelUuid: `00000000-0000-4000-8000-00000000000${i}`, rebuildApplied: null,
    }));
    const stamp = new Date(1234);
    const state = { _id: 'd'.repeat(24), node: id, status: 'installed', desiredState: 'installed',
        rebuildInstallToken: '01234567-89ab-4def-abcd-0123456789ab', backupId, rebuildMachineId: machineId,
        routingMode: 'follow-relay', routingVersion: 1, secretRevision: 1, clientCidr: '10.5.0.0/24',
        localAddress: '10.5.0.1', poolStart: '10.5.0.10', poolEnd: '10.5.0.20', tproxyPort: 12345, fwmark: 25,
        routeTable: 125, pskEncrypted: 'fixture-private-value', installedAt: stamp, lastVerifiedAt: stamp, lastSyncAt: stamp,
        updatedAt: stamp, futureField: { x: 1 } };
    const user = { _id: 'e'.repeat(24), relayNode: id, login: 'relay-bootstrap', ip: state.poolStart, enabled: true,
        desiredRevision: 1, appliedRevision: 1, syncStatus: 'synced', passwordEncrypted: 'fixture-private-value',
        createdAt: stamp, updatedAt: stamp, lastSyncedAt: stamp };
    const data = { nodes, links, states: installed ? [state] : [], accounts: installed ? [user] : [],
        users: [{ _id: 'f'.repeat(24), nodes: [portal, id, exit] }], [DIRECTORY]: [], [GRANTS]: [], [RETIRED]: [] };
    const f = { trace: [], data, profiles: new Map(), census: { activeSessions: 0, activeIpsec: 0, census }, factories: 0 };
    const env = { C3_REBUILD_ENABLED: 'true', ...(installed && {
        C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: id, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId,
        C3_REBUILD_L2TP_SSH_SHA256: '4'.repeat(64),
    }) };
    const controlPlaneAddresses = nodes.map(n => n.ip);
    const compose = followRelayStates => composeRebuildProfiles({ nodes: nodes.map(n => ({ ...n, active: true })), links,
        followRelayStates, controlPlaneAddresses });
    const withoutL2tp = compose([]).find(p => p.nodeId === id && p.profile === 'main').config;
    for (const { nodeId, profile, config } of compose(data.states)) f.profiles.set(`${nodeId}:${profile}`, config);
    const mark = (...event) => { assert.ok(f.lock, 'all observations and effects need the global guard'); f.trace.push(event); };
    const query = (getter, name) => {
        let session, selection;
        const q = { lean: async () => {
            const docs = structuredClone(getter(session));
            if (!docs || !selection) return docs;
            return Array.isArray(docs) ? docs.map(row => fields(row, selection)) : fields(docs, selection);
        }, session: value => { session = value; return q; }, select: value => {
            // An ordinary positive Node projection (in particular standalone
            // Remove) is not equivalent to the full card returned by lean().
            if (name === 'nodes' && typeof value === 'string') {
                const keys = value.split(/\s+/).filter(key => key && !/^[+-]/.test(key));
                if (keys.length) selection = Object.fromEntries(keys.map(key => [key, 1]));
            }
            return q;
        } };
        for (const method of ['read', 'readConcern', 'limit', 'maxTimeMS']) q[method] = () => q;
        return q;
    };
    let activeSession;
    const table = (name, session) => {
        if (!session) return data[name];
        // Mongo pins the snapshot at the first operation, not startTransaction.
        if (!session.base) {
            f.beforeTransactionSnapshot?.();
            session.base = structuredClone(data);
            session.staged = structuredClone(session.base);
        }
        return session.staged[name];
    };
    const readRow = (name, row, opts) => {
        const projected = fields(name === 'nodes' ? nativeNode(row) : row, opts.projection);
        const raw = BSON.serialize(projected);
        if (name === 'nodes' && opts.raw) f.onRawNodeRead?.(projected, opts);
        return opts.raw ? raw : BSON.deserialize(raw);
    };
    // Only the ODM facade accepts string node IDs as a proxy for a cast.
    const selectRow = (name, row, filter) => name !== 'nodes' ? matches(row, filter)
        : filter._id instanceof ObjectId && matches(nativeNode(row), filter);
    const collection = name => ({
        async findOne(filter, opts = {}) {
            if (name === 'nodes' && f.dbError) throw f.dbError;
            const row = table(name, opts.session).find(row => selectRow(name, row, filter));
            return row ? readRow(name, row, opts) : null;
        },
        find(filter, opts = {}) {
            return { toArray: async () => {
                const rows = table(name, opts.session).filter(row => selectRow(name, row, filter));
                if (opts.sort?._id === 1) rows.sort((a, b) => String(a._id).localeCompare(String(b._id)));
                return rows.slice(0, opts.limit).map(row => readRow(name, row, opts));
            } };
        },
        async updateOne(filter, update, opts = {}) {
            // Same-row independent writer waits once a delete has been staged.
            // On commit it re-evaluates the filter against the now-absent row.
            const session = activeSession;
            if (!opts.session && name === 'nodes' && session?.deletedNodeIds.has(String(filter._id))) {
                await session.finished.promise;
            }
            return this.updateMany(filter, update, opts);
        },
        async updateMany(filter, update, opts = {}) {
            const rows = table(name, opts.session);
            if (update.$setOnInsert) { rows.push(structuredClone(update.$setOnInsert)); return { acknowledged: true, upsertedCount: 1 }; }
            const picked = rows.filter(row => selectRow(name, row, filter));
            for (const row of picked) {
                Object.assign(row, update.$set);
                for (const field of Object.keys(update.$unset ?? {})) delete row[field];
                if (update.$pull) row.nodes = row.nodes.filter(key => key !== id);
            }
            if (name === 'states' && update.$set?.status === 'removing') mark('reserve');
            if (name === 'states' && update.$set?.status === 'not_installed') f.afterRemove?.();
            return { acknowledged: true, matchedCount: picked.length };
        },
        async insertOne(row, { session }) { table(name, session).push(structuredClone(row)); return { acknowledged: true }; },
        async deleteOne(filter, opts = {}) {
            const result = await this.deleteMany(filter, opts);
            if (name === 'nodes' && result.deletedCount === 1 && opts.session) {
                opts.session.deletedNodeIds.add(String(filter._id));
                f.onStagedNodeDelete?.(filter, opts);
            }
            return result;
        },
        async deleteMany(filter, opts = {}) {
            const rows = table(name, opts.session), kept = rows.filter(row => !selectRow(name, row, filter));
            if (name === 'nodes' && opts.session && rows.length !== kept.length) {
                const removed = rows.filter(row => !kept.includes(row));
                if (removed.some(row => !sameBson(row, data.nodes.find(other => other._id === row._id)))) throw fault(112);
            }
            const deletedCount = rows.length - kept.length;
            rows.splice(0, rows.length, ...kept);
            mark('delete', name);
            return { acknowledged: true, deletedCount };
        },
    });
    const client = { db: () => ({ async command(cmd, { session }) {
        assert.equal(cmd.commitTransaction, 1); mark('commit');
        if (f.commitError) throw f.commitError;
        for (const [name, staged] of Object.entries(session.staged)) {
            const base = new Map(session.base[name].map(row => [row._id, row]));
            for (const row of staged) {
                if (!sameBson(row, base.get(row._id))) {
                    const i = data[name].findIndex(other => other._id === row._id);
                    if (i < 0) data[name].push(row);
                    else data[name][i] = row;
                }
                base.delete(row._id);
            }
            data[name] = data[name].filter(row => !base.has(row._id));
        }
        return { ok: 1 };
    } }) };
    const db = { collection, getClient: () => client, async startSession() {
        function settle() { activeSession.active = false; activeSession.finished.resolve(); activeSession = undefined; }
        return { client, transaction: { transition: settle }, inTransaction() { return this.active; },
            startTransaction() { mark('begin'); assert.equal(activeSession, undefined);
                this.active = true; this.finished = Promise.withResolvers(); this.deletedNodeIds = new Set(); activeSession = this; },
            async abortTransaction() { mark('abort'); settle(); },
            async endSession() { assert.equal(this.active, false); },
        };
    }, models: {} };
    const model = name => {
        const col = collection(name);
        const find = filter => query(session => table(name, session).filter(row => matches(row, filter)), name);
        const findOne = filter => query(session => table(name, session).find(row => matches(row, filter)) ?? null, name);
        return { db, collection: col, find, findOne, findById: _id => findOne({ _id }), updateMany: col.updateMany,
            deleteMany: col.deleteMany, countDocuments: filter => ({ read() { return this; }, readConcern() { return this; },
                maxTimeMS: async () => { if (f.countDbError) throw f.countDbError; return data[name].filter(row => matches(row, filter)).length; } }),
        };
    };
    db.models.HyUser = model('users');
    const locks = makeLocks({
        async insertOne(row) { if (f.lock) throw fault(11000); f.lock = row; mark('lock'); },
        async findOne({ token }) { return f.lock?.token === token ? f.lock : null; },
        async deleteMany({ token }) { assert.equal(f.lock?.token, token); f.lock = undefined; return { acknowledged: true, deletedCount: 1 }; },
    });
    const sshReach = node => { assert.equal(String(node._id), id); mark('ssh', id); if (f.sshError) throw f.sshError; };
    if (!realSshAdmission) {
        t.mock.method(NodeSSH.prototype, 'connectDirectOnce', async function () { sshReach(this.node); });
        t.mock.method(NodeSSH, 'probeDirectKex', async (host, port) => {
            const target = nodes.find(node => node._id === id);
            assert.equal(host, target.ip); assert.equal(port, target.ssh.port);
            sshReach(target);
        });
    }
    t.mock.method(NodeSSH.prototype, 'disconnect', function () { mark('ssh-close', String(this.node._id)); });
    const staged = new Map();
    t.mock.method(NodeSSH.prototype, 'exec', async function (frame, options) {
        assert.equal(String(this.node._id), id);
        const { command, accepts } = rebuildApplyMachineGuard(frame);
        if (accepts) assert.ok(accepts(machineId));
        if (command === '/usr/bin/head -c 34 /etc/machine-id') { mark('machine', id); return ok(`${f.observedMachine ?? machineId}\n`); }
        if (command === '/usr/local/bin/xray version') return ok('Xray 26.3.27\n');
        if (command.startsWith('if test -f ')) {
            const profile = command.includes(BRIDGE) ? 'bridge' : 'main'; mark('read', id, profile);
            return ok(JSON.stringify(f.profiles.get(`${id}:${profile}`)));
        }
        if (options?.stdin?.startsWith('{"action":"check-apply-network"')) {
            mark('activation', id);
            return f.activationFrame ?? ok(`${JSON.stringify({ ok: true, backupId, proof: census })}\n`);
        }
        if (command.startsWith('systemctl show -p LoadState')) return ok('loaded');
        const profile = command.includes(BRIDGE) || command.includes('xray-bridge') ? 'bridge' : 'main';
        if (command.startsWith('systemctl show -p ExecStart')) return ok(`path=/usr/local/bin/xray ; -config ${profile === 'main' ? MAIN : BRIDGE} ;`);
        if (command.includes('cat > ')) { mark('stage', id); staged.set(profile, JSON.parse(options.stdin)); return ok(); }
        if (command.includes('mv -fT ')) { mark('put', id); f.profiles.set(`${id}:${profile}`, staged.get(profile)); return ok(); }
        if (/^(?:systemctl (?:stop|enable|disable)|rm -f -- )/.test(command)) return ok();
        assert.fail('unexpected SSH command in fixture');
    });
    const defaults = { env, locks, grantDb: db, Link: model('links'), Node: model('nodes'), State: model('states'), L2tpUser: model('accounts'),
        sync: { async _getUsersForNode() { return []; }, async readRebuildReverseObservation(node, path, timeout) {
            assert.equal(String(node._id), id); assert.equal(path, '/info'); assert.equal(timeout, 5000); mark('agent');
            if (f.agentProbe) return f.agentProbe(node, path, timeout);
            if (f.agentError) throw f.agentError;
            return { status: 200, data: '{"agent_version":"fixture"}' };
        } }, cache: { async invalidateAllSubscriptions() { mark('cache'); if (f.cacheError) throw f.cacheError; } },
        createRelayDirect({ verifyRemoveStdin }) {
            assert.equal(verifyRemoveStdin, true);
            return {
                async readSessionCount() { mark('census'); return f.census; },
                async prepareRemove() { mark('remove-plan'); f.duringRemovePlan?.(); return {}; },
                async remove(_plan, verify) {
                    await verify(); mark('remove'); if (f.removeError) throw f.removeError;
                    f.profiles.set(`${id}:main`, structuredClone(withoutL2tp)); f.afterHostRemove?.(); return true;
                },
                async close() { if (f.closeRemoveError && steps(f).includes('remove')) throw f.closeRemoveError; },
            };
        },
        connect(node) {
            mark('graph-connect', node._id);
            const put = p => f.profiles.set(`${node._id}:${p.profile}`, structuredClone(p.config));
            return { async requireSupportedCore() {}, async checkActivation() {
                mark('activation', node._id); if (node._id === exit && f.neighborError) throw f.neighborError;
                f.onActivation?.(node);
            }, async read(profile) { mark('read', node._id, profile); return structuredClone(f.profiles.get(`${node._id}:${profile}`)); },
            async stagePair() { mark('stage', node._id); f.onStage?.(node); },
            async putPair(pair) { mark('put', node._id); pair.forEach(put); }, async close() {} };
        },
    };
    f.nodeCollection = defaults.Node.collection;
    f.factory = () => { f.factories++; return createRebuildService(defaults); };
    f.first = f.factory();
    f.controllerWithRemove = removal => createRebuildRelayRetire({ ...defaults, removal, locks: f.first.locks,
        gate() {}, retireGraph: f.first.retireGraph, sameProtectedTarget: () => assert.fail('must not reach graph settlement'),
        async verifyLinks(nodeId, expected) { assert.ok(expected.startsWith(fingerprintLinks(retirementScope(data.links, nodeId).links))); },
        async guard(verify, retain, fence, fn) { assert.equal(typeof retain, 'function'); await verify(); await fence(); return fn(); },
    });
    f.preview = () => f.first.previewRetireRelay(id);
    f.confirm = (estimate, decision = 'delete') => f.factory().confirmRetireRelay(id, estimate, decision);
    return f;
}

function request(app, action, session, headers, input) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { chunks.push(chunk.toString()); done(); } });
        socket.remoteAddress = '192.0.2.10';
        const req = new IncomingMessage(socket), body = JSON.stringify(input);
        Object.assign(req, { method: 'POST', url: `/panel/rebuild/relays/${id}/retire/${action}`, session,
            sessionID: 'fixture-session', complete: true, headers: { host: 'fixture.invalid', ...headers, 'content-length': String(Buffer.byteLength(body)) } });
        req.push(body); req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            const wire = chunks.join('').split('\r\n\r\n').at(-1);
            socket.destroy();
            try { assert.doesNotMatch(wire, /fixture-private-value|survivorPreview|previewId/); resolve([res.statusCode, JSON.parse(wire)]); }
            catch (error) { reject(error); }
        });
        app(req, res);
    });
}

function http(t, f) {
    const express = require('express'), app = express();
    t.mock.method(require('../rebuildService'), 'createRebuildService', f.factory);
    const config = require('../../../config'), old = config.PANEL_IP_WHITELIST;
    config.PANEL_IP_WHITELIST = '192.0.2.10';
    const oldMode = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = 'true';
    t.after(() => { config.PANEL_IP_WHITELIST = old; if (oldMode === undefined) delete process.env.C3_REBUILD_ENABLED;
        else process.env.C3_REBUILD_ENABLED = oldMode; });
    const Settings = require('../../models/settingsModel');
    const settings = { deployment: { completed: true } };
    t.mock.method(Settings, 'get', async () => settings);
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: async () => settings }) }));
    app.use(require('../../routes/panel/rebuildL2tp').rebuildL2tpIngress);
    app.use(express.json());
    app.use('/panel', require('../../routes/panel').createPanelRouter({ l2tpRateLimiter: (_req, _res, next) => next() }));
    const session = { authenticated: true, adminUsername: 'fixture-admin' };
    const headers = { 'content-type': 'application/json', 'x-csrf-token': require('../../routes/panel/csrf').issuePanelCsrfToken({ session }) };
    return (action, body = {}) => request(app, action, session, headers, body);
}

test('mounted route joins the originating store and Remove proof across factories; survivors preflight before Remove', async t => {
    const f = fixture(t), send = http(t, f);
    const [status, { preview }] = await send('preview');
    assert.equal(status, 200);
    assert.deepEqual(preview, { nodeId: id, mode: 'online', allowed: true, accountCount: 1, activeClients: 0, unavailableSince: null, ticket: preview.ticket });
    noEffects(f);
    f.trace.length = 0;
    assert.deepEqual(await send('confirm', { ticket: preview.ticket, decision: 'delete' }), [200, { nodeId: id, status: 'deleted' }]);
    assert.equal(f.factories, 3); // one service for each request, plus the unused fixture instance
    const reserve = steps(f).indexOf('reserve'), remove = steps(f).indexOf('remove'), stage = steps(f).indexOf('stage');
    assert.ok(reserve >= 0 && reserve < remove && remove < stage);
    assert.deepEqual(f.trace.slice(0, reserve).filter(([step]) => step === 'activation').map(row => row[1]).sort(), [id, portal, exit]);
    assert.equal(steps(f).filter(step => step === 'lock').length, 1);
    assert.deepEqual(f.data.nodes.map(n => n._id), [portal, exit]);
    assert.deepEqual(f.data.states, []);
    assert.deepEqual(f.data.links, []);
    assert.deepEqual(f.data.users[0].nodes, [portal, exit]);
    assert.deepEqual(f.data[RETIRED], [{ _id: id }]);
    assert.equal(f.data[DIRECTORY][0].accounts[0].id, 'e'.repeat(24));
    assert.equal((await send('confirm', { ticket: preview.ticket, decision: 'delete' }))[0], 409);
    assert.equal(steps(f).filter(step => step === 'remove').length, 1);
});

for (const full of [true, false]) test(`joined online retirement tolerates periodic telemetry ${full ? 'from preview through settlement' : 'at settlement alone'}`, async t => {
    const f = fixture(t);
    const target = { _id: new ObjectId(id) }, survivor = { _id: new ObjectId(portal) };
    const samples = [], projections = [];
    let phase = 'preview', cas;
    t.mock.timers.enable({ apis: ['setInterval'] });
    const timer = setInterval(() => {
        const n = samples.length + 1, now = new Date(2000 + n);
        const sample = { phase, n, now };
        const $set = { agentLastSeen: now, updatedAt: now, lastSync: now, agentStatus: 'online',
            traffic: { tx: n, rx: n * 2, lastUpdate: now }, status: n % 2 ? 'online' : 'offline',
            healthFailures: n % 2, onlineUsers: n % 2 ? n : 0 };
        sample.target = f.nodeCollection.updateOne(target, { $set });
        if (phase === 'finalizer') sample.survivor = f.nodeCollection.updateOne(survivor, { $set });
        samples.push(sample);
    }, 10);
    t.after(() => clearInterval(timer));
    const tick = name => {
        phase = name;
        const count = samples.length;
        t.mock.timers.tick(10);
        assert.equal(samples.length, count + 1, `${name}: one scheduled writer tick`);
        return samples.at(-1);
    };
    f.onRawNodeRead = (row, options) => {
        if (options.projection) projections.push({ row, session: options.session });
    };
    if (full) {
        f.agentProbe = async () => {
            const sample = tick(phase === 'preview' ? 'preview' : 'confirm');
            assert.equal((await sample.target).matchedCount, 1);
            assert.deepEqual(f.data.nodes[1].agentLastSeen, sample.now);
            return { status: 200, data: '{"agent_version":"fixture"}' };
        };
        f.duringRemovePlan = () => tick('remove preparation');
        f.afterRemove = () => tick('remove publication');
    }
    f.beforeTransactionSnapshot = () => {
        if (!steps(f).includes('stage')) return;
        const sample = tick('settlement admission');
        assert.deepEqual(f.data.nodes[1].agentLastSeen, sample.now);
    };
    f.onStagedNodeDelete = (filter, opts) => {
        cas = { filter, opts, preimage: nativeNode(f.data.nodes[1]) };
        const sample = tick('finalizer');
        // The independent writer still sees the target. Its update must wait
        // for the staged delete and then find no row; other rows can advance.
        assert.equal(f.data.nodes[1].traffic.tx, sample.n - 1);
        assert.equal(f.data.nodes[0].traffic.tx, sample.n);
    };
    const estimate = await f.preview();
    assert.deepEqual(estimate, { nodeId: id, mode: 'online', allowed: true, accountCount: 1, activeClients: 0, unavailableSince: null });
    noEffects(f);
    if (full) assert.equal((await tick('between requests').target).matchedCount, 1);
    assert.deepEqual(await f.confirm(estimate), { nodeId: id, status: 'deleted' });
    assert.deepEqual(samples.map(sample => sample.phase), [
        ...(full ? ['preview', 'between requests', 'confirm', 'remove preparation', 'remove publication'] : []),
        'settlement admission', 'finalizer',
    ]);
    assert.deepEqual(await Promise.all(samples.map(async ({ target }) => (await target).matchedCount)),
        [...Array(samples.length - 1).fill(1), 0]);
    assert.equal((await samples.at(-1).survivor).matchedCount, 1);
    assert.equal(f.data.nodes[0].traffic.tx, samples.at(-1).n, 'commit must not overwrite independent telemetry');
    assert.equal(await f.nodeCollection.findOne(target), null);
    assert.deepEqual(f.data.nodes.map(node => node._id), [portal, exit]);
    assert.deepEqual(f.data.states, []);
    assert.deepEqual(f.data.accounts, []);
    assert.deepEqual(f.data.links, []);
    assert.deepEqual(f.data[RETIRED], [{ _id: id }]);
    assert.equal(steps(f).filter(step => step === 'remove').length, 1);
    assert.equal(f.lock, undefined);

    const reads = projections.filter(read => read.session === cas.opts.session);
    assert.ok(reads.length > 0, 'settlement must read the projected card in its own transaction');
    assert.deepEqual(cas.opts.collation, { locale: 'simple' });
    const projected = reads.at(-1).row;
    assert.ok(projected._id.equals(target._id));
    assert.deepEqual(projected.image.value.xray.value.agentToken, { type: 'string', value: 'fixture-private-value' });
    for (const key of ['agentLastSeen', 'updatedAt', 'traffic', 'status']) assert.ok(!Object.hasOwn(projected.image.value, key));
    assert.ok(sameBson(projected.image, cas.filter.$expr.$eq[1].$literal));
    assert.ok(!matches({ ...cas.preimage, ip: '192.0.2.99' }, cas.filter), 'the real CAS rejects endpoint drift');
});

test('both network refusals permit abandon; only survivors are observed by the graph', async t => {
    const f = fixture(t);
    f.data.nodes[1].active = false;
    f.agentError = fault('ECONNREFUSED'); f.sshError = fault('EHOSTUNREACH');
    const started = Date.now();
    const estimate = await f.preview();
    const observed = Date.parse(estimate.unavailableSince);
    assert.ok(observed >= started && observed <= Date.now());
    assert.deepEqual(estimate, { nodeId: id, mode: 'abandon', activeClients: null, accountCount: 1, allowed: true,
        unavailableSince: new Date(observed).toISOString() });
    f.trace.length = 0;
    assert.deepEqual(await f.confirm(estimate, 'abandon'), { nodeId: id, status: 'deleted' });
    noTarget(f);
    assert.deepEqual(f.trace.filter(([step]) => step === 'put').map(([, node]) => node).sort(), [portal, exit]);
});

test('abandon remains panel-only even if the target would respond again at confirmation', async t => {
    const f = fixture(t), send = http(t, f);
    f.agentError = fault('ECONNREFUSED'); f.sshError = fault('EHOSTUNREACH');
    const [, { preview }] = await send('preview');
    assert.equal(preview.mode, 'abandon');
    f.agentError = f.sshError = undefined;
    f.trace.length = 0;
    assert.deepEqual(await send('confirm', { ticket: preview.ticket, decision: 'abandon' }), [200, { nodeId: id, status: 'deleted' }]);
    noTarget(f);
});

test('abandon with changed local evidence refuses without probing, even via the route stale handler', async t => {
    const f = fixture(t), send = http(t, f);
    f.agentError = fault('ECONNREFUSED'); f.sshError = fault('EHOSTUNREACH');
    const [, { preview }] = await send('preview');
    assert.equal(preview.mode, 'abandon');
    f.data.nodes[1].ssh.password = 'changed-fixture-password';
    f.trace.length = 0;
    assert.deepEqual(await send('confirm', { ticket: preview.ticket, decision: 'abandon' }), [409, { error: { code: 'PREVIEW_CHANGED' } }]);
    noTarget(f); noEffects(f);
});

for (const [leg, code] of [['agentError', 'ECONNREFUSED'], ['sshError', 'EHOSTUNREACH']]) {
    test(`${leg} alone qualifies for abandonment with an unknown census`, async t => {
        const f = fixture(t, { installed: false });
        f[leg] = fault(code);
        const estimate = await f.preview();
        assert.equal(estimate.mode, 'abandon'); assert.equal(estimate.activeClients, null); assert.equal(estimate.accountCount, 0);
        assert.equal(estimate.allowed, true);
        assert.ok(!steps(f).includes('census'));
    });
}

for (const [reply, credential, agentDown, expected] of [
    ['kex', 'password', true, 'abandon'],
    ['kex', 'privateKey', false, 'online'],
    ['network', 'privateKey', false, 'abandon'],
    ['auth', 'password', true, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['handshake', 'privateKey', true, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
]) test(`unbound SSH observation is credential-free: ${reply}, agent ${agentDown ? 'down' : 'up'}`, async t => {
    const f = fixture(t, { installed: false, realSshAdmission: true });
    const sentinel = 'synthetic-ssh-credential-sentinel';
    f.data.nodes[1].ssh = { port: 2222, username: 'fixture_account', [credential]: sentinel };
    if (agentDown) f.agentError = fault('ECONNREFUSED');
    const crypto = require('../cryptoService');
    let decrypts = 0, destroys = 0, authRequests = 0, config, accepted;
    const decrypt = () => { decrypts++; return sentinel; };
    t.mock.method(crypto, 'decryptSafe', decrypt);
    t.mock.method(crypto, 'decryptPrivateKey', decrypt);
    t.mock.method(require('ssh2').Client.prototype, 'connect', function (options) {
        config = options;
        this._sock = { destroy() { destroys++; } };
        if (reply === 'kex') {
            accepted = config.hostVerifier?.(Buffer.from('fixture host key'));
            if (accepted !== false && config.authHandler?.() !== false) authRequests++;
            // ssh2 reports its intentional verification rejection as an error.
            this.emit('error', fault(undefined, { level: 'handshake' }));
        } else {
            this.emit('error', reply === 'network' ? fault('ECONNREFUSED', { level: 'client-socket' })
                : fault('ETIMEDOUT', { level: reply === 'auth' ? 'client-authentication' : 'handshake' }));
        }
    });
    const result = await f.preview().catch(error => error);
    assert.equal(decrypts, 0, 'unbound availability must not decrypt card credentials');
    assert.equal(authRequests, 0);
    assert.equal(destroys, 1);
    assert.equal(config.host, '192.0.2.2'); assert.equal(config.port, 2222);
    assert.ok(config.username !== 'fixture_account');
    assert.ok(['password', 'privateKey', 'passphrase', 'agent'].every(key => !Object.hasOwn(config, key)));
    if (reply === 'kex') assert.equal(accepted, false, 'an observed key must never be accepted');
    assert.equal(result.mode ?? result.code, expected);
    if (result.mode) {
        assert.equal(result.allowed, true);
        assert.equal(result.activeClients, result.mode === 'online' ? 0 : null);
    }
    assert.ok(!steps(f).some(step => ['machine', 'census'].includes(step)));
    assert.ok(!(result instanceof Error ? result.message : JSON.stringify(result)).includes(sentinel));
    noEffects(f);
});

for (const queueOnly of [false, true]) test(`unbound SSH ${queueOnly ? 'queue' : 'KEX'} deadline is bounded`, async t => {
    const f = fixture(t, { installed: false, realSshAdmission: true });
    const controller = new AbortController();
    t.mock.method(AbortSignal, 'timeout', ms => {
        assert.equal(ms, require('../rebuildSshLimits').CONNECT_TIMEOUT_MS);
        return controller.signal;
    });
    const oldActive = NodeSSH._activeDirect;
    if (queueOnly) NodeSSH._activeDirect = Number.MAX_SAFE_INTEGER;
    t.after(() => { NodeSSH._activeDirect = oldActive; });
    let verifyKey, destroys = 0;
    t.mock.method(require('ssh2').Client.prototype, 'connect', function (config) {
        verifyKey = config.hostVerifier;
        this._sock = { destroy: () => { destroys++; this.emit('error', fault('ECONNRESET')); } };
    });
    const pending = f.preview();
    const checked = queueOnly ? assert.rejects(pending, { code: 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE' }) : pending;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(typeof verifyKey === 'function', !queueOnly);
    assert.equal(NodeSSH._waitQueue.length, queueOnly ? 1 : 0);
    controller.abort();
    const estimate = await checked;
    if (!queueOnly) {
        assert.equal(estimate.mode, 'abandon');
        assert.equal(verifyKey(Buffer.from('late key')), false);
        assert.equal(NodeSSH._activeDirect, oldActive);
    }
    assert.equal(destroys, queueOnly ? 0 : 1);
    assert.equal(NodeSSH._waitQueue.length, 0);
    noEffects(f);
});

test('real agent GET adapter timeout qualifies without using health flags', async t => {
    const f = fixture(t);
    const sync = require('../syncService');
    let calls = 0, error;
    t.mock.method(require('node:https'), 'request', options => {
        calls++;
        assert.equal(options.method, 'GET'); assert.equal(options.path, '/info');
        const req = new EventEmitter();
        req.destroy = () => {};
        req.end = () => {};
        req.setTimeout = (ms, callback) => { assert.equal(ms, 5000); queueMicrotask(callback); };
        return req;
    });
    f.agentProbe = async (...args) => {
        try { return await sync.readRebuildReverseObservation(...args); }
        catch (cause) { error = cause; throw cause; }
    };
    const estimate = await f.preview();
    assert.equal(calls, 1);
    assert.equal(error.code, 'ECONNABORTED'); assert.equal(error.isAxiosError, true);
    assert.equal(estimate.mode, 'abandon'); assert.equal(estimate.activeClients, null);
});

test('the agent GET absolute deadline classifies Axios cancellation from its own signal', async t => {
    const f = fixture(t);
    const controller = new AbortController();
    t.mock.method(AbortSignal, 'timeout', ms => {
        assert.equal(ms, 5000);
        return controller.signal;
    });
    t.mock.method(require('node:https'), 'request', () => {
        const req = new EventEmitter();
        req.destroy = () => {};
        req.setTimeout = () => {};
        req.end = () => queueMicrotask(() => controller.abort()); // Fire the product-owned deadline at the request seam.
        return req;
    });
    const sync = require('../syncService');
    f.agentProbe = (...args) => sync.readRebuildReverseObservation(...args);
    const estimate = await f.preview();
    assert.equal(estimate.mode, 'abandon'); assert.equal(estimate.activeClients, null);
});

for (const queueOnly of [false, true]) test(`real SSH one-shot ${queueOnly ? 'queue' : 'admission'} deadline is typed`, async t => {
    const f = fixture(t, { realSshAdmission: true });
    let attempts = 0, destroys = 0, observed;
    const oldActive = NodeSSH._activeDirect;
    if (queueOnly) NodeSSH._activeDirect = Number.MAX_SAFE_INTEGER;
    t.after(() => { NodeSSH._activeDirect = oldActive; });
    t.mock.method(require('ssh2').Client.prototype, 'connect', function () {
        attempts++;
        this._sock = { destroy() { destroys++; } };
    });
    const connect = NodeSSH.prototype.connectDirectOnce;
    t.mock.method(NodeSSH.prototype, 'connectDirectOnce', async function (ms) {
        try { return await connect.call(this, ms); }
        catch (error) { observed = error; throw error; }
    });
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const deadline = require('../rebuildSshLimits').CONNECT_TIMEOUT_MS;
    const pending = f.preview();
    const checked = queueOnly ? assert.rejects(pending, { code: 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE' }) : pending;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(attempts, queueOnly ? 0 : 1);
    assert.equal(NodeSSH._waitQueue.length, queueOnly ? 1 : 0);
    t.mock.timers.tick(deadline);
    const estimate = await checked;
    assert.equal(observed.code, queueOnly ? 'SSH_ADMISSION_QUEUE_TIMEOUT' : 'SSH_ADMISSION_TIMEOUT');
    if (!queueOnly) { assert.equal(estimate.mode, 'abandon'); assert.equal(estimate.activeClients, null); }
    assert.equal(destroys, queueOnly ? 0 : 1);
    assert.equal(NodeSSH._waitQueue.length, 0);
});

test('outage time uses bounded observations across factories, not lastSync or status flags', async t => {
    const f = fixture(t);
    const first = Date.parse('2026-01-02T03:04:05.000Z');
    let elapsed = 0;
    t.mock.method(Date, 'now', () => first + elapsed);
    t.mock.method(performance, 'now', () => elapsed);
    Object.assign(f.data.nodes[1], { lastSync: new Date(1), agentLastSeen: new Date(2), agentStatus: 'offline', status: 'offline' });
    const preview = () => f.factory().previewRetireRelay(id);
    assert.equal((await preview()).mode, 'online');
    f.agentError = fault('ECONNREFUSED');
    assert.equal((await preview()).unavailableSince, new Date(first).toISOString());
    elapsed = 1000;
    assert.equal((await preview()).unavailableSince, new Date(first).toISOString());
    f.agentError = undefined; f.sshError = fault('ETIMEDOUT');
    assert.equal((await preview()).unavailableSince, new Date(first + elapsed).toISOString());
    elapsed = 2000;
    f.sshError = undefined;
    assert.equal((await preview()).unavailableSince, null);
    f.agentError = fault('ECONNREFUSED');
    assert.equal((await preview()).unavailableSince, new Date(first + elapsed).toISOString());
    elapsed += 24 * 60 * 60 * 1000;
    assert.equal((await preview()).unavailableSince, new Date(first + elapsed).toISOString());
});

for (const [name, setup, expected] of [
    ['auth refusal is not network down', f => { f.agentError = fault('AGENT_HTTP_ERROR', { httpStatus: 401 }); f.sshError = fault('ECONNREFUSED'); }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['HTTP response wins over agent transport code', f => { f.agentError = fault('ETIMEDOUT', { response: { status: 403 } }); }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['agent cancellation without deadline proof', f => { f.agentError = fault('ERR_CANCELED', { isAxiosError: true }); }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['agent TLS refusal is not network down', f => { f.agentError = fault('ERR_TLS_CERT_ALTNAME_INVALID'); }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['SSH auth error text is not network down', f => { f.agentError = fault('ECONNREFUSED'); f.sshError = fault(undefined); }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['SSH auth subtype wins over a transport code', f => { f.agentError = fault('ECONNREFUSED'); f.sshError = fault('ETIMEDOUT', { level: 'client-authentication' }); }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['SSH queue deadline is not network down', f => { f.agentError = fault('ECONNREFUSED'); f.sshError = fault('SSH_ADMISSION_QUEUE_TIMEOUT'); }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['pin mismatch', f => { f.agentError = fault('ECONNREFUSED'); f.sshError = fault('SSH_HOST_KEY_MISMATCH'); }, 'REBUILD_L2TP_IDENTITY_CHANGED'],
    ['machine mismatch', f => { f.agentError = fault('ECONNREFUSED'); f.observedMachine = '0'.repeat(32); }, 'REBUILD_L2TP_IDENTITY_CHANGED'],
    ['active=false is not network down', f => { f.data.nodes[1].active = false; }, 'REBUILD_NODE_UNSUPPORTED'],
    ['invalid endpoint', f => { f.data.nodes[1].xray.agentPort = -1; }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['non-string SSH username', f => { f.data.nodes[1].ssh.username = ['root']; }, 'REBUILD_RETIRE_PREVIEW_UNAVAILABLE'],
    ['DB code is not transport evidence', f => { f.dbError = fault('ECONNREFUSED'); }, 'REBUILD_NODE_RETIRE_UNAVAILABLE'],
]) test(`fails closed: ${name}`, async t => {
    const f = fixture(t); setup(f);
    await assert.rejects(f.preview(), { code: expected }); noEffects(f);
});

test('no-install refuses unexpected owned ingress in BRIDGE as well as MAIN', async t => {
    const f = fixture(t, { installed: false });
    for (const [profile, tag] of [['main', `relay-l2tp-${id}`], ['bridge', 'rebuild-relay-ingress']]) {
        const inbounds = f.profiles.get(`${id}:${profile}`).inbounds;
        inbounds.push({ tag, protocol: 'socks' });
        await assert.rejects(f.preview(), { code: 'REBUILD_L2TP_BASELINE_MISMATCH' });
        inbounds.pop();
    }
    noEffects(f);
});

test('reachable unjoined PPP/IPsec counts and DB-count failures never authorize force', async t => {
    const f = fixture(t);
    for (const value of [null, { activeSessions: 3, activeIpsec: 0, census }, { activeSessions: 2, activeIpsec: 2, census }]) {
        f.census = value;
        const preview = await f.preview();
        assert.equal(preview.mode, 'online'); assert.equal(preview.activeClients, null); assert.equal(preview.allowed, false);
        await assert.rejects(f.confirm(preview, 'force'), { code: 'REBUILD_RETIRE_CONFIRMATION_REQUIRED' });
    }
    f.census = { activeSessions: 0, activeIpsec: 0, census };
    f.countDbError = fault('ECONNREFUSED');
    assert.equal((await f.preview()).allowed, false);
    noEffects(f);
});

test('preview copies, a verifier from another service, and the wrong retain function are not authority', async t => {
    const f = fixture(t), preview = await f.preview();
    await assert.rejects(f.confirm({ ...preview }), { code: 'REBUILD_RETIRE_CONFIRMATION_REQUIRED' });
    await f.first.locks.run(async (verify, retain) => {
        await assert.rejects(f.factory().previewRetireL2tp(id, verify, retain), { code: 'REBUILD_LOCK_LOST' });
        await assert.rejects(f.first.previewRetireL2tp(id, verify, () => {}), { code: 'REBUILD_LOCK_LOST' });
        await assert.rejects(f.first.previewRetireL2tp(id, verify), { code: 'REBUILD_LOCK_LOST' });
    });
    noEffects(f);
});

test('a confirmable positive census requires force and delegates the exact private estimate', async t => {
    const f = fixture(t);
    // Isolate the controller decision here; the joined fixture also exercises
    // the real Remove backend and the emitted host helper has its own tests.
    const issued = [];
    const service = f.controllerWithRemove({
        async previewRetireL2tp(nodeId, verify, retain) {
            assert.equal(nodeId, id);
            await verify(); assert.equal(typeof retain, 'function');
            const proof = Object.freeze({ nodeId, confirmable: true, accountCount: 1, activeClients: 2 });
            issued.push(proof);
            return proof;
        },
        async confirmRetireL2tp(nodeId, estimate, verify, retain) {
            assert.equal(nodeId, id); assert.equal(estimate, issued[1]);
            await verify(); assert.equal(typeof retain, 'function');
            f.trace.push(['force-dispatch']);
            throw fault('REBUILD_L2TP_REMOVE_REFUSED');
        },
    });
    const first = await service.previewRetireRelay(id);
    assert.equal(first.allowed, true); assert.equal(first.activeClients, 2);
    await assert.rejects(f.confirm(first), { code: 'REBUILD_RETIRE_DECISION_REQUIRED' });
    await assert.rejects(f.confirm(first, 'force'), { code: 'REBUILD_RETIRE_CONFIRMATION_REQUIRED' });
    const next = await service.previewRetireRelay(id);
    await assert.rejects(f.confirm(next, 'force'), { code: 'REBUILD_L2TP_REMOVE_REFUSED' });
    assert.equal(steps(f).filter(step => step === 'force-dispatch').length, 1);
    noEffects(f);
});

for (const [name, setup, code] of [
    ['neighbor fails preflight', f => { f.neighborError = fault('ECONNREFUSED'); }, 'REBUILD_NEIGHBOR_UNAVAILABLE'],
    ['incident links differ', f => { f.data.links[0].unknownField = 1; }, 'PREVIEW_CHANGED'],
    ['node SSH credentials differ', f => { f.data.nodes[1].ssh.password = 'changed-fixture-password'; }, 'PREVIEW_CHANGED'],
    ['network classification changes', f => { f.agentError = fault('ECONNREFUSED'); f.sshError = fault('ENETUNREACH'); }, 'PREVIEW_CHANGED'],
    ['same count, changed generation', f => { f.census.census = '4'.repeat(64); }, 'PREVIEW_CHANGED'],
    ['graph drift inside Remove preparation', f => { f.duringRemovePlan = () => { f.data.links[0].unknownField = 1; }; }, 'PREVIEW_CHANGED'],
    ['card drift inside Remove preparation', f => { f.duringRemovePlan = () => { f.data.nodes[1].ssh.password = 'changed-fixture-password'; }; }, 'PREVIEW_CHANGED'],
]) test(`${name}: no host or DB effects`, async t => {
    const f = fixture(t), estimate = await f.preview();
    setup(f);
    await assert.rejects(f.confirm(estimate), { code });
    noEffects(f); assert.equal(f.lock, undefined);
});

for (const [field, change] of [
    ['ip', node => { node.ip = '192.0.2.99'; }],
    ['cascadeRole', node => { node.cascadeRole = 'bridge'; }],
    ['xray.agentToken', node => { node.xray.agentToken = 'rotated-fixture-token'; }],
]) test(`joined online confirmation refuses stale ${field} before effects`, async t => {
    const f = fixture(t), estimate = await f.preview();
    assert.equal(estimate.mode, 'online');
    assert.equal(estimate.allowed, true);
    change(f.data.nodes[1]);
    const before = BSON.serialize(f.data);
    f.trace.length = 0;
    await assert.rejects(f.confirm(estimate), { code: 'PREVIEW_CHANGED' });
    noTarget(f);
    noEffects(f);
    assert.equal(f.lock, undefined);
    assert.deepEqual(BSON.serialize(f.data), before);
});

for (const [name, setup, reset, expected, step] of [
    ['machine identity', f => { f.observedMachine = '0'.repeat(32); }, f => { f.observedMachine = machineId; },
        { code: 'REBUILD_L2TP_IDENTITY_CHANGED' }, 'machine'],
    ['runtime attestation', f => { f.activationFrame = { code: 70, stdout: '', stderr: 'DIRECT_RUNTIME_FOREIGN_CHANGE\n' }; },
        f => { delete f.activationFrame; }, { code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED', reason: 'RUNTIME_FOREIGN_CHANGE' }, 'activation'],
]) test(`online confirmation does not replay a ${name} refusal`, async t => {
    const f = fixture(t), estimate = await f.preview();
    assert.equal(estimate.mode, 'online');
    assert.equal(estimate.allowed, true);
    f.trace.length = 0;
    setup(f);
    await assert.rejects(f.confirm(estimate), expected);
    assert.equal(f.trace.filter(([name, node]) => name === step && node === id).length, 1);
    noEffects(f);
    assert.equal(f.lock, undefined);
    reset(f);
    const trace = f.trace.slice();
    await assert.rejects(f.confirm(estimate), { code: 'REBUILD_RETIRE_CONFIRMATION_REQUIRED' });
    assert.deepEqual(f.trace, trace);
    assert.equal(f.data.nodes[1]._id, id);
});

for (const [name, setup, outcome] of [
    ['Remove lost reply', f => { f.removeError = fault('ECONNRESET'); }, 'unknown'],
    ['Remove committed, cleanup lost', f => { f.closeRemoveError = fault('ECONNRESET'); }, 'partial'],
    ['unexpected post-Remove state delta', f => { f.afterRemove = () => { f.data.states[0].futureField.x++; }; }, 'partial'],
    ['post-Remove survivor profile drift', f => { f.afterHostRemove = () => { f.profiles.get(`${exit}:main`).log = { loglevel: 'warning' }; }; }, 'partial'],
    ['post-Remove protected target drift', f => { f.afterHostRemove = () => { f.profiles.get(`${id}:main`).inbounds.push({ protocol: 'vless', tag: 'foreign-client' }); }; }, 'partial'],
    ['post-Remove protected BRIDGE drift', f => { f.afterHostRemove = () => { f.profiles.get(`${id}:bridge`).inbounds.push({ protocol: 'vless', tag: 'foreign-client' }); }; }, 'partial'],
    ['graph commit lost', f => { f.commitError = fault('ECONNRESET'); }, 'unknown'],
    ['graph committed, cache cleanup lost', f => { f.cacheError = fault('ECONNRESET'); }, 'deleted'],
]) test(`${name}: never expose a fresh confirmation or replay`, async t => {
    const f = fixture(t), estimate = await f.preview();
    setup(f);
    await assert.rejects(f.confirm(estimate), { outcome, retryAllowed: false,
        ...((outcome !== 'unknown' || f.commitError) && { l2tpRemoved: true }) });
    const trace = f.trace.slice();
    await assert.rejects(f.confirm(estimate), { code: 'REBUILD_RETIRE_CONFIRMATION_REQUIRED' });
    assert.deepEqual(f.trace, trace, 'replay must not even reacquire the lock or observe the target');
    assert.equal(steps(f).filter(step => step === 'remove').length, 1);
    if (outcome === 'partial') assert.ok(!steps(f).includes('stage'));
    if (outcome === 'deleted') assert.equal(f.data.nodes.some(node => node._id === id), false);
    else assert.ok(f.lock);
});

test('late store drift after graph activation checks still blocks the first graph stage', async t => {
    const f = fixture(t, { installed: false }), estimate = await f.preview();
    let checks = 0;
    f.onActivation = node => { if (node._id === exit && ++checks === 2) f.data.nodes[1].ssh.password = 'changed-fixture-password'; };
    await assert.rejects(f.confirm(estimate), { code: 'PREVIEW_CHANGED' });
    assert.equal(checks, 2);
    noEffects(f);
});

test('store drift during graph staging blocks live activation without authorizing retry', async t => {
    const f = fixture(t, { installed: false }), estimate = await f.preview();
    f.onStage = () => { f.data.nodes[1].ssh.password = 'changed-fixture-password'; };
    await assert.rejects(f.confirm(estimate), { outcome: 'unknown', retryAllowed: false });
    assert.ok(steps(f).includes('stage'));
    assert.ok(!steps(f).some(step => ['put', 'begin', 'commit'].includes(step)));
    assert.ok(f.lock);
});

test('after an acknowledged Remove, late graph failure does not re-preview over the route', async t => {
    const f = fixture(t), send = http(t, f);
    const [, { preview }] = await send('preview');
    f.afterHostRemove = () => { f.neighborError = fault('ECONNREFUSED'); };
    assert.deepEqual(await send('confirm', { ticket: preview.ticket, decision: 'delete' }),
        [503, { error: { code: 'REBUILD_RETIRE_OUTCOME_UNCONFIRMED' } }]);
    assert.equal(f.factories, 3);
    assert.ok(f.lock);
    assert.ok(!steps(f).includes('stage'));
});
