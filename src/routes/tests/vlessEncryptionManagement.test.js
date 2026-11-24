'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const ejs = require('ejs');
const path = require('node:path');

const form = path.resolve(__dirname, '../../../views/partials/node-form/xray.ejs');
const render = node => ejs.renderFile(form, { node, t: key => key });

test('stock primary/extra form and add-extra template expose only public key controls', async () => {
    const html = await render({ type: 'xray', cascadeRole: 'portal', xrayVersion: '25.9.5', xrayEncryptionAvailable: true,
        xray: { vlessEncryption: true, vlessEncryptionPublicKey: 'fixture-main-public',
            vlessEncryptionPrivateKey: 'fixture-main-private', extraInbounds: [{ id: 'extra', port: 444,
                vlessEncryption: true, vlessEncryptionPublicKey: 'fixture-extra-public', vlessEncryptionPrivateKey: 'fixture-extra-private' }] } });
    assert.match(html, /name="xray\.vlessEncryptionRegenerate"/);
    assert.equal((html.match(/name="xray_extra_vlessEncryptionRegenerate"/g) || []).length, 2);
    assert.match(html, /fixture-main-public/);
    assert.match(html, /fixture-extra-public/);
    assert.match(html, /<small class="hint">nodes\.xrayVlessEncAuthHelp/);
    assert.equal(/fixture-(?:extra|main)-private/.test(html), false);
    assert.match(await render({ type: 'xray', xrayVersion: '26.1.0' }), /data-available="false" disabled/);
});

// Stock routers, parsers, Mongoose casting/projections, and crypto. Mock only
// external I/O and use an in-memory HTTP stream instead of binding a socket.
const Module = require('node:module');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const express = require('express');
const mongoose = require('mongoose');
const { i18nMiddleware, t: translate } = require('../../middleware/i18n');
const root = path.resolve(__dirname, '../../..');
const noIO = async () => {};
const pushes = [];
const invalidations = [];
const invalidate = async () => { invalidations.push(true); };
let preview;
const modules = {
    'utils/logger': { info() {}, warn() {}, error() {}, debug() {} },
    'services/cacheService': { getGroups: async () => [], invalidateNodes: invalidate, invalidateActiveNodes: invalidate,
        invalidateAllSubscriptions: invalidate, invalidateDashboard: invalidate, invalidateDashboardCounts: invalidate },
    'services/sshPoolService': { close: noIO },
    'services/syncService': { schedulePush: (...args) => pushes.push(args) },
    'services/nodeSetup': { generateAgentToken: () => 'fixture-agent',
        connectSSH: async () => ({ end() {} }), execSSH: async () => ({ success: true, output: preview }) },
    'services/totpService': {}, 'services/statsService': {}, 'services/uaStatsService': {},
    'services/cascadeService': {}, 'services/sniScanner': {},
    'services/backupService': {}, 'services/expireScheduler': {}, 'services/webhookService': {},
};
let Node, panel, api, mcp, mcpRouter;
const originalLoad = Module._load;
Module._load = function(request, parent, isMain) {
    if (request === 'multer') return () => ({});
    const resolved = Module._resolveFilename(request, parent);
    const key = resolved.slice(root.length + '/src/'.length, -'.js'.length);
    return Object.hasOwn(modules, key) ? modules[key] : originalLoad.call(this, request, parent, isMain);
};
try {
    Node = require('../../models/hyNodeModel');
    panel = require('../panel/nodes');
    api = require('../nodes');
    mcp = require('../../mcp/tools/nodes');
    mcpRouter = require('../mcp');
    // MCP resolves Sync lazily, after the loader seam has been restored.
    const syncPath = require.resolve('../../services/syncService');
    const syncStub = new Module(syncPath);
    syncStub.exports = modules['services/syncService'];
    syncStub.loaded = true;
    require.cache[syncPath] = syncStub;
} finally { Module._load = originalLoad; }

const app = express();
app.use(express.json(), express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    req.session = { authenticated: true };
    next();
});
app.use(i18nMiddleware);
app.use('/panel', panel);
app.use('/nodes', api);
app.use('/api/mcp', mcpRouter);
function request(method, url, body, form = false, language) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const stream = new Duplex({ read() {}, write(chunk, _enc, done) { chunks.push(chunk); done(); } });
        const bytes = body ? (form ? new URLSearchParams(body).toString() : JSON.stringify(body)) : '';
        const req = new IncomingMessage(stream);
        Object.assign(req, { method, url, complete: true, headers: { host: 'fixture.invalid',
            'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json',
            'content-length': Buffer.byteLength(bytes) } });
        if (language) req.headers['accept-language'] = language;
        const res = new ServerResponse(req);
        res.assignSocket(stream);
        res.on('error', reject);
        res.on('finish', () => {
            const wire = Buffer.concat(chunks).toString();
            resolve({ status: res.statusCode, location: decodeURIComponent(res.getHeader('location') || ''),
                type: res.getHeader('content-type'), body: wire.slice(wire.indexOf('\r\n\r\n') + 4) });
            stream.destroy();
        });
        if (bytes) req.push(bytes);
        req.push(null);
        app(req, res);
    });
}

const bson = value => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize({ value })).value;
const id = new mongoose.Types.ObjectId('507f1f77bcf86cd799439031');
const get = (obj, key) => key.split('.').reduce((v, name) => v?.[name], obj);
function set(obj, key, value) {
    const parts = key.split('.');
    const last = parts.pop();
    for (const part of parts) obj = obj[part] ??= {};
    obj[last] = bson(value);
}
function matches(row, filter) {
    return Object.entries(filter).every(([key, val]) => {
        const actual = get(row, key);
        if (val?.$exists !== undefined) return (actual !== undefined) === val.$exists;
        if (val?.$ne !== undefined) return String(actual) !== String(val.$ne);
        if (val?.$in) return val.$in.some(entry => String(entry) === String(actual));
        return String(actual) === String(val);
    });
}
function project(row, projection = {}) {
    if (!row) return null;
    const included = Object.entries(projection).filter(([, v]) => v === 1);
    if (included.some(([key]) => key.startsWith('xray.extraInbounds.'))) {
        return require('mongoose/lib/helpers/projection/applyProjection')(bson(row), projection);
    }
    const result = included.length ? { _id: row._id } : bson(row);
    for (const [key] of included) if (get(row, key) !== undefined) set(result, key, get(row, key));
    for (const [key, value] of Object.entries(projection)) {
        if (value !== 0) continue;
        const cut = key.lastIndexOf('.');
        const obj = cut === -1 ? result : get(result, key.slice(0, cut));
        for (const item of Array.isArray(obj) ? obj : [obj]) if (item) delete item[key.slice(cut + 1)];
    }
    return result;
}
let rows, writes, beforeWrite;
let held, lockAcquires, incident, linkReads;
const lockStore = {
    async insertOne(row) { assert.equal(held, null); held = row; lockAcquires++; },
    async findOne({ _id, token }) { return held?._id === _id && held.token === token ? held : null; },
    async deleteMany(filter) {
        assert.deepEqual(filter, { _id: 'apply', token: held.token });
        held = null;
        return { acknowledged: true, deletedCount: 1 };
    },
};
const collection = mongoose.connection.collection.bind(mongoose.connection);
mongoose.connection.collection = (name, ...args) => {
    if (name === 'c3_rebuild_locks') return lockStore;
    if (name === 'c3_rebuild_relay_accounts') return { async findOne(filter) {
        assert.ok(held);
        assert.deepEqual(filter, { _id: 'pending' });
        return null;
    } };
    return collection(name, ...args);
};
const Link = require('../../models/cascadeLinkModel');
Link.collection.buffer = false;
Link.collection.collection = { async findOne(query) {
    assert.ok(held, 'edit must check incident ownership under the real Apply lock');
    assert.deepEqual(query, { active: true, $or: [{ portalNode: id }, { bridgeNode: id }] });
    linkReads++;
    if (incident instanceof Error) throw incident;
    return incident ? { _id: new mongoose.Types.ObjectId() } : null;
} };
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
State.collection.buffer = false;
State.collection.collection = { async findOne() { assert.ok(held); return null; } };
function change(filter, update) {
    const runtimeStatus = update.$set?.status === 'syncing'
        && Object.keys(update.$set).every(key => key === 'status' || key === 'updatedAt');
    if (process.env.C3_REBUILD_ENABLED === 'true' && !runtimeStatus) assert.ok(held, 'card write must hold the real Apply lock');
    beforeWrite?.();
    const row = rows.find(item => matches(item, filter));
    if (!row) return null;
    writes.push(update);
    for (const [key, val] of Object.entries(update.$set || {})) set(row, key, val);
    for (const [key, val] of Object.entries(update.$inc || {})) set(row, key, (get(row, key) || 0) + val);
    return row;
}
Node.collection.buffer = false;
Node.collection.collection = {
    async find(filter, opts) {
        return { toArray: async () => rows.filter(row => matches(row, filter)).map(row => project(row, opts.projection)) };
    },
    async findOne(filter, opts) { return project(rows.find(row => matches(row, filter)), opts.projection); },
    async insertOne(row) { writes.push({ insert: true }); rows.push(bson(row)); return { insertedId: row._id }; },
    async updateOne(filter, update) { return { matchedCount: change(filter, update) ? 1 : 0 }; },
    async findOneAndUpdate(filter, update, opts) { return project(change(filter, update), opts.projection); },
};
const User = require('../../models/hyUserModel');
User.collection.buffer = false;
User.collection.collection = { countDocuments: async () => 0 };

const fixture = { _id: id, name: 'Encryption fixture', ip: '192.0.2.10', type: 'xray', cascadeRole: 'portal', active: true };
const extra = { id: 'second', port: 444, inboundTag: 'client-two', security: 'none', transport: 'tcp' };
function reset(xrayVersion, values = {}) {
    delete process.env.C3_REBUILD_ENABLED;
    held = null;
    lockAcquires = linkReads = 0;
    incident = false;
    beforeWrite = undefined;
    pushes.length = 0;
    invalidations.length = 0;
    writes = [];
    rows = [{ ...fixture, xrayVersion,
        xray: { security: 'none', agentToken: 'fixture-agent', manualKey: 'fixture-hidden-pem',
            accessLogs: { ingestTokenEncrypted: 'fixture-hidden-ingest' }, extraInbounds: [{ ...extra }] }, ...values }];
}
function formValues() {
    return { name: fixture.name, ip: fixture.ip, type: 'xray', cascadeRole: 'portal', active: 'on',
        'xray.transport': 'tcp', 'xray.security': 'none',
        'xray.vlessEncryptionAuth': 'x25519', 'xray.vlessEncryptionMode': 'native', 'xray.vlessEncryptionTicket': '600s',
        xray_extra_id: 'second', xray_extra_port: '444', xray_extra_inboundTag: 'client-two', xray_extra_security: 'none',
        xray_extra_vlessEncryptionAuth: 'x25519', xray_extra_vlessEncryptionMode: 'random',
        xray_extra_vlessEncryptionTicket: '0s' };
}
const panelEdit = (body, lang) => request('POST', `/panel/nodes/${id}`, body, true, lang);
const restEdit = (data, lang) => request('PUT', `/nodes/${id}`, data, false, lang);
const mcpEdit = data => mcp.manageNode({ action: 'update', id: String(id), data });
async function mcpCall(args, lang) {
    const response = await request('POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'manage_node', arguments: args } }, false, lang);
    assert.equal(response.status, 200);
    const event = response.body.match(/^data: (\{.*\})$/m);
    assert.ok(event, response.body);
    const { result } = JSON.parse(event[1]);
    assert.equal(result.isError, true);
    return result.content[0].text;
}
const mcpEditLocalized = (data, lang) => mcpCall({ action: 'update', id: String(id), data }, lang);
const encryptRequest = { xray: { vlessEncryption: true, vlessEncryptionMode: 'xorpub', vlessEncryptionTicket: '300-600s',
    extraInbounds: [{ ...extra, vlessEncryption: true, vlessEncryptionTicket: '0s' }] } };
const privateField = 'vlessEncryptionPrivateKey';
const publicField = 'vlessEncryptionPublicKey';
function assertKeys(xray) {
    assert.equal(xray.vlessEncryption, true);
    assert.equal(xray.extraInbounds[0].vlessEncryption, true);
    assert.ok(xray[privateField]);
    assert.ok(xray.extraInbounds[0][privateField]);
    assert.notEqual(xray[publicField], xray.extraInbounds[0][publicField]);
}
function assertRedacted(body) {
    assert.equal(body.includes(privateField), false);
    assert.equal(body.includes(rows[0].xray[privateField]), false);
    assert.equal(body.includes(rows[0].xray.extraInbounds[0][privateField]), false);
}

test('stock create paths refuse main or extra encryption even with caller-supplied version', async () => {
    reset(undefined, { ip: '192.0.2.20' });
    const data = { name: fixture.name, ip: fixture.ip, type: 'xray', xrayVersion: '26.1.0', ...encryptRequest };
    const panelResult = await request('POST', '/panel/nodes', { ...formValues(), xrayVersion: '26.1.0',
        xray_extra_vlessEncryption: 'second' }, true);
    assert.match(panelResult.location, /25\.9\.5/);
    assert.equal((await request('POST', '/nodes', data)).status, 400);
    assert.equal((await mcp.manageNode({ action: 'create', data })).code, 400);
    assert.equal(writes.length, 0);
    assert.equal(pushes.length, 0);
    const off = await request('POST', '/panel/nodes', { ...formValues(), xray_extra_vlessEncryptionMode: 'native' }, true);
    assert.match(off.location, /^\/panel\/nodes\/[0-9a-f]+$/);
    assert.equal(rows[1].xray.vlessEncryption, undefined);
    assert.equal(rows[1].xray.extraInbounds[0].vlessEncryption, undefined);
});

test('stock edit paths refuse unknown, old, malformed or non-client health with no write or push', async () => {
    for (const [version, role] of [[undefined, 'portal'], ['25.9.4', 'portal'], ['garbage 26.1.0', 'portal'], ['25.9.5', 'relay']]) {
        reset(version, { cascadeRole: role });
        const body = { ...formValues(), cascadeRole: role, xrayVersion: '26.1.0', 'xray.vlessEncryption': 'on' };
        assert.match((await panelEdit(body, 'en')).location, /error=.*VLESS Encryption/);
        assert.equal((await restEdit({ ...encryptRequest, xrayVersion: '26.1.0' })).status, 400);
        assert.equal((await mcpEdit({ ...encryptRequest, xrayVersion: '26.1.0' })).code, 400);
        assert.equal(writes.length, 0);
        assert.equal(pushes.length, 0);
    }
});

test('mounted VLESS create/edit refusals use the request locale without reflecting input', async () => {
    for (const [lang, unknown, old, fallback, key, auth] of [
        ['ru-RU', /нет достоверной версии/, /проверка состояния узла сообщила версию 25\.9\.4/, /несовместимо с fallbackDest/,
            /Основной вход: .*ключ.*недействителен/iu, /x25519 или mlkem768/],
        ['en-GB', /no valid version from node health/, /node health reports 25\.9\.4/, /cannot be combined with fallbackDest/,
            /Main inbound: VLESS Encryption key is invalid/, /x25519 or mlkem768/],
    ]) {
        const create = { name: fixture.name, ip: '192.0.2.20', type: 'xray', ...encryptRequest };
        reset('25.9.5');
        assert.match((await request('POST', '/panel/nodes', { ...formOn(), ip: create.ip }, true, lang)).location, unknown);
        const restCreate = await request('POST', '/nodes', create, false, lang);
        assert.equal(restCreate.status, 400);
        assert.match(JSON.parse(restCreate.body).error, unknown);
        const mcpCreate = JSON.parse(await mcpCall({ action: 'create', data: create }, lang));
        assert.equal(mcpCreate.code, 400);
        assert.match(mcpCreate.error, unknown);

        async function refusals(panelBody, apiBody, expected) {
            const panelResult = await panelEdit(panelBody, lang);
            assert.equal(panelResult.status, 302);
            assert.match(panelResult.location, expected);
            assert.doesNotMatch(panelResult.location, /fixture-do-not-reflect/);
            const restResult = await restEdit(apiBody, lang);
            assert.equal(restResult.status, 400);
            assert.match(JSON.parse(restResult.body).error, expected);
            assert.doesNotMatch(restResult.body, /fixture-do-not-reflect/);
            const mcpResult = JSON.parse(await mcpEditLocalized(apiBody, lang));
            assert.equal(mcpResult.code, 400);
            assert.match(mcpResult.error, expected);
            assert.doesNotMatch(mcpResult.error, /fixture-do-not-reflect/);
            assert.deepEqual([writes.length, pushes.length], [0, 0]);
        }
        reset('fixture-do-not-reflect');
        await refusals(formOn(), encryptRequest, unknown);
        reset('v25.9.4');
        await refusals(formOn(), encryptRequest, old);
        reset('25.9.5');
        await refusals({ ...formOn(), 'xray.fallbackDest': '127.0.0.1:80' },
            { xray: { vlessEncryption: true, fallbackDest: '127.0.0.1:80' } }, fallback);
        Object.assign(rows[0].xray, { vlessEncryption: true, vlessEncryptionAuth: 'x25519',
            [privateField]: 'fixture-do-not-reflect' });
        await refusals(formOn(), encryptRequest, key);

        const invalidAuth = { xray: { vlessEncryption: true, vlessEncryptionAuth: 'fixture-do-not-reflect' } };
        const rest = await restEdit(invalidAuth, lang);
        assert.equal(rest.status, 400);
        assert.match(JSON.parse(rest.body).error, auth);
        const mcp = await mcpEditLocalized(invalidAuth, lang);
        assert.match(mcp, auth);
        assert.doesNotMatch(rest.body + mcp, /fixture-do-not-reflect/);
        assert.deepEqual([writes.length, pushes.length], [0, 0]);
    }
});

test('stock panel edit: enable at the threshold, preserve hidden keys, rotate only the named extra, and disable after health is lost', async () => {
    reset('25.9.5');
    const body = { ...formValues(), 'xray.vlessEncryption': 'on', xray_extra_vlessEncryption: 'second',
        'xray.vlessEncryptionPrivateKey': 'caller-value', 'xray.manualKey': '***SET***' };
    assert.equal((await panelEdit(body)).location, '/panel/nodes');
    assertKeys(rows[0].xray);
    assert.notEqual(rows[0].xray[privateField], 'caller-value');
    const first = bson(rows[0].xray);
    assert.equal(first.manualKey, 'fixture-hidden-pem');
    assert.equal(first.accessLogs.ingestTokenEncrypted, 'fixture-hidden-ingest');
    assert.equal((await panelEdit(body)).location, '/panel/nodes');
    assert.equal(rows[0].xray[privateField], first[privateField]);
    assert.equal(rows[0].xray.extraInbounds[0][privateField], first.extraInbounds[0][privateField]);
    assert.equal((await panelEdit({ ...body, xray_extra_vlessEncryptionRegenerate: 'second' })).location, '/panel/nodes');
    assert.equal(rows[0].xray[privateField], first[privateField]);
    assert.notEqual(rows[0].xray.extraInbounds[0][publicField], first.extraInbounds[0][publicField]);
    assert.equal(rows[0].xray.extraInbounds[0].vlessEncryptionRegenerate, undefined);
    rows[0].xrayVersion = '';
    assert.equal((await panelEdit(formValues())).location, '/panel/nodes');
    assert.equal(rows[0].xray.vlessEncryption, false);
    assert.equal(rows[0].xray[privateField], first[privateField]);
});

test('REST and MCP round-trip settings, reject caller keys and preserve secrets on generate, edit, reads and preview', async () => {
    reset('26.1.0');
    const input = { xray: { ...encryptRequest.xray, [privateField]: 'caller-key', [publicField]: 'caller-public',
        'extraInbounds.0.vlessEncryptionPrivateKey': 'caller-dotted-key' } };
    const created = await restEdit(input);
    assert.equal(created.status, 200, created.body);
    assertKeys(rows[0].xray);
    assertRedacted(created.body);
    const first = bson(rows[0].xray);
    assert.equal(first.manualKey, 'fixture-hidden-pem');
    assert.equal(first.accessLogs.ingestTokenEncrypted, 'fixture-hidden-ingest');
    assert.notEqual(first[publicField], 'caller-public');
    const updated = await mcpEdit({ xray: { vlessEncryptionRegenerate: true, vlessEncryptionTicket: '0s', [privateField]: 'caller-key' } });
    assert.equal(updated.success, true, updated.error);
    assert.notEqual(rows[0].xray[publicField], first[publicField]);
    assert.equal(rows[0].xray.extraInbounds[0][privateField], first.extraInbounds[0][privateField]);
    assert.equal(rows[0].xray.vlessEncryptionTicket, '0s');
    assertRedacted(JSON.stringify(updated));
    for (const uri of ['/nodes', `/nodes/${id}`, `/nodes/${id}/config`]) {
        const result = await request('GET', uri);
        assert.equal(result.status, 200);
        assertRedacted(result.body);
        if (uri.endsWith('/config')) assert.match(result.type, /yaml/);
    }
    for (const query of [{}, { id: String(id), includeConfig: true }]) assertRedacted(JSON.stringify(await mcp.queryNodes(query)));
});

test('invalid settings or ambiguous extra IDs cannot write or dispatch; true standalone Rebuild encryption uses the normal sync dispatcher', async () => {
    reset('25.9.5');
    for (const xray of [
        { vlessEncryption: true, vlessEncryptionTicket: '99999s' },
        { vlessEncryption: true, fallbackDest: 'localhost:80' },
        { extraInbounds: [{ ...extra, id: 'main', vlessEncryption: true }] },
        { extraInbounds: [{ ...extra, id: 'extra.0', vlessEncryption: true }] },
        { extraInbounds: [{ ...extra, vlessEncryption: true }, { ...extra, port: 445 }] },
        { extraInbounds: { ...extra, vlessEncryption: true } },
        { 'extraInbounds.0': { ...extra, vlessEncryption: true, [privateField]: 'caller-key' } },
    ]) assert.equal((await restEdit({ xray })).status, 400);
    assert.equal(writes.length, 0);
    assert.equal(pushes.length, 0);
    rows[0].cascadeRole = 'standalone';
    process.env.C3_REBUILD_ENABLED = 'true';
    assert.equal((await restEdit(encryptRequest)).status, 200);
    assertKeys(rows[0].xray);
    const result = await mcpEdit({ xray: { vlessEncryptionRegenerate: true } });
    assert.equal(result.success, true, result.error);
    const edited = await panelEdit({ ...formValues(), cascadeRole: 'standalone', 'xray.vlessEncryption': 'on', xray_extra_vlessEncryption: 'second',
        'xray.vlessEncryptionRegenerate': '1' });
    assert.equal(edited.location, '/panel/nodes');
    assert.equal(pushes.length, 3);
    assert.equal(lockAcquires, 3);
    assert.equal(linkReads, 3);
    assert.equal(held, null);
    // An ordinary config edit on an encrypted standalone is not suppressed.
    assert.equal((await panelEdit({ ...formOn(), cascadeRole: 'standalone', domain: 'fixture.invalid' })).location, '/panel/nodes');
    assert.equal(pushes.length, 4);
    assert.equal(linkReads, 3, 'ordinary config edit did not consult encryption ownership');
});

const formOn = () => ({ ...formValues(), 'xray.vlessEncryption': 'on', xray_extra_vlessEncryption: 'second' });
const protectedKey = 'nodes.xrayVlessEncProtected';
const unavailableKey = 'nodes.xrayVlessEncOwnershipUnavailable';
const protectedReason = 'REBUILD_VLESS_CLIENT_PROTECTED';
const { isDeepStrictEqual: isSame } = require('node:util');
async function refuseAll(panelBody, apiBody, code = 409, lang) {
    const old = bson(rows[0]);
    const counts = [writes.length, invalidations.length, pushes.length];
    const result = await panelEdit(panelBody, lang);
    const key = code === 409 ? protectedKey : unavailableKey;
    const message = translate(key, lang);
    assert.ok(result.location.endsWith(`?error=${message}`), result.location);
    const rest = await restEdit(apiBody, lang);
    assert.equal(rest.status, code);
    assert.equal(JSON.parse(rest.body).error, message);
    if (code === 409) assert.equal(JSON.parse(rest.body).code, protectedReason);
    const mcp = JSON.parse(await mcpEditLocalized(apiBody, lang));
    assert.equal(mcp.code, code);
    assert.equal(mcp.error, message);
    if (code === 409) assert.equal(mcp.reason, protectedReason);
    assert.deepEqual([writes.length, invalidations.length, pushes.length], counts);
    assert.ok(isSame(bson(rows[0]), old), 'refused edit changed stored client data');
    assert.equal(held, null);
}

test('panel/REST/MCP refuse protected enable before publication, including submitted alternate role', async () => {
    reset('25.9.5');
    process.env.C3_REBUILD_ENABLED = 'true';
    await refuseAll(formOn(), encryptRequest);
    await refuseAll({ ...formOn(), cascadeRole: 'standalone' }, { ...encryptRequest, cascadeRole: 'standalone' }, 409, 'en');
    assert.equal(lockAcquires, 6);
    assert.equal(linkReads, 0, 'fresh stored portal is already topology-owned');
});

test('panel/REST/MCP refuse encrypted client rotations, ticket/disable edits, and dropping an enabled extra; no-op and metadata still work', async () => {
    reset('25.9.5');
    assert.equal((await panelEdit(formOn())).location, '/panel/nodes');
    process.env.C3_REBUILD_ENABLED = 'true';
    await refuseAll({ ...formOn(), xray_extra_vlessEncryptionRegenerate: 'second' },
        { xray: { extraInbounds: [{ ...extra, vlessEncryptionRegenerate: true }] } });
    await refuseAll({ ...formOn(), 'xray.vlessEncryptionTicket': '0s' }, { xray: { vlessEncryptionTicket: '0s' } });
    await refuseAll({ ...formOn(), 'xray.vlessEncryption': '' }, { xray: { vlessEncryption: false } });
    await refuseAll({ ...formOn(), cascadeRole: 'standalone' }, { cascadeRole: 'standalone' });
    const noExtra = Object.fromEntries(Object.entries(formOn()).filter(([key]) => !key.startsWith('xray_extra_')));
    await refuseAll(noExtra, { xray: { extraInbounds: [] } });
    const snapshot = bson(rows[0].xray);
    const noOpCounts = [writes.length, pushes.length];
    assert.equal((await restEdit({ xray: { vlessEncryption: true } })).status, 200);
    assert.equal((await mcpEdit({ xray: { vlessEncryption: true } })).success, true);
    assert.deepEqual([writes.length, pushes.length], noOpCounts);
    assert.equal((await panelEdit({ ...formOn(), comment: 'panel metadata' })).location, '/panel/nodes');
    assert.equal((await restEdit({ comment: 'REST metadata', xray: { vlessEncryptionTicket: '0600S' } })).status, 200);
    assert.equal((await mcpEdit({ comment: 'MCP metadata', xray: { vlessEncryption: true } })).success, true);
    assert.equal(rows[0].comment, 'MCP metadata');
    assertKeys(rows[0].xray);
    assert.ok(rows[0].xray[privateField] === snapshot[privateField]);
    assert.ok(rows[0].xray.extraInbounds[0][privateField] === snapshot.extraInbounds[0][privateField]);
});

test('an incident edge on a standalone card vetoes writes; failed edge lookup is not absence', async () => {
    reset('25.9.5', { cascadeRole: 'standalone' });
    process.env.C3_REBUILD_ENABLED = 'true';
    incident = true;
    await refuseAll({ ...formOn(), cascadeRole: 'standalone' }, encryptRequest);
    incident = new Error('private fixture driver diagnostic');
    await refuseAll({ ...formOn(), cascadeRole: 'standalone' }, encryptRequest, 503, 'en');
    assert.equal(linkReads, 6);
    assert.equal((await restEdit({ xray: { vlessEncryption: false } })).status, 200);
    assert.equal(linkReads, 6, 'off baseline edit did not probe links');
    assert.equal(writes.length, 0);
    assert.equal(pushes.length, 0);
});

test('the Rebuild-encryption explanation and refusal strings are localized', async () => {
    const locales = ['en', 'ru', 'zh-CN'];
    for (const key of ['xrayVlessEncProtected', 'xrayVlessEncOwnershipUnavailable', 'xrayVlessEncRebuildScope']) {
        const values = locales.map(lang => require(`../../locales/${lang}.json`).nodes[key]);
        assert.ok(values.every(value => typeof value === 'string' && value.length > 0));
        assert.equal(new Set(values).size, locales.length);
    }
    const node = { type: 'xray', xrayEncryptionAvailable: true };
    assert.doesNotMatch(await render(node), /xrayVlessEncRebuildScope/);
    assert.match(await render({ ...node, xrayEncryptionRebuild: true }), /xrayVlessEncRebuildScope/);
});

test('standalone Save and explicit Sync prepare encrypted MAIN for first Rebuild Preview and Apply', async t => {
    reset('26.3.27', { cascadeRole: 'standalone', ssh: { password: 'fixture-ssh' } });
    process.env.C3_REBUILD_ENABLED = 'true';
    const bridgeId = new mongoose.Types.ObjectId('507f1f77bcf86cd799439032');
    rows.push({ ...fixture, _id: bridgeId, name: 'fixture-exit', ip: '192.0.2.11', cascadeRole: 'bridge' });
    const vless = require('../../utils/vlessEncryption');
    const generator = require('../../services/configGenerator');
    const user = { userId: 'fixture-user', xrayUuid: '10000000-0000-4000-8000-000000000001' };
    const baseline = JSON.parse(generator.generateXrayConfigWithApi(bson(rows[0]), [user]));
    const live = new Map([[String(id), { main: baseline }], [String(bridgeId), { main: { inbounds: [] } }]]);
    let uploads = 0, stages = 0, puts = 0, link;
    const methods = [], ownershipScopes = [];
    const { MAIN } = require('../../services/classicAppliedConfig');
    class OfflineSsh {
        async connect() { assert.ok(held); }
        async exec(command) {
            assert.ok(command.includes(MAIN));
            return { code: 0, stdout: JSON.stringify(live.get(String(id)).main), stderr: '' };
        }
        async uploadContent(bytes, path) {
            assert.ok(held);
            assert.equal(path, MAIN);
            uploads++;
            live.get(String(id)).main = JSON.parse(bytes);
        }
        disconnect() {}
    }
    const syncPath = require.resolve('../../services/syncService');
    const oldSync = require.cache[syncPath];
    delete require.cache[syncPath];
    let sync;
    Module._load = function(request, parent, isMain) {
        const resolved = Module._resolveFilename(request, parent);
        const key = resolved.slice(root.length + '/src/'.length, -'.js'.length);
        if (key === 'services/nodeSSH') return OfflineSsh;
        if (key === 'services/nodeSetup') return { reloadCcAgent: noIO };
        if (key === 'services/cacheService' || key === 'utils/logger') return modules[key];
        return originalLoad.call(this, request, parent, isMain);
    };
    try { sync = require(syncPath); }
    finally { Module._load = originalLoad; }
    modules['services/syncService'].updateNodeConfig = sync.updateNodeConfig.bind(sync);
    t.after(() => {
        require.cache[syncPath] = oldSync;
        delete modules['services/syncService'].updateNodeConfig;
    });
    t.mock.method(sync, '_getUsersForNode', async node => String(node._id) === String(id) ? [user] : []);
    t.mock.method(sync, '_agentRequest', async (_node, _method, route) => { methods.push(route); });
    t.mock.method(sync, 'checkXrayAgentHealth', async () => ({ online: true }));
    const cursor = items => ({ toArray: async () => items });
    t.mock.method(Link.collection.collection, 'findOne', async query => {
        ownershipScopes.push(!!held);
        assert.ok(query.active);
        return link ? { _id: link._id } : null;
    });
    Object.assign(Link.collection.collection, {
        find: () => cursor(link ? [bson(link)] : []),
        async insertOne(row) {
            assert.ok(held);
            assert.equal(link, undefined);
            link = bson(row);
            return { acknowledged: true, insertedId: row._id };
        },
        async updateOne(filter, update) {
            assert.ok(held);
            assert.ok(matches(link, filter));
            Object.assign(link, bson(update.$set));
            return { acknowledged: true, matchedCount: 1 };
        },
    });
    State.collection.collection.find = () => cursor([]);
    t.mock.method(Link.db, 'transaction', async fn => fn({ inTransaction: () => true }));
    const { createRebuildService } = require('../../services/rebuildService');
    const service = createRebuildService({ sync, env: { ...process.env }, async connect(node) {
        const profiles = live.get(String(node._id));
        return {
            async read(profile) { return profiles[profile] ?? null; },
            async requireSupportedCore() { return '26.3.27'; },
            async stagePair() { assert.ok(held); stages++; },
            async putPair(pair) {
                assert.ok(held);
                puts++;
                for (const { profile, config } of pair) profiles[profile] = JSON.parse(JSON.stringify(config));
            },
            async close() {},
        };
    }, cache: modules['services/cacheService'] });
    app.use('/api/nodes', api);
    app.use('/api/cascade', (req, res, next) => {
        req.apiKey = { scopes: ['nodes:write'] }; // authenticated caller fixture
        next();
    }, require('../cascadeRebuild').routerForRebuild({ service }));

    assert.equal((await restEdit(encryptRequest)).status, 200);
    assert.equal(pushes.length, 1);
    const syncUri = `/api/nodes/${id}/update-config`;
    const synced = await request('POST', syncUri);
    assert.equal(synced.status, 200, synced.body);
    assert.equal(uploads, 1);
    assert.deepEqual(ownershipScopes, [true, false, true], 'save checks under Apply; Sync checks again under Apply before writing');
    assert.deepEqual(methods, ['/restart', '/sync']);
    const values = main => main.inbounds.filter(item => item.protocol === 'vless').map(item => item.settings.decryption);
    const encrypted = values(live.get(String(id)).main);
    assert.ok(isSame(encrypted, [rows[0].xray, rows[0].xray.extraInbounds[0]].map(x => vless.buildServerDecryption(x))));

    assert.equal((await restEdit({ cascadeRole: 'portal' })).status, 200);
    const draft = await request('POST', '/api/cascade/links', { name: 'fixture-link', portalNodeId: String(id),
        bridgeNodeId: String(bridgeId), mode: 'reverse', tunnelPort: 31443, tunnelSecurity: 'none', tunnelEncryption: 'none' });
    assert.equal(draft.status, 200, draft.body);
    const { linkId } = JSON.parse(draft.body);
    assert.equal(link.status, 'pending');
    const previewUri = '/api/cascade/rebuild/preview';
    const applyUri = '/api/cascade/topology/deploy';
    const ready = await request('POST', previewUri, { linkId });
    assert.equal(ready.status, 200, ready.body);
    const { allowed, previewId } = JSON.parse(ready.body);
    assert.equal(allowed, true, ready.body);
    assert.equal(puts, 0);

    await refuseAll({ ...formOn(), 'xray.vlessEncryptionRegenerate': '1' }, { xray: { vlessEncryptionRegenerate: true } });
    const userSync = await request('POST', syncUri);
    assert.equal(userSync.status, 200, userSync.body);
    const beforeRestart = lockAcquires;
    const panelRestart = await request('POST', `/panel/nodes/${id}/restart`);
    assert.equal(panelRestart.status, 200, panelRestart.body);
    assert.equal(lockAcquires, beforeRestart + 1, 'held node verifier prevents re-entering Apply');
    assert.equal(uploads, 1, 'managed sync must not upload or restart MAIN');
    assert.deepEqual(methods, ['/restart', '/sync', '/sync', '/sync']);
    const applied = await request('POST', applyUri, { linkId, expectedPreview: previewId });
    assert.equal(applied.status, 200, applied.body);
    assert.equal(link.status, 'deployed');
    assert.ok(isSame(values(live.get(String(id)).main).slice(0, 2), encrypted));
    assert.deepEqual([uploads, stages, puts], [1, 2, 2]);

    // An already-published but uninstalled key is still refused by the
    // real Preview/Apply routes, not repaired or adopted implicitly.
    const rotated = { ...rows[0].xray };
    assert.equal(await vless.applyVlessEncryption(rotated, rows[0].xray, { regenerate: true }), null);
    rows[0].xray = rotated;
    const mismatch = await request('POST', previewUri, { linkId });
    assert.equal(mismatch.status, 200, mismatch.body);
    const blocked = JSON.parse(mismatch.body);
    assert.equal(blocked.allowed, false);
    const rejected = await request('POST', applyUri, { linkId, expectedPreview: blocked.previewId });
    assert.equal(rejected.status, 409, rejected.body);
    assert.equal(JSON.parse(rejected.body).error.code, 'REBUILD_CLIENT_CHANGE');
    assert.deepEqual([uploads, stages, puts], [1, 2, 2]);
    assert.equal(held, null);
});

test('racing stored health change blocks stock panel/REST/MCP key writes and dispatch', async () => {
    for (const [lang, expected] of [['ru', /Обновите страницу узла/], ['en', /Reload the node/]]) {
        for (const edit of [() => panelEdit({ ...formValues(), 'xray.vlessEncryption': 'on' }, lang),
            () => restEdit(encryptRequest, lang), async () => JSON.parse(await mcpEditLocalized(encryptRequest, lang))]) {
            reset('25.9.5');
            beforeWrite = () => { rows[0].xrayVersion = '25.9.4'; };
            const result = await edit();
            assert.equal(result.status ?? result.code, 409);
            assert.match(result.error ?? (result.type?.includes('json') ? JSON.parse(result.body).error : result.body), expected);
            assert.equal(writes.length, 0);
            assert.equal(pushes.length, 0);
        }
    }
});

test('default-off and attempted caller key writes leave legacy data untouched', async () => {
    reset('25.9.5');
    assert.equal((await restEdit({ xray: { vlessEncryption: false, [privateField]: 'caller-key' } })).status, 200);
    assert.equal((await mcpEdit({ xray: { vlessEncryption: false, [privateField]: 'caller-key' } })).success, true);
    assert.equal(rows[0].xray.vlessEncryption, undefined);
    assert.equal(rows[0].xray[privateField], undefined);
    assert.equal(rows[0].xray.extraInbounds[0].id, extra.id);
    assert.equal(writes.length, 0);
    assert.equal(pushes.length, 0);
});

test('panel remote-config preview redacts server decryption values without exposing malformed Xray output', async () => {
    reset('25.9.5', { ssh: { password: 'fixture-ssh' } });
    preview = JSON.stringify({ inbounds: [
        { protocol: 'vless', settings: { decryption: 'fixture-server-material' } },
        { protocol: 'vless', settings: { decryption: 'none' } },
    ] });
    const uri = `/panel/nodes/${id}/get-config`;
    const result = await request('GET', uri);
    assert.equal(result.status, 200);
    assert.equal(result.body.includes('fixture-server-material'), false);
    const { inbounds } = JSON.parse(JSON.parse(result.body).config);
    assert.deepEqual(inbounds.map(inbound => inbound.settings.decryption), ['<redacted>', 'none']);
    preview += ' fixture-server-material';
    const failure = await request('GET', uri);
    assert.equal(failure.status, 502);
    assert.equal(failure.body.includes('fixture-server-material'), false);
});
