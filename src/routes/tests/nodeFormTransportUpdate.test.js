'use strict';

const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');
const express = require('express');
const mongoose = require('mongoose');

// No Mongo/Redis/SSH: keep the real model, query casting/projections, form
// parsers, validation, encryption, save and schedulePush. Replace only external
// infrastructure and observe the full-config dispatch boundary.
const root = path.resolve(__dirname, '../../..');
const cfg = { PANEL_DOMAIN: 'transport-form.invalid', ACME_EMAIL: 'test@example.invalid',
    ENCRYPTION_KEY: 'test-only-transport-encryption-key-32', SESSION_SECRET: 'test-only-session',
    BASE_URL: 'https://transport-form.invalid' };
let invalidations = 0;
const cache = { invalidateActiveNodes: async () => {}, invalidateAllSubscriptions: async () => {},
    invalidateDashboard: async () => {}, invalidateNodes: async () => {},
    getGroups: async () => [], invalidateUser: async () => {} };
const noop = () => {};
const stubs = new Map(Object.entries({
    'config.js': cfg,
    'src/utils/logger.js': { info: noop, warn: noop, error: noop, debug: noop },
    'src/services/cacheService.js': cache,
    'src/services/totpService.js': {},
    'src/services/nodeSetup.js': { generateAgentToken: () => 'generated-test-agent-token' },
    'src/services/cascadeService.js': {},
    'src/services/statsService.js': {},
    'src/services/uaStatsService.js': {},
    'src/services/sniScanner.js': {},
    'src/services/webhookService.js': {},
}).map(([p, value]) => [path.join(root, p), value]));
const originalLoad = Module._load;
Module._load = function(request, parent, isMain) {
    // The unrelated backup upload constructor must not mkdir an absolute /tmp path.
    if (request === 'multer') return () => ({});
    const resolved = Module._resolveFilename(request, parent);
    if (stubs.has(resolved)) return stubs.get(resolved);
    return originalLoad.call(this, request, parent, isMain);
};
let HyNode, sync, pool, cryptoService, helpers, router;
try {
    HyNode = require('../../models/hyNodeModel');
    const utils = require('../../utils/helpers');
    utils.invalidateNodesCache = async () => { invalidations++; };
    sync = require('../../services/syncService');
    pool = require('../../services/sshPoolService');
    cryptoService = require('../../services/cryptoService');
    helpers = require('../panel/helpers');
    router = require('../panel/nodes');
} finally { Module._load = originalLoad; }

const ID = '507f1f77bcf86cd799439031';
const SIBLING = '507f1f77bcf86cd799439032';
const GROUP = '507f1f77bcf86cd799439041';
const bson = value => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize({ value })).value;
const get = (obj, key) => key.split('.').reduce((v, p) => v?.[p], obj);
function set(obj, key, value) {
    const parts = key.split('.');
    const last = parts.pop();
    for (const p of parts) obj = obj[p] ??= {};
    obj[last] = bson({ value }).value;
}
function unset(obj, key) {
    const parts = key.split('.');
    const last = parts.pop();
    for (const p of parts) { obj = obj?.[p]; if (!obj) return; }
    delete obj[last];
}
function matches(row, filter) {
    return Object.entries(bson(filter)).every(([key, value]) => {
        if (value && Object.hasOwn(value, '$ne')) return String(get(row, key)) !== String(value.$ne);
        return String(get(row, key)) === String(value);
    });
}
function project(row, projection = {}) {
    if (!row) return null;
    let result = bson(row);
    const included = Object.entries(projection).filter(([key, v]) => v === 1 && key !== '_id');
    if (included.length) {
        result = { _id: row._id };
        for (const [key] of included) if (get(row, key) !== undefined) set(result, key, get(row, key));
    }
    for (const [key, value] of Object.entries(projection)) if (value === 0) unset(result, key);
    return bson(result);
}
let rows, writes, reads, dispatches, failSave;
const priorCollection = HyNode.collection.collection;
const priorBuffer = HyNode.collection.buffer;
HyNode.collection.buffer = false;
HyNode.collection.collection = {
    async findOne(filter, options = {}) {
        reads.push({ filter: bson(filter), projection: options.projection });
        return project(rows.find(row => matches(row, filter)), options.projection);
    },
    async updateOne(filter, update) {
        if (failSave) throw new Error('modeled save outcome unknown');
        const row = rows.find(row => matches(row, filter));
        assert.ok(row, 'real Mongoose save filter must match a persisted row');
        writes.push({ filter: bson(filter), update: bson(update) });
        for (const [key, value] of Object.entries(update.$set || {})) set(row, key, value);
        for (const key of Object.keys(update.$unset || {})) unset(row, key);
        for (const [key, value] of Object.entries(update.$inc || {})) set(row, key, (get(row, key) || 0) + value);
        return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
    },
    async updateMany(filter, update) {
        const selected = rows.filter(row => matches(row, filter));
        writes.push({ filter: bson(filter), update: bson(update), many: true });
        for (const row of selected) for (const [key, value] of Object.entries(update.$set || {})) set(row, key, value);
        return { acknowledged: true, matchedCount: selected.length, modifiedCount: selected.length };
    },
};
const originalUpdateNodeConfig = sync.updateNodeConfig;
sync.updateNodeConfig = async node => { dispatches.push(node.toObject()); };
let server, base;
test.before(async () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    // Same existing panel authentication middleware; only the session store is modeled.
    app.use((req, _res, next) => { req.session = { authenticated: req.headers['x-test-session'] === 'yes' }; next(); });
    app.use('/panel', helpers.requireAuth, router);
    server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
});
test.after(async () => {
    await new Promise(resolve => server.close(resolve));
    pool.closeAll();
    sync.updateNodeConfig = originalUpdateNodeConfig;
    HyNode.collection.collection = priorCollection;
    HyNode.collection.buffer = priorBuffer;
});

function reset(overrides = {}) {
    const doc = new HyNode({ _id: ID, name: 'Portal transport fixture', type: 'xray',
        ip: '192.0.2.10', cascadeRole: 'portal', groups: [GROUP], active: true,
        ssh: { port: 22, username: 'root', password: cryptoService.encrypt('old-local-test-password') },
        xray: { agentToken: 'retained-agent-token', manualKey: 'retained-private-PEM',
            accessLogs: { ingestTokenEncrypted: 'retained-private-ingest' } },
        executionBindingCheck: 'retained-private-CAS-nonce', ...overrides });
    rows = [bson(doc.toObject())];
    writes = []; reads = []; dispatches = []; invalidations = 0; failSave = false;
    return doc;
}
// Full ordinary Xray form: shared defaults and Xray controls use browser strings,
// comma-list arrays, blank credentials and hidden delete-all/checkbox semantics.
// These are the actual named controls in views/partials/node-form/*.ejs, not
// a sparse API patch. cascadeRole can be omitted by older supported forms.
function form(node) {
    const body = {};
    for (const key of ['name', 'type', 'ip', 'domain', 'sni', 'port', 'portRange', 'statsPort',
        'statsSecret', 'maxOnlineUsers', 'rankingCoefficient', 'customConfig', 'flag',
        'cascadeRole', 'country', 'comment', 'initScript']) body[key] = String(node[key] ?? '');
    body.groups = String(node.groups[0]);
    if (node.active) body.active = 'on';
    if (node.useCustomConfig) body.useCustomConfig = 'on';
    body['obfs.type'] = node.obfs.type;
    body['obfs.password'] = node.obfs.password;
    body['ssh.port'] = String(node.ssh.port);
    body['ssh.username'] = node.ssh.username;
    body['ssh.password'] = '';
    body['ssh.privateKey'] = '';
    body['ssh.clearPrivateKey'] = '0';
    for (const key of ['transport', 'security', 'flow', 'fingerprint', 'realityDest', 'realityPrivateKey',
        'realityPublicKey', 'realitySpiderX', 'wsPath', 'wsHost', 'grpcServiceName', 'xhttpPath',
        'xhttpHost', 'xhttpMode', 'apiPort', 'fallbackDest', 'tlsSource', 'manualCert', 'acmeEmail']) {
        body[`xray.${key}`] = String(node.xray[key] ?? '');
    }
    for (const key of ['alpn', 'fingerprintPool', 'realitySni', 'realityShortIds']) {
        body[`xray.${key}`] = node.xray[key].join(', ');
    }
    body['xray.manualKey'] = '***SET***';
    return body;
}
async function post(body, authenticated = true) {
    const response = await fetch(`${base}/panel/nodes/${ID}`, { method: 'POST', redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
            'x-test-session': authenticated ? 'yes' : 'no' }, body: new URLSearchParams(body) });
    await response.text();
    // Let the actual schedulePush setImmediate and its actual Mongoose read settle.
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
    return response;
}
async function readSaved() { return HyNode.findById(ID).select('+xray.manualKey +executionBindingCheck +xray.accessLogs.ingestTokenEncrypted').lean(); }

test('full public form persists transport-only portal edit with zero MAIN dispatch', async () => {
    const original = reset();
    const body = form(original);
    body.ip = '198.51.100.20';
    body['ssh.port'] = '2222';
    body['ssh.username'] = 'c3-test-runner';
    delete body.cascadeRole; // Must preserve portal, never deactivate/change role to avoid a push.
    const response = await post(body);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), '/panel/nodes');
    const saved = await readSaved();
    assert.equal(saved.ip, body.ip);
    assert.equal(saved.ssh.port, 2222);
    assert.equal(saved.ssh.username, body['ssh.username']);
    assert.equal(saved.active, true);
    assert.equal(saved.cascadeRole, 'portal');
    assert.equal(dispatches.length, 0, 'transport-only save must not dispatch full MAIN reader/upload/restart');
    assert.deepEqual(saved.xray, original.toObject().xray);
    assert.equal(saved.executionBindingCheck, 'retained-private-CAS-nonce');
    assert.equal(invalidations, 1);
    assert.ok(writes.some(write => !write.many), 'public form reached real document save');
});

test('genuine transport edit retires the old unpinned SSH pool connection without MAIN dispatch', async () => {
    const node = reset();
    let closed = 0;
    pool.connections.set(ID, { client: { end() { closed++; } }, lastUsed: Date.now() });
    const body = form(node);
    body['ssh.port'] = '2222';
    await post(body);
    assert.equal((await readSaved()).ssh.port, 2222);
    assert.equal(closed, 1, 'the pre-edit pooled endpoint cannot be reused');
    assert.equal(pool.connections.has(ID), false);
    assert.equal(dispatches.length, 0);
});

for (const mixed of [false, true]) {
    test(`${mixed ? 'mixed transport plus' : 'config-only'} actual Xray config edit still dispatches ordinary push`, async () => {
        const node = reset();
        const body = form(node);
        if (mixed) { body.ip = '198.51.100.20'; body['ssh.port'] = '2222'; body['ssh.username'] = 'c3-test-runner'; }
        body['xray.apiPort'] = '61001';
        // A request cannot select a no-push path.
        body.skipPush = 'true'; body.transportOnly = 'true';
        const response = await post(body);
        assert.equal(response.headers.get('location'), '/panel/nodes');
        const saved = await readSaved();
        assert.equal(saved.xray.apiPort, 61001);
        assert.equal(saved.ip, mixed ? '198.51.100.20' : node.ip);
        assert.equal(dispatches.length, 1);
        assert.equal(dispatches[0].xray.apiPort, 61001);
        assert.equal(dispatches[0].ssh.port, mixed ? 2222 : 22);
        assert.equal(saved.executionBindingCheck, 'retained-private-CAS-nonce');
    });
}

test('unchanged full form uses schema-cast equality and leaves a live pool connection alone', async () => {
    const node = reset();
    let closed = 0;
    pool.connections.set(ID, { client: { end() { closed++; } }, lastUsed: Date.now() });
    const body = form(node);
    body.port = '0443'; body['ssh.port'] = '022'; // Equivalent numeric form values.
    const response = await post(body);
    assert.equal(response.headers.get('location'), '/panel/nodes');
    assert.equal(dispatches.length, 0);
    assert.equal(closed, 0);
    assert.deepEqual((await readSaved()).ssh, node.toObject().ssh);
    pool.removeConnection(ID, 'fixture cleanup');
});

test('missing default fields are compared after applying existing form defaults', async () => {
    const node = reset();
    const body = form(node);
    for (const key of ['domain', 'sni', 'port', 'portRange', 'statsPort', 'customConfig', 'obfs.type',
        'obfs.password', 'xray.wsPath', 'xray.security', 'ssh.port', 'ssh.username', 'cascadeRole']) delete body[key];
    body.ip = '198.51.100.20';
    await post(body);
    const saved = await readSaved();
    assert.equal(saved.port, 443);
    assert.equal(saved.ssh.port, 22);
    assert.equal(saved.cascadeRole, 'portal');
    assert.deepEqual(saved.xray, node.toObject().xray);
    assert.equal(dispatches.length, 0);
});

test('missing form value that changes a nondefault runtime setting is not transport-only', async () => {
    const node = reset({ port: 8443 });
    const body = form(node);
    body.ip = '198.51.100.20';
    delete body.port; // Existing public route persists default 443, a real change.
    await post(body);
    assert.equal((await readSaved()).port, 443);
    assert.equal(dispatches.length, 1);
});

test('null runtime value to form default remains a genuine config change', async () => {
    const node = reset({ statsPort: null });
    const body = form(node);
    body.ip = '198.51.100.20';
    await post(body);
    assert.equal((await readSaved()).statsPort, 9999);
    assert.equal(dispatches.length, 1);
});

test('blank optional credential preserves persisted null and encrypted SSH credentials', async () => {
    const node = reset({ statsSecret: null });
    const body = form(node);
    body['ssh.username'] = 'c3-test-runner';
    await post(body);
    const saved = await readSaved();
    assert.equal(saved.statsSecret, null);
    assert.equal(saved.ssh.password, node.ssh.password);
    assert.equal(saved.xray.manualKey, 'retained-private-PEM');
    assert.equal(dispatches.length, 0);
});

for (const role of ['standalone', 'relay', 'portal']) {
    test(`active ${role} transport edit does not use a bridge/inactive shortcut`, async () => {
        const node = reset({ cascadeRole: role });
        const body = form(node);
        body.ip = '198.51.100.20';
        await post(body);
        const saved = await readSaved();
        assert.equal(saved.cascadeRole, role);
        assert.equal(saved.active, true);
        assert.equal(dispatches.length, 0);
    });
}

test('role transition still uses the ordinary full-form push path', async () => {
    const node = reset({ cascadeRole: 'bridge' });
    const body = form(node);
    body.cascadeRole = 'portal';
    await post(body);
    assert.equal((await readSaved()).cascadeRole, 'portal');
    assert.equal(dispatches.length, 1);
});

test('bridge genuine config edit still respects schedulePush existing bridge ownership exclusion', async () => {
    const node = reset({ cascadeRole: 'bridge' });
    const body = form(node);
    body.port = '8443';
    await post(body);
    assert.equal((await readSaved()).port, 8443);
    assert.equal(dispatches.length, 0);
});

test('private Xray fields survive full replacement and remain excluded from ordinary query projection', async () => {
    const node = reset();
    const body = form(node);
    body.ip = '198.51.100.20';
    await post(body);
    const saved = await readSaved();
    assert.equal(saved.xray.accessLogs.ingestTokenEncrypted, 'retained-private-ingest');
    assert.equal(saved.xray.manualKey, 'retained-private-PEM');
    assert.equal(saved.executionBindingCheck, 'retained-private-CAS-nonce');
    const publicRead = await HyNode.findById(ID).lean();
    assert.equal(Object.hasOwn(publicRead, 'executionBindingCheck'), false);
    assert.equal(Object.hasOwn(publicRead.xray, 'manualKey'), false);
    assert.equal(Object.hasOwn(publicRead.xray.accessLogs, 'ingestTokenEncrypted'), false);
    assert.ok(reads.some(read => read.projection?.executionBindingCheck === 0), 'actual select:false projection reached modeled driver');
    assert.equal(dispatches.length, 0);
});

test('SSH credentials remain encrypted and synchronize only to same-IP sibling', async () => {
    const node = reset();
    const sibling = new HyNode({ _id: SIBLING, name: 'Hysteria sibling', type: 'hysteria', ip: node.ip,
        ssh: { password: 'old-sibling-encrypted' }, comment: 'untouched sibling metadata' });
    rows.push(bson(sibling.toObject()));
    const other = new HyNode({ _id: '507f1f77bcf86cd799439033', name: 'Other IP', type: 'hysteria', ip: '192.0.2.11' });
    rows.push(bson(other.toObject()));
    const otherBefore = bson(rows[2]);
    const body = form(node);
    body['ssh.password'] = 'new-local-test-password';
    body['ssh.username'] = 'c3-test-runner';
    await post(body);
    const saved = await readSaved();
    assert.notEqual(saved.ssh.password, body['ssh.password']);
    assert.equal(cryptoService.decrypt(saved.ssh.password), body['ssh.password']);
    assert.deepEqual(rows[1].ssh, saved.ssh);
    assert.equal(rows[1].comment, sibling.comment);
    assert.deepEqual(rows[2], otherBefore);
    assert.equal(dispatches.length, 0);
});

test('valid SSH private key update and explicit clearing stay transport-only', async () => {
    const node = reset();
    const key = require('../../services/sshKeyService').generateEd25519KeyPair().privateKey;
    const body = form(node);
    body['ssh.privateKey'] = key;
    await post(body);
    const saved = await readSaved();
    assert.notEqual(saved.ssh.privateKey, key);
    assert.equal(cryptoService.decryptPrivateKey(saved.ssh.privateKey), key.trim());
    assert.equal(dispatches.length, 0);
    const nextBody = form(HyNode.hydrate(saved));
    nextBody['ssh.clearPrivateKey'] = '1';
    await post(nextBody);
    assert.equal((await readSaved()).ssh.privateKey, '');
    assert.equal(dispatches.length, 0);
});

for (const invalid of ['name', 'ip', 'privateKey', 'xray', 'role']) {
    test(`invalid ${invalid} is refused before save, dispatch or pool cleanup`, async () => {
        const node = reset();
        const before = bson(rows);
        const body = form(node);
        body.ip = '198.51.100.20';
        if (invalid === 'name') body.name = '';
        if (invalid === 'ip') body.ip = '';
        if (invalid === 'privateKey') body['ssh.privateKey'] = 'not-a-key';
        if (invalid === 'xray') { body['xray.security'] = 'tls'; body['xray.tlsSource'] = 'manual'; }
        if (invalid === 'role') body.cascadeRole = 'not-a-role';
        let closed = 0;
        pool.connections.set(ID, { client: { end() { closed++; } }, lastUsed: Date.now() });
        const response = await post(body);
        assert.match(response.headers.get('location'), /\?error=/);
        assert.deepEqual(rows, before);
        assert.equal(writes.length, 0);
        assert.equal(dispatches.length, 0);
        assert.equal(closed, 0);
        pool.removeConnection(ID, 'fixture cleanup');
    });
}

test('unauthenticated public form is refused before reading or saving nodes', async () => {
    const node = reset();
    const response = await post(form(node), false);
    assert.equal(response.headers.get('location'), '/panel/login');
    assert.equal(reads.length, 0);
    assert.equal(writes.length, 0);
    assert.equal(dispatches.length, 0);
});

test('manual TLS placeholder preserves the selected real key without push', async () => {
    const fs = require('node:fs');
    const dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'node-form-transport-'));
    try {
        require('node:child_process').execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'),
            '-days', '1', '-nodes', '-subj', '/CN=node.example.invalid'], { stdio: 'ignore' });
        const key = fs.readFileSync(path.join(dir, 'key.pem'), 'utf8').trim();
        const cert = fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8').trim();
        const node = reset({ domain: 'node.example.invalid', xray: { security: 'tls', tlsSource: 'manual',
            manualKey: key, manualCert: cert, agentToken: 'retained-agent-token' } });
        const body = form(node);
        body.ip = '198.51.100.20';
        const response = await post(body);
        assert.equal(response.headers.get('location'), '/panel/nodes');
        const saved = await readSaved();
        assert.equal(saved.xray.manualKey, key);
        assert.equal(saved.xray.manualCert, cert);
        assert.equal(dispatches.length, 0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('unchanged extra inbound arrays are normalized before comparison and delete-all still pushes', async () => {
    const node = reset({ xray: { agentToken: 'retained-agent-token', extraInbounds: [{
        id: 'existing-ws', port: 8443, inboundTag: 'ws-in', transport: 'ws', security: 'none', flow: '',
    }] } });
    const body = form(node);
    const extra = node.xray.extraInbounds[0].toObject();
    for (const [key, value] of Object.entries(extra)) {
        if (key === 'uniqueName') continue;
        body[`xray_extra_${key}`] = Array.isArray(value) ? value.join(', ') : String(value);
    }
    body.ip = '198.51.100.20';
    await post(body);
    assert.deepEqual((await readSaved()).xray.extraInbounds, node.toObject().xray.extraInbounds);
    assert.equal(dispatches.length, 0);
    const deletion = form(HyNode.hydrate(await readSaved()));
    await post(deletion); // No extra rows = existing supported delete-all intent.
    assert.deepEqual((await readSaved()).xray.extraInbounds, []);
    assert.equal(dispatches.length, 1);
});

test('form activation retains ordinary full-form push semantics', async () => {
    const node = reset({ active: false });
    const body = form(node);
    body.active = 'on';
    await post(body);
    assert.equal((await readSaved()).active, true);
    assert.equal(dispatches.length, 1);
});

test('protocol transition retains ordinary full-form push semantics', async () => {
    const node = reset({ type: 'hysteria' });
    const body = form(node);
    body.type = 'xray';
    await post(body);
    assert.equal((await readSaved()).type, 'xray');
    assert.equal(dispatches.length, 1);
});

for (const configChanged of [false, true]) {
    test(`Hysteria full-form transport edit ${configChanged ? 'with runtime change pushes' : 'without runtime change does not push'}`, async () => {
        const node = reset({ type: 'hysteria', cascadeRole: 'standalone' });
        const body = { ...form(node), 'masquerade.proxy.rewriteHost': 'on', 'acl.enabled': 'on',
            'acl.inlineRules': 'reject(geoip:private)', useTlsFiles: 'on' };
        // Persist a strict-schema value produced by the actual supported form,
        // including Hysteria's form defaults (which differ from schema defaults).
        const fields = helpers.parseHysteriaFormFields(body);
        delete fields.acmeDnsConfigValid;
        const previous = new HyNode({ ...node.toObject(), ...fields });
        rows[0] = bson(previous.toObject());
        body.ip = '198.51.100.20'; body['ssh.port'] = '2222';
        if (configChanged) { body['bandwidth.enabled'] = 'on'; body['bandwidth.up'] = '100 mbps'; }
        const response = await post(body);
        assert.equal(response.headers.get('location'), '/panel/nodes');
        const saved = await readSaved();
        assert.equal(saved.ip, body.ip);
        assert.equal(saved.ssh.port, 2222);
        assert.equal(saved.bandwidth.up, configChanged ? '100 mbps' : '');
        if (!configChanged) for (const key of Object.keys(fields)) assert.deepEqual(saved[key], previous.toObject()[key]);
        assert.equal(dispatches.length, configChanged ? 1 : 0);
    });
}

test('unknown save outcome does not authorize push or pool cleanup', async () => {
    const node = reset();
    const before = bson(rows);
    failSave = true;
    let closed = 0;
    pool.connections.set(ID, { client: { end() { closed++; } }, lastUsed: Date.now() });
    const body = form(node);
    body.ip = '198.51.100.20'; body.port = '8443';
    const response = await post(body);
    assert.match(response.headers.get('location'), /modeled%20save%20outcome%20unknown/);
    assert.deepEqual(rows, before);
    assert.equal(dispatches.length, 0);
    assert.equal(closed, 0);
    pool.removeConnection(ID, 'fixture cleanup');
});
