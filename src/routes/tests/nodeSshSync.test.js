'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');
const net = require('node:net');
const path = require('node:path');
const test = require('node:test');

// Mount the real routes and model without sockets, a real config, or remote services.
const noIO = () => assert.fail('unexpected network operation');
net.Socket.prototype.connect = noIO;
net.Server.prototype.listen = noIO;
const express = require('express');
const noop = () => {};
const logged = [];
const root = path.resolve(__dirname, '../../..');
const stubs = new Map(Object.entries({
    'config.js': { ENCRYPTION_KEY: 'fixture-only' },
    'src/classicSettings.js': null,
    'src/utils/logger.js': { info: noop, warn: noop, error: message => logged.push(message) },
    'src/services/cacheService.js': {
        invalidateNodes: noop, invalidateAllSubscriptions: noop, invalidateDashboardCounts: noop,
    },
    'src/services/syncService.js': { schedulePush: noop },
    'src/services/sshPoolService.js': { close: noop },
    ...Object.fromEntries(['nodeSetup', 'configGenerator', 'nodeSSH', 'cascadeService',
        'statsService', 'uaStatsService', 'totpService', 'sniScanner'].map(name => [`src/services/${name}.js`, {}])),
}).map(([file, stub]) => [path.join(root, file), stub]));
const load = Module._load;
Module._load = function(request, parent, isMain) {
    if (request === 'dotenv') assert.fail('unexpected dotenv import');
    if (request === 'multer') return () => ({}); // No backup upload directory creation.
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (stubs.has(resolved)) return stubs.get(resolved);
    return load.call(this, request, parent, isMain);
};
test.after(() => { Module._load = load; });

const HyNode = require('../../models/hyNodeModel');
const cryptoService = require('../../services/cryptoService');
const app = express();
app.use(express.json(), express.urlencoded({ extended: false }));
app.use((req, _res, next) => { req.session = { authenticated: true }; next(); });
app.use('/api/nodes', require('../../middleware/auth'), require('../nodes'));
app.use('/panel', require('../panel/helpers').requireAuth, require('../panel/nodes'));

const OLD_IP = '192.0.2.10';
const NEW_IP = '192.0.2.20';
const VIRTUAL = { selectMode: 'group', sourceGroup: '507f1f77bcf86cd799439041' };
const PASSWORD = 'synthetic-update-value';
let edited, oldPeer, newPeer, virtualPeer, rows, syncFilters, syncError;
function row(name, ip, type, port) {
    return new HyNode({ name, ip, type, virtual: type === 'virtual' ? VIRTUAL : undefined,
        ssh: { port, username: name, password: cryptoService.encrypt(`password-${name}`),
            privateKey: cryptoService.encrypt(`key-${name}`) } }).toObject();
}
test.beforeEach(() => {
    edited = row('edited', OLD_IP, 'hysteria', 2201);
    oldPeer = row('old-peer', OLD_IP, 'xray', 2202);
    newPeer = row('new-peer', NEW_IP, 'xray', 2203);
    virtualPeer = row('virtual-peer', null, 'virtual', 2204);
    rows = [edited, oldPeer, newPeer, virtualPeer];
    syncFilters = [];
    syncError = null;
    logged.length = 0;
});

// Replace only the Mongo driver calls; casting, projections and doc.save() are real.
const copy = value => HyNode.base.mongo.BSON.deserialize(HyNode.base.mongo.BSON.serialize({ value })).value;
const get = (obj, key) => key.split('.').reduce((val, part) => val?.[part], obj);
function set(obj, key, value) {
    const parts = key.split('.');
    const field = parts.pop();
    for (const part of parts) obj = obj[part] ??= {};
    if (value === undefined) delete obj[field];
    else obj[field] = value;
}
function project(doc, projection = {}) {
    if (!doc) return null;
    const fields = Object.entries(projection);
    const projected = fields.some(([, include]) => include === 1) ? { _id: doc._id } : copy(doc);
    for (const [key, include] of fields) set(projected, key, include ? get(doc, key) : undefined);
    return copy(projected);
}
const find = filter => rows.find(doc => String(doc._id) === String(filter._id));
function apply(doc, update) {
    for (const [key, value] of Object.entries(update.$set || {})) set(doc, key, copy(value));
}
HyNode.collection.buffer = false;
HyNode.collection.collection = {
    async findOne(filter, options) { return project(find(filter), options.projection); },
    async findOneAndUpdate(filter, update, options) {
        const doc = find(filter);
        apply(doc, update);
        return project(doc, options.projection);
    },
    async updateOne(filter, update) {
        apply(find(filter), update);
        return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
    },
    async updateMany(filter, update) {
        syncFilters.push(filter);
        if (syncError) throw syncError;
        for (const doc of rows) {
            if (doc.ip === filter.ip && String(doc._id) !== String(filter._id.$ne)) apply(doc, update);
        }
        return { acknowledged: true };
    },
};

function edit(route, body) {
    const api = route === 'API';
    const data = api ? JSON.stringify(body) : String(new URLSearchParams(body));
    return new Promise(resolve => {
        const req = new http.IncomingMessage(new net.Socket());
        Object.assign(req, {
            method: api ? 'PUT' : 'POST', url: `${api ? '/api' : '/panel'}/nodes/${edited._id}`,
            headers: { 'content-type': api ? 'application/json' : 'application/x-www-form-urlencoded',
                'content-length': Buffer.byteLength(data) },
        });
        req.push(data);
        req.push(null);
        const res = new http.ServerResponse(req);
        res.end = bytes => resolve({ status: res.statusCode, location: res.getHeader('location'), text: String(bytes) });
        app(req, res);
    });
}
const panelForm = { name: 'edited', ip: OLD_IP, type: 'hysteria' };
function assertSaved(route, response) {
    assert.equal(response.status, route === 'API' ? 200 : 302);
    if (route === 'panel') assert.equal(response.location === '/panel/nodes', true, 'edit redirected to the node list');
}
function assertSsh(doc, expected, message) {
    // Keep even fixture SSH values out of failed assertions.
    assert.ok(Object.keys(expected).every(key => doc.ssh[key] === expected[key]), message);
}

for (const route of ['API', 'panel']) {
    test(`${route}: partial SSH update syncs only the supplied field to the old-IP sibling`, async () => {
        const [before, siblingBefore, otherBefore] = rows.map(doc => copy(doc.ssh));
        const response = await edit(route, route === 'API' ? { ssh: { password: PASSWORD } }
            : { ...panelForm, 'ssh.password': PASSWORD, 'ssh.privateKey': '', 'ssh.clearPrivateKey': '0' });
        assertSaved(route, response);
        const encrypted = edited.ssh.password;
        assert.ok(encrypted !== PASSWORD && cryptoService.decrypt(encrypted) === PASSWORD, 'password encrypted at rest');
        assertSsh(edited, { ...before, password: encrypted }, 'edited node retains unspecified SSH fields');
        assertSsh(oldPeer, { ...siblingBefore, password: encrypted }, 'sibling retains its own unspecified SSH fields');
        assertSsh(newPeer, otherBefore, 'node on another IP is untouched');
        assert.deepEqual(syncFilters, [{ ip: OLD_IP, _id: { $ne: edited._id } }]);
    });

    test(`${route}: no supplied SSH fields makes no SSH write`, async () => {
        const before = rows.map(doc => copy(doc.ssh));
        assertSaved(route, await edit(route, route === 'API' ? { comment: 'edited metadata', ssh: {} }
            : { ...panelForm, comment: 'edited metadata', 'ssh.password': '', 'ssh.privateKey': '' }));
        assert.equal(edited.comment, 'edited metadata');
        assert.equal(syncFilters.length, 0);
        rows.forEach((doc, index) => assertSsh(doc, before[index], 'SSH fields are unchanged'));
    });

    test(`${route}: editing SSH while changing the IP does not sync to any sibling`, async () => {
        const peers = rows.slice(1).map(doc => copy(doc.ssh));
        // The API clears IP on conversion to virtual; the panel allows a move to another host.
        const response = await edit(route, route === 'API' ? { type: 'virtual', virtual: VIRTUAL, ssh: { port: 2299 } }
            : { ...panelForm, ip: NEW_IP, 'ssh.port': '2299' });
        assertSaved(route, response);
        assert.equal(edited.ip, route === 'API' ? null : NEW_IP);
        assert.equal(edited.ssh.port, 2299);
        assert.equal(syncFilters.length, 0);
        rows.slice(1).forEach((doc, index) => assertSsh(doc, peers[index], 'sibling SSH fields are unchanged'));
    });

    test(`${route}: nodes without an IP do not share SSH fields`, async () => {
        Object.assign(edited, { type: 'virtual', ip: null, virtual: VIRTUAL });
        const peerBefore = copy(virtualPeer.ssh);
        assertSaved(route, await edit(route, route === 'API' ? { ssh: { port: 2299 } } : {
            name: edited.name, type: 'virtual', 'virtual.selectMode': 'group', 'virtual.sourceGroup': VIRTUAL.sourceGroup,
            'ssh.port': '2299',
        }));
        assert.equal(edited.ssh.port, 2299);
        assert.equal(syncFilters.length, 0);
        assertSsh(virtualPeer, peerBefore, 'peer without an IP is untouched');
    });

    test(`${route}: SSH sync errors do not disclose write details`, async () => {
        syncError = new Error(PASSWORD);
        const response = await edit(route, route === 'API' ? { ssh: { port: 2299 } }
            : { ...panelForm, 'ssh.port': '2299' });
        assert.equal(syncFilters.length, 1);
        assert.equal(response.status, route === 'API' ? 500 : 302);
        assert.ok(!`${response.text} ${response.location} ${logged.join(' ')}`.includes(PASSWORD), 'write details stay private');
    });
}

test('API: edit response omits stored SSH secrets but keeps transport fields', async () => {
    const response = await edit('API', { ssh: { username: 'new-user' } });
    assertSaved('API', response);
    const { ssh } = JSON.parse(response.text);
    assert.equal(ssh.username, 'new-user');
    assert.equal(Object.hasOwn(ssh, 'password') || Object.hasOwn(ssh, 'privateKey'), false);
});

test('panel: explicit private-key clearing is synchronized without touching other fields', async () => {
    const [before, siblingBefore] = rows.map(doc => copy(doc.ssh));
    assertSaved('panel', await edit('panel', { ...panelForm, 'ssh.clearPrivateKey': '1' }));
    assertSsh(edited, { ...before, privateKey: '' }, 'edited key is cleared');
    assertSsh(oldPeer, { ...siblingBefore, privateKey: '' }, 'sibling key is cleared without other changes');
});
