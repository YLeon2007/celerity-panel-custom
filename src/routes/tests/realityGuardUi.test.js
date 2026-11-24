'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { isDeepStrictEqual } = require('node:util');
const HyNode = require('../../models/hyNodeModel');
const Settings = require('../../models/settingsModel');

const legacy = { type: 'xray', name: 'Legacy', ip: '192.0.2.42', cascadeRole: 'standalone', xray: {} };

test('new Xray nodes default off on validation; hydrated legacy policies remain absent', async () => {
    const card = new HyNode(legacy);
    await card.validate();
    assert.equal(card.xray.realityGuard.mode, 'off');
    for (const xray of [undefined, {}, { realityGuard: { mode: 'retired' } }]) {
        const row = HyNode.hydrate({ ...legacy, xray });
        row.comment = 'unrelated';
        assert.deepEqual(row.toObject().xray?.realityGuard, xray?.realityGuard);
        assert.ok(Object.keys(row.getChanges().$set).every(key => !key.startsWith('xray.realityGuard')));
    }
});

test('model rejects new auto', () => {
    const auto = new HyNode({ ...legacy, xray: { realityGuard: { mode: 'auto' } } });
    assert.ok(auto.validateSync()?.errors['xray.realityGuard.mode']);
});

test('missing Security setting does not materialize a default in the model', () => {
    assert.equal(Settings.hydrate({ _id: 'settings' }).realityGuard?.enabled, undefined);
});

// Use the actual Express parsers, routes, EJS and Mongoose. No listener: the
// driver collections below and the request's Duplex are in-memory boundaries.
const Module = require('node:module');
const path = require('node:path');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const express = require('express');
const mongoose = require('mongoose');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../..');
const noop = () => {};
const allowNoIO = async () => {};
const pushes = [];
const cache = {
    getGroups: async () => [], isConnected: () => false, invalidateSettings: allowNoIO,
    invalidateNodes: allowNoIO, invalidateActiveNodes: allowNoIO, invalidateAllSubscriptions: allowNoIO,
    invalidateDashboard: allowNoIO, invalidateDashboardCounts: allowNoIO,
};
const stubs = Object.fromEntries(Object.entries({
    'config.js': { PANEL_DOMAIN: 'panel.fixture.invalid', BASE_URL: 'https://panel.fixture.invalid', MONGO_URI: '' },
    'src/utils/logger.js': { debug: noop, info: noop, warn: noop, error: noop },
    'src/services/cacheService.js': cache,
    'src/services/cryptoService.js': {
        generateNodeSecret: () => '', generateX25519KeysLocal: () => ({}),
        encrypt: () => '', encryptSshCredentials: v => v,
    },
    'src/services/nodeSetup.js': { generateAgentToken: () => '' },
    'src/services/syncService.js': { schedulePush: (_id, fields) => pushes.push(fields) },
    'src/services/totpService.js': {}, 'src/services/sshPoolService.js': { close: allowNoIO },
    'src/services/cascadeService.js': {}, 'src/services/statsService.js': {},
    'src/services/uaStatsService.js': {}, 'src/services/sniScanner.js': {},
    'src/services/webhookService.js': { EVENTS: {} },
    'src/services/hwidDeviceService.js': { topUsersByDeviceCount: async () => [] },
    'src/services/homepageService.js': { getMode: () => 'nginx', hasCustom: () => false, getCustomSize: () => 0, MAX_CUSTOM_BYTES: 262144 },
    'src/services/updateService.js': {},
}).map(([key, value]) => [path.join(root, key), value]));
// Lazy requires in handlers must see the same I/O boundaries as startup.
for (const [filename, value] of Object.entries(stubs)) {
    const fixture = new Module(filename);
    fixture.filename = filename;
    fixture.exports = value;
    fixture.loaded = true;
    require.cache[filename] = fixture;
}
const originalLoad = Module._load;
let wizardFences = 0;
Module._load = function(request, parent, isMain) {
    if (request === 'multer') return Object.assign(() => ({ single: () => noop }), { memoryStorage: () => ({}) });
    const resolved = Module._resolveFilename(request, parent);
    if (Object.hasOwn(stubs, resolved)) return stubs[resolved];
    if (parent?.filename === path.join(root, 'src/routes/panel/wizard.js') && resolved.endsWith('/rebuildRelayRoleGuard.js')) {
        return {
            withNodeWriterFence: fn => ++wizardFences % 2 ? fn({}, allowNoIO) : Promise.reject(new Error('fixture stops before bootstrap')),
            describeRoleError: () => null,
        };
    }
    return originalLoad.call(this, request, parent, isMain);
};
let panelNodes, panelSettings, panelWizard, apiNodes, mcp, auth, setId, i18n;
try {
    panelNodes = require('../panel/nodes');
    panelSettings = require('../panel/settings');
    panelWizard = require('../panel/wizard');
    apiNodes = require('../nodes');
    mcp = require('../../mcp/tools/nodes');
    auth = require('../../middleware/auth');
    setId = require('../panel/csrf').issuePanelCsrfToken;
    i18n = require('../../middleware/i18n');
    for (const [name, method, result] of [['cascadeLink', 'find', []], ['cascadeLink', 'countDocuments', 0],
        ['serverGroup', 'find', []], ['admin', 'findOne', null], ['apiKey', 'find', []]]) {
        const model = require(`../../models/${name}Model`);
        model.collection.buffer = false;
        model.collection.collection ||= {};
        model.collection.collection[method] = async () => Array.isArray(result) ? { toArray: async () => result } : result;
    }
} finally {
    Module._load = originalLoad;
}

const bson = value => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize({ value })).value;
const id = new mongoose.Types.ObjectId('507f1f77bcf86cd799439011');
const get = (obj, key) => key.split('.').reduce((o, part) => o?.[part], obj);
function set(obj, key, value) {
    const parts = key.split('.');
    const last = parts.pop();
    for (const part of parts) obj = obj[part] ??= {};
    obj[last] = value;
}
function matches(doc, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$expr') {
            const [field, { $literal }] = value.$eq;
            return isDeepStrictEqual(get(doc, field.slice(1)), $literal);
        }
        const actual = get(doc, key);
        if (value?.$in) return value.$in.some(v => String(actual) === String(v));
        if (value?.$exists !== undefined) return (actual !== undefined) === value.$exists;
        if (value?.$elemMatch) return actual?.some(row => matches(row, value.$elemMatch));
        if (value?.$ne !== undefined) return String(actual) !== String(value.$ne);
        return String(actual) === String(value);
    });
}
function project(row, projection = {}) {
    if (!row) return null;
    if (Object.values(projection).includes(1)) {
        const obj = { _id: row._id };
        for (const [key, value] of Object.entries(projection)) {
            const prefix = 'xray.extraInbounds.';
            if (value === 1 && key.startsWith(prefix) && Array.isArray(row.xray?.extraInbounds)) {
                obj.xray ??= {};
                const extras = obj.xray.extraInbounds ??= row.xray.extraInbounds.map(() => ({}));
                const field = key.slice(prefix.length);
                row.xray.extraInbounds.forEach((extra, i) => {
                    if (field in extra) extras[i][field] = extra[field];
                });
                continue;
            }
            if (value === 1 && get(row, key) !== undefined) set(obj, key, get(row, key));
        }
        return bson(obj);
    }
    // EJS readback needs the real scalar cast; the fixture has no credentials.
    return bson(row);
}
function collection(Model, rows) {
    Model.collection.buffer = false;
    Model.collection.collection = {
        async find(filter, opts) {
            return { toArray: async () => rows.filter(row => matches(row, filter)).map(row => project(row, opts.projection)) };
        },
        async findOne(filter, opts) { return project(rows.find(row => matches(row, filter)), opts.projection); },
        async insertOne(row) {
            rows.push(bson(row));
            return { acknowledged: true, insertedId: row._id };
        },
        async updateOne(filter, update) {
            const row = rows.find(row => matches(row, filter));
            if (!row) return { acknowledged: true, matchedCount: 0, modifiedCount: 0 };
            apply(row, update);
            return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
        async findOneAndUpdate(filter, update, opts) {
            let row = rows.find(row => matches(row, filter));
            if (!row) {
                if (!opts.upsert) return null;
                row = { _id: filter._id, ...update.$setOnInsert };
                rows.push(row);
            }
            apply(row, update);
            return project(row, opts.projection);
        },
    };
}
const writes = [];
function apply(row, update) {
    writes.push(bson(update));
    for (const [key, value] of Object.entries(update.$set || {})) set(row, key, bson(value));
}
const rows = [], settingsRows = [];
collection(HyNode, rows);
collection(Settings, settingsRows);
function reset(...values) {
    rows.splice(0, rows.length, ...values.map(bson));
    settingsRows.splice(0, settingsRows.length, { _id: 'settings', homepage: { mode: 'custom' }, webhook: { enabled: true } });
    pushes.length = writes.length = 0;
}

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(root, 'views'));
app.use(express.urlencoded({ extended: true }), express.json(), i18n.i18nMiddleware);
app.use((req, res, next) => { res.locals.csrfToken = setId(req); next(); });
app.use('/panel', auth, panelNodes, panelSettings, panelWizard);
app.use('/api/nodes', apiNodes);
const session = { authenticated: true, adminUsername: 'operator' };
function request(url, { form, data, method = form || data ? 'POST' : 'GET', lang = 'en' } = {}) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const socket = new Duplex({ read() {}, write(chunk, _encoding, done) { chunks.push(chunk); done(); } });
        socket.remoteAddress = '192.0.2.55';
        const req = new IncomingMessage(socket);
        const headers = { host: 'panel.fixture.invalid', 'accept-language': lang };
        const bytes = form ? new URLSearchParams(form).toString() : data ? JSON.stringify(data) : '';
        if (form || data) {
            headers['content-type'] = form ? 'application/x-www-form-urlencoded' : 'application/json';
            headers['content-length'] = Buffer.byteLength(bytes);
        }
        Object.assign(req, { method, url, headers, session, complete: true });
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.on('error', reject);
        res.on('finish', () => {
            const wire = Buffer.concat(chunks).toString();
            resolve({ code: res.statusCode, location: res.getHeader('location'), body: wire.slice(wire.indexOf('\r\n\r\n') + 4) });
            socket.destroy();
        });
        if (bytes) req.push(bytes);
        req.push(null);
        app(req, res);
    });
}
const prefix = 'xray.realityGuard.';
const nodePath = '/panel/nodes/' + id;
const publicDest = 'www.google.com:443';
const baseForm = { name: legacy.name, ip: legacy.ip, type: 'xray', active: 'on',
    'xray.security': 'reality', 'xray.realityDest': publicDest };
const token = html => html.match(/name="_csrf" value="([A-Za-z0-9_-]+)"/)?.[1];
const mode = html => html.match(/name="xray\.realityGuard\.mode" value="(\w+)" checked/)?.[1];
const widget = html => html.match(/<fieldset id="xrayRealityGuardGroup"[^>]*>[\s\S]*?<\/fieldset>/)?.[0];
const guardRead = async () => (await HyNode.findById(id)).toObject().xray.realityGuard;
const t = (lang, key) => i18n.t(key, lang);
function translated(html, lang, key) { assert.ok(html.includes(t(lang, key)), key); }

const put = data => request('/api/nodes/' + id, { method: 'PUT', data });
const mcpUpdate = data => mcp.manageNode({ action: 'update', id: String(id), data });
const policy = mode => ({ xray: { realityGuard: { mode } } });

test('list and edit keep populated documents and only read Guard profiles when enabled', async ctx => {
    const Group = require('../../models/serverGroupModel');
    const group = { _id: new mongoose.Types.ObjectId(), name: 'Fixture group', color: '#123456' };
    reset({ ...legacy, _id: id, active: true, groups: [group._id],
        xray: { security: 'reality', realityDest: publicDest, realityGuard: { mode: 'notify' } } });
    ctx.mock.method(Group.collection.collection, 'find', async () => ({ toArray: async () => [bson(group)] }));
    const calls = [], rendered = [];
    const exec = HyNode.Query.prototype.exec, render = app.response.render;
    ctx.mock.method(HyNode.Query.prototype, 'exec', async function(...args) {
        const result = await exec.apply(this, args);
        calls.push({ result, filter: this.getFilter(), projection: this.projection(), lean: !!this.mongooseOptions().lean });
        return result;
    });
    ctx.mock.method(app.response, 'render', function(view, locals, ...rest) {
        rendered.push(locals);
        return render.call(this, view, locals, ...rest);
    });
    for (const enabled of [false, true, false]) {
        settingsRows[0].realityGuard = { enabled };
        for (const list of [true, false]) {
            calls.length = rendered.length = 0;
            assert.equal((await request(list ? '/panel/nodes' : nodePath)).code, 200);
            // List has one inventory read; edit also fetches virtual source candidates.
            assert.equal(calls.length, (list ? 1 : 2) + Number(enabled));
            const primary = calls.find(q => !q.lean);
            const doc = list ? primary?.result[0] : primary?.result;
            assert.ok(doc instanceof HyNode && doc.groups[0] instanceof Group);
            assert.equal(doc.groups[0].get('name'), group.name);
            if (list) assert.equal(rendered[0].nodes[0], doc);
            else {
                assert.equal(Object.getPrototypeOf(rendered[0].node), Object.prototype);
                assert.equal(rendered[0].node.groups[0].name, group.name);
            }
            const profiles = calls.filter(q => q.filter['xray.realityGuard.mode'] === 'notify');
            assert.equal(profiles.length, Number(enabled));
            if (enabled) {
                assert.ok(profiles[0].lean);
                assert.deepEqual(profiles[0].filter._id.$in.map(String), [String(id)]);
                assert.equal(profiles[0].projection['xray.realityDest'], 1);
            }
        }
    }
    assert.deepEqual(writes, []);
});

test('ordinary non-Xray cards round-trip without persisting any guard defaults', async () => {
    for (const type of [undefined, 'hysteria', 'virtual', 'xray']) {
        reset();
        // Use a real model insert: a default xray subdocument is not evidence
        // that the owning card's schema-cast type is Xray.
        const input = { xray: {}, ...legacy, _id: id, type, virtual: { sources: [new mongoose.Types.ObjectId()] } };
        const card = await HyNode.create(input);
        assert.equal(card.type, type ?? 'hysteria');
        assert.deepEqual(rows[0].xray.realityGuard, type === 'xray' ? { mode: 'off' } : undefined);
        const ordinary = await put({ comment: 'round trip', xray: card.toObject().xray });
        assert.equal(ordinary.code, 200, ordinary.body);
        assert.equal(rows[0].comment, 'round trip');
        assert.deepEqual(rows[0].xray.realityGuard, type === 'xray' ? { mode: 'off' } : undefined);
    }
});

test('an acknowledged competing Off wins over stale whole-Xray PUT and explicit surrounding edits', async () => {
    const driver = HyNode.collection.collection;
    const xray = { security: 'reality', realityDest: publicDest, apiPort: 61003, fingerprint: 'firefox',
        realityGuard: { mode: 'notify', lastError: 'preserve history' } };
    for (const kind of ['API replacement', 'API explicit', 'MCP explicit', 'panel explicit']) {
        reset({ ...legacy, _id: id, cascadeRole: 'standalone', xray });
        const methods = kind === 'panel explicit' ? 'updateOne' : 'findOneAndUpdate';
        const original = driver[methods];
        const page = await request(nodePath);
        driver[methods] = async function(...args) {
            driver[methods] = original;
            assert.equal((await put(policy('off'))).code, 200);
            assert.equal(rows[0].xray.realityGuard.mode, 'off');
            return original.apply(this, args);
        };
        try {
            const replacement = { security: 'reality', realityDest: publicDest, apiPort: 61004 };
            const explicit = kind === 'API replacement' ? {} : policy('notify').xray;
            const result = kind === 'MCP explicit' ? await mcpUpdate({ ...policy('notify'), comment: 'stale' })
                : kind === 'panel explicit' ? await request(nodePath, { form: { ...baseForm, _csrf: token(page.body),
                    [prefix + 'mode']: 'notify', comment: 'stale' } })
                    : await put({ xray: { ...replacement, ...explicit } });
            assert.equal(result.code, 409, kind);
            assert.deepEqual(rows[0].xray, { ...xray, realityGuard: { ...xray.realityGuard, mode: 'off' } });
            assert.equal(rows[0].comment, undefined);
            assert.deepEqual(writes, [{ $set: { [prefix + 'mode']: 'off' } }]);
            assert.deepEqual(pushes, []);
        } finally { driver[methods] = original; }
    }
    assert.equal((await put({ xray: { security: 'reality', realityDest: publicDest, apiPort: 61004 } })).code, 200);
    assert.equal(rows[0].xray.apiPort, 61004);
    assert.notEqual(rows[0].xray.fingerprint, 'firefox', 'PUT still replaces other Xray fields');
    assert.deepEqual(rows[0].xray.realityGuard, { mode: 'off', lastError: 'preserve history' });

    // Legacy BSON null and a missing leaf are distinct preimages.
    const write = driver.findOneAndUpdate;
    for (const [before, after] of [[{}, { mode: null }], [{ mode: null }, {}]]) {
        reset({ ...legacy, _id: id, xray: { ...xray, realityGuard: before } });
        driver.findOneAndUpdate = function(...args) {
            rows[0].xray.realityGuard = after;
            return write.apply(this, args);
        };
        try {
            assert.equal((await put({ xray: { apiPort: 61004 } })).code, 409);
            assert.deepEqual(rows[0].xray.realityGuard, after);
            assert.deepEqual(writes, []);
            assert.deepEqual(pushes, []);
        } finally { driver.findOneAndUpdate = write; }
    }
});

test('legacy saved cards with no raw role cannot opt in or backfill on form save; new standalone can opt in', async () => {
    reset({ ...legacy, _id: id, xray: { security: 'reality', realityDest: publicDest } });
    delete rows[0].cascadeRole;
    const page = await request(nodePath);
    assert.equal(page.code, 200);
    assert.doesNotMatch(page.body, /action="[^"]+\/reality-guard"/);
    assert.match(page.body, /id="cascadeRole" name="cascadeRole" value=""/);
    for (const formRole of [{}, { cascadeRole: '' }]) {
        const form = { ...baseForm, ...formRole, _csrf: token(page.body), comment: 'ordinary' };
        assert.equal((await request(nodePath, { form })).location, '/panel/nodes');
        assert.equal(rows[0].cascadeRole, undefined);
        assert.match((await request(nodePath, { form: { ...form, [prefix + 'mode']: 'notify' } })).location, /\?error=/);
    }
    const form = { _csrf: token(page.body), [prefix + 'mode']: 'notify' };
    assert.match((await request(nodePath, { form: { ...baseForm, ...form, cascadeRole: 'standalone' } })).location, /\?error=/);
    assert.match((await request(nodePath + '/reality-guard', { form })).location, /\?error=/);
    assert.equal((await put(policy('notify'))).code, 400);
    assert.equal((await mcpUpdate(policy('notify'))).code, 400);
    assert.equal((await put({ ...policy('notify'), cascadeRole: 'standalone' })).code, 400);
    assert.equal((await mcpUpdate({ ...policy('notify'), cascadeRole: 'standalone' })).code, 400);
    assert.equal(rows[0].xray.realityGuard, undefined);
    rows[0].xray.realityGuard = { mode: 'notify' };
    settingsRows[0].realityGuard = { enabled: true };
    assert.doesNotMatch((await request('/panel/nodes')).body, /data-reality-guard-badge/);
    assert.equal((await put(policy('off'))).code, 200, 'ineligible legacy cards can still opt out');
    assert.equal(rows[0].xray.realityGuard.mode, 'off');
    assert.equal(rows[0].cascadeRole, undefined);
    const creates = [data => request('/api/nodes', { data }), data => mcp.manageNode({ action: 'create', data })];
    for (const [i, create] of creates.entries()) {
        const result = await create({ name: 'New Xray', type: 'xray', ip: `198.51.100.${72 + i}`, ...policy('notify') });
        assert.ok(result.code === 201 || result.success === true, result.body ?? result.error);
        assert.equal(rows.at(-1).cascadeRole, 'standalone');
        assert.equal(rows.at(-1).xray.realityGuard.mode, 'notify');
    }
});

test('unchanged rendered controls and unrelated saves do not backfill old cards', async () => {
    for (const guard of [undefined, { mode: 'retired' }, { mode: 'auto', allowedCidr: 'historical value',
        reserveSnis: ['WWW.Example.invalid.'], lastError: 'keep history' }, { mode: 'notify' }]) {
        const xray = { security: 'reality', realityDest: publicDest, ...(guard ? { realityGuard: guard } : {}) };
        reset({ ...legacy, _id: id, xray });
        const hydrated = await HyNode.findById(id);
        hydrated.comment = 'direct model save';
        await hydrated.save();
        assert.deepEqual(rows[0].xray.realityGuard, guard);
        const page = await request(nodePath);
        assert.equal(page.code, 200);
        const displayed = guard?.mode === 'notify' ? 'notify' : 'off';
        assert.equal(mode(widget(page.body)), displayed);
        const edited = await request(nodePath, { form: { ...baseForm, comment: 'unrelated edit', _csrf: token(page.body) } });
        assert.equal(edited.location, '/panel/nodes');
        assert.equal(rows[0].comment, 'unrelated edit');
        assert.deepEqual(rows[0].xray.realityGuard, guard);
        assert.ok(writes.every(update => Object.keys(update.$set || {}).every(key => !key.startsWith(prefix))));
        if (guard?.mode === 'auto') {
            const { action, csrf } = guardForm(page.body);
            const count = writes.length;
            assert.equal((await request(action, { form: { _csrf: csrf, [prefix + 'mode']: 'off' } })).location, nodePath);
            assert.deepEqual(rows[0].xray.realityGuard, guard);
            assert.equal(writes.length, count);
        }
    }
});

function guardForm(html) {
    const form = html.match(/<form[^>]*method="POST" action="([^"]+\/reality-guard)"[^>]*>[\s\S]*?<\/form>/)?.[0];
    assert.ok(form, 'expected independent Reality Guard POST form');
    const action = form.match(/action="([^"]+)"/)[1];
    const csrf = token(form);
    assert.ok(csrf);
    assert.match(form, /type="submit"/);
    return { action, csrf, form };
}

test('rendered guard form saves off -> notify with global OFF and touches only the mode', async () => {
    const old = { ...legacy, _id: id, active: true, xray: { security: 'reality', realityDest: publicDest,
        agentPort: 62090, accessLogs: { spoolBytes: 700 }, realityGuard: { ...storedWatchState, mode: 'off' } } };
    reset(old);
    const lang = 'ru';
    const page = await request(nodePath, { lang });
    const { action, csrf, form } = guardForm(page.body);
    assert.equal(mode(form), 'off');
    assert.match(form, /name="xray\.realityGuard\.mode" value="notify"(?![^>]*disabled)/);
    assert.match(form, /name="xray\.realityGuard\.mode" value="auto" disabled/);
    assert.match(form, /Недоступна с cc-agent 1\.5\.1/);
    assert.doesNotMatch(form, /reserveSnis|allowedCidr|previous\.invalid/);
    translated(form, lang, 'nodes.realityGuardPaused');
    const submit = (mode, _csrf = csrf) => request(action, { lang, form: { _csrf, [prefix + 'mode']: mode } });
    assert.equal((await submit('notify', '')).code, 403);
    assert.equal(new URL((await submit('auto')).location, 'https://fixture.invalid').searchParams.get('error'),
        'Недоступна с cc-agent 1.5.1');
    assert.equal(writes.length, 0);
    assert.equal((await submit('notify')).location, nodePath);
    assert.equal(mode(guardForm((await request(nodePath, { lang })).body).form), 'notify');
    assert.deepEqual(rows[0], { ...old, xray: { ...old.xray, realityGuard: { ...old.xray.realityGuard, mode: 'notify' } } });
    assert.deepEqual(writes, [{ $set: { [prefix + 'mode']: 'notify' } }]);
    assert.deepEqual(pushes, []);
    assert.equal(settingsRows[0].realityGuard, undefined);
});

test('panel create (including a form opened with an existing node) defaults off and accepts explicit opt-in on a public target', async () => {
    reset({ _id: id, name: 'Sibling', ip: '192.0.2.71', type: 'hysteria' });
    const page = await request('/panel/nodes/add?cloneFrom=' + id);
    assert.equal(page.code, 200, page.body.slice(0, 500));
    assert.equal(mode(widget(page.body)), 'off');
    const created = await request('/panel/nodes', { form: { ...baseForm, _csrf: token(page.body), [prefix + 'mode']: mode(widget(page.body)) } });
    assert.match(created.location, /^\/panel\/nodes\/[a-f0-9]{24}$/);
    assert.equal(rows[1].xray.realityGuard.mode, 'off');
    await request('/panel/nodes', { form: { ...baseForm, ip: '198.51.100.41' } });
    assert.equal(rows[2].xray.realityGuard.mode, 'off');
    const create = (mode, fields) => request('/panel/nodes', { form: { ...baseForm, ip: '198.51.100.42',
        _csrf: token(page.body), [prefix + 'mode']: mode, ...fields } });
    assert.match((await create('auto')).location, /\/panel\/nodes\/add\?error=/);
    assert.match((await create('notify', { 'xray.realityDest': '[::1]:443' })).location, /\/panel\/nodes\/add\?error=/);
    assert.equal(rows.length, 3);
    assert.match((await create('notify')).location, /^\/panel\/nodes\/[a-f0-9]{24}$/);
    assert.equal(rows[3].cascadeRole, 'standalone');
    assert.equal(rows[3].xray.realityGuard.mode, 'notify');
});

test('HTTP and MCP create/update expose only off and notify and never push a guard-only edit', async () => {
    reset();
    const xray = { security: 'reality', realityDest: publicDest, apiPort: 61003 };
    const api = (data, method = 'POST', id) => request('/api/nodes' + (id ? '/' + id : ''), { method, data });
    const callMcp = (data, action = 'create', id) => mcp.manageNode({ action, id: id?.toString(), data });
    const data = { name: 'API node', type: 'xray', ip: '198.51.100.70', xray };
    const withMode = mode => ({ xray: { realityGuard: { mode } } });
    for (const [create, ip] of [[api, '198.51.100.70'], [callMcp, '198.51.100.71']]) {
        await create({ ...data, ip });
        assert.equal(rows.at(-1).xray.realityGuard.mode, 'off');
    }
    const [httpNode, mcpNode] = rows;
    const auto = { ...data, ip: '198.51.100.72', xray: { ...xray, ...withMode('auto').xray } };
    for (const res of [await api(auto), await api(withMode('auto'), 'PUT', httpNode._id)]) {
        assert.equal(res.code, 400);
        assert.match(JSON.parse(res.body).error, /cc-agent 1\.5\.1/);
    }
    assert.equal((await api({ xray: { 'realityGuard.mode': 'auto' } }, 'PUT', httpNode._id)).code, 400);
    assert.equal((await api({ [prefix + 'mode']: 'auto' }, 'PUT', httpNode._id)).code, 400);
    await assert.rejects(callMcp(auto), /off.*notify/);
    await assert.rejects(callMcp(withMode('auto'), 'update', mcpNode._id), /off.*notify/);
    assert.equal(rows.length, 2);
    assert.deepEqual(writes, []);
    assert.equal((await api(withMode('notify'), 'PUT', httpNode._id)).code, 200);
    assert.equal((await callMcp(withMode('notify'), 'update', mcpNode._id)).success, true);
    assert.deepEqual(rows.map(row => row.xray.apiPort), [61003, 61003]);
    assert.deepEqual(rows.map(row => row.xray.realityGuard.mode), ['notify', 'notify']);
    assert.deepEqual(writes, Array(2).fill({ $set: { [prefix + 'mode']: 'notify' } }));
    assert.deepEqual(pushes, []);
    const unused = { xray: { realityGuard: { allowedCidr: 'irrelevant', reserveSnis: ['unused.invalid'], status: 'dead' } } };
    assert.equal((await api(unused, 'PUT', httpNode._id)).code, 200);
    assert.equal((await callMcp(unused, 'update', mcpNode._id)).success, true);
    assert.equal(writes.length, 2);
});

test('wizard inserts off; reusing a historical card leaves no policy', async () => {
    reset({ ...legacy, _id: id });
    const wizard = ip => request('/panel/wizard/self-host', { form: { installXray: 'on', 'ssh.ip': ip, 'ssh.password': 'synthetic-fixture-value' } });
    assert.match((await wizard(legacy.ip)).location, /^\/panel\/wizard\/progress\//);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].xray.realityGuard, undefined);
    assert.match((await wizard('192.0.2.76')).location, /^\/panel\/wizard\/progress\//);
    assert.equal(rows[1].xray.realityGuard.mode, 'off');
});

const storedWatchState = {
    mode: 'notify', status: 'dead', lastCheckAt: new Date('2025-01-22T13:45:00Z'),
    lastError: 'old.invalid: cert_expired', warning: 'old.invalid: no_h2', failCount: 3,
    lastRotatedAt: new Date('2025-01-21T13:45:00Z'), lastRotatedFrom: 'previous.invalid:443', lastRotatedTo: 'old.invalid:443',
};
test('monitor observations reach the actual form and list, not stored telemetry', async () => {
    const { createRealityGuard } = require('../../services/realityGuardService');
    const other = (suffix, cascadeRole, security, mode) => ({ ...legacy, active: true, cascadeRole,
        _id: new mongoose.Types.ObjectId('507f1f77bcf86cd7994390' + suffix), ip: `192.0.2.${suffix}`,
        xray: { security, realityDest: publicDest, realityGuard: { ...storedWatchState, mode } } });
    const extra = { id: 'fixture-extra', port: 8443, inboundTag: 'fixture-extra', security: 'reality',
        realityDest: publicDest, realitySni: ['www.google.com'], realityPrivateKey: 'fixture-not-a-key' };
    reset({ ...other('11', 'standalone', 'none', 'notify'), ip: '93.184.216.10', createdAt: new Date(1),
        xray: { security: 'reality', realityDest: '[::1]:443', extraInbounds: [extra], realityGuard: storedWatchState } },
    other('12', 'relay', 'reality', 'notify'), other('13', 'bridge', 'reality', 'notify'),
    other('14', 'portal', 'none', 'notify'), other('15', 'portal', 'reality', 'off'));
    settingsRows[0].realityGuard = { enabled: true };
    const before = bson(rows);
    const read = () => {
        const row = bson(rows[0]);
        delete row.xray.extraInbounds[0].port;
        delete row.xray.extraInbounds[0].inboundTag;
        delete row.xray.extraInbounds[0].realityPrivateKey;
        return row;
    };
    let state = 'failed', confirmations = 0, notifications = 0, checked = Date.now() - 10_000;
    const monitor = createRealityGuard({ listNodes: async () => [read()], readNode: async () => read(),
        isGloballyEnabled: async () => settingsRows[0].realityGuard.enabled,
        isBusy: async () => false, isClientProfile: async () => true, now: () => checked,
        panelProbe: async () => ({ state, ip: '93.184.216.20', reason: 'cert_expired' }),
        withNodeProbe: async (_node, work) => { confirmations++; return work(async () => ({ state: 'failed', reason: 'cert_expired' })); },
        notify: async () => { notifications++; }, // No webhook configured: never admits a POST.
    });
    async function rendered(status, key, lang = 'en', count) {
        const page = await request(nodePath, { lang });
        assert.equal(page.code, 200);
        const form = widget(page.body);
        const text = t(lang, 'nodes.realityGuard' + key).replace('{n}', count).replace('{max}', 3);
        assert.ok(form.includes(text), `${status}: ${text}`);
        assert.equal(form.includes(t(lang, 'nodes.realityGuardLastCheck')), status !== 'not_checked');
        assert.doesNotMatch(form, /(?:old|previous)\.invalid/);
        const list = await request('/panel/nodes', { lang });
        assert.equal(list.code, 200);
        assert.deepEqual([...list.body.matchAll(/data-reality-guard-badge="([^"]+)"/g)].map(m => m[1]), [status]);
        assert.ok(list.body.includes(text));
        return form;
    }
    try {
        await rendered('not_checked', 'NotChecked');
        await monitor.checkAll();
        await rendered('failing', 'StatusFailing', 'en', 1);
        await monitor.checkAll();
        await rendered('failing', 'StatusFailing', 'en', 2);
        await monitor.checkAll();
        assert.equal(confirmations, 1);
        assert.equal(notifications, 1);
        for (const lang of ['ru', 'en', 'zh-CN']) {
            translated(await rendered('dead', 'StatusDead', lang), lang, 'nodes.realityGuardReason.cert_expired');
        }
        state = 'unknown';
        await monitor.checkAll();
        await rendered('unknown', 'StatusUnknown');
        state = 'healthy';
        checked += 1000;
        await monitor.checkAll();
        await rendered('ok', 'StatusOk');
        for (const key of ['ip', 'cascadeRole', 'createdAt']) {
            const old = rows[0][key];
            rows[0][key] = { ip: '93.184.216.11', cascadeRole: 'portal', createdAt: new Date(2) }[key];
            await rendered('not_checked', 'NotChecked');
            rows[0][key] = old;
        }
        rows[0].xray.extraInbounds[0].realitySni = ['changed.example'];
        await rendered('not_checked', 'NotChecked');
        rows[0].xray.extraInbounds[0].realitySni = extra.realitySni;
        rows[0].name = 'Cosmetic rename';
        await rendered('ok', 'StatusOk');
        rows[0].name = before[0].name;
        settingsRows[0].realityGuard.enabled = false;
        assert.doesNotMatch((await request('/panel/nodes')).body, /data-reality-guard-badge/);
        await monitor.checkAll();
        settingsRows[0].realityGuard.enabled = true;
        await rendered('not_checked', 'NotChecked');
        checked -= 25 * 60 * 60 * 1000;
        await monitor.checkAll();
        await rendered('not_checked', 'NotChecked');
        assert.deepEqual(rows, before);
        assert.deepEqual(writes, []);
        assert.deepEqual(pushes, []);
    } finally { await monitor.drain(); }
});

test('server gating prevents policy changes on non-client cards; create UI tracks destination edits', async () => {
    for (const [role, security, available] of [['relay', 'reality', false], ['bridge', 'reality', false],
        ['standalone', 'none', false], ['portal', 'none', true]]) {
        reset({ ...legacy, _id: id, cascadeRole: role, xray: { security, ...(available ? { extraInbounds: [
            { id: 'extra', port: 8443, inboundTag: 'extra-in', security: 'reality', realityDest: publicDest },
        ] } : {}) } });
        const page = await request(nodePath);
        assert.equal(page.code, 200);
        const guard = widget(page.body);
        assert.equal(!!guard && !/<fieldset[^>]*disabled/.test(guard), available);
        if (!available) {
            const policy = { xray: { realityGuard: { mode: 'notify' } } };
            const post = await request(nodePath + '/reality-guard', { form: { _csrf: token(page.body), [prefix + 'mode']: 'notify' } });
            assert.match(post.location, /\?error=/);
            assert.equal((await request('/api/nodes/' + id, { method: 'PUT', data: policy })).code, 400);
            assert.equal((await mcp.manageNode({ action: 'update', id: String(id), data: policy })).code, 400);
            assert.equal(rows[0].xray.realityGuard, undefined);
            assert.deepEqual(writes, []);
            assert.deepEqual(pushes, []);
        }
    }
    reset({ ...legacy, _id: id, type: 'hysteria' });
    const html = (await request('/panel/nodes/add?cloneFrom=' + id, { lang: 'ru' })).body;
    const guard = widget(html);
    assert.deepEqual([...guard.matchAll(/<strong>(Выключено|Только уведомлять|Автозамена)<\/strong>/g)].map(m => m[1]),
        ['Выключено', 'Только уведомлять', 'Автозамена']);
    assert.doesNotMatch(guard, /<details[^>]*\bopen\b/);
    const script = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).find(s => s.includes('function updateRealityGuardUI('));
    const start = script.includes('const realityGuardDests =') ? script.indexOf('const realityGuardDests =') : script.indexOf('function updateRealityGuardUI(');
    const end = script.indexOf('function updateXraySecurityUI(', start);
    const listeners = {};
    const modes = ['off', 'notify', 'auto'].map(value => ({ value }));
    for (const mode of modes) Object.defineProperty(mode, 'checked', {
        get: () => modes.chosen === mode.value, set: value => { if (value) modes.chosen = mode.value; },
    });
    modes.chosen = 'off';
    const hints = ['local', 'mixed', 'unknown'].map(kind => ({ dataset: { rgHint: kind } }));
    const advanced = {};
    const fieldset = { form: { id: 'nodeForm' }, dataset: { selectedMode: 'off' }, disabled: false,
        querySelectorAll: key => key === '[data-rg-hint]' ? hints : key === '[data-rg-public]' ? [advanced] : modes };
    const main = { id: 'xrayRealityDest', value: '[::1]:443' };
    const fields = { xrayRealityGuardGroup: fieldset, cascadeRole: { value: 'portal' }, xraySecurity: { value: 'reality' },
        xrayRealityDest: main, nodeForm: { addEventListener: (name, cb) => { listeners[name] = cb; } } };
    const protocol = { value: 'xray' };
    const dest = { name: 'xray_extra_realityDest', value: 'unix:/run/reality.sock' };
    const extra = { querySelector: sel => sel.includes('security') ? { value: 'reality' } : dest };
    const extras = [extra];
    const context = vm.createContext({ URL, document: { getElementById: id => fields[id], querySelector: () => protocol,
        querySelectorAll: () => extras } });
    vm.runInContext(script.slice(start, end), context);
    function state({ disabled, hidden = false, hint = null, mode = 'off' }) {
        assert.equal(fieldset.disabled, disabled);
        assert.equal(fieldset.hidden, hidden);
        assert.equal(advanced.hidden, disabled);
        assert.equal(modes.chosen, mode);
        assert.deepEqual(hints.filter(h => !h.hidden).map(h => h.dataset.rgHint), hint ? [hint] : []);
    }
    const refresh = () => vm.runInContext('updateRealityGuardUI()', context);
    refresh(); state({ disabled: true, hint: 'local' });
    dest.value = publicDest;
    listeners.input({ target: dest }); state({ disabled: false, hint: 'mixed' });
    modes.chosen = 'notify';
    extras.pop(); // removeExtraInbound calls updateXraySecurityUI, which refreshes the guard
    refresh(); state({ disabled: true, hint: 'local' });
    main.value = 'malformed';
    listeners.input({ target: main }); state({ disabled: true, hint: 'unknown' });
    main.value = '[2606:4700::1111]:443';
    listeners.input({ target: main }); state({ disabled: false, mode: 'notify' });
    extras.push(extra); main.value = '[::1]:443';
    refresh(); state({ disabled: false, hint: 'mixed', mode: 'notify' });
    fields.cascadeRole.value = 'relay';
    refresh(); state({ disabled: true, hidden: true });
});

test('saved public extra permits notify but a concurrent target or role change blocks the write', async () => {
    const extra = { id: 'extra', port: 8443, inboundTag: 'extra-in', security: 'reality', realityDest: publicDest };
    const node = { ...legacy, _id: id, cascadeRole: 'portal', xray: { security: 'none', extraInbounds: [extra] } };
    const driver = HyNode.collection.collection;
    const original = driver.findOneAndUpdate;
    for (const change of [null, row => { row.role = 'relay'; }, row => { row.xray.extraInbounds[0].realityDest = 'localhost:443'; }]) {
        reset(node);
        const { action, csrf } = guardForm((await request(nodePath)).body);
        driver.findOneAndUpdate = function(...args) {
            change?.(rows[0]);
            return original.apply(this, args);
        };
        try {
            const saved = await request(action, { form: { _csrf: csrf, [prefix + 'mode']: 'notify' } });
            assert.equal(saved.code, change ? 409 : 302);
        } finally { driver.findOneAndUpdate = original; }
        assert.equal(rows[0].xray.realityGuard?.mode, change ? undefined : 'notify');
        assert.equal(writes.length, change ? 0 : 1);
        assert.deepEqual(pushes, []);
    }
});

test('Security card persists only its setting and renders a paused state across reload', async () => {
    reset({ ...legacy, _id: id, xray: { realityGuard: storedWatchState } });
    const url = '/panel/settings?tab=security';
    const lang = 'zh-CN';
    const initial = await request(url, { lang });
    assert.equal(initial.code, 200, initial.body);
    const card = html => html.match(/<form method="POST" action="\/panel\/settings\/reality-guard">[\s\S]*?<\/form>/)?.[0];
    const control = /name="realityGuard\.enabled" checked/;
    translated(card(initial.body), lang, 'settings.realityGuardEnabled');
    assert.doesNotMatch(card(initial.body), control);
    for (const enabled of ['true', 1, 'on', null, false, true]) {
        settingsRows[0].realityGuard = { enabled };
        assert.equal(control.test(card((await request(url, { lang })).body)), enabled === true, String(enabled));
    }
    assert.equal(writes.length, 0);
    const path = '/panel/settings/reality-guard';
    assert.equal((await request(path, { form: {} })).code, 403);
    const saved = await request(path, { form: { _csrf: token(card(initial.body)), 'homepage.mode': 'nginx' }, lang });
    assert.equal(saved.code, 302);
    assert.match(saved.location, /tab=security/);
    assert.equal(settingsRows[0].realityGuard.enabled, false);
    assert.deepEqual(settingsRows[0].homepage, { mode: 'custom' });
    assert.deepEqual(settingsRows[0].webhook, { enabled: true });
    const off = await request(url, { lang });
    assert.doesNotMatch(card(off.body), control);
    translated(widget((await request(nodePath, { lang })).body), lang, 'nodes.realityGuardPaused');
    assert.doesNotMatch((await request('/panel/nodes')).body, /data-reality-guard-badge/);
    assert.equal((await guardRead()).status, 'dead');
    await request(path, { form: { _csrf: token(card(off.body)), 'realityGuard.enabled': 'on' } });
    assert.equal(settingsRows[0].realityGuard.enabled, true);
    assert.deepEqual(writes.map(write => write.$set), [false, true].map(enabled => ({ 'realityGuard.enabled': enabled })));
    settingsRows.length = 0;
    await request(path, { form: { _csrf: token(card(off.body)), 'realityGuard.enabled': 'on' } });
    assert.deepEqual(Object.keys(settingsRows[0]).filter(key => key !== '__v').sort(), ['_id', 'realityGuard']);
    assert.deepEqual(pushes, []);
});

test('guard locale leaves are explicit and placeholders match in all three source files', () => {
    function leaves(obj, prefix) {
        return Object.entries(obj).flatMap(([key, value]) => typeof value === 'string'
            ? [[prefix + key, value]] : leaves(value, prefix + key + '.'));
    }
    const guardStrings = lang => {
        const locale = require(`../../locales/${lang}.json`);
        return Object.fromEntries(['nodes', 'settings'].flatMap(scope => leaves(locale[scope], scope + '.')
            .filter(([key]) => key.startsWith(scope + '.realityGuard'))));
    };
    const expected = guardStrings('en');
    assert.ok(Object.keys(expected).length >= 30);
    for (const lang of ['ru', 'zh-CN']) {
        const localized = guardStrings(lang);
        assert.deepEqual(Object.keys(localized).sort(), Object.keys(expected).sort());
        for (const [key, source] of Object.entries(expected)) {
            const placeholders = text => (text.match(/\{\w+\}/g) || []).sort();
            assert.deepEqual(placeholders(localized[key]), placeholders(source), key);
        }
    }
});

const localDestinations = ['localhost:443', 'localhost.:443', 'node.localhost:443', '127.1.2.3:443', '10.1.2.3:443', '172.31.1.2:443', '192.168.1.2:443',
    '[::1]:443', '[0:0:0:0:0:0:0:1]:443', '[fd00::1]:443', '[fe80::abcd%eth0]:443',
    '[::ffff:192.168.1.2]:443', '/run/reality.sock', 'unix:///run/reality.sock', '/run/reality socket', '@reality'];
const otherDestinations = ['', 'garbled', 'www.example.invalid:0', '[broken]:443', '192.0.2.42:443'];
const publicDestinations = [publicDest, '93.184.216.34:443', '[2606:4700::1111]:443'];

test('all-local cards show the exact label and disabled controls, with no list badge; invalid is distinct', async () => {
    for (const dest of [...localDestinations, ...otherDestinations]) {
        const xray = { security: 'reality', realityDest: dest, realityGuard: storedWatchState };
        reset({ ...legacy, _id: id, active: true, xray });
        settingsRows[0].realityGuard = { enabled: true };
        const form = widget((await request(nodePath, { lang: 'ru' })).body);
        assert.match(form, /<fieldset[^>]*disabled/, dest);
        const local = /<p[^>]*data-rg-hint="local"(?![^>]*hidden)[^>]*>Сайт-заглушка на самой ноде — проверка не нужна<\/p>/;
        assert.equal(local.test(form), localDestinations.includes(dest), dest);
        const list = await request('/panel/nodes', { lang: 'ru' });
        assert.equal(list.code, 200);
        assert.doesNotMatch(list.body, /data-reality-guard-badge/, dest);
    }
});

test('a public extra makes a local main eligible and target edits never persist check telemetry', async () => {
    const extra = { id: 'extra', port: 8443, inboundTag: 'extra-in', security: 'reality', realityDest: publicDest };
    const xray = { security: 'reality', realityDest: '[::1]:443', realityGuard: storedWatchState, extraInbounds: [extra] };
    reset({ ...legacy, _id: id, active: true, xray });
    settingsRows[0].realityGuard = { enabled: true };
    const page = await request(nodePath, { lang: 'ru' });
    assert.equal(page.code, 200);
    const form = widget(page.body);
    assert.doesNotMatch(form, /<fieldset[^>]*disabled/);
    assert.match(form, /data-rg-hint="mixed"(?![^>]*hidden)/);
    assert.match((await request('/panel/nodes')).body, /data-reality-guard-badge="not_checked"/);
    const changed = { ...baseForm, _csrf: token(page.body), 'xray.realityDest': '127.0.0.1:443',
        xray_extra_id: 'extra', xray_extra_port: '8443', xray_extra_tag: 'extra-in', xray_extra_security: 'reality',
        xray_extra_realityDest: publicDest, xray_extra_realitySni: 'www.google.com' };
    assert.equal((await request(nodePath, { form: changed })).location, '/panel/nodes');
    assert.equal(rows[0].xray.realityGuard.status, 'dead');
    assert.equal(rows[0].xray.realityDest, '127.0.0.1:443');
    changed.xray_extra_realityDest = '[fd00::1]:443';
    assert.equal((await request(nodePath, { form: changed })).location, '/panel/nodes');
    assert.equal(rows[0].xray.extraInbounds[0].realityDest, '[fd00::1]:443');
    assert.deepEqual(rows[0].xray.realityGuard, storedWatchState);
    assert.ok(writes.every(update => Object.keys(update.$set || {}).every(key => !key.startsWith(prefix))));
    assert.doesNotMatch((await request('/panel/nodes')).body, /data-reality-guard-badge/);
});

test('runtime global read is projected, strictly boolean, read-only, and fails closed', async () => {
    reset();
    const { isGloballyEnabled } = require('../../models/realityGuardPolicy');
    assert.equal(typeof isGloballyEnabled, 'function');
    const data = Settings.collection.collection;
    const original = data.findOne;
    let reads = 0;
    data.findOne = async (filter, options) => {
        reads++;
        assert.deepEqual(filter, { _id: 'settings' });
        assert.deepEqual(options.projection, { _id: 0, 'realityGuard.enabled': 1 });
        return original.call(data, filter, options);
    };
    try {
        for (const enabled of ['true', 1, 'on', null, false, true]) {
            settingsRows[0].realityGuard = { enabled };
            assert.equal(await isGloballyEnabled(), enabled === true, String(enabled));
        }
        assert.equal(await isGloballyEnabled(), true);
        settingsRows.length = 0;
        assert.equal(await isGloballyEnabled(), false);
        assert.equal(reads, 8);
        assert.equal(writes.length, 0);
        assert.equal(settingsRows.length, 0);
        data.findOne = async () => { throw new Error('fixture read failed'); };
        assert.equal(await isGloballyEnabled(), false);
    } finally { data.findOne = original; }
});


test('browser destination syntax agrees with the service; mixed targets exclude all non-public inbounds', () => {
    const { parseDest, collectRealityTargets } = require('../../services/realityGuardService');
    const { classifyRealityGuardDest, summarizeRealityGuardDests } = require('../../models/realityGuardDest');
    const boundaries = ['0.0.0.1:443', '100.63.255.255:443', '100.64.0.0:443', '100.127.255.255:443',
        '100.128.0.0:443', '192.0.0.0:443', '192.88.99.255:443', '198.18.255.255:443', '224.0.0.1:443',
        '01.2.3.4:443', '999.2.3.4:443', 'host.local:443', 'web.internal:443', 'www.example.com.:443',
        '[2000::]:443', '[2001:1ff::]:443', '[2001:200::]:443', '[2001:db8::1]:443', '[2002::]:443',
        '[2003::]:443', '[3fff:fff::]:443', '[3fff:1000::]:443', '[4000::]:443', '[2606::1%eth0]:443',
        '[::ffff:93.184.216.34]:443', 'site.example:65536', 'site.example:65535', 'site.example:00001', ' website.example:443'];
    for (const dest of [...localDestinations, ...otherDestinations, ...publicDestinations, ...boundaries]) {
        assert.equal(classifyRealityGuardDest(dest) === 'public', !!parseDest(dest), dest);
        assert.equal(classifyRealityGuardDest(dest, parseDest), classifyRealityGuardDest(dest), dest);
    }
    assert.equal(summarizeRealityGuardDests(['[::1]:443', 'garbled']), 'unknown');
    const reality = realityDest => ({ security: 'reality', realityDest, realitySni: ['site.example'] });
    const xray = { ...reality('[::1]:443'), extraInbounds: [reality('garbled'), reality(publicDest),
        { ...reality('other.example:443'), security: 'tls' }] };
    assert.deepEqual(collectRealityTargets(xray).map(target => target.dest), [publicDest]);
});

test('API replacement of unrelated Xray fields does not backfill missing legacy policy', async () => {
    reset({ ...legacy, _id: id, xray: { security: 'reality', realityDest: publicDest } });
    const result = await request('/api/nodes/' + id, { method: 'PUT', data: { xray: { security: 'reality',
        realityDest: publicDest, apiPort: 61004 } } });
    assert.equal(result.code, 200, result.body);
    assert.equal(rows[0].xray.apiPort, 61004);
    assert.equal(rows[0].xray.realityGuard, undefined);
});
