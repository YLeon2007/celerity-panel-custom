'use strict';

const assert = require('node:assert/strict');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const test = require('node:test');
const express = require('express');
const mongoose = require('mongoose');
const id = 'a'.repeat(24);
const fixtureId = new mongoose.Types.ObjectId(id);

function request(app, url, method, body = {}) {
    return new Promise((resolve, reject) => {
        const wire = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { wire.push(chunk.toString()); done(); } });
        const req = new IncomingMessage(socket);
        Object.assign(req, { method, url, headers: { host: 'panel.fixture.invalid' }, body, session: { authenticated: true } });
        req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            resolve({ status: res.statusCode, location: res.getHeader('location'), body: wire.join('').split('\r\n\r\n').slice(1).join('\r\n\r\n') });
            socket.destroy();
        });
        app(req, res);
    });
}

test('stock rebuild node form and direct role writers fence the persisted role and report only DB accounts', { timeout: 5000 }, async t => {
    const previous = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = 'true';
    t.after(() => { if (previous === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = previous; });
    const Node = require('../../models/hyNodeModel');
    const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
    const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
    const Group = require('../../models/serverGroupModel');
    const Link = require('../../models/cascadeLinkModel');
    const Settings = require('../../models/settingsModel');
    const cache = require('../cacheService');
    const sync = require('../syncService');
    const { t: translate } = require('../../middleware/i18n');
    const { makeLocks } = require('../rebuildLocks');
    const { createRebuildRelayBackend } = require('../rebuildRelayBackend');
    const { createPanelRouter } = require('../../routes/panel');
    const { invalidateOnboardingCache } = require('../../routes/panel/helpers');
    const requireAuth = require('../../middleware/auth');
    const { manageNode } = require('../../mcp/tools/nodes');
    t.after(() => require('../sshPoolService').closeAll());
    invalidateOnboardingCache();
    t.after(invalidateOnboardingCache);

    let held, state = { status: 'installed', desiredState: 'installed' }, accounts = 3, writes = 0, pushes = 0, reads = 0;
    const row = { _id: fixtureId, name: 'Relay fixture', ip: '192.0.2.10', active: true, type: 'xray',
        cascadeRole: 'relay', xray: { agentToken: 'fixture' } };
    const lockStore = {
        async insertOne(token) { if (held) throw Object.assign(new Error('busy fixture'), { code: 11000 }); held = token; },
        async findOne({ _id, token }) { return held?._id === _id && held.token === token ? held : null; },
        async deleteOne({ token }) { assert.equal(held.token, token); held = null; },
    };
    t.mock.method(mongoose.connection, 'collection', name => {
        assert.equal(name, 'c3_rebuild_locks');
        return lockStore;
    });
    t.mock.method(Settings, 'get', async () => ({ deployment: { completed: true } }));
    for (const method of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts']) {
        t.mock.method(cache, method, async () => {});
    }
    t.mock.method(sync, 'schedulePush', () => { pushes++; });
    const cursor = values => ({ toArray: async () => values });
    let onNodeRead, onPersist;
    for (const [model, collection] of [[Node, {
        async findOne(filter, options) {
            await onNodeRead?.(options);
            return String(filter._id) === id ? { ...row } : null;
        },
        find: () => cursor([]),
        async updateOne(_, update, options) { await persist(update, options); return { acknowledged: true, matchedCount: 1 }; },
        async findOneAndUpdate(_, update, options) { await persist(update, options); return { ...row }; },
    }], [State, {
        async findOne(filter, options) {
            assert.equal(String(filter.node), id);
            assert.equal(options.readConcern.level, 'majority');
            assert.equal(options.readPreference.mode, 'primary');
            reads++;
            if (state instanceof Error) throw state;
            return state;
        },
    }], [User, {
        async countDocuments(filter, options) {
            assert.deepEqual(filter, { relayNode: fixtureId });
            assert.equal(options.readConcern.level, 'majority');
            assert.equal(options.readPreference.mode, 'primary');
            if (accounts === null) throw new Error('private fixture database error');
            return accounts;
        },
    }], [Group, { find: () => cursor([]) }], [Link, { find: () => cursor([]) }]]) {
        const { buffer, collection: prior } = model.collection;
        model.collection.buffer = false;
        model.collection.collection = collection;
        t.after(() => { model.collection.buffer = buffer; model.collection.collection = prior; });
    }

    async function persist(update, options) {
        await onPersist?.(update, options);
        writes++;
        Object.assign(row, update.$set);
    }
    const app = express();
    app.use((req, res, next) => {
        res.locals.t = key => translate(key, 'ru');
        res.locals.lang = 'ru';
        res.render = (view, data) => { assert.equal(view, 'layout'); res.send(data.content); };
        next();
    });
    app.use('/panel', createPanelRouter());
    app.use('/api/nodes', requireAuth, require('../../routes/nodes'));
    const url = `/panel/nodes/${id}`;
    const api = `/api/nodes/${id}`;
    const body = { name: 'Relay fixture', type: 'xray', ip: row.ip, active: 'on' };
    const post = role => request(app, url, 'POST', { ...body, ...(role !== undefined && { cascadeRole: role }) });
    const put = role => request(app, api, 'PUT', { cascadeRole: role });

    for (const role of ['portal', 'bridge', 'standalone']) {
        const refused = await post(role);
        assert.equal(refused.status, 302);
        assert.match(decodeURIComponent(refused.location), /Сначала удалите L2TP: 3 учёток, сессии не подтверждены/);
    }
    const refused = await put('portal');
    assert.equal(refused.status, 409);
    assert.equal(JSON.parse(refused.body).accountCount, 3);
    assert.equal(JSON.parse(refused.body).activeSessions, null);
    assert.equal((await put(null)).status, 409, 'nullable REST update must not bypass the guard');
    assert.equal((await manageNode({ action: 'update', id, data: { cascadeRole: 'bridge' } })).code, 409);
    assert.equal(writes, 0);
    assert.equal(pushes, 0);
    assert.equal(row.cascadeRole, 'relay');

    const edit = await request(app, url, 'GET');
    assert.equal(edit.status, 200, edit.body.slice(0, 400));
    assert.match(edit.body, /Сначала удалите L2TP: 3 учёток, сессии не подтверждены/);
    assert.match(edit.body, /id="cascadeRole"[^>]+value="relay"[^>]+data-l2tp-role-blocked="true"/);
    assert.doesNotMatch(edit.body, /onclick="selectCascadeRole\('(portal|bridge|standalone)'|\/rebuild\/relays\/[^/]+\/l2tp\/remove/);
    accounts = null;
    assert.match(decodeURIComponent((await post('portal')).location), /число учёток не подтверждено, сессии не подтверждены/);
    assert.equal(writes, 0);
    accounts = 0; // A successful exact account count of zero is distinct from unavailable sessions.
    state = { status: 'installing', desiredState: 'installed' };
    assert.match(decodeURIComponent((await post('portal')).location), /0 учёток, сессии не подтверждены/);
    state = { status: 'not_installed', desiredState: 'installed' };
    assert.equal((await put('standalone')).status, 409);
    state = new Error('private fixture state error');
    assert.equal((await put('standalone')).status, 503);
    assert.equal(writes, 0);
    const before = reads;
    assert.equal((await post()).location, '/panel/nodes');
    assert.equal((await post('relay')).location, '/panel/nodes');
    assert.equal(reads, before);

    // Older rows without a persisted cascadeRole hydrate the schema default.
    // An unrelated edit must not write that default, even if another caller
    // promotes the node to relay after the form handler has read it.
    delete row.cascadeRole;
    onPersist = async update => {
        row.cascadeRole = 'relay'; // Concurrent promotion before the captured write.
        assert.equal(Object.hasOwn(update.$set, 'cascadeRole'), false);
    };
    const omittedLegacy = await request(app, url, 'POST', { ...body, name: 'Legacy fixture edit' });
    assert.equal(omittedLegacy.location, '/panel/nodes');
    assert.equal(row.cascadeRole, 'relay');
    onPersist = undefined;

    await makeLocks(lockStore).run(async () => {
        assert.match(decodeURIComponent((await post('portal')).location), /Повторите/);
        assert.equal((await put('bridge')).status, 409);
        assert.equal(row.cascadeRole, 'relay');
    });
    state = { status: 'not_installed', desiredState: 'absent' };
    const install = createRebuildRelayBackend({ Node, Link, State, L2tpUser: User, locks: makeLocks(lockStore),
        env: { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: id,
            C3_REBUILD_L2TP_RELAY_MACHINE_ID: 'b'.repeat(32) }, createRelayDirect: () => assert.fail('no transport') });
    onPersist = async (update, options) => {
        assert.equal(update.$set.cascadeRole, 'portal');
        assert.equal(options.writeConcern.w, 'majority');
        assert.ok(held, 'role write must retain the Apply lock through persistence');
        await assert.rejects(install(id), { code: 'REBUILD_BUSY' });
    };
    assert.equal((await post('portal')).location, '/panel/nodes');
    assert.equal(row.cascadeRole, 'portal');
    assert.equal(held, null);
    onPersist = null;
    await assert.rejects(install(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });

    row.cascadeRole = 'relay';
    state = { status: 'installing', desiredState: 'installed' };
    onNodeRead = async options => {
        // Install entered its fresh eligibility read under the shared lock.
        if (options.projection?.useCustomConfig !== 1) return;
        assert.ok(held);
        assert.match(decodeURIComponent((await post('portal')).location), /Повторите/);
        assert.equal((await put('bridge')).status, 409);
        assert.equal(row.cascadeRole, 'relay');
        row.useCustomConfig = true; // End fixture pre-dispatch, no driver or remote calls.
    };
    await assert.rejects(install(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
    assert.equal(row.useCustomConfig, true, 'real Install reached the fenced inventory');
    delete row.useCustomConfig;
    onNodeRead = undefined;
    state = null;
    assert.equal((await put('bridge')).status, 200);
    assert.equal(row.cascadeRole, 'bridge');
    row.cascadeRole = 'relay';
    state = { status: 'installed', desiredState: 'installed' };
    process.env.C3_REBUILD_ENABLED = 'false';
    assert.equal((await post('standalone')).location, '/panel/nodes');
    assert.equal(row.cascadeRole, 'standalone');
});
