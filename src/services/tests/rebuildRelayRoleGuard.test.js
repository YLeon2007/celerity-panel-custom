'use strict';

const assert = require('node:assert/strict');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const test = require('node:test');
const express = require('express');
const mongoose = require('mongoose');
const id = 'a'.repeat(24);
const fixtureId = new mongoose.Types.ObjectId(id);

const panelSession = { authenticated: true };
function request(app, url, method, body = {}, { session = panelSession, sessionID = 'fixture-session', headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const wire = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { wire.push(chunk.toString()); done(); } });
        const req = new IncomingMessage(socket);
        Object.assign(req, { method, url, headers: { host: 'panel.fixture.invalid', ...headers }, body, session, sessionID });
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

test('mounted role guard and Remove use one estimate, require a current session-bound confirmation, and preserve fences', { timeout: 8000 }, async t => {
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
    let account, removeWrites = 0, limit = 0, throttle = false;
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
        async updateMany(filter, update) {
            assert.ok(held);
            assert.equal(String(filter._id.$eq), String(state._id));
            state = { ...state, ...update.$set };
            for (const field of Object.keys(update.$unset ?? {})) delete state[field];
            removeWrites++;
            return { acknowledged: true, matchedCount: 1 };
        },
    }], [User, {
        async countDocuments(filter, options) {
            assert.deepEqual(filter, { relayNode: fixtureId });
            assert.equal(options.readConcern.level, 'majority');
            assert.equal(options.readPreference.mode, 'primary');
            if (accounts === null) throw new Error('private fixture database error');
            return accounts;
        },
        find(filter) {
            assert.deepEqual(filter, { relayNode: fixtureId });
            return cursor(account ? [account] : []);
        },
        async deleteMany(filter) {
            assert.ok(held);
            assert.equal(String(filter._id.$eq), String(account._id));
            account = null;
            accounts = 0;
            removeWrites++;
            return { acknowledged: true, deletedCount: 1 };
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
    app.use('/panel', createPanelRouter({
        l2tpRateLimiter(req, res, next) { limit++; return throttle ? res.status(429).end() : next(); },
    }));
    app.use('/api/nodes', requireAuth, require('../../routes/nodes'));
    const url = `/panel/nodes/${id}`;
    const api = `/api/nodes/${id}`;
    const body = { name: 'Relay fixture', type: 'xray', ip: row.ip, active: 'on' };
    const post = role => request(app, url, 'POST', { ...body, ...(role !== undefined && { cascadeRole: role }) });
    const put = role => request(app, api, 'PUT', { cascadeRole: role });

    for (const role of ['portal', 'bridge', 'standalone']) {
        const refused = await post(role);
        assert.equal(refused.status, 302);
        assert.match(decodeURIComponent(refused.location), /Учётные записи L2TP: 3; активные сессии PPP\/L2TP: не подтверждено/);
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
    assert.match(edit.body, /Учётные записи L2TP: 3; активные сессии PPP\/L2TP: не подтверждено/);
    assert.match(edit.body, /id="cascadeRole"[^>]+value="relay"[^>]+data-l2tp-role-blocked="true"/);
    assert.doesNotMatch(edit.body, /onclick="selectCascadeRole\('(portal|bridge|standalone)'|\/rebuild\/relays\/[^/]+\/l2tp\/remove/);
    accounts = null;
    assert.match(decodeURIComponent((await post('portal')).location), /Учётные записи L2TP: не подтверждено; активные сессии PPP\/L2TP: не подтверждено/);
    assert.equal(writes, 0);
    accounts = 0; // A successful exact account count of zero is distinct from unavailable sessions.
    state = { status: 'installing', desiredState: 'installed' };
    assert.match(decodeURIComponent((await post('portal')).location), /Учётные записи L2TP: 0; активные сессии PPP\/L2TP: не подтверждено/);
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
    const machine = 'b'.repeat(32), backupId = 'c'.repeat(32);
    const enrollment = { C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: id, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machine };
    for (const [key, value] of Object.entries(enrollment)) {
        const old = process.env[key];
        process.env[key] = value;
        t.after(() => { if (old === undefined) delete process.env[key]; else process.env[key] = old; });
    }
    const clock = new Date();
    const network = { clientCidr: '10.255.0.0/24', tproxyPort: 20110, fwmark: 400, routeTable: 400 };
    state = { ...network, _id: new mongoose.Types.ObjectId(), node: fixtureId, status: 'installed', desiredState: 'installed',
        routingMode: 'follow-relay', routingVersion: 1, rebuildMachineId: machine, rebuildInstallToken: '00000000-0000-4000-8000-000000000005',
        backupId, secretRevision: 1, pskEncrypted: 'fixture-psk', poolStart: '10.255.0.10', installedAt: clock, lastVerifiedAt: clock, lastSyncAt: clock };
    account = { _id: new mongoose.Types.ObjectId(), relayNode: fixtureId, enabled: true, ip: state.poolStart, login: 'relay-bootstrap',
        passwordEncrypted: 'fixture-password', desiredRevision: 1, appliedRevision: 1, syncStatus: 'synced', createdAt: clock,
        updatedAt: clock, lastSyncedAt: clock };
    accounts = 1;
    const validCensus = 'd'.repeat(64);
    let count = { activeSessions: 0, census: validCensus }, closeError = false, missingCounter = false;
    const events = [];
    t.mock.method(require('../rebuildRelayDirect'), 'createRelayDirect', ({ node }) => {
        events.push('create');
        assert.equal(String(node._id), id);
        assert.ok(held, 'read/confirm must hold the shared lock');
        const plan = {};
        return {
            ...(!missingCounter && { async readSessionCount(input) {
                events.push('count');
                assert.deepEqual(input, { nodeId: id, backupId, network });
                if (count instanceof Error) throw count;
                return count;
            } }),
            async prepareRemove() { events.push('prepare'); return plan; },
            async remove(proof, guard) {
                assert.equal(proof, plan);
                await guard();
                assert.equal(state.status, 'removing');
                events.push('remove');
                return true;
            },
            async close() { events.push('close'); if (closeError) throw Error('fixture cleanup refusal'); },
        };
    });
    const removeUrl = `/panel/rebuild/relays/${id}/l2tp/remove`;
    const submit = (ticket, decision = 'confirm', options, path = decision === 'cancel' ? `${removeUrl}/cancel` : removeUrl) => request(app, path, 'POST',
        { _csrf: panelSession.panelCsrfToken, ticket, decision }, options);
    const matchesCount = async (n, m) => {
        const form = await request(app, url, 'GET');
        assert.equal(form.status, 200, form.body.slice(0, 250));
        const text = `Учётные записи L2TP: ${n}; активные сессии PPP/L2TP: ${m}.`;
        assert.equal(form.body.split(text).length, 3, 'both strings must use exactly the same estimate');
        assert.doesNotMatch(form.body, new RegExp(`${validCensus}|fixture-psk|fixture-password|private fixture details`));
        const ticket = form.body.match(/name="ticket" value="([a-f0-9]{64})"/)?.[1];
        if (ticket) assert.ok(form.body.includes(`value="cancel" formaction="${removeUrl}/cancel"`));
        return ticket;
    };

    const beforeLimit = limit;
    assert.equal((await request(app, url, 'GET', {}, { session: null })).status, 302);
    assert.equal((await request(app, url, 'GET', {}, { headers: { 'sec-fetch-site': 'cross-site' } })).status, 200);
    assert.equal(limit, beforeLimit);
    throttle = true;
    assert.equal((await request(app, url, 'GET')).status, 429);
    throttle = false;
    assert.equal((await put('portal')).status, 409);
    assert.deepEqual(events, [], 'no driver on anonymous, limited, cross-site, or blocked role writes');

    count = { activeSessions: 3, census: validCensus };
    assert.equal(await matchesCount(1, 3), undefined);
    assert.deepEqual(events.splice(0), ['create', 'count', 'close']);
    accounts = 0;
    assert.equal(await matchesCount(0, 3), undefined, 'the two populations are independent');
    assert.deepEqual(events.splice(0), ['create', 'count', 'close']);
    accounts = 1;
    for (const refusal of [new Error('private fixture details'), { activeSessions: 0, census: 'F'.repeat(64) },
        { activeSessions: '0', census: validCensus }, { activeSessions: -1, census: validCensus }]) {
        count = refusal;
        assert.equal(await matchesCount(1, 'не подтверждено'), undefined);
        assert.deepEqual(events.splice(0), ['create', 'count', 'close']);
    }
    count = { activeSessions: 0, census: validCensus };
    accounts = null;
    assert.equal(await matchesCount('не подтверждено', 0), undefined, 'unavailable account count cannot be reconstructed from the session count');
    assert.deepEqual(events.splice(0), ['create', 'count', 'close']);
    accounts = 1;
    missingCounter = true;
    assert.equal(await matchesCount(1, 'не подтверждено'), undefined);
    assert.deepEqual(events.splice(0), ['create', 'close']);
    missingCounter = false;
    closeError = true;
    assert.equal(await matchesCount(1, 'не подтверждено'), undefined);
    assert.deepEqual(events.splice(0), ['create', 'count', 'close']);
    closeError = false;
    state.rebuildMachineId = 'e'.repeat(32);
    assert.equal(await matchesCount(1, 'не подтверждено'), undefined);
    assert.deepEqual(events, [], 'foreign machine does not connect');
    state.rebuildMachineId = machine;
    account.login = 'foreign';
    assert.equal(await matchesCount(1, 0), undefined, 'zero is not ownership');
    assert.deepEqual(events.splice(0), ['create', 'count', 'close']);
    account.login = 'relay-bootstrap';

    let ticket = await matchesCount(1, 0);
    assert.ok(ticket);
    assert.equal((await submit(ticket, 'confirm', { session: { ...panelSession }, sessionID: 'other' })).status, 409);
    assert.equal((await submit(ticket, 'confirm', {}, removeUrl.replace(id, 'f'.repeat(24)))).status, 409);
    assert.equal((await submit(ticket, 'cancel', {}, removeUrl)).status, 409, 'only confirm is accepted by the Remove route');
    assert.equal((await submit(ticket, 'cancel')).status, 303);
    assert.equal((await submit(ticket)).status, 409);
    assert.deepEqual(events.splice(0), ['create', 'count', 'close'], 'cancel did not even invoke confirmation');

    ticket = await matchesCount(1, 0);
    const advance = t.mock.method(performance, 'now', () => Number.MAX_SAFE_INTEGER);
    try { assert.equal((await submit(ticket)).status, 409); }
    finally { advance.mock.restore(); }
    assert.deepEqual(events.splice(0), ['create', 'count', 'close'], 'expired confirmation did not invoke the driver');

    ticket = await matchesCount(1, 0);
    account = { ...account, _id: new mongoose.Types.ObjectId() }; // same count, new ownership generation
    const replaced = await submit(ticket);
    assert.equal(replaced.status, 409);
    assert.deepEqual(JSON.parse(replaced.body), { error: { code: 'REBUILD_L2TP_REMOVE_PREVIEW_CHANGED' } });
    assert.deepEqual(events.splice(0), ['create', 'count', 'close'], 'a replacement account is refused before transport');

    ticket = await matchesCount(1, 0);
    const holdingApply = await makeLocks(lockStore).run(() => submit(ticket));
    assert.equal(holdingApply.status, 409);
    assert.deepEqual(JSON.parse(holdingApply.body), { error: { code: 'REBUILD_BUSY' } });
    assert.deepEqual(events.splice(0), ['create', 'count', 'close'], 'a busy Apply lock prevents a fresh census and removal');

    for (const [fresh, code] of [[{ activeSessions: 2, census: validCensus }, 'SESSIONS_BUSY'],
        [{ activeSessions: 0, census: 'e'.repeat(64) }, 'PREVIEW_CHANGED'], [Error('lost census'), 'COUNT_UNAVAILABLE']]) {
        count = { activeSessions: 0, census: validCensus };
        ticket = await matchesCount(1, 0);
        count = fresh;
        const denied = await submit(ticket);
        assert.equal(denied.status, 409);
        assert.deepEqual(JSON.parse(denied.body), { error: { code: `REBUILD_L2TP_REMOVE_${code}` } });
        assert.deepEqual(events.splice(0), ['create', 'count', 'close', 'create', 'count', 'close']);
    }
    assert.equal(removeWrites, 0);
    count = { activeSessions: 0, census: validCensus };
    ticket = await matchesCount(1, 0);
    const outcomes = await Promise.all([submit(ticket), submit(ticket)]);
    assert.deepEqual(outcomes.map(result => result.status).sort(), [200, 409]);
    assert.deepEqual(events, ['create', 'count', 'close', 'create', 'count', 'prepare', 'remove', 'close']);
    assert.equal(removeWrites, 3);
    assert.equal(state.status, 'not_installed');
    assert.equal(account, null);

    state = { status: 'installed', desiredState: 'installed' };
    process.env.C3_REBUILD_ENABLED = 'false';
    assert.equal((await post('standalone')).location, '/panel/nodes');
    assert.equal(row.cascadeRole, 'standalone');
});
