'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const mongoose = require('mongoose');
const { request } = require('./helpers/rebuildPanelRequest');
const { issuePanelCsrfToken } = require('../../routes/panel/csrf');
const { makeLocks } = require('../rebuildLocks');

const id = 'a'.repeat(24), portal = 'b'.repeat(24), linkId = 'c'.repeat(24);
const blocked = 'REBUILD_L2TP_ACCOUNTS_BLOCKED';
const unavailable = 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE';
const panelRelay = `/panel/rebuild/relays/${id}/l2tp`;
const expectedPreview = 'd'.repeat(64);
const query = value => ({ select() { return this; }, sort() { return this; }, read() { return this; },
    readConcern() { return this; }, maxTimeMS() { return this; }, limit() { return this; },
    lean: async () => value, populate: async () => value });

test('pending relay-account intent fences public Install, confirmed Remove, Apply, drafts and role writes', { timeout: 5000 }, async t => {
    t.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());
    const machine = 'e'.repeat(32);
    for (const [key, value] of Object.entries({ C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
        C3_REBUILD_L2TP_RELAY_ID: id, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machine })) {
        const previous = process.env[key];
        process.env[key] = value;
        t.after(() => { if (previous === undefined) delete process.env[key]; else process.env[key] = previous; });
    }
    const Node = require('../../models/hyNodeModel');
    const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
    const User = require('../../modules/relay-l2tp/models/l2tpUserModel');
    const Link = require('../../models/cascadeLinkModel');
    const sync = require('../syncService');
    const cache = require('../cacheService');
    const Settings = require('../../models/settingsModel');
    const serviceModule = require('../rebuildService');
    const now = new Date();
    const node = { _id: id, name: 'Fixture relay', cascadeRole: 'relay', type: 'xray', active: true, ip: '192.0.2.30' };
    let state = { _id: '1'.repeat(24), node: id, status: 'installed', desiredState: 'installed',
        routingMode: 'follow-relay', routingVersion: 1, rebuildMachineId: machine,
        rebuildInstallToken: '00000000-0000-4000-8000-000000000001', backupId: 'fixture-backup',
        secretRevision: 1, pskEncrypted: 'dummy-psk', clientCidr: '10.255.0.0/24', poolStart: '10.255.0.10',
        tproxyPort: 20110, fwmark: 400, routeTable: 400, installedAt: now, lastVerifiedAt: now, lastSyncAt: now };
    const account = { _id: '2'.repeat(24), relayNode: id, login: 'relay-bootstrap', enabled: true, ip: state.poolStart,
        passwordEncrypted: 'dummy-password', desiredRevision: 1, appliedRevision: 1, syncStatus: 'synced',
        createdAt: now, updatedAt: now, lastSyncedAt: now };
    const draft = { name: 'Fixture link', portalNodeId: portal, bridgeNodeId: id, tunnelSecurity: 'none', tunnelPort: 22222, priority: 1 };
    const savedLink = new Link({ _id: linkId, ...draft, portalNode: portal, bridgeNode: id });
    const effects = [], lockEvents = [];
    let held = null, pending = null, onRoleWrite, loseLock = false;
    const record = event => { effects.push(event); };
    const lockStore = {
        async insertOne(row) {
            assert.equal(row._id, 'apply');
            if (held) { lockEvents.push('busy'); throw Object.assign(new Error('fixture contention'), { code: 11000 }); }
            lockEvents.push('acquire');
            held = row;
        },
        async findOne(filter) {
            assert.deepEqual(filter, { _id: 'apply', token: held?.token });
            lockEvents.push('verify');
            return loseLock && lockEvents.includes('intent') ? null : held;
        },
        async deleteMany(filter) {
            assert.deepEqual(filter, { _id: 'apply', token: held?.token });
            lockEvents.push('release');
            held = null;
            return { acknowledged: true, deletedCount: 1 };
        },
    };
    const collection = mongoose.connection.collection.bind(mongoose.connection);
    t.mock.method(mongoose.connection, 'collection', (name, ...options) => {
        if (name === 'c3_rebuild_locks') return lockStore;
        if (name !== 'c3_rebuild_relay_accounts') return collection(name, ...options);
        return { async findOne(filter, options) {
            assert.ok(held, 'the pending read must occur under the actual Apply singleton');
            assert.equal(lockEvents.at(-1), 'verify', 'verify ownership before reading intent');
            assert.deepEqual(filter, { _id: 'pending' });
            assert.deepEqual(options, { readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000, projection: { _id: 1 } });
            lockEvents.push('intent');
            if (pending instanceof Error) throw pending;
            return pending;
        } };
    });
    t.mock.method(Settings, 'get', async () => ({ deployment: { completed: true } }));
    t.mock.method(Node, 'findById', () => ({ ...query({ ...node }),
        then: (resolve, reject) => Promise.resolve(Node.hydrate(node)).then(resolve, reject),
    }));
    t.mock.method(Node, 'find', () => { record('node inventory'); return query([{ ...node }, { _id: portal, cascadeRole: 'portal' }]); });
    t.mock.method(Node, 'findByIdAndUpdate', (_, update, options) => {
        record('role write');
        assert.ok(held);
        assert.equal(lockEvents.at(-1), 'verify');
        assert.equal(options.writeConcern.w, 'majority');
        return { select() { return this; }, async populate() {
            await onRoleWrite?.();
            Object.assign(node, update.$set);
            return { ...node };
        } };
    });
    t.mock.method(State, 'findOne', () => query(state));
    t.mock.method(User, 'find', () => query([account]));
    t.mock.method(User, 'countDocuments', () => ({ ...query(1), maxTimeMS: async () => 1 }));
    // Project a clean installed legacy Remove inventory, including no applied links.
    t.mock.method(Link, 'find', () => { record('link inventory'); return query([]); });
    t.mock.method(Link, 'findById', () => query(savedLink));
    t.mock.method(Link.prototype, 'save', async function () { record('draft save'); return this; });
    t.mock.method(Link, 'updateOne', async () => { record('link update'); return { matchedCount: 1 }; });
    t.mock.method(State, 'updateMany', async () => { record('state write'); return { matchedCount: 1 }; });
    t.mock.method(User, 'deleteMany', async () => { record('account delete'); return { deletedCount: 1 }; });
    t.mock.method(sync, 'schedulePush', () => record('push'));
    for (const method of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts']) {
        t.mock.method(cache, method, async () => {});
    }
    const service = serviceModule.createRebuildService({
        connect() { record('Apply driver'); assert.fail('unexpected fixture Apply transport'); },
        createRelayDirect() {
            record('relay driver');
            return { async readSessionCount() { record('Remove census'); return { activeSessions: 0, activeIpsec: 0, census: 'f'.repeat(64) }; },
                async close() { record('close'); } };
        },
    });
    // Stock panel selects this real service with only its I/O seams replaced.
    t.mock.method(serviceModule, 'createRebuildService', () => service);
    const panel = require('../../routes/panel');
    const { invalidateOnboardingCache } = require('../../routes/panel/helpers');
    const { issueRemovalTicket } = require('../../routes/panel/rebuildRelayRemove');
    const { routerForRebuild } = require('../../routes/cascadeRebuild');
    const requireAuth = require('../../middleware/auth');
    t.after(invalidateOnboardingCache);
    invalidateOnboardingCache();
    const app = express();
    app.use('/panel', panel);
    app.use('/api/cascade', requireAuth, routerForRebuild());
    app.use('/api/nodes', requireAuth, require('../../routes/nodes'));
    const session = { authenticated: true }, sessionID = 'fixture-session';
    const send = (url, body, method) => request(app, url, { method, session, sessionID, body,
        headers: { 'x-csrf-token': issuePanelCsrfToken({ session }) } });
    const previews = { expectedPreview };
    const apply = () => send(`/api/cascade/links/${linkId}/deploy`, previews);
    const role = () => send(`/api/nodes/${id}`, { cascadeRole: 'portal' }, 'PUT');
    const install = () => send(`${panelRelay}/install`, {});

    // Use actual Remove preview/proof before introducing the pending intent;
    // a fabricated ticket would be rejected before the account guard runs.
    const estimate = await service.previewRemoveRelay(id);
    assert.equal(estimate.confirmable, true);
    const ticket = issueRemovalTicket({ method: 'GET', session, sessionID, params: { id }, headers: {} }, estimate);
    assert.ok(ticket);
    assert.deepEqual(effects.splice(0), ['link inventory', 'relay driver', 'Remove census', 'close']);
    const remove = () => send(`${panelRelay}/remove`, { decision: 'confirm', ticket });
    const createLink = autoDeploy => send('/api/cascade/links', { ...draft, autoDeploy });
    const editLink = () => send(`/api/cascade/links/${linkId}`, { name: 'Edited fixture', autoDeploy: true }, 'PUT');
    const adverse = async (name, call, code = blocked, status = 409) => {
        lockEvents.length = 0;
        const response = await call();
        assert.equal(response.status, status, name);
        const body = JSON.parse(response.body);
        if (name === 'role') assert.equal(body.code, code);
        else if (name === 'Install') assert.deepEqual(body, { error: { code, outcome: code === blocked ? 'busy' : 'unknown' } }, name);
        else assert.deepEqual(body, { error: { code } }, name);
        assert.deepEqual(lockEvents, ['acquire', 'verify', 'intent', 'release'], name);
        assert.deepEqual(effects, [], name);
        assert.equal(held, null, name);
    };

    pending = { _id: 'pending' };
    for (const [name, action] of [
        ['Install', install], ['confirmed Remove', remove], ['link Apply', apply],
        ['unscoped Apply', () => send('/api/cascade/topology/deploy', previews)],
        ['link deletion', () => send(`/api/cascade/links/${linkId}`, previews, 'DELETE')],
        ['save-only draft', () => createLink(false)], ['auto-preview draft', () => createLink(true)],
        ['auto-preview edit', editLink], ['role', role],
    ]) await adverse(name, action);

    // Exercise execute's already-held entry directly: guarded public unscoped
    // Apply is refused at its outer lock, so it cannot reach this second check.
    const locks = makeLocks();
    lockEvents.length = 0;
    pending = null;
    await service.locks.run(async verify => {
        const original = held;
        pending = { _id: 'pending' };
        await assert.rejects(service.execute({ linkId, expectedPreview }, verify), { code: blocked });
        assert.equal(held, original, 'do not reacquire or unlock someone else’s Apply generation');
        assert.deepEqual(lockEvents, ['acquire', 'verify', 'intent', 'verify', 'verify', 'intent']);
    });
    assert.deepEqual(lockEvents, ['acquire', 'verify', 'intent', 'verify', 'verify', 'intent', 'release']);
    assert.deepEqual(effects, []);
    assert.equal(node.cascadeRole, 'relay');

    pending = new Error('dummy private database detail');
    await adverse('unreadable intent', apply, unavailable);
    await adverse('Install', install, unavailable);
    await adverse('role', role, unavailable);

    // Positive controls: the same draft can save, and a role mutation holds
    // the singleton THROUGH the business write, contending with real Apply.
    pending = null;
    // Loss after the pending read must not authorize the draft or role write.
    node.cascadeRole = 'bridge';
    state = null; // Positive controls do not carry a relay installation.
    loseLock = true;
    for (const [action, isRole] of [[() => createLink(false), false], [role, true]]) {
        lockEvents.length = 0;
        const refused = await action();
        assert.equal(refused.status, 409);
        const body = JSON.parse(refused.body);
        assert.equal(isRole ? body.code : body.error?.code, 'REBUILD_LOCK_LOST');
        assert.deepEqual(lockEvents, ['acquire', 'verify', 'intent', 'verify', 'release']);
        assert.deepEqual(effects, []);
    }
    loseLock = false;
    const saved = await createLink(false);
    assert.equal(saved.status, 200);
    assert.equal(JSON.parse(saved.body).desiredSaved, true);
    assert.deepEqual(effects.splice(0), ['node inventory', 'draft save']);
    await locks.run(async () => {
        const busy = await role();
        assert.equal(busy.status, 409);
        assert.equal(JSON.parse(busy.body).code, 'REBUILD_BUSY');
        assert.deepEqual(effects, []);
    });
    onRoleWrite = async () => {
        const busy = await apply();
        assert.equal(busy.status, 409);
        assert.deepEqual(JSON.parse(busy.body), { error: { code: 'REBUILD_BUSY' } });
        assert.equal(lockEvents.at(-1), 'busy');
    };
    assert.equal((await role()).status, 200);
    assert.equal(node.cascadeRole, 'portal');
    assert.deepEqual(effects, ['role write', 'push']);
    assert.equal(held, null);
});
