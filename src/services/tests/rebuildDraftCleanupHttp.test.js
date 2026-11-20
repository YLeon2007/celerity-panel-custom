'use strict';

process.env.PANEL_DOMAIN ||= 'panel.fixture.invalid';
process.env.ACME_EMAIL ||= 'local@fixture.invalid';
process.env.ENCRYPTION_KEY ||= '01234567890123456789012345678901';
process.env.SESSION_SECRET ||= '01234567890123456789012345678901';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const mongoose = require('mongoose');
const { fixture } = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const { issuePanelCsrfToken } = require('../../routes/panel/csrf');
const { routerForRebuild } = require('../../routes/cascadeRebuild');
const { createRebuildService } = require('../rebuildService');
const { makeLocks } = require('../rebuildLocks');
const { request } = require('./helpers/rebuildPanelRequest');

test('mounted rebuild drafts preserve the acknowledged write and primary refusal across Apply cleanup', async t => {
    const f = fixture();
    t.after(() => f.stop());
    await f.start();
    const { HyNode: Node, CascadeLink: Link } = f.models;
    const cards = ['portal', 'bridge'].map((cascadeRole, i) => ({ _id: new mongoose.Types.ObjectId(),
        cascadeRole, type: 'xray', active: true, name: cascadeRole, ip: `192.0.2.${i + 1}` }));
    await Node.collection.insertMany(cards);
    const store = f.connection.db.collection('c3_rebuild_locks');
    let fault, releases = 0;
    const release = method => async filter => {
        releases++;
        const row = await store.findOne({ _id: 'apply' });
        assert.deepEqual(filter, { _id: 'apply', token: row.token });
        if (fault === 'replacement') await store.updateOne(filter, { $set: { token: 'fixture-replacement' } });
        const result = await store[method](filter);
        if (fault === 'lost reply') throw Object.assign(new Error(`private database detail ${row.token}`), {
            code: 'REBUILD_PRIVATE_DB_DETAIL', preview: { token: row.token },
        });
        return result;
    };
    const locks = makeLocks({
        insertOne: store.insertOne.bind(store), findOne: store.findOne.bind(store),
        deleteMany: release('deleteMany'), deleteOne: release('deleteOne'),
    });
    const service = createRebuildService({ locks, env: { C3_REBUILD_ENABLED: 'true' },
        connect() { assert.fail('fixture must not open any node transport'); } });
    const app = express();
    app.use('/api/cascade', routerForRebuild({ service, Link, Node }));
    const session = { authenticated: true };
    const send = async (body, linkId) => {
        const response = await request(app, `/api/cascade/links${linkId ? `/${linkId}` : ''}`, { body, session,
            method: linkId ? 'PUT' : 'POST', headers: { 'x-csrf-token': issuePanelCsrfToken({ session }) } });
        return { status: response.status, body: JSON.parse(response.body) };
    };
    const draft = { name: 'created', portalNodeId: String(cards[0]._id), bridgeNodeId: String(cards[1]._id),
        tunnelSecurity: 'none', tunnelPort: 24001, priority: 1, autoDeploy: false };
    const cleanup = 'REBUILD_LOCK_RELEASE_UNCONFIRMED';
    const refused = (code, linkId, status = 409) => ({ status, body: { error: { code },
        ...(linkId ? { desiredSaved: true, linkId } : {}),
    } });

    fault = 'lost reply';
    assert.deepEqual(await send({ ...draft, tunnelPort: 0 }), refused('REBUILD_INVALID_REQUEST', undefined, 400));
    assert.equal(await Link.countDocuments(), 0);
    const created = await send(draft);
    const saved = await Link.findOne({ name: draft.name }).lean();
    assert.ok(saved);
    const linkId = String(saved._id);
    assert.deepEqual(created, refused(cleanup, linkId));
    assert.equal(await Link.countDocuments(), 1);
    assert.equal(await store.countDocuments(), 0, 'delete took effect even though its acknowledgement was lost');

    const save = Link.prototype.save;
    const lostSave = t.mock.method(Link.prototype, 'save', async function () {
        await save.call(this);
        throw new Error('private lost save acknowledgement');
    });
    assert.deepEqual(await send({ ...draft, name: 'unconfirmed save', tunnelPort: 24002 }), refused('REBUILD_FAILED'));
    assert.equal(await Link.countDocuments(), 2, 'an applied but unacknowledged write is not reported as known saved');
    lostSave.mock.restore();

    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const preview = { allowed: true, nodes: [], previewId: 'a'.repeat(64) };
    let previewError, rejectPreview = true;
    t.mock.method(service, 'execute', async (req, verify) => {
        assert.deepEqual(req, { linkId, preview: true });
        await verify();
        if (rejectPreview) throw previewError;
        return preview;
    });
    for (const [cause, code] of [
        [Object.freeze(Object.assign(new Error('private preview detail'), { code: 'REBUILD_LOCK_LOST' })), 'REBUILD_LOCK_LOST'],
        [Object.assign(new Error('private preview detail'), { code: 123, saved: 'not-an-acknowledged-id' }), 'REBUILD_FAILED'],
        [{ code: 'REBUILD_PREVIEW_CHANGED', preview: revoked.proxy }, 'REBUILD_PREVIEW_CHANGED'],
        [undefined, 'REBUILD_FAILED'],
        [revoked.proxy, 'REBUILD_FAILED'],
    ]) {
        previewError = cause;
        assert.deepEqual(await send({ name: 'edited', autoDeploy: true }, linkId), refused(code, linkId));
        assert.equal((await Link.findById(linkId).lean()).name, 'edited');
    }
    rejectPreview = false;
    fault = 'replacement';
    assert.deepEqual(await send({ name: 'previewed', autoDeploy: true }, linkId), refused(cleanup, linkId));
    assert.equal((await Link.findById(linkId).lean()).name, 'previewed');
    assert.equal((await store.findOne({ _id: 'apply' })).token, 'fixture-replacement');
    assert.equal(releases, 9);
    const deletes = f.commands.filter(command => command.name === 'delete' && command.collection === 'c3_rebuild_locks');
    assert.equal(deletes.length, releases);
    assert.ok(deletes.every(command => command.txnNumber === undefined), 'release is not a retryable MongoDB write');
});
