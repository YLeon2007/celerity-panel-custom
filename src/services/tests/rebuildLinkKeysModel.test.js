'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const mongoose = require('mongoose');
const Link = require('../../models/cascadeLinkModel');
const { prepareLinks, tunnelSettings } = require('../rebuildLinkKeys');

const FIELD = 'rebuildVlessKeyEnvelope';

test('real Mongoose casts guarded writes and excludes rebuild secrets from normal lean and serialized documents', async t => {
    const row = {
        _id: new mongoose.Types.ObjectId(), name: 'synthetic', active: true,
        portalNode: new mongoose.Types.ObjectId(), bridgeNode: new mongoose.Types.ObjectId(),
        tunnelUuid: 'synthetic-example', updatedAt: new Date(1000),
    };
    // Real Mongoose clones plain option objects, but not ClientSession instances.
    const session = new class MockClientSession {}();
    let guarded = false;
    const env = { ENCRYPTION_KEY: randomBytes(32).toString('hex') };
    function projected(options) {
        const result = { ...row };
        for (const [key, bit] of Object.entries(options.projection || {})) {
            if (bit === 0) delete result[key];
        }
        return result;
    }
    t.mock.method(Link.collection, 'find', (filter, options) => {
        assert.ok(!filter._id || filter._id.$in[0].equals(row._id), 'lookup was not cast to ObjectId');
        return { toArray: async () => [projected(options)] };
    });
    t.mock.method(Link.collection, 'findOne', async (filter, options) => {
        assert.ok(filter._id.equals(row._id), 'detail lookup was not cast to ObjectId');
        return projected(options);
    });
    t.mock.method(Link.collection, 'updateOne', async (filter, update, options) => {
        assert.ok(guarded && options.session === session, 'write was not guarded/in session');
        assert.ok(filter._id.equals(row._id) && filter[FIELD].$exists === false, 'invalid compare-and-set filter');
        assert.ok(Object.keys(update).join() === '$set' && Object.keys(update.$set).join() === FIELD,
            'cast update includes fields other than the envelope');
        row[FIELD] = update.$set[FIELD];
        return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
    });
    t.mock.method(Link.db, 'transaction', work => work(session));

    const [before] = await Link.find({}).lean();
    const prepared = await prepareLinks(Link, [before], { env });
    await prepareLinks(Link, prepared, { env, persist: true, verify: async () => { guarded = true; } });
    assert.ok(Object.hasOwn(row, FIELD), 'envelope was not persisted');
    const runtime = tunnelSettings(prepared[0]);
    const [revisited] = await prepareLinks(Link, [before], { env });
    assert.ok(tunnelSettings(revisited).decryption === runtime.decryption, 'stored key failed round trip');

    const doc = await Link.findById(String(row._id)).select(`+${FIELD}`);
    assert.ok(doc.get(FIELD) === row[FIELD], 'explicit private selection failed');
    doc.set('_rebuildVless', runtime);
    assert.ok(!doc.isModified('_rebuildVless'), 'runtime material is a persistent path');
    for (const result of [await Link.find({}).lean(), await Link.findById(row._id).lean(), doc, doc.toObject()]) {
        const json = JSON.stringify(result);
        assert.ok(!json.includes(FIELD) && !json.includes(row[FIELD]) && !json.includes('_rebuildVless')
            && !json.includes(runtime.decryption) && !json.includes(runtime.encryption), 'serialized link exposes a secret');
    }
});
