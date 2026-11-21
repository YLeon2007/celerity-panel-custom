'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { createHash } = require('node:crypto');
const { readFileSync, realpathSync } = require('node:fs');
const path = require('node:path');
const { request } = require('./helpers/rebuildPanelRequest');

// The image invocation never derives the runtime root from the mounted tests.
const image = process.env.C3_TELEMETRY_IMAGE === '1';
const root = image ? '/app' : path.resolve(__dirname, '../../..');
const runtime = createRequire(path.join(root, 'package.json'));
const express = runtime('express');
const mongoose = runtime('mongoose');
const { routerForRebuild } = runtime('./src/routes/cascadeRebuild');
const { createRebuildService } = runtime('./src/services/rebuildService');
const { generateXrayConfigWithApi } = runtime('./src/services/configGenerator');
const requireAuth = runtime('./src/middleware/auth');
const { issuePanelCsrfToken } = runtime('./src/routes/panel/csrf');
const Link = runtime('./src/models/cascadeLinkModel');

if (image) {
    const files = ['index.js', 'package-lock.json', 'src/routes/cascadeRebuild.js', 'src/services/rebuildService.js',
        'src/services/rebuildCoordinator.js', 'src/services/rebuildLinkSnapshot.js', 'src/services/rebuildLinkKeys.js',
        'src/models/cascadeLinkModel.js', 'src/modules/relay-l2tp/services/rebuildTopologyComposer.js'];
    for (const name of ['express', 'mongoose']) {
        assert.ok(realpathSync(runtime.resolve(name)).startsWith('/app/node_modules/'), `${name} is not packaged`);
    }
    for (const file of files) {
        const filename = path.join(root, file);
        assert.equal(realpathSync(runtime.resolve(filename)), filename);
        console.log(`sha256 ${createHash('sha256').update(readFileSync(filename)).digest('hex')}  ${filename}`);
    }
}

// Match only the Mongo query forms used by this smoke. Actual Mongoose casts,
// validators, timestamp middleware, and schema-level projections run above it.
function matches(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(part => matches(row, part));
        if (value instanceof mongoose.Types.ObjectId) return value.equals(row[key]);
        if (typeof value === 'boolean') return row[key] === value;
        if (Object.hasOwn(value, '$in')) return value.$in.some(id => id.equals(row[key]));
        if (Object.hasOwn(value, '$ne')) return row[key] !== value.$ne;
        if (Object.hasOwn(value, '$exists')) return Object.hasOwn(row, key) === value.$exists;
        assert.fail(`Unexpected fixture filter: ${key}`);
    });
}

test('rebuild confirmations ignore telemetry but refuse configuration drift', { timeout: 10000 }, async t => {
    t.after(() => require.cache[runtime.resolve('./src/services/sshPoolService')]?.exports.closeAll());
    const id = n => new mongoose.Types.ObjectId(n.toString(16).padStart(24, '0'));
    const nodes = ['portal', 'bridge', 'bridge'].map((cascadeRole, i) => ({
        _id: id(i + 1), name: `fixture-${i}`, type: 'xray', cascadeRole, active: true,
        ip: `192.0.2.${i + 1}`, port: 22000 + i,
        xray: { security: 'none', transport: 'tcp', inboundTag: 'client', apiPort: 32000 + i },
    }));
    const [target, survivor] = nodes.slice(1).map((bridge, i) => ({
        _id: id(i + 10), name: bridge.name, portalNode: nodes[0]._id, bridgeNode: bridge._id,
        mode: 'reverse', tunnelSecurity: 'none', tunnelPort: 41000 + i, priority: i + 1,
        tunnelUuid: `00000000-0000-4000-8000-00000000000${i}`, active: true, updatedAt: new Date(1000),
    }));
    const rows = [target, survivor];
    const allNodes = nodes.map(n => String(n._id)).sort();
    const users = [{ xrayUuid: '00000000-0000-4000-8000-000000000010', userId: 'fixture-user' }];
    const nodeUsers = n => n === nodes[0] ? users : [];
    const profiles = new Map(nodes.map(n => [String(n._id), {
        main: JSON.parse(generateXrayConfigWithApi(n, nodeUsers(n))), bridge: null,
    }]));
    const effects = [];
    let tick = 1000, tickOnReread = false, rereads = 0;
    t.mock.method(mongoose, 'now', () => new Date(++tick));
    async function health(row) {
        const previous = row.updatedAt;
        const patch = { status: row.status === 'offline' ? 'online' : 'offline',
            lastHealthCheck: new Date(tick + 1), latencyMs: tick, lastError: `fixture health ${tick}` };
        assert.equal((await Link.updateOne({ _id: row._id }, { $set: patch })).matchedCount, 1);
        for (const [field, value] of Object.entries(patch)) assert.deepEqual(row[field], value);
        assert.ok(row.updatedAt > previous, 'Mongoose must advance the telemetry timestamp');
    }
    t.mock.method(Link.collection, 'find', (filter, { projection } = {}) => ({
        async toArray() {
            // Change a retained row after inventory but before key preparation
            // reads it again, and again before Apply's key persistence recheck.
            if (tickOnReread && filter._id?.$in) { rereads++; await health(survivor); }
            return rows.filter(row => matches(row, filter)).map(row => {
                const result = { ...row };
                for (const [field, bit] of Object.entries(projection || {})) {
                    assert.equal(bit, 0, 'fixture expects an exclusion projection');
                    delete result[field];
                }
                return result;
            });
        },
    }));
    t.mock.method(Link.collection, 'updateOne', async (filter, { $set }) => {
        const row = rows.find(row => matches(row, filter));
        if (row) {
            if (!$set.lastHealthCheck) effects.push(['link-write', String(row._id)]);
            // A database read returns plain BSON, not Mongoose subdocuments.
            const { serialize, deserialize } = mongoose.mongo.BSON;
            Object.assign(row, deserialize(serialize($set)));
        }
        return { acknowledged: true, matchedCount: Number(!!row), modifiedCount: Number(!!row) };
    });
    t.mock.method(Link.collection, 'deleteMany', async filter => {
        const deleted = rows.filter(row => matches(row, filter));
        for (const row of deleted) { effects.push(['delete', String(row._id)]); rows.splice(rows.indexOf(row), 1); }
        return { acknowledged: true, deletedCount: deleted.length };
    });
    const session = new class FixtureTransaction {}();
    t.mock.method(Link.db, 'transaction', work => work(session));
    const service = createRebuildService({
        Link, Node: { find: () => ({ select: () => ({ lean: async () => nodes }) }) },
        State: { find: () => ({ select: () => ({ lean: async () => [] }) }) },
        env: { C3_REBUILD_ENABLED: 'true', PANEL_DOMAIN: 'fixture.invalid', ENCRYPTION_KEY: process.env.ENCRYPTION_KEY },
        locks: { run: work => work(async () => {}) }, assertNoRelayAccountIntent: async () => {},
        sync: { _getUsersForNode: async n => nodeUsers(n) }, cache: { invalidateAllSubscriptions: async () => {} },
        connect(node) {
            const key = String(node._id), row = profiles.get(key);
            return {
                async requireSupportedCore() {}, async close() {}, async read(profile) { return structuredClone(row[profile]); },
                async stagePair() { effects.push(['stage', key]); },
                async putPair(pair) {
                    effects.push(['activate', key]);
                    for (const { profile, config } of pair) row[profile] = structuredClone(config);
                },
            };
        },
    });
    const app = express(), login = { authenticated: true };
    const headers = { 'x-csrf-token': issuePanelCsrfToken({ session: login }) };
    app.use('/api/cascade', requireAuth, routerForRebuild({ service, Link }));
    async function call(method, url, body, status = 200, code) {
        const res = await request(app, `/api/cascade${url}`, { method, body, session: login, headers });
        const result = JSON.parse(res.body);
        assert.equal(res.status, status, `${method} ${url}: ${result.error?.code || 'no error code'}`);
        assert.equal(result.error?.code, code);
        return result;
    }
    const linkId = String(target._id);
    for (const remove of [false, true]) await t.test(remove ? 'Preview Remove / DELETE' : 'Preview / Apply', async () => {
        const preview = () => call('POST', '/rebuild/preview', { linkId, remove });
        const confirm = (expectedPreview, status, code) => remove
            ? call('DELETE', `/links/${linkId}`, { expectedPreview }, status, code)
            : call('POST', '/topology/deploy', { linkId, expectedPreview }, status, code);
        const before = effects.length;
        const report = await preview();
        assert.equal(report.allowed, true);
        await health(target); await health(survivor);
        tickOnReread = true;
        const initialReads = rereads;
        try {
            assert.equal((await preview()).previewId, report.previewId, 'telemetry changed the confirmation');
        } finally { tickOnReread = false; }
        assert.equal(rereads, initialReads + 1, 'preview must exercise the inventory-to-preparation race');
        assert.equal(effects.length, before, 'Preview must not write');

        // For Remove, changing only the removed link's port doesn't affect the
        // desired profiles. The inventory guard must still invalidate the ticket.
        const port = target.tunnelPort;
        target.tunnelPort++;
        try { await confirm(report.previewId, 409, 'REBUILD_LINK_CHANGED'); }
        finally { target.tunnelPort = port; }
        const main = profiles.get(String(nodes[0]._id)).main;
        const access = main.log.access;
        main.log.access = '/fixture-drift.log';
        try { await confirm(report.previewId, 409, 'REBUILD_PREVIEW_CHANGED'); }
        finally { main.log.access = access; }
        const client = main.inbounds.find(i => i.tag === 'client');
        client.port++;
        try { await confirm(report.previewId, 409, 'REBUILD_CLIENT_CHANGE'); }
        finally { client.port--; }
        assert.equal(effects.length, before, 'drift must not stage, activate, or write links');
        assert.ok(rows.includes(target) && target.rebuildDelete !== true);

        tickOnReread = true;
        const beforeConfirm = rereads;
        let result;
        try { result = await confirm(report.previewId); }
        finally { tickOnReread = false; }
        assert.equal(rereads, beforeConfirm + 2, 'confirmation must exercise preparation and persistence rereads');
        assert.equal(result.executionMode, 'rebuild');
        assert.deepEqual(result.nodes.map(node => node.nodeId).sort(), allNodes);
        for (const effect of ['stage', 'activate']) {
            assert.deepEqual(effects.slice(before).filter(([kind]) => kind === effect).map(([, id]) => id).sort(), allNodes);
        }
        assert.equal(rows.includes(target), !remove);
        assert.ok(rows.includes(survivor) && survivor.rebuildApplied?.port === survivor.tunnelPort);
        if (remove) assert.equal(result.deleted, linkId);
        else assert.ok(target.rebuildApplied?.port === port);
    });
});
