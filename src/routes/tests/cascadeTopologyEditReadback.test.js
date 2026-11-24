'use strict';

// The mounted cascade read router snapshots its mode when it is imported.
// This node:test worker exercises Rebuild for its entire lifetime.
process.env.C3_REBUILD_ENABLED = 'true';

const assert = require('node:assert/strict');
const test = require('node:test');
const { isDeepStrictEqual } = require('node:util');
const express = require('express');
const { Types: { ObjectId }, mongo: { BSON } } = require('mongoose');
const applyProjection = require('mongoose/lib/helpers/projection/applyProjection');
const requireAuth = require('../../middleware/auth');
const Link = require('../../models/cascadeLinkModel');
const Node = require('../../models/hyNodeModel');
const Settings = require('../../models/settingsModel');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const { collectionName: accountCollection } = require('../../services/rebuildRelayDirectory');
const { createRebuildService } = require('../../services/rebuildService');
const { makeLocks } = require('../../services/rebuildLocks');
const { generateXrayConfigWithApi } = require('../../services/configGenerator');
const { request } = require('../../services/tests/helpers/rebuildPanelRequest');
const { issuePanelCsrfToken } = require('../panel/csrf');
const { routerForRebuild } = require('../cascadeRebuild');
const { createCascadeTopologyDeployRouter } = require('../cascadeTopologyDeploy');
const cascadeRoutes = require('../cascade');

test.after(() => require('../../services/sshPoolService').closeAll());

const clone = doc => BSON.deserialize(BSON.serialize(doc));
const equal = (a, b) => a instanceof ObjectId ? a.equals(b) : isDeepStrictEqual(a, b);
const matches = (row, filter) => Object.entries(filter).every(([key, want]) => {
    if (key === '$or') return want.some(part => matches(row, part));
    if (key === '$and') return want.every(part => matches(row, part));
    const got = key.split('.').reduce((value, path) => value?.[path], row);
    if (want?.$in) return want.$in.some(v => v === null ? got == null : equal(v, got));
    if (want?.$nin) return !want.$nin.some(v => equal(v, got));
    if (want?.$ne !== undefined) return !equal(want.$ne, got);
    if (want?.$exists !== undefined) return (got !== undefined) === want.$exists;
    if (want?.$type === 'null') return got === null;
    if (want?.$not) return !matches(row, { [key]: want.$not });
    return want === null ? got == null : equal(want, got);
});
function read(rows, filter, { projection } = {}) {
    return rows.filter(row => matches(row, filter)).map(row => applyProjection(clone(row),
        Object.values(projection ?? {}).includes(1) ? { _id: 1, ...projection } : projection));
}

for (const [mode, transport, initial] of [
        ['reverse','tcp','applied'], ['reverse','kcp','applied'],
        ['reverse','tcp','legacy'], ['reverse','kcp','draft'],
        ['forward','tcp','legacy'], ['forward','kcp','draft'],
        ['reverse','kcp','legacy'], ['reverse','tcp','draft'],
        ['forward','kcp','legacy'], ['forward','tcp','draft'],
    ]) {
    const marker = 'rebuildDesiredEdited';
    test(`mounted Rebuild ${mode}/${transport}/${initial} PUT survives preview cancellation and Apply clears pending`, async t => {
        const nodes = ['portal', 'bridge'].map((cascadeRole, i) => ({
            _id: new ObjectId(), name: cascadeRole, ip: `192.0.2.${i + 1}`, type: 'xray', active: true,
            cascadeRole, xrayVersion: '26.6.1', port: 22000 + i,
            xray: { security: 'none', transport: 'tcp', inboundTag: 'client', apiPort: 23000 + i },
        }));
        const rows = [];
        for (const [model, docs] of [[Link, rows], [Node, nodes], [Settings, []], [State, []], [require('../../modules/relay-l2tp/models/cascadeTopologyStateModel'), []]]) {
            t.mock.method(model.collection, 'find', (filter, options) => ({ toArray: async () => read(docs, filter, options) }));
            t.mock.method(model.collection, 'findOne', async (filter, options) => read(docs, filter, options)[0] ?? null);
        }
        // Real Mongoose save/update casting, selection and validation. Only
        // the collection operations and transaction acknowledgement are modeled.
        t.mock.method(Link.collection, 'insertOne', async row => {
            assert.equal(rows.length, 0);
            rows.push(clone(row));
            return { acknowledged: true, insertedId: row._id };
        });
        const dbSession = new class FixtureTransaction {}();
        const writes = t.mock.method(Link.collection, 'updateOne', async (filter, update, options) => {
            if (Object.hasOwn(update.$set ?? {}, 'rebuildApplied')) assert.equal(options.session, dbSession);
            const row = rows.find(doc => matches(doc, filter));
            if (row) {
                // Mongoose adds $setOnInsert.createdAt even on a matched update.
                assert.deepEqual(Object.keys(update).filter(key => !['$set', '$unset', '$setOnInsert'].includes(key)), []);
                if (update.$set) Object.assign(row, clone(update.$set));
                for (const key of Object.keys(update.$unset ?? {})) delete row[key];
            }
            return { acknowledged: true, matchedCount: Number(!!row), modifiedCount: Number(!!row) };
        });
        const transaction = t.mock.method(Link.db, 'transaction', fn => fn(dbSession));
        let lock;
        const locks = makeLocks({
            async insertOne(row) { assert.equal(lock, undefined); lock = clone(row); },
            async findOne(filter) { return lock && matches(lock, filter) ? clone(lock) : null; },
            async deleteMany(filter) {
                assert.ok(lock && matches(lock, filter));
                lock = undefined;
                return { acknowledged: true, deletedCount: 1 };
            },
        });
        const collection = Link.db.collection.bind(Link.db);
        t.mock.method(Link.db, 'collection', (name, ...args) => name === accountCollection ? {
            async findOne(filter) { assert.deepEqual(filter, { _id: 'pending' }); return null; },
        } : collection(name, ...args));
        t.mock.method(require('../../services/configGenerator'), 'buildPanelInlineCertificate', () => null);
        const removals = t.mock.method(Link.collection, 'deleteMany', async (filter, options) => {
            assert.equal(options.session, dbSession);
            assert.ok(matches(rows[0], filter));
            rows.pop();
            return { acknowledged: true, deletedCount: 1 };
        });
        const profiles = new Map(nodes.map(node => [String(node._id), {
            main: JSON.parse(generateXrayConfigWithApi(node, [])), bridge: null,
        }]));
        let stages = 0;
        let activations = 0;
        const service = createRebuildService({ locks,
            compose(input) {
                for (const link of input.links) assert.equal(Object.hasOwn(link, marker), false);
                return require('../../modules/relay-l2tp/services/rebuildTopologyComposer').composeRebuildProfiles(input);
            }, env: { C3_REBUILD_ENABLED: 'true', PANEL_DOMAIN: 'panel.fixture.invalid' },
            sync: { _getUsersForNode: async () => [] }, cache: { invalidateAllSubscriptions: async () => {} },
            connect(node) {
                const current = profiles.get(String(node._id));
                return {
                    async requireSupportedCore() {}, async close() {},
                    async read(profile) { return structuredClone(current[profile]); },
                    async stagePair(pair) { assert.ok(!JSON.stringify(pair).includes(marker)); stages++; },
                    async putPair(pair) {
                        activations++;
                        for (const { profile, config } of pair) current[profile] = structuredClone(config);
                    },
                };
            },
        });

        const cascade = require('../../services/cascadeService');
        const probes = [[cascade, '_measureTcpLatency'], [cascade, '_checkTunnel'],
            [require('../../services/syncService'), 'readRebuildReverseObservation']]
            .map(([target, key]) => t.mock.method(target, key, () => assert.fail('pending link must not be probed')));
        const app = express();
        app.use('/api/cascade', requireAuth, routerForRebuild({ service }));
        app.use('/api/cascade/topology', createCascadeTopologyDeployRouter());
        app.use('/api/cascade', requireAuth, cascadeRoutes);
        const session = { authenticated: true };
        const headers = { 'x-csrf-token': issuePanelCsrfToken({ session }) };
        const send = async (method, path, body) => {
            const result = await request(app, `/api/cascade${path}`, { method, session, headers, body });
            const json = JSON.parse(result.body);
            assert.equal(result.status, 200, `${method} ${path}: ${json.error?.code ?? ''}`);
            if (method === 'GET') assert.equal(result.headers['cache-control'], 'no-store');
            return json;
        };
        const draft = await send('POST', '/links', {
            name: 'Original', portalNodeId: String(nodes[0]._id), bridgeNodeId: String(nodes[1]._id),
            mode, tunnelPort: 24001, tunnelSecurity: 'none', tunnelEncryption: 'none', tunnelTransport: transport,
        });
        const { linkId } = draft;
        assert.equal(draft.status, 'saved');
        const [row] = rows;
        assert.ok(!Object.hasOwn(row, marker), 'creation must not store marker');
        const beforeFailure = clone(row);
        const failSave = t.mock.method(Link.collection, 'updateOne', async () => { throw new Error('fixture write rejected'); });
        try {
            const refused = await request(app, '/api/cascade/links/' + linkId, { method: 'PUT', session, headers, body: { name: 'Rejected' } });
            assert.equal(refused.status, 409);
            assert.deepEqual(JSON.parse(refused.body), { error: { code: 'REBUILD_FAILED' } });
            assert.equal(failSave.mock.callCount(), 1);
            assert.deepEqual(row, beforeFailure);
        } finally { failSave.mock.restore(); }
        const linkPath = `/links/${linkId}`;
        const preview = async () => {
            const report = await send('POST', '/rebuild/preview', { linkId });
            assert.equal(report.allowed, true);
            return report.previewId;
        };
        const apply = async expectedPreview => {
            const result = await send('POST', `${linkPath}/deploy`, { expectedPreview });
            assert.equal(result.status, 'succeeded');
        };
        const edge = async () => (await send('GET', '/topology')).edges.find(({ data }) => data.linkId === linkId).data;

        assert.equal(row.rebuildApplied, null);
        const newDraft = await edge();
        assert.equal(newDraft.rebuildApplied, false);
        assert.equal((await edge()).hasUnappliedChanges, false, 'failed save leaves no pending marker');
        if (initial === 'legacy') delete row.rebuildApplied;
        if (initial === 'applied') {
            await apply(await preview());
            assert.equal(row.status, 'deployed');
            assert.ok(!Object.hasOwn(row, marker));
        }
        const previousEffects = initial === 'applied' ? 2 : 0;
        const previousSettlements = initial === 'applied' ? 1 : 0;
        assert.equal(stages, previousEffects);
        assert.equal(activations, previousEffects);
        const receipt = row.rebuildApplied && clone(row.rebuildApplied);
        const epoch = row.rebuildApplyEpoch;
        const stamp = row.rebuildKcpApplied;
        assert.equal(typeof stamp, transport === 'kcp' && initial === 'applied' ? 'string' : 'undefined');
        const initiallyApplied = await edge();

        const changes = transport === 'kcp' ? { kcpTti: 30 } : { name: 'Renamed' };
        const beforeEditWrites = writes.mock.callCount();
        const saved = await send('PUT', linkPath, changes);
        assert.deepEqual(saved, { executionMode: 'rebuild', desiredSaved: true, linkId, status: 'saved' });
        for (const [field, value] of Object.entries(changes)) assert.equal(row[field], value);
        assert.equal(row.status, 'pending');
        assert.deepEqual(row.rebuildApplied, receipt);
        assert.equal(row.rebuildApplyEpoch, epoch);
        assert.equal(row.rebuildKcpApplied, stamp);
        assert.equal(writes.mock.callCount(), beforeEditWrites + 1);
        const afterPut = await edge();
        const pending = clone(row);
        assert.equal(pending[marker], true);
        const [, savedUpdate] = writes.mock.calls.at(-1).arguments;
        assert.equal(savedUpdate.$set[marker], true);
        assert.equal(savedUpdate.$set.status ?? row.status, 'pending');
        assert.ok(lock === undefined);
        const health = await send('GET', `${linkPath}/health`);
        assert.deepEqual([health.status, health.healthy, health.lastHealthCheck], ['pending', false, null]);
        assert.ok(probes.every(probe => probe.mock.callCount() === 0));
        assert.deepEqual(row, pending, 'health reset does not overwrite the saved draft');
        const beforePreview = { profiles: structuredClone(profiles), writes: writes.mock.callCount() };

        await preview(); // Cancel is omitting the deploy request, not undoing the saved PUT.
        assert.equal(lock, undefined);
        assert.deepEqual(row, pending);
        assert.deepEqual(profiles, beforePreview.profiles);
        assert.equal(writes.mock.callCount(), beforePreview.writes);
        assert.equal(transaction.mock.callCount(), previousSettlements);
        assert.equal(stages, previousEffects);
        assert.equal(activations, previousEffects);
        const afterCancel = await edge();
        assert.deepEqual(afterCancel, afterPut);
        assert.equal(afterCancel.label, changes.name ?? 'Original');
        assert.equal(afterCancel.status, 'pending');
        assert.equal(afterCancel.rebuildApplied, initial === 'applied' ? true : initial === 'draft' ? false : undefined);
        assert.equal(afterCancel.hasUnappliedChanges, true, 'fresh topology retains the saved-but-unapplied edit');
        assert.equal(afterCancel.canEdit, true);
        assert.equal(newDraft.hasUnappliedChanges, false);
        assert.equal(initiallyApplied.hasUnappliedChanges, false);
        assert.equal(JSON.stringify(afterCancel).includes(row.tunnelUuid), false);

        assert.equal(Object.hasOwn(afterCancel, marker), false);
        const list = await send('GET', '/links');
        const detail = await send('GET', linkPath);
        const { linkSnapshot, linkSnapshotBytes } = require('../../services/rebuildLinkSnapshot');
        const { fingerprintLinks } = require('../../services/rebuildCoordinator');
        for (const response of [list, detail, linkSnapshot(row)]) assert.ok(!JSON.stringify(response).includes(marker));
        const marked = await Link.findById(row._id).select('+' + marker);
        assert.equal(marked[marker], true);
        assert.equal(Object.hasOwn(marked.toJSON(), marker), false);
        assert.equal(Object.hasOwn(marked.toObject(), marker), false);
        assert.equal(Object.hasOwn(await Link.findById(row._id).lean(), marker), false);
        const token = await preview();
        delete row[marker];
        assert.ok(linkSnapshotBytes(row).equals(linkSnapshotBytes(pending)));
        assert.equal(fingerprintLinks([row]), fingerprintLinks([pending]));
        const { linkDesiredVersion } = require('../../modules/relay-l2tp/services/topologyIntentService');
        assert.equal(linkDesiredVersion(row), linkDesiredVersion(pending));
        assert.equal(await preview(), token, 'advisory marker cannot change the real preview digest');
        row[marker] = true;
        // Out-of-band legacy telemetry must not clear a saved edit.
        row.status = 'offline';
        assert.equal((await edge()).hasUnappliedChanges, true);
        row.status = 'pending';
        assert.ok(!JSON.stringify([...profiles]).includes(marker));
        await apply(await preview()); // A new explicit confirmation.
        assert.ok(!Object.hasOwn(row, marker));
        const [, update, options] = writes.mock.calls.at(-1).arguments;
        assert.equal(update.$unset[marker], '');
        assert.equal(options.session, dbSession);
        assert.ok(!JSON.stringify([...profiles]).includes(marker));
        assert.equal(transaction.mock.callCount(), previousSettlements + 1);
        assert.equal(activations, previousEffects + 2);
        assert.notEqual(row.rebuildApplyEpoch, epoch);
        if (transport === 'kcp') assert.notEqual(row.rebuildKcpApplied, stamp);
        const applied = await edge();
        assert.deepEqual([applied.canEdit, applied.hasUnappliedChanges, applied.rebuildApplied, applied.status], [true, false, true, 'deployed']);
        assert.equal(applied.lastHealthCheck, null, 'settlement is not runtime health');
        await send('PUT', linkPath, { name: 'Edited before teardown' });
        assert.equal(row[marker], true);
        const plan = async () => send('POST', '/rebuild/preview', { linkId, remove: true });
        const withMarker = await plan();
        delete row[marker];
        assert.deepEqual(await plan(), withMarker, 'teardown plan cannot depend on pending badge');
        row[marker] = true;
        assert.equal(withMarker.allowed, true);
        await send('DELETE', linkPath, { expectedPreview: withMarker.previewId });
        assert.equal(removals.mock.callCount(), 1);
        assert.equal(rows.length, 0);
        assert.ok(!JSON.stringify([...profiles]).includes(marker));
    });
}
