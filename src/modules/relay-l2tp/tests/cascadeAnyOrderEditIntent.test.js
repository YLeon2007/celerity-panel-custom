'use strict';
// Actual route + schemas + intent/draft/deployment repositories. Transaction
// isolation/rollback below is modeled local persistence, NOT Mongo proof.
process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'admin@test.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'test-session-secret';
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const express = require('express');
const LinkModel = require('../../../models/cascadeLinkModel');
const IntentModel = require('../models/topologyCreateIntentModel');
const { TopologyIntentService, linkDesiredVersion } = require('../services/topologyIntentService');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { TopologyDraftWriteService } = require('../services/topologyDraftWriteService');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { createCascadeLinksRouter, prepareIntentLink } = require('../../../routes/cascadeLinks');
const sshPool = require('../../../services/sshPoolService');
test.after(() => sshPool.closeAll());
const context = Object.freeze({ target: 'test', hostIdentity: 'test.infograd.online' });
const ids = Array.from({ length: 8 }, (_, i) => `507f1f77bcf86cd7994390${String(i).padStart(2, '0')}`);
const copy = value => value === undefined ? undefined : structuredClone(value);
const json = value => JSON.parse(JSON.stringify(value));
const equal = (a, b) => String(a) === String(b);
function matches(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(part => matches(row, part));
        const actual = key.split('.').reduce((v, part) => v?.[part], row);
        if (value && typeof value === 'object' && !(value instanceof Date)) {
            return Object.entries(value).every(([op, expected]) => {
                if (op === '$in') return expected.some(v => equal(actual, v));
                if (op === '$nin') return expected.every(v => !equal(actual, v));
                if (op === '$exists') return (actual !== undefined) === expected;
                if (op === '$gt') return actual > expected;
                if (op === '$lt') return actual < expected;
                if (op === '$ne') return !equal(actual, expected);
                if (op === '$eq') return equal(actual, expected);
                throw Error(`Unsupported fixture predicate ${op}`);
            });
        }
        return equal(actual, value);
    });
}
function apply(row, update) {
    for (const [key, value] of Object.entries(update.$set || {})) {
        const parts = key.split('.'); let target = row;
        for (const part of parts.slice(0, -1)) target = target[part] ||= {};
        target[parts.at(-1)] = copy(value);
    }
    for (const [key, value] of Object.entries(update.$inc || {})) row[key] = (row[key] || 0) + value;
    for (const key of Object.keys(update.$unset || {})) delete row[key];
}
function fixture() {
    const client = {}, db = { getClient: () => client };
    let data = {
        CascadeTopologyState: [{ _id: 'singleton', revision: 7, deployedRevision: 5, topologyAdmissionCount: 0, remoteAdmissionCount: 0 }],
        HyNode: ids.map((_id, i) => ({ _id, active: true, type: 'xray', cascadeRole: i % 2 ? 'bridge' : 'portal' })),
        CascadeLink: [json(new LinkModel({ _id: ids[7], name: 'original', portalNode: ids[0], bridgeNode: ids[1], tunnelUuid: 'stable-uuid' }).toObject())],
        CascadeRouteGroup: [], RelayL2tpState: [], TopologyCreateIntent: [],
        TopologyIntentQueueState: [{ _id: 'create-v1', ordinal: 0, outstanding: 0 }],
        TopologyOperation: [], TopologyConfigOwner: [], NodeOperationLock: [], RemoteAdmission: [],
    };
    const trace = [];
    function model(name) {
        const SchemaModel = name === 'TopologyCreateIntent' ? IntentModel : LinkModel;
        class Model {
            constructor(input) { return new SchemaModel(input); }
            static db = db;
            static query(work) {
                let session;
                return {
                    session(value) { session = value; return this; }, select() { return this; }, populate() { return this; },
                    sort() { return this; },
                    readConcern(value) { trace.push(['readConcern', value]); return this; },
                    read(value) { trace.push(['read', value]); return this; },
                    maxTimeMS(value) { trace.push(['maxTimeMS', value]); return this; },
                    async lean() { return copy(await work(session?.data || data, session)); },
                    then(resolve, reject) { return this.lean().then(resolve, reject); },
                };
            }
            static find(filter) { return this.query(state => state[name].filter(row => matches(row, filter))); }
            static findOne(filter) { return this.query(state => state[name].find(row => matches(row, filter)) || null); }
            static findById(_id) { return this.findOne({ _id }); }
            static exists(filter) { return this.findOne(filter); }
            static findOneAndUpdate(filter, update, options = {}) {
                return this.query((state, session) => {
                    trace.push(['cas', name, session]);
                    const row = state[name].find(candidate => matches(candidate, filter));
                    if (!row) return null;
                    apply(row, update); return row;
                }).session(options.session);
            }
            static async create(rows, { session } = {}) {
                trace.push(['create', name, session]);
                const state = session?.data || data;
                const saved = [];
                for (const input of rows) {
                    const doc = ['CascadeLink', 'TopologyCreateIntent'].includes(name) ? new SchemaModel(input) : null;
                    if (doc) await doc.validate();
                    const row = json(doc ? doc.toObject() : { _id: new mongoose.Types.ObjectId(), ...input });
                    if (name === 'TopologyCreateIntent' && state[name].some(existing => existing.requestKey === row.requestKey)) {
                        throw Object.assign(Error('duplicate key'), { code: 11000 });
                    }
                    state[name].push(row); saved.push(row);
                }
                return saved;
            }
            static async updateOne(filter, update, { session } = {}) {
                trace.push(['update', name, session]);
                const row = (session?.data || data)[name].find(candidate => matches(candidate, filter));
                if (row) apply(row, update);
                return { matchedCount: row ? 1 : 0 };
            }
            static async deleteOne(filter, { session } = {}) {
                const rows = (session?.data || data)[name];
                const index = rows.findIndex(row => matches(row, filter));
                if (index >= 0) rows.splice(index, 1);
                return { deletedCount: index >= 0 ? 1 : 0 };
            }
        }
        return Model;
    }
    const dependencies = Object.fromEntries(Object.keys(data).map(name => [name, model(name)]));
    Object.assign(dependencies, { executionContext: context,
        async transactionRunner(work) {
            const session = { data: copy(data), client, inTransaction: () => true };
            trace.push(['begin', session]);
            const result = await work(session);
            data = session.data;
            trace.push(['commit', session]);
            return result;
        },
        async resolveIntentResources({ link, session }) {
            trace.push(['resources', session]);
            return [String(link.portalNode), String(link.bridgeNode)].sort();
        },
        prepareLink: prepareIntentLink,
    });
    const draftRepository = new TopologyDraftRepository({ ...dependencies,
        transactionRunner() { throw Error('joined writer must not open its own transaction'); } });
    const deploymentRepository = new TopologyDeploymentRepository({ ...dependencies, snapshotReader: draftRepository });
    dependencies.intentDraftWriter = draftRepository.createIntentDraftWriter({ selectedTopologyRepository: deploymentRepository });
    return { dependencies, draftRepository, deploymentRepository, trace, get data() { return data; } };
}
function router(f, extra = {}) {
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use('/links', createCascadeLinksRouter({ Link: f.dependencies.CascadeLink, Node: f.dependencies.HyNode,
        TopologyState: f.dependencies.CascadeTopologyState, ClientProofOperation: f.dependencies.TopologyOperation,
        topologyIntentService: new TopologyIntentService(f.dependencies),
        topologyDraftWriteService: new TopologyDraftWriteService({ repository: new TopologyDraftRepository(f.dependencies) }),
        deploymentEnv: {}, maintainAutoL2tpPathsFn: async () => {}, invalidateSubscriptions: async () => {},
        invalidateTopology: async () => {}, ...extra }));
    return app;
}
async function request(f, body, key = 'edit-key', extra = {}) {
    const app = router(f, extra);
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}/links/${ids[7]}`, {
            method: 'PUT', headers: { 'content-type': 'application/json', ...(key === null ? {} : { 'idempotency-key': key }) },
            body: JSON.stringify(body),
        });
        return { status: response.status, body: await response.json() };
    } finally { await new Promise(resolve => server.close(resolve)); }
}
const edit = overrides => ({ expectedTopologyRevision: 7, autoDeploy: true, name: 'requested', tunnelPort: 10088, ...overrides });

for (const fault of ['intent insertion', 'resource admission', 'draft admission']) {
    test(`PUT Auto ${fault} refusal leaves desired, counters and jobs unchanged`, async () => {
        const f = fixture(); const before = copy(f.data);
        if (fault === 'intent insertion') f.dependencies.TopologyCreateIntent.create = async () => { throw Error('modeled insert failure'); };
        if (fault === 'resource admission') f.dependencies.resolveIntentResources = async () => {
            throw Object.assign(Error('modeled admission refusal'), { code: 'TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE' });
        };
        if (fault === 'draft admission') {
            f.data.CascadeTopologyState[0].remoteDrain = true;
            before.CascadeTopologyState[0].remoteDrain = true;
        }
        const result = await request(f, edit());
        assert.ok(result.status >= 400, JSON.stringify(result.body));
        assert.equal(result.body.job, undefined); assert.equal(result.body.desiredSaved, undefined);
        if (fault === 'draft admission') {
            assert.equal(result.status, 409, JSON.stringify(result.body));
            assert.equal(result.body.error.code, 'TOPOLOGY_ADMISSION_UNAVAILABLE');
        }
        assert.deepEqual(f.data, before);
        if (fault !== 'draft admission') assert.ok(f.trace.some(([kind, name]) => kind === 'update' && name === 'CascadeLink'),
            'the actual joined draft update ran before the modeled later refusal');
    });
}

test('PUT cannot edit an accepted deleting row, including a late same-session marker', async () => {
    for (const late of [false, true]) {
        const f = fixture(); const marker = { state: 'deleting', deleteJobId: ids[6], desiredVersion: linkDesiredVersion(f.data.CascadeLink[0]) };
        if (late) f.dependencies.prepareLink = link => {
            // Modeled ordering only: Mongo concurrency/rollback is verified in a
            // separately owned replica-set test, not by this transaction fixture.
            const session = f.trace.findLast(([kind]) => kind === 'begin')[1];
            session.data.CascadeLink[0].lifecycle = copy(marker);
            return link;
        };
        else f.data.CascadeLink[0].lifecycle = copy(marker);
        const before = copy(f.data);
        const result = await request(f, edit());
        assert.equal(result.status, 409, JSON.stringify(result.body));
        assert.equal(result.body.error.code, 'CASCADE_LINK_DELETING');
        assert.deepEqual(f.data, before);
        assert.equal(f.trace.filter(([kind, name]) => kind === 'update' && name === 'CascadeLink').length, 0);
    }
});

test('PUT Auto blank controls preserve an existing REALITY credential tuple', async () => {
    const f = fixture();
    const existing = prepareIntentLink({ ...f.data.CascadeLink[0], tunnelSecurity: 'reality' });
    f.data.CascadeLink[0] = copy(existing);
    const result = await request(f, edit({ realityPrivateKey: '', realityPublicKey: '', realityShortIds: [], tunnelUuid: '' }));
    assert.equal(result.status, 202, JSON.stringify(result.body));
    for (const key of ['tunnelUuid', 'realityPrivateKey', 'realityPublicKey', 'realityShortIds']) {
        assert.deepEqual(f.data.CascadeLink[0][key], existing[key], key);
    }
    assert.equal(result.body.job.desiredVersion, linkDesiredVersion(f.data.CascadeLink[0]));
});

test('ordinary save-only PUT never accepts another job even with persisted autoDeploy metadata', async () => {
    const f = fixture();
    const accepted = await request(f, edit());
    assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
    const saved = await request(f, { expectedTopologyRevision: 8, name: 'only saved' }, null);
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.equal(saved.body.desiredSaved, true); assert.equal(saved.body.job, undefined);
    assert.equal(f.data.CascadeLink[0].autoDeploy, true);
    assert.equal(f.data.CascadeLink[0].name, 'only saved');
    assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
    const replay = await request(f, edit({ expectedTopologyRevision: 0 }));
    assert.deepEqual(replay.body.job, accepted.body.job);
    assert.equal(f.data.CascadeLink[0].name, 'only saved');
});

test('atomic edits require the joined same-connection writer and reject missing native runtime without fallback', async () => {
    for (const malformed of ['absent', 'create-only', 'foreign-writer', 'foreign-model', 'runtime']) {
        const f = fixture(); const before = copy(f.data);
        if (malformed === 'absent') delete f.dependencies.intentDraftWriter;
        if (malformed === 'create-only') f.dependencies.intentDraftWriter = { db: f.dependencies.CascadeLink.db, createLink() { throw Error('not an update'); } };
        if (malformed === 'foreign-writer') f.dependencies.intentDraftWriter = { db: {}, updateLink() { throw Error('foreign connection'); } };
        if (malformed === 'foreign-model') f.dependencies.HyNode = class extends f.dependencies.HyNode { static db = {}; };
        const result = await request(f, edit(), 'no-fallback', malformed === 'runtime' ? { topologyIntentService: null } : {});
        assert.equal(result.status, 503, `${malformed}: ${JSON.stringify(result.body)}`);
        assert.equal(result.body.error.code, malformed === 'runtime' ? 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE'
            : malformed === 'foreign-model' ? 'TOPOLOGY_INTENT_DRAFT_CONNECTION_MISMATCH' : 'TOPOLOGY_INTENT_DRAFT_TRANSACTION_UNAVAILABLE');
        assert.deepEqual(f.data, before);
    }
});

test('joined update writer rejects absent, inactive and foreign sessions before persistence', async () => {
    const f = fixture();
    for (const session of [undefined, { inTransaction: () => false }, { client: {}, inTransaction: () => true }]) {
        await assert.rejects(f.dependencies.intentDraftWriter.updateLink({ expectedTopologyRevision: 7, linkId: ids[7],
            changes: { name: 'refused' }, session }), TypeError);
    }
    assert.equal(f.trace.length, 0); assert.equal(f.data.CascadeLink[0].name, 'original');
});

test('ambiguous commit confirms the persisted edit key by bounded primary-majority read without another edit', async () => {
    const f = fixture(); const run = f.dependencies.transactionRunner;
    f.dependencies.transactionRunner = async work => {
        await run(work); // Modeled successful commit whose acknowledgement is lost.
        throw Object.assign(Error('unknown commit delivery'), { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' });
    };
    const first = await request(f, edit());
    assert.equal(first.status, 202, JSON.stringify(first.body));
    assert.equal(f.data.CascadeLink[0].name, 'requested'); assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.ok(f.trace.some(([kind, value]) => kind === 'readConcern' && value === 'majority'));
    assert.ok(f.trace.some(([kind, value]) => kind === 'read' && value === 'primary'));
    assert.ok(f.trace.some(([kind, value]) => kind === 'maxTimeMS' && value === 5000));
    f.dependencies.transactionRunner = run;
    const replay = await request(f, edit({ expectedTopologyRevision: 0 }));
    assert.deepEqual(replay.body.job, first.body.job);
    assert.equal(f.trace.filter(([kind, name]) => kind === 'update' && name === 'CascadeLink').length, 1);
});

test('failed primary-majority confirmation cannot acknowledge an ambiguous edit; a later retry replays it', async () => {
    const f = fixture(); const run = f.dependencies.transactionRunner;
    const find = f.dependencies.TopologyCreateIntent.findOne;
    f.dependencies.TopologyCreateIntent.findOne = function (filter) {
        const query = find.call(this, filter);
        const concern = query.readConcern;
        query.readConcern = function (value) {
            concern.call(this, value);
            this.lean = async () => { throw Error('modeled durable confirmation failure'); };
            return this;
        };
        return query;
    };
    f.dependencies.transactionRunner = async work => {
        await run(work);
        throw Object.assign(Error('unknown delivery'), { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' });
    };
    const refused = await request(f, edit());
    assert.equal(refused.status, 500, JSON.stringify(refused.body)); assert.equal(refused.body.job, undefined);
    assert.equal(f.data.TopologyCreateIntent.length, 1, 'the modeled committed job must remain');
    const before = copy(f.data);
    f.dependencies.transactionRunner = run; f.dependencies.TopologyCreateIntent.findOne = find;
    const retry = await request(f, edit({ expectedTopologyRevision: 0 }));
    assert.equal(retry.status, 202, JSON.stringify(retry.body));
    assert.equal(retry.body.job.jobId, before.TopologyCreateIntent[0]._id);
    assert.deepEqual(f.data, before);
    assert.equal(f.trace.filter(([kind, name]) => kind === 'update' && name === 'CascadeLink').length, 1);
});

test('unprepared native REALITY edits refuse before desired mutation; the generator dependency is not an HTTP fallback', async () => {
    const f = fixture(); delete f.dependencies.prepareLink;
    const before = copy(f.data);
    const result = await request(f, edit({ tunnelSecurity: 'reality' }));
    assert.equal(result.status, 503, JSON.stringify(result.body));
    assert.equal(result.body.error.code, 'TOPOLOGY_INTENT_PREPARATION_UNAVAILABLE');
    assert.deepEqual(f.data, before);
});

test('new edit admission rechecks revision, active state and actual mixed-mode listener collisions', async () => {
    for (const kind of ['revision', 'disabled', 'listener']) {
        const f = fixture();
        if (kind === 'disabled') f.data.CascadeLink[0].active = false;
        if (kind === 'listener') f.data.CascadeLink.push(json(new LinkModel({ _id: ids[6], name: 'forward listener',
            portalNode: ids[2], bridgeNode: ids[0], tunnelPort: 10088, tunnelUuid: 'other', mode: 'forward' }).toObject()));
        const before = copy(f.data);
        const result = await request(f, edit(kind === 'revision' ? { expectedTopologyRevision: 0 } : {}));
        assert.equal(result.status, 409, JSON.stringify(result.body));
        assert.equal(result.body.error.code, kind === 'revision' ? 'STALE_TOPOLOGY_REVISION'
            : kind === 'disabled' ? 'CASCADE_LINK_DISABLED' : 'CASCADE_LINK_CONFLICT');
        assert.deepEqual(f.data, before);
    }
});

test('credential preparation cannot mutate the persisted normalized edit request through shared arrays', async () => {
    const f = fixture();
    f.dependencies.prepareLink = link => {
        link.realitySni.push('local-default.test');
        return prepareIntentLink(link);
    };
    const result = await request(f, edit({ tunnelSecurity: 'reality', realitySni: ['requested.test'] }));
    assert.equal(result.status, 202, JSON.stringify(result.body));
    assert.deepEqual(f.data.TopologyCreateIntent[0].payload.changes.realitySni, ['requested.test']);
    assert.deepEqual(f.data.CascadeLink[0].realitySni, ['requested.test', 'local-default.test']);
    const replay = await request(f, edit({ expectedTopologyRevision: 0, tunnelSecurity: 'reality', realitySni: ['requested.test'] }));
    assert.deepEqual(replay.body.job, result.body.job);
});

test('PUT Auto queue overflow rolls desired edit and intent admission back together', async () => {
    const f = fixture(); f.data.TopologyIntentQueueState[0].outstanding = 32;
    const before = copy(f.data);
    const result = await request(f, edit());
    assert.equal(result.status, 503, JSON.stringify(result.body));
    assert.equal(result.body.error.code, 'TOPOLOGY_INTENT_BACKLOG_FULL');
    assert.deepEqual(f.data, before, 'a rejected Auto must not leave the desired edit saved');
    assert.equal(result.body.desiredSaved, undefined);
});

test('PUT Auto joins actual draft update, desired pin, resource resolution and insert in one session', async () => {
    const f = fixture(); let maintenance = 0;
    const result = await request(f, edit({ tunnelPort: '10088', geoRouting: { enabled: true, domains: ['example.test'] } }),
        'atomic-edit', { maintainAutoL2tpPathsFn: async () => { maintenance++; } });
    assert.equal(result.status, 202, JSON.stringify(result.body));
    assert.equal(result.body.desiredSaved, true);
    assert.equal(result.body.job.kind, 'link.apply');
    assert.equal(result.body.job.linkId, ids[7]);
    assert.equal(result.body.job.createdLinkId, undefined);
    assert.deepEqual(result.body.autoDeployJob, result.body.job);
    assert.equal(f.data.CascadeLink[0].name, 'requested');
    assert.equal(f.data.CascadeLink[0].tunnelPort, 10088);
    assert.deepEqual(f.data.CascadeLink[0].geoRouting, { enabled: true, domains: ['example.test'], geoip: [] });
    assert.equal(f.data.CascadeTopologyState[0].revision, 8);
    assert.equal(f.data.CascadeTopologyState[0].deployedRevision, 5);
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
    const row = f.data.TopologyCreateIntent[0];
    assert.equal(row.desiredVersion, linkDesiredVersion(f.data.CascadeLink[0]));
    assert.equal(row.payload.desiredVersion, row.desiredVersion);
    assert.deepEqual(row.payload.changes, { autoDeploy: true, name: 'requested', tunnelPort: 10088,
        'geoRouting.enabled': true, 'geoRouting.domains': ['example.test'] });
    const updates = f.trace.filter(([kind, name]) => kind === 'update' && name === 'CascadeLink');
    const inserts = f.trace.filter(([kind, name]) => kind === 'create' && name === 'TopologyCreateIntent');
    assert.equal(updates.length, 1); assert.equal(inserts.length, 1);
    assert.ok(updates[0][2] === inserts[0][2]);
    assert.ok(f.trace.find(([kind]) => kind === 'resources')[1] === inserts[0][2]);
    assert.equal(f.trace.filter(([kind]) => kind === 'begin').length, 1);
    assert.equal(f.trace.filter(([kind]) => kind === 'commit').length, 1);
    assert.equal(f.data.TopologyOperation.length, 0, 'acceptance does not dispatch or invent an operation');
    assert.equal(maintenance, 0);
});

test('PUT persisted-key replay survives service reconstruction and later desired edits without another mutation', async () => {
    const f = fixture(); let generated = 0;
    f.dependencies.prepareLink = link => { generated++; return prepareIntentLink(link); };
    const body = edit({ tunnelSecurity: 'reality', realityPrivateKey: '', realityPublicKey: '', realityShortIds: [] });
    const first = await request(f, body, 'durable-edit');
    assert.equal(first.status, 202, JSON.stringify(first.body));
    const accepted = copy(f.data.CascadeLink[0]);
    assert.match(accepted.realityPrivateKey, /^[A-Za-z0-9_-]{43}$/);
    assert.match(accepted.realityPublicKey, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(generated, 1);
    f.data.CascadeLink[0].wsHost = 'a-later-save.test';
    f.data.CascadeTopologyState[0].revision = 50;
    const before = copy(f.data);
    const replay = await request(f, { ...body, expectedTopologyRevision: 1, tunnelPort: '10088' }, 'durable-edit');
    assert.equal(replay.status, 202, JSON.stringify(replay.body));
    assert.deepEqual(replay.body.job, first.body.job);
    assert.deepEqual(f.data, before, 'replay must not undo any later save');
    assert.equal(generated, 1);
    assert.equal(f.trace.filter(([kind, name]) => kind === 'update' && name === 'CascadeLink').length, 1);
    const conflict = await request(f, { ...body, expectedTopologyRevision: 50, name: 'different request' }, 'durable-edit');
    assert.equal(conflict.status, 409, JSON.stringify(conflict.body));
    assert.equal(conflict.body.error.code, 'TOPOLOGY_INTENT_KEY_CONFLICT');
    assert.deepEqual(f.data, before); assert.equal(generated, 1);
    assert.doesNotMatch(JSON.stringify(replay.body), new RegExp(accepted.realityPrivateKey));
    f.data.CascadeLink.length = 0; // Simulated later completed deletion.
    const absent = await request(f, { ...body, expectedTopologyRevision: 0 }, 'durable-edit');
    assert.equal(absent.status, 202, JSON.stringify(absent.body));
    assert.deepEqual(absent.body.job, first.body.job);
    assert.equal(f.data.CascadeLink.length, 0); assert.equal(generated, 1);
});
