'use strict';

const assert = require('node:assert/strict');
const { test, after } = require('node:test');
const { once } = require('node:events');
const { randomUUID } = require('node:crypto');
const { runInNewContext } = require('node:vm');
const { guard, PORT, SET, uri } = require('./fixture.cjs');
// Refuse before loading any application models or connecting.
guard(process.env.PARENT_NETNS);
assert.equal(process.env.C3_RETIRE_FIXTURE_PORT, PORT);
const mode = process.env.FIXTURE_MODE;
assert.ok(['graph', 'public'].includes(mode));

const mongoose = require('mongoose');
const express = require('express');
const source = path => require(`../src/${path}`);
const Node = source('models/hyNodeModel');
const User = source('models/hyUserModel');
const Link = source('models/cascadeLinkModel');
const Settings = source('models/settingsModel');
const State = source('modules/relay-l2tp/models/relayL2tpStateModel');
const Account = source('modules/relay-l2tp/models/l2tpUserModel');
const serviceModule = source('services/rebuildService');
const { createRebuildService } = serviceModule;
const { createRetireStore } = source('services/rebuildRelayRetireStore');
const { createRelayGrantStore, GRANTS, RETIRED } = source('services/rebuildRelayGrantStore');
const { collectionName: DIRECTORY } = source('services/rebuildRelayDirectory');
const { composeRebuildProfiles } = source('modules/relay-l2tp/services/rebuildTopologyComposer');
const { buildPanelInlineCertificate } = source('services/configGenerator');
const sync = source('services/syncService');
const NodeSSH = source('services/nodeSSH');
const db = mongoose.connection;
const { ObjectId } = mongoose.Types;
const ids = ['1', '2', '3', '4', '5', '6', '7'].map(n => n.repeat(24));
const [portal, relay, exit, upstream, tombstone, unrelated, unrelatedExit] = ids;
const survivors = [portal, exit, upstream, tombstone];
const secret = 'FIXTURE_PRIVATE_ENVELOPE';
const nodeIP = id => `192.0.2.${ids.indexOf(id) + 1}`;
const oid = id => new ObjectId(id);
const rowId = n => n.toString(16).padStart(24, '0');
const incident = (n, from, to, extras = {}) => ({
    _id: oid(rowId(n)), portalNode: oid(from), bridgeNode: oid(to), active: true, mode: 'forward',
    tunnelEncryption: 'none', tunnelPort: 14000 + n, tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, ...extras,
});
const binding = { nodeId: relay, host: nodeIP(relay), port: 22, username: 'root',
    machineId: '2'.repeat(32), sshHostKeySha256: '2'.repeat(64) };
const relayUserId = oid(rowId(11));
const noStage = trace => assert.deepEqual(trace.filter(e => ['stage', 'prepare', 'put'].includes(e[0])), []);
const lockCollection = 'c3_rebuild_locks';
const refuseNetwork = Object.assign(new Error('modeled neighbor unavailable'), { code: 'ECONNREFUSED' });
const noDbWrite = commands => assert.deepEqual(commands.filter(x => x.collection !== lockCollection), []);
after(() => source('services/sshPoolService').closeAll());

async function fixture(t, { orphan = false, linkOnly = false, publicProbe = false, online } = {}) {
    const name = `retire_join_${randomUUID().replaceAll('-', '')}`;
    await mongoose.connect(uri, { dbName: name, serverSelectionTimeoutMS: 2000, monitorCommands: true,
        autoIndex: false, autoCreate: false });
    const observer = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 2000 });
    t.after(async () => {
        try { await db.dropDatabase(); }
        finally { await observer.close(); await mongoose.disconnect(); }
    });
    const independent = observer.db(name);
    const hello = await independent.admin().command({ hello: 1 });
    assert.equal(hello.setName, SET);
    assert.equal(hello.isWritablePrimary, true);
    assert.deepEqual(hello.hosts, [`127.0.0.1:${PORT}`]);
    const nodes = ['portal', 'relay', 'bridge', 'portal', 'bridge', 'portal', 'bridge'].map((cascadeRole, i) => ({
        _id: oid(ids[i]), name: `Fixture ${cascadeRole} ${i}`, cascadeRole, type: 'xray', active: i !== 1 || !!online,
        ip: nodeIP(ids[i]), port: 16000 + i, xray: { security: 'none', apiPort: 15000 + i, inboundTag: `users-${i}` },
        ...(i === 1 && { ssh: { port: 22, username: 'root', password: secret } }),
    }));
    nodes[1].xray.agentToken = secret;
    await Node.collection.insertMany(nodes);
    const links = orphan ? [] : linkOnly ? [incident(3, relay, tombstone, { rebuildDelete: true, active: false })] : [
        incident(1, portal, relay), incident(2, relay, exit, { active: false, rebuildApplied: {
            mode: 'forward', protocol: 'vless', port: 14002, uuid: '00000000-0000-4000-8000-000000000002', listener: oid(exit),
        } }), incident(3, relay, tombstone, { rebuildDelete: true }), incident(4, upstream, exit), incident(5, unrelated, unrelatedExit),
    ];
    online?.linkReceipts(links);
    if (links.length) await Link.collection.insertMany(links);
    await Settings.collection.insertOne({ _id: 'settings', deployment: { completed: true } });
    await User.collection.insertMany([
        { _id: relayUserId, userId: 'fixture-subscriber', enabled: true, nodes: [oid(portal), oid(relay), relay],
            xrayUuid: '00000000-0000-4000-8000-000000000100' },
        { _id: oid(rowId(12)), userId: 'fixture-sibling-subscriber', enabled: true, nodes: [oid(unrelated)],
            xrayUuid: '00000000-0000-4000-8000-000000000101' },
    ]);
    if (!linkOnly) {
        await createRelayGrantStore({ db, env: process.env }).mutate({ action: 'grant', binding: online?.binding ?? binding, actor: 'fixture-admin' });
        // Orphan variant has no links, state or accounts: enrollment alone must refuse bare DELETE.
        if (!orphan) {
            await State.collection.insertOne({ _id: oid(relay), node: oid(relay), status: 'installed', desiredState: 'installed',
                routingMode: 'follow-relay', routingVersion: 1, rebuildMachineId: binding.machineId,
                rebuildInstallToken: randomUUID(), backupId: binding.machineId, secretRevision: 1, pskEncrypted: secret, installedAt: new Date(1),
                clientCidr: '10.200.2.0/24', localAddress: '10.200.2.1', poolStart: '10.200.2.10', poolEnd: '10.200.2.20',
                ...online?.state });
            const accounts = online?.accounts ?? ['relay-bootstrap', 'disabled'].map((login, i) => ({
                login, enabled: i === 0, passwordEncrypted: `${secret}-${i}`, ip: `10.200.2.${10 + i}`,
            }));
            await Account.collection.insertMany(accounts.map((account, i) => ({
                _id: oid(rowId(13 + i)), relayNode: oid(relay), ...account,
                syncStatus: 'synced', desiredRevision: 1, appliedRevision: 1,
            })));
        }
    }
    // Compose seeded applied profiles with the stock composer and subscriber projection.
    // Preserve even the obsolete inactive/tombstone legs in the preimage.
    const cert = buildPanelInlineCertificate();
    const usersByNode = new Map();
    for (const node of nodes) usersByNode.set(String(node._id), await sync._getUsersForNode(node));
    const composition = { nodes: nodes.map(n => ({ ...n, _id: String(n._id), active: true })),
        links: links.map(l => ({ ...l, _id: String(l._id), portalNode: String(l.portalNode), bridgeNode: String(l.bridgeNode), active: true })),
        usersByNode, panelTls: { ...cert, serverName: cert?.domain || process.env.PANEL_DOMAIN },
        controlPlaneAddresses: [process.env.PANEL_DOMAIN, ...nodes.map(n => n.ip)] };
    const initial = composeRebuildProfiles(online
        ? { ...composition, followRelayStates: [{ node: relay, ...online.state }] } : composition);
    const profiles = new Map(initial.map(({ nodeId, profile, config }) => [`${nodeId}:${profile}`, config]));
    const trace = [], commands = [], targetCalls = [], probes = [];
    const touched = [Node.collection.name, User.collection.name, Link.collection.name, State.collection.name,
        Account.collection.name, GRANTS, DIRECTORY, RETIRED];
    db.getClient().on('commandStarted', ({ commandName, command, requestId }) => {
        if (!['insert', 'update', 'delete', 'findAndModify', 'commitTransaction', 'abortTransaction'].includes(commandName)
            && command.autocommit !== false) return;
        const event = { commandName, requestId, collection: command[commandName], txn: command.txnNumber?.toString(),
            session: command.lsid?.id?.toString('hex'), inTxn: command.autocommit === false };
        commands.push(event);
        trace.push(['mongo', event]);
    });
    db.getClient().on('commandSucceeded', e => {
        if (e.commandName === 'commitTransaction') trace.push(['committed', e.requestId, e.reply.ok]);
    });
    const snapshot = async (raw = true) => Object.fromEntries(await Promise.all(touched.map(async name => [name,
        await independent.collection(name).find({}, { raw, sort: { _id: 1 }, readConcern: { level: 'majority' } }).toArray(),
    ])));
    function unexpectedTarget(...args) {
        targetCalls.push(args);
        assert.fail('ordinary transport called for the abandoned target');
    }
    // Unexpected real SSH dispatch must fail even if the caller swallows it.
    for (const method of online ? ['connect'] : ['connect', 'connectDirectOnce', '_openDirectClient', 'exec']) {
        if (typeof NodeSSH.prototype[method] !== 'function') continue;
        t.mock.method(NodeSSH.prototype, method, function () {
            if (publicProbe && method === 'connectDirectOnce' && String(this.node?._id) === relay) {
                probes.push('ssh-admission');
                throw refuseNetwork;
            }
            targetCalls.push([method, String(this.node?._id)]);
            assert.fail('fixture must not dispatch stock SSH');
        });
    }
    t.mock.method(sync, 'readRebuildReverseObservation', async (node, path) => {
        if (online && String(node._id) === relay && path === '/info') {
            probes.push('agent-info');
            await online.probeBarrier?.();
            return { status: 200, data: '{"agent_version":"fixture"}' };
        }
        if (publicProbe && String(node._id) === relay && path === '/info') {
            probes.push('agent-info');
            throw refuseNetwork;
        }
        unexpectedTarget('agent', String(node._id), path);
    });
    t.after(() => assert.deepEqual(targetCalls, []));
    online?.wire(t, { profiles, trace, independent, composition });
    let failCheckAt = 0, secondNeighborChecks = 0, corruptReadback = false;
    function connect(node) {
        const id = String(node._id);
        if (id === relay) unexpectedTarget('connect', id);
        assert.ok(survivors.includes(id), `out-of-scope transport ${id}`);
        trace.push(['connect', id]);
        let staged, put = false, closed = false;
        const record = (step, ...args) => { assert.equal(closed, false); trace.push([step, id, ...args]); };
        return {
            async requireSupportedCore() { record('core'); },
            async verifyIdentity() { record('identity'); },
            async checkActivation() { record('check'); if (id === exit && ++secondNeighborChecks === failCheckAt) throw refuseNetwork; },
            async read(profile) {
                record(put ? 'readback' : 'read', profile);
                const config = structuredClone(profiles.get(`${id}:${profile}`));
                assert.ok(config, `missing model profile ${id}:${profile}`);
                if (put && corruptReadback && id === exit && profile === 'bridge') config.fixtureDrift = true;
                return config;
            },
            async stagePair(pair) { record('stage'); staged = structuredClone(pair); },
            async prepareActivation() { record('prepare'); assert.ok(staged); },
            async putPair(pair) {
                record('put');
                assert.deepEqual(pair, staged);
                assert.deepEqual(pair.map(x => x.profile).sort(), ['bridge', 'main']);
                for (const { profile, config } of staged) profiles.set(`${id}:${profile}`, config);
                put = true;
            },
            async close() { record('close'); closed = true; },
        };
    }
    const service = () => createRebuildService({ connect });
    const real = service();
    const graph = fn => real.locks.run(verify => fn(req => real.retireGraph({ nodeId: relay, mode: 'abandon', ...req }, verify), verify));
    const reset = () => { trace.length = 0; commands.length = 0; probes.length = 0; secondNeighborChecks = 0; };
    return { independent, snapshot, profiles, trace, commands, probes, reset, graph, service,
        failActivation(check = 1) { failCheckAt = check; }, corruptReadback() { corruptReadback = true; },
        unlocked: async () => assert.equal(await independent.collection(lockCollection).countDocuments(), 0) };
}

async function mount(t, f, panel) {
    const app = express();
    const session = { authenticated: true, adminUsername: 'fixture-admin' };
    // Authentication/session storage alone is simulated. All route/mode/body/
    // scope/onboarding/CSRF guards downstream still run against the fixture.
    app.use((req, _res, next) => { req.session = session; req.sessionID = 'fixture-session'; next(); });
    if (panel) app.use(source('routes/panel/rebuildL2tp').rebuildL2tpIngress);
    app.use(express.json(), source('middleware/i18n').i18nMiddleware);
    app.use('/api/nodes', source('middleware/auth'), source('routes/nodes'));
    if (panel) {
        app.set('views', '/app/views');
        app.set('view engine', 'ejs');
        app.use((_req, res, next) => { res.locals.c3Rebuild = true; next(); });
        // The real route instantiates a fresh service for each request. Preserve
        // that and inject only the test's transport boundary into each instance.
        t.mock.method(serviceModule, 'createRebuildService', f.service);
        app.use('/panel', source('routes/panel').createPanelRouter());
        app.get('/js/rebuild-relay-retire.js', (_req, res) => res.sendFile('/app/public/js/rebuild-relay-retire.js'));
    }
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
    const base = `http://127.0.0.1:${server.address().port}`;
    const endpoint = action => `/panel/rebuild/relays/${relay}/retire/${action}`;
    const csrf = source('routes/panel/csrf').issuePanelCsrfToken({ session });
    async function wire(path, options) {
        assert.match(path, /^\/(?!\/)/);
        const response = await fetch(base + path, { redirect: 'manual', signal: AbortSignal.timeout(6000), ...options });
        const text = await response.text();
        assert.equal(text.includes(secret), false);
        return { status: response.status, cache: response.headers.get('cache-control'), text,
            json: response.headers.get('content-type')?.startsWith('application/json') ? JSON.parse(text) : undefined };
    }
    const send = (path, method, body, token = csrf) => wire(path, { method,
        ...(body && { body: JSON.stringify(body), headers: { 'content-type': 'application/json', 'x-csrf-token': token } }) });
    return { wire, del: () => send(`/api/nodes/${relay}`, 'DELETE'), page: () => send('/panel/nodes', 'GET'),
        preview: token => send(endpoint('preview'), 'POST', {}, token),
        confirm: (preview, token) => send(endpoint('confirm'), 'POST', { ticket: preview.ticket, decision: 'abandon' }, token), csrf };
}

// Exercise the shipped browser script and its actual request/response ABI.
// The tiny DOM/event/location adapter is a model, not a browser engine.
async function retireUi(app, html) {
    const attr = (tag, name) => tag.match(new RegExp(` ${name}="([^"]*)"`))?.[1]
        ?.replace(/&quot;|&#34;|&#39;|&lt;|&gt;|&amp;/g, key => ({ '&quot;': '"', '&#34;': '"', '&#39;': "'", '&lt;': '<', '&gt;': '>', '&amp;': '&' })[key]);
    function widget(tag) {
        assert.ok(tag, 'expected control in actual EJS render');
        const events = new Map();
        return { open: false, hidden: / hidden(?=[ >])/.test(tag), disabled: / disabled(?=[ >])/.test(tag),
            addEventListener(event, cb) { events.set(event, cb); },
            click() { assert.ok(!this.disabled && !this.hidden); return events.get('click')({ detail: 1 }); },
            showModal() { this.open = true; }, focus() {} };
    }
    const tag = html.match(/<dialog\b[^>]* id="relay-retire-dialog"[^>]*>/)?.[0];
    const dialog = widget(tag);
    dialog.dataset = { csrf: attr(tag, 'data-csrf'), messages: attr(tag, 'data-messages'), locale: attr(tag, 'data-locale') };
    assert.equal(dialog.dataset.csrf, app.csrf);
    const copy = JSON.parse(dialog.dataset.messages);
    const fields = Object.fromEntries(['target', 'message', 'status', 'confirm', 'close'].map(field =>
        [`[data-retire-${field}]`, widget(html.match(new RegExp(`<\\w+ [^>]*data-retire-${field}(?=[ >])[^>]*>`))?.[0])]));
    dialog.querySelector = selector => fields[selector];
    const buttonTag = html.match(new RegExp(`<button\\b[^>]* data-retire-node="${relay}"[^>]*>`))?.[0];
    const button = widget(buttonTag);
    button.dataset = { retireNode: attr(buttonTag, 'data-retire-node'), retireName: attr(buttonTag, 'data-retire-name') };
    const src = html.match(/<script\b[^>]* src="(\/js\/rebuild-relay-retire\.js)(?:\?[^" ]*)?"/)?.[1];
    assert.ok(src);
    const asset = await app.wire(src);
    assert.equal(asset.status, 200);
    const requests = [];
    let reloads = 0;
    runInNewContext(asset.text, {
        document: { getElementById: key => key === 'relay-retire-dialog' ? dialog : null, querySelectorAll: () => [button] },
        location: { reload() { reloads++; } },
        async fetch(path, opts) {
            const response = await app.wire(path, opts);
            requests.push({ path, opts, ...response });
            return { status: response.status, ok: response.status < 300, json: async () => response.json };
        },
    });
    return { button, approve: fields['[data-retire-confirm]'], copy, requests, reloads: () => reloads };
}

async function graphPreview(f) {
    const preview = await f.graph(call => call({ preview: true }));
    assert.equal(preview.allowed, true);
    assert.deepEqual(preview.nodes.map(n => n.nodeId), survivors);
    return preview;
}
function graphConfirm(f, store, saved, preview, afterFinish) {
    return f.graph((call, verify) => call({ preview: false, expectedPreview: preview.previewId, async finish(session) {
        await store.finish(saved, session, verify);
        await afterFinish?.();
    } }));
}
function settlement(f) {
    const writes = f.commands.filter(e => e.inTxn && ['insert', 'update', 'delete'].includes(e.commandName));
    const [commit] = f.commands.filter(e => e.commandName === 'commitTransaction');
    assert.equal(f.commands.filter(e => e.commandName === 'commitTransaction').length, 1);
    assert.equal(f.commands.filter(e => e.commandName === 'abortTransaction').length, 0);
    assert.deepEqual(new Set(writes.map(e => e.collection)), new Set([Link.collection.name, Node.collection.name,
        State.collection.name, Account.collection.name, User.collection.name, GRANTS, DIRECTORY, RETIRED]));
    assert.ok(commit.txn && commit.session);
    for (const command of f.commands.filter(e => e.inTxn)) {
        assert.equal(command.txn, commit.txn);
        assert.equal(command.session, commit.session);
    }
    const finish = f.trace.findIndex(e => e[0] === 'mongo' && e[1].inTxn);
    assert.ok(finish > 0);
    const before = f.trace.slice(0, finish);
    assert.deepEqual(before.filter(e => e[0] === 'put').map(e => e[1]), survivors);
    assert.deepEqual(before.filter(e => e[0] === 'readback').map(e => e.slice(1)),
        survivors.flatMap(id => [[id, 'main'], [id, 'bridge']]));
    const afterReadback = before.slice(before.findLastIndex(e => e[0] === 'readback') + 1);
    assert.deepEqual(afterReadback.filter(e => e[0] === 'close').map(e => e[1]), survivors);
    assert.deepEqual(f.trace.filter(e => e[0] === 'committed'), [['committed', commit.requestId, 1]]);
}
async function assertRetired(f, before, beforeProfiles) {
    settlement(f);
    const after = await f.snapshot(false);
    const links = after[Link.collection.name];
    assert.deepEqual(links.map(l => String(l._id)), [rowId(4), rowId(5)]);
    assert.equal(links[0].status, 'deployed');
    assert.equal(String(links[0].rebuildApplied.listener), exit);
    assert.match(links[0].rebuildApplyEpoch, /^[a-f0-9]{32}$/);
    assert.deepEqual(links[1], before[Link.collection.name].at(-1));
    assert.deepEqual(after[Node.collection.name], before[Node.collection.name].filter(n => String(n._id) !== relay));
    assert.deepEqual(after[User.collection.name], [{ ...before[User.collection.name][0], nodes: [oid(portal)] }, before[User.collection.name][1]]);
    for (const name of [State.collection.name, Account.collection.name, GRANTS]) assert.deepEqual(after[name], []);
    assert.deepEqual(after[RETIRED], [{ _id: relay }]);
    assert.equal(after[DIRECTORY].length, 1);
    assert.deepEqual(after[DIRECTORY][0].accounts, before[Account.collection.name].slice().reverse().map(a => ({
        id: String(a._id), login: a.login, enabled: a.enabled, passwordEncrypted: a.passwordEncrypted,
    })));
    assert.ok(JSON.stringify([...beforeProfiles].filter(([key]) => key.startsWith(portal))).includes(nodeIP(relay)));
    assert.equal(JSON.stringify([...f.profiles].filter(([key]) => survivors.some(id => key.startsWith(id)))).includes(nodeIP(relay)), false);
    for (const [key, profile] of beforeProfiles) {
        if (!survivors.some(id => key.startsWith(id))) assert.deepEqual(f.profiles.get(key), profile);
    }
    await f.unlocked();
}

for (const [name, opts, code] of [
    ['an inactive link tombstone', { linkOnly: true }, 'REBUILD_NODE_HAS_LINKS'],
    ['an otherwise orphaned grant', { orphan: true }, 'REBUILD_NODE_RETIRE_REQUIRED'],
]) {
    test(`actual bare REST DELETE refuses to leave ${name}`, async t => {
        const f = await fixture(t, opts);
        const before = await f.snapshot();
        const app = await mount(t, f, false);
        const response = await app.del();
        assert.equal(response.status, 409, response.text);
        assert.equal(response.json.code, code);
        assert.deepEqual(await f.snapshot(), before);
        noDbWrite(f.commands);
        await f.unlocked();
    });
}

test('real graph readback and real retirement store share one transaction in abandon', async t => {
    const f = await fixture(t);
    const before = await f.snapshot(false), beforeRaw = await f.snapshot(), profiles = new Map(f.profiles);
    const store = createRetireStore({ Link, Node, State, L2tpUser: Account });
    const saved = await store.capture(relay);
    const preview = await graphPreview(f);
    noStage(f.trace);
    noDbWrite(f.commands);
    f.reset();
    const result = await graphConfirm(f, store, saved, preview, async () => assert.deepEqual(await f.snapshot(), beforeRaw,
        'a separate MongoClient still sees the complete preimage after the real store finalizer and before commit'));
    assert.equal(result.previewId, preview.previewId);
    await assertRetired(f, before, profiles);
});

test('real graph and store abort one native transaction on a post-finalizer refusal', async t => {
    const f = await fixture(t);
    const before = await f.snapshot();
    const store = createRetireStore({ Link, Node, State, L2tpUser: Account });
    const saved = await store.capture(relay), preview = await graphPreview(f);
    const refusal = new Error('fixture refused after the real store staged its last write');
    f.reset();
    await assert.rejects(graphConfirm(f, store, saved, preview, async () => {
        assert.deepEqual(await f.snapshot(), before, 'separate client cannot see the staged removals');
        throw refusal;
    }), error => error === refusal);
    assert.equal(f.commands.filter(e => e.commandName === 'commitTransaction').length, 0);
    const aborts = f.commands.filter(e => e.commandName === 'abortTransaction');
    assert.equal(aborts.length, 1);
    assert.ok(f.commands.some(e => e.inTxn && e.commandName === 'delete' && e.collection === Node.collection.name));
    for (const command of f.commands.filter(e => e.inTxn)) {
        assert.equal(command.txn, aborts[0].txn);
        assert.equal(command.session, aborts[0].session);
    }
    assert.deepEqual(await f.snapshot(), before);
    await f.unlocked();
});

for (const [kind, fault, code] of [
    ['second neighbor refuses activation preflight', 'failActivation', 'REBUILD_NEIGHBOR_UNAVAILABLE'],
    ['second neighbor post-write readback is corrupted', 'corruptReadback', 'REBUILD_READBACK_MISMATCH'],
]) {
    test(`real graph: ${kind}; never starts Mongo settlement`, async t => {
        const f = await fixture(t);
        const before = await f.snapshot(), profiles = new Map(f.profiles);
        const store = createRetireStore({ Link, Node, State, L2tpUser: Account });
        const saved = await store.capture(relay);
        const preview = await graphPreview(f);
        f.reset();
        f[fault]();
        await assert.rejects(graphConfirm(f, store, saved, preview, () => assert.fail('unexpected finalizer success')), error => {
            assert.equal(error.code, code);
            if (fault === 'failActivation') assert.equal(error.nodeId, exit);
            return true;
        });
        if (fault === 'failActivation') {
            assert.deepEqual(f.trace.filter(e => e[0] === 'check').map(e => e[1]), [portal, exit]);
            noStage(f.trace);
            assert.deepEqual(f.profiles, profiles);
        } else {
            assert.ok(f.trace.some(e => e[0] === 'readback' && e[1] === exit && e[2] === 'bridge'));
            assert.notDeepEqual(f.profiles, profiles, 'readback refusal is not remote rollback');
        }
        noDbWrite(f.commands);
        assert.deepEqual(await f.snapshot(), before);
        await f.unlocked();
    });
}

if (mode === 'public') {
    test('rendered retire action and real panel preview/confirm abandon through graph and Mongo', async t => {
        const f = await fixture(t, { publicProbe: true });

        const before = await f.snapshot(false), raw = await f.snapshot(), profiles = new Map(f.profiles);
        const app = await mount(t, f, true);
        const page = await app.page();
        assert.equal(page.status, 200);
        assert.match(page.text, new RegExp(`data-retire-node="${relay}"`));
        assert.ok(!page.text.includes(`deleteNode('${relay}')`));
        const ui = await retireUi(app, page.text);
        assert.deepEqual(ui.requests, []);
        assert.deepEqual(f.trace.filter(x => x[0] === 'connect'), []);
        assert.deepEqual(f.probes, []);
        const direct = await app.del();
        assert.equal(direct.status, 409, direct.text);
        assert.equal(direct.json.code, 'REBUILD_NODE_HAS_LINKS');
        const observedAfter = Date.now();
        await ui.button.click();
        const [response] = ui.requests;
        assert.equal(ui.requests.length, 1);
        assert.match(response.path, /\/retire\/preview$/);
        assert.equal(response.opts.body, '{}');
        assert.equal(response.status, 200, response.text);
        assert.equal(response.cache, 'no-store');
        const { preview } = response.json;
        const observedAt = Date.parse(preview.unavailableSince);
        assert.ok(observedAt >= observedAfter && observedAt <= Date.now());
        assert.deepEqual({ ...preview, ticket: null }, {
            nodeId: relay, mode: 'abandon', activeClients: null, accountCount: 2,
            unavailableSince: new Date(observedAt).toISOString(), allowed: true, ticket: null,
        });
        assert.match(preview.ticket, /^[a-f0-9]{64}$/);
        assert.equal(ui.approve.textContent, ui.copy.confirmAbandon);
        assert.deepEqual(f.probes, ['agent-info', 'ssh-admission']);
        noStage(f.trace);
        noDbWrite(f.commands);
        assert.deepEqual(await f.snapshot(), raw);
        f.reset();
        await ui.approve.click();
        assert.equal(ui.requests.length, 2);
        const confirm = ui.requests[1];
        assert.match(confirm.path, /\/retire\/confirm$/);
        assert.deepEqual(JSON.parse(confirm.opts.body), { ticket: preview.ticket, decision: 'abandon' });
        assert.equal(confirm.status, 200, confirm.text);
        assert.equal(confirm.cache, 'no-store');
        assert.deepEqual(confirm.json, { nodeId: relay, status: 'deleted' });
        assert.equal(ui.reloads(), 1);
        assert.equal(ui.button.disabled, true);
        assert.deepEqual(f.probes, []);
        await assertRetired(f, before, profiles);
        f.reset();
        const replay = await app.confirm(preview);
        assert.equal(replay.status, 409, 'consumed ticket never replays settlement');
        assert.equal(replay.json.error.code, 'REBUILD_RETIRE_CONFIRMATION_REQUIRED');
        assert.deepEqual(f.commands, []);
        assert.deepEqual(f.trace, []);
    });

    test('real panel confirmation refuses the second neighbor before writes', async t => {
        const f = await fixture(t, { publicProbe: true });

        const app = await mount(t, f, true);
        const before = await f.snapshot(), profiles = new Map(f.profiles);
        const response = await app.preview();
        assert.equal(response.status, 200, response.text);
        assert.equal(response.json.preview.mode, 'abandon');
        assert.equal(response.json.preview.allowed, true);
        f.reset();
        // Let confirmation re-preview all neighbors. Fail only on the actual
        // apply preflight's second neighbor, after the portal passed both rounds.
        f.failActivation(2);
        const failed = await app.confirm(response.json.preview);
        assert.equal(failed.status, 409, failed.text);
        assert.equal(failed.cache, 'no-store');
        assert.deepEqual(failed.json, { error: { code: 'REBUILD_NEIGHBOR_UNAVAILABLE' } });
        assert.deepEqual(f.trace.filter(e => e[0] === 'check').map(e => e[1]), [...survivors, portal, exit]);
        assert.deepEqual(f.probes, []);
        noStage(f.trace);
        noDbWrite(f.commands);
        assert.deepEqual(f.profiles, profiles);
        assert.deepEqual(await f.snapshot(), before);
        await f.unlocked();
    });
}

if (mode === 'public') require('./online.cjs')({ fixture, mount, binding, survivors, nodeIP, relay, portal, exit, rowId, lockCollection,
    collections: { nodes: Node.collection.name, users: User.collection.name, links: Link.collection.name,
        state: State.collection.name, accounts: Account.collection.name, grants: GRANTS, directory: DIRECTORY, retired: RETIRED } });
