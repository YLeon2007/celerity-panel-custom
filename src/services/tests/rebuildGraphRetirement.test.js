'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createRebuildService } = require('../rebuildService');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const generator = require('../configGenerator');
const NodeSSH = require('../nodeSSH');
const { MAIN } = require('../classicAppliedConfig');
const { rebuildApplyMachineGuard } = require('./helpers/rebuildApplyMachineGuard');

test.before(() => test.mock.method(require('node:net').Socket.prototype, 'connect', () => assert.fail('fixture must not open sockets')));
test.after(() => require('../sshPoolService').closeAll());

const ids = ['1','2','3','4','5','6','7'].map(n => n.repeat(24));
const [portal, relay, exit, upstream, retiredPeer, other, otherExit] = ids;
const incident = (n, portalNode, bridgeNode, extras = {}) => ({
    _id: n.toString(16).padStart(24, '0'), portalNode, bridgeNode, active: true, mode: 'forward',
    tunnelEncryption: 'none', tunnelPort: 14000 + n, tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12,'0')}`, ...extras,
});
const code = name => Object.assign(new Error('untrusted transport detail'), { code: name });

function fixture(t, { isolated = false, offline = true, onlineL2tp = false } = {}) {
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const nodes = ['portal','relay','bridge','portal','bridge','portal','bridge'].map((cascadeRole, i) => ({
        _id: ids[i], name: `Node ${i + 1}`, cascadeRole, type: 'xray', active: i !== 1 || !offline, ip: `192.0.2.${i + 1}`,
        xray: {security: 'none', apiPort: 15000 + i, inboundTag: `users-${i}`}, port: 16000 + i,
    }));
    const expectedDesired = incident(4, upstream, exit);
    // The inactive incident row still has applied ownership, while the
    // tombstone's other endpoint must remain in scope even after the cut.
    const links = isolated ? [] : [incident(1, portal, relay), incident(2, relay, exit, { active: false }),
        incident(3, relay, retiredPeer, { rebuildDelete: true }), expectedDesired, incident(5, other, otherExit)];
    if (!isolated) links[1].rebuildApplied = { mode: 'forward', protocol: 'vless', port: links[1].tunnelPort,
        uuid: links[1].tunnelUuid, listener: exit };
    const installed = onlineL2tp ? [{ _id: 'state', node: relay, status: 'installed', desiredState: 'installed',
        secretRevision: 1, routingMode: 'follow-relay', routingVersion: 1, clientCidr: '10.0.0.0/24', tproxyPort: 58123, fwmark: 260, routeTable: 260 }] : [];
    const trace = [], profileStore = new Map();
    const env = { C3_REBUILD_ENABLED: 'true' };
    const users = [{ userId: 'fixture-user', xrayUuid: '00000000-0000-4000-8000-000000000100' }];
    const controlPlaneAddresses = nodes.map(n => n.ip);
    const baseline = () => composeRebuildProfiles({ nodes: nodes.map(n => ({...n, active: true})),
        links: links.map(l => ({ ...l, active: true })),
        usersByNode: new Map([[portal, users]]), followRelayStates: installed, controlPlaneAddresses });
    function resetProfiles() {
        for (const { nodeId, profile, config } of baseline()) profileStore.set(`${nodeId}:${profile}`, config);
    }
    resetProfiles();
    if (onlineL2tp) {
        const machine = '1'.repeat(32), staged = new Map();
        Object.assign(env, { C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: relay,
            C3_REBUILD_L2TP_RELAY_MACHINE_ID: machine, C3_REBUILD_L2TP_SSH_SHA256: 'a'.repeat(64) });
        nodes[1].ssh = { port: 22, username: 'root' };
        t.mock.method(NodeSSH.prototype, 'connectDirectOnce', async function () { assert.equal(this.node._id, relay); });
        t.mock.method(NodeSSH.prototype, 'disconnect', function () { trace.push(['close', relay]); });
        t.mock.method(NodeSSH.prototype, 'exec', async function (frame, opts) {
            assert.equal(this.node._id, relay);
            const { command, accepts } = rebuildApplyMachineGuard(frame);
            if (accepts) assert.ok(accepts(machine));
            const ok = (stdout = '') => ({ code: 0, stdout, stderr: '' });
            if (command === '/usr/bin/head -c 34 /etc/machine-id') return ok(`${machine}\n`);
            if (command === '/usr/local/bin/xray version') return ok('Xray 26.3.27\n');
            const side = command.includes('xray-bridge'), unit = side ? 'xray-bridge' : 'xray', profile = side ? 'bridge' : 'main';
            const key = `${relay}:${profile}`;
            if (command.startsWith('if test -f ')) return ok(JSON.stringify(profileStore.get(key)));
            if (command.startsWith('systemctl show -p LoadState')) return ok('loaded');
            if (command.startsWith('systemctl show -p ExecStart')) return ok(`path=/usr/local/bin/xray ; -config ${side ? '/usr/local/etc/xray-bridge/config.json' : MAIN} ;`);
            if (command.includes('cat > ')) { staged.set(profile, JSON.parse(opts.stdin)); return ok(); }
            if (command.includes('mv -fT ')) { trace.push(['put', relay]); profileStore.set(key, staged.get(profile)); return ok(); }
            if (command.startsWith(`systemctl enable ${unit}`) || command.startsWith(`systemctl stop ${unit}`)
                || command.startsWith(`systemctl disable ${unit}`) || command.startsWith('rm -f -- ')) return ok();
            assert.fail('unexpected bound transport command');
        });
    }
    let held = false, failReadback = false, failNode, activationError, readError, protectedDrift = false;
    let pendingLinks, commitError, beforeTransaction;
    const query = (resolve, options) => ({ select() { return this; }, read() { return this; }, readConcern() { return this; },
        session(value) { assert.equal(value, session); options.session = value; return this; },
        lean: async () => structuredClone(resolve(options?.session)) });
    const session = {
        transaction: { transition() { session.active = false; } },
        startTransaction() { assert.ok(held); trace.push(['begin']); beforeTransaction?.(); session.active = true; pendingLinks = structuredClone(links); },
        inTransaction: () => session.active,
        async abortTransaction() { trace.push(['abort']); session.active = false; },
        async endSession() { assert.equal(session.active, false); },
    };
    const db = {
        async startSession() { return session; },
        getClient: () => ({ db: () => ({ async command(cmd, options) {
            assert.equal(cmd.commitTransaction, 1); assert.equal(options.session, session);
            trace.push(['commit']); if (commitError) throw commitError;
            links.splice(0, links.length, ...pendingLinks); return { ok: 1 };
        } }) }),
    };
    const Link = {
        db,
        find(filter) { return query(current => (current ? pendingLinks : links).filter(l => !filter._id || filter._id.$in.includes(l._id)), {}); },
        async deleteMany(filter, options) {
            assert.equal(options.session, session); trace.push(['delete', ...filter._id.$in]);
            assert.equal(session.active, true);
            let removed = 0;
            for (let i = pendingLinks.length - 1; i >= 0; i--) if (filter._id.$in.includes(pendingLinks[i]._id)) {
                pendingLinks.splice(i, 1); removed++;
            }
            return { acknowledged: true, deletedCount: removed };
        },
        async updateOne(filter, update, options) {
            assert.equal(options.session, session); trace.push(['update', filter._id]);
            const row = pendingLinks.find(l => l._id === filter._id);
            if (!row) return { acknowledged: true, matchedCount: 0 };
            Object.assign(row, update.$set);
            return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
    };
    const service = createRebuildService({
        env, assertNoRelayAccountIntent: async () => assert.ok(held),
        locks: { run: async fn => { assert.equal(held, false); held = true; try { return await fn(() => held); } finally { held = false; } } },
        Node: { find(filter) { return query(() => nodes.filter(n => filter._id.$in.includes(n._id))); } },
        Link, State: { db, find(filter) { trace.push(['state', ...filter.node.$in]); return query(() => installed.filter(r => filter.node.$in.includes(r.node))); } },
        cache: { async invalidateAllSubscriptions() { trace.push(['cache']); } },
        sync: { async _getUsersForNode(node) { trace.push(['users', node._id]); return node._id === portal ? users : []; } },
        compose(input) {
            trace.push(['compose', ...input.affectedNodeIds]);
            if (offline) {
                assert.equal(input.nodes.some(n => n._id === relay), false);
                assert.equal(input.controlPlaneAddresses.includes(nodes[1].ip), false);
                assert.equal(input.followRelayStates.some(r => r.node === relay), false);
            }
            if (offline) assert.equal(input.links.some(l => [l.portalNode,l.bridgeNode].includes(relay)), false);
            return composeRebuildProfiles(input);
        },
        connect(node) {
            const id = node._id;
            assert.ok(held); trace.push(['connect', id]);
            const check = () => { if (failNode === id && activationError) throw activationError; };
            return {
                async requireSupportedCore() { trace.push(['core', id]); },
                async verifyIdentity() { trace.push(['identity', id]); },
                async checkActivation({ readOnly }) { trace.push(['check', id, readOnly]); check(); },
                async prepareActivation() { trace.push(['prepare', id]); },
                async read(profile) {
                    trace.push(['read', id, profile]);
                    if (id === failNode && readError) throw readError;
                    const config = structuredClone(profileStore.get(`${id}:${profile}`));
                    if (profile === 'main' && protectedDrift && id === portal) config.inbounds.find(i => i.tag === 'users-0').port++;
                    if (failReadback && trace.some(x => x[0] === 'put')) config.drift = true;
                    return config;
                },
                async stagePair(pair) { trace.push(['stage', id]); assert.equal(pair.length, 2); },
                async putPair(pair) {
                    trace.push(['put', id]);
                    for (const { profile, config } of pair) profileStore.set(`${id}:${profile}`, structuredClone(config));
                },
                async close() { trace.push(['close', id]); },
            };
        },
    });
    const call = (req, verify) => service.retireGraph({ nodeId: relay, mode: offline ? 'abandon' : 'online', ...req }, verify);
    return { service, call, run: req => service.locks.run(verify => call(req, verify)), nodes, trace, links, session, profileStore, env,
        readbackFault() { failReadback = true; }, commitFault() { commitError = new Error('commit reply lost'); },
        beforeTransaction(fn) { beforeTransaction = fn; },
        fail(id, stage, error) { failNode = id; if (stage === 'read') readError = error; else activationError = error; },
        protect() { protectedDrift = true; },
        removeL2tp() { installed.length = 0; resetProfiles(); },
    };
}

const operations = (f, step) => f.trace.filter(row => row[0] === step).map(row => row.slice(1));
const noWrite = f => assert.deepEqual(f.trace.filter(row => ['stage','prepare','put','begin','delete','update','commit'].includes(row[0])), []);

test('abandon rebuilds both disconnected halves and inactive/tombstone neighbors, then settles exact rows once', async t => {
    const f = fixture(t);
    const preview = await f.run({ preview: true });
    assert.equal(preview.allowed, true);
    assert.deepEqual(preview.nodes.map(n => n.nodeId), [portal, exit, upstream, retiredPeer]);
    noWrite(f);
    f.trace.length = 0;
    const before = structuredClone(f.links);
    const result = await f.run({ preview: false, expectedPreview: preview.previewId, async finish(session) {
        assert.equal(session, f.session);
        assert.deepEqual(f.links, before);
        f.trace.push(['finish']);
    } });
    assert.equal(result.previewId, preview.previewId);
    for (const step of ['connect','users','core','identity','stage','prepare','put','close']) {
        assert.deepEqual(operations(f, step).flat().sort(), [portal, exit, upstream, retiredPeer]);
    }
    assert.deepEqual(operations(f, 'check').sort(), [portal, exit, upstream, retiredPeer].map(id => [id, false]));
    assert.deepEqual(operations(f, 'state'), [[portal, exit, upstream, retiredPeer]]);
    assert.deepEqual(operations(f, 'delete'), [before.slice(0, 3).map(l => l._id)]);
    assert.deepEqual(operations(f, 'update'), [[before[3]._id]]);
    const steps = f.trace.map(row => row[0]);
    assert.ok(steps.lastIndexOf('read') < steps.indexOf('begin'));
    assert.ok(steps.indexOf('delete') < steps.indexOf('finish') && steps.indexOf('finish') < steps.indexOf('commit'));
    assert.deepEqual(f.links.map(l => l._id), before.slice(3).map(l => l._id));
    assert.equal(JSON.stringify([...f.profileStore].filter(([id]) => [portal,exit,upstream,retiredPeer].some(n => id.startsWith(n)))).includes(f.nodes[1].ip), false);
});

test('abandon with zero links has no target transport or projection but can join finish', async t => {
    const f = fixture(t, { isolated: true });
    const preview = await f.run({ preview: true });
    assert.deepEqual(preview.nodes, []);
    await f.run({ preview: false, expectedPreview: preview.previewId, async finish(session) { assert.equal(session, f.session); f.trace.push(['finish']); } });
    assert.deepEqual(f.trace, [['begin'],['finish'],['commit'],['cache']]);
});

test('online cleans target MAIN and BRIDGE after a fresh preview; ordinary L2TP Remove does not invalidate survivorPreview', async t => {
    const f = fixture(t, { offline: false, onlineL2tp: true });
    const original = await f.run({ preview: true });
    assert.equal(original.allowed, true);
    await assert.rejects(f.run({ preview: false, expectedPreview: original.previewId }), { code: 'REBUILD_L2TP_STATE_TRANSITION' });
    f.removeL2tp();
    const fresh = await f.run({ preview: true });
    assert.notEqual(original.previewId, fresh.previewId);
    assert.equal(original.survivorPreview, fresh.survivorPreview);
    await assert.rejects(f.run({ preview: false, expectedPreview: original.previewId }), { code: 'REBUILD_PREVIEW_CHANGED' });
    noWrite(f);
    await f.run({ preview: false, expectedPreview: fresh.previewId });
    assert.ok(operations(f, 'put').flat().includes(relay));
    const configs = [...f.profileStore].filter(([key]) => key.startsWith(relay));
    for (const row of configs) assert.doesNotMatch(JSON.stringify(row), /(?:relay-l2tp-|fwd-hop-|"fwd-)/);
});

test('desired tunnel key provisioning joins settlement, never incident retirement or a pre-readback write', async t => {
    const f = fixture(t);
    const survivor = f.links[3];
    survivor.tunnelEncryption = 'vless-enc';
    await assert.rejects(f.run({ preview: true }), { code: 'REBUILD_LINK_KEY_UNAVAILABLE' });
    noWrite(f);
    f.env.ENCRYPTION_KEY = 'fixture-root'.repeat(4);
    const { previewId } = await f.run({ preview: true });
    noWrite(f);
    f.trace.length = 0;
    await f.run({ preview: false, expectedPreview: previewId });
    const steps = f.trace.map(row => row[0]);
    assert.ok(steps.lastIndexOf('read') < steps.indexOf('begin'));
    assert.ok(steps.lastIndexOf('close') < steps.indexOf('begin'));
    assert.deepEqual(operations(f, 'begin'), [[]]);
    assert.deepEqual(operations(f, 'update'), [[survivor._id], [survivor._id]]);
    assert.match(f.links[0].rebuildVlessKeyEnvelope, /^v1\./);
});

test('inactive incident edit or newly incident row invalidates confirmation before transport', async t => {
    const f = fixture(t);
    const preview = await f.run({ preview: true });
    f.trace.length = 0;
    f.links[1].note = 'different';
    await assert.rejects(f.run({ preview: false, expectedPreview: preview.previewId }), { code: 'REBUILD_LINK_CHANGED' });
    f.links[1].note = undefined; delete f.links[1].note;
    f.links.push(incident(6, relay, otherExit, { active: false, rebuildApplied: null }));
    await assert.rejects(f.run({ preview: false, expectedPreview: preview.previewId }), { code: 'REBUILD_LINK_CHANGED' });
    assert.deepEqual(f.trace, []);
});

test('unsupported old applied endpoints, ineligible target and malformed survivor topology are never silently skipped', async t => {
    const f = fixture(t);
    const receipt = f.links[1].rebuildApplied;
    receipt.listener = otherExit;
    await assert.rejects(f.run({ preview: true }), { code: 'REBUILD_L2TP_APPLIED_LINK_UNPROVED' });
    receipt.listener = exit;
    f.nodes[1].cascadeRole = 'bridge';
    await assert.rejects(f.run({ preview: true }), { code: 'REBUILD_NODE_UNSUPPORTED' });
    f.nodes[1].cascadeRole = 'relay';
    f.links[3].mode = 'invalid';
    await assert.rejects(f.run({ preview: true }), { code: 'REBUILD_INVALID_MODE' });
    noWrite(f);
});

test('preflight checks a disconnected component and maps only safe transport evidence', async t => {
    const f = fixture(t);
    f.fail(retiredPeer, 'read', code('ECONNREFUSED'));
    await assert.rejects(f.run({ preview: true }), error => error.code === 'REBUILD_NEIGHBOR_UNAVAILABLE' &&
        error.nodeId === retiredPeer && !JSON.stringify(error).includes('untrusted'));
    f.fail(retiredPeer, 'read', code('CLASSIC_APPLIED_BASELINE_INVALID'));
    await assert.rejects(f.run({ preview: true }), { code: 'CLASSIC_APPLIED_BASELINE_INVALID' });
    noWrite(f);
});

test('preserves protected profiles and activation refusal before any staging', async t => {
    const f = fixture(t);
    const original = await f.run({ preview: true });
    f.fail(retiredPeer, 'activation', code('REBUILD_L2TP_APPLY_NETWORK_REFUSED'));
    await assert.rejects(f.run({ preview: false, expectedPreview: original.previewId }), { code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED' });
    f.fail(retiredPeer, 'activation', null);
    f.protect();
    const drift = await f.run({ preview: true });
    assert.equal(drift.allowed, false);
    assert.notEqual(original.survivorPreview, drift.survivorPreview);
    await assert.rejects(f.run({ preview: false, expectedPreview: drift.previewId }), { code: 'REBUILD_CLIENT_CHANGE' });
    noWrite(f);
});

test('retire and link previews project only an attributed read-only activation refusal', async t => {
    const f = fixture(t, { offline: false });
    const peer = f.nodes.find(n => n._id === retiredPeer);
    peer.name = '  212\n\u202e East  ';
    const family = 'REBUILD_L2TP_APPLY_NETWORK_REFUSED';
    const denied = (reason, extra) => Object.assign(code(family), { reason, nodeName: '/private/path', ...extra });
    f.fail(retiredPeer, 'activation', denied('RUNTIME_FOREIGN_CHANGE'));
    const link = f.links.find(l => l.bridgeNode === retiredPeer);
    for (const preview of [() => f.run({ preview: true }),
        () => f.service.execute({ linkId: link._id, preview: true, remove: true })]) {
        await assert.rejects(preview(), error => {
            assert.equal(error.code, 'REBUILD_RETIRE_NEIGHBOR_REFUSED');
            const { neighborRefusalForError } = require('../rebuildNeighborRefusal');
            assert.deepEqual(neighborRefusalForError(error), {
                code: 'REBUILD_RETIRE_NEIGHBOR_REFUSED', neighborName: '212 East', reason: 'RUNTIME_FOREIGN_CHANGE',
            });
            return true;
        });
    }
    assert.ok(f.trace.some(([kind, id]) => kind === 'check' && id === retiredPeer));
    assert.ok(f.trace.filter(([kind]) => kind === 'check').every(([, , readOnly]) => readOnly === true));
    f.fail(retiredPeer, 'activation', denied('/private/path'));
    peer.name = '界'.repeat(130);
    await assert.rejects(f.run({ preview: true }), error => {
        const { neighborRefusalForError } = require('../rebuildNeighborRefusal');
        assert.deepEqual(neighborRefusalForError(error), {
            code: 'REBUILD_RETIRE_NEIGHBOR_REFUSED', neighborName: '界'.repeat(80), reason: 'APPLY_NETWORK_REFUSED',
        });
        return true;
    });
    f.fail(retiredPeer, 'activation', denied('RUNTIME_FOREIGN_CHANGE', { outcome: 'unknown' }));
    await assert.rejects(f.run({ preview: true }), { code: family, outcome: 'unknown' });
    f.fail(retiredPeer, 'activation', code('REBUILD_L2TP_IDENTITY_CHANGED'));
    await assert.rejects(f.run({ preview: true }), { code: 'REBUILD_L2TP_IDENTITY_CHANGED' });
    f.fail(relay, 'activation', denied('RUNTIME_FOREIGN_CHANGE'));
    await assert.rejects(f.run({ preview: true }), { code: family });
    noWrite(f);
});

test('readback mismatch starts no transaction and leaves incident rows untouched', async t => {
    const f = fixture(t);
    const snapshot = structuredClone(f.links);
    const { previewId } = await f.run({ preview: true });
    f.readbackFault();
    await assert.rejects(f.run({ preview: false, expectedPreview: previewId, finish: async () => assert.fail('unexpected finish') }),
        { code: 'REBUILD_READBACK_MISMATCH' });
    assert.deepEqual(operations(f, 'begin'), []);
    assert.deepEqual(f.links, snapshot);
});

test('settlement rereads the original scope in-session and refuses a late incident insertion', async t => {
    const f = fixture(t);
    const { previewId } = await f.run({ preview: true });
    f.beforeTransaction(() => f.links.push(incident(6, relay, otherExit, { active: false, rebuildApplied: null })));
    await assert.rejects(f.run({ preview: false, expectedPreview: previewId, async finish() { assert.fail('stale settlement'); } }),
        { code: 'REBUILD_LINK_CHANGED' });
    assert.deepEqual(operations(f, 'abort'), [[]]);
    for (const step of ['update','delete','commit']) assert.deepEqual(operations(f, step), []);
    assert.equal(f.links.length, 6);
});

test('finish refusal rolls back changes; lost commit is not replayed or aborted', async t => {
    const f = fixture(t);
    const before = structuredClone(f.links);
    const { previewId } = await f.run({ preview: true });
    await assert.rejects(f.run({ preview: false, expectedPreview: previewId, async finish() { throw code('FINISH_REFUSED'); } }),
        { code: 'FINISH_REFUSED' });
    assert.deepEqual(f.links, before);
    assert.deepEqual(operations(f, 'abort'), [[]]);
    assert.deepEqual(operations(f, 'commit'), []);
    const fresh = await f.run({ preview: true });
    f.commitFault();
    await assert.rejects(f.run({ preview: false, expectedPreview: fresh.previewId, async finish() { f.trace.push(['finish']); } }));
    assert.deepEqual(operations(f, 'finish'), [[]]);
    assert.deepEqual(operations(f, 'commit'), [[]]);
    assert.deepEqual(operations(f, 'abort'), [[]]);
});

test('only a live service-issued verifier can enter retirement; execute cannot select retirement via request data', async t => {
    const f = fixture(t, { isolated: true });
    await assert.rejects(f.call({ preview: true }), { code: 'REBUILD_LOCK_LOST' });
    await assert.rejects(f.call({ preview: true }, async () => {}), { code: 'REBUILD_LOCK_LOST' });
    const expired = await f.service.locks.run(verify => verify);
    await assert.rejects(f.call({ preview: true }, expired), { code: 'REBUILD_LOCK_LOST' });
    await assert.rejects(f.service.execute({ nodeId: relay, mode: 'abandon', preview: true, retire: true,
        finish: () => assert.fail('not an execution option') }), { code: 'REBUILD_NODE_UNSUPPORTED' });
    noWrite(f);
});
