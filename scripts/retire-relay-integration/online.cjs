'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { EventEmitter } = require('node:events');
const { createHash } = require('node:crypto');
const { Client } = require('ssh2');
const { Types: { ObjectId } } = require('mongoose');
const { MAIN, BRIDGE } = require('../src/services/classicAppliedConfig');
const { appliedLink } = require('../src/services/rebuildAppliedLink');
const { encrypt } = require('../src/modules/relay-l2tp/services/secretBoxService');
const { composeRebuildProfiles } = require('../src/modules/relay-l2tp/services/rebuildTopologyComposer');
const { rebuildApplyMachineGuard } = require('../src/services/tests/helpers/rebuildApplyMachineGuard');
const { inactiveClassicRelay, operations } = require('../src/services/tests/helpers/rebuildRelayClassicLifecycleFixture');

const sha = value => createHash('sha256').update(value).digest('hex');
const hostKey = Buffer.from('synthetic retirement fixture key');
const paths = { main: MAIN, bridge: BRIDGE };
const profilesInOrder = ['main', 'bridge'];
const network = { clientCidr: '10.200.2.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 };
const stamp = new Date(1);
const writes = new Set(['insert', 'update', 'delete', 'findAndModify']);
const byLogin = (a, b) => a.login.localeCompare(b.login, 'en');

function installedPeer({ binding, collections, relay }, initialCount) {
    const { machineId, host, port, username } = binding;
    const bindingId = new ObjectId(relay);
    const backupId = 'a'.repeat(32);
    const state = { ...network, backupId, status: 'installed', desiredState: 'installed', routingMode: 'follow-relay',
        routingVersion: 1, secretRevision: 1, updatedAt: stamp, lastVerifiedAt: stamp, lastSyncAt: stamp };
    // The persisted bootstrap must occupy the first slot in the pool.
    const currentUsers = ['relay-bootstrap', 'relay-secondary', 'disabled'].map((login, i) => ({ login, enabled: i < 2,
        password: `synthetic-chap-${i}`, ipAddress: `10.200.2.${10 + i}` }));
    let count = initialCount, generation = 0, joined = true;
    const receipt = () => sha(`${backupId}:${count}:${generation}`);
    // Equal PPP and IPsec tallies alone do not establish a joined cohort.
    const confirmedCount = () => count === 0 || (joined && count <= 32) ? count : null;
    const model = { installed: true, chap: ['foreign-line', 'owned-block'], policy: ['foreign-chain', 'owned-policy'],
        listeners: ['foreign-listener', 'owned-xl2tpd', 'owned-ipsec'] };
    const snapshot = () => structuredClone(model);
    return {
        binding: { ...binding, sshHostKeySha256: sha(hostKey) }, state, snapshot,
        setCensus(nextCount, hasJoin = true) { count = nextCount; joined = hasJoin; generation++; },
        accounts: currentUsers.map(({ login, enabled, password, ipAddress }) => ({
            login, enabled, ip: ipAddress, passwordEncrypted: encrypt(password, process.env.ENCRYPTION_KEY),
            createdAt: stamp, updatedAt: stamp, lastSyncedAt: stamp,
        })),
        linkReceipts(links) {
            for (const link of links.filter(l => [l.portalNode, l.bridgeNode].some(id => String(id) === relay))) {
                Object.assign(link, { rebuildApplied: appliedLink(link), status: 'deployed' });
            }
        },
        wire(t, { profiles, trace, independent, composition }) {
            const plainTarget = composeRebuildProfiles(composition).filter(p => p.nodeId === relay);
            const [listener] = composition.links;
            const transit = [{ linkId: listener._id, mode: 'forward', port: listener.tunnelPort, uuid: listener.tunnelUuid }];
            const baseline = sha('owned installed target preimage');
            const clients = new Map(), faults = [];
            const getState = () => independent.collection(collections.state).findOne({ node: bindingId },
                { readConcern: { level: 'majority' } });
            const ack = value => JSON.stringify(value) + '\n';
            const direct = /^\/usr\/bin\/timeout (-k (?:1s 22s|4s 125s)) \/usr\/bin\/python3 -I -B -c '[^']+'$/;
            t.after(() => { assert.deepEqual(faults, []); assert.equal(clients.size, 0, 'all modeled SSH clients closed'); });
            t.mock.method(Client.prototype, 'connect', function (config) {
                try {
                    assert.deepEqual([config.host, config.port, config.username], [host, port, username]);
                    assert.equal(config.hostVerifier(hostKey), true);
                    clients.set(this, { staged: new Map() });
                    queueMicrotask(() => this.emit('ready'));
                    return this;
                } catch (error) { faults.push(error); throw error; }
            });
            t.mock.method(Client.prototype, 'end', function () { assert.ok(clients.delete(this)); });
            t.mock.method(Client.prototype, 'exec', function (outer, onChannel) {
                const peer = clients.get(this);
                const { command, accepts } = rebuildApplyMachineGuard(outer);
                const directCall = direct.exec(command);
                const hasStdin = !!directCall || command.includes('(set -C; cat > ');
                const stream = new EventEmitter(), chunks = [];
                stream.stderr = new EventEmitter();
                stream.write = bytes => { chunks.push(Buffer.from(bytes)); return true; };
                stream.end = done => { done(); queueMicrotask(() => run(Buffer.concat(chunks).toString('utf8'))); };
                stream.destroy = () => {};
                const reply = (stdout = '', code = 0, stderr = '') => {
                    if (stdout) stream.emit('data', stdout);
                    if (stderr) stream.stderr.emit('data', stderr);
                    stream.stderr.emit('end');
                    stream.emit('close', code);
                };
                const run = async stdin => {
                    try {
                        assert.ok(peer);
                        if (outer === '/usr/bin/head -c 34 /etc/machine-id') {
                            peer.attested = true;
                            return reply(`${machineId}\n`);
                        }
                        if (directCall) {
                            const request = JSON.parse(stdin);
                            const { action, ...input } = request;
                            assert.deepEqual([input.machineId, input.backupId, input.network], [machineId, backupId, network]);
                            assert.equal(directCall[1], action === 'retirement-count' ? '-k 1s 22s' : '-k 4s 125s');
                            assert.ok(model.installed);
                            trace.push(['direct', action]);
                            if (action === 'check-apply-network') {
                                assert.deepEqual(input, { machineId, backupId, network });
                                return reply(ack({ ok: true, backupId, proof: baseline }));
                            }
                            // DIRECT must attest on this same client before passing
                            // private stdin. The modeled receiver starts only at EOF.
                            assert.equal(peer.attested, true);
                            peer.attested = false;
                            const expected = { machineId, backupId, network, nodeId: relay, currentUsers: currentUsers.toSorted(byLogin), transit };
                            if (action === 'retirement-count') {
                                assert.deepEqual(input, expected);
                                return reply(ack({ activeSessions: count, activeIpsec: count, census: receipt(), activeClients: confirmedCount() }));
                            }
                            assert.notEqual(confirmedCount(), null, 'unconfirmed census must not reach Remove');
                            Object.assign(expected, { retirement: true, expectedCensus: receipt(), ...(count > 0 && { drain: true }) });
                            if (action === 'prepare-remove') {
                                assert.deepEqual(input, expected);
                                assert.equal((await getState()).status, 'installed');
                                peer.prepared = true;
                                return reply(ack({ ok: true, backupId, machineId, baseline }));
                            }
                            assert.equal(action, 'remove');
                            assert.equal(peer.prepared, true);
                            assert.deepEqual(input, { ...expected, baseline });
                            assert.equal((await getState()).status, 'removing');
                            assert.deepEqual(model.chap, ['foreign-line', 'owned-block']);
                            for (const { profile, config } of plainTarget) profiles.set(`${relay}:${profile}`, config);
                            Object.assign(model, { installed: false, chap: ['foreign-line'], policy: ['foreign-chain'],
                                listeners: ['foreign-listener'] });
                            const drained = count;
                            count = 0;
                            trace.push(['host-removed', drained]);
                            return reply(ack({ ok: true, backupId, removed: true }));
                        }
                        if (command === '/usr/local/bin/xray version') return reply('Xray 26.3.27 (fixture)\n');
                        for (const [profile, path] of Object.entries(paths)) {
                            const unit = profile === 'main' ? 'xray' : 'xray-bridge';
                            if (command === `if test -f ${path}; then cat ${path}; elif test ! -e ${path}; then printf 'C3_CLASSIC_PROFILE_ABSENT'; else exit 1; fi`) {
                                if (peer.applied) trace.push(['readback', relay, profile]);
                                return reply(JSON.stringify(profiles.get(`${relay}:${profile}`)));
                            }
                            if (command === `systemctl show -p LoadState --value ${unit}.service`) return reply('loaded\n');
                            if (command === `systemctl show -p ExecStart --value ${unit}.service`) return reply(`path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${path} ;`);
                            if (command.includes(`cat > ${path}.rebuild-`)) {
                                assert.ok(accepts?.(machineId));
                                assert.equal(model.installed, false, 'no graph staging before host removal');
                                assert.equal((await getState()).status, 'not_installed', 'Remove settled before graph staging');
                                peer.staged.set(profile, JSON.parse(stdin));
                                trace.push(['target-stage', profile]);
                                return reply();
                            }
                            if (command.startsWith('set -eu; if test -f ') && command.endsWith(` ${path}`)) {
                                assert.ok(accepts?.(machineId));
                                assert.ok(peer.staged.has(profile));
                                profiles.set(`${relay}:${profile}`, peer.staged.get(profile));
                                return reply();
                            }
                        }
                        assert.ok(accepts?.(machineId));
                        if (command === 'systemctl enable xray.service && systemctl restart xray.service && systemctl is-active --quiet xray.service') {
                            assert.equal(peer.staged.size, 2);
                            peer.applied = true;
                            trace.push(['put', relay]);
                        } else if (command.startsWith('rm -f -- ')) {
                            peer.staged.clear();
                            trace.push(['target-cleanup']);
                        } else assert.ok(['systemctl stop xray-bridge.service', 'systemctl disable xray-bridge.service'].includes(command), 'unexpected graph command');
                        return reply();
                    } catch (error) { faults.push(error); stream.emit('error', error); }
                };
                onChannel(null, stream);
                if (!hasStdin) queueMicrotask(() => run());
            });
        },
    };
}

module.exports = function onlineTests(ctx) {
    const { fixture, mount, relay, portal, exit, survivors, nodeIP, rowId, collections: C, lockCollection } = ctx;
    const path = `/panel/rebuild/relays/${relay}/retire/confirm`;
    const confirm = (app, ticket, decision, csrf = app.csrf) => app.wire(path, { method: 'POST',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify({ ticket, decision }) });
    async function mountOnline(t, f) {
        // Each case has its own fixture DB/session, but the stock router's
        // localhost rate-limit bucket is shared. Reset only between cases.
        require('../src/routes/panel').l2tpRateLimiter.resetKey('127.0.0.1');
        return mount(t, f, true);
    }
    async function rejectedReplay(app, ticket, decision) {
        const replay = await confirm(app, ticket, decision);
        assert.equal(replay.status, 409, replay.text);
        assert.deepEqual(replay.json, { error: { code: 'REBUILD_RETIRE_CONFIRMATION_REQUIRED' } });
    }
    const previewIs = ({ status, cache, json, text }, clients, expectedStatus = 200) => {
        assert.equal(status, expectedStatus, text);
        assert.equal(cache, 'no-store');
        const { ticket, ...preview } = json.preview;
        assert.deepEqual(preview, { nodeId: relay, mode: 'online', activeClients: clients,
            accountCount: 3, allowed: true, unavailableSince: null });
        assert.match(ticket, /^[a-f0-9]{64}$/);
        return ticket;
    };
    async function unchanged(f, host, before, profiles, hostBefore) {
        assert.deepEqual(await f.snapshot(), before);
        assert.deepEqual(f.profiles, profiles);
        assert.deepEqual(host.snapshot(), hostBefore);
        assert.deepEqual(f.commands.filter(e => e.collection !== lockCollection), []);
        assert.deepEqual(f.trace.filter(e => ['stage', 'target-stage', 'prepare', 'put', 'host-removed'].includes(e[0])
            || e[0] === 'direct' && ['prepare-remove', 'remove'].includes(e[1])), []);
        await f.unlocked();
    }
    async function retired(f, host, before, profiles, count, classicState) {
        const writesIn = commit => f.commands.filter(e => e.inTxn && e.session === commit.session && e.txn === commit.txn
            && writes.has(e.commandName)).map(e => e.collection);
        const commits = f.commands.filter(e => e.commandName === 'commitTransaction');
        assert.equal(commits.length, 3, 'Remove reservation, Remove settlement, graph retirement');
        const [reserve, remove, graph] = commits;
        assert.deepEqual(new Set(writesIn(reserve)), new Set([C.directory, C.state]));
        assert.deepEqual(writesIn(remove), [C.accounts, C.accounts, C.accounts, C.state]);
        assert.deepEqual(new Set(writesIn(graph)), new Set([C.links, C.nodes, C.users, C.state, C.grants, C.retired]));
        assert.deepEqual(f.commands.filter(e => e.commandName === 'abortTransaction'), []);
        assert.deepEqual(f.trace.filter(e => e[0] === 'committed'), commits.map(c => ['committed', c.requestId, 1]));
        const cut = c => f.trace.findIndex(e => e[0] === 'committed' && e[1] === c.requestId);
        const physical = f.trace.findIndex(e => e[0] === 'host-removed');
        assert.ok(cut(reserve) < physical && physical < cut(remove));
        assert.deepEqual(f.trace.filter(e => e[0] === 'host-removed'), [['host-removed', count]]);
        const all = [...survivors, relay].sort();
        const stage = f.trace.findIndex(e => ['stage', 'target-stage'].includes(e[0]));
        assert.ok(cut(remove) < stage);
        const graphStart = f.trace.findIndex(e => e[0] === 'mongo' && e[1].inTxn && e[1].session === graph.session && e[1].txn === graph.txn);
        assert.ok(graphStart > stage && cut(graph) > graphStart);
        const applied = f.trace.slice(stage, graphStart);
        assert.deepEqual(applied.filter(e => e[0] === 'put').map(e => e[1]), all);
        assert.deepEqual(applied.filter(e => e[0] === 'readback').map(e => e.slice(1)), all.flatMap(id => profilesInOrder.map(p => [id, p])));
        const disposal = applied.slice(applied.findLastIndex(e => e[0] === 'readback') + 1);
        assert.deepEqual(disposal.filter(e => e[0] === 'target-cleanup'), [['target-cleanup']]);
        assert.deepEqual(disposal.filter(e => e[0] === 'close').map(e => e[1]), survivors);
        assert.deepEqual(f.trace.filter(e => e[0] === 'direct' && ['prepare-remove', 'remove'].includes(e[1])),
            [['direct', 'prepare-remove'], ['direct', 'remove']]);
        assert.deepEqual(host.snapshot(), { installed: false, chap: ['foreign-line'], policy: ['foreign-chain'], listeners: ['foreign-listener'] });
        const after = await f.snapshot(false);
        assert.deepEqual(after[C.nodes], before[C.nodes].filter(n => String(n._id) !== relay));
        assert.deepEqual(after[C.users], [{ ...before[C.users][0], nodes: before[C.users][0].nodes.filter(id => String(id) !== relay) }, before[C.users][1]]);
        assert.deepEqual(after[C.links].map(l => String(l._id)), [rowId(4), rowId(5)]);
        assert.equal(after[C.links][0].status, 'deployed');
        assert.equal(String(after[C.links][0].rebuildApplied.listener), exit);
        assert.match(after[C.links][0].rebuildApplyEpoch, /^[a-f0-9]{32}$/);
        assert.deepEqual(after[C.links][1], before[C.links][4]);
        assert.deepEqual(after[C.state], classicState ? [classicState] : []);
        for (const name of [C.accounts, C.grants]) assert.deepEqual(after[name], []);
        assert.deepEqual(after[C.retired], [{ _id: relay }]);
        assert.equal(after[C.directory].length, 1);
        assert.deepEqual(after[C.directory][0].accounts, before[C.accounts].toSorted(byLogin).map(a => ({
            id: String(a._id), login: a.login, enabled: a.enabled, passwordEncrypted: a.passwordEncrypted,
        })));
        const targetPair = profilesInOrder.map(p => f.profiles.get(`${relay}:${p}`));
        const targetPreimage = JSON.stringify(profilesInOrder.map(p => profiles.get(`${relay}:${p}`)));
        const targetClean = JSON.stringify(targetPair);
        assert.ok(profiles.get(`${relay}:main`).inbounds.some(i => i.tag === `relay-l2tp-${relay}`));
        for (const tag of [`relay-l2tp-${relay}`, ...before[C.links].slice(0, 3).map(link => link.tunnelUuid)]) {
            assert.ok(targetPreimage.includes(tag), `non-vacuous target cleanup for ${tag}`);
            assert.equal(targetClean.includes(tag), false);
        }
        const client = (map, id, tag) => map.get(`${id}:main`).inbounds.find(i => i.tag === tag);
        for (const [id, tag] of [[portal, 'users-0'], [relay, 'users-1']]) {
            const original = client(profiles, id, tag);
            assert.ok(original.settings.clients.length > 0);
            assert.deepEqual(client(f.profiles, id, tag), original);
        }
        assert.ok(JSON.stringify(profiles.get(`${portal}:main`)).includes(nodeIP(relay)));
        for (const [key, value] of profiles) {
            if (!all.includes(key.split(':')[0])) assert.deepEqual(f.profiles.get(key), value);
            else if (!key.startsWith(relay)) assert.equal(JSON.stringify(f.profiles.get(key)).includes(nodeIP(relay)), false);
        }
        await f.unlocked();
    }

    for (const [count, classic] of [[0, false], [2, false], [0, true]]) test(classic
        ? '#13 ONLINE Retire joins directory-backfilling Remove and graph with an inactive classic neighbor'
        : `installed ONLINE retirement joins real Remove and graph (${count ? 'explicit force for two clients' : 'zero clients'})`, async t => {
        const host = installedPeer(ctx, count);
        const f = await fixture(t, { online: host });
        let classicRows, classicBytes;
        if (classic) {
            classicRows = inactiveClassicRelay('8'.repeat(24), host.state.clientCidr.split('.').slice(0, 3).join('.'));
            const { state, operation } = classicRows;
            await f.independent.collection(C.nodes).insertOne({ _id: state.node,
                name: 'Inactive classic fixture', type: 'xray', cascadeRole: 'relay', active: false, ip: '192.0.2.8' });
            await f.independent.collection(C.state).insertOne(state);
            await f.independent.collection(operations).insertOne(operation);
            classicBytes = () => Promise.all([
                f.independent.collection(C.state).findOne({ _id: state._id }, { raw: true }),
                f.independent.collection(operations).findOne({ _id: operation._id }, { raw: true }),
            ]);
        }
        const classicBefore = await classicBytes?.();
        const app = await mountOnline(t, f);
        const before = await f.snapshot(false), raw = await f.snapshot(), profiles = new Map(f.profiles), hostBefore = host.snapshot();
        if (classic) assert.deepEqual(before[C.directory], [], 'exercise directory backfill');
        const first = await app.preview();
        if (!first.json?.preview?.allowed) t.diagnostic(JSON.stringify(f.trace.filter(e => e[0] !== 'mongo')));
        let ticket = previewIs(first, count);
        await unchanged(f, host, raw, profiles, hostBefore);
        if (count) {
            f.reset();
            const busy = await confirm(app, ticket, 'delete');
            assert.equal(busy.status, 409);
            assert.deepEqual(busy.json, { error: { code: 'REBUILD_RETIRE_DECISION_REQUIRED', activeClients: count } });
            assert.deepEqual(f.trace, []);
            await unchanged(f, host, raw, profiles, hostBefore);
            await rejectedReplay(app, ticket, 'force');

            // Census drift after preview: consume the old decision and report
            // the new count without a Remove reservation or graph writes.
            host.setCensus(0);
            const stale = previewIs(await app.preview(), 0);
            host.setCensus(count);
            f.reset();
            const drift = await confirm(app, stale, 'delete');
            ticket = previewIs(drift, count, 409);
            assert.notEqual(ticket, stale);
            assert.deepEqual(drift.json.error, { code: 'PREVIEW_CHANGED' });
            assert.deepEqual(f.trace.filter(e => e[0] === 'direct' && e[1] === 'retirement-count'),
                [['direct', 'retirement-count'], ['direct', 'retirement-count']]);
            await unchanged(f, host, raw, profiles, hostBefore);
            await rejectedReplay(app, stale, 'force');

            // A changed client generation with the same count is not the old
            // force decision either. A fresh ticket is still required.
            host.setCensus(count);
            f.reset();
            const sameCount = await confirm(app, ticket, 'force');
            const replacement = previewIs(sameCount, count, 409);
            assert.notEqual(replacement, ticket);
            assert.deepEqual(sameCount.json.error, { code: 'PREVIEW_CHANGED' });
            await unchanged(f, host, raw, profiles, hostBefore);
            ticket = replacement;
        }
        f.reset();
        const result = await confirm(app, ticket, count ? 'force' : 'delete');
        assert.equal(result.status, 200, `${result.text}; ${f.trace.map(e => e[0] === 'direct' ? e.join(':') : e[0]).filter(x => x !== 'mongo').join(' ')}`);
        assert.equal(result.cache, 'no-store');
        assert.deepEqual(result.json, { nodeId: relay, status: 'deleted' });
        await retired(f, host, before, profiles, count, classicRows?.state);
        if (classic) {
            assert.deepEqual(await classicBytes(), classicBefore);
            assert.ok(!f.commands.some(e => e.collection === operations && writes.has(e.commandName)));
        }
        f.reset();
        await rejectedReplay(app, ticket, count ? 'force' : 'delete');
        assert.deepEqual(f.trace, []);
    });

    test('installed ONLINE can retire through the panel while its card is being sampled', async t => {
        const host = installedPeer(ctx, 0), f = await fixture(t, { online: host });
        const app = await mountOnline(t, f), before = await f.snapshot(false), profiles = new Map(f.profiles);
        const cards = f.independent.collection(C.nodes), target = { _id: before[C.nodes].find(n => String(n._id) === relay)._id };
        // An independent Mongo client really commits during each HTTP request.
        // The timer keeps running until confirm returns (including settlement).
        const stop = new AbortController(), phases = [];
        let next = Promise.withResolvers(), n = 0;
        const pump = (async () => {
            const ticks = require('node:timers/promises').setInterval(2000, null, { signal: stop.signal });
            try {
                for await (const _ of ticks) {
                    const now = new Date(); n++;
                    const ack = await cards.updateOne(target, { $set: { agentLastSeen: now, updatedAt: now,
                        'traffic.tx': n, 'traffic.rx': 2*n, 'traffic.lastUpdate': now, status: n % 2 ? 'offline' : 'online',
                        'xray.accessLogs.lastBatchAt': now } }, { writeConcern: { w: 'majority' } });
                    const tick = next; next = Promise.withResolvers(); tick.resolve(ack.matchedCount);
                }
            } catch (err) { if (err.name !== 'AbortError') { next.resolve(-1); throw err; } }
        })();
        pump.catch(() => {}); // joined in finally, including DB errors before the barrier
        let phase = 'preview';
        host.probeBarrier = async () => { assert.equal(await next.promise, 1); phases.push(phase); };
        try {
            const ticket = previewIs(await app.preview(), 0);
            phase = 'confirm';
            const result = await confirm(app, ticket, 'delete');
            assert.equal(result.status, 200); assert.deepEqual(result.json, { nodeId: relay, status: 'deleted' });
            assert.deepEqual(phases, ['preview', 'confirm']);
            assert.equal(await cards.findOne(target), null);
            await retired(f, host, before, profiles, 0);
        } finally { stop.abort(); await pump; }
    });

    test('installed ONLINE retirement cannot confirm an unjoined or over-limit census', async t => {
        const host = installedPeer(ctx, 2);
        const f = await fixture(t, { online: host });
        const app = await mountOnline(t, f);
        const raw = await f.snapshot(), profiles = new Map(f.profiles), hostBefore = host.snapshot();
        for (const [count, joined] of [[2, false], [33, true]]) {
            host.setCensus(count, joined);
            f.reset();
            const blocked = await app.preview();
            assert.equal(blocked.status, 200, blocked.text);
            assert.equal(blocked.cache, 'no-store');
            assert.deepEqual(blocked.json, { preview: { nodeId: relay, mode: 'online', activeClients: null,
                accountCount: 3, allowed: false, unavailableSince: null } });
            assert.deepEqual(f.trace.filter(e => e[0] === 'direct' && e[1] === 'retirement-count'), [['direct', 'retirement-count']]);
            await unchanged(f, host, raw, profiles, hostBefore);
        }
    });

    test('installed ONLINE retirement force does not bypass CSRF or the protected graph interfaces', async t => {
        const host = installedPeer(ctx, 1);
        const f = await fixture(t, { online: host });
        const app = await mountOnline(t, f);
        const raw = await f.snapshot(), profiles = new Map(f.profiles), hostBefore = host.snapshot();
        const ticket = previewIs(await app.preview(), 1);
        f.reset();
        assert.equal((await confirm(app, ticket, 'force', 'invalid')).status, 403);
        assert.deepEqual(f.trace, []);
        await unchanged(f, host, raw, profiles, hostBefore);

        // Introduce transport-only drift after a genuine force ticket. The
        // candidate still has the original protected subscriber port.
        const key = `${portal}:main`, changed = structuredClone(profiles.get(key));
        const client = changed.inbounds.find(i => i.tag === 'users-0');
        assert.ok(client.settings.clients.length > 0);
        client.port++;
        f.profiles.set(key, changed);
        const drifted = new Map(f.profiles);
        const refused = await confirm(app, ticket, 'force');
        assert.equal(refused.status, 409, refused.text);
        assert.deepEqual(refused.json, { error: { code: 'REBUILD_RETIRE_PROTECTED_CHANGE' } });
        await unchanged(f, host, raw, drifted, hostBefore);
    });
};
