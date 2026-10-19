'use strict';

// Real cascadeService -> NodeSSH -> SSHPool exec, local stream/persistence seams only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { SFTP } = require('ssh2/lib/protocol/SFTP');
const cascade = require('../cascadeService');
const NodeSSH = require('../nodeSSH');
const pool = require('../sshPoolService');
const sync = require('../syncService');
const generator = require('../configGenerator');
const Link = require('../../models/cascadeLinkModel');
const Node = require('../../models/hyNodeModel');
const legacy = require('../../modules/relay-l2tp/services/legacyCascadeUndeploy');
const State = require('../../modules/relay-l2tp/models/cascadeTopologyStateModel');
const Operation = require('../../modules/relay-l2tp/models/topologyOperationModel');
const Intent = require('../../modules/relay-l2tp/models/topologyCreateIntentModel');
const Queue = require('../../modules/relay-l2tp/models/topologyIntentQueueStateModel');
const Lock = require('../../modules/relay-l2tp/models/nodeOperationLockModel');
test.after(() => pool.closeAll());

function query(value) {
    return { session() { return this; }, lean: async () => structuredClone(value), then(resolve) { return Promise.resolve(value).then(resolve); },
        populate() { return this; } };
}
function fixture(t, { mode = 'reverse', remaining = false, fault = () => null, direct = false, sftp = null } = {}) {
    const state = { _id: 'singleton', revision: 7, deployedRevision: 5, replacementEpoch: 0,
        topologyAdmissionCount: 0, remoteAdmissionCount: 0 };
    const nodes = {
        portal: { _id: 'portal', name: 'portal', type: 'xray', active: true, ssh: { password: 'local-mock' } },
        bridge: { _id: 'bridge', name: 'bridge', type: mode === 'forward' ? 'xray' : 'hysteria', active: true,
            ssh: { password: 'local-mock' } },
    };
    const link = { _id: 'removed', name: 'removed', portalNode: 'portal', bridgeNode: 'bridge', mode };
    const survivor = { _id: 'survivor', portalNode: nodes.portal, bridgeNode: 'bridge', mode: 'reverse' };
    const calls = { commands: [], uploads: [], releases: 0, liveWriter: false, agent: 0, generatedLinks: [] };
    t.mock.method(State.db, 'transaction', async work => work({ localOnly: true }));
    t.mock.method(State, 'findById', () => query(state));
    t.mock.method(State, 'findOneAndUpdate', (filter, update) => {
        if (update.$unset) {
            calls.releases++;
            assert.equal(filter['replacementReservation.ownerToken'], state.replacementReservation.ownerToken);
            assert.equal(filter['replacementReservation.epoch'], state.replacementReservation.epoch);
            delete state.replacementReservation;
        } else {
            assert.equal(state.replacementReservation, undefined);
            Object.assign(state, update.$set);
            for (const [key, amount] of Object.entries(update.$inc)) state[key] += amount;
        }
        return query(state);
    });
    for (const model of [Operation, Intent, Queue, Lock]) t.mock.method(model, 'exists', () => query(null));
    t.mock.method(Node, 'findById', async id => nodes[id]);
    t.mock.method(Link, 'updateOne', async () => ({ acknowledged: true, matchedCount: 1 }));
    t.mock.method(Link, 'find', filter => {
        if (filter.bridgeNode === 'bridge' && filter.mode?.$ne === 'forward') {
            return query(remaining ? (filter._id ? [survivor] : [link, survivor]) : []);
        }
        return query([]);
    });
    t.mock.method(sync, '_getUsersForNode', async () => []);
    t.mock.method(sync, '_agentRequest', async () => { calls.agent++; return { success: true }; });
    t.mock.method(generator, 'generateXrayConfigWithApi', () => JSON.stringify({ inbounds: [], outbounds: [], routing: { rules: [] } }));
    t.mock.method(generator, 'generateCombinedBridgeConfig', links => { calls.generatedLinks = links.map(row => row._id); return '{}'; });
    t.mock.method(generator, 'generateBridgeSystemdService', () => 'local unit');
    t.mock.method(cascade, '_invalidateTopologyCache', async () => {});
    const originalTimeout = global.setTimeout;
    t.mock.method(global, 'setTimeout', (fn, ms, ...args) => originalTimeout(fn, ms === 30000 ? 100 : ms, ...args));
    function client(node) {
        return { end() {}, exec(command, callback) {
            calls.commands.push([node._id, command]);
            const stream = new EventEmitter(); stream.stderr = new EventEmitter();
            callback(null, stream);
            const failure = fault(node, command);
            if (failure === 'timeout') { calls.liveWriter = true; return; }
            setImmediate(() => {
                const marker = command.match(/C3_LEGACY_DONE_[a-f0-9]+/);
                const output = command.includes('command -v xray') ? '/usr/bin/xray\n'
                    : command.includes('is-active xray-bridge') ? 'active\n' : '';
                stream.emit('data', Buffer.from(output + (marker && failure !== 'missing-receipt' ? `\n${marker[0]}\n` : '')));
                if (failure) calls.liveWriter = true;
                stream.emit('close', failure === 'nonzero' ? 1 : failure === 'missing-exit' ? undefined : 0);
            });
        }, sftp(callback) { callback(null, sftp(node, calls)); } };
    }
    t.mock.method(pool, 'getConnection', async node => client(node));
    if (!sftp) t.mock.method(pool, 'writeFile', async (node, remotePath) => { calls.uploads.push([node._id, remotePath]); });
    if (direct) {
        t.mock.method(NodeSSH.prototype, 'connect', async function () { this.usePool = false; this.directClient = client(this.node); });
        if (!sftp) t.mock.method(NodeSSH.prototype, 'writeFile', async function (remotePath) { calls.uploads.push([this.node._id, remotePath]); });
    }
    return { state, calls, nodes, link, run: () => legacy.withLegacyCascadeUndeploy(async () => {
        await cascade.undeployLink(link); // HTTP discards the return receipt.
    }) };
}

async function assertRetained(f) {
    assert.match(f.state.replacementReservation.ownerToken, /^legacy-undeploy:/);
    assert.equal(f.state.replacementReservation.epoch, 1);
    assert.equal(f.state.replacementReservation.expiresAt, undefined);
    assert.equal(f.calls.releases, 0);
    assert.equal(f.state.deployedRevision, 0);
    await assert.rejects(legacy.withLegacyCascadeUndeploy(async () => assert.fail('successor must not start')),
        { code: 'LEGACY_CASCADE_UNDEPLOY_BUSY' });
}

test('actual-source bridge stop timeout keeps a live remote writer fenced after normal legacy catch', async t => {
    const f = fixture(t, { fault: (node, command) => node._id === 'bridge' && command.includes('systemctl stop') ? 'timeout' : null });
    await assert.rejects(f.run());
    assert.equal(f.calls.liveWriter, true);
    await assertRetained(f);
});

for (const failure of ['nonzero', 'missing-exit', 'missing-receipt']) {
    test(`actual-source bridge stop ${failure} is not completion proof`, async t => {
        const f = fixture(t, { fault: (node, command) => node._id === 'bridge' && command.includes('systemctl stop') ? failure : null });
        await assert.rejects(f.run(), { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
        assert.equal(f.calls.liveWriter, true);
        await assertRetained(f);
    });
}

for (const [name, options, targetNode, targetCommand] of [
    ['portal upload mkdir', {}, 'portal', 'mkdir -p'],
    ['portal restart', {}, 'portal', 'systemctl restart xray'],
    ['forward bridge restart', { mode: 'forward' }, 'bridge', 'systemctl restart xray'],
    ['remaining reverse bridge restart', { remaining: true }, 'bridge', 'systemctl daemon-reload'],
]) {
    for (const failure of ['timeout', 'nonzero', 'missing-exit', 'missing-receipt']) {
        test(`${name} ${failure} cannot be swallowed or superseded`, async t => {
            const f = fixture(t, { ...options, fault: (node, command) =>
                node._id === targetNode && command.includes(targetCommand) ? failure : null });
            await assert.rejects(f.run());
            assert.equal(f.calls.liveWriter, true);
            await assertRetained(f);
        });
    }
}

for (const reason of ['missing portal', 'missing bridge', 'no portal credentials', 'no bridge credentials', 'agent acknowledgement', 'topology skip']) {
    test(`legacy ${reason} cannot authorize fence release`, async t => {
        const f = fixture(t);
        if (reason === 'missing portal') delete f.nodes.portal;
        if (reason === 'missing bridge') delete f.nodes.bridge;
        if (reason === 'no portal credentials') delete f.nodes.portal.ssh;
        if (reason === 'no bridge credentials') delete f.nodes.bridge.ssh;
        if (reason === 'agent acknowledgement') f.nodes.portal.xray = { agentToken: 'local-only' };
        if (reason === 'topology skip') {
            for (const flag of ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED']) {
                const old = process.env[flag]; process.env[flag] = 'true';
                t.after(() => { if (old === undefined) delete process.env[flag]; else process.env[flag] = old; });
            }
            f.nodes.portal.cascadeRole = 'portal';
        }
        await assert.rejects(f.run(), { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
        assert.equal(f.calls.agent, 0, 'do not issue an unjoinable agent restart');
        await assertRetained(f);
    });
}

for (const value of [undefined, true, false, { success: true }, { success: false }, { success: true, remoteQuiescent: true }]) {
    test(`unattested callback result ${JSON.stringify(value)} keeps the fence`, async t => {
        const f = fixture(t);
        await assert.rejects(legacy.withLegacyCascadeUndeploy(async () => value),
            { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
        await assertRetained(f);
    });
}

test('a callback swallowing a real timeout cannot turn later success into release proof', async t => {
    let fail = true;
    const f = fixture(t, { fault: (node, command) => fail && node._id === 'bridge' && command.includes('systemctl stop') ? 'timeout' : null });
    await assert.rejects(legacy.withLegacyCascadeUndeploy(async () => {
        await cascade.undeployLink(f.link).catch(() => {});
        fail = false;
        await cascade.undeployLink(f.link);
    }), { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
    await assertRetained(f);
});

for (const options of [{}, { mode: 'forward' }, { remaining: true }, { direct: true }]) {
    test(`checked foreground success releases exact fence ${JSON.stringify(options)}`, async t => {
        const f = fixture(t, options);
        const result = await legacy.withLegacyCascadeUndeploy(async () => {
            const receipt = await cascade.undeployLink(f.link);
            assert.deepEqual(receipt, { success: true, remoteQuiescent: true });
            return { name: 'MCP callback document' };
        });
        assert.deepEqual(result, { name: 'MCP callback document' });
        assert.equal(f.state.replacementReservation, undefined);
        assert.equal(f.calls.releases, 1);
        if (options.remaining) assert.deepEqual(f.calls.generatedLinks, ['survivor'], 'removed link must not reappear during a successful bridge rebuild');
        assert.ok(f.calls.uploads.length > 0);
        assert.ok(f.calls.commands.every(([, command]) => /C3_LEGACY_DONE_[a-f0-9]+/.test(command)));
        const markers = f.calls.commands.map(([, command]) => command.match(/C3_LEGACY_DONE_[a-f0-9]+/)[0]);
        assert.equal(new Set(markers).size, markers.length, 'completion receipts cannot be replayed across commands');
    });
}

for (const failure of ['missing-exit', 'missing-receipt']) {
    test(`direct NodeSSH close with ${failure} retains ownership`, async t => {
        const f = fixture(t, { direct: true, fault: (node, command) => node._id === 'bridge' && command.includes('systemctl stop') ? failure : null });
        await assert.rejects(f.run(), { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
        await assertRetained(f);
    });
}

// Use ssh2's real WriteStream: a failed WRITE calls destroy() without the
// error, so a successful CLOSE can suppress the stream's error event entirely.
// Only the SFTP request/response boundary is local; neither writeFile is mocked.
function sftpTransport(evidence, { writeReply = callback => callback(null), closeReply = callback => callback(null) } = {}) {
    return (node, calls) => ({
        createWriteStream(remotePath) {
            this.path = remotePath;
            calls.uploads.push([node._id, remotePath]);
            const stream = SFTP.prototype.createWriteStream.call(this, remotePath);
            stream.on('error', error => evidence.errors.push(error));
            stream.on('close', () => evidence.closes++);
            return stream;
        },
        open(_path, _flags, _mode, callback) { setImmediate(() => callback(null, Buffer.from('handle'))); },
        fchmod(_handle, _mode, callback) { setImmediate(() => callback(null)); },
        write(_handle, buffer, offset, length, _position, callback) {
            setImmediate(() => {
                evidence.writes++;
                writeReply(error => callback(error, error ? undefined : length), {
                    node, path: this.path, content: buffer.subarray(offset, offset + length), calls,
                });
            });
        },
        close(_handle, callback) { setImmediate(() => closeReply(callback)); },
    });
}

for (const direct of [false, true]) {
    for (const [name, options, targetNode, targetPath] of [
        ['portal config', {}, 'portal', '/usr/local/etc/xray/config.json'],
        ['forward bridge config', { mode: 'forward' }, 'bridge', '/usr/local/etc/xray/config.json'],
        ['remaining reverse bridge config', { remaining: true }, 'bridge', '/usr/local/etc/xray-bridge/config.json'],
        ['remaining reverse bridge unit', { remaining: true }, 'bridge', '/etc/systemd/system/xray-bridge.service'],
    ]) {
        test(`actual ssh2 suppressed WRITE error cannot release the legacy fence (${direct ? 'direct' : 'pooled'}, ${name})`, async t => {
            const evidence = { writes: 0, closes: 0, errors: [] };
            let failedAt;
            const f = fixture(t, { ...options, direct, sftp: sftpTransport(evidence, {
                writeReply(callback, { node, path, calls }) {
                    if (node._id === targetNode && path === targetPath) {
                        failedAt = calls.commands.length;
                        callback(Object.assign(new Error('SFTP WRITE status 4'), { code: 4 }));
                    } else callback(null);
                },
            }) });
            const error = await f.run().then(() => null, error => error);
            await new Promise(resolve => setImmediate(resolve));
            assert.ok(evidence.writes > 0);
            assert.equal(evidence.closes, evidence.writes, 'CLOSE acknowledgement is successful despite failed WRITE');
            assert.deepEqual(evidence.errors, [], 'regression must exercise the suppressed-error path');
            assert.equal(f.calls.releases, 0, 'failed WRITE must not authorize fence release');
            assert.match(error?.message || '', /SFTP WRITE status 4/);
            assert.equal(error.code, 4);
            assert.equal(f.calls.commands.length, failedAt, 'no commands or restarts after a failed upload');
            await assertRetained(f);
        });
    }

    test(`actual ssh2 failed CLOSE retains the fence after successful WRITE (${direct ? 'direct' : 'pooled'})`, async t => {
        const evidence = { writes: 0, closes: 0, errors: [] };
        const f = fixture(t, { direct, sftp: sftpTransport(evidence, {
            closeReply(callback) { callback(new Error('SFTP CLOSE status 4')); },
        }) });
        await assert.rejects(f.run(), /SFTP CLOSE status 4/);
        assert.equal(evidence.writes, 1);
        assert.equal(evidence.closes, 0);
        assert.equal(evidence.errors.length, 1);
        assert.equal(f.calls.commands.some(([, command]) => command.includes('systemctl restart')), false);
        await assertRetained(f);
    });

    test(`actual ssh2 success awaits WRITE and CLOSE before releasing the exact fence (${direct ? 'direct' : 'pooled'})`, async t => {
        const evidence = { writes: 0, closes: 0, errors: [] };
        let ackWrite, ackClose;
        let reachedWrite, reachedClose;
        const writing = new Promise(resolve => { reachedWrite = resolve; });
        const closing = new Promise(resolve => { reachedClose = resolve; });
        const f = fixture(t, { direct, sftp: sftpTransport(evidence, {
            writeReply(callback, { content }) { ackWrite = callback; reachedWrite(content); },
            closeReply(callback) { ackClose = callback; reachedClose(); },
        }) });
        let finished = false;
        const work = f.run().then(() => { finished = true; });
        const content = await writing;
        assert.ok(content.length > 0, 'upload actual generated config bytes');
        await assertRetained(f);
        assert.equal(finished, false);
        assert.equal(f.calls.commands.some(([, command]) => command.includes('systemctl restart')), false);
        ackWrite(null);
        await closing;
        await assertRetained(f);
        assert.equal(finished, false, 'WRITE success alone does not join the open upload');
        assert.equal(f.calls.commands.some(([, command]) => command.includes('systemctl restart')), false);
        ackClose(null);
        await work;
        assert.equal(evidence.writes, 1);
        assert.equal(evidence.closes, 1);
        assert.deepEqual(evidence.errors, []);
        assert.equal(f.calls.releases, 1);
        assert.equal(f.state.replacementReservation, undefined);
    });
}

test('SFTP failure cannot be treated as a successful undefined upload receipt', async t => {
    const f = fixture(t);
    t.mock.method(pool, 'writeFile', async () => { f.calls.liveWriter = true; throw new Error('SFTP channel lost'); });
    await assert.rejects(f.run(), /SFTP channel lost/);
    assert.equal(f.calls.liveWriter, true);
    assert.equal(f.calls.commands.some(([, command]) => command.includes('systemctl restart')), false);
    await assertRetained(f);
});

test('unawaited in-flight service call keeps ownership even when callback returns', async t => {
    const f = fixture(t);
    let finish;
    const pending = new Promise(resolve => { finish = resolve; });
    t.mock.method(pool, 'writeFile', () => pending);
    let call;
    await assert.rejects(legacy.withLegacyCascadeUndeploy(async () => { call = cascade.undeployLink(f.link); }),
        { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
    await assertRetained(f);
    finish(); await call;
    await assertRetained(f);
});

test('a service call inherited after callback closure cannot dispatch remote effects', async t => {
    const f = fixture(t);
    let late;
    await assert.rejects(legacy.withLegacyCascadeUndeploy(async () => {
        late = new Promise(resolve => setImmediate(() => resolve(cascade.undeployLink(f.link).catch(error => error))));
    }), { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
    assert.equal((await late).code, 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN');
    assert.deepEqual(f.calls.commands, []);
    await assertRetained(f);
});

test('counted active work is rejected before actual service dispatch', async t => {
    const f = fixture(t);
    f.state.topologyAdmissionCount = 1;
    await assert.rejects(f.run(), { code: 'LEGACY_CASCADE_UNDEPLOY_BUSY' });
    assert.deepEqual(f.calls.commands, []);
    assert.deepEqual(f.calls.uploads, []);
    assert.equal(f.state.revision, 7);
    assert.equal(f.state.replacementReservation, undefined);
});
