'use strict';
// Actual runner + typed transport + real PPP verifier in a disposable user namespace.
// systemd/physical attestation are explicit local fixtures, never live authority.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { fakeRunner } = require('./helpers/topologyTerminalFakeRunner');
const { TopologyNodeTransportFactory } = require('../services/topologyNodeTransportFactory');
const source = path.join(__dirname, '../node-artifacts/topology/runner.sh');
const verifier = path.join(__dirname, '../node-artifacts/l2tp/verify-users.sh');
const sha = text => createHash('sha256').update(text).digest('hex');
const auxId = command => sha(`topology-readiness-v1:${command}:verify-1`);
async function fixture(t, content = '{"inbounds":[],"outbounds":[]}\n') {
    const f = fakeRunner(t, 'boot-1');
    const binding = { operationId: 'op-1', nodeId: 'node-1', candidateHash: `sha256:${sha(content)}`,
        backupId: 'backup-1', targetProfile: 'xray-main', executionContext: 'test.infograd.online',
        attemptId: 'attempt-1', generation: 'generation-1', predecessorGeneration: 'none' };
    const calls = [], replies = [];
    const nodeSSH = { async exec(command, options = {}) {
        calls.push(command);
        assert.ok(command.startsWith('/usr/local/bin/celerity-topology-node-runner '));
        const result = spawnSync('unshare', ['--user', '--map-root-user', 'bash', source, ...command.split(' ').slice(1)], {
            env: { ...process.env, CELERITY_TOPOLOGY_ROOT: f.root }, input: options.stdin, encoding: 'utf8', timeout: 10000 });
        replies.push(result);
        return { code: result.status, stdout: result.stdout, stderr: result.stderr };
    } };
    const transport = await new TopologyNodeTransportFactory({ executionContext: binding.executionContext,
        nodeExecutionResolver: { async resolve() { return nodeSSH; } } }).create({ nodeId: binding.nodeId, role: 'portal' });
    await transport.prepare({ ...binding, commandId: 'prepare-1', artifact: { id: 'xray-config', content } });
    await transport.commit({ ...binding, commandId: 'commit-1' });
    await transport.verify({ ...binding, commandId: 'verify-1', checks: [] });
    f.put('usr/local/lib/celerity/relay-l2tp/verify-users.sh', fs.readFileSync(verifier), 0o750);
    for (const name of ['usr', 'usr/local', 'usr/local/lib', 'usr/local/lib/celerity', 'usr/local/lib/celerity/relay-l2tp']) {
        fs.chmodSync(path.join(f.root, name), 0o755);
    }
    f.put('var/lib/celerity/l2tp/operations/ppp-sync-1/desired.json', JSON.stringify({ credentialRevision: 7,
        users: [{ login: 'alice', password: 'local-fixture-secret', ipAddress: '10.44.0.2', enabled: true }] }));
    f.put('etc/ppp/chap-secrets', '# BEGIN CELERITY MANAGED L2TP USERS\n"alice" l2tpd "local-fixture-secret" 10.44.0.2\n# END CELERITY MANAGED L2TP USERS\n');
    const request = { ...binding, commandId: auxId('verify-ppp-users'), bootId: 'boot-1',
        expectation: { operationId: 'ppp-sync-1', expectedCredentialRevision: 7, expectedEnabledUserCount: 1 } };
    return { ...f, binding, calls, replies, transport, request };
}
test('finite PPP readiness verifies a nonempty existing revision without shell/bootstrap or file writes', async t => {
    const f = await fixture(t);
    const before = fs.readFileSync(path.join(f.root, 'etc/ppp/chap-secrets'));
    const desired = fs.readFileSync(path.join(f.root, 'var/lib/celerity/l2tp/operations/ppp-sync-1/desired.json'));
    const result = await f.transport.verifyPppUsers(f.request);
    const { parseReadinessReceipt } = require('../services/topologyReadinessProtocol');
    const { bootId, expectation, ...binding } = f.request;
    const invocation = { command: 'verify-ppp-users', ...binding, readiness: { bootId, ...expectation } };
    const raw = f.replies.at(-1);
    assert.throws(() => parseReadinessReceipt({ code: 0, stderr: '', stdout: raw.stdout.replace('{', '{"protocolVersion":2,') },
        'verify-ppp-users', invocation), /Unconfirmed/);
    assert.deepEqual(result, { ok: true, code: 'USERS_VERIFIED', credentialRevision: 7, enabledUserCount: 1, managedUserCount: 1 });
    assert.deepEqual(fs.readFileSync(path.join(f.root, 'etc/ppp/chap-secrets')), before);
    assert.deepEqual(fs.readFileSync(path.join(f.root, 'var/lib/celerity/l2tp/operations/ppp-sync-1/desired.json')), desired);
    assert.match(f.calls.at(-1), /--command verify-ppp-users .*--checks [A-Za-z0-9_-]+$/);
    await f.transport.close({ ...f.binding, commandId: 'close-1' });
});

test('finite restore repopulates real Xray runtime from a nonempty snapshot after candidate restart', async t => {
    assert.ok(process.env.C3_XRAY, 'set reviewed local Xray binary for the actual RPC proof');
    const net = require('node:net');
    const apiPort = await new Promise(resolve => {
        const server = net.createServer(); server.listen(0, '127.0.0.1', () => {
            const port = server.address().port; server.close(() => resolve(port));
        });
    });
    const config = { log: { loglevel: 'none' }, api: { tag: 'API', services: ['HandlerService'] },
        inbounds: [{ tag: 'API_INBOUND', listen: '127.0.0.1', port: apiPort, protocol: 'dokodemo-door', settings: { address: '127.0.0.1' } },
            { tag: 'vless-in', listen: '127.0.0.1', port: 0, protocol: 'vless', settings: { decryption: 'none', clients: [] } }],
        outbounds: [{ protocol: 'freedom', tag: 'direct' }], routing: { rules: [{ type: 'field', inboundTag: ['API_INBOUND'], outboundTag: 'API' }] } };
    const f = await fixture(t, `${JSON.stringify(config)}\n`);
    fs.copyFileSync(process.env.C3_XRAY, path.join(f.root, 'usr/local/bin/xray'));
    fs.chmodSync(path.join(f.root, 'usr/local/bin/xray'), 0o750);
    const { spawn } = require('node:child_process');
    const child = spawn(process.env.C3_XRAY, ['run', '-config', path.join(f.root, 'usr/local/etc/xray/config.json')], { stdio: 'ignore' });
    t.after(async () => { if (child.exitCode === null) { const exited = new Promise(resolve => child.once('exit', resolve)); child.kill(); await exited; } });
    const query = () => spawnSync(process.env.C3_XRAY, ['api', 'inbounduser', `--server=127.0.0.1:${apiPort}`, '-tag=vless-in'], { encoding: 'utf8', timeout: 5000 });
    let initial;
    for (let n = 0; n < 100; n++) { initial = query(); if (initial.status === 0) break; await new Promise(resolve => setTimeout(resolve, 20)); }
    assert.equal(initial.status, 0, initial.stderr);
    assert.deepEqual(JSON.parse(initial.stdout).users || [], [], 'candidate process really starts without subscription users');
    const users = [{ id: '550e8400-e29b-41d4-a716-446655440000', email: 'alice' }];
    const restored = await f.transport.restoreUsers({ ...f.binding, commandId: auxId('restore-users'), bootId: 'boot-1', users });
    assert.deepEqual(restored, { ok: true, code: 'XRAY_USERS_RESTORED', userCount: 1, inboundCount: 1 });
    assert.deepEqual(JSON.parse(query().stdout).users.map(user => ({ id: user.account.id, email: user.email })), users);
    await f.transport.close({ ...f.binding, commandId: 'close-1' });
});

test('finite PPP refuses pin/drift/expected-revision uncertainty and retains the running journal against close', async t => {
    for (const fault of ['pin', 'chap', 'revision', 'symlink']) await t.test(fault, async t => {
        const f = await fixture(t);
        if (fault === 'pin') fs.appendFileSync(path.join(f.root, 'usr/local/lib/celerity/relay-l2tp/verify-users.sh'), '\n# drift\n');
        if (fault === 'chap') f.put('etc/ppp/chap-secrets', '# BEGIN CELERITY MANAGED L2TP USERS\n# END CELERITY MANAGED L2TP USERS\n');
        if (fault === 'revision') f.request.expectation.expectedCredentialRevision = 8;
        if (fault === 'symlink') {
            const target = path.join(f.root, 'usr/local/lib/celerity/relay-l2tp/verify-users.sh');
            fs.renameSync(target, `${target}.saved`); fs.symlinkSync(`${target}.saved`, target);
        }
        await assert.rejects(f.transport.verifyPppUsers(f.request), { ownershipRetained: true, remoteOutcomeUnknown: true });
        await assert.rejects(f.transport.close({ ...f.binding, commandId: 'close-1' }));
        assert.match(f.replies.at(-1).stderr, /UNKNOWN_COMMAND_OUTCOME/);
    });
});

test('PPP expectation cannot override the executor boot or smuggle extra typed fields', async t => {
    const f = await fixture(t), before = f.calls.length;
    await assert.rejects(f.transport.verifyPppUsers({ ...f.request, bootId: 'foreign',
        expectation: { ...f.request.expectation, bootId: 'boot-1' } }), { code: 'INVALID_PLAN' });
    assert.equal(f.calls.length, before);
});

test('finite auxiliary identity rejects foreign node/profile/boot/predecessor and stale command IDs', async t => {
    const f = await fixture(t);
    for (const change of [{ nodeId: 'foreign' }, { targetProfile: 'xray-bridge' }, { bootId: 'foreign' },
        { predecessorGeneration: 'foreign' }, { attemptId: 'foreign' }, { commandId: 'arbitrary' }]) {
        await assert.rejects(f.transport.verifyPppUsers({ ...f.request, ...change }));
    }
    assert.equal((await f.transport.verifyPppUsers(f.request)).ok, true);
    await assert.rejects(f.transport.verifyPppUsers(f.request));
    assert.match(f.replies.at(-1).stderr, /COMMAND_REUSE/);
    await f.transport.close({ ...f.binding, commandId: 'close-1' });
    await assert.rejects(f.transport.verifyPppUsers(f.request));
    assert.match(f.replies.at(-1).stderr, /GENERATION_CLOSED/);
});

test('empty/duplicate user snapshots refuse locally and unavailable real RPC cannot permit close', async t => {
    const f = await fixture(t);
    const base = { ...f.binding, commandId: auxId('restore-users'), bootId: 'boot-1' };
    const before = f.calls.length;
    const u = { id: '550e8400-e29b-41d4-a716-446655440000', email: 'alice' };
    for (const users of [[], [u, u], [{ ...u, id: 'malformed' }]]) {
        await assert.rejects(f.transport.restoreUsers({ ...base, users }), { code: 'INVALID_PLAN' });
    }
    assert.equal(f.calls.length, before);
    // No API in this real candidate: a successful mock Xray executable cannot
    // invent a configured management service or authenticate a user.
    await assert.rejects(f.transport.restoreUsers({ ...base, users: [u] }));
    await assert.rejects(f.transport.close({ ...f.binding, commandId: 'close-1' }));
    assert.match(f.replies.at(-1).stderr, /UNKNOWN_COMMAND_OUTCOME/);
});
