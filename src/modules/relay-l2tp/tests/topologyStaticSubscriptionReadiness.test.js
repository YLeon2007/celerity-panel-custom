'use strict';
// Exact retained-M1 regression. Local user-namespace journal/systemd fixture,
// real pinned Xray runtime/RPC on loopback; no SSH/live authority or DB writes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { fakeRunner } = require('./helpers/topologyTerminalFakeRunner');
const { TopologyNodeTransportFactory } = require('../services/topologyNodeTransportFactory');
const runner = path.join(__dirname, '../node-artifacts/topology/runner.sh');
const sha = text => createHash('sha256').update(text).digest('hex');
const alice = { id: '550e8400-e29b-41d4-a716-446655440000', email: 'alice' };
const bob = { id: '550e8400-e29b-41d4-a716-446655440001', email: 'bob' };
const tunnel = { id: '550e8400-e29b-41d4-a716-446655440099' };
async function fixture(t, clients) {
    assert.ok(process.env.C3_XRAY, 'explicit pinned local Xray binary required');
    const port = await new Promise(resolve => {
        const server = net.createServer(); server.listen(0, '127.0.0.1', () => {
            const value = server.address().port; server.close(() => resolve(value));
        });
    });
    const config = { log: { loglevel: 'none' }, api: { tag: 'API', services: ['HandlerService'] },
        inbounds: [
            { tag: 'API_INBOUND', listen: '127.0.0.1', port, protocol: 'dokodemo-door', settings: { address: '127.0.0.1' } },
            { tag: 'vless-in', listen: '127.0.0.1', port: 0, protocol: 'vless', settings: { decryption: 'none', clients } },
            { tag: 'bridge-conn-retained', listen: '127.0.0.1', port: 0, protocol: 'vless', settings: { decryption: 'none', clients: [tunnel] } },
        ], outbounds: [{ protocol: 'freedom', tag: 'direct' }],
        routing: { rules: [{ type: 'field', inboundTag: ['API_INBOUND'], outboundTag: 'API' }] } };
    const content = `${JSON.stringify(config)}\n`, f = fakeRunner(t, 'boot-static');
    const binding = { operationId: 'op-static', nodeId: 'node-static', candidateHash: `sha256:${sha(content)}`,
        backupId: 'backup-static', targetProfile: 'xray-main', executionContext: 'test.infograd.online',
        attemptId: 'attempt-static', generation: 'generation-static', predecessorGeneration: 'none' };
    const replies = [];
    const transport = await new TopologyNodeTransportFactory({ executionContext: binding.executionContext,
        nodeExecutionResolver: { async resolve() { return { async exec(command, options = {}) {
            const result = spawnSync('unshare', ['--user', '--map-root-user', 'bash', runner, ...command.split(' ').slice(1)], {
                env: { ...process.env, CELERITY_TOPOLOGY_ROOT: f.root }, input: options.stdin,
                encoding: 'utf8', timeout: 15000 });
            replies.push(result); return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        } }; } } }).create({ nodeId: binding.nodeId, role: 'portal' });
    await transport.prepare({ ...binding, commandId: 'prepare-static', artifact: { id: 'xray-config', content } });
    await transport.commit({ ...binding, commandId: 'commit-static' });
    await transport.verify({ ...binding, commandId: 'verify-static', checks: [] });
    fs.copyFileSync(process.env.C3_XRAY, path.join(f.root, 'usr/local/bin/xray'));
    fs.chmodSync(path.join(f.root, 'usr/local/bin/xray'), 0o750);
    const active = path.join(f.root, 'usr/local/etc/xray/config.json');
    const child = spawn(process.env.C3_XRAY, ['run', '-config', active], { stdio: 'ignore' });
    t.after(async () => {
        if (child.exitCode === null) { const joined = new Promise(resolve => child.once('exit', resolve)); child.kill(); await joined; }
        assert.notEqual(child.exitCode, null, 'own actual Xray child joined');
    });
    const query = tag => {
        const response = spawnSync(process.env.C3_XRAY, ['api', 'inbounduser', `--server=127.0.0.1:${port}`, '-tag=' + tag], { encoding: 'utf8', timeout: 5000 });
        assert.equal(response.status, 0, response.stderr);
        return (JSON.parse(response.stdout).users || []).map(user => ({ id: user.account.id, email: user.email || '' })).sort((a,b) => a.id.localeCompare(b.id));
    };
    for (let n=0;n<100;n++) {
        const response=spawnSync(process.env.C3_XRAY,['api','inbounduser',`--server=127.0.0.1:${port}`,'-tag=vless-in'],{encoding:'utf8',timeout:5000});
        if(response.status===0)break;
        await new Promise(resolve=>setTimeout(resolve,20));
    }
    return { ...f, binding, transport, replies, query, active, original: fs.readFileSync(active), request: users => ({ ...binding,
        commandId: sha('topology-readiness-v1:restore-users:verify-static'), bootId: 'boot-static', users }) };
}
test('static subscription exact imported user is verified without treating tunnel clients as subscriptions', async t => {
    const f = await fixture(t, [{ ...alice, level: 0 }]);
    assert.deepEqual(f.query('vless-in'), [alice]);
    const tunnelBefore = f.query('bridge-conn-retained');
    const result = await f.transport.restoreUsers(f.request([alice]));
    assert.deepEqual(result, { ok: true, code: 'XRAY_USERS_RESTORED', userCount: 1, inboundCount: 1 });
    assert.deepEqual(f.query('vless-in'), [alice]);
    assert.deepEqual(f.query('bridge-conn-retained'), tunnelBefore);
    assert.deepEqual(fs.readFileSync(f.active), f.original, 'no static candidate rewrite');
    await f.transport.close({ ...f.binding, commandId: 'close-static' });
});
test('static subscription subset restores only missing assigned users and keeps original static bytes', async t => {
    const f = await fixture(t, [{ ...alice, level: 0 }]);
    const tunnelBefore = f.query('bridge-conn-retained');
    const result = await f.transport.restoreUsers(f.request([alice, bob]));
    assert.deepEqual(result, { ok: true, code: 'XRAY_USERS_RESTORED', userCount: 2, inboundCount: 1 });
    assert.deepEqual(f.query('vless-in'), [alice,bob]);
    assert.deepEqual(f.query('bridge-conn-retained'), tunnelBefore);
    assert.deepEqual(fs.readFileSync(f.active), f.original);
    await f.transport.close({ ...f.binding, commandId: 'close-static' });
});
test('static subscription mismatched imported UUID remains unselected and uncertain journal blocks close', async t => {
    const different = { ...alice, id: bob.id }, f = await fixture(t, [different]);
    await assert.rejects(f.transport.restoreUsers(f.request([alice])), { ownershipRetained: true, remoteOutcomeUnknown: true });
    assert.match(f.replies.at(-1).stderr, /USER_INBOUNDS_UNAVAILABLE/);
    assert.deepEqual(f.query('vless-in'), [different]);
    assert.deepEqual(fs.readFileSync(f.active), f.original);
    await assert.rejects(f.transport.close({ ...f.binding, commandId: 'close-static' }));
});
