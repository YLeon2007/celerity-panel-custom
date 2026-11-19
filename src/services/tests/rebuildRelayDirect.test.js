'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { createRelayDirect } = require('../rebuildRelayDirect');

const nodeId = 'a'.repeat(24);
const machineId = 'b'.repeat(32);
const pin = 'c'.repeat(64);
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
    C3_REBUILD_L2TP_RELAY_ID: nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: pin };
const node = { _id: nodeId, ip: '192.0.2.19', ssh: { username: 'root', port: 22 } };
const sha = data => createHash('sha256').update(data).digest('hex');
const main = JSON.stringify({ inbounds: [{ tag: 'fwd-hop-a', protocol: 'vless', port: 443 }],
    outbounds: [{ tag: 'block', protocol: 'blackhole' }], routing: { rules: [
        { type: 'field', ruleTag: 'rebuild-policy-default', inboundTag: ['fwd-hop-a'], outboundTag: 'block' },
    ] } });
const desired = { psk: 'fixture-only-shared-secret', users: [
    { login: 'fixture', password: 'fixture-only-user-password', ipAddress: '10.255.1.10', enabled: true },
], clientCidr: '10.255.1.0/24', localAddress: '10.255.1.1', poolStart: '10.255.1.10', poolEnd: '10.255.1.50',
mtu: 1380, mru: 1370, dnsServers: ['1.1.1.1'], routeTable: 177, fwmark: 77, tproxyPort: 12345 };
const args = { nodeId, desired, controlPlaneAddresses: ['panel.invalid'], carryDomain: false };
const ok = body => ({ code: 0, stdout: JSON.stringify(body) + '\n', stderr: '' });
const ready = { machineId, ppp: true, masked: false, unitsLoaded: true };
const observation = { ...ready, main, bridge: null, mainSha256: sha(main), bridgeSha256: null, baseline: 'd'.repeat(64) };

function fixture(handler = () => {}) {
    const calls = [];
    class SSH {
        constructor(selected, options) {
            assert.equal(selected, node);
            assert.deepEqual(options, { expectedEndpoint: { ip: node.ip, port: 22, username: 'root' }, expectedHostKeySha256: pin });
            this.usePool = true;
        }
        async connect() { assert.equal(this.usePool, false); calls.push('connect'); }
        disconnect() { calls.push('close'); }
        async exec(command, options) {
            const input = JSON.parse(options.stdin);
            assert.ok(options.timeout > 0 && options.timeout <= 150000);
            assert.ok(!command.includes(desired.psk) && !command.includes(desired.users[0].password));
            calls.push(input.action);
            const result = await handler(input);
            if (result !== undefined) return result;
            if (input.action === 'preflight') return ok(ready);
            if (input.action === 'prepare') return ok(observation);
            if (input.action === 'check') return ok({ ok: true });
            return ok({ ok: true, backupId: input.backupId });
        }
    }
    return { remote: createRelayDirect({ node, env, SSH }), calls };
}

test('requires authority and canonical ssh2 pin before construction', () => {
    const SSH = class { constructor() { assert.fail(); } };
    for (const override of [{ C3_REBUILD_L2TP_SSH_SHA256: undefined }, { C3_REBUILD_L2TP_SSH_SHA256: 'SHA256:abc' },
        { C3_REBUILD_ENABLED: 'false' }, { C3_REBUILD_L2TP_RELAY_MACHINE_ID: undefined }]) {
        assert.throws(() => createRelayDirect({ node, env: { ...env, ...override }, SSH }));
    }
});

test('the exact SSH command shell and Python stdin reject invalid framing locally', async () => {
    class SSH {
        connect() {}
        disconnect() {}
        exec(command) {
            // Malformed identity is rejected even under root, before reading
            // machine identity or invoking any host-side commands.
            const result = spawnSync('/bin/sh', ['-c', command], {
                input: '{"action":"preflight","machineId":"invalid"}', encoding: 'utf8', timeout: 5000,
            });
            assert.equal(result.status, 70, result.stderr || result.error?.message);
            assert.equal(result.stdout, '');
            assert.equal(result.stderr, 'DIRECT_PREREQUISITE\n');
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        }
    }
    const remote = createRelayDirect({ node, env, SSH });
    await assert.rejects(remote.preflight(), { code: 'REBUILD_L2TP_DIRECT_PREREQUISITE' });
    await remote.close();
});

test('prepare and validate before mutation, bind private desired and lock, then read back', async () => {
    const { remote, calls } = fixture(input => {
        if (input.action === 'check' || input.action === 'install') {
            assert.ok(Object.values(input.files).some(value => Buffer.from(value, 'base64').toString().includes(desired.psk)));
            assert.ok(Object.values(input.files).some(value => Buffer.from(value, 'base64').toString().includes('mtu 1380\nmru 1370')));
        }
    });
    assert.deepEqual(await remote.preflight(), ready);
    const plan = await remote.prepare(args);
    assert.match(plan.backupId, /^[a-f0-9]{32}$/);
    assert.ok(!JSON.stringify(plan).includes(desired.psk));
    assert.equal(plan.getDesired().psk, desired.psk);
    assert.deepEqual(calls, ['connect', 'preflight', 'preflight', 'prepare', 'check']);
    await assert.rejects(remote.install({ ...plan }, async () => {}));
    await assert.rejects(remote.install(plan, async () => { throw Error('lease lost'); }));
    assert.ok(!calls.includes('install'));
    await remote.install(plan, async () => calls.push('lock'));
    assert.equal(await remote.verify(plan), true);
    await remote.close();
    assert.deepEqual(calls.slice(5), ['lock', 'install', 'verify', 'close']);
});

test('masked or wrong machine and invalid generated addresses cannot dispatch writes', async () => {
    for (const response of [{ ...ready, machineId: 'e'.repeat(32) }, { ...ready, masked: true }, { ...ready, ppp: false }]) {
        const { remote, calls } = fixture(() => ok(response));
        await assert.rejects(remote.prepare(args));
        assert.deepEqual(calls, ['connect', 'preflight']);
        await remote.close();
    }
    const { remote, calls } = fixture();
    await assert.rejects(remote.prepare({ ...args, desired: { ...desired, localAddress: '10.255.1.10' } }));
    assert.deepEqual(calls, []);
});

test('wire receipt for settled install refusal releases the coordinator to attempt verified rollback', async () => {
    const { remote } = fixture(input => input.action === 'install'
        ? { code: 70, stderr: 'DIRECT_COMMAND_FAILED\n', stdout: '' } : undefined);
    const plan = await remote.prepare(args);
    await assert.rejects(remote.install(plan, async () => {}), { code: 'REBUILD_L2TP_DIRECT_COMMAND_FAILED', commandSettled: true });
    assert.equal(await remote.rollback(plan, async () => {}), true);
    await remote.close();
});

test('definite nonzero permits exact rollback, but SSH failure, signal, timeout or lost receipt never do', async () => {
    for (const outcome of [{ code: 70, stderr: 'DIRECT_COMMAND_FAILED\n', stdout: '' }, { code: 70 }, { code: null }, { code: 75 }, { code: 0, stdout: '{}' }, new Error(desired.psk)]) {
        const { remote, calls } = fixture(input => {
            if (input.action !== 'install') return undefined;
            if (outcome instanceof Error) throw outcome;
            return { stderr: desired.psk, ...outcome };
        });
        const plan = await remote.prepare(args);
        const uncertain = outcome.code !== 70 || outcome.stderr !== 'DIRECT_COMMAND_FAILED\n';
        await assert.rejects(remote.install(plan, async () => {}), err => {
            assert.equal(err.remoteOutcomeUncertain === true, uncertain);
            assert.ok(!String(err.stack).includes(desired.psk));
            return true;
        });
        assert.equal(await remote.rollback(plan, async () => {}), !uncertain);
        assert.equal(calls.includes('rollback'), !uncertain);
        assert.equal(await remote.rollback(plan, async () => {}), false);
        await remote.close();
    }
});
