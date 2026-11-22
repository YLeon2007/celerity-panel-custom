'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createRelayDirect } = require('../rebuildRelayDirect');
const attested = require('./helpers/rebuildRelayDirectWire');

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), pin = 'c'.repeat(64);
const backupId = 'd'.repeat(32), census = 'e'.repeat(64);
const node = { _id: nodeId, ip: '192.0.2.19', ssh: { username: 'root', port: 22 } };
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
    C3_REBUILD_L2TP_RELAY_ID: nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: pin };
const network = { clientCidr: '10.255.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 };
const request = { nodeId, backupId, network };
const ok = value => ({ code: 0, stdout: JSON.stringify(value) + '\n', stderr: '' });

function fixture(reply, override = {}) {
    const calls = [];
    class SSH {
        constructor(selected, options) {
            assert.equal(selected, node);
            assert.deepEqual(options, { expectedEndpoint: { ip: node.ip, port: 22, username: 'root' }, expectedHostKeySha256: pin });
        }
        connect() { assert.equal(this.usePool, false); calls.push('connect'); }
        disconnect() { calls.push('disconnect'); }
        async exec(command, { stdin, timeout }) {
            calls.push('exec');
            assert.match(command, /^\/usr\/bin\/timeout -k 1s 9s \/usr\/bin\/python3 -I -B -c /);
            assert.ok(Buffer.byteLength(command) + 1 <= 128 * 1024, 'fits Linux MAX_ARG_STRLEN');
            assert.ok(!command.includes(backupId) && !command.includes(machineId));
            assert.equal(timeout, 12000);
            assert.deepEqual(JSON.parse(stdin), { action: 'session-count', machineId, ...request });
            if (reply instanceof Error) throw reply;
            return typeof reply === 'function' ? reply(command) : reply;
        }
    }
    return { remote: createRelayDirect({ node, env: { ...env, ...override }, SSH: attested(SSH, machineId) }), calls };
}

for (const receipt of [{ activeSessions: 0, activeIpsec: 1, census }, { activeSessions: 3, activeIpsec: null, census: null },
    { activeSessions: null, activeIpsec: 1, census: null }]) {
    test(`session count admits exactly the bounded receipt (${receipt.activeSessions}, ${receipt.activeIpsec}) over pinned transport`, async () => {
        const { remote, calls } = fixture(ok(receipt));
        assert.deepEqual(await remote.readSessionCount(request), receipt);
        assert.deepEqual(calls, ['connect', 'exec']);
        await remote.close();
    });
}

test('session count rejects wrong enrollment and input without connecting', async () => {
    assert.throws(() => fixture(null, { C3_REBUILD_L2TP_RELAY_MACHINE_ID: '' }), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    assert.throws(() => fixture(null, { C3_REBUILD_L2TP_SSH_SHA256: 'invalid' }), { code: 'REBUILD_L2TP_SSH_PIN_INVALID' });
    const { remote, calls } = fixture(null);
    for (const fields of [{ nodeId: 'f'.repeat(24) }, { backupId: backupId + '\n' }, { extra: true },
        { network: { ...network, fwmark: '77' } }, { network: { ...network, unexpected: true } }]) {
        await assert.rejects(remote.readSessionCount({ ...request, ...fields }), { code: 'REBUILD_L2TP_SESSION_COUNT_INPUT_INVALID' });
    }
    assert.deepEqual(calls, []);
    await remote.close();
});

test('session count errors never become zero or expose raw transport data', async () => {
    const secret = 'mock-session-secret', positive = { activeSessions: 0, activeIpsec: 0, census };
    const invalid = [ok({ ...positive, detail: secret }), ok({ activeSessions: '0', census }), ok({ activeSessions: -1, census }),
        ok({ activeSessions: 0.5, census }), ok({ activeSessions: null, census }), ok({ activeSessions: Number.MAX_SAFE_INTEGER + 1, census }),
        ok({ activeSessions: 0, census: secret }), ok({ activeSessions: 0, census: census + '\n' }), ok({}),
        ok({ ...positive, activeIpsec: -1 }), ok({ ...positive, activeIpsec: null }),
        ok({ ...positive, activeIpsec: '0' }), ok({ ...positive, census: secret }), ok({ ...positive, census: census + '\n' }),
        ok({ ...positive, census: null }), ok({ activeSessions: null, activeIpsec: null, census: null }),
        { ...ok(positive), stdout: `{"activeSessions":2,${ok(positive).stdout.slice(1)}` },
        { ...ok(positive), stderr: secret }, { code: 70, stdout: '', stderr: 'DIRECT_SESSION_COUNT_UNPROVED\n' },
        { code: 124, stdout: '', stderr: '' }, new Error(secret)];
    for (const receipt of invalid) {
        const { remote, calls } = fixture(receipt);
        await assert.rejects(remote.readSessionCount(request), error => {
            assert.match(error.code, /^REBUILD_L2TP_DIRECT_(SESSION_COUNT_UNPROVED|OUTCOME_UNKNOWN)$/);
            assert.ok(!String(error.stack).includes(secret) && !error.cause && !error.remoteOutcomeUncertain);
            return true;
        });
        assert.deepEqual(calls.slice(0, 2), ['connect', 'exec']);
        await remote.close();
    }
});

test('real local shell and Python dispatch accept framing and sanitize refusal', async () => {
    const { remote } = fixture(command => {
        // Deliberately omit machineId so dispatch refuses before any host reads.
        const r = spawnSync('/bin/sh', ['-c', command], {
            input: '{"action":"session-count"}', encoding: 'utf8', timeout: 12000,
        });
        assert.ifError(r.error);
        assert.equal(r.status, 70);
        assert.equal(r.stdout, '');
        assert.equal(r.stderr, 'DIRECT_SESSION_COUNT_UNPROVED\n');
        return { code: r.status, stdout: r.stdout, stderr: r.stderr };
    });
    await assert.rejects(remote.readSessionCount(request), { code: 'REBUILD_L2TP_DIRECT_SESSION_COUNT_UNPROVED' });
    await remote.close();
});
