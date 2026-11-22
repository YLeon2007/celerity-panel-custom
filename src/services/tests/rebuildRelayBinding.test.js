'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { canInstallRelay, resolveRelayBinding } = require('../rebuildRelayAuthorization');
const { createRelayDirect } = require('../rebuildRelayDirect');
const attested = require('./helpers/rebuildRelayDirectWire');

const a = { nodeId: 'a'.repeat(24), host: '192.0.2.19', port: 22, username: 'root',
    machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) };
const b = { nodeId: 'b'.repeat(24), host: 'relay-b.invalid', port: 2222, username: 'root',
    machineId: '3'.repeat(32), sshHostKeySha256: '4'.repeat(64) };
const legacy = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: a.nodeId,
    C3_REBUILD_L2TP_RELAY_MACHINE_ID: a.machineId, C3_REBUILD_L2TP_SSH_SHA256: a.sshHostKeySha256 };
const listKey = 'C3_REBUILD_L2TP_RELAYS_JSON';
const list = (...rows) => ({ ...legacy, [listKey]: JSON.stringify(rows) });
const card = (row, ssh = {}) => ({ _id: row.nodeId, ip: row.host, ssh: { port: row.port, username: row.username, ...ssh } });
const mismatch = { code: 'REBUILD_L2TP_BINDING_MISMATCH' };

test('operator list grants distinct frozen bindings by ID, not by card or legacy selection', () => {
    const env = list(a, b);
    for (const row of [a, b]) {
        assert.equal(canInstallRelay(env, row.nodeId), true);
        const binding = resolveRelayBinding(env, row.nodeId, card(row));
        assert.deepEqual(binding, row);
        assert.equal(Object.isFrozen(binding), true);
    }
    assert.throws(() => resolveRelayBinding(env, b.nodeId, card(a)), mismatch);
    assert.throws(() => resolveRelayBinding(env, b.nodeId, { ...card(b), ip: a.host }), mismatch);
    assert.throws(() => resolveRelayBinding(env, b.nodeId, card(b, { port: 22 })), mismatch);
    assert.throws(() => resolveRelayBinding(env, b.nodeId, card(b, { username: 'operator' })), mismatch);
});

test('missing or malformed list authority never falls back to the legacy singleton', () => {
    const invalid = [undefined, null, '', '{', '{}', 'null', '[null]', JSON.stringify([a, { ...b, port: '22' }]),
        JSON.stringify([{ ...a, host: 'example.invalid\n' }]), JSON.stringify([{ ...a, host: 'http://example.invalid' }]),
        JSON.stringify([{ ...a, machineId: 'A'.repeat(32) }]), JSON.stringify([{ ...a, machineId: `${a.machineId}\n` }]),
        JSON.stringify([{ ...a, sshHostKeySha256: 'B'.repeat(64) }]), JSON.stringify([{ ...a, sshHostKeySha256: `${a.sshHostKeySha256}\n` }]),
        JSON.stringify([{ ...a, username: '-root' }]), JSON.stringify([{ ...a, password: 'unexpected' }]),
        `[${JSON.stringify(a).slice(0, -1)},"p\\u006frt":22}]`];
    for (const env of [list(b), list(), ...invalid.map(raw => ({ ...legacy, [listKey]: raw }))]) {
        assert.equal(canInstallRelay(env, a.nodeId), false);
        assert.throws(() => resolveRelayBinding(env, a.nodeId, card(a)));
    }
});

test('a duplicate ID, machine, key or host+port alias invalidates the entire list', () => {
    for (const rows of [[a, a], [a, { ...b, nodeId: a.nodeId }], [a, { ...b, machineId: a.machineId }],
        [a, { ...b, sshHostKeySha256: a.sshHostKeySha256 }], [a, { ...b, host: a.host, port: a.port }],
        [a, { ...b, host: '::ffff:c000:213', port: a.port }],
        [{ ...a, host: '2001:db8::1' }, { ...b, host: '2001:0DB8:0000:0::1', port: a.port }],
        [{ ...a, host: 'RELAY-B.invalid.', port: b.port }, b]]) {
        const env = list(...rows);
        assert.equal(canInstallRelay(env, a.nodeId), false);
        assert.equal(canInstallRelay(env, b.nodeId), false);
    }
});

test('pure route gate preserves legacy admission, but strict/classic cannot opt in', () => {
    assert.deepEqual(resolveRelayBinding(legacy, a.nodeId, card(a)), a);
    const noPin = { ...legacy, C3_REBUILD_L2TP_SSH_SHA256: undefined };
    assert.equal(canInstallRelay(noPin, a.nodeId), true);
    assert.throws(() => resolveRelayBinding(noPin, a.nodeId, card(a)), { code: 'REBUILD_L2TP_SSH_PIN_INVALID' });
    for (const flag of ['L2TP_EXECUTION_ENABLED', 'CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED']) {
        const env = { ...list(a, b), [flag]: 'true' };
        assert.equal(canInstallRelay(env, a.nodeId), false);
        assert.throws(() => resolveRelayBinding(env, a.nodeId, card(a)));
    }
});

test('DIRECT uses only operator endpoint and pin, plus allowlisted card credentials', async () => {
    const calls = [];
    for (const row of [a, b]) {
        const node = card(row, { password: 'dummy', privateKey: 'dummy-key', proxy: 'unexpected',
            hostVerifier: () => true, hostKeySha256: 'f'.repeat(64), host: 'other.invalid' });
        node.sock = 'unexpected';
        if (row === b) node.ip = 'RELAY-B.INVALID.'; // Corroborates, but isn't passed to SSH.
        class SSH {
            constructor(selected, options) {
                assert.equal(selected.ip, row.host);
                assert.equal(selected.sock, undefined);
                assert.deepEqual(selected.ssh, { port: row.port, username: row.username, password: 'dummy', privateKey: 'dummy-key' });
                assert.deepEqual(options, { expectedEndpoint: { ip: row.host, port: row.port, username: row.username },
                    expectedHostKeySha256: row.sshHostKeySha256 });
            }
            connect() { assert.equal(this.usePool, false); }
            disconnect() {}
            exec(_, { stdin }) {
                const frame = JSON.parse(stdin);
                calls.push(frame);
                return { code: 0, stderr: '', stdout: `${JSON.stringify({ machineId: row.machineId, ppp: true, masked: false, unitsLoaded: true })}\n` };
            }
        }
        const remote = createRelayDirect({ env: list(a, b), node, SSH: attested(SSH, row.machineId) });
        assert.equal((await remote.preflight()).machineId, row.machineId);
        await remote.close();
    }
    assert.deepEqual(calls, [a, b].map(({ machineId }) => ({ action: 'preflight', machineId })));
});

test('DIRECT fences config and card drift across an awaited handshake without dispatch', async () => {
    for (const drift of [(env, node) => { node.ssh.port += 1; }, env => Object.assign(env, list(a)),
        env => Object.assign(env, list(a, { ...b, sshHostKeySha256: '5'.repeat(64) }))]) {
        const env = list(a, b), node = card(b);
        class SSH {
            connectDirectOnce() { drift(env, node); return () => assert.fail('binding drift must block dispatch'); }
            disconnect() {}
        }
        const remote = createRelayDirect({ env, node, SSH });
        await assert.rejects(remote.preflight(), { code: /^REBUILD_L2TP_(INSTALL_DISABLED|BINDING_MISMATCH)$/ });
        await remote.close();
    }
});