'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTransport } = require('../rebuildTransport');
const logger = require('../../utils/logger');

const machineId = '1'.repeat(32), backupId = '2'.repeat(32), proof = '3'.repeat(64);
const installation = { rebuildMachineId: machineId, backupId,
    rebuildInstallToken: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    clientCidr: '10.20.30.0/24', fwmark: 77, routeTable: 177, tproxyPort: 12345 };
const phases = ['check', 'prepare', 'verify_before_restart', 'restart', 'verify_after_restart'];
const actions = ['check', 'prepare', 'verify', 'restart', 'verify'].map(x => `${x}-apply-network`);
const unknown = 'REBUILD_L2TP_APPLY_NETWORK_OUTCOME_UNKNOWN';
const refused = 'REBUILD_L2TP_APPLY_NETWORK_REFUSED';
const identity = 'REBUILD_L2TP_IDENTITY_CHANGED';
const ok = { code: 0, stdout: JSON.stringify({ ok: true, backupId, proof }) + '\n', stderr: '' };
const privateText = 'private-fixture.invalid/session=must-not-appear';
const lost = () => { throw Object.assign(new Error(privateText), { code: privateText }); };
const frame = { code: 70, stdout: '', stderr: 'DIRECT_RUNTIME_UNPROVED\n' };

// Actual bound Apply methods and DIRECT decoder; the SSH double never runs a command.
async function exercise(t, at, respond, expectedClass, code, options = {}) {
    const events = [], seen = [];
    let guardArmed = false, modeledRestarts = 0, connections = 0;
    t.mock.method(logger, 'warn', (...args) => {
        events.push(args);
        if (options.brokenLogger) throw new Error(privateText);
    });
    class SSH {
        async connectDirectOnce() { assert.equal(this.usePool, false); connections++; }
        async exec(cmd, opts) {
            if (cmd === '/usr/bin/head -c 34 /etc/machine-id') return { code: 0, stdout: machineId, stderr: '' };
            if (cmd.includes('LoadState')) return { code: 0, stdout: cmd.includes('xray-bridge') ? 'not-found' : 'loaded' };
            if (cmd.includes('ExecStart')) return { code: 0, stdout: 'path=/usr/local/bin/xray ; -config /usr/local/etc/xray/config.json ;' };
            if (!cmd.startsWith('/usr/bin/timeout ')) return { code: 0, stdout: '', stderr: '' };
            const action = JSON.parse(opts.stdin).action;
            seen.push(action);
            if (action === 'restart-apply-network' && options.effectBeforeLoss) modeledRestarts++;
            return seen.length - 1 === at ? respond() : ok;
        }
        disconnect() {}
    }
    const bound = createTransport({}, SSH, { machineId, installation, merged: true,
        verify: async () => { if (guardArmed && options.guardFails) lost(); } });
    const apply = async () => {
        await bound.attest();
        guardArmed = true;
        await bound.checkActivation();
        await bound.stagePair(['main', 'bridge'].map(profile => ({ profile, config: { inbounds: [], outbounds: [] } })));
        await bound.prepareActivation();
        await bound.putPair();
    };
    try {
        if (!code) await apply();
        else await assert.rejects(apply(), err => {
            assert.equal(err.code, code);
            assert.equal(err.remoteOutcomeUncertain, code === unknown && [1, 3].includes(at) ? true : undefined);
            return true;
        });
    } finally { guardArmed = false; await bound.close(); }
    assert.equal(connections, 1);
    assert.deepEqual(seen, options.guardFails ? [] : actions.slice(0, code ? at + 1 : actions.length));
    if (options.effectBeforeLoss) assert.equal(modeledRestarts, 1);
    assert.deepEqual(events, code ? [[JSON.stringify({ event: 'rebuild.apply_network.failure', phase: phases[at], failureClass: expectedClass })]] : []);
}

for (const [i, phase] of phases.entries()) {
    test(`Apply ${phase}: no SSH reply is not a refusal or a retry`, t =>
        exercise(t, i, lost, 'ssh_no_reply', unknown, { effectBeforeLoss: phase === 'restart' }));
}
for (const [label, response, kind, code] of [
    ['exact DIRECT refusal', frame, 'direct_refusal', refused],
    ['exact DIRECT identity', { ...frame, stderr: 'DIRECT_IDENTITY\n' }, 'direct_refusal', identity],
    ['contaminated refusal', { ...frame, stderr: frame.stderr + privateText }, 'unrecognized_exit_70', unknown],
    ['extra stdout on refusal', { ...frame, stdout: privateText }, 'unrecognized_exit_70', unknown],
    ['no exit status', { ...frame, code: null }, 'missing_exit_status', unknown],
    ['host inconclusive', { code: 75, stdout: '', stderr: '' }, 'remote_exit_75', unknown],
    ['other nonzero status', { ...frame, code: 23 }, 'other_nonzero_exit', unknown],
    ['malformed success frame', { ...ok, stdout: privateText }, 'invalid_reply', unknown],
    ['wrong proof', { ...ok, stdout: ok.stdout.replace(proof, 'a'.repeat(64)) }, 'invalid_reply', unknown],
]) test(`Apply restart: ${label}`, t => exercise(t, 3, () => response, kind, code));
test('local guard rejection is not a lost SSH result', t => exercise(t, 0, lost, 'local_check', unknown, { guardFails: true }));
test('logging failure cannot replace the unknown outcome', t => exercise(t, 3, lost, 'ssh_no_reply', unknown, { brokenLogger: true }));
test('acknowledged Apply emits no failure event', t => exercise(t, -1, null));
