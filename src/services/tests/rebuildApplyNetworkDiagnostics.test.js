'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTransport } = require('../rebuildTransport');
const logger = require('../../utils/logger');

const machineId = '1'.repeat(32), backupId = '2'.repeat(32), proof = '3'.repeat(64), published = '4'.repeat(64);
const nodeId = '5'.repeat(24);
const installation = { node: nodeId, rebuildMachineId: machineId, backupId,
    rebuildInstallToken: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    clientCidr: '10.20.30.0/24', fwmark: 77, routeTable: 177, tproxyPort: 12345 };
const phases = ['check', 'prepare', 'verify_before_restart', 'publish', 'restart', 'verify_after_restart'];
const actions = ['check-apply-network', 'prepare-apply-network', 'verify-apply-network', 'publish-apply-profiles',
    'restart-apply-network', 'finalize-apply-profiles'];
const unknown = 'REBUILD_L2TP_APPLY_NETWORK_OUTCOME_UNKNOWN';
const refused = 'REBUILD_L2TP_APPLY_NETWORK_REFUSED';
const identity = 'REBUILD_L2TP_IDENTITY_CHANGED';
const ok = { code: 0, stdout: JSON.stringify({ ok: true, backupId, proof }) + '\n', stderr: '' };
const privateText = 'private-fixture.invalid/session=must-not-appear';
const lost = () => { throw Object.assign(new Error(privateText), { code: privateText }); };
const frame = { code: 70, stdout: '', stderr: 'DIRECT_RUNTIME_UNPROVED\n' };

// Actual bound Apply methods and DIRECT decoder; the SSH double never runs a command.
async function exercise(t, at, respond, expectedClass, code, options = {}) {
    const events = [], seen = [], bridgeCommands = [];
    const bridge = { inbounds: options.activeBridge ? [{ tag: 'fixture', port: 9443 }] : [], outbounds: [] };
    let guardArmed = false, modeledRestarts = 0, connections = 0;
    t.mock.method(logger, 'warn', (...args) => {
        events.push(args);
        if (options.brokenLogger) throw new Error(privateText);
    });
    class SSH {
        async connectDirectOnce() { assert.equal(this.usePool, false); connections++; }
        async exec(cmd, opts) {
            if (cmd === '/usr/bin/head -c 34 /etc/machine-id') return { code: 0, stdout: machineId, stderr: '' };
            if (cmd.includes('LoadState')) return { code: 0, stdout: cmd.includes('xray-bridge') && !options.loadedBridge ? 'not-found' : 'loaded' };
            if (cmd.includes('ExecStart')) return { code: 0, stdout: `path=/usr/local/bin/xray ; -config /usr/local/etc/${cmd.includes('xray-bridge') ? 'xray-bridge' : 'xray'}/config.json ;` };
            const bridgeCommand = /(?:^|; )(systemctl (?:stop|disable|enable) xray-bridge\.service\b.*)$/.exec(cmd);
            if (bridgeCommand) bridgeCommands.push(bridgeCommand[1]);
            if (!cmd.startsWith('/usr/bin/timeout ')) return { code: 0, stdout: '', stderr: '' };
            const request = JSON.parse(opts.stdin), { action } = request;
            seen.push(action);
            if (action === 'publish-apply-profiles') {
                assert.equal(request.nodeId, nodeId);
                assert.equal(request.proof, proof);
                const sha = profile => require('node:crypto').createHash('sha256').update(JSON.stringify(profile)).digest('hex');
                assert.deepEqual(request.profiles, { main: sha({ inbounds: [], outbounds: [] }), bridge: sha(bridge) });
            }
            if (action === 'restart-apply-network' || action === 'finalize-apply-profiles') assert.equal(request.proof, published);
            if (action === 'restart-apply-network' && options.effectBeforeLoss) modeledRestarts++;
            return seen.length - 1 === at ? respond() : (seen.length >= 4 ? { ...ok, stdout: ok.stdout.replace(proof, published) } : ok);
        }
        disconnect() {}
    }
    const bound = createTransport({ _id: nodeId }, SSH, { machineId, installation, merged: true,
        verify: async () => { if (guardArmed && options.guardFails) lost(); } });
    const apply = async () => {
        await bound.attest();
        guardArmed = true;
        await bound.checkActivation();
        await bound.stagePair([{ profile: 'main', config: { inbounds: [], outbounds: [] } }, { profile: 'bridge', config: bridge }]);
        await bound.prepareActivation();
        await bound.putPair();
    };
    try {
        if (!code) await apply();
        else await assert.rejects(apply(), err => {
            assert.equal(err.code, code);
            assert.equal(err.remoteOutcomeUncertain, code === unknown && [1, 3, 4, 5].includes(at) ? true : undefined);
            return true;
        });
    } finally { guardArmed = false; await bound.close(); }
    assert.equal(connections, 1);
    assert.deepEqual(seen, options.guardFails ? [] : actions.slice(0, code ? at + 1 : actions.length));
    assert.deepEqual(bridgeCommands, options.bridgeCommands ?? []);
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
]) test(`Apply restart: ${label}`, t => exercise(t, 4, () => response, kind, code));
test('local guard rejection is not a lost SSH result', t => exercise(t, 0, lost, 'local_check', unknown, { guardFails: true }));
test('logging failure cannot replace the unknown outcome', t => exercise(t, 4, lost, 'ssh_no_reply', unknown, { brokenLogger: true }));
test('acknowledged Apply emits no failure event', t => exercise(t, -1, null));

test('Apply preserves a loaded inactive bridge only on an exact publication acknowledgement', async t => {
    const reply = value => ({ ...ok, stdout: JSON.stringify({ ok: true, backupId, proof: published, bridgeUnchanged: value }) + '\n' });
    const loaded = { loadedBridge: true };
    await t.test('keep the proven placeholder', t => exercise(t, 3, () => reply(true), undefined, undefined, loaded));
    await t.test('unchanged behavior without the witness', t => exercise(t, -1, null, undefined, undefined, {
        ...loaded, bridgeCommands: ['systemctl stop xray-bridge.service', 'systemctl disable xray-bridge.service'],
    }));
    await t.test('reject on an active candidate', t => exercise(t, 3, () => reply(true), 'invalid_reply', unknown, { ...loaded, activeBridge: true }));
    await t.test('reject a false witness', t => exercise(t, 3, () => reply(false), 'invalid_reply', unknown, loaded));
    await t.test('reject the witness on restart', t => exercise(t, 4, () => reply(true), 'invalid_reply', unknown, {
        ...loaded, bridgeCommands: ['systemctl stop xray-bridge.service'],
    }));
});

test('only publication recognizes the exact empty-bridge refusal, not generic drift or a late frame', async t => {
    const bridge = { ...frame, stderr: 'DIRECT_BRIDGE_PLACEHOLDER_UNPROVED\n' };
    await t.test('publish', t => exercise(t, 3, () => bridge, 'direct_refusal', 'REBUILD_L2TP_APPLY_BRIDGE_PLACEHOLDER_UNPROVED'));
    await t.test('generic rollback drift', t => exercise(t, 3, () => ({ ...frame, stderr: 'DIRECT_ROLLBACK_DRIFT\n' }), 'direct_refusal', refused));
    await t.test('late frame', t => exercise(t, 5, () => bridge, 'unrecognized_exit_70', unknown));
    await t.test('extra bytes', t => exercise(t, 3, () => ({ ...bridge, stderr: bridge.stderr + 'foreign\n' }), 'unrecognized_exit_70', unknown));
});
test('preview checks project an exact runtime refusal without ever sending reattestation', async t => {
    const nodeId = '4'.repeat(24);
    const actions = [];
    let stdout = '', stderr = 'DIRECT_RUNTIME_FOREIGN_CHANGE\n';
    t.mock.method(logger, 'warn', () => {});
    class SSH {
        async connectDirectOnce() {
            return async (_cmd, options) => {
                const action = JSON.parse(options.stdin).action;
                actions.push(action);
                assert.equal(action, 'check-apply-network');
                return { code: 70, stdout, stderr };
            };
        }
        async exec(cmd) {
            assert.equal(cmd, '/usr/bin/head -c 34 /etc/machine-id');
            return { code: 0, stdout: machineId, stderr: '' };
        }
        disconnect() {}
    }
    const bound = createTransport({ _id: nodeId }, SSH, { machineId, merged: true,
        installation: { ...installation, node: nodeId }, verify: async () => {} });
    const check = () => bound.checkActivation({ readOnly: true });
    try {
        await bound.attest();
        await assert.rejects(check(), { code: refused, reason: 'RUNTIME_FOREIGN_CHANGE' });
        stdout = privateText;
        await assert.rejects(check(), { code: unknown });
        stdout = '';
        stderr = 'DIRECT_RUNTIME_REATTEST_REQUIRED\n';
        await assert.rejects(check(), { code: 'REBUILD_L2TP_DIRECT_RUNTIME_REATTEST_REQUIRED' });
    } finally { await bound.close(); }
    assert.deepEqual(actions, Array(3).fill('check-apply-network'));
});
