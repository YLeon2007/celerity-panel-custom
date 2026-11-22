'use strict';
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createHash } = require('node:crypto');
const { Client } = require('ssh2');
const { MAIN, BRIDGE } = require('../../classicAppliedConfig');

// Bridge the existing profile fixtures to the pinned NodeSSH transport; they
// still own profile storage, parser checks and simulated activation failures.
const key = Buffer.from('offline fixture host key');
const pin = createHash('sha256').update(key).digest('hex');
function bindProfileWire(replace, endpoint, machineId, createFixture) {
    const clients = new WeakMap(), paths = { main: MAIN, bridge: BRIDGE };
    replace(Client.prototype, 'connect', function (config) {
        assert.equal(config.host, endpoint);
        assert.equal(config.port, 22);
        assert.equal(config.username, 'root');
        assert.equal(config.hostVerifier(key), true);
        clients.set(this, { fixture: createFixture(), staged: [] });
        queueMicrotask(() => this.emit('ready'));
        return this;
    });
    replace(Client.prototype, 'end', function () { clients.delete(this); });
    replace(Client.prototype, 'exec', function (command, ready) {
        const { fixture, staged } = clients.get(this);
        const stream = new EventEmitter(), chunks = [];
        stream.stderr = new EventEmitter();
        stream.write = chunk => { chunks.push(Buffer.from(chunk)); return true; };
        let ended = false;
        async function run(stdin) {
            const ok = (stdout = '') => { stream.emit('data', stdout); stream.emit('close', 0); };
            try {
                if (command === '/usr/bin/head -c 34 /etc/machine-id') return ok(machineId + '\n');
                if (command.startsWith('/usr/bin/timeout -k ') && fixture.relayNetwork) {
                    const request = JSON.parse(stdin);
                    assert.equal(request.machineId, machineId);
                    return ok(JSON.stringify({ ok: true, backupId: request.backupId, proof: await fixture.relayNetwork(request) }) + '\n');
                }
                if (command === '/usr/local/bin/xray version') {
                    let version;
                    try { version = await fixture.requireSupportedCore(); }
                    catch (error) { if (error.code === 'REBUILD_XRAY_VERSION_TOO_OLD') return ok('Xray 25.0.0'); throw error; }
                    return ok(`Xray ${version ?? '26.3.27'}`);
                }
                for (const [profile, path] of Object.entries(paths)) {
                    const unit = profile === 'main' ? 'xray' : 'xray-bridge';
                    if (command.startsWith(`if test -f ${path}; then cat ${path};`)) {
                        const value = await fixture.read(profile);
                        return ok(value === null ? 'C3_CLASSIC_PROFILE_ABSENT' : JSON.stringify(value));
                    }
                    if (command === `systemctl show -p LoadState --value ${unit}.service`) return ok('loaded\n');
                    if (command === `systemctl show -p ExecStart --value ${unit}.service`) return ok(`path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${path} ;`);
                    if (command.includes(`cat > ${path}.rebuild-`)) {
                        staged.push({ profile, config: JSON.parse(stdin) });
                        if (staged.length === 2) await fixture.stagePair(staged);
                        return ok();
                    }
                }
                if (command === 'systemctl stop xray-bridge.service') { await fixture.putPair(staged); return ok(); }
                if (command.startsWith('rm -f -- ')) { await fixture.close(); return ok(); }
                if (/^(?:set -eu; .* mv -fT |systemctl (?:enable|disable) )/.test(command)) return ok();
                assert.fail('unexpected bound profile command');
            } catch (error) { stream.emit('error', error); }
        }
        stream.end = done => { ended = true; done(); queueMicrotask(() => run(Buffer.concat(chunks).toString('utf8'))); };
        ready(null, stream);
        queueMicrotask(() => { if (!ended) void run(); });
    });
}
module.exports = { bindProfileWire, pin };
