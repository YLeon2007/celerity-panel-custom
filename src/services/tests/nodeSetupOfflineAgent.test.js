'use strict';

// Opt in to the positive/integrity cases with CC_AGENT_TEST_MAIN_KIT=<accepted kit>.
// No SSH connection, downloads or service manager. Run only this test file.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');
const { EventEmitter } = require('node:events');
const { Writable } = require('node:stream');
const { spawn } = require('node:child_process');

const kitSource = process.env.CC_AGENT_TEST_MAIN_KIT;
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const nodeInfo = { xray: { agentTls: false } };
const source = require.resolve('../nodeSetup');
const originalLoad = Module._load;
let setup;
try {
    // Refuse real connections and bypass unrelated production config, DB and logging.
    Module._load = function (id, parent, ...rest) {
        if (parent?.filename === source) {
            if (id === 'ssh2') return { Client: class { constructor() { throw Error('unexpected connection'); } } };
            if (id === '../utils/logger') return { info() {}, error() {} };
            if (['../../config', './cryptoService', '../models/settingsModel', './configGenerator'].includes(id)) return {};
        }
        return originalLoad.call(this, id, parent, ...rest);
    };
    setup = require(source);
} finally { Module._load = originalLoad; }

function fixture(t, arch, fault) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cc-agent-offline-'));
    t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
    const kit = path.join(dir, 'kit'), dst = path.join(dir, 'bin'), tools = path.join(dir, 'tools');
    for (const d of [kit, dst, tools]) fs.mkdirSync(d);
    const old = process.env.CC_AGENT_OFFLINE_KIT_DIR;
    process.env.CC_AGENT_OFFLINE_KIT_DIR = kit;
    t.after(() => { if (old === undefined) delete process.env.CC_AGENT_OFFLINE_KIT_DIR; else process.env.CC_AGENT_OFFLINE_KIT_DIR = old; });
    for (const tool of ['mktemp', 'cat', 'sha256sum', 'chmod', 'mv', 'rm']) fs.symlinkSync(`/usr/bin/${tool}`, path.join(tools, tool));
    fs.writeFileSync(path.join(tools, 'uname'), '#!/bin/sh\n[ "$1" = -m ] && printf "%s\\n" "$FIXTURE_ARCH"\n', { mode: 0o755 });
    const target = path.join(dst, 'cc-agent');
    fs.writeFileSync(target, 'previous binary', { mode: 0o711 });
    const preimage = () => { const s = fs.statSync(target, { bigint: true }); return [sha(fs.readFileSync(target)), s.ino, s.mode, s.ctimeNs]; };
    const before = preimage(), calls = [], late = [];
    // Exercise the real ssh2 exec adapter and its chunked stdin writer, not just a command generator.
    const conn = {
        exec(command, callback) {
            calls.push(command);
            if (/curl|github\.com|latest\/download/.test(command)) throw Error('network fallback attempted');
            let cmd;
            if (command === 'uname -m' || command.includes('mktemp')) {
                if (fault === 'lost-ack' && calls.length > 2) throw Error('replay');
                cmd = command.replaceAll('/usr/local/bin/', './bin/'); // cwd is the private fixture root
            } else if (command === 'mkdir -p /etc/cc-agent /var/lib/cc-agent' || command === 'chmod 600 /etc/cc-agent/config.json' || command.includes('systemctl restart cc-agent')) {
                late.push(command); cmd = command.includes('systemctl restart cc-agent') ? 'printf "OK: cc-agent running\\n"' : ':';
            } else { throw Error('unexpected command'); }
            const child = spawn('/bin/sh', ['-c', cmd], { env: { LC_ALL: 'C', PATH: tools, FIXTURE_ARCH: arch }, cwd: dir });
            const ch = new EventEmitter(); ch.stderr = child.stderr;
            ch.write = b => child.stdin.write(fault === 'wire' ? b.subarray(1) : b);
            ch.end = cb => child.stdin.end(cb);
            ch.destroy = () => child.kill();
            child.stdin.on('drain', () => ch.emit('drain'));
            child.stdin.on('error', () => {});
            child.stdout.on('data', b => ch.emit('data', b));
            child.on('close', code => ch.emit('close', fault === 'lost-ack' && command.includes('mktemp') ? null : code));
            callback(null, ch);
        },
        sftp(cb) { late.push('sftp'); cb(null, { createWriteStream: () => new Writable({ write(_b, _enc, done) { done(); } }) }); },
    };
    const populate = () => {
        for (const name of ['SHA256SUMS', 'cc-agent-linux-amd64', 'cc-agent-linux-arm64']) fs.copyFileSync(path.join(kitSource, name), path.join(kit, name));
    };
    return { kit, target, calls, late, populate,
        run: () => setup.installCCAgent(conn, nodeInfo, 'fixture', '', false, () => {}),
        unchanged() { assert.deepEqual(preimage(), before); assert.deepEqual(fs.readdirSync(dst), ['cc-agent']); assert.deepEqual(late, []); },
    };
}

test('explicit missing kit fails before any SSH command', async t => {
    const f = fixture(t, 'x86_64');
    assert.equal((await f.run()).success, false); f.unchanged(); assert.deepEqual(f.calls, []);
});

test('explicit empty selector does not restore latest', async t => {
    const f = fixture(t, 'x86_64'); process.env.CC_AGENT_OFFLINE_KIT_DIR = '';
    assert.equal((await f.run()).success, false); f.unchanged(); assert.deepEqual(f.calls, []);
});

test('combined setup rejects an incomplete kit before token provisioning or connection', async t => {
    const f = fixture(t, 'x86_64');
    const result = await setup.setupXrayNodeWithAgent(nodeInfo);
    assert.equal(result.success, false); assert.match(result.error, /incomplete MAIN cc-agent/); f.unchanged();
});

for (const [arch, suffix] of [['x86_64', 'amd64'], ['aarch64', 'arm64'], ['amd64', 'amd64'], ['arm64', 'arm64']]) {
    test(`accepted MAIN kit installs exact ${suffix} bytes for ${arch}`, { skip: !kitSource }, async t => {
        const f = fixture(t, arch); f.populate(); const result = await f.run();
        assert.equal(result.success, true, result.output); assert.equal(result.agentVersion, '1.5.1');
        assert.equal(sha(fs.readFileSync(f.target)), sha(fs.readFileSync(path.join(kitSource, `cc-agent-linux-${suffix}`))));
        assert.equal(fs.statSync(f.target).mode & 0o777, 0o755); assert.deepEqual(fs.readdirSync(path.dirname(f.target)), ['cc-agent']);
        assert.ok(f.late.some(s => s.includes('systemctl restart cc-agent')));
    });
}

for (const fault of ['unknown-architecture', 'missing-other', 'missing-manifest', 'incomplete-manifest', 'tampered-selected', 'tampered-other', 'changed-manifest', 'symlink', 'wire']) {
    test(`offline refusal preserves old agent: ${fault}`, { skip: !kitSource }, async t => {
        const f = fixture(t, fault === 'unknown-architecture' ? 'riscv64' : 'x86_64', fault); f.populate();
        const amd = path.join(f.kit, 'cc-agent-linux-amd64'), arm = path.join(f.kit, 'cc-agent-linux-arm64'), sums = path.join(f.kit, 'SHA256SUMS');
        if (fault === 'missing-other') fs.unlinkSync(arm);
        if (fault === 'missing-manifest') fs.unlinkSync(sums);
        if (fault === 'incomplete-manifest') fs.writeFileSync(sums, fs.readFileSync(sums, 'utf8').split('\n')[0] + '\n');
        if (fault.startsWith('tampered-') || fault === 'changed-manifest') {
            const file = fault === 'tampered-other' ? arm : amd, bytes = fs.readFileSync(file); bytes[999] ^= 1; fs.writeFileSync(file, bytes);
            if (fault === 'changed-manifest') fs.writeFileSync(sums, fs.readFileSync(sums, 'utf8').replace(/^[0-9a-f]{64}/, sha(bytes)));
        }
        if (fault === 'symlink') { fs.unlinkSync(amd); fs.symlinkSync(path.join(kitSource, 'cc-agent-linux-amd64'), amd); }
        assert.equal((await f.run()).success, false); f.unchanged();
        assert.equal(f.calls.length, fault === 'unknown-architecture' ? 1 : fault === 'wire' ? 2 : 0);
    });
}

test('lost replacement acknowledgement never retries or starts the service', { skip: !kitSource }, async t => {
    const f = fixture(t, 'x86_64', 'lost-ack'); f.populate(); const result = await f.run();
    assert.equal(result.success, false); assert.equal(f.calls.length, 2); assert.deepEqual(f.late, []);
    // The rename really happened; do not report a confirmed rollback on this outcome.
    assert.equal(sha(fs.readFileSync(f.target)), sha(fs.readFileSync(path.join(kitSource, 'cc-agent-linux-amd64'))));
});
