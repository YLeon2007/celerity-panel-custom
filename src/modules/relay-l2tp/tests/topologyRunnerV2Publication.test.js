'use strict';
// Real rendered shell/file operations in disposable local roots. Remote/root
// ownership and config-directory setup are modeled, never physical acceptance.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { TopologyRunnerBootstrapper } = require('../services/topologyRunnerBootstrapper');
const V2 = '/usr/local/bin/celerity-topology-node-runner-v2';
const OLD = '/usr/local/bin/celerity-topology-node-runner';
const UPLOAD = '/usr/local/bin/.celerity-topology-node-runner-v2.upload';
const NEXT = '/usr/local/bin/.celerity-topology-node-runner-v2.next';
const SOURCE = fs.readFileSync(path.join(__dirname, '../node-artifacts/topology/runner.sh'));
const SENTINEL = Buffer.from('foreign existing bytes\n');
function fixture(t, { race = null, mode = 0o750, existing = null } = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'v2-publish-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const local = fixed => path.join(root, fixed.slice(1));
    fs.mkdirSync(path.dirname(local(V2)), { recursive: true });
    fs.writeFileSync(local(OLD), SENTINEL, { mode: 0o750 });
    const oldIdentity = fs.statSync(local(OLD));
    if (existing === 'directory') fs.mkdirSync(local(V2));
    else if (existing === 'symlink') fs.symlinkSync(local(OLD), local(V2));
    else if (existing === 'dangling') fs.symlinkSync(local('/absent'), local(V2));
    else if (existing) { fs.writeFileSync(local(V2), existing === 'exact' ? SOURCE : SENTINEL); fs.chmodSync(local(V2), mode); }
    const commands = []; let uploads = 0;
    const nodeSSH = {
        async exec(command) {
            commands.push(command);
            assert.ok(!command.includes(OLD) || command.includes(V2));
            if (command.startsWith('/usr/bin/install -d')) return { code: 0, stdout: '', stderr: '' }; // modeled remote config setup
            let rendered = command.replaceAll('/usr/local/bin/', local('/usr/local/bin/'));
            if (race && command.includes('/usr/bin/mv ')) {
                // Inject at the actual publication syscall boundary, after any
                // product prechecks. GNU mv -n may return zero without moving.
                const wrapper = path.join(root, 'mv-race');
                fs.writeFileSync(wrapper, `#!/bin/sh\nprintf '%s\\n' 'foreign existing bytes' > '${local(V2)}'\nexec /usr/bin/mv "$@"\n`, { mode: 0o700 });
                rendered = rendered.replace('/usr/bin/mv ', `${wrapper} `);
            }
            const result = spawnSync('/bin/sh', ['-c', rendered], { encoding: 'utf8' });
            return { code: result.status, stdout: result.stdout.replaceAll(root + '/', '/'), stderr: result.stderr };
        },
        async writeFile(remote, bytes) {
            uploads++;
            assert.equal(remote, UPLOAD); assert.deepEqual(bytes, SOURCE);
            fs.writeFileSync(local(remote), bytes);
        },
    };
    const run = () => new TopologyRunnerBootstrapper({ nodeSSH, target: 'test', hostIdentity: 'test.infograd.online', role: 'portal' }).ensureRunner();
    function oldUnchanged() {
        assert.deepEqual(fs.readFileSync(local(OLD)), SENTINEL);
        const now = fs.statSync(local(OLD));
        for (const key of ['dev', 'ino', 'mode', 'mtimeMs', 'ctimeMs']) assert.equal(now[key], oldIdentity[key], key);
    }
    return { run, local, commands, uploads: () => uploads, oldUnchanged };
}

test('actual rendered V2 shell publishes missing target and reuses exact bytes/mode without old-path mutation', async t => {
    for (const existing of [null, 'exact']) {
        const f = fixture(t, { existing });
        assert.equal((await f.run()).changed, !existing);
        assert.deepEqual(fs.readFileSync(f.local(V2)), SOURCE);
        assert.equal(fs.statSync(f.local(V2)).mode & 0o777, 0o750);
        assert.equal(f.uploads(), existing ? 0 : 1);
        assert.equal(fs.existsSync(f.local(UPLOAD)), false);
        assert.equal(fs.existsSync(f.local(NEXT)), false);
        f.oldUnchanged();
    }
});

test('actual V2 inspection refuses foreign bytes, mode, directories and symlinks before upload or config writes', async t => {
    for (const [existing, mode] of [['foreign', 0o750], ['exact', 0o755], ['directory', 0o750], ['symlink', 0o750], ['dangling', 0o750]]) {
        const f = fixture(t, { existing, mode });
        await assert.rejects(f.run(), { code: 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE' });
        assert.equal(f.uploads(), 0, existing);
        assert.equal(f.commands.length, 1, existing);
        if (existing === 'foreign') assert.deepEqual(fs.readFileSync(f.local(V2)), SENTINEL);
        if (existing === 'exact') assert.equal(fs.statSync(f.local(V2)).mode & 0o777, mode);
        f.oldUnchanged();
    }
});

test('existing V2 stages refuse before any upload or directory write and remain untouched', async t => {
    for (const fixed of [UPLOAD, NEXT]) {
        const f = fixture(t);
        fs.writeFileSync(f.local(fixed), SENTINEL);
        await assert.rejects(f.run(), { code: 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE' });
        assert.equal(f.uploads(), 0); assert.equal(f.commands.length, 1);
        assert.deepEqual(fs.readFileSync(f.local(fixed)), SENTINEL);
        f.oldUnchanged();
    }
});

test('actual mv publication refuses a racing foreign target even when no-clobber skip exits zero and retains stage', async t => {
    const f = fixture(t, { race: true });
    await assert.rejects(f.run(), { code: 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE' });
    assert.deepEqual(fs.readFileSync(f.local(V2)), SENTINEL);
    assert.deepEqual(fs.readFileSync(f.local(NEXT)), SOURCE);
    assert.deepEqual(fs.readFileSync(f.local(UPLOAD)), SOURCE);
    f.oldUnchanged();
});
