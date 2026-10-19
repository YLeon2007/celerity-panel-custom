'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');
const runner = path.join(__dirname, '../node-artifacts/topology/runner.sh');
const content = '{"inbounds":[],"outbounds":[]}\n';
const candidateHash = `sha256:${createHash('sha256').update(content).digest('hex')}`;
const base = { operationId: 'op-1', nodeId: 'node-1', candidateHash, backupId: 'backup-1', targetProfile: 'xray-main', executionContext: 'test.infograd.online', attemptId: 'attempt-1', generation: 'generation-1', predecessorGeneration: 'none' };
function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'topology-fence-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    function put(file, text, mode = 0o600) {
        const target = path.join(root, file);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, text, { mode });
    }
    put('proc/sys/kernel/random/boot_id', 'boot-1\n');
    put('usr/local/etc/xray/config.json', '{"old":true}\n');
    fs.mkdirSync(path.join(root, 'usr/local/share/xray'), { recursive: true });
    fs.mkdirSync(path.join(root, 'var/lib'), { recursive: true });
    put('usr/local/bin/xray', '#!/bin/bash\nexit 0\n', 0o700);
    put('usr/bin/systemctl', `#!/bin/bash
set -eu
root="$CELERITY_TOPOLOGY_ROOT"
printf '%s\\n' "$*" >> "$root/systemctl.log"
case "$1" in
restart|stop)
  touch "$root/started"
  while [[ -e "$root/hold" ]]; do sleep 0.02; done
  [[ ! -e "$root/fail-job" ]] || exit 1
  ;;
show)
  if [[ -e "$root/pending-job" ]]; then printf 'Job=42\\n';
  elif [[ -e "$root/stopped" ]]; then printf 'Job=0\\nActiveState=inactive\\nSubState=dead\\n';
  else printf 'Job=0\\nActiveState=active\\nSubState=running\\n'; fi
  ;;
is-active) exit 0 ;;
*) exit 64 ;;
esac
`, 0o700);
    function args(command, overrides = {}) {
        const plan = { ...base, commandId: `${command}-1`, ...overrides };
        const names = { operationId: 'operation-id', nodeId: 'node-id', candidateHash: 'candidate-hash', backupId: 'backup-id', targetProfile: 'target-profile', executionContext: 'execution-context', attemptId: 'attempt-id', generation: 'generation', predecessorGeneration: 'predecessor-generation', commandId: 'command-id' };
        const result = ['--command', command];
        for (const [key, name] of Object.entries(names)) result.push(`--${name}`, plan[key]);
        if (command === 'verify') result.push('--checks', Buffer.from('[]').toString('base64url'));
        return result;
    }
    const env = { ...process.env, CELERITY_TOPOLOGY_ROOT: root };
    function run(command, overrides = {}, input = content) {
        return spawnSync('bash', [runner, ...args(command, overrides)], { env, input, encoding: 'utf8' });
    }
    function ok(command, overrides = {}) {
        const result = run(command, overrides);
        assert.equal(result.status, 0, result.stderr);
        return JSON.parse(result.stdout);
    }
    return { root, put, args, env, run, ok };
}
test('runner refuses the old unfenced protocol before any config or service effect', t => {
    const f = fixture(t);
    const result = spawnSync('bash', [runner, '--command', 'prepare', '--operation-id', base.operationId, '--node-id', base.nodeId, '--candidate-hash', candidateHash, '--backup-id', base.backupId, '--target-profile', base.targetProfile], { env: f.env, input: content, encoding: 'utf8' });
    assert.notEqual(result.status, 0, 'unfenced prepare was accepted');
    assert.match(result.stderr, /FENCE_REQUIRED/);
    assert.equal(fs.existsSync(path.join(f.root, 'systemctl.log')), false);
});
test('prepare completion is durably bound to attempt, generation and command', t => {
    const f = fixture(t);
    const receipt = f.ok('prepare');
    assert.equal(receipt.generation, base.generation);
    assert.equal(receipt.attemptId, base.attemptId);
    assert.equal(receipt.commandId, 'prepare-1');
    assert.equal(receipt.completion, 'completed');
    assert.equal(receipt.phase, 'prepared');
    assert.equal(receipt.terminal, false);
    assert.equal(receipt.ownershipRetained, true);
    const journal = JSON.parse(fs.readFileSync(path.join(f.root, 'var/lib/celerity/topology/fences/xray-main/journal.json')));
    assert.equal(journal.generations[base.generation].commands['prepare-1'].state, 'completed');
});

test('close durably seals a verified generation and exact terminal status cannot authorize delayed mutation', t => {
    const f = fixture(t);
    f.ok('prepare');
    const committed = f.ok('commit');
    assert.equal(committed.systemdJob, 'completed');
    assert.equal(committed.serviceState, 'active:running');
    f.ok('verify');
    const closed = f.ok('close');
    assert.equal(closed.terminal, true);
    assert.equal(closed.phase, 'closed');
    assert.equal(closed.terminalOutcome, 'verified');
    assert.equal(closed.ownershipRetained, true, 'runner completion never grants classic ownership or DB release');
    assert.deepEqual(f.ok('status', { commandId: 'close-1' }), { ...closed, command: 'status' });
    const before = fs.readFileSync(path.join(f.root, 'systemctl.log'), 'utf8');
    for (const command of ['prepare', 'commit', 'rollback']) {
        const result = f.run(command, { commandId: `delayed-${command}` });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /GENERATION_CLOSED/);
    }
    assert.equal(fs.readFileSync(path.join(f.root, 'systemctl.log'), 'utf8'), before);
});

test('terminal cancellation arriving before prepare seals its generation without service effects', t => {
    const f = fixture(t);
    assert.equal(f.ok('close').terminalOutcome, 'cancelled');
    assert.match(f.run('prepare').stderr, /GENERATION_CLOSED/);
    assert.equal(fs.existsSync(path.join(f.root, 'systemctl.log')), false);
});

test('successor requires exact closed predecessor and stale generations or command IDs never execute again', t => {
    const f = fixture(t);
    f.ok('prepare');
    assert.match(f.run('prepare').stderr, /COMMAND_REUSE/);
    assert.match(f.run('commit', { attemptId: 'foreign-attempt' }).stderr, /FENCE_BINDING_MISMATCH/);
    assert.match(f.run('commit', { executionContext: 'lm1.infograd.online' }).stderr, /FENCE_BINDING_MISMATCH/);
    const next = { operationId: 'op-2', backupId: 'backup-2', generation: 'generation-2', commandId: 'prepare-2' };
    assert.match(f.run('prepare', next).stderr, /OWNERSHIP_RETAINED/);
    f.ok('close');
    assert.match(f.run('prepare', next).stderr, /STALE_PREDECESSOR/);
    assert.equal(f.ok('prepare', { ...next, predecessorGeneration: base.generation }).phase, 'prepared');
    assert.match(f.run('rollback', { commandId: 'old-rollback' }).stderr, /GENERATION_CLOSED/);
    assert.match(f.run('commit', { ...next, predecessorGeneration: base.generation, commandId: 'prepare-1' }).stderr, /COMMAND_REUSE/);
});

async function waitUntil(predicate, label) {
    const deadline = Date.now() + 5000;
    while (!predicate()) {
        assert.ok(Date.now() < deadline, `timed out: ${label}`);
        await new Promise(resolve => setTimeout(resolve, 15));
    }
}
function launch(f, command, overrides = {}) {
    const child = spawn('bash', [runner, ...f.args(command, overrides)], { env: f.env, stdio: ['pipe', 'pipe', 'pipe'] });
    const result = new Promise(resolve => {
        let stdout = '', stderr = '';
        child.stdout.on('data', data => { stdout += data; });
        child.stderr.on('data', data => { stderr += data; });
        child.on('exit', (code, signal) => resolve({ code, signal, stdout, stderr }));
    });
    child.stdin.end(content);
    return { child, result };
}
test('local RPC timeout does not cancel remote writer: exclusion remains until exact remote completion', async t => {
    const f = fixture(t);
    f.ok('prepare');
    f.put('hold', '');
    const { child, result } = launch(f, 'commit');
    t.after(() => { fs.rmSync(path.join(f.root, 'hold'), { force: true }); child.kill(); });
    await waitUntil(() => fs.existsSync(path.join(f.root, 'started')), 'remote restart entered');
    // Simulated RPC gives up without killing the remote process.
    const rpc = await Promise.race([result, new Promise(resolve => setTimeout(() => resolve('local-timeout'), 30))]);
    assert.equal(rpc, 'local-timeout');
    for (const command of ['commit', 'rollback', 'close', 'status']) {
        const refused = f.run(command, { commandId: command === 'status' ? 'commit-1' : `racing-${command}` });
        assert.match(refused.stderr, /COMMAND_IN_FLIGHT/);
        assert.equal(JSON.parse(refused.stderr).ownershipRetained, true);
    }
    fs.unlinkSync(path.join(f.root, 'hold'));
    assert.equal((await result).code, 0);
    const readback = f.ok('status', { commandId: 'commit-1' });
    assert.equal(readback.completedCommand, 'commit');
    assert.equal(readback.systemdJob, 'completed');
    assert.equal(readback.terminal, false);
    f.ok('verify'); f.ok('close');
});
test('supervisor death does not free child execution and orphaned running journal remains unknown after child exit', async t => {
    const f = fixture(t);
    f.ok('prepare'); f.put('hold', '');
    const { child, result } = launch(f, 'commit');
    t.after(() => { fs.rmSync(path.join(f.root, 'hold'), { force: true }); child.kill(); });
    await waitUntil(() => fs.existsSync(path.join(f.root, 'started')), 'child restart entered');
    child.kill('SIGKILL'); await result;
    assert.match(f.run('rollback').stderr, /COMMAND_IN_FLIGHT/);
    fs.unlinkSync(path.join(f.root, 'hold'));
    await waitUntil(() => !f.run('status', { commandId: 'commit-1' }).stderr.includes('COMMAND_IN_FLIGHT'), 'orphan exited');
    for (const command of ['rollback', 'close', 'status']) {
        const refused = f.run(command, { commandId: command === 'status' ? 'commit-1' : command + '-after-death' });
        assert.match(refused.stderr, /UNKNOWN_COMMAND_OUTCOME/);
        assert.equal(JSON.parse(refused.stderr).ownershipRetained, true);
    }
});
test('profiles have independent exclusion without silently adopting legacy receipts', t => {
    const f = fixture(t); f.ok('prepare');
    f.put('usr/local/etc/xray-bridge/config.json', '{"oldBridge":true}\n');
    const bridge = { targetProfile: 'xray-bridge', commandId: 'bridge-prepare' };
    assert.equal(f.ok('prepare', bridge).phase, 'prepared');
    const logBefore = fs.existsSync(path.join(f.root, 'systemctl.log'));
    assert.equal(logBefore, false);
});
test('rollback restores exact snapshot and closes with an explicit rolledback terminal outcome', t => {
    const f = fixture(t); f.ok('prepare'); f.ok('commit'); f.ok('verify');
    assert.equal(f.ok('rollback').serviceState, 'active:running');
    assert.equal(fs.readFileSync(path.join(f.root, 'usr/local/etc/xray/config.json'), 'utf8'), '{"old":true}\n');
    assert.equal(f.ok('close').terminalOutcome, 'rolledback');
    assert.match(f.run('commit', { commandId: 'late-commit' }).stderr, /GENERATION_CLOSED/);
});
test('absent-config rollback waits for stopped systemd job and terminal readback remains exact', t => {
    const f = fixture(t); fs.unlinkSync(path.join(f.root, 'usr/local/etc/xray/config.json'));
    f.ok('prepare'); f.ok('commit'); f.ok('verify'); f.put('stopped', '');
    assert.equal(f.ok('rollback', { commandId: '000-rollback' }).serviceState, 'inactive:dead');
    assert.equal(fs.existsSync(path.join(f.root, 'usr/local/etc/xray/config.json')), false);
    assert.equal(f.ok('close').terminalOutcome, 'rolledback');
});
test('factory, typed transport, real runner and terminal readback work together in a fake root', async t => {
    const f = fixture(t);
    const { TopologyNodeTransportFactory } = require('../services/topologyNodeTransportFactory');
    const calls = [];
    const factory = new TopologyNodeTransportFactory({ executionContext: base.executionContext, nodeExecutionResolver: {
        resolve: async () => ({ exec: async (command, options) => {
            calls.push(command);
            const result = spawnSync('bash', [runner, ...command.split(' ').slice(1)], { env: f.env, input: options?.stdin || '', encoding: 'utf8' });
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        } }),
    } });
    const transport = await factory.create({ nodeId: base.nodeId, role: 'portal' });
    await transport.prepare({ ...base, commandId: 'prepare-1', artifact: { id: 'xray-config', content } });
    await transport.commit({ ...base, commandId: 'commit-1' });
    await transport.verify({ ...base, commandId: 'verify-1', checks: [] });
    const closed = await transport.close({ ...base, commandId: 'close-1' });
    assert.deepEqual(await transport.status({ ...base, commandId: 'close-1', completedCommand: 'close' }), { ...closed, command: 'status' });
    assert.equal(calls.length, 5);
});
test('oversized otherwise valid journal is retained rather than read or garbage-collected', t => {
    const f = fixture(t); f.ok('prepare');
    const file = path.join(f.root, 'var/lib/celerity/topology/fences/xray-main/journal.json');
    fs.appendFileSync(file, ' '.repeat(4194304));
    assert.match(f.run('commit').stderr, /JOURNAL_CAPACITY_RETAINED/);
    assert.equal(fs.existsSync(path.join(f.root, 'systemctl.log')), false);
});

test('missing journal after prior use is unknown rather than a fresh fence', t => {
    const f = fixture(t);
    f.ok('close');
    fs.unlinkSync(path.join(f.root, 'var/lib/celerity/topology/fences/xray-main/journal.json'));
    assert.match(f.run('prepare').stderr, /JOURNAL_UNCERTAIN/);
});
test('reboot, malformed and unfinished journals cannot recover or release automatically', async t => {
    for (const mode of ['reboot', 'truncated', 'unfinished']) await t.test(mode, st => {
        const f = fixture(st); f.ok('prepare');
        if (mode === 'reboot') f.put('proc/sys/kernel/random/boot_id', 'boot-2\n');
        if (mode === 'truncated') f.put('var/lib/celerity/topology/fences/xray-main/journal.json', '{');
        if (mode === 'unfinished') f.put('var/lib/celerity/topology/fences/xray-main/journal.next', '{}');
        for (const command of ['commit', 'rollback', 'close', 'status']) {
            const refused = f.run(command);
            assert.match(refused.stderr, /BOOT_CHANGED_UNCERTAIN|JOURNAL_UNCERTAIN/);
            assert.equal(JSON.parse(refused.stderr).ownershipRetained, true);
        }
        assert.equal(fs.existsSync(path.join(f.root, 'systemctl.log')), false);
    });
});
test('nonzero restart or still-pending systemd job retains the generation with unknown outcome', async t => {
    for (const failure of ['fail-job', 'pending-job']) await t.test(failure, st => {
        const f = fixture(st); f.ok('prepare'); f.put(failure, '');
        const failed = f.run('commit');
        assert.match(failed.stderr, /COMMAND_OUTCOME_UNKNOWN|SYSTEMD_COMPLETION_UNPROVEN/);
        assert.match(f.run('close').stderr, /UNKNOWN_COMMAND_OUTCOME/);
        assert.match(f.run('rollback').stderr, /UNKNOWN_COMMAND_OUTCOME/);
        assert.match(f.run('status', { commandId: 'commit-1' }).stderr, /UNKNOWN_COMMAND_OUTCOME/);
    });
});
