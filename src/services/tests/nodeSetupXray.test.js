'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { test } = require('node:test');

const secret = 'fixture-secret-not-for-logs';
const configBytes = JSON.stringify({ privateKey: secret, padding: 'ж'.repeat(80000) });
const configPath = '/usr/local/etc/xray/config.json';
const unitPath = '/etc/systemd/system/xray.service';
const baseUnit = '[Service]\nUser=nobody\nGroup=custom\nExecStart=/usr/local/bin/xray run -config ' + configPath + '\n';
const stockSingleConfig = '[Service]\nExecStart=\nExecStart=/usr/local/bin/xray run -config ' + configPath + '\n';
const accessDrop = '90-celerity-config-access.conf';
const logsDrop = '90-celerity-logs-directory.conf';
const mode = file => fs.statSync(file).mode & 0o7777;

// Real setup entry point and SSH channel helpers; no SSH socket. Mutations run
// through the actual command in a temp tree, with fixture systemd, NSS and ownership.
function fixture(t, options = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'xray-setup-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const at = name => path.join(root, name);
    const dir = at('/usr/local/etc/xray');
    const units = at('/etc/systemd/system');
    const unit = at(unitPath);
    const conf = at(configPath);
    const dropdir = `${unit}.d`;
    const journal = at('calls');
    fs.mkdirSync(dir, { recursive: true });
    fs.chmodSync(dir, 0o750);
    fs.mkdirSync(dropdir, { recursive: true });
    // Match system unit-directory permissions independently of the runner's umask.
    fs.chmodSync(units, 0o755);
    fs.chmodSync(dropdir, 0o755);
    const adminDropIn = path.join(dropdir, '10-admin.conf');
    fs.writeFileSync(adminDropIn, '# fixture admin override\n[Service]\nUser=nobody\nGroup=custom\n');
    if (!options.noUnit) fs.writeFileSync(unit, baseUnit);
    if (options.stock) fs.writeFileSync(path.join(dropdir, '10-donot_touch_single_conf.conf'), stockSingleConfig);
    fs.writeFileSync(path.join(dir, 'unrelated'), 'unchanged', { mode: 0o600 });
    fs.writeFileSync(journal, '');
    const bin = at('bin');
    fs.mkdirSync(bin);
    const writeTool = (name, body) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\nset -eu\n' + body, { mode: 0o755 });
    writeTool('getent', `
case "$*" in
    'group xray') [[ "$FIXTURE_NO_XRAY" == 0 ]] || exit 2; echo 'xray:x:401:' ;;
    'hosts node.invalid') echo '192.0.2.5 node.invalid' ;;
    'group custom'|'group 402') echo 'custom:x:402:' ;;
    'passwd nobody') echo 'nobody:x:65534:402::/:/usr/sbin/nologin' ;;
    *) exit 2 ;;
esac`);
    // The prescribed unshare maps one UID/GID. Record the selected numeric GID
    // then perform the actual operation on the mapped GID; modes remain real.
    writeTool('chgrp', `
[[ "$1" == -- ]] && shift
printf 'chgrp %s\\n' "$1" >> "$FIXTURE_CALLS"
if [[ "$2" == "$FIXTURE_DIR" ]]; then echo "$1" > "$FIXTURE_DIR_GID"; fi
if [[ "$2" == "$FIXTURE_DIR/config.json" ]]; then echo "$1" > "$FIXTURE_CONFIG_GID"; fi
shift
exec /usr/bin/chgrp -- "$(id -g)" "$@"`);
    writeTool('stat', `
if [[ "$*" == "-c %g:%a -- $FIXTURE_DIR" ]]; then
    printf '%s:%s\\n' "$(cat "$FIXTURE_DIR_GID")" "$(/usr/bin/stat -c %a -- "$FIXTURE_DIR")"
elif [[ "$*" == "-c %u:%h:%g:%a -- $FIXTURE_DIR/config.json" ]]; then
    printf '%s:%s:%s\\n' "0:$(/usr/bin/stat -c %h -- "$FIXTURE_DIR/config.json")" "$(cat "$FIXTURE_CONFIG_GID")" "$(/usr/bin/stat -c %a -- "$FIXTURE_DIR/config.json")"
elif [[ "$2" == '%u:%a' || "$2" == '%u:%a:%h' ]]; then
    [[ "$(/usr/bin/stat -c %u -- "$4")" == "$(id -u)" ]]
    exec /usr/bin/stat -c "0:\${2#%u:}" -- "$4"
else exec /usr/bin/stat "$@"; fi`);
    writeTool('chown', `
[[ "$1" == -- ]] && shift
printf 'chown %s\\n' "$1" >> "$FIXTURE_CALLS"
shift
exec /usr/bin/chown -- "$(id -u):$(id -g)" "$@"`);
    writeTool('setpriv', `
echo access-check >> "$FIXTURE_CALLS"
[[ "$FIXTURE_MODE" != access-denied ]]
gid=401; if [[ "$FIXTURE_NO_XRAY" == 1 ]]; then gid=402; fi
[[ "$1 $2 $3 $4 $5 $6 $7" == "--reuid 65534 --regid 402 --groups $gid --" ]]
[[ "$(<"$FIXTURE_DIR_GID")" == "$gid" && "$(/usr/bin/stat -c %a -- "$FIXTURE_DIR")" == 750 ]]
if [[ -e "$FIXTURE_DIR/config.json" ]]; then
    [[ "$(<"$FIXTURE_CONFIG_GID")" == "$gid" ]];
    (( (8#$(/usr/bin/stat -c %a -- "$FIXTURE_DIR/config.json") & 0040) != 0 ))
fi`);
    if (options.realDac) {
        for (const tool of ['chgrp', 'stat', 'chown', 'setpriv']) fs.unlinkSync(path.join(bin, tool));
        fs.chmodSync(root, 0o711);
        fs.chownSync(dir, 0, 401);
    }
    writeTool('sleep', `printf 'sleep %s\\n' "$*" >> "$FIXTURE_CALLS"`);
    writeTool('systemctl', `
while [[ "$1" == --* ]]; do shift; done
printf '%s\\n' "$1" >> "$FIXTURE_CALLS"
case "$1" in
    daemon-reload|enable) exit 0 ;;
    restart)
        [[ "$FIXTURE_MODE" != restart-fails ]] || { echo '${secret}' >&2; exit 1; }
        [[ "$(stat -c %a "$FIXTURE_DIR")" == 750 && "$(stat -c %a "$FIXTURE_DIR/config.json")" == 640 ]]
        if [[ "$FIXTURE_NO_XRAY" == 0 ]]; then
            [[ "$(cat "$FIXTURE_DIR_GID")" == 401 ]]
            grep -qs '^SupplementaryGroups=xray$' "$FIXTURE_UNIT".d/*
        else [[ "$(cat "$FIXTURE_DIR_GID")" == 402 ]]; fi ;;
    show)
        args="$*"
        if [[ "$args" == *NRestarts* ]]; then
            n=$(grep -c '^sample$' "$FIXTURE_CALLS" || :)
            echo sample >> "$FIXTURE_CALLS"
            [[ "$FIXTURE_MODE" != unavailable ]] || { echo '${secret}' >&2; exit 1; }
            counter=7 pid=122 state=active sub=running load=loaded
            case "$FIXTURE_MODE" in
                inactive) state=failed; sub=failed ;;
                exited) sub=exited ;;
                no-pid) pid=0 ;;
                not-loaded) load=not-found ;;
                loop) [[ "$n" -lt 6 ]] || counter=8 ;;
                late-loop) [[ "$n" -lt 9 ]] || counter=8 ;;
                counter-decreases) [[ "$n" == 0 ]] || counter=0 ;;
                pid-change) [[ "$n" == 0 ]] || pid=123 ;;
                bad-counter) counter='7broken' ;;
                overflow) counter=4294967296 ;;
                duplicate) echo NRestarts=7 ;;
                empty-counter) counter='' ;;
                missing-counter) ;;
            esac
            printf 'MainPID=%s\\nSubState=%s\\nLoadState=%s\\nActiveState=%s\\n' "$pid" "$sub" "$load" "$state"
            if [[ "$FIXTURE_MODE" != missing-counter ]]; then printf 'NRestarts=%s\\n' "$counter"; fi
        elif [[ "$args" == *LoadState* ]]; then
            if [[ -f "$FIXTURE_UNIT" ]]; then echo loaded; else echo not-found; exit 1; fi
        elif [[ "$args" == *ExecStart* ]]; then
            argv=$(grep -sh '^ExecStart=.' "$FIXTURE_UNIT" "$FIXTURE_UNIT".d/*.conf | tail -n 1)
            argv="\${argv#ExecStart=}"
            canonical=/usr/local/etc/xray/config.json
            argv="\${argv/" $canonical"/" $FIXTURE_CONFIG_ARG"}"
            echo "{ path=/usr/local/bin/xray ; argv[]=$argv ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        elif [[ "$args" == *DropInPaths* ]]; then
            printf '%s ' "$FIXTURE_UNIT".d/*.conf
        elif [[ "$args" == *LogsDirectory* ]]; then
            printf 'other-app'
            if [[ "$FIXTURE_MODE" != later-logs-reset ]] && grep -qs '^LogsDirectory=xray$' "$FIXTURE_UNIT" "$FIXTURE_UNIT".d/*.conf; then printf ' xray'; fi
            printf '\\n'
        elif [[ "$args" == *DynamicUser* ]]; then echo no
        elif [[ "$args" == *SupplementaryGroups* ]]; then
            printf audit
            if [[ "$FIXTURE_MODE" != later-reset ]] && grep -qs '^SupplementaryGroups=xray$' "$FIXTURE_UNIT".d/*; then printf ' xray'; fi
            printf '\\n'
        elif [[ "$args" == *User* ]]; then echo nobody
        elif [[ "$args" == *Group* ]]; then echo custom
        else exit 1
        fi ;;
    reload) exit 0 ;;
    status|is-active) echo '${secret}'; exit 0 ;;  # legacy bug: final command masks restart failure
    *) exit 99 ;;
esac`);
    writeTool('journalctl', `echo '${secret}'; exit 0`);
    const home = at('home');
    fs.mkdirSync(path.join(home, '.acme.sh', 'node.invalid_ecc'), { recursive: true });
    fs.writeFileSync(path.join(home, '.acme.sh', 'node.invalid_ecc', 'node.invalid.cer'), 'fixture');
    writeTool('ss', 'exit 0');
    writeTool('crontab', 'exit 0');
    for (const denied of ['curl', 'apt-get', 'yum', 'apk']) writeTool(denied, 'exit 99');
    fs.writeFileSync(path.join(home, '.acme.sh', 'acme.sh'), `#!/bin/bash
set -eu
if [[ "$1" == --set-default-ca ]]; then exit 0; fi
[[ "$1" == --install-cert ]] || exit 99
while (( $# )); do
    case "$1" in
        --key-file|--fullchain-file) printf '%s' '${secret}' > "$2"; shift ;;
        --reloadcmd) printf '%s' "$2" > "$HOME/acme-renewal"; /bin/sh -c "$2"; shift ;;
    esac
    shift
done`, { mode: 0o755 });
    const env = { ...process.env, HOME: home, PATH: `${bin}:/usr/bin:/bin`, FIXTURE_CALLS: journal, FIXTURE_UNIT: unit,
        FIXTURE_DIR: dir, FIXTURE_DIR_GID: at('gid'), FIXTURE_CONFIG_ARG: options.configArg || conf,
        FIXTURE_CONFIG_GID: at('config-gid'),
        FIXTURE_NO_XRAY: options.noXray ? '1' : '0', FIXTURE_MODE: options.scenario || 'normal' };
    fs.writeFileSync(env.FIXTURE_CONFIG_GID, '0\n');
    fs.writeFileSync(env.FIXTURE_DIR_GID, options.dirGid || '0');
    const logs = [];
    const translate = cmd => cmd.replaceAll('/usr/local/etc/xray', dir)
        .replaceAll('/etc/systemd/system', units);
    let connections = 0, execCount = 0;
    class FakeClient extends EventEmitter {
        connect() { this.agentPhase = ++connections === 2 && options.withAgent; queueMicrotask(() => this.emit('ready')); }
        end() {}
        sftp(callback) {
            if (this.agentPhase) return callback(null, { createWriteStream: () => new (require('node:stream').Writable)({
                write: (_chunk, _enc, done) => done(),
            }) });
            callback(null, { createWriteStream: target => fs.createWriteStream(translate(target)) });
        }
        exec(command, callback) {
            execCount++;
            assert.equal(command.includes(secret), false, 'secrets must not appear in SSH argv');
            let local = command;
            if (this.agentPhase && !command.includes('NRestarts')) {
                local = command.includes('systemctl restart cc-agent') ? "printf 'OK: cc-agent running\\n'" : ':';
            } else if (command.includes('Installing Xray-core')) {
                // Exercise the existing SSH output boundary, never the real installer.
                local = 'printf "%s" "$FIXTURE_INSTALL_STDOUT"; printf "%s" "$FIXTURE_INSTALL_STDERR" >&2';
            } else if (command.includes('Opening firewall ports')) {
                local = ':';
            } else if (!(options.acme && command.includes('--install-cert'))) {
                assert.doesNotMatch(command, /curl |apt-get|github\.com|iptables|modprobe/);
            }
            const child = spawn('/bin/sh', ['-c', translate(local)], { env, cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });
            const channel = new EventEmitter();
            channel.stderr = child.stderr;
            channel.write = chunk => child.stdin.write(options.truncate ? chunk.subarray(0, 1) : chunk);
            channel.end = callback => child.stdin.end(callback);
            channel.destroy = () => child.kill();
            child.stdin.on('drain', () => channel.emit('drain'));
            child.stdin.on('error', error => channel.emit('error', error));
            child.stdout.on('data', chunk => channel.emit('data', chunk));
            child.on('close', code => channel.emit('close', code));
            callback(null, channel);
        }
    }
    const original = Module._load;
    const source = require.resolve('../nodeSetup');
    Module._load = function (id, parent, isMain) {
        if (parent?.filename === source) {
            if (id === 'ssh2') return { Client: FakeClient };
            if (id === '../../config') return { PANEL_DOMAIN: 'panel.invalid' };
            if (id === '../utils/logger') return { info: line => logs.push(line), error: line => logs.push(line) };
            if (id === '../models/hyNodeModel') return { updateOne: async () => ({}) };
            if (id === './cryptoService') return { decryptSafe: () => 'fixture' };
            if (id === '../models/settingsModel') return {};
            if (id === './syncService') return { _getUsersForNode: async () => [] };
            if (id === './configGenerator') return {
                generateXrayConfigWithApi: () => {
                    assert.ok(!options.installOnly, 'exitOnly must not generate config');
                    return configBytes;
                },
                generateXraySystemdService: () => baseUnit + 'LogsDirectory=xray\n',
            };
        }
        return original.call(this, id, parent, isMain);
    };
    delete require.cache[source];
    const setup = require(source);
    t.after(() => { Module._load = original; delete require.cache[source]; });
    return { dir, unit, conf, dropdir, adminDropIn, logs, home, env, execCount: () => execCount,
        calls: () => fs.readFileSync(journal, 'utf8').trim().split('\n'),
        fullSetup: () => setup.setupXrayNodeWithAgent({ type: 'xray', ip: '192.0.2.5', port: 8443,
            name: 'fixture', ssh: { password: 'fixture' }, xray: { security: 'none', agentToken: 'fixture', agentTls: false } }),
        run: (opts, xray = { security: 'none' }) => setup.setupXrayNode({ ip: '192.0.2.5', name: 'fixture', port: 8443,
            domain: options.acme ? 'node.invalid' : undefined, ssh: { password: 'fixture' }, xray }, opts) };
}

function noSecrets(f, result) {
    assert.equal(JSON.stringify([result, f.logs]).includes(secret), false, 'no config or raw systemd output');
}

const installed = (version, already = false) =>
    `Done: Xray ${already ? 'already ' : ''}installed (Xray ${version} (Xray, Penetrates Everything.) 676eaf6 (go1.27.3 linux/amd64))`;
for (const [name, stdout, stderr, warn] of [
    ['new install 26.11.9', installed('26.11.9'), '', true],
    ['existing 26.11.10', installed('26.11.10', true), '', true],
    ['26.3.27', installed('26.3.27'), '', false],
    ['no version', 'Done: Xray installed ()', '', false],
    ['unmarked banner', 'Xray 26.11.9', '', false],
    ['non-release suffix', installed('26.11.9-custom'), '', false],
    ['conflicting markers', installed('26.11.9') + '\n' + installed('26.3.27'), '', false],
    ['marker only on stderr', '', installed('26.11.9'), false],
]) {
    test(`setup compatibility notice: ${name}`, async t => {
        const f = fixture(t);
        f.env.FIXTURE_INSTALL_STDOUT = `${secret}\n${stdout}\nDone: Directory /usr/local/etc/xray ready\n`;
        f.env.FIXTURE_INSTALL_STDERR = `${stderr}\n${secret}`;
        const result = await f.run({ restartService: false });
        assert.equal(result.success, true, result.error);
        assert.equal(f.execCount(), 4, 'only install, access, config write and firewall');
        noSecrets(f, result);
        assert.doesNotMatch(JSON.stringify([result.logs, f.logs]), /Penetrates Everything|Done: Xray|676eaf6|\[STDERR\]/);
        const notices = result.logs.filter(line => /REALITY|fingerprint|совместим/i.test(line));
        assert.equal(notices.length, warn ? 1 : 0);
        if (warn) assert.match(notices[0], /⚠.*Xray 26\.11\.x.*набирающей стороне REALITY.*только chrome, firefox и safari\./);
    });
}

// Optional kernel-DAC probe in a private multi-ID user namespace and tmpfs.
if (process.env.C3_XRAY_REAL_DAC === '1') test('kernel enforces Debian xray access before and after setup', async t => {
    const f = fixture(t, { realDac: true, stock: true });
    fs.writeFileSync(f.conf, 'existing fixture', { mode: 0o600 });
    const canRead = group => spawnSync('/usr/bin/setpriv', [
        '--reuid', '65534', '--regid', '402', ...(group ? ['--groups', '401'] : ['--clear-groups']),
        '--', '/usr/bin/head', '-c', '1', f.conf,
    ], { stdio: 'ignore' }).status;
    assert.equal(canRead(false), 1, 'stock nobody cannot open config');
    const result = await f.run({ restartService: false });
    assert.equal(result.success, true, result.error);
    assert.equal(fs.statSync(f.conf).gid, 401);
    assert.equal(mode(f.conf), 0o640);
    assert.equal(mode(f.dir), 0o750);
    assert.match(fs.readFileSync(path.join(f.dropdir, accessDrop), 'utf8'), /^SupplementaryGroups=xray$/m);
    assert.equal(canRead(true), 0, 'service credentials can open the config');
    assert.equal(canRead(false), 1, 'same UID without the service group still cannot');
});

test('Debian layout is private before a deferred restart and existing units are preserved', async t => {
    const f = fixture(t);
    const r = await f.run({ restartService: false });
    assert.equal(r.success, true, r.error);
    assert.equal(r.serviceVerified, false);
    assert.equal(mode(f.dir), 0o750);
    assert.equal(mode(f.conf), 0o640);
    assert.equal(fs.readFileSync(f.conf, 'utf8') === configBytes, true);
    assert.equal(fs.readFileSync(f.unit, 'utf8'), baseUnit);
    assert.match(fs.readFileSync(f.adminDropIn, 'utf8'), /Group=custom/);
    assert.ok(fs.readdirSync(f.dropdir).some(file =>
        fs.readFileSync(path.join(f.dropdir, file), 'utf8').includes('SupplementaryGroups=xray')));
    assert.ok(f.calls().includes('chgrp 401'));
    assert.ok(!f.calls().some(c => /^(restart|enable|sample)$/.test(c)));
    assert.equal(mode(path.join(f.dir, 'unrelated')), 0o600);
    noSecrets(f, r);
});

test('no dedicated group: prepares a missing unit and uses the effective primary group', async t => {
    const f = fixture(t, { noXray: true, noUnit: true });
    const r = await f.run();
    assert.equal(r.success, true, r.error);
    assert.equal(r.serviceVerified, true);
    assert.ok(f.calls().includes('chgrp 402'));
    assert.equal(fs.readdirSync(f.dropdir).length, 1);
    assert.equal(f.calls().filter(c => c === 'sample').length, 7);
    assert.equal(f.calls().filter(c => c === 'sleep 1').length, 6);
    assert.equal(mode(f.conf), 0o640);
    noSecrets(f, r);
});

for (const [scenario, expected] of [
    ['restart-fails', /перезапустить/], ['inactive', /не работает/], ['exited', /не работает/],
    ['no-pid', /не работает/], ['not-loaded', /не работает/], ['loop', /NRestarts.*изменился/],
    ['pid-change', /PID.*изменился/], ['unavailable', /состояние.*systemd/], ['bad-counter', /NRestarts/],
    ['missing-counter', /NRestarts/], ['empty-counter', /NRestarts/], ['duplicate', /NRestarts/],
    ['counter-decreases', /NRestarts.*изменился/], ['overflow', /NRestarts/],
]) {
    test(`normal setup is unsuccessful for ${scenario}`, async t => {
        const f = fixture(t, { scenario });
        const r = await f.run();
        assert.equal(r.success, false);
        assert.match(r.error, expected);
        noSecrets(f, r);
    });
}

test('agent installation followed by a late Xray crash-loop fails setup without another restart', async t => {
    const f = fixture(t, { withAgent: true, scenario: 'late-loop' });
    const result = await f.fullSetup();
    assert.equal(result.success, false);
    assert.equal(result.serviceVerified, false);
    assert.match(result.error, /NRestarts/);
    assert.equal(f.calls().filter(c => c === 'restart').length, 1);
    noSecrets(f, result);
});

test('bridge without a normal unit prepares one but leaves config absent and defers activation', async t => {
    const f = fixture(t, { noUnit: true, installOnly: true });
    const r = await f.run({ exitOnly: true, restartService: false });
    assert.equal(r.success, true, r.error);
    assert.equal(r.serviceVerified, false);
    assert.match(fs.readFileSync(f.unit, 'utf8'), /ExecStart=/);
    assert.equal(fs.existsSync(f.conf), false);
    assert.ok(fs.existsSync(path.join(f.dropdir, accessDrop)));
    assert.ok(!f.calls().some(c => /^(start|restart|reload|enable|sample)$/.test(c)));
});

test('bridge repairs existing main config in place and leaves the cascade sidecar untouched', async t => {
    const f = fixture(t, { installOnly: true, dirGid: '401' }); // root:xray 0750, unit runs as nobody
    const sidecar = `${f.dir}-bridge`;
    fs.mkdirSync(sidecar);
    fs.writeFileSync(path.join(sidecar, 'config.json'), 'sidecar', { mode: 0o600 });
    fs.writeFileSync(f.conf, 'retained', { mode: 0o600 });
    const before = fs.statSync(f.conf);
    const r = await f.run({ exitOnly: true }); // Must defer even with restartService defaulting to true.
    assert.equal(r.success, true, r.error);
    assert.equal(r.serviceVerified, false);
    assert.equal(fs.statSync(f.conf).ino, before.ino);
    assert.equal(fs.readFileSync(f.conf, 'utf8'), 'retained');
    assert.equal(mode(f.conf), 0o640);
    assert.equal(fs.readFileSync(f.env.FIXTURE_CONFIG_GID, 'utf8').trim(), '401');
    assert.equal(fs.readFileSync(f.env.FIXTURE_DIR_GID, 'utf8').trim(), '401');
    assert.match(fs.readFileSync(path.join(f.dropdir, accessDrop), 'utf8'), /^SupplementaryGroups=xray$/m);
    assert.equal(fs.readFileSync(f.unit, 'utf8'), baseUnit);
    assert.equal(fs.readFileSync(path.join(sidecar, 'config.json'), 'utf8'), 'sidecar');
    assert.equal(mode(path.join(sidecar, 'config.json')), 0o600);
    assert.ok(f.calls().includes('access-check'));
    assert.ok(!f.calls().some(c => /^(start|restart|reload|enable|sample)$/.test(c)));
    assert.doesNotMatch(r.logs.join('\n'), /binary only/i);
    const again = await f.run({ exitOnly: true });
    assert.equal(again.success, true, again.error);
    assert.equal(f.calls().filter(c => c === 'chgrp 401').length, 1, 'do not re-group readable paths');
});

test('bridge refuses handoff when the service identity cannot access the prepared paths', async t => {
    const f = fixture(t, { installOnly: true, scenario: 'access-denied' });
    const r = await f.run({ exitOnly: true, restartService: false });
    assert.equal(r.success, false);
    assert.match(r.error, /доступ/);
    assert.equal(fs.existsSync(f.conf), false);
});

for (const type of ['symlink', 'hardlink']) {
    test(`bridge refuses a ${type} at config.json without modifying its target`, async t => {
        const f = fixture(t, { installOnly: true });
        const target = path.join(f.dir, 'unrelated');
        if (type === 'symlink') fs.symlinkSync(target, f.conf);
        else fs.linkSync(target, f.conf);
        const r = await f.run({ exitOnly: true });
        assert.equal(r.success, false);
        assert.match(r.error, /config.json/);
        assert.equal(mode(target), 0o600);
        assert.equal(fs.readFileSync(target, 'utf8'), 'unchanged');
        assert.ok(!f.calls().some(c => /^(start|restart|reload|enable|sample)$/.test(c)));
    });
}

test('normal setup on the stock single-config unit retains LogsDirectory with an additive drop-in', async t => {
    const f = fixture(t, { stock: true });
    assert.equal(fs.existsSync(f.conf), false);
    const xray = { accessLogs: { enabled: true } };
    const r = await f.run({ restartService: false }, xray);
    assert.equal(r.success, true, r.error);
    assert.equal(fs.readFileSync(f.conf, 'utf8'), configBytes);
    assert.equal(fs.readFileSync(f.unit, 'utf8'), baseUnit);
    assert.equal(fs.readFileSync(path.join(f.dropdir, '10-donot_touch_single_conf.conf'), 'utf8'), stockSingleConfig);
    assert.match(fs.readFileSync(path.join(f.dropdir, logsDrop), 'utf8'), /^\[Service\]\nLogsDirectory=xray\n$/m);
    assert.ok(!f.calls().some(c => /^(start|restart|reload|enable|sample)$/.test(c)));
});

test('a later LogsDirectory reset fails without leaving an ineffective managed drop-in', async t => {
    const f = fixture(t, { scenario: 'later-logs-reset' });
    const r = await f.run({ restartService: false });
    assert.equal(r.success, false);
    assert.match(r.error, /LogsDirectory/);
    assert.equal(fs.existsSync(path.join(f.dropdir, logsDrop)), false);
    assert.equal(fs.existsSync(f.conf), false);
});

test('logs drop-in collision is refused without overwriting it or uploading config', async t => {
    const f = fixture(t);
    const drop = path.join(f.dropdir, logsDrop);
    fs.writeFileSync(drop, '[Service]\nLogsDirectory=admin\n');
    const r = await f.run({ restartService: false });
    assert.equal(r.success, false);
    assert.match(r.error, /LogsDirectory/);
    assert.equal(fs.readFileSync(drop, 'utf8'), '[Service]\nLogsDirectory=admin\n');
    assert.equal(fs.existsSync(f.conf), false);
});

test('an administrator-owned same-name drop-in is not changed', async t => {
    const f = fixture(t);
    const drop = path.join(f.dropdir, '90-celerity-config-access.conf');
    fs.writeFileSync(drop, '# custom admin content\n');
    const r = await f.run({ restartService: false });
    assert.equal(r.success, false);
    assert.match(r.error, /drop-in/);
    assert.equal(fs.readFileSync(drop, 'utf8'), '# custom admin content\n');
    assert.equal(fs.existsSync(f.conf), false);
});

test('a later override removing the group fails before config upload', async t => {
    const f = fixture(t, { scenario: 'later-reset' });
    const r = await f.run({ restartService: false });
    assert.equal(r.success, false);
    assert.match(r.error, /drop-in/);
    assert.deepEqual(fs.readdirSync(f.dropdir), ['10-admin.conf']);
    assert.equal(fs.existsSync(f.conf), false);
});

test('a unit reading a different config is preserved and rejected', async t => {
    const f = fixture(t, { configArg: '/foreign/config.json' });
    const r = await f.run();
    assert.equal(r.success, false);
    assert.match(r.error, /не использует управляемый/);
    assert.equal(fs.readFileSync(f.unit, 'utf8'), baseUnit);
    assert.equal(fs.existsSync(f.conf), false);
});

test('incomplete stdin does not replace the existing config or leave a stage', async t => {
    const f = fixture(t, { truncate: true });
    fs.writeFileSync(f.conf, 'old config', { mode: 0o640 });
    const r = await f.run();
    assert.equal(r.success, false);
    assert.match(r.error, /записать config.json/);
    assert.equal(fs.readFileSync(f.conf, 'utf8'), 'old config');
    assert.deepEqual(fs.readdirSync(f.dir), ['config.json', 'unrelated']);
    assert.ok(!f.calls().includes('restart'));
    noSecrets(f, r);
});

test('self-signed TLS generates and reuses a private service-readable pair', async t => {
    const f = fixture(t);
    const tls = { security: 'tls', tlsSource: 'self-signed' };
    const key = path.join(f.dir, 'key.pem');
    const cert = path.join(f.dir, 'cert.pem');
    const first = await f.run({ restartService: false }, tls);
    assert.equal(first.success, true, first.error);
    assert.equal(mode(key), 0o640);
    assert.equal(mode(cert), 0o640);
    assert.ok(f.calls().includes('chown 0:401'));
    const originalKey = fs.readFileSync(key);
    const second = await f.run({ restartService: false }, tls);
    assert.equal(second.success, true, second.error);
    assert.equal(fs.readFileSync(key).equals(originalKey), true);
    assert.ok(!f.calls().some(c => /^(restart|enable|sample)$/.test(c)));
    noSecrets(f, second);
});

test('ACME hook secures the pair without restarting deferred setup; renewal may reload', async t => {
    const f = fixture(t, { acme: true, noXray: true });
    const r = await f.run({ restartService: false }, { security: 'tls', tlsSource: 'acme', acmeEmail: 'fixture@node.invalid' });
    assert.equal(r.success, true, r.error);
    assert.equal(r.serviceVerified, false);
    assert.equal(mode(path.join(f.dir, 'key.pem')), 0o640);
    assert.ok(f.calls().includes('chown 0:402'));
    assert.ok(!f.calls().some(c => /^(restart|reload|enable|sample)$/.test(c)));
    const renew = fs.readFileSync(path.join(f.home, 'acme-renewal'), 'utf8');
    const child = spawn('/bin/sh', ['-c', renew], { env: f.env, stdio: 'ignore' });
    assert.equal(await new Promise(resolve => child.once('close', resolve)), 0);
    assert.equal(f.calls().filter(c => c === 'reload').length, 1);
    noSecrets(f, r);
});
