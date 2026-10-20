'use strict';
// Local fake-root runner only. No SSH, production filesystem or real systemd.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const runner = path.join(__dirname, '../../node-artifacts/topology/runner.sh');
function fakeRunner(t, bootId, { root: existingRoot } = {}) {
    const root = existingRoot || fs.mkdtempSync(path.join(process.env.TMPDIR, 'c3-terminal-runner-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const put = (name, content, mode = 0o600) => {
        const file = path.join(root, name);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, content, { mode });
    };
    put('proc/sys/kernel/random/boot_id', `${bootId}\n`);
    if (!existingRoot) put('usr/local/etc/xray/config.json', '{"old":true}\n');
    fs.mkdirSync(path.join(root, 'usr/local/share/xray'), { recursive: true });
    fs.mkdirSync(path.join(root, 'var/lib'), { recursive: true });
    put('usr/local/bin/xray', '#!/bin/bash\nexit 0\n', 0o700);
    put('usr/bin/systemctl', `#!/bin/bash
set -eu
printf '%s\\n' "$*" >> "$CELERITY_TOPOLOGY_ROOT/systemctl.log"
case "$1" in
restart|stop) exit 0 ;;
show) printf 'Job=\\nActiveState=active\\nSubState=running\\n' ;;
is-active) exit 0 ;;
*) exit 64 ;;
esac
`, 0o700);
    const execute = (command, options = {}) => {
        const result = spawnSync('bash', [runner, ...command.split(' ').slice(1)], {
            env: { ...process.env, CELERITY_TOPOLOGY_ROOT: root }, input: options.stdin, encoding: 'utf8',
        });
        return { code: result.status, stdout: result.stdout, stderr: result.stderr };
    };
    return { root, execute, put };
}
module.exports = { fakeRunner };
