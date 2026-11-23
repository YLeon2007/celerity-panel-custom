'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

// MAIN's accepted cc-agent 1.5.1 manifest. A replacement binary and replacement
// SHA256SUMS in the same directory must not be able to authorize one another.
const MANIFEST_SHA256 = 'b229552a95d647c950cec7000a553cda15558f816f1742c3ada215c7aaf76961';
const VERSION = '1.5.1';
const INVALID_KIT = 'Invalid or incomplete MAIN cc-agent 1.5.1 kit; check CC_AGENT_OFFLINE_KIT_DIR.';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

async function readRegular(dir, name, limit) {
    const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK } = fs.constants;
    const file = await fs.promises.open(path.join(dir, name), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    try {
        const stat = await file.stat();
        if (!stat.isFile() || stat.size < 1 || stat.size > limit) throw Error(INVALID_KIT);
        // Read at most the admitted size even if a file is concurrently extended.
        const bytes = Buffer.alloc(stat.size);
        let offset = 0;
        while (offset < bytes.length) {
            const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, offset);
            if (!bytesRead) throw Error(INVALID_KIT);
            offset += bytesRead;
        }
        if ((await file.stat()).size !== bytes.length) throw Error(INVALID_KIT);
        return bytes;
    } finally { await file.close(); }
}

async function loadSelectedKit() {
    // Only a trusted panel-process setting, never a path from a node or a form.
    const dir = process.env.CC_AGENT_OFFLINE_KIT_DIR;
    if (dir === undefined) return null;
    try {
        if (!path.isAbsolute(dir) || !(await fs.promises.lstat(dir)).isDirectory()) throw Error(INVALID_KIT);
        const manifest = await readRegular(dir, 'SHA256SUMS', 1024);
        if (digest(manifest) !== MANIFEST_SHA256) throw Error(INVALID_KIT);
        const kit = new Map();
        for (const line of manifest.toString('ascii').trimEnd().split('\n')) {
            const [, hash, name, arch] = /^([a-f0-9]{64})  (cc-agent-linux-(amd64|arm64))$/.exec(line);
            const bytes = await readRegular(dir, name, 32 * 1024 * 1024);
            if (digest(bytes) !== hash) throw Error(INVALID_KIT);
            kit.set(arch, { bytes, hash }); // Send precisely what we checked, without reopening a path.
        }
        if (kit.size !== 2) throw Error(INVALID_KIT);
        return kit;
    } catch { throw Error(INVALID_KIT); } // Do not disclose filesystem details.
}

async function installSelectedKit(kit, exec) {
    const machine = await exec('uname -m', { timeoutMs: 15000 });
    const arch = new Map([['x86_64\n', 'amd64'], ['amd64\n', 'amd64'], ['aarch64\n', 'arm64'], ['arm64\n', 'arm64']]).get(machine.output);
    if (!machine.success || !arch) return { success: false, output: 'Unsupported or unconfirmed cc-agent architecture; existing agent preserved.' };
    const { bytes, hash } = kit.get(arch);
    const aliases = arch === 'amd64' ? 'x86_64|amd64' : 'aarch64|arm64';
    const command = `set -eu
case "$(uname -m)" in ${aliases}) ;; *) exit 41 ;; esac
umask 077
tmp=$(mktemp /usr/local/bin/.cc-agent-main.XXXXXXXX)
trap 'rm -f -- "$tmp"' 0
trap 'exit 1' HUP INT TERM
cat > "$tmp"
sum=$(sha256sum -- "$tmp")
[ "\${sum%% *}" = '${hash}' ] || exit 42
chmod 0755 "$tmp"
mv -fT -- "$tmp" /usr/local/bin/cc-agent
trap - 0 HUP INT TERM
printf 'CC_AGENT_MAIN_INSTALLED\\n'`;
    try {
        const ack = await exec(command, { stdin: bytes, timeoutMs: 300000 });
        if (ack.success && ack.output === 'CC_AGENT_MAIN_INSTALLED\n') return { success: true, output: 'Installed verified MAIN cc-agent 1.5.1.' };
        if (ack.code === 41 || ack.code === 42) return { success: false, output: 'Architecture or SHA-256 mismatch; existing agent preserved.' };
    } catch { /* The channel may have been lost after rename. Never replay or fall back. */ }
    return { success: false, output: 'Offline replacement not confirmed; inspect the agent before retrying.' };
}

module.exports = { loadSelectedKit, installSelectedKit, VERSION };
