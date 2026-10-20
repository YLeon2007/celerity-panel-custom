'use strict';
// Fixed finite installed root helper only. No environment/config path selector,
// receipt, boolean or arbitrary executable is an authority input.
const fs = require('node:fs');
const { spawn: spawnProcess } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const CONFIG = '/etc/celerity/topology-test-capture.json';
const HELPER = '/usr/local/libexec/c3-test-coordinated-capture.py';
function refusal() { return Object.assign(new Error('DURABLE_CAPTURE_UNKNOWN_RETAINED'), { code: 'DURABLE_CAPTURE_UNKNOWN_RETAINED' }); }
function need(value) { if (!value) throw refusal(); }
function readTrusted(file) {
    let fd = fs.openSync('/', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
        const parts = file.split('/').slice(1);
        for (let i = 0; i < parts.length; i++) {
            const child = fs.openSync(`/proc/self/fd/${fd}/${parts[i]}`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
                | fs.constants.O_NONBLOCK | (i < parts.length - 1 ? fs.constants.O_DIRECTORY : 0));
            fs.closeSync(fd); fd = child;
            const st = fs.fstatSync(fd);
            need(st.uid === 0 && st.gid === 0 && !(st.mode & 0o022)
                && (i < parts.length - 1 ? st.isDirectory() : st.isFile() && st.nlink === 1 && st.size <= 1024 * 1024 && !(st.mode & 0o007)));
        }
        return fs.readFileSync(fd);
    } finally { fs.closeSync(fd); }
}
function createDurableNodeOriginals({ read = readTrusted, spawn = spawnProcess, timeoutMs = 15000 } = {}) {
    // Test seams are programmatic constructors only; the root factory never
    // takes these values from environment, request fields or mutable node rows.
    let used = false;
    return async function withDurableNodeOriginals(challenge, callback) {
        need(!used && typeof callback === 'function'); used = true;
        let child, pending, tail = Promise.resolve(), buffer = '', open = true, lost = false, seq = 0;
        let exitResolve, exited = false, exitCode;
        const exit = new Promise(resolve => { exitResolve = resolve; });
        const poison = () => {
            lost = true;
            if (pending) { clearTimeout(pending.timer); pending.reject(refusal()); pending = undefined; }
        };
        const request = op => {
            const run = () => new Promise((resolve, reject) => {
                if (!open || lost || !child || exited) return reject(refusal());
                const frame = { version: 1, op, seq: seq++, nonce: randomBytes(32).toString('hex'), ownerChallenge: challenge };
                const timer = setTimeout(poison, timeoutMs);
                pending = { frame, resolve, reject, timer };
                child.stdin.write(JSON.stringify(frame) + '\n', error => { if (error) poison(); });
            });
            const result = tail.then(run); tail = result.catch(() => {}); return result;
        };
        try {
            const config = JSON.parse(read(CONFIG));
            need(equal(Object.keys(config).sort(), ['helperSha256', 'version']) && config.version === 1
                && typeof config.helperSha256 === 'string' && /^[a-f0-9]{64}$/.test(config.helperSha256)
                && createHash('sha256').update(read(HELPER)).digest('hex') === config.helperSha256);
            child = spawn('/usr/bin/python3', ['-I', HELPER, 'owner-channel'], {
                shell: false, stdio: ['pipe', 'pipe', 'pipe'],
                env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C', HOME: '/root' },
            });
            child.once('error', () => { poison(); if (!exited) { exited = true; exitResolve(); } });
            child.once('close', code => { exited = true; exitCode = code; poison(); exitResolve(); });
            child.stdin.on('error', poison); child.stdout.on('error', poison); child.stdout.on('end', poison);
            child.stderr.on('data', poison); child.stderr.on('error', poison);
            child.stdout.on('data', data => {
                if (lost) return;
                buffer += data.toString('utf8');
                if (Buffer.byteLength(buffer) > 16384) return poison();
                const index = buffer.indexOf('\n');
                if (index === -1) return;
                try {
                    need(index === buffer.length - 1 && pending);
                    const reply = JSON.parse(buffer.slice(0, index)); buffer = '';
                    need(equal(reply, { version: 1, op: 'capture-held', seq: pending.frame.seq, nonce: pending.frame.nonce }));
                    const current = pending; pending = undefined;
                    clearTimeout(current.timer); current.resolve();
                } catch { poison(); }
            });
            await request('open');
            const check = () => request('check');
            const result = await callback(check);
            await check();
            need(open && !lost && !exited);
            // No permission after cleanup: finish deliberately has no GO reply.
            child.stdin.end(JSON.stringify({ version: 1, op: 'finish', seq: seq++, nonce: randomBytes(32).toString('hex'), ownerChallenge: challenge }) + '\n');
            let timer;
            try { await Promise.race([exit, new Promise((_, reject) => { timer = setTimeout(() => reject(refusal()), 3000); })]); }
            finally { clearTimeout(timer); }
            need(exitCode === 0); return result;
        } catch { poison(); throw refusal(); }
        finally {
            open = false; poison();
            if (child) {
                child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
                if (!exited) {
                    child.kill('SIGKILL');
                    let timer;
                    try { await Promise.race([exit, new Promise(resolve => { timer = setTimeout(resolve, 3000); })]); }
                    finally { clearTimeout(timer); }
                }
            }
        }
    };
}
module.exports = { createDurableNodeOriginals };
