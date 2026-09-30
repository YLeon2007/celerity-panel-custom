'use strict';

// A deliberately un-wired, operator-invoked client-side smoke probe. The caller
// supplies one published xray-json profile and an approved HTTPS IP-echo URL;
// this module neither fetches subscriptions nor asserts bridge-log correlation.
const { spawn, execFile } = require('node:child_process');
const { mkdtemp, writeFile, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const net = require('node:net');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function selectProfile(input, index) {
    if (typeof input === 'string') {
        if (Buffer.byteLength(input) > 262144) return null;
        input = JSON.parse(input);
    }
    if (Array.isArray(input)) {
        if (!Number.isSafeInteger(index) || index < 0 || index >= input.length) return null;
        input = input[index];
    } else if (index !== undefined) return null;
    if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
    if (!Array.isArray(input.outbounds)) return null;
    const vless = input.outbounds.filter(o => o?.protocol === 'vless');
    if (vless.length !== 1 || vless[0].tag !== 'proxy') return null;
    const outbound = vless[0];
    const server = outbound.settings?.vnext;
    if (!Array.isArray(server) || server.length !== 1 || !Array.isArray(server[0]?.users)
        || server[0].users.length !== 1 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(server[0].users[0]?.id)
        || typeof server[0].address !== 'string' || !server[0].address
        || !Number.isInteger(server[0].port) || server[0].port < 1 || server[0].port > 65535
        || outbound.streamSettings?.network !== 'tcp'
        || outbound.streamSettings?.security !== 'reality'
        || typeof outbound.streamSettings.realitySettings?.publicKey !== 'string'
        || !outbound.streamSettings.realitySettings.publicKey) return null;
    // No arbitrary additional outbound (e.g. a second proxy/direct fallback).
    if (input.outbounds.some(o => o !== outbound && !['freedom', 'blackhole'].includes(o?.protocol))) return null;
    return outbound;
}

function approvedEndpoint(value) {
    if (typeof value !== 'string' || value.length > 2048) return false;
    try {
        const url = new URL(value);
        return url.protocol === 'https:' && !!url.hostname && !url.username && !url.password
            && !url.hash && !url.search && net.isIP(url.hostname.replace(/^\[|\]$/g, '')) === 0
            && url.hostname !== 'localhost';
    } catch { return false; }
}

async function unusedPort() {
    const server = net.createServer();
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    return port;
}

async function ready(port, child) {
    for (let n = 0; n < 40; n++) {
        if (child.exitCode !== null || child.signalCode !== null) return false;
        const connected = await new Promise(resolve => {
            const socket = net.connect({ host: '127.0.0.1', port });
            socket.setTimeout(150);
            socket.once('connect', () => { socket.destroy(); resolve(true); });
            socket.once('error', () => { socket.destroy(); resolve(false); });
            socket.once('timeout', () => { socket.destroy(); resolve(false); });
        });
        if (connected) return true;
        await delay(100);
    }
    return false;
}

async function stop(child) {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    child.kill('SIGTERM');
    const exited = new Promise(resolve => child.once('close', () => resolve(true)));
    if (await Promise.race([exited, delay(500).then(() => false)])) return;
    child.kill('SIGKILL');
    await Promise.race([exited, delay(500)]);
}

function defaultCurl(binary, args) {
    return new Promise((resolve, reject) => execFile(binary, args,
        { timeout: 20000, maxBuffer: 1024, encoding: 'utf8', env: { PATH: process.env.PATH || '/usr/bin:/bin' } },
        (error, stdout, stderr) => error ? reject(error) : resolve({ stdout, stderr })));
}

class TopologyClientProfileProbe {
    constructor({ xrayBinary = '/usr/local/bin/xray', curlBinary = 'curl', spawnClient = spawn, runCurl = defaultCurl } = {}) {
        this.xrayBinary = xrayBinary;
        this.curlBinary = curlBinary;
        this.spawnClient = spawnClient;
        this.runCurl = runCurl;
    }

    /**
     * profile: one xray-json object or published JSON array (select with
     * profileIndex, zero-based); endpoint: approved HTTPS IP-echo URL.
     * Never returns profiles, raw process output, UUIDs, commands or errors.
     * A positive result proves only a loopback Xray VLESS request and expected
     * public IPv4; it does NOT prove a particular bridge or phone/Happ traffic.
     */
    async probe({ profile, profileIndex, endpoint, expectedEgressIp } = {}) {
        let dir;
        let child;
        let result = { ok: false };
        try {
            const outbound = selectProfile(profile, profileIndex);
            if (!outbound || !approvedEndpoint(endpoint) || net.isIP(expectedEgressIp) !== 4) return { ok: false };
            const port = await unusedPort();
            const config = {
                log: { loglevel: 'none' },
                inbounds: [{ tag: 'probe-socks', listen: '127.0.0.1', port, protocol: 'socks', settings: { auth: 'noauth', udp: false } }],
                outbounds: [outbound],
                routing: { rules: [{ type: 'field', inboundTag: ['probe-socks'], outboundTag: 'proxy' }] },
            };
            dir = await mkdtemp(join(tmpdir(), 'topology-client-probe-'));
            const file = join(dir, 'client.json');
            await writeFile(file, JSON.stringify(config), { mode: 0o600, flag: 'wx' });
            child = this.spawnClient(this.xrayBinary, ['run', '-config', file], { stdio: 'ignore', env: { PATH: process.env.PATH || '/usr/bin:/bin' } });
            child.on('error', () => {}); // Error details may contain sensitive command arguments.
            if (!await ready(port, child)) return { ok: false };
            const args = ['--disable', '--socks5-hostname', `127.0.0.1:${port}`, '--noproxy', '', '--fail', '--silent', '--show-error', '--max-time', '15', '--max-filesize', '64', '--write-out', '\nPROBE_STATUS:%{http_code}', endpoint];
            const output = await this.runCurl(this.curlBinary, args);
            if (typeof output?.stdout !== 'string' || output.stdout.length > 128 || output.stderr !== '') return { ok: false };
            const match = /^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*\nPROBE_STATUS:(\d{3})$/.exec(output.stdout);
            if (!match || net.isIP(match[1]) !== 4 || match[2] !== '200'
                || match[1] !== expectedEgressIp || child.exitCode !== null || child.signalCode !== null) return { ok: false };
            result = { ok: true, httpStatus: 200, observedEgressIp: match[1] };
        } catch {
            return { ok: false };
        } finally {
            try { await stop(child); } catch { result = { ok: false }; }
            try { if (dir) await rm(dir, { recursive: true, force: true }); }
            catch { result = { ok: false }; }
        }
        return result;
    }
}

module.exports = { TopologyClientProfileProbe };
