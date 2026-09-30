'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TopologyClientProfileProbe } = require('../services/topologyClientProfileProbe');
const { mkdtemp, writeFile, chmod, rm, stat } = require('node:fs/promises');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const profile = {
    remarks: 'TEST disposable',
    log: { loglevel: 'debug' },
    inbounds: [{ tag: 'socks-in', port: 10808, listen: '127.0.0.1', protocol: 'socks' }],
    outbounds: [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'test.infograd.online', port: 443, users: [{ id: '11111111-1111-4111-8111-111111111111', encryption: 'none', flow: 'xtls-rprx-vision' }] }] }, streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'example.org', publicKey: 'public-key', shortId: '01234567', fingerprint: 'chrome' } } }, { tag: 'direct', protocol: 'freedom', settings: {} }, { tag: 'block', protocol: 'blackhole', settings: {} }],
    routing: { rules: [{ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' }] },
};

test('probe requires a published xray-json profile and fails closed without a profile', async () => {
    const probe = new TopologyClientProfileProbe();
    assert.deepEqual(await probe.probe({ endpoint: 'https://echo.example/ip', expectedEgressIp: '198.51.100.10' }), { ok: false });
});

test('published single-VLESS profile launches a private loopback client and checks approved egress', async () => {
    const calls = [];
    const probe = new TopologyClientProfileProbe({
        xrayBinary: process.execPath,
        curlBinary: process.execPath,
        // Executable runner injection is limited to test doubles; production uses spawn/execFile.
        spawnClient: (binary, args, options) => {
            calls.push({ binary, args, options });
            const { spawn } = require('node:child_process');
            return spawn(binary, ['-e', `const net = require('node:net'); const fs = require('node:fs'); const c=JSON.parse(fs.readFileSync(process.argv[1])); if(c.outbounds[0].settings.vnext[0].address !== 'test.infograd.online') process.exit(2);net.createServer(s=>s.end()).listen(c.inbounds[0].port, '127.0.0.1');`, args[2]], options);
        },
        runCurl: async (binary, args) => {
            calls.push({ binary, args });
            assert.equal(args[args.length - 1], 'https://echo.example/ip');
            assert(args.includes('--socks5-hostname'));
            return { stdout: '198.51.100.10\nPROBE_STATUS:200', stderr: '' };
        },
    });
    const other = structuredClone(profile);
    other.outbounds[0].settings.vnext[0].address = 'other.example';
    const result = await probe.probe({ profile: JSON.stringify([other, profile]), profileIndex: 1, endpoint: 'https://echo.example/ip', expectedEgressIp: '198.51.100.10' });
    assert.deepEqual(result, { ok: true, httpStatus: 200, observedEgressIp: '198.51.100.10' });
    assert.equal(calls.length, 2);
    assert(!JSON.stringify(result).includes('11111111'));
});

test('actual process orchestration binds loopback, keeps client config private, and removes it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'probe-test-'));
    const xray = join(dir, 'fake-xray');
    const curl = join(dir, 'fake-curl');
    const marker = join(dir, 'config-path');
    try {
        await writeFile(xray, `#!${process.execPath}\nconst net=require('node:net'),fs=require('node:fs'); const file=process.argv[4]; const cfg=JSON.parse(fs.readFileSync(file)); if(cfg.inbounds.length!==1||cfg.inbounds[0].listen!=='127.0.0.1'||cfg.log.loglevel!=='none'||(fs.statSync(file).mode&0o777)!==0o600)process.exit(2); fs.writeFileSync(${JSON.stringify(marker)},file);net.createServer(s=>s.end()).listen(cfg.inbounds[0].port,'127.0.0.1');\n`);
        await writeFile(curl, `#!${process.execPath}\nconst net=require('node:net'),args=process.argv.slice(2);if(args[0]!=='--disable'||!args.includes('--socks5-hostname')||args.at(-1)!=='https://echo.example/ip')process.exit(2);const port=Number(args[args.indexOf('--socks5-hostname')+1].split(':')[1]);const s=net.connect(port,'127.0.0.1',()=>{process.stdout.write('198.51.100.10\\nPROBE_STATUS:200');s.end()});s.on('error',()=>process.exit(3));\n`);
        await chmod(xray, 0o700);
        await chmod(curl, 0o700);
        const result = await new TopologyClientProfileProbe({ xrayBinary: xray, curlBinary: curl }).probe({ profile, endpoint: 'https://echo.example/ip', expectedEgressIp: '198.51.100.10' });
        assert.deepEqual(result, { ok: true, httpStatus: 200, observedEgressIp: '198.51.100.10' });
        const path = await require('node:fs/promises').readFile(marker, 'utf8');
        await assert.rejects(stat(path), { code: 'ENOENT' });
    } finally { await rm(dir, { recursive: true, force: true }); }
});

test('invalid profiles and executable errors fail closed without secret output', async () => {
    let launched = 0;
    const probe = new TopologyClientProfileProbe({ spawnClient() { launched++; throw Error('secret UUID 11111111'); } });
    for (const value of [null, '{}', '[', [profile, profile], { ...profile, outbounds: [] }, { ...profile, outbounds: [profile.outbounds[0], profile.outbounds[0]] }]) {
        assert.deepEqual(await probe.probe({ profile: value, endpoint: 'https://echo.example/ip', expectedEgressIp: '198.51.100.10' }), { ok: false });
    }
    assert.equal(launched, 0);
    assert.deepEqual(await probe.probe({ profile, endpoint: 'http://echo.example/ip', expectedEgressIp: '198.51.100.10' }), { ok: false });
    assert.equal(launched, 0);
    assert.deepEqual(await probe.probe({ profile, endpoint: 'https://echo.example/ip', expectedEgressIp: '198.51.100.10' }), { ok: false });
    assert.equal(launched, 1);
});

test('wrong bridge exit or HTTP response is never accepted as client proof', async () => {
    const { spawn } = require('node:child_process');
    const fakeXray = (binary, args, options) => spawn(process.execPath, ['-e', `const net=require('node:net'),fs=require('node:fs'); const c=JSON.parse(fs.readFileSync(process.argv[1]));net.createServer(s=>s.end()).listen(c.inbounds[0].port,'127.0.0.1');`, args[2]], options);
    for (const stdout of ['203.0.113.20\nPROBE_STATUS:200', '198.51.100.10\nPROBE_STATUS:500', '198.51.100.10\nPROBE_STATUS:200\nSECRET']) {
        const probe = new TopologyClientProfileProbe({ spawnClient: fakeXray, runCurl: async () => ({ stdout, stderr: '' }) });
        assert.deepEqual(await probe.probe({ profile, endpoint: 'https://echo.example/ip', expectedEgressIp: '198.51.100.10' }), { ok: false });
    }
});
