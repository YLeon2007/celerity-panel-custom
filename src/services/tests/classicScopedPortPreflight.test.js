'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const { preflightTunnelPort } = require('../classicScopedPortPreflight');
const node = { active: true, ip: '192.0.2.1', ssh: { password: 'fixture' } };
test('read-only deadline refuses without ownership and late connection cannot dispatch a command', async () => {
    let finish, commands = 0, disconnected = 0;
    class SSH {
        connect() { return new Promise(resolve => { finish = resolve; }); }
        exec() { commands++; throw Error('must not dispatch'); }
        disconnect() { disconnected++; }
    }
    await assert.rejects(preflightTunnelPort({ node, port: 10086 }, { NodeSSH: SSH, timeoutMs: 20 }), { code: 'TUNNEL_PORT_CHECK_UNAVAILABLE' });
    finish(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(commands, 0); assert.ok(disconnected >= 1);
});
test('actual read-only shell and local kernel TCP listener detect a runtime-only collision', async () => {
    const directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'classic-port-read-'));
    const server = net.createServer();
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const commands = [];
    class SSH {
        async connect() {}
        disconnect() {}
        async exec(command) {
            commands.push(command);
            assert.doesNotMatch(command, /\.stage|restart|ufw|firewall-cmd|\bmv\b/);
            const local = command.replaceAll('/usr/local/etc/xray-bridge/config.json', `${directory}/bridge.json`)
                .replaceAll('/usr/local/etc/xray/config.json', `${directory}/main.json`);
            const { stdout, stderr } = await execFile('sh', ['-c', local], { timeout: 8000 });
            return { code: 0, stdout, stderr };
        }
    }
    try {
        await assert.rejects(preflightTunnelPort({ node, port }, { NodeSSH: SSH }), { code: 'TUNNEL_PORT_IN_USE' });
        await new Promise(resolve => server.close(resolve));
        await preflightTunnelPort({ node, port }, { NodeSSH: SSH });
        assert.equal(commands.filter(command => command.includes('ss -')).length, 2);
        assert.deepEqual(await fs.readdir(directory), [], 'inspection created no profile/stage files');
    } finally {
        if (server.listening) await new Promise(resolve => server.close(resolve));
        await fs.rm(directory, { recursive: true, force: true });
    }
});
