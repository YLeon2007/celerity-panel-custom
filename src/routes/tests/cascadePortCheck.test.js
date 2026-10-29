'use strict';
Object.assign(process.env, { PANEL_DOMAIN: 'test.invalid', ACME_EMAIL: 'test@test.invalid', ENCRYPTION_KEY: 'a'.repeat(32), SESSION_SECRET: 'b'.repeat(32) });
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createCascadeLinksRouter } = require('../cascadeLinks');
const generator = require('../../services/configGenerator');
test.after(() => require('../../services/sshPoolService').closeAll());
const A = '507f1f77bcf86cd799439031', B = '507f1f77bcf86cd799439032', L = '507f1f77bcf86cd799439041';
const MAIN = '/usr/local/etc/xray/config.json', TRANSIT = '/usr/local/etc/xray-bridge/config.json';
function harness(options = {}) {
    const node = { _id: A, active: true, type: 'xray', ip: '192.0.2.1', ssh: { password: 'fixture' }, xray: { inboundTag: 'vless-in' } };
    const link = { _id: L, active: true, mode: options.mode || 'reverse', tunnelPort: 10086, tunnelUuid: 'fixture-uuid',
        portalNode: node, bridgeNode: { _id: B, ip: '192.0.2.2' } };
    if (link.mode === 'forward') [link.portalNode, link.bridgeNode] = [link.bridgeNode, node];
    const main = { inbounds: [{ tag: 'vless-in', port: 443 }], outbounds: [], routing: { rules: [] } };
    if (options.own) {
        if (link.mode === 'reverse') generator.applyReversePortal(main, [link], ['vless-in']);
        else generator.applyForwardHopInbound(main, [link]);
    }
    if (options.forged) main.inbounds.find(row => row.port === 10086).settings.clients[0].id = 'foreign';
    if (options.wrongNode) link.portalNode = { _id: B };
    const calls = { db: [], ssh: [] };
    const query = value => ({ populate() { return this; }, setOptions() { return this; }, lean: async () => structuredClone(value) });
    class SSH {
        constructor(selected) { assert.deepEqual(selected, node); }
        async connect() { calls.ssh.push('connect'); }
        disconnect() { calls.ssh.push('disconnect'); }
        async exec(command) {
            calls.ssh.push(command);
            assert.doesNotMatch(command, /\.stage|restart|ufw|firewall-cmd|\bmv\b|upload/);
            if (options.fail) return { code: 1, stdout: '', stderr: 'password=secret' };
            const marker = command.match(/C3_PORT_READ_[a-f0-9]+/)[0];
            let text = '';
            if (command.includes('C3_READ_CONFIG')) text = command.includes(TRANSIT)
                ? JSON.stringify({ inbounds: options.preserved ? [{ tag: 'conn-down-old', port: 10086 }] : [] }) : JSON.stringify(main);
            if (command.includes('ss -')) text = options.own || options.runtime
                ? `LISTEN 0 128 *:10086 *:* users:(("xray",pid=${options.foreignPID ? 999 : 123},fd=3))\n` : '';
            if (command.includes('systemctl show')) text = `MainPID=123\nActiveState=active\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${MAIN} ; }\n`;
            return { code: 0, stdout: `${text}\n${marker}\n`, stderr: '' };
        }
    }
    const fail = new Proxy({}, { get() { throw Error('no ownership, reservation or draft dependency may be used'); } });
    const router = createCascadeLinksRouter({ Node: { findById(id) { calls.db.push(['node', id]); return query(node); } },
        Link: { findById(id) { calls.db.push(['link', id]); return query(link); } },
        TopologyState: fail, topologyDraftWriteService: fail, classicTopologyCoordinator: fail,
        portCheckSSH: SSH });
    return { router, calls };
}
async function request(h, query = `nodeId=${A}&port=10086`, scopes = ['nodes:read']) {
    const app = express();
    app.use((req, res, next) => { if (scopes) req.apiKey = { scopes }; next(); });
    app.use(h.router);
    const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
    try { const response = await fetch(`http://127.0.0.1:${server.address().port}/port-check?${query}`);
        return { status: response.status, body: await response.json() }; }
    finally { await new Promise(resolve => server.close(resolve)); }
}
test('port-check authenticated read-only endpoint reads both profiles and actual TCP sockets without any claims', async () => {
    const h = harness();
    assert.deepEqual(await request(h), { status: 200, body: { available: true, port: 10086, code: null } });
    assert.deepEqual(h.calls.db, [['node', A]]);
    assert.equal(h.calls.ssh.filter(cmd => cmd.includes('C3_READ_CONFIG')).length, 2);
    assert.equal(h.calls.ssh.filter(cmd => cmd.includes('ss -')).length, 1);
});
for (const options of [{ preserved: true }, { runtime: true }, { own: true, forged: true }, { own: true, foreignPID: true }, { own: true, wrongNode: true }]) {
    test(`port-check occupied refuses without false-free or linkId bypass ${JSON.stringify(options)}`, async () => {
        const h = harness(options);
        assert.deepEqual(await request(h, `nodeId=${A}&port=10086&linkId=${L}`),
            { status: 200, body: { available: false, port: 10086, code: 'TUNNEL_PORT_IN_USE' } });
    });
}
for (const mode of ['reverse', 'forward']) test(`port-check exact ${mode} own listener with canonical service PID is replayable`, async () => {
    assert.deepEqual(await request(harness({ own: true, mode }), `nodeId=${A}&port=10086&linkId=${L}`),
        { status: 200, body: { available: true, port: 10086, code: null } });
});
test('port-check unknown inspection returns safe 503, not available', async () => {
    const r = await request(harness({ fail: true }));
    assert.equal(r.status, 503); assert.equal(r.body.error.code, 'TUNNEL_PORT_CHECK_UNAVAILABLE');
    assert.doesNotMatch(JSON.stringify(r.body), /password|secret/); assert.notEqual(r.body.available, true);
});
test('port-check rejects noncanonical, duplicate and caller endpoint fields before DB or SSH', async () => {
    for (const q of [`nodeId=${A}&port=010086`, `nodeId=${A}&port=0`, `nodeId=${A}&port=65536`,
        `nodeId=${A}&port=1.5`, `nodeId=${A}&port=1e4`, `nodeId=${A}&port=10086&port=10087`,
        `nodeId=${A}&port=10086&host=evil`, `nodeId=${A}&port=10086&linkId=bad`, 'nodeId=bad&port=10086']) {
        const h = harness(); const r = await request(h, q);
        assert.equal(r.status, 400, q); assert.deepEqual(h.calls, { db: [], ssh: [] });
    }
});
test('port-check requires nodes:read and performs no external calls without authorization', async () => {
    for (const scopes of [null, [], ['users:read']]) {
        const h = harness(); assert.equal((await request(h, undefined, scopes)).status, 403);
        assert.deepEqual(h.calls, { db: [], ssh: [] });
    }
});
