'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { tmpdir } = require('node:os');
const { spawnSync } = require('node:child_process');
const generator = require('../configGenerator');
const { createRebuildService } = require('../rebuildService');
const { createTransport } = require('../rebuildTransport');
const { READ_CHAIN, VERIFY_CHAIN, tunnelName, verifyTunnelTrust } = require('../rebuildTunnelTls');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const ids = ['000000000000000000000001', '000000000000000000000002'];
const nodes = ids.map((_id, i) => ({ _id, cascadeRole: i ? 'bridge' : 'portal', type: 'xray', active: true,
    ip: `192.0.2.${i + 1}`, port: 23000 + i, xray: { inboundTag: 'client', transport: 'tcp', security: 'none' } }));
const name = 'exact.example.invalid';
const edge = mode => ({ _id: '000000000000000000000003', portalNode: ids[0], bridgeNode: ids[1], mode, active: true,
    tunnelSecurity: 'tls', tunnelPort: 29000, tunnelUuid: '00000000-0000-4000-8000-000000000003', rebuildTlsServerName: name });
const sections = all => all.flatMap(p => [...p.config.inbounds, ...p.config.outbounds]).filter(o => o.streamSettings?.security === 'tls');

for (const mode of ['forward', 'reverse']) test(`${mode} emits exact SNI, system trust and original tunnel certificate source only in rebuild`, () => {
    const link = edge(mode);
    for (const panel of [false, true]) {
        const panelTls = panel ? { serverName: name, certificate: ['fixture-cert'], key: ['fixture-key'] } : {};
        const wire = sections(composeRebuildProfiles({ nodes, links: [link], panelTls }));
        assert.equal(wire.length, 2);
        const [listener, dialer] = [wire.find(o => o.listen), wire.find(o => !o.listen)];
        assert.deepEqual(dialer.streamSettings.tlsSettings, { serverName: name, useSystemCA: true });
        const cert = listener.streamSettings.tlsSettings.certificates[0];
        if (panel) assert.deepEqual(cert.certificate, ['fixture-cert']);
        else assert.deepEqual(cert, { certificateFile: '/usr/local/etc/xray/cert.pem', keyFile: '/usr/local/etc/xray/key.pem' });
        assert.equal(listener.streamSettings.tlsSettings.serverName, name);
        const classic = generator.buildCascadeTunnelStreamSettings({ ...link, tlsServerName: name }, { panelTls });
        assert.deepEqual(classic.tlsSettings, { serverName: name, ...(panel ? {} : { allowInsecure: true }) });
    }
    assert.throws(() => tunnelName({ tunnelDomain: name }), { code: 'REBUILD_TLS_SERVER_NAME_REQUIRED' });
});

// Exercise the real remote read/verify commands in an isolated local fixture.
// Only the virtual public chain and system trust bundle change between calls.
const bwrap = '/usr/bin/bwrap';
const linuxFixture = fs.existsSync(bwrap) && spawnSync(bwrap, ['--ro-bind','/','/','--unshare-net','--','true']).status === 0;
test('actual TLS chain gates Preview, fresh Apply and draft before persistence', { skip: !linuxFixture }, async t => {
    const dir = fs.mkdtempSync(path.join(tmpdir(), 'rebuild-tls-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const exec = args => assert.equal(spawnSync('openssl', args, { cwd: dir, stdio: 'ignore', timeout: 8000 }).status, 0);
    for (const ca of ['trusted', 'other']) exec(['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes',
        '-days','1','-subj',`/CN=${ca}`,'-addext','basicConstraints=critical,CA:TRUE','-keyout',`${ca}.key`,'-out',`${ca}.pem`]);
    exec(['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj',`/CN=${name}`,'-keyout','leaf.key','-out','leaf.csr']);
    fs.writeFileSync(path.join(dir,'ext'), `subjectAltName=DNS:${name}\nextendedKeyUsage=serverAuth\n`);
    exec(['x509','-req','-in','leaf.csr','-CA','trusted.pem','-CAkey','trusted.key','-CAcreateserial','-days','1','-extfile','ext','-out','leaf.pem']);
    exec(['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj',`/CN=${name}`,
        '-addext',`subjectAltName=DNS:${name}`,'-keyout','self.key','-out','self.pem']);
    const chain = path.join(dir,'fullchain.pem');
    fs.writeFileSync(chain, ['leaf.pem','trusted.pem'].map(f=>fs.readFileSync(path.join(dir,f),'utf8')).join('\n'));
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    for (const mode of ['forward','reverse']) {
        const link = edge(mode), listener = ids[mode === 'forward' ? 1 : 0], dialer = ids.find(id=>id!==listener);
        let served = chain, roots = 'trusted.pem', writes = 0;
        const calls = [];
        const model = rows => ({ find: () => ({ select(){return this;}, read(){return this;}, readConcern(){return this;},
            lean: async()=>structuredClone(rows) }), updateOne(){writes++; throw Error();} });
        const baseline = composeRebuildProfiles({nodes,links:[link]});
        class LocalSSH {
            constructor(node){ this.id=node._id; } async connect(){} disconnect(){}
            async exec(command,{stdin}) {
                calls.push([this.id,command]);
                assert.ok(command===READ_CHAIN||command===VERIFY_CHAIN);
                assert.equal(this.id,command===READ_CHAIN?listener:dialer);
                const res=spawnSync(bwrap,['--die-with-parent','--unshare-net','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin',
                    '--tmpfs','/usr/local','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev',
                    '--ro-bind',served,'/usr/local/etc/xray/cert.pem','--ro-bind',path.join(dir,roots),'/etc/ssl/certs/ca-certificates.crt',
                    '--','/bin/sh','-c',command],{ input:stdin,encoding:'utf8',timeout:5000 });
                return { code:res.status,stdout:res.stdout };
            }
        }
        const service=createRebuildService({ Node:model(nodes), Link:model([link]), State:model([]), locks:{run:fn=>fn(async()=>{})},
            assertNoRelayAccountIntent:async()=>{},
            env:{C3_REBUILD_ENABLED:'true'}, cache:{},sync:{_getUsersForNode:async()=>[]},connect(n){const tr=createTransport(n,LocalSSH);
                return {...tr,requireSupportedCore:async()=>{},read:async p=>baseline.find(b=>b.nodeId===n._id&&b.profile===p).config,
                    putPair:async()=>{writes++;},stagePair:async()=>{writes++;} };} });
        const preview=await service.execute({linkId:link._id,preview:true});
        assert.equal(preview.allowed,true);
        assert.deepEqual(calls,[[listener,READ_CHAIN],[dialer,VERIFY_CHAIN]]);
        await service.verifyDraftTls(link);
        const panelTls = { serverName:name, certificate: fs.readFileSync(chain,'utf8').trim().split('\n') };
        const channels = new Map(nodes.map(n=>[n._id,createTransport(n,LocalSSH)]));
        try {
            calls.length=0;
            await verifyTunnelTrust([link],panelTls,channels);
            assert.deepEqual(calls,[[dialer,VERIFY_CHAIN]],'inline panel chain uses no file fallback');
            roots='other.pem';
            await assert.rejects(verifyTunnelTrust([link],panelTls,channels),{code:'REBUILD_TLS_TRUST_UNVERIFIED'});
        } finally { await Promise.all([...channels.values()].map(ch=>ch.close())); }
        for (const bad of ['other-root','self-signed','wrong-name']) {
            roots=bad==='other-root'?'other.pem':'trusted.pem'; served=bad==='self-signed'?path.join(dir,'self.pem'):chain;
            link.rebuildTlsServerName=bad==='wrong-name'?'other.example.invalid':name;
            const code=bad==='wrong-name'?'REBUILD_TLS_NAME_MISMATCH':'REBUILD_TLS_TRUST_UNVERIFIED';
            await assert.rejects(service.verifyDraftTls(link),{code});
            await assert.rejects(service.execute({linkId:link._id,expectedPreview:preview.previewId}),{code});
            assert.equal(writes,0);
        }
    }
});
