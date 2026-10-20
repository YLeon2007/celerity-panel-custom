'use strict';
// Protocol process/files are real; remote/root physical authority SIMULATED.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
let api;
try { api = require('../runtime/testDurableOriginals'); } catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
const sha = raw => createHash('sha256').update(raw).digest('hex');
const helper = Buffer.from('SIMULATED independently pinned installed helper');
const challenge = Object.freeze({ version: 1, test: 'fixed-fixture' });
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const fixtureScript = path.join(__dirname, '../../../../scripts/test-node-isolation/capture_fixture.py');
const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
async function actualFixture(t, fault) {
    const supervisor = spawn('/usr/bin/python3', [fixtureScript, 'supervisor'], { env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let errors = ''; supervisor.stderr.on('data', b => { errors += b; });
    t.after(async () => {
        if (supervisor.exitCode === null && supervisor.signalCode === null) {
            const done = once(supervisor, 'close'); supervisor.kill('SIGINT'); await done;
        }
    });
    const f = await new Promise((resolve, reject) => {
        let text = '';
        supervisor.stdout.on('data', b => { text += b; if (text.includes('\n')) resolve(JSON.parse(text.trim())); });
        supervisor.once('close', code => { if (code) reject(new Error(errors)); });
    });
    const runtime = require('../runtime/testPhysicalController');
    const controller = runtime.createRootTestPhysicalAuthority({ env,
        read(file) {
            if (file === '/etc/celerity/topology-test-physical.json') return Buffer.from(JSON.stringify(f.physical));
            if (file === '/etc/celerity/topology-test-capture.json') return Buffer.from(JSON.stringify({ version: 1, helperSha256: sha(fs.readFileSync(path.join(__dirname, '../../../../scripts/test-node-isolation/coordinated_capture.py'))) }));
            assert.equal(file, '/usr/local/libexec/c3-test-coordinated-capture.py');
            return fs.readFileSync(path.join(__dirname, '../../../../scripts/test-node-isolation/coordinated_capture.py'));
        },
        captureSpawn(command, args, options) {
            assert.equal(command, '/usr/bin/python3');
            assert.deepEqual(args, ['-I', '/usr/local/libexec/c3-test-coordinated-capture.py', 'owner-channel']);
            if (fault === 'challenge') {
                const file = path.join(f.root, 'etc/c3-test-coordinated-capture.json');
                const config = JSON.parse(fs.readFileSync(file)); config.ownerChallenge.host.backend.pid++;
                fs.writeFileSync(file, JSON.stringify(config));
            }
            return spawn('/usr/bin/python3', [fixtureScript, 'owner', f.root, f.socket], { ...options, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
        },
        openChannel: async pin => ({ alive: true, close() {}, async request() {
            const { proofRef, ...snapshot } = pin.originalSnapshot;
            return { nodeId: pin.nodeId, targetProfile: pin.targetProfile, endpoint: pin.endpoint, physical: pin.physical,
                maintenanceId: pin.maintenanceId, planHash: pin.planHash, guard: pin.guard,
                host: pin.nodeId === '6ab189dc63913ebd4a917399' ? f.physical.host : null,
                configTransfer: { ...f.observations[pin.nodeId], readback: { source: 'node-readback', ...snapshot } },
                runnerState: { head: null, journal: 'absent', legacyState: 'absent', terminal: null } };
        } }),
    });
    t.after(() => controller.close());
    return { ...f, controller, supervisor, errors: () => errors };
}
test('SIMULATED observer seam: default factory uses actual five-node capture UDS before actual owner entry model boundary', async t => {
    const f = await actualFixture(t);
    const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: f.controller });
    let writes = 0;
    // Stop exactly at first public-model boundary; real Mongo readback remains
    // the parent serial assembled fixture, not this local protocol test.
    const marker = new Error('EXPECTED_FIRST_PUBLIC_MODEL_BOUNDARY');
    await assert.rejects(require('../../../../scripts/test-topology-owner').enrollTestOwners({ env, lifecycle,
        TopologyConfigOwner: { collection: { async indexes() {
            for (const pin of f.physical.nodes) {
                // Each accepted node fixture root is private to its helper. The
                // coordinator journal cannot be used as historical permission:
                // this access occurs only after live root-peer checks succeed.
                assert.ok(pin.originalSnapshot);
            }
            const intent = JSON.parse(fs.readFileSync(path.join(f.root, 'var/lib/c3-test-node-isolation/coordinated-capture.json')));
            assert.equal(intent.phase, 'captured-held'); assert.equal(intent.capturedNodes.length, 5);
            writes++; throw marker;
        } } }, store: { preEnroll() { assert.fail('past first public model boundary'); } },
    }));
    assert.equal(writes, 1, 'actual default root capture must open the public owner entry, not keep refusing');
});
test('DEFAULT root and actual owner entry refuse changed independent challenge with zero model/store access', async t => {
    const f = await actualFixture(t, 'challenge');
    const { TopologyExecutionAuthorityLifecycle } = require('../runtime/topologyExecutionAuthorityLifecycle');
    const lifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller: f.controller });
    let accesses = 0;
    await assert.rejects(require('../../../../scripts/test-topology-owner').enrollTestOwners({ env, lifecycle,
        TopologyConfigOwner: { collection: { indexes() { accesses++; } }, create() { accesses++; } },
        store: { preEnroll() { accesses++; } },
    }));
    assert.equal(accesses, 0);
});

function setup(mode = '') {
    const children = [];
    return { children, capability: api.createDurableNodeOriginals({
        read(file) {
            if (file === '/etc/celerity/topology-test-capture.json') return Buffer.from(JSON.stringify({ version: 1, helperSha256: sha(helper) }));
            assert.equal(file, '/usr/local/libexec/c3-test-coordinated-capture.py'); return helper;
        },
        spawn(command, args, options) {
            assert.equal(command, '/usr/bin/python3');
            assert.deepEqual(args, ['-I', '/usr/local/libexec/c3-test-coordinated-capture.py', 'owner-channel']);
            assert.equal(options.shell, false);
            const child = spawn(process.execPath, ['-e', `
                let text=''; process.stdin.on('data',b=>{ text+=b; let i; while((i=text.indexOf('\\n'))>=0){
                    const f=JSON.parse(text.slice(0,i)); text=text.slice(i+1);
                    if(f.op==='finish') {process.exit(0);}
                    if(${JSON.stringify(mode)}==='silent') continue;
                    process.stdout.write(JSON.stringify({version:1,op:'capture-held',seq:f.seq,nonce:${JSON.stringify(mode)}==='nonce'?'foreign':f.nonce})+'\\n');
                }});`], { stdio: ['pipe', 'pipe', 'pipe'] });
            children.push(child); return child;
        }, timeoutMs: 100,
    }) };
}
test('fixed installed adapter awaits live challenges across callback and revokes escaped checker', async () => {
    assert.ok(api?.createDurableNodeOriginals, 'actual default durable capture adapter is missing');
    const f = setup(); let escaped, writes = 0;
    const result = await f.capability(challenge, async check => { escaped = check; await check(); writes++; return 17; });
    assert.equal(result, 17); assert.equal(writes, 1);
    await assert.rejects(escaped());
    assert.notEqual(f.children[0].exitCode, null);
});
test('wrong nonce and timeout refuse before callback and permanently revoke adapter', async () => {
    assert.ok(api?.createDurableNodeOriginals);
    for (const mode of ['nonce', 'silent']) {
        const f = setup(mode); let writes = 0;
        await assert.rejects(f.capability(challenge, () => { writes++; }));
        await assert.rejects(f.capability(challenge, () => { writes++; }));
        assert.equal(writes, 0);
        assert.equal(f.children.length, 1);
    }
});
