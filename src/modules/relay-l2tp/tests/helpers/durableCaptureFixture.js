'use strict';
// Real capture/OFD/UDS/observer files; physical/kernel/UID/SSH facts SIMULATED.
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { createHash } = require('node:crypto');
const assert = require('node:assert/strict');
const sha = raw => createHash('sha256').update(raw).digest('hex');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../domain/topologyExecutionContext');
const fixtureScript = path.join(__dirname, '../../../../../scripts/test-node-isolation/capture_fixture.py');
const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
async function actualFixture(t, fault, large = false) {
    const supervisor = spawn('/usr/bin/python3', [fixtureScript, 'supervisor', ...(large ? ['large'] : [])], { env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let errors = ''; supervisor.stderr.on('data', b => { errors += b; });
    t.after(async () => {
        if (supervisor.exitCode === null && supervisor.signalCode === null) {
            const done = once(supervisor, 'close'); supervisor.kill('SIGINT'); await done;
        }
    });
    let closedResolve;
    const captureHoldersClosed = new Promise(resolve => { closedResolve = resolve; });
    const f = await new Promise((resolve, reject) => {
        let text = '';
        supervisor.stdout.on('data', b => {
            text += b; let index;
            while ((index = text.indexOf('\n')) !== -1) {
                const value = JSON.parse(text.slice(0, index)); text = text.slice(index + 1);
                if (value.fixtureCaptureHoldersClosed === true) closedResolve(); else resolve(value);
            }
        });
        supervisor.once('close', code => { if (code) reject(new Error(errors)); });
    });
    const runtime = require('../../runtime/testPhysicalController');
    const options = { env,
        read(file) {
            if (file === '/etc/celerity/topology-test-physical.json') return Buffer.from(JSON.stringify(f.physical));
            if (file === '/etc/celerity/topology-test-capture.json') return Buffer.from(JSON.stringify({ version: 1, helperSha256: sha(fs.readFileSync(path.join(__dirname, '../../../../../scripts/test-node-isolation/coordinated_capture.py'))) }));
            assert.equal(file, '/usr/local/libexec/c3-test-coordinated-capture.py');
            return fs.readFileSync(path.join(__dirname, '../../../../../scripts/test-node-isolation/coordinated_capture.py'));
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
        openChannel: async () => { assert.fail('default same-OFD path must never open a second observer'); },
    };
    const createController = ownerEnrollment => {
        const controller = runtime.createRootTestPhysicalAuthority({ ...options, ownerEnrollment,
            openChannel: ownerEnrollment ? options.openChannel : async pin => {
                const child = spawn('/usr/bin/python3', [fixtureScript, 'runtime-observer', f.nodeRoots[pin.nodeId]],
                    { env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
                t.after(async () => { if (child.exitCode === null && child.signalCode === null) {
                    const done = once(child, 'close'); child.kill(); await done;
                } });
                return new runtime.AttestationChannel(child.stdout, child.stdin, child, { timeoutMs: 5000 });
            },
        });
        t.after(() => controller.close()); return controller;
    };
    const controller = createController(true);
    return { ...f, controller, createController, captureHoldersClosed, supervisor, errors: () => errors };
}
module.exports = { actualFixture };
