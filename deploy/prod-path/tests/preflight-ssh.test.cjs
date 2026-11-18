'use strict';
const { EventEmitter } = require('node:events');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const Module = require('node:module');
const test = require('node:test');
const { preflight, routable } = require('../preflight-ssh.cjs');

const sha = raw => createHash('sha256').update(raw).digest('hex');
const PROD = { target: 'production', hostIdentity: 'lm1.infograd.online' };
const env = { PANEL_DOMAIN: PROD.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false' };
const key = Buffer.from('fixture only');
const hostKeys = [Buffer.from('fixture host'), Buffer.from('fixture node P'), Buffer.from('fixture node B')];
const pins = hostKeys.map((hostKey, i) => ({
    kind: i === 0 ? 'host' : 'node', policySha256: String(i + 1).repeat(64),
    physical: { bootId: randomUUID(), machineId: String(i + 1).repeat(32), sshHostKeySha256: sha(hostKey) },
    endpoint: { ip: `192.0.2.${i + 1}`, port: 222, username: 'root' },
    privateKeyPath: `/etc/celerity/fixture-key-${i}`, maintenanceId: randomUUID(),
    ...(i === 0 ? {} : { nodeId: String(i).repeat(24), targetProfile: i === 1 ? 'xray-main' : 'xray-bridge',
        proofRef: 'fixture', originalSnapshot: { source: 'node-readback', configSha256: '3'.repeat(64),
            unitSha256: '4'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' }, acceptedOwner: { owner: 'absent' } }),
}));
const model = { version: 1, executionContext: PROD, mode: 'enroll', admission: { serverContext: PROD },
    host: pins[0], nodes: pins.slice(1) };

function simulatedSsh(t, config, { wrongKey, wrongBoot } = {}) {
    const attempts = [], actions = [], ends = [];
    class Client extends EventEmitter {
        connect(opts) {
            const target = [config.host, ...config.nodes].find(p => p.endpoint.ip === opts.host);
            assert.ok(target);
            this.pin = config.nodes.find(p => p.policySha256 === target.policySha256) ?? target;
            attempts.push(opts.host);
            assert.equal(opts.port, target.endpoint.port);
            assert.equal(opts.username, 'root');
            assert.equal(opts.privateKey, key);
            assert.equal(opts.hostVerifier(Buffer.from('unknown fixture key')), false);
            assert.equal(opts.hostVerifier(target.physical.sshHostKeySha256), false);
            const supplied = wrongKey === opts.host ? Buffer.from('wrong fixture key')
                : hostKeys.find(raw => sha(raw) === target.physical.sshHostKeySha256);
            queueMicrotask(() => opts.hostVerifier(supplied) ? this.emit('ready') : this.emit('error', Error('blocked')));
        }
        exec(command, callback) {
            assert.equal(command, '/usr/bin/python3 -I -B /usr/local/libexec/c3-production-physical.py');
            const stream = new EventEmitter();
            stream.stderr = new EventEmitter();
            stream.write = wire => {
                const q = JSON.parse(wire);
                actions.push([this.pin.kind, q.action]);
                assert.equal(q.action, 'observe');
                const observed = { ...this.pin, serverContext: PROD, held: true,
                    oldBackend: { instanceId: 'fixture-drained', pid: 42, processStartTime: '123' } };
                if (wrongBoot === this.pin.endpoint.ip) observed.physical = { ...this.pin.physical, bootId: randomUUID() };
                queueMicrotask(() => stream.emit('data', Buffer.from(JSON.stringify({ nonce: q.nonce, result: observed }) + '\n')));
            };
            callback(null, stream);
        }
        end() { ends.push(this.pin.endpoint.ip); }
        destroy() { this.end(); }
    }
    const load = Module._load;
    Module._load = (id, ...args) => id === 'ssh2' ? { Client } : load(id, ...args);
    t.after(() => { Module._load = load; });
    return { attempts, actions, ends };
}

function run(config, options = {}) {
    return preflight({ env, uid: 0, read: file => file === '/etc/celerity/topology-production.json'
        ? JSON.stringify(config) : key,
    mountInfo: () => '50 20 0:1 /root /etc/celerity ro,relatime - ext4 /dev/none rw\n', ...options });
}

test('container preflight uses actual production SSH client verifier and observes all roles', async t => {
    const { attempts, actions, ends } = simulatedSsh(t, model);
    await run(model);
    assert.deepEqual(attempts, pins.map(p => p.endpoint.ip));
    assert.deepEqual(actions.map(a => a[0]), ['host', 'node', 'node', 'host', 'node', 'node']);
    assert.deepEqual(ends, attempts);
});

test('exact cohost still checks both logical roles over one actual open', async t => {
    const config = { ...model, host: { ...pins[1], kind: 'host' } };
    const { attempts, actions } = simulatedSsh(t, config);
    await run(config);
    assert.deepEqual(attempts, pins.slice(1).map(p => p.endpoint.ip));
    assert.equal(actions.length, 4);
});

test('host-key mismatch on the host stops before any remote command', async t => {
    const { attempts, actions } = simulatedSsh(t, model, { wrongKey: model.host.endpoint.ip });
    await assert.rejects(run(model), /PRODUCTION_AUTHORITY_CONNECT_FAILED/);
    assert.deepEqual(attempts, [model.host.endpoint.ip]);
    assert.deepEqual(actions, []);
});

test('a matching ssh key is not sufficient: stale Boot or mixed host pin refuses', async t => {
    const { ends } = simulatedSsh(t, model, { wrongBoot: model.host.endpoint.ip });
    await assert.rejects(run(model), /UNKNOWN_RETAINED/);
    assert.equal(ends.length, pins.length);
});

test('missing key, nonroot UID, wrong domain and loopback refuse before opening SSH', async t => {
    const { attempts } = simulatedSsh(t, model);
    await assert.rejects(run(model, { uid: 1000 }), /CONTAINER_ROOT_REQUIRED/);
    await assert.rejects(run(model, { env: { ...env, PANEL_DOMAIN: 'test.invalid' } }), /PROD_SELECTOR_REQUIRED/);
    await assert.rejects(run({ ...model, host: { ...model.host, endpoint: { ...model.host.endpoint, ip: '127.0.0.1' } } }), /NON_ROUTABLE_ENDPOINT/);
    await assert.rejects(run(model, { read: p => {
        if (p.endsWith('.json')) return JSON.stringify(model);
        throw new Error('KEY_UNREADABLE');
    } }), /KEY_UNREADABLE/);
    assert.deepEqual(attempts, []);
    for (const ip of ['::1', '::ffff:127.0.0.1', 'fe80::2', '224.0.0.1', '0.0.0.0', 'host.docker.internal']) assert.equal(routable(ip), false);
    for (const ip of ['192.0.2.1', '2001:db8::42', 'fd00::1']) assert.equal(routable(ip), true);
});

test('missing, writable and shadowed trust binds refuse before reading credentials', async t => {
    const { attempts } = simulatedSsh(t, model);
    const top = '50 20 0:1 /root /etc/celerity ro,relatime - ext4 /dev/none rw\n';
    for (const raw of ['', top.replace(' ro,', ' rw,'), top + top.replace('/etc/celerity ', '/etc/celerity/keys ')]) {
        await assert.rejects(run(model, { mountInfo: () => raw, read: () => assert.fail('read before mount gate') }), /CONFIG_BIND_NOT_READ_ONLY/);
    }
    assert.deepEqual(attempts, []);
});
