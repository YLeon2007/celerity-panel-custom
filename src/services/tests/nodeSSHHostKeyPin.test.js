'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, generateKeyPairSync } = require('node:crypto');
const { Server, utils } = require('ssh2');
const NodeSSH = require('../nodeSSH');
const pool = require('../sshPoolService');
const { TopologyNodeExecutionResolver } = require('../../modules/relay-l2tp/services/topologyNodeExecutionResolver');

// Actual ssh2 handshakes over loopback only. Fingerprints hash the SSH wire
// public-key blob, NOT PEM, a textual OpenSSH key, or its base64 representation.
const privateKey = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
}).privateKey;
const wireKey = utils.parseKey(privateKey).getPublicSSH();
const digest = createHash('sha256').update(wireKey).digest('hex');

pool.settingsLoaded = true;
pool.config.maxRetries = 0;
pool.config.connectTimeout = 2000;
test.after(() => pool.closeAll());

async function serverFixture(t) {
    const clients = new Set();
    const counts = { connections: 0, authentication: 0, exec: 0, sftp: 0 };
    const server = new Server({ hostKeys: [privateKey] }, client => {
        counts.connections++;
        clients.add(client);
        client.on('error', () => {});
        client.on('close', () => clients.delete(client));
        client.on('authentication', ctx => { counts.authentication++; ctx.accept(); });
        client.on('ready', () => client.on('session', accept => {
            const session = accept();
            session.on('exec', acceptExec => {
                counts.exec++;
                const stream = acceptExec();
                stream.exit(0);
                stream.end('local-ok');
            });
            session.on('sftp', (_accept, reject) => { counts.sftp++; reject(); });
        }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
        pool.closeAll();
        for (const client of clients) client.end();
        await new Promise(resolve => server.close(resolve));
    });
    const node = { _id: 'same-node', name: 'loopback', ip: '127.0.0.1',
        ssh: { port: server.address().port, username: 'local', password: 'local-fixture' } };
    const options = { expectedHostKeySha256: digest,
        expectedEndpoint: { ip: node.ip, port: node.ssh.port, username: node.ssh.username } };
    return { node, options, counts };
}

test('pinned pool request cannot reuse an existing unpinned nodeId connection', async t => {
    const { node, options, counts } = await serverFixture(t);
    const legacy = new NodeSSH(node);
    await legacy.connect();
    assert.equal((await legacy.exec('legacy-local')).stdout, 'local-ok');
    const pinned = new NodeSSH(node, { ...options, expectedHostKeySha256: '0'.repeat(64) });
    let directAttempts = 0;
    pinned.connectDirect = async () => { directAttempts++; throw new Error('unexpected fallback'); };
    await assert.rejects(pinned.connect(), /host.*(key|verification)|pin/i);
    await assert.rejects(pinned.exec('must-not-run'));
    await assert.rejects(pinned.uploadContent('must-not-write', '/forbidden/file'));
    assert.equal(directAttempts, 0);
    assert.equal(counts.exec, 1);
    assert.equal(counts.sftp, 0);
});

test('production resolver passes only its explicit authority to the real pinned transport', async t => {
    const { node, options, counts } = await serverFixture(t);
    Object.assign(node, { active: true, type: 'xray', cascadeRole: 'portal', sshHostKeySha256: 'f'.repeat(64) });
    const HyNode = { findById() { return { select() { return { lean: async () => node }; } }; } };
    const resolver = new TopologyNodeExecutionResolver({ HyNode, NodeSSH,
        target: 'production', hostIdentity: 'lm1.infograd.online' });
    const request = { nodeId: node._id, role: 'portal' };
    await assert.rejects(resolver.resolve(request), { code: 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE' });
    assert.equal(counts.connections, 0);
    const selected = await resolver.resolve(request, options);
    await selected.connect();
    assert.equal((await selected.exec('local-authorized')).stdout, 'local-ok');
    for (const usePool of [false, true]) {
        const wrong = await resolver.resolve(request, { ...options, expectedHostKeySha256: '0'.repeat(64) });
        wrong.usePool = usePool;
        await assert.rejects(wrong.connect(), /verification failed/i);
        await assert.rejects(wrong.exec('not-run'));
        await assert.rejects(wrong.uploadContent('not-written', '/forbidden/file'));
    }
    assert.equal(counts.exec, 1);
    assert.equal(counts.sftp, 0);
});

test('raw SSH public-key SHA-256 accepts exact pin in direct and pooled handshakes', async t => {
    const { node, options, counts } = await serverFixture(t);
    const direct = new NodeSSH(node, options);
    direct.usePool = false;
    t.after(() => direct.disconnect());
    await direct.connect();
    assert.equal((await direct.exec('local-direct')).stdout, 'local-ok');
    const pooled = new NodeSSH(node, options);
    await pooled.connect();
    assert.equal((await pooled.exec('local-pool')).stdout, 'local-ok');
    await new NodeSSH(node, options).connect();
    assert.equal(counts.connections, 2, 'same pinned identity reuses only its pinned connection');
    assert.equal(counts.exec, 2);
});

test('hashing base64 text instead of SSH wire bytes is rejected by both transports', async t => {
    const { node, options, counts } = await serverFixture(t);
    const wrongDigest = createHash('sha256').update(wireKey.toString('base64')).digest('hex');
    assert.notEqual(wrongDigest, digest);
    for (const usePool of [false, true]) {
        const ssh = new NodeSSH(node, { ...options, expectedHostKeySha256: wrongDigest });
        ssh.usePool = usePool;
        t.after(() => ssh.disconnect());
        await assert.rejects(ssh.connect(), /verification failed/i);
        await assert.rejects(ssh.writeFile('/forbidden', 'not-written'));
    }
    assert.equal(counts.authentication, 0);
    assert.equal(counts.sftp, 0);
});

test('malformed and missing explicit pins refuse before any socket is opened', async t => {
    const { node, options, counts } = await serverFixture(t);
    for (const value of [undefined, null, '', digest.toUpperCase(), `SHA256:${wireKey.toString('base64')}`,
        `${digest} `, `${digest}\n`, digest.slice(1), 'g'.repeat(64), Buffer.from(digest)]) {
        const malformed = { ...options, expectedHostKeySha256: value };
        assert.throws(() => new NodeSSH(node, malformed), { code: 'SSH_HOST_KEY_PIN_INVALID' });
        await assert.rejects(pool.getConnection(node, malformed), { code: 'SSH_HOST_KEY_PIN_INVALID' });
    }
    for (const malformed of [{}, null, { expectedHostKeySha256: digest },
        { ...options, expectedEndpoint: { ...options.expectedEndpoint, port: String(node.ssh.port) } }]) {
        assert.throws(() => new NodeSSH(node, malformed), { code: 'SSH_HOST_KEY_PIN_INVALID' });
    }
    assert.equal(counts.connections, 0);
});

test('nodeId reuse with a different pin cannot reuse a pinned ready or in-flight connection', async t => {
    const { node, options, counts } = await serverFixture(t);
    const wrong = { ...options, expectedHostKeySha256: '0'.repeat(64) };
    const connecting = pool.getConnection(node, options);
    const samePinConnecting = pool.getConnection(node, options);
    await assert.rejects(pool.getConnection(node, wrong), /verification failed/i);
    const first = await connecting;
    assert.equal(await samePinConnecting, first);
    await assert.rejects(pool.getConnection(node, wrong), /verification failed/i);
    assert.equal(await pool.getConnection(node, options), first);
    assert.equal(counts.authentication, 1);
    assert.equal(counts.exec, 0);
});

test('an unpinned in-flight connection cannot satisfy a pinned pool request', async t => {
    const { node, options, counts } = await serverFixture(t);
    const connecting = pool.getConnection(node);
    await assert.rejects(pool.getConnection(node, { ...options, expectedHostKeySha256: '0'.repeat(64) }),
        /verification failed/i);
    await connecting;
    assert.equal(counts.authentication, 1);
});

test('same nodeId at a different selected endpoint performs a separate handshake', async t => {
    const first = await serverFixture(t);
    const second = await serverFixture(t);
    const original = await pool.getConnection(first.node, first.options);
    const changed = await pool.getConnection(second.node, second.options);
    assert.notEqual(changed, original);
    assert.equal(first.counts.connections, 1);
    assert.equal(second.counts.connections, 1);
});

test('changed IP, port or username refuses before dispatch on either transport', async t => {
    for (const usePool of [false, true]) {
        const { node, options, counts } = await serverFixture(t);
        const ssh = new NodeSSH(node, options);
        ssh.usePool = usePool;
        t.after(() => ssh.disconnect());
        await ssh.connect();
        for (const [object, field, replacement] of [[node, 'ip', '127.0.0.2'],
            [node.ssh, 'port', 1], [node.ssh, 'username', 'another-user']]) {
            const previous = object[field];
            object[field] = replacement;
            await assert.rejects(ssh.connect(), { code: 'SSH_HOST_KEY_PIN_INVALID' });
            await assert.rejects(ssh.exec('not-run'), { code: 'SSH_HOST_KEY_PIN_INVALID' });
            await assert.rejects(ssh.writeFile('/forbidden', 'not-written'), { code: 'SSH_HOST_KEY_PIN_INVALID' });
            await assert.rejects(ssh.readFile('/forbidden'), { code: 'SSH_HOST_KEY_PIN_INVALID' });
            object[field] = previous;
        }
        assert.equal(counts.exec, 0);
        assert.equal(counts.sftp, 0);
    }
});

test('disabled pool direct fallback retains the pin and cannot upload on mismatch', async t => {
    const { node, options, counts } = await serverFixture(t);
    pool.config.enabled = false;
    t.after(() => { pool.config.enabled = true; });
    const wrong = new NodeSSH(node, { ...options, expectedHostKeySha256: '0'.repeat(64) });
    await assert.rejects(wrong.connect(), /verification failed/i);
    assert.equal(wrong.usePool, false);
    await assert.rejects(wrong.exec('not-run'));
    await assert.rejects(wrong.uploadContent('not-written', '/forbidden/file'));
    assert.equal(counts.authentication, 0);
    const correct = new NodeSSH(node, options);
    t.after(() => correct.disconnect());
    await correct.connect();
    assert.equal((await correct.exec('local-correct')).stdout, 'local-ok');
    assert.equal(counts.exec, 1);
    assert.equal(counts.sftp, 0);
});

test('generic pool errors do not downgrade pinned callers but preserve legacy fallback', async t => {
    const { node, options, counts } = await serverFixture(t);
    const original = pool.getConnection;
    pool.getConnection = async () => { throw new Error('injected pool outage'); };
    t.after(() => { pool.getConnection = original; });
    const pinned = new NodeSSH(node, options);
    let attempts = 0;
    pinned.connectDirect = async () => { attempts++; };
    await assert.rejects(pinned.connect(), /injected pool outage/);
    assert.equal(attempts, 0);
    const legacy = new NodeSSH(node);
    t.after(() => legacy.disconnect());
    await legacy.connect();
    assert.equal(legacy.usePool, false);
    assert.equal((await legacy.exec('legacy-local')).stdout, 'local-ok');
    assert.equal(counts.exec, 1);
});

test('pin authority is snapshotted and cannot be replaced through mutable options', async t => {
    const { node, options } = await serverFixture(t);
    const ssh = new NodeSSH(node, options);
    options.expectedHostKeySha256 = '0'.repeat(64);
    options.expectedEndpoint.port = 1;
    await ssh.connect();
    assert.equal((await ssh.exec('snapshot-local')).stdout, 'local-ok');
});

test('bounded retries preserve the verifier on every direct and pooled handshake', async t => {
    pool.config.maxRetries = 1;
    t.after(() => { pool.config.maxRetries = 0; });
    for (const usePool of [false, true]) {
        const { node, options, counts } = await serverFixture(t);
        const ssh = new NodeSSH(node, { ...options, expectedHostKeySha256: '0'.repeat(64) });
        ssh.usePool = usePool;
        await assert.rejects(ssh.connect(), /verification failed/i);
        assert.equal(counts.connections, 2, 'one initial handshake plus one bounded retry');
        assert.equal(counts.authentication, 0);
        assert.equal(counts.exec, 0);
        assert.equal(counts.sftp, 0);
    }
});

test('direct mismatched host key fails before authentication, exec or upload', async t => {
    const { node, options, counts } = await serverFixture(t);
    const ssh = new NodeSSH(node, { ...options, expectedHostKeySha256: '0'.repeat(64) });
    ssh.usePool = false;
    t.after(() => ssh.disconnect());
    await assert.rejects(ssh.connect(), /host.*(key|verification)|pin/i);
    await assert.rejects(ssh.exec('must-not-run'));
    await assert.rejects(ssh.uploadContent('must-not-write', '/forbidden/file'));
    assert.equal(counts.authentication, 0);
    assert.equal(counts.exec, 0);
    assert.equal(counts.sftp, 0);
});
