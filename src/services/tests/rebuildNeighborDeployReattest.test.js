'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { once } = require('node:events');
const { join } = require('node:path');
const { createInterface } = require('node:readline');
const test = require('node:test');

// Keep application settings, log writers, and credential storage out of the fixture.
function fixtureModule(specifier, exports) {
    const id = require.resolve(specifier);
    require.cache[id] = { id, filename: id, loaded: true, exports };
}
fixtureModule('../../utils/logger', { warn() {} });
fixtureModule('../sshPoolService', { hostKeyOptions: () => ({}) });
fixtureModule('../cryptoService', {});
fixtureModule('../cascadeService', { _invalidateTopologyCache() {} });
const generator = require('../configGenerator');
generator.buildPanelInlineCertificate = () => null;
const { MAIN, BRIDGE } = require('../classicAppliedConfig');
const NodeSSH = require('../nodeSSH');
const { createRebuildService } = require('../rebuildService');
const { makeLocks } = require('../rebuildLocks');
const { neighborRefusalForError } = require('../rebuildNeighborRefusal');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const { rebuildApplyMachineGuard } = require('./helpers/rebuildApplyMachineGuard');
const net = require('node:net');
test.before(() => {
    for (const [prototype, method] of [[net.Socket.prototype, 'connect'], [net.Server.prototype, 'listen']]) {
        test.mock.method(prototype, method, () => assert.fail('fixture must not open sockets'));
    }
});

const phases = ['check-apply-network', 'prepare-apply-network', 'verify-apply-network', 'publish-apply-profiles',
    'restart-apply-network', 'finalize-apply-profiles'];
const token = '12345678-1234-4234-8234-123456789abc';
const id = n => n.toString(16).padStart(24, '0');
const query = rows => ({ select() { return this; }, read() { return this; }, readConcern() { return this; },
    session() { return this; }, async lean() { return structuredClone(rows); } });

async function fixture(t) {
    const child = spawn('/usr/bin/python3', ['-I', '-B', join(__dirname, 'helpers/rebuildNeighborDeployHost.py')],
        { cwd: require('node:os').tmpdir(), env: {} });
    const exited = once(child, 'exit');
    let diagnostic = '';
    child.stderr.setEncoding('utf8').on('data', chunk => { diagnostic += chunk; });
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    t.after(async () => {
        child.stdin.end();
        assert.deepEqual(await exited, [0, null], diagnostic);
    });
    // Transport cleanup calls may be concurrent; serialize messages on the pipe.
    let tail = Promise.resolve();
    const host = (node, op, ...args) => {
        const result = tail.then(async () => {
            assert.equal(child.exitCode, null, diagnostic);
            child.stdin.write(`${JSON.stringify([node, op, ...args])}\n`);
            const line = await lines.next();
            assert.equal(line.done, false, diagnostic || 'host fixture EOF');
            return JSON.parse(line.value);
        });
        tail = result.catch(() => {});
        return result;
    };
    const nodes = ['relay', 'relay', 'bridge'].map((cascadeRole, i) => ({ _id: id(i + 1), name: `Fixture ${i + 1}`,
        ip: `node${i}.fixture.invalid`, type: 'xray', active: true, cascadeRole, port: 443,
        xray: { security: 'none', transport: 'tcp', apiPort: 10085 }, ssh: { port: 2222, username: 'root', password: 'fixture-only' } }));
    const [first, second, exit] = nodes.map(n => n._id);
    const states = [first, second].map((node, i) => ({ _id: node, node, backupId: 'a'.repeat(32),
        rebuildMachineId: String(i + 1).repeat(32), rebuildInstallToken: token, status: 'installed', desiredState: 'installed',
        clientCidr: '10.60.0.0/24', tproxyPort: 12456, fwmark: 805, routeTable: 210, secretRevision: 1, routingMode: 'follow-relay', routingVersion: 1 }));
    const installed = new Map(states.map(row => [row.node, row]));
    const edge = (n, portalNode, bridgeNode) => ({ _id: id(n), portalNode, bridgeNode, active: true, mode: 'forward',
        tunnelSecurity: 'none', tunnelEncryption: 'none', tunnelPort: 40000 + n, tunnelUuid: token });
    const neighbor = edge(11, first, second);
    const existing = edge(12, second, exit);
    const links = [neighbor, existing];
    const baseline = composeRebuildProfiles({ nodes, links: [existing], followRelayStates: states,
        controlPlaneAddresses: nodes.map(n => n.ip) });
    const base = (node, profile) => JSON.stringify(baseline.find(p => p.nodeId === node && p.profile === profile).config);
    for (const state of states) await host(state.node, 'seed', state, base(state.node, 'main'), null);
    const exitFiles = new Map([[MAIN, base(exit, 'main')], [BRIDGE, base(exit, 'bridge')]]);
    const trace = [], settlement = [];
    let held;
    const locks = makeLocks({
        async insertOne(row) { assert.equal(held, undefined); held = row; },
        async findOne({ token }) { return held?.token === token ? held : null; },
        async deleteMany({ _id, token }) {
            assert.equal(held?._id, _id);
            assert.equal(held?.token, token);
            held = undefined;
            return { acknowledged: true, deletedCount: 1 };
        },
    });
    const ok = stdout => ({ code: 0, stdout: stdout ?? '', stderr: '' });
    const profileRead = path => `if test -f ${path}; then cat ${path}; elif test ! -e ${path}; then printf 'C3_CLASSIC_PROFILE_ABSENT'; else exit 1; fi`;
    const stageFile = `(?:${MAIN.replaceAll('.', '\\.')}|${BRIDGE.replaceAll('.', '\\.')})\\.rebuild-[a-f0-9-]{36}\\.json`;
    const stageCommand = new RegExp(`cat > (${stageFile})\\); /usr/local/bin/xray run -test -config \\1 >/dev/null 2>&1$`);
    const cleanupCommand = new RegExp(`^rm -f -- (${stageFile}) (${stageFile})$`);
    t.mock.method(NodeSSH.prototype, 'connectDirectOnce', async function () {
        assert.ok(held && !this.usePool && installed.has(this.node._id));
        return (cmd, opts, beforeStdin) => dispatch(this.node._id, cmd, opts, beforeStdin);
    });
    t.mock.method(NodeSSH.prototype, 'disconnect', function () {});
    t.mock.method(NodeSSH.prototype, 'exec', function (command, opts) { return dispatch(this.node._id, command, opts); });
    async function dispatch(node, frame, opts, beforeStdin) {
        assert.ok(held);
        const { command, accepts } = rebuildApplyMachineGuard(frame);
        const state = installed.get(node);
        if (accepts) assert.ok(state && accepts(state.rebuildMachineId));
        if (command === '/usr/bin/head -c 34 /etc/machine-id') return ok(`${state.rebuildMachineId}\n`);
        if (command === '/usr/local/bin/xray version') return ok('Xray 26.3.27\n');
        if (command.startsWith('/usr/bin/timeout -k 4s 125s /usr/bin/python3 -I -B -c ')) {
            assert.ok(state && !accepts);
            const request = JSON.parse(opts.stdin);
            await beforeStdin?.();
            const result = await host(node, 'direct', opts.stdin);
            trace.push({ node, action: request.action, request, result });
            return result;
        }
        for (const [path, unit] of [[MAIN, 'xray'], [BRIDGE, 'xray-bridge']]) {
            if (command === profileRead(path)) {
                const bytes = state ? await host(node, 'file', path) : exitFiles.get(path);
                return ok(bytes ?? 'C3_CLASSIC_PROFILE_ABSENT');
            }
            if (command === `systemctl show -p LoadState --value ${unit}.service`) {
                return ok(path === BRIDGE && state ? 'not-found\n' : 'loaded\n');
            }
            if (command === `systemctl show -p ExecStart --value ${unit}.service`) {
                return ok(`path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${path} ;\n`);
            }
        }
        const stage = stageCommand.exec(command);
        if (stage) {
            trace.push({ node, action: 'stage', file: stage[1], bytes: opts.stdin });
            if (state) { assert.ok(accepts); await host(node, 'stage', stage[1], opts.stdin); }
            else exitFiles.set(stage[1], opts.stdin);
            return ok();
        }
        const cleanup = cleanupCommand.exec(command);
        if (cleanup) {
            trace.push({ node, action: 'cleanup' });
            if (state) { assert.ok(accepts); await host(node, 'cleanup', ...cleanup.slice(1)); }
            else cleanup.slice(1).forEach(file => exitFiles.delete(file));
            return ok();
        }
        if (state) {
            assert.equal(command, 'systemctl enable xray.service');
            assert.ok(accepts);
            await host(node, 'enable-main');
            return ok();
        }
        const moved = new RegExp(`mv -fT (${stageFile}) (${MAIN}|${BRIDGE})$`).exec(command);
        if (moved) {
            assert.ok(exitFiles.has(moved[1]));
            exitFiles.set(moved[2], exitFiles.get(moved[1]));
            exitFiles.delete(moved[1]);
            return ok();
        }
        assert.ok(['systemctl stop xray-bridge.service', 'systemctl enable xray.service && systemctl restart xray.service && systemctl is-active --quiet xray.service',
            'systemctl enable xray-bridge.service && systemctl restart xray-bridge.service && systemctl is-active --quiet xray-bridge.service'].includes(command),
        `unexpected modeled shell command: ${command.slice(0, 180)}`);
        return ok();
    }
    t.mock.method(NodeSSH.prototype, 'connect', async function () { assert.ok(held && this.node._id === exit); });
    const service = createRebuildService({ env: { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
        C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify(states.map(state => ({ nodeId: state.node,
            host: nodes.find(n => n._id === state.node).ip, port: 2222, username: 'root', machineId: state.rebuildMachineId,
            sshHostKeySha256: state.rebuildMachineId.repeat(2) }))) },
    locks,
    Node: { find: ({ _id }) => query(nodes.filter(n => _id.$in.includes(n._id))) },
    State: { find: ({ node }) => query(states.filter(row => node.$in.includes(row.node))),
        async updateOne(filter) { settlement.push(filter._id); return { matchedCount: 1 }; } },
    Link: { find: ({ _id }) => query(links.filter(row => !_id || _id.$in.includes(row._id))),
        db: { async transaction(fn) { assert.ok(held); return fn({}); } },
        async updateOne(filter, { $set }) {
            assert.ok($set.rebuildApplied);
            settlement.push(filter._id);
            return { acknowledged: true, matchedCount: 1 };
        } },
    L2tpUser: {}, assertNoRelayAccountIntent: async () => assert.ok(held),
    sync: { async _getUsersForNode() { return []; } }, cache: { async invalidateAllSubscriptions() {} } });
    const preview = () => service.execute({ linkId: neighbor._id, preview: true });
    const deploy = async (beforeApply = async () => {}) => {
        const report = await preview();
        assert.equal(report.allowed, true);
        trace.length = 0;
        await beforeApply(report);
        return service.execute({ linkId: neighbor._id, expectedPreview: report.previewId });
    };
    return { first, second, exit, installed, neighbor, existing, host, trace, settlement, preview, deploy };
}

function assertPublished(f, node, snapshot) {
    const { manifest, files } = snapshot;
    assert.ok(manifest.currentApply);
    assert.equal(manifest.phase, 'installed');
    assert.equal(manifest.currentApply.nodeId, node);
    assert.deepEqual(manifest.currentApply.files, files);
    assert.ok(!Object.hasOwn(manifest, 'applyPending'));
    const frames = f.trace.filter(entry => entry.node === node && entry.request);
    assert.deepEqual(frames.map(x => x.action), phases);
    const stage = f.trace.filter(entry => entry.node === node && entry.action === 'stage');
    assert.equal(stage.length, 2);
    assert.ok(stage.every(entry => f.trace.indexOf(entry) < f.trace.indexOf(frames[1])));
    for (const [i, profile] of ['main', 'bridge'].entries()) {
        const sha = createHash('sha256').update(stage[i].bytes).digest('hex');
        assert.equal(frames[3].request.profiles[profile], sha);
        assert.equal(files[profile][0].data, sha);
    }
    for (const { result } of frames) assert.deepEqual([result.code, result.stderr], [0, '']);
    assert.notEqual(frames[3].request.proof, JSON.parse(frames[3].result.stdout).proof);
    assert.equal(frames[4].request.proof, JSON.parse(frames[3].result.stdout).proof);
    assert.equal(frames[5].request.proof, frames[4].request.proof);
}

test('neighboring-link deploy publishes every installed participant; reboot is reattested through Preview', { timeout: 15000 }, async t => {
    const f = await fixture(t);
    await f.deploy();
    assert.deepEqual(f.settlement, [f.first, f.second, f.neighbor._id, f.existing._id]);
    assert.ok(!f.trace.some(x => x.node === f.exit && x.request));
    const deployed = new Map();
    for (const node of f.installed.keys()) {
        const snapshot = await f.host(node, 'snapshot');
        assertPublished(f, node, snapshot);
        assert.notEqual(snapshot.manifest.after.main.data, snapshot.files.main[0].data);
        deployed.set(node, snapshot);
        await f.host(node, 'reboot');
    }
    f.trace.length = 0;
    const preview = await f.preview();
    assert.equal(preview.allowed, true);
    const reattested = new Map();
    for (const [node, before] of deployed) {
        const frames = f.trace.filter(x => x.node === node);
        assert.deepEqual(frames.map(x => x.action), ['check-apply-network', 'reattest-runtime', 'check-apply-network']);
        assert.deepEqual(frames.map(x => x.result.code), [70, 0, 0]);
        assert.equal(frames[0].result.stderr, 'DIRECT_RUNTIME_REATTEST_REQUIRED\n');
        const after = await f.host(node, 'snapshot');
        assert.deepEqual(after.files, before.files);
        assert.deepEqual(after.manifest, { ...before.manifest, runtime: { ...before.manifest.runtime,
            boot: '12345678-1234-1234-1234-123456789abb', invocations: ['4', '5', '6', '7'].map(x => x.repeat(32)),
            pids: ['31', '32', '33', '0'] } });
        reattested.set(node, after);
    }
    // An unchanged report still executes the full publication path on deploy.
    await f.deploy(report => assert.ok(report.nodes.every(n => n.profiles.every(p => p.change === 'unchanged'))));
    for (const [node, before] of reattested) {
        const after = await f.host(node, 'snapshot');
        assertPublished(f, node, after);
        for (const profile of ['main', 'bridge']) {
            assert.equal(after.files[profile][0].data, before.files[profile][0].data);
            assert.notDeepEqual(after.files[profile][1], before.files[profile][1]);
        }
    }
});

test('legacy-shaped receipt after deploy and reboot refuses without adopting live files', { timeout: 15000 }, async t => {
    const f = await fixture(t);
    await f.deploy();
    await f.host(f.first, 'legacy-receipt');
    await f.host(f.first, 'reboot');
    const before = await f.host(f.first, 'snapshot');
    assert.ok(!Object.hasOwn(before.manifest, 'currentApply'));
    assert.notEqual(before.manifest.after.main.data, before.files.main[0].data);
    f.trace.length = 0;
    await assert.rejects(f.preview(), error => {
        assert.equal(error.code, 'REBUILD_RETIRE_NEIGHBOR_REFUSED');
        assert.deepEqual(neighborRefusalForError(error), { code: error.code, neighborName: 'Fixture 1', reason: 'RUNTIME_FOREIGN_CHANGE' });
        return true;
    });
    assert.deepEqual(f.trace.map(x => [x.node, x.action, x.result.code]), [
        [f.first, 'check-apply-network', 70], [f.first, 'reattest-runtime', 70] ]);
    assert.equal(f.trace.at(-1).result.stderr, 'DIRECT_RUNTIME_FOREIGN_CHANGE\n');
    assert.deepEqual(await f.host(f.first, 'snapshot'), before);
});

test('late host finalization failure keeps its pending receipt, prior publication, and skips graph settlement', { timeout: 15000 }, async t => {
    const f = await fixture(t);
    await assert.rejects(f.deploy(() => f.host(f.second, 'cut-final')), { code: 'REBUILD_L2TP_APPLY_NETWORK_OUTCOME_UNKNOWN' });
    assert.deepEqual(f.settlement, []);
    assertPublished(f, f.first, await f.host(f.first, 'snapshot'));
    const failed = await f.host(f.second, 'snapshot');
    assert.equal(failed.manifest.phase, 'apply-profiles-pending');
    assert.ok(failed.manifest.applyPending && !failed.manifest.currentApply);
    assert.deepEqual(failed.manifest.applyPending.files, failed.files);
    assert.equal(f.trace.find(x => x.node === f.second && x.action === phases.at(-1)).result.code, 75);
    await f.host(f.second, 'reboot');
    const state = f.installed.get(f.second);
    const { clientCidr, tproxyPort, fwmark, routeTable } = state;
    assert.deepEqual(await f.host(f.second, 'direct', JSON.stringify({ action: 'reattest-runtime', nodeId: f.second,
        machineId: state.rebuildMachineId, backupId: state.backupId, network: { clientCidr, tproxyPort, fwmark, routeTable } })),
    { code: 70, stdout: '', stderr: 'DIRECT_RUNTIME_FOREIGN_CHANGE\n' });
    assert.deepEqual(await f.host(f.second, 'snapshot'), failed);
});
