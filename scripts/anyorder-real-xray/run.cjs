'use strict';
// REAL generator/executor/transport/NodeSSH/runner/systemd/Xray/HTTP.
// SYNTHETIC frozen descriptor + binding/maintenance authority and fixture units.
// This is NOT HTTP/API/DB/worker acceptance or real enrollment/handback proof.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const root = process.env.C3_CANDIDATE_ROOT;
const work = process.env.C3_FIXTURE_WORK;
const requireCandidate = name => require(path.join(root, name));
const { TopologyOperationPlanMaterializer } = requireCandidate('src/modules/relay-l2tp/services/topologyOperationPlanMaterializer');
const { compileTopology } = requireCandidate('src/modules/relay-l2tp/domain/topologyCompiler');
const { TopologyOperationExecutor, isTopologyTerminalProof } = requireCandidate('src/modules/relay-l2tp/services/topologyOperationExecutor');
const { TOPOLOGY_RUNNER_PATH, TOPOLOGY_RUNNER_SHA256 } = requireCandidate('src/modules/relay-l2tp/services/topologyRunnerBootstrapper');
const NodeSSH = requireCandidate('src/services/nodeSSH');
const cfg = JSON.parse(fs.readFileSync(path.join(work, 'fixture.private.json')));
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const connections = new Map(), heads = new Map();
const auditFile = path.join(work, 'ssh-exits.jsonl');
const ledgerFile = path.join(work, 'cases.jsonl');
let sequence = 0, activeLabel = 'preflight';
const ledger = row => fs.appendFileSync(ledgerFile, JSON.stringify(row) + '\n');
const audit = row => fs.appendFileSync(auditFile, JSON.stringify({ case: activeLabel, ...row }) + '\n');
const shell = text => "'" + text.replaceAll("'", "'\\''") + "'";
function causal(error) { return { name: error.name, code: error.code, message: error.message.slice(0, 2000),
    uncertain: error.remoteOutcomeUncertain, ...(error.cause ? { cause: causal(error.cause) } : {}) }; }
async function exec(id, command, options) {
    const result = await connections.get(id).exec('env GOMAXPROCS=2 sh -c ' + shell(command), options);
    const runnerCommand = command.match(/--command ([a-z-]+)/)?.[1];
    audit({ node: id, action: runnerCommand || (command.startsWith('curl ') ? 'http-probe' : 'fixture-read-or-setup'),
        code: result.code, stdoutSha256: sha(result.stdout || ''), stderr: result.stderr.slice(0, 2000),
        ...(runnerCommand ? { receipt: (() => { try { return JSON.parse(result.stdout); } catch { return null; } })() } : {}) });
    return result;
}
async function ok(id, command, options) {
    const r = await exec(id, command, options);
    assert.equal(r.code, 0, `node=${id} command=${command.split(' ')[0]} stderr=${r.stderr}`);
    return r.stdout;
}
const noReads = { find() { throw Error('Frozen descriptors must not query mutable application models'); } };
const materializer = new TopologyOperationPlanMaterializer({ HyNode: noReads, CascadeLink: noReads });
async function materialize(before, after, kind = 'link.apply') {
    return materializer.materialize({ target: 'test', hostIdentity: 'test.infograd.online', operationKind: kind,
        pinnedSnapshot: { revision: sequence + 1, topology: after, compiled: compileTopology(after) },
        baselineTopology: before, effectiveTopology: after });
}
const nodes = Object.entries(cfg.nodes).map(([id, n]) => ({ id, role: n.role, type: 'xray', active: true,
    ip: n.ip, port: 24443, xray: { inboundTag: `client-${id}`, apiPort: 61000,
        transport: 'tcp', security: 'none', extraInbounds: [] } }));
let state = { nodes: structuredClone(nodes), links: [], groups: [] };
const baseLinks = [
    { id: 'pb1', source: 'p', target: 'b1', tunnelPort: 12200 },
    { id: 'pr', source: 'p', target: 'r', tunnelPort: 12201 },
    { id: 'rb1', source: 'r', target: 'b1', tunnelPort: 12202 },
    { id: 'rb2', source: 'r', target: 'b2', tunnelPort: 12203,
        geoRouting: { enabled: true, domains: ['full:geo.anyorder.test'] } },
].map(l => ({ ...l, active: true, tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelUuid: cfg.linkUuids[l.id] }));

// Existing image units are intentionally root-in-private-userns fixture units,
// not the production managed-nobody unit. The adapter installs ONLY the exact
// candidate runner and pins it. All lifecycle command execution stays native.
class SyntheticFixtureBootstrapper {
    constructor({ nodeSSH }) { this.ssh = nodeSSH; }
    async ensureRunner() {
        const r = await this.ssh.exec(`sha256sum ${TOPOLOGY_RUNNER_PATH}`);
        assert.equal(r.code, 0);
        assert.equal('sha256:' + r.stdout.split(' ')[0], TOPOLOGY_RUNNER_SHA256);
    }
}
async function status(id, node) {
    const target = node.role === 'portal' ? 'xray' : 'xray-bridge';
    const output = await ok(id, `sha256sum /usr/local/etc/${target}/config.json; stat -c '%i' /usr/local/etc/${target}/config.json; systemctl show ${target}.service -p MainPID -p ExecMainStartTimestampMonotonic -p NRestarts -p ActiveState -p SubState; sha256sum /usr/local/etc/${target === 'xray' ? 'xray-bridge' : 'xray'}/config.json`);
    return output;
}
async function executePlan(plan, label, expectNoop = false) {
    activeLabel = label; sequence++;
    const op = `anyorder-${sequence}`, generation = randomUUID();
    const fence = freeze({ owner: cfg.runId, attempt: 1, generation });
    const contexts = plan.nodes.map(n => freeze({ operationId: op, topologyRevision: sequence,
        priorDeployedRevision: sequence - 1, executionFence: fence,
        node: { ...n, candidateHash: n.candidate.sha256 } }));
    if (sequence === 1) {
        let dispatch = 0;
        const closed = new TopologyOperationExecutor({ target: 'test', hostIdentity: 'test.infograd.online',
            nodeExecutionResolver: { async resolve() { dispatch++; throw Error('must not dispatch'); } } });
        await assert.rejects(closed.prepare(contexts[0]), e => e.code === 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' && e.remoteOutcomeUncertain === false);
        assert.equal(dispatch, 0);
        ledger({ kind: 'native-authority-refusal', status: 'expected-refusal', code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', dispatch });
    }
    const records = new Map(contexts.map(c => [c.node.node, freeze({
        operationId: op, nodeId: c.node.node, topologyRevision: sequence, priorDeployedRevision: sequence - 1,
        candidateHash: `sha256:${c.node.candidateHash}`,
        backupId: `topology-${sha([op, c.node.node, `sha256:${c.node.candidateHash}`, c.node.targetProfile].join('\0'))}`,
        targetProfile: c.node.targetProfile, executionContext: 'test.infograd.online', ...fence,
        attemptId: `attempt-${sequence}`, predecessorGeneration: heads.get(c.node.node) || 'none',
        bootId: cfg.nodes[c.node.node].bootId, maintenanceId: cfg.runId,
        commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(command => [command, `${command}-${sequence}-${c.node.node}`])),
    })]));
    const reader = {
        async readVerified(expected) { return records.get(expected.nodeId); },
        async readVerifiedConnection(expected) { return freeze({ binding: records.get(expected.nodeId), connection: cfg.nodes[expected.nodeId].pin }); },
        async withVerifiedBinding(expected, fn) { return fn(records.get(expected.nodeId), async () => {}); },
    };
    const executor = new TopologyOperationExecutor({ target: 'test', hostIdentity: 'test.infograd.online',
        executionBindingReader: reader, RunnerBootstrapper: SyntheticFixtureBootstrapper,
        nodeExecutionResolver: { async resolve({ nodeId }, pin) {
            assert.deepEqual(pin, cfg.nodes[nodeId].pin);
            return { exec: (command, options) => exec(nodeId, command, options) };
        } } });
    const before = new Map();
    for (const c of contexts) before.set(c.node.node, await status(c.node.node, c.node));
    const lifecycle = [];
    for (const c of contexts) { const p = await executor.prepare(c); lifecycle.push({ ...c, backupId: p.backupId, prepared: p.prepared }); }
    for (const c of lifecycle) await executor.commit(c);
    for (const c of lifecycle) await executor.verify(c);
    const evidence = [];
    for (const c of lifecycle) {
        const proof = await executor.close(c);
        assert.ok(isTopologyTerminalProof(proof)); assert.equal(proof.terminalOutcome, 'verified');
        heads.set(c.node.node, generation);
        const bytes = await ok(c.node.node, `cat ${shell(c.node.configPath)}`);
        assert.equal(sha(bytes), c.node.candidate.sha256);
        const afterStatus = await status(c.node.node, c.node);
        if (expectNoop) assert.equal(afterStatus, before.get(c.node.node), `${c.node.node} byte-noop replaced inode/restarted/changed peer`);
        const afterLines = afterStatus.trim().split('\n'), beforeLines = before.get(c.node.node).trim().split('\n');
        assert.equal(afterLines.at(-1), beforeLines.at(-1), 'unselected other profile must remain byte-identical');
        evidence.push({ node: c.node.node, configSha256: c.node.candidate.sha256, checks: c.node.checks,
            before: before.get(c.node.node), after: afterStatus, proof });
        const node = state.nodes.find(n => n.id === c.node.node);
        if (node) node.profileConfig = JSON.parse(bytes);
    }
    ledger({ kind: 'plan', label, operationId: op, generation, authority: 'synthetic-frozen-local-only',
        executor: 'real', noop: expectNoop, staged: plan.staged, routeState: plan.routeState, evidence, status: 'passed' });
}
async function transition(links, label, kind = 'link.apply', noop = false) {
    const before = structuredClone(state);
    const after = { ...structuredClone(state), links: structuredClone(links) };
    const plan = await materialize(before, after, kind);
    fs.writeFileSync(path.join(work, `plan-${sequence + 1}.private.json`), JSON.stringify(plan));
    await executePlan(plan, label, noop);
    state.links = structuredClone(links);
}
async function traffic(domain, expected, label) {
    const nonce = randomUUID();
    let last, observed;
    const max = expected ? 10 : 2;
    for (let attempt = 0; attempt < max; attempt++) {
        last = await exec('p', `curl --silent --show-error --connect-timeout 1 --max-time 2 --socks5-hostname 127.0.0.1:10808 ${shell(`http://${domain}:18080/probe?nonce=${nonce}`)}`);
        if (last.code === 0) { observed = JSON.parse(last.stdout); break; }
        if (expected) await new Promise(resolve => setTimeout(resolve, 500));
    }
    if (expected) {
        assert.equal(last.code, 0, `traffic ${label} failed exit=${last.code}`);
        assert.equal(observed.role, expected, `traffic ${label} selected wrong exit/direct canary`);
        assert.equal(observed.identity, cfg.nodes[expected].machineId);
        assert.equal(observed.peer, '127.0.0.1'); assert.equal(observed.nonce, nonce);
    } else assert.notEqual(last.code, 0, `incomplete ${label} leaked to ${observed?.role}`);
    ledger({ kind: 'traffic', label, domain, expected: expected || 'blocked', code: last.code,
        response: observed || null, status: 'passed', proof: 'private-loopback-only-not-public-country-egress' });
}
async function checkRoute(graph, label) {
    const ids = new Set(graph.map(l => l.id));
    const reachesR = ids.has('pr');
    const def = ids.has('pb1') || (reachesR && ids.has('rb1'));
    const geo = reachesR && ids.has('rb2');
    await traffic('127.0.0.1', def ? 'b1' : null, label + ':default');
    await traffic('geo.anyorder.test', geo ? 'b2' : (def ? 'b1' : null), label + ':geo');
}
async function main() {
    // Compare used package versions, retaining lock digests; no install/build.
    const desired = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json')));
    const installed = JSON.parse(fs.readFileSync('/deps/.package-lock.json'));
    const drift = Object.entries(desired.packages || {}).filter(([k, v]) => k && !v.optional && v.version && installed.packages[k]?.version !== v.version)
        .map(([k, v]) => ({ name: k, expected: v.version, actual: installed.packages[k]?.version || null }));
    fs.writeFileSync(path.join(work, 'dependency-parity.json'), JSON.stringify({ lockSha256: sha(fs.readFileSync(path.join(root, 'package-lock.json'))),
        installedLockSha256: sha(fs.readFileSync('/deps/.package-lock.json')), drift }, null, 2));
    assert.deepEqual(drift, []);
    for (const [id, n] of Object.entries(cfg.nodes)) {
        const ssh = new NodeSSH({ _id: n.nodeId, name: `${cfg.runId}-${id}`, ip: n.ip,
            ssh: { port: 22, username: 'root', privateKey: cfg.sshPrivateKey } }, n.pin);
        ssh.usePool = false; await ssh.connect(); connections.set(id, ssh);
        assert.equal((await ok(id, 'cat /etc/machine-id')).trim(), n.machineId);
        assert.equal((await ok(id, 'cat /proc/sys/kernel/random/boot_id')).trim(), n.bootId);
        assert.equal((await ok(id, 'ip -4 route show default')).trim(), '', 'fixture must have no public default route');
        const own = JSON.parse(await ok(id, 'curl --silent --show-error --max-time 2 http://127.0.0.1:18080/?nonce=canary'));
        assert.equal(own.role, id);
    }
    // Seed is fixture-only; every subsequent install uses the unchanged native executor/runner.
    const initial = await materialize({ nodes: [], links: [], groups: [] }, state);
    for (const n of initial.nodes) {
        const config = JSON.parse(Buffer.from(n.candidate.bytes));
        if (n.node === 'p') config.inbounds.find(i => i.tag === 'client-p').settings.clients = [{ id: cfg.clientUuid, email: 'synthetic@anyorder.invalid' }];
        const bytes = JSON.stringify(config) + '\n';
        await connections.get(n.node).writeFile(n.configPath, bytes);
        await ok(n.node, `chmod 0644 ${shell(n.configPath)}; /usr/local/bin/xray run -test -config ${shell(n.configPath)} && systemctl start ${n.serviceUnit}`);
        state.nodes.find(row => row.id === n.node).profileConfig = config;
    }
    const client = { log: { loglevel: 'warning' }, inbounds: [{ tag: 'fixture-socks', listen: '127.0.0.1', port: 10808,
        protocol: 'socks', settings: { auth: 'noauth', udp: false } }], outbounds: [{ protocol: 'vless',
        settings: { vnext: [{ address: cfg.nodes.p.ip, port: 24443, users: [{ id: cfg.clientUuid, encryption: 'none' }] }] },
        streamSettings: { network: 'tcp', security: 'none' } }] };
    await connections.get('p').writeFile('/root/anyorder-client.json', JSON.stringify(client));
    await ok('p', '/usr/local/bin/xray run -test -config /root/anyorder-client.json && systemctl start anyorder-client.service');
    const scenarios = [
        ['G1-forward', ['pb1'], ['forward']], ['G1-reverse', ['pb1'], ['reverse']],
        ['G2-output-first-forward', ['rb1', 'pr'], ['forward', 'forward']],
        ['G2-output-first-reverse', ['rb1', 'pr'], ['reverse', 'reverse']],
        ['G2-output-first-mixed', ['rb1', 'pr'], ['reverse', 'forward']],
        ['G3-output-first-forward', ['rb1', 'rb2', 'pr'], ['forward', 'forward', 'forward']],
        ['G3-output-first-reverse', ['rb1', 'rb2', 'pr'], ['reverse', 'reverse', 'reverse']],
        ['G3-output-first-mixed', ['rb1', 'rb2', 'pr'], ['reverse', 'forward', 'reverse']],
    ];
    fs.writeFileSync(path.join(work, 'matrix.json'), JSON.stringify(scenarios, null, 2));
    for (const [name, order, modes] of scenarios) {
        let graph = [];
        for (let i = 0; i < order.length; i++) {
            graph.push({ ...baseLinks.find(l => l.id === order[i]), mode: modes[i] });
            await transition(graph, `${name}:add:${order[i]}`);
            await checkRoute(graph, `${name}:add:${order[i]}`);
        }
        await transition(graph, `${name}:noop`, 'link.apply', true);
        await checkRoute(graph, `${name}:noop`);
        for (const edge of [...graph]) {
            const reduced = graph.filter(l => l.id !== edge.id);
            await transition(reduced, `${name}:delete:${edge.id}`, 'link.delete');
            await checkRoute(reduced, `${name}:delete:${edge.id}`);
            const restored = [...reduced, edge];
            await transition(restored, `${name}:recreate:${edge.id}`);
            await checkRoute(restored, `${name}:recreate:${edge.id}`);
            graph = restored;
        }
        await transition([], `${name}:delete-all`, 'link.delete');
        await checkRoute([], `${name}:delete-all`);
        ledger({ kind: 'scenario', name, order, modes, status: 'passed' });
        console.log(JSON.stringify({ scenario: name, status: 'passed' }));
    }
    fs.writeFileSync(path.join(work, 'result.json'), JSON.stringify({ status: 'passed', scenarios: scenarios.length,
        planExecutions: sequence, nativeRuntimeAuthority: 'unavailable-expected-refusal',
        authorityAdapter: 'synthetic-frozen-local-only', actual: ['materializer', 'compiler', 'composer', 'executor', 'transport', 'NodeSSH', 'runner', 'systemd', 'Xray', 'private-HTTP'],
        notProved: ['public POST/manual jobs', 'Mongo/worker settlement', 'physical enrollment/maintenance authority', 'PPP', 'REALITY', 'browser/assets', 'all permutations', 'country Internet exit', 'background writer compatibility', 'migration/rollback'] }, null, 2));
}
main().catch(error => {
    const failure = { status: 'failed', label: activeLabel, error: causal(error), sequence };
    fs.writeFileSync(path.join(work, 'failure.json'), JSON.stringify(failure, null, 2));
    console.error(JSON.stringify(failure)); process.exitCode = 1;
}).finally(() => {
    for (const ssh of connections.values()) ssh.disconnect();
    requireCandidate('src/services/sshPoolService').closeAll();
    requireCandidate('src/utils/logger').close();
});
