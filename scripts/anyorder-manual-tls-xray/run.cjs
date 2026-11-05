'use strict';
// REAL public import producer + generator/materializer/executor/SSH/runner/Xray.
// SYNTHETIC local query persistence, external maintenance and binding authority.
// No native physical controller, Mongo, HTTP jobs, worker or PPP acceptance.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {createHash, randomUUID, randomBytes} = require('node:crypto');
const {model} = require('./owner-model.cjs');
const root = process.env.C3_CANDIDATE_ROOT, work = process.env.C3_FIXTURE_WORK;
const candidate = name => require(path.join(root, name));
const generator = candidate('src/services/configGenerator');
const {TopologyConfigTransfer, verifyLegacyAppliedProfile} = candidate('src/services/topologyConfigTransfer');
const {TEST_TOPOLOGY_EXECUTION_CONTEXT: context} = candidate('src/modules/relay-l2tp/domain/topologyExecutionContext');

const {TopologyOperationPlanMaterializer} = candidate('src/modules/relay-l2tp/services/topologyOperationPlanMaterializer');
const {compileTopology} = candidate('src/modules/relay-l2tp/domain/topologyCompiler');
const {TopologyOperationExecutor, isTopologyTerminalProof} = candidate('src/modules/relay-l2tp/services/topologyOperationExecutor');
const {TOPOLOGY_RUNNER_PATH, TOPOLOGY_RUNNER_SHA256} = candidate('src/modules/relay-l2tp/services/topologyRunnerBootstrapper');
const NodeSSH = candidate('src/services/nodeSSH');
const cfg = JSON.parse(fs.readFileSync(path.join(work, 'fixture.private.json')));
const copy = value => structuredClone(value);
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = value => createHash('sha256').update(value).digest('hex');
const shell = value => "'" + value.replaceAll("'", "'\\''") + "'";
const save = (name, value) => fs.writeFileSync(path.join(work, name), JSON.stringify(value, null, 2) + '\n');
const ledger = row => fs.appendFileSync(path.join(work, 'cases.jsonl'), JSON.stringify({...row, security: cfg.security}) + '\n');
const connections = new Map(), heads = new Map(), originals = new Map();
let label = 'setup', sequence = 0, selectedOwners;
function causal(error) { return {name: error.name, code: error.code, message: error.message.slice(0, 2000),
    uncertain: error.remoteOutcomeUncertain, ...(error.cause ? {cause: causal(error.cause)} : {})}; }
async function exec(id, command, options) {
    const result = await connections.get(id).exec('env GOMAXPROCS=2 sh -c ' + shell(command), options);
    const action = command.match(/--command ([a-z-]+)/)?.[1] || (command.startsWith('curl ') ? 'http-probe' : 'fixture-read-or-setup');
    let receipt;
    if (command.includes('--command ')) { try { receipt = JSON.parse(result.stdout); } catch {} }
    if (receipt) fs.appendFileSync(path.join(work, 'runner-responses.jsonl'), JSON.stringify({label, node: id, action, raw: result.stdout, sha256: sha(result.stdout)}) + '\n');
    fs.appendFileSync(path.join(work, 'ssh-exits.jsonl'), JSON.stringify({label, node: id, action, code: result.code,
        stdoutSha256: sha(result.stdout || ''), stderr: result.stderr.slice(0, 2000), ...(receipt ? {receipt} : {})}) + '\n');
    return result;
}
async function ok(id, command, options) {
    const r = await exec(id, command, options);
    assert.equal(r.code, 0, `node=${id} command=${command.split(' ')[0]} stderr=${r.stderr}`);
    return r.stdout;
}
async function profile(id, name) {
    const service = name === 'main' ? 'xray' : 'xray-bridge';
    const config = await ok(id, `cat /usr/local/etc/${service}/config.json`);
    const unit = await ok(id, `cat /etc/systemd/system/${service}.service`);
    const identity = await ok(id, `stat -c '%i' /usr/local/etc/${service}/config.json; systemctl show ${service}.service -p MainPID -p ExecMainStartTimestampMonotonic -p NRestarts -p ActiveState -p SubState; systemctl is-enabled ${service}.service`);
    assert.match(identity, /ActiveState=active/); assert.match(identity, /SubState=running/);
    assert.match(identity, /MainPID=[1-9][0-9]*/); assert.match(identity, /enabled/);
    return {config, unit, identity};
}
const nodes = Object.entries(cfg.nodes).map(([id, n]) => ({id: n.nodeId, role: n.role, type: 'xray', active: true,
    ip: n.ip, port: 24443, domain: cfg.manualTls.domain,
    xray: {inboundTag: 'client-in', security: id === 'p' && cfg.variant === 'primary' ? 'tls' : 'none', transport: 'tcp', extraInbounds: [],
        ...(id === 'p' ? {tlsSource: 'manual', manualCert: cfg.manualTls.cert, manualKey: cfg.manualTls.key,
            alpn: ['http/1.1', 'h2'], flow: 'xtls-rprx-vision',
            extraInbounds: cfg.variant === 'extra' ? [{id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', inboundTag: 'tls-extra', port: 24444,
                security: 'tls', transport: 'tcp', alpn: ['h2', 'http/1.1'], flow: 'xtls-rprx-vision'}] : []} : {})}}));
const selected = id => id === 'p' ? 'main' : 'sidecar';
const independent = id => id === 'p' ? 'sidecar' : 'main';
const target = id => selected(id) === 'main' ? 'xray-main' : 'xray-bridge';
const short = nodeId => Object.entries(cfg.nodes).find(([, n]) => n.nodeId === nodeId)[0];
const metadata = node => ({...copy(node), _id: node.id, cascadeRole: node.role});
const realityFields = {realityPrivateKey: cfg.reality.privateKey, realityPublicKey: cfg.reality.publicKey,
    realityShortIds: [cfg.reality.shortId], realityDest: '127.0.0.1:18443', realitySni: [cfg.reality.serverName], realityFingerprint: 'chrome'};
const link = {id: randomBytes(12).toString('hex'), source: nodes.find(n => n.role === 'portal').id,
    target: nodes.find(n => n.role === 'bridge').id, mode: 'reverse', active: true, priority: 1,
    tunnelPort: 25000, tunnelUuid: randomUUID(), tunnelSecurity: cfg.security, tunnelTransport: 'tcp',
    ...(cfg.security === 'reality' ? realityFields : {})};
let state = {nodes, links: [link], groups: []};
const noReads = {find() { assert.fail('frozen descriptor composition must not query mutable desired metadata'); }};
const materializer = new TopologyOperationPlanMaterializer({HyNode: noReads, CascadeLink: noReads});
async function materialize(before, after, kind) {
    return materializer.materialize({...context, operationKind: kind,
        pinnedSnapshot: {revision: sequence + 1, topology: after, compiled: compileTopology(after)},
        baselineTopology: before, effectiveTopology: after, selectedOwnerPins: selectedOwners});
}
class SyntheticFixtureBootstrapper {
    constructor({nodeSSH}) { this.ssh = nodeSSH; }
    async ensureRunner() {
        const r = await this.ssh.exec(`sha256sum ${TOPOLOGY_RUNNER_PATH}`);
        assert.equal(r.code, 0); assert.equal('sha256:' + r.stdout.split(' ')[0], TOPOLOGY_RUNNER_SHA256);
    }
}
async function execute(plan, name, noop) {
    label = name; sequence++;
    const op = `manual-tls-${sequence}`, generation = randomUUID(), fence = freeze({owner: cfg.runId, attempt: 1, generation});
    const contexts = plan.nodes.map(n => freeze({operationId: op, topologyRevision: sequence, priorDeployedRevision: sequence - 1,
        executionFence: fence, node: {...n, candidateHash: n.candidate.sha256}}));
    if (sequence === 1) {
        let dispatch = 0;
        const closed = new TopologyOperationExecutor({...context, nodeExecutionResolver: {async resolve() { dispatch++; assert.fail('must not dispatch'); }}});
        await assert.rejects(closed.prepare(contexts[0]), error => error.code === 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' && error.remoteOutcomeUncertain === false);
        assert.equal(dispatch, 0);
        ledger({kind: 'no-reader-control', dispatch, code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', status: 'expected-refusal'});
    }
    // This is the existing independent physical-fixture adapter, NOT enrollment.
    const records = new Map(contexts.map(c => [c.node.node, freeze({operationId: op, nodeId: c.node.node,
        topologyRevision: sequence, priorDeployedRevision: sequence - 1, candidateHash: `sha256:${c.node.candidateHash}`,
        backupId: `topology-${sha([op, c.node.node, `sha256:${c.node.candidateHash}`, c.node.targetProfile].join('\0'))}`,
        targetProfile: c.node.targetProfile, executionContext: context.hostIdentity, ...fence,
        attemptId: `attempt-${sequence}`, predecessorGeneration: heads.get(c.node.node) || 'none',
        bootId: cfg.nodes[short(c.node.node)].bootId, maintenanceId: cfg.runId,
        commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(command => [command, `${command}-${sequence}-${short(c.node.node)}`]))})]));
    const reader = {async readVerified(expected) { return records.get(expected.nodeId); },
        async readVerifiedConnection(expected) { return freeze({binding: records.get(expected.nodeId), connection: cfg.nodes[short(expected.nodeId)].pin}); },
        async withVerifiedBinding(expected, fn) { return fn(records.get(expected.nodeId), async () => {}); }};
    const executor = new TopologyOperationExecutor({...context, executionBindingReader: reader, RunnerBootstrapper: SyntheticFixtureBootstrapper,
        nodeExecutionResolver: {async resolve({nodeId}, pin) { const id = short(nodeId); assert.deepEqual(pin, cfg.nodes[id].pin);
            return {exec: (command, options) => exec(id, command, options)}; }}});
    const before = new Map();
    for (const c of contexts) {
        assert.equal(c.node.targetProfile, target(short(c.node.node)));
        assert.equal(Object.hasOwn(c.node, 'profileTargetPin'), false, 'reverse uses native role-default targets, not forward pins');
        assert.equal(c.node.targetProfile, selectedOwners.find(o => o.node === c.node.node).profile);
        before.set(c.node.node, await profile(short(c.node.node), selected(short(c.node.node))));
    }
    const lifecycle = [];
    for (const c of contexts) { const p = await executor.prepare(c); lifecycle.push({...c, backupId: p.backupId, prepared: p.prepared}); }
    for (const c of lifecycle) await executor.commit(c);
    for (const c of lifecycle) await executor.verify(c);
    const evidence = [];
    for (const c of lifecycle) {
        const proof = await executor.close(c);
        assert.ok(isTopologyTerminalProof(proof)); assert.equal(proof.terminalOutcome, 'verified');
        heads.set(c.node.node, generation);
        const id = short(c.node.node), actual = await profile(id, selected(id));
        assert.equal(actual.config, Buffer.from(c.node.candidate.bytes).toString());
        assert.equal(sha(actual.config), c.node.candidate.sha256);
        assert.equal(actual.unit, originals.get(id)[selected(id)].unit);
        if (noop) assert.deepEqual(actual, before.get(c.node.node), 'byte-noop changed bytes/inode/PID/start/restarts/unit');
        const original = JSON.parse(originals.get(id)[selected(id)].config), current = JSON.parse(actual.config);
        for (const tag of ['client-in', 'tls-extra', 'unrelated-in']) assert.deepEqual(current.inbounds.find(i => i.tag === tag), original.inbounds.find(i => i.tag === tag));
        assert.deepEqual(current.policy, original.policy);
        assert.deepEqual(current.outbounds.find(o => o.tag === 'unrelated-out'), original.outbounds.find(o => o.tag === 'unrelated-out'));
        assert.deepEqual(current.routing.rules.filter(r => r.outboundTag === 'unrelated-out'), original.routing.rules.filter(r => r.outboundTag === 'unrelated-out'));
        const other = await profile(id, independent(id));
        assert.deepEqual(other, originals.get(id)[independent(id)], 'independent nonempty profile bytes/unit/inode/PID/start/restarts changed');
        state.nodes.find(n => n.id === c.node.node).profileConfig = actual.config;
        evidence.push({node: id, configSha256: sha(actual.config), checks: c.node.checks, profileTargetPin: c.node.profileTargetPin,
            before: {...before.get(c.node.node), config: sha(before.get(c.node.node).config)},
            after: {...actual, config: sha(actual.config)}, selectedProfile: target(id), independentProfile: independent(id), otherSha256: sha(other.config), otherIdentity: other.identity, proof});
    }
    ledger({kind: 'plan', label, operationId: op, noop, evidence, status: 'passed'});
}
async function transition(links, name, kind = 'link.apply', noop = false) {
    label = name;
    const before = copy(state), after = {...copy(state), links: copy(links)};
    const plan = await materialize(before, after, kind);
    save(`plan-${sequence + 1}.private.json`, plan);
    await execute(plan, name, noop); state.links = copy(links);
}
async function traffic(port, expected, name) {
    const nonce = randomUUID(); let last, observed;
    // Unrelated selected-profile clients retain classic private-IP protection.
    // A TEST-only benchmark address is redirected by their own frozen freedom
    // outbound to the local witness; no packet leaves the private stand.
    const destination = name.includes(':selected-fragment-') ? '198.18.35.1' : '127.0.0.1';
    for (let attempt = 0; attempt < (expected ? 10 : 2); attempt++) {
        last = await exec('p', `curl --silent --show-error --connect-timeout 1 --max-time 2 --socks5-hostname 127.0.0.1:${port} ${shell(`http://${destination}:18080/probe?nonce=${nonce}`)}`);
        fs.appendFileSync(path.join(work, 'http-results.jsonl'), JSON.stringify({label: name, nonce, port, expected, code: last.code, raw: last.stdout, sha256: sha(last.stdout)}) + '\n');
        if (last.code === 0) { observed = JSON.parse(last.stdout); break; }
        if (expected) await new Promise(resolve => setTimeout(resolve, 400));
    }
    if (expected) {
        assert.equal(last.code, 0, `traffic ${name} failed exit=${last.code}`);
        assert.equal(observed.role, expected, `wrong exit/direct fallback for ${name}`);
        assert.equal(observed.identity, cfg.nodes[expected].machineId); assert.equal(observed.nonce, nonce);
        assert.equal(observed.peer, '127.0.0.1');
    } else assert.notEqual(last.code, 0, `deleted selected route leaked to ${observed?.role}`);
    ledger({kind: 'traffic', label: name, port, expected: expected || 'blocked', nonce, rawSha256: sha(last.stdout), code: last.code, response: observed || null, status: 'passed'});
}
async function probes(stage, selected = 'b') {
    const certificate = JSON.parse(await ok('p', `python3 /root/manual-cert-check.py ${cfg.variant === 'primary' ? 24443 : 24444}`));
    save(`certificate-${stage}.json`, certificate);
    if (stage === 'baseline') save('certificate-validation.json', certificate);
    ledger({kind: 'certificate', label: stage, ...certificate});
    await traffic(10808, selected, `${stage}:selected`);
    if (cfg.variant === 'extra') await traffic(10807, selected, `${stage}:primary-none`);
    for (const [id, port] of [['p', 10811], ['b', 10812]]) await traffic(port, id, `${stage}:selected-fragment-${id}`);
    for (const [id, port] of [['p', 10821], ['b', 10822]]) await traffic(port, id, `${stage}:independent-${id}`);
}
async function artifacts(stage, activeLink) {
    const sockets = await ok('p', 'ss -H -lntp');
    const has = port => sockets.split('\n').some(line => line.trim().split(/\s+/)[3]?.endsWith(':' + port));
    assert.equal(has(link.tunnelPort), !!activeLink && activeLink.id === link.id);
    if (activeLink && activeLink.id !== link.id) assert.equal(has(activeLink.tunnelPort), true);
    let newArtifacts = 0;
    for (const id of ['p', 'b']) {
        const main = await profile(id, selected(id)), other = await profile(id, independent(id));
        const parsed = JSON.parse(main.config);
        assert.equal(JSON.parse(other.config).inbounds.some(i => i.port === link.tunnelPort || i.port === activeLink?.tunnelPort), false);
        if (!activeLink || activeLink.id !== link.id) {
            assert.equal(main.config.includes(link.tunnelUuid), false);
            for (const key of [link.id.slice(-8), sha('celerity-topology-link:' + link.id).slice(0, 8)])
                assert.equal(main.config.includes(key), false, 'old generated identity survived');
        }
        if (activeLink) {
            assert.ok(main.config.includes(activeLink.tunnelUuid));
            const key = activeLink.id === link.id ? link.id.slice(-8) : sha('celerity-topology-link:' + activeLink.id).slice(0, 8);
            assert.ok(main.config.includes(key)); newArtifacts++;
            if (id === 'p') {
                const inbound = parsed.inbounds.find(i => i.port === activeLink.tunnelPort);
                assert.equal(inbound.settings.clients[0].id, activeLink.tunnelUuid);
                assert.equal(inbound.streamSettings.security, cfg.security);
                if (cfg.security === 'reality') assert.equal(inbound.streamSettings.realitySettings.privateKey, activeLink.realityPrivateKey);
            }
        }
    }
    ledger({kind: 'artifacts', label: stage, oldListenerPresent: has(link.tunnelPort), newArtifacts,
        ...(activeLink ? {id: activeLink.id, port: activeLink.tunnelPort, credentialSha256: sha(activeLink.tunnelUuid)} : {}), status: 'passed'});
}
async function main() {
    const desired = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'))), installed = JSON.parse(fs.readFileSync('/deps/.package-lock.json'));
    const drift = Object.entries(desired.packages || {}).filter(([k, v]) => k && !v.optional && v.version && installed.packages[k]?.version !== v.version)
        .map(([k, v]) => ({name: k, expected: v.version, actual: installed.packages[k]?.version || null}));
    save('dependency-parity.json', {lockSha256: sha(fs.readFileSync(path.join(root, 'package-lock.json'))), installedLockSha256: sha(fs.readFileSync('/deps/.package-lock.json')), drift});
    assert.deepEqual(drift, []);
    const versions = {};
    for (const [id, n] of Object.entries(cfg.nodes)) {
        const ssh = new NodeSSH({_id: n.nodeId, name: cfg.runId + '-' + id, ip: n.ip,
            ssh: {port: 22, username: 'root', privateKey: cfg.sshPrivateKey}}, n.pin);
        ssh.usePool = false; await ssh.connect(); connections.set(id, ssh);
        assert.equal((await ok(id, 'cat /etc/machine-id')).trim(), n.machineId);
        assert.equal((await ok(id, 'cat /proc/sys/kernel/random/boot_id')).trim(), n.bootId);
        assert.equal((await ok(id, 'ip -4 route show default')).trim(), '');
        versions[id] = await ok(id, '/usr/local/bin/xray version; sha256sum /usr/local/bin/xray /usr/local/bin/celerity-topology-node-runner-v2');
        const own = JSON.parse(await ok(id, 'curl --silent --show-error --max-time 2 http://127.0.0.1:18080/?nonce=canary'));
        assert.equal(own.role, id); assert.equal(own.identity, n.machineId); assert.equal(own.nonce, 'canary');
        const tls = JSON.parse(await ok(id, `python3 -c ${shell("import socket,ssl,json; c=ssl.create_default_context(cafile='/root/anyorder-tls.crt'); c.set_alpn_protocols(['h2']); s=c.wrap_socket(socket.create_connection(('127.0.0.1',18443),timeout=3),server_hostname='reality.anyorder.test'); print(json.dumps({'version':s.version(),'alpn':s.selected_alpn_protocol(),'certificateBytes':len(s.getpeercert(binary_form=True))})); s.close()")}`));
        assert.equal(tls.version, 'TLSv1.3'); assert.equal(tls.alpn, 'h2'); assert.ok(tls.certificateBytes > 512);
        save(`tls-${id}.json`, tls);
    }
    save('binary-pins-readback.json', {node: process.version, versions});
    const client = {log: {loglevel: 'warning'}, inbounds: [], outbounds: [], routing: {rules: []}};
    function clientRoute(port, id, serverPort, uuid, tls = false) {
        const tag = `probe-${port}`;
        client.inbounds.push({tag, listen: '127.0.0.1', port, protocol: 'socks', settings: {auth: 'noauth', udp: false}});
        client.outbounds.push({tag, protocol: 'vless', settings: {vnext: [{address: cfg.nodes[id].ip, port: serverPort,
            users: [{id: uuid, encryption: 'none', ...(tls ? {flow: 'xtls-rprx-vision'} : {})}]}]},
            streamSettings: {network: 'tcp', security: tls ? 'tls' : 'none', ...(tls ? {tlsSettings: {
                serverName: cfg.manualTls.domain, alpn: ['http/1.1', 'h2'], disableSystemRoot: true,
                certificates: [{certificate: cfg.manualTls.cert.trim().split('\n'), usage: 'verify'}]}} : {})}});
        client.routing.rules.push({type: 'field', inboundTag: [tag], outboundTag: tag});
    }
    const populated = {...copy(link), _id: link.id, portalNode: metadata(nodes.find(n => n.role === 'portal')), bridgeNode: metadata(nodes.find(n => n.role === 'bridge'))};
    for (const node of nodes) {
        const id = short(node.id), unrelatedUuid = randomUUID(), otherUuid = randomUUID();
        let base;
        if (id === 'p') {
            base = JSON.parse(generator.generateXrayConfig(metadata(node), [{xrayUuid: cfg.clientUuid, userId: 'TEST-existing@invalid'}]));
            generator.applyReversePortal(base, [populated], ['client-in', ...(cfg.variant === 'extra' ? ['tls-extra'] : [])]);
        } else base = JSON.parse(generator.generateCombinedBridgeConfig([populated]));
        base.inbounds ||= [];
        base.inbounds.push({tag: 'unrelated-in', listen: '0.0.0.0', port: 24543, protocol: 'vless',
            settings: {clients: [{id: unrelatedUuid, email: `independent-${id}@invalid`}], decryption: 'none'}, streamSettings: {network: 'tcp', security: 'none'}});
        base.outbounds.push({tag: 'unrelated-out', protocol: 'freedom', settings: {redirect: '127.0.0.1:18080'}});
        base.routing.rules.push({type: 'field', inboundTag: ['unrelated-in'], outboundTag: 'unrelated-out'});
        base.policy = {levels: {0: {statsUserUplink: true, statsUserDownlink: true}}};
        node.profileConfig = JSON.stringify(base, null, 2) + '\n';
        const other = {log: {loglevel: 'warning'}, inbounds: [{tag: 'independent-other', listen: '0.0.0.0', port: 24643, protocol: 'vless',
            settings: {clients: [{id: otherUuid, email: `other-${id}@invalid`}], decryption: 'none'}, streamSettings: {network: 'tcp', security: 'none'}}],
            outbounds: [{tag: 'other-independent-out', protocol: 'freedom'}], routing: {rules: [{type: 'field', inboundTag: ['independent-other'], outboundTag: 'other-independent-out'}]}};
        for (const [name, bytes] of [[selected(id), node.profileConfig], [independent(id), JSON.stringify(other, null, 2) + '\n']]) {
            const service = name === 'main' ? 'xray' : 'xray-bridge';
            await connections.get(id).writeFile(`/usr/local/etc/${service}/config.json`, bytes);
            await ok(id, `chmod 0600 /usr/local/etc/${service}/config.json; /usr/local/bin/xray run -test -config /usr/local/etc/${service}/config.json && systemctl enable ${service}.service && systemctl start ${service}.service`);
        }
        originals.set(id, {main: await profile(id, 'main'), sidecar: await profile(id, 'sidecar')});
        clientRoute(id === 'p' ? 10811 : 10812, id, 24543, unrelatedUuid);
        clientRoute(id === 'p' ? 10821 : 10822, id, 24643, otherUuid);
    }
    clientRoute(10808, 'p', cfg.variant === 'primary' ? 24443 : 24444, cfg.clientUuid, true);
    if (cfg.variant === 'extra') clientRoute(10807, 'p', 24443, cfg.clientUuid);
    await connections.get('p').writeFile('/root/anyorder-client.json', JSON.stringify(client));
    await ok('p', 'chmod 0600 /root/anyorder-client.json; /usr/local/bin/xray run -test -config /root/anyorder-client.json && systemctl start anyorder-client.service');
    save('client-config.private.json', client); save('originals.private.json', Object.fromEntries(originals));
    const certCheck = await ok('p', `python3 /root/manual-cert-check.py ${cfg.variant === 'primary' ? 24443 : 24444}`);
    save('certificate-validation.json', JSON.parse(certCheck));
    const db = {transaction: fn => fn({inTransaction: () => true})}, Owner = model([], db);
    const transfer = new TopologyConfigTransfer({executionContext: context, TopologyConfigOwner: Owner,
        async withVerifiedMaintenance({binding, proofRef}, fn) {
            assert.equal(proofRef, 'SYNTHETIC-private-fixture-exclusion');
            const id = short(binding.node), name = binding.profile === 'xray-main' ? 'main' : 'sidecar', actual = await profile(id, name);
            assert.deepEqual(actual, originals.get(id)[name]);
            // Existing explicit synthetic external-hold seam; not physical exclusion.
            await fn({authority: 'external-maintenance-v1', status: 'verified', binding: copy(binding), proofId: randomUUID(), maintenanceId: randomUUID(),
                maintenance: 'held', allWriters: 'drained', oldBackend: {instanceId: 'SYNTHETIC-no-classic-backend', pid: 42, processStartTime: 'SYNTHETIC', processTree: 'stopped', dispatch: 'disabled'},
                readback: {source: 'node-readback', configSha256: sha(actual.config), unitSha256: sha(actual.unit), serviceActive: 'active', serviceEnabled: 'enabled'}});
        }});
    const owners = [], allOwners = [];
    for (const node of nodes) for (const name of [selected(short(node.id)), independent(short(node.id))]) {
        const id = short(node.id), profileName = name === 'main' ? 'xray-main' : 'xray-bridge', n = cfg.nodes[id];
        const classic = await transfer.initializeClassic({node: node.id, profile: profileName,
            nodeIdentity: {machineId: n.machineId, sshHostKeySha256: n.pin.expectedHostKeySha256}});
        assert.equal(classic.owner, 'classic'); assert.equal(classic.adoptionReceipt, undefined);
        const adopted = await transfer.adopt({node: node.id, profile: profileName, generation: classic.generation,
            proofRef: 'SYNTHETIC-private-fixture-exclusion', ...(name === selected(id) ? {legacyTopology: state} : {})});
        const confirmed = await Owner.findOne({node: node.id, profile: profileName}).select('+legacyAppliedTopology +profileTargetPin').lean();
        assert.deepEqual(confirmed, adopted); allOwners.push(freeze(copy(confirmed)));
        if (name === selected(id)) {
            assert.equal(Object.hasOwn(confirmed, 'profileTargetPin'), false);
            assert.deepEqual(verifyLegacyAppliedProfile(confirmed.legacyAppliedTopology, {node: node.id,
                profile: profileName, originalSnapshot: confirmed.originalSnapshot}), confirmed.legacyAppliedTopology);
            owners.push(freeze(copy(confirmed)));
        }
        assert.deepEqual(await profile(id, name), originals.get(id)[name], 'adoption wrote profile');
    }
    selectedOwners = freeze(owners.map(({legacyAppliedTopology, ...pin}) => copy(pin)));
    const immutable = sha(JSON.stringify(owners));
    save('public-import.private.json', owners); save('all-owners.private.json', allOwners);
    ledger({kind: 'public-import', owners: selectedOwners.map(o => ({node: o.node, profile: o.profile, generation: o.generation,
        originalSnapshot: o.originalSnapshot, adoptionReceiptSha256: sha(JSON.stringify(o.adoptionReceipt))})),
        authority: 'synthetic-external-hold/local-query-model', status: 'passed'});
    save('matrix.json', {security: cfg.security, stages: ['baseline', 'apply', 'noop', 'delete', 'recreate'], planStages: ['apply', 'noop', 'delete', 'recreate'], probesPerStage: cfg.variant === 'extra' ? 6 : 5, variant: cfg.variant});
    await probes('baseline'); await artifacts('baseline', link);
    await transition([link], 'apply'); await probes('apply'); await artifacts('apply', link);
    await transition([link], 'noop', 'link.apply', true); await probes('noop');
    await transition([], 'delete', 'link.delete'); await probes('delete', null); await artifacts('delete', null);
    const replacement = {...copy(link), id: randomBytes(12).toString('hex'), tunnelPort: link.tunnelPort + 200, tunnelUuid: randomUUID()};
    await transition([replacement], 'recreate'); await probes('recreate'); await artifacts('recreate', replacement);
    assert.notEqual(replacement.id, link.id); assert.notEqual(replacement.tunnelPort, link.tunnelPort); assert.notEqual(replacement.tunnelUuid, link.tunnelUuid);
    save('witnesses.json', Object.fromEntries(await Promise.all(['p', 'b'].map(async id => [id,
        (await ok(id, 'cat /root/witness.jsonl')).trim().split('\n').map(JSON.parse)]))));
    assert.equal(sha(JSON.stringify(owners)), immutable);
    assert.deepEqual(await Owner.find({}).select('+legacyAppliedTopology +profileTargetPin').lean(), allOwners);
    save('recreation.json', {oldId: link.id, newId: replacement.id, oldPort: link.tunnelPort, newPort: replacement.tunnelPort,
        oldCredentialSha256: sha(link.tunnelUuid), newCredentialSha256: sha(replacement.tunnelUuid), importedPinsUnchanged: true});
    ledger({kind: 'scenario', name: cfg.security, status: 'passed'});
    save('result.json', {status: 'passed', variant: cfg.variant, security: cfg.security, planExecutions: sequence, authorityAdapter: 'synthetic-external-hold/local-query-model/in-memory-bindings',
        actual: ['public initializeClassic/adopt/pin verifier', 'generator', 'compiler', 'materializer', 'composer', 'typed executor', 'NodeSSH', 'unchanged runner', 'systemd', 'Xray', 'certificate-validating TLS+Vision client', 'identity/nonce HTTP'],
        notProved: ['native physical authority', 'HTTP/Mongo/worker join', 'full deployment', 'PPP', 'public create ID allocation', 'background writer exclusion', 'Internet country exit', 'all permutations']});
}
main().catch(async error => {
    const failure = {status: 'failed', label, sequence, error: causal(error)}; save('failure.json', failure);
    for (const [id] of connections) { try { const d = await exec(id, 'systemctl status xray xray-bridge anyorder-client anyorder-tls --no-pager; journalctl -u xray -u xray-bridge -u anyorder-client -u anyorder-tls --no-pager -n 100; ss -lntp');
        fs.writeFileSync(path.join(work, `diagnostic-${id}.private.log`), d.stdout + d.stderr); } catch {} }
    console.error(JSON.stringify(failure)); process.exitCode = 1;
}).finally(() => { for (const ssh of connections.values()) ssh.disconnect(); candidate('src/services/sshPoolService').closeAll(); candidate('src/utils/logger').close(); });
