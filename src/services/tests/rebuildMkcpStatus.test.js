'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { Types: { ObjectId } } = require('mongoose');
const cascade = require('../cascadeService');
const Link = require('../../models/cascadeLinkModel');
const Node = require('../../models/hyNodeModel');
const sshPool = require('../sshPoolService');
const observation = require('../rebuildReverseLinkHealth');
const { appliedLink } = require('../rebuildAppliedLink');

test.after(() => sshPool.closeAll());

test('network drawer shows the localized action and parallel reads cannot carry TCP green into mKCP', () => {
    const source = readFileSync(join(__dirname, '../../../public/js/network.js'), 'utf8');
    const projection = source.match(/        for \(const e of edges\) \{[\s\S]*?\n        \}/)[0];
    const detail = source.match(/    function linkStateFields\(d\) \{[\s\S]*?\n    \}/)[0];
    const base = { linkId: 'link', source: 'a', target: 'b', status: 'online', mode: 'forward', tunnelTransport: 'tcp' };
    const kcp = { ...base, status: 'deployed', tunnelTransport: 'kcp', tunnelVerification: 'mkcp_runtime_unsupported' };
    function renderEdge(edge, link) {
        const elements = [];
        vm.runInNewContext(projection, { elements, rebuild: true, edges: [{ data: edge }],
            visibleNodeIds: new Set(['a', 'b']), confirmedDeletions: new Set(), listedLinkIds: new Set(['link']),
            _allLinks: [{ _id: 'link', ...link }], linkProgress: new Map(), buildEdgeLabel: () => '' });
        return elements[0].data;
    }
    for (const [edge, link] of [[base, kcp], [kcp, base]]) {
        const result = renderEdge(edge, link);
        assert.equal(result.status, 'pending');
        assert.equal(result.tunnelState, 'unknown');
        assert.equal(result.clientReadiness, undefined);
    }
    const active = renderEdge(kcp, kcp);
    assert.equal(active.status, 'deployed');
    assert.equal(active.tunnelState, 'unknown');
    for (const locale of ['en', 'ru', 'zh-CN']) {
        const i18n = require(`../../locales/${locale}.json`).network;
        const output = vm.runInNewContext(detail + '\nlinkStateFields(row)', { row: active, i18n, rebuild: true,
            CLIENT_READINESS_UNVERIFIED: 'unverified', field: (_, value) => String(value) + '\n', escHtml: String });
        assert.match(i18n.mkcpRuntimeUnsupported, /cc-agent 1\.5\.1.*mKCP/);
        assert.ok(output.includes(i18n.mkcpRuntimeUnsupported));
    }
});

const mkcp = mode => ({ _id: new ObjectId(), active: true, status: 'deployed', name: 'fixture',
    portalNode: new ObjectId(), bridgeNode: new ObjectId(), mode, tunnelTransport: 'kcp',
    tunnelProtocol: 'vless', tunnelSecurity: 'none', tunnelEncryption: 'none', tunnelPort: 43119,
    tunnelUuid: '00000000-0000-4000-8000-000000000001', updatedAt: new Date(), rebuildApplyEpoch: 'e'.repeat(32) });

test('stock agent authenticates the native reverse observation and refuses non-TCP/REALITY before stats', () => {
    const gitSource = name => readFileSync(join(__dirname, '../../../cc-agent', name), 'utf8');
    assert.match(gitSource('api.go'), /"GET \/rebuild\/reverse-observation\/\{id\}", a\.auth\(a\.handleReverseObservation\)/);
    const source = gitSource('reverse_observation.go');
    const scope = source.slice(source.indexOf('func (c *XrayClient) reverseScope('));
    assert.match(scope, /stream\.GetProtocolName\(\) != "tcp" \|\| stream\.GetSecurityType\(\) != "xray\.transport\.internet\.reality\.Config"\s*\{\s*return false, nil/);
    assert.match(source, /observeReverse\(ctx context\.Context, s reverseObservationSubject\)[\s\S]*?c\.reverseScope\(ctx, rpc, s\)[\s\S]*?name := "user>>>"/);
});

for (const mode of ['forward', 'reverse']) {
    test(`${mode}: neither Rebuild nor classic health falls back to TCP for mKCP`, async t => {
        const row = mkcp(mode);
        const guard = t.mock.method(cascade, '_measureTcpLatency', async () => 1);
        const ssh = t.mock.method(cascade, '_checkTunnel', async () => true);
        const lookups = t.mock.method(Node, 'findById', async () => ({ ip: '192.0.2.1' }));
        const writes = t.mock.method(Link, 'updateOne', async () => ({ matchedCount: 1 }));
        const flag = process.env.C3_REBUILD_ENABLED;
        t.after(() => { if (flag === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = flag; });
        for (const rebuild of ['false', 'true']) {
            process.env.C3_REBUILD_ENABLED = rebuild;
            assert.equal(await cascade.healthCheckLink(row), false, rebuild);
        }
        assert.equal((await cascade.deployLink(row)).success, false);
        for (const observer of [guard, ssh, lookups, writes]) assert.equal(observer.mock.callCount(), 0);
    });
}

for (const mode of ['forward', 'reverse']) {
    test(`${mode}: only the matching mKCP Apply generation is applied; liveness is never inferred`, () => {
        const row = mkcp(mode);
        row.rebuildApplied = appliedLink(row);
        row.rebuildKcpApplied = observation.kcpApplyFingerprint(row, row.rebuildApplyEpoch);
        // Even a stored positive plus apparent TCP latency and aggregate counters cannot make this online.
        const noisy = { ...row, status: 'online', lastError: 'old TCP probe', latencyMs: 3,
            lastHealthCheck: new Date(), observationExpiresAt: Date.now() + 10_000,
            tunnelState: 'connected', clientReadiness: { status: 'ready' }, xrayReadiness: 'verified', pppReadiness: 'verified',
            rebuildReverseObservation: { version: 1, observedAt: new Date(), established: true, generation: 'f'.repeat(64) } };
        const project = (input, rebuild = true) => observation.projectLinkHealth(input, rebuild);
        const good = project(noisy);
        assert.deepEqual([good.status, good.tunnelState, good.tunnelVerification], ['deployed', 'unknown', 'mkcp_runtime_unsupported']);
        assert.deepEqual([good.lastHealthCheck, good.latencyMs, good.lastError, good.observationExpiresAt], [null, null, '', undefined]);
        for (const key of ['rebuildKcpApplied', 'rebuildApplied', 'rebuildApplyEpoch', 'rebuildReverseObservation',
            'clientReadiness', 'xrayReadiness', 'pppReadiness']) assert.ok(!Object.hasOwn(good, key));
        for (const [field, value] of [
            ['_id', new ObjectId()], ['portalNode', new ObjectId()], ['bridgeNode', new ObjectId()],
            ['tunnelSecurity', 'tls'], ['tunnelTransport', 'tcp'], ['rebuildApplyEpoch', 'b'.repeat(32)],
            ['rebuildKcpApplied', undefined], ['rebuildApplied', null],
            ['rebuildApplied', { ...row.rebuildApplied, listener: new ObjectId() }],
            ['active', false], ['rebuildDelete', true], ['lifecycle', { state: 'deleting' }],
        ]) {
            const bad = project({ ...noisy, [field]: value });
            assert.deepEqual([bad.status, bad.tunnelState, bad.tunnelVerification], ['pending', 'unknown', 'mkcp_apply_unconfirmed'], field);
        }
        assert.equal(project({ ...noisy, status: 'pending' }).status, 'pending');
        assert.equal(project({ ...noisy, status: 'error', lastError: 'Apply failed' }).lastError, 'Apply failed');
        assert.equal(project(noisy, false).status, 'pending');
    });
}
