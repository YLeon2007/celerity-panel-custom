'use strict';
// Local orchestration fixtures only: no live SSH/systemd or connectivity claims.
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');
const fixturePath = path.resolve(__dirname, '../src/services/tests/cascadeScopedClassicDeploy.test.js');
const fixtureModule = new Module(fixturePath, module);
fixtureModule.filename = fixturePath;
fixtureModule.paths = Module._nodeModulePaths(path.dirname(fixturePath));
const fixtureSource = fs.readFileSync(fixturePath, 'utf8').split("test('checked absent pending removal")[0];
fixtureModule._compile(`${fixtureSource}\nmodule.exports = { fixture, SOURCE, BRIDGE, TARGET, BASE, MAIN, TRANSIT };`, fixturePath);
const { fixture, SOURCE, BRIDGE, TARGET, BASE, MAIN, TRANSIT } = fixtureModule.exports;
const args = { linkId: TARGET, expectedTopologyRevision: 17, baselineLinkIds: [BASE] };
const { isClassicPortalBridgePreflightError } = require('../src/services/classicPortalBridgePhase');
const bootstrapper = require('../src/services/classicPortalBridgeBootstrap');
const complete = (command, stdout = '') => ({ code: 0, stderr: '', stdout: `${stdout}\n${command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0]}\n` });
function fresh(t, fault) {
    const f = fixture(t, { fault(info) {
        const value = fault?.(info);
        if (value) return value;
        if (info.command.includes('C3_PORTAL_BRIDGE_PREFLIGHT')) return complete(info.command, 'a'.repeat(64));
        if (info.command.includes('C3_PORTAL_BRIDGE_BOOTSTRAP')) {
            info.files.set(`${info.id}:${TRANSIT}`, bootstrapper.IDLE_BYTES);
            return complete(info.command, 'C3_BRIDGE_READY');
        }
    } });
    f.nodes[SOURCE].cascadeRole = 'portal';
    f.links.splice(f.links.indexOf(f.baseline), 1);
    f.files.delete(`${BRIDGE}:${TRANSIT}`);
    f.apply = extra => f.cascade.deployScopedClassicLink({ ...args, baselineLinkIds: [], ...extra });
    return f;
}

test('trusted callback aborts before the first staging dispatch', async t => {
    const f = fixture(t);
    f.nodes[SOURCE].cascadeRole = 'portal';
    let calls = 0;
    await assert.rejects(f.cascade.deployScopedClassicLink({ ...args, beforeRemoteMutation() {
        calls++; throw new Error('held admission lost');
    } }));
    assert.equal(calls, 1);
    assert.equal(f.writes.length, 0);
    assert.equal(f.commands.some(row => /mv --|ufw allow|systemctl restart/.test(row.command)), false);
});

test('fresh absent standalone bridge is bootstrapped idle before ordinary apply; replay does not mutate', async t => {
    const phases = [];
    let bootstrap = 0;
    const f = fixture(t, { fault({ id, command, files }) {
        const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0];
        if (command.includes('C3_PORTAL_BRIDGE_PREFLIGHT')) return { code: 0, stderr: '', stdout: `${'a'.repeat(64)}\n${marker}\n` };
        if (command.includes('C3_PORTAL_BRIDGE_BOOTSTRAP')) {
            bootstrap++;
            const { IDLE_BYTES } = require('../src/services/classicPortalBridgeBootstrap');
            files.set(`${id}:${TRANSIT}`, IDLE_BYTES);
            return { code: 0, stderr: '', stdout: `C3_BRIDGE_READY\n${marker}\n` };
        }
    } });
    f.nodes[SOURCE].cascadeRole = 'portal';
    f.links.splice(f.links.indexOf(f.baseline), 1);
    f.files.delete(`${BRIDGE}:${TRANSIT}`);
    const input = { ...args, baselineLinkIds: [], beforeRemoteMutation: info => phases.push(info) };
    assert.equal((await f.cascade.deployScopedClassicLink(input)).success, true);
    assert.equal(bootstrap, 1);
    assert.equal(phases[0].phase, 'bootstrap');
    assert.equal(phases[0].nodeId, BRIDGE);
    const config = JSON.parse(f.files.get(`${BRIDGE}:${TRANSIT}`));
    assert.ok(config.routing.rules.some(row => row.ip?.includes('geoip:private')), 'fresh ordinary bridge keeps canonical private-address block');
    assert.ok(config.routing.rules.some(row => row.ip?.includes('::/0')), 'fresh ordinary bridge keeps canonical IPv6 block');
    const applied = new Map(f.files), calls = phases.length;
    assert.equal((await f.cascade.deployScopedClassicLink(input)).success, true);
    assert.deepEqual(f.files, applied);
    assert.equal(phases.length, calls);
    assert.equal(bootstrap, 1);
});

test('bootstrap callback refusal exposes trusted no-write proof before dispatch', async t => {
    const f = fresh(t);
    await assert.rejects(f.apply({ beforeRemoteMutation({ phase }) {
        assert.equal(phase, 'bootstrap'); throw new Error('lost');
    } }), isClassicPortalBridgePreflightError);
    assert.equal(f.commands.some(row => row.command.includes('C3_PORTAL_BRIDGE_BOOTSTRAP')), false);
    assert.equal(f.writes.length, 0);
    assert.equal(f.locks.size, 2, 'existing lock wrapper retains; parent owns proof-consumption wiring');
});

test('all mutation boundaries are signalled including same-node stages', async t => {
    const phases = [];
    const f = fresh(t);
    await f.apply({ beforeRemoteMutation(info) { assert.ok(Object.isFrozen(info)); phases.push([info.nodeId, info.phase]); } });
    assert.deepEqual(phases, [[BRIDGE, 'bootstrap'], [SOURCE, 'stage'], [BRIDGE, 'stage'],
        [BRIDGE, 'stage-permissions'], [SOURCE, 'firewall'], [SOURCE, 'apply'], [BRIDGE, 'apply']]);
});

for (const boundary of ['bootstrap', 'stage', 'stage-permissions', 'firewall', 'apply']) {
    for (const mode of ['throw', 'nonzero', 'missing-marker']) test(`${boundary} ${mode} stays unknown, never no-write`, async t => {
        let current;
        const f = fresh(t, ({ command }) => {
            if (current !== boundary) return;
            if (mode === 'throw') throw Object.assign(new Error('forged no-write'), { code: 'CLASSIC_SCOPED_PREFLIGHT', remoteMutationStarted: false });
            return { code: mode === 'nonzero' ? 1 : 0, stdout: '', stderr: '' };
        });
        await assert.rejects(f.apply({ beforeRemoteMutation({ phase }) { current = phase; } }), error => !isClassicPortalBridgePreflightError(error));
        assert.equal(f.locks.size, 2);
    });
}

test('callback refusal after first same-node stage cannot become no-write', async t => {
    const f = fixture(t);
    f.nodes[SOURCE].cascadeRole = 'portal';
    let n = 0;
    await assert.rejects(f.cascade.deployScopedClassicLink({ ...args, beforeRemoteMutation() {
        if (++n === 2) throw new Error('later refusal');
    } }), error => !isClassicPortalBridgePreflightError(error));
    assert.equal(f.writes.length, 1);
    assert.equal(f.locks.size, 2);
});

test('same-node validation error after successful source stage cannot authorize cleanup', async t => {
    const f = fixture(t, { fault({ id, command }) {
        if (id === SOURCE && command.includes('run -test -format json -config')) {
            throw Object.assign(new Error('validator failed'), { code: 'CLASSIC_SCOPED_PREFLIGHT', noRemoteMutation: true });
        }
    } });
    f.nodes[SOURCE].cascadeRole = 'portal';
    await assert.rejects(f.cascade.deployScopedClassicLink({ ...args, beforeRemoteMutation() {} }),
        error => !isClassicPortalBridgePreflightError(error));
    assert.equal(f.writes.length, 1);
    assert.equal(f.locks.size, 2);
});

test('no-effect read failures branded only with internal callback, never by public code', async t => {
    const fault = ({ command }) => { if (command.includes('C3_READ_CONFIG')) throw Object.assign(new Error('read fail'), { code: 'CLASSIC_SCOPED_PREFLIGHT' }); };
    const f = fixture(t, { fault });
    await assert.rejects(f.run(), error => !isClassicPortalBridgePreflightError(error));
    const g = fixture(t, { fault });
    await assert.rejects(g.cascade.deployScopedClassicLink({ ...args, beforeRemoteMutation() { assert.fail('read must refuse first'); } }), isClassicPortalBridgePreflightError);
    assert.equal(isClassicPortalBridgePreflightError({ code: 'CLASSIC_SCOPED_PREFLIGHT', noRemoteMutation: true }), false);
});

test('relay absent-sidecar behavior remains refusal without bootstrap', async t => {
    const f = fixture(t);
    f.files.delete(`${BRIDGE}:${TRANSIT}`);
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_SERVICE_LAYOUT_UNSUPPORTED' });
    assert.equal(f.commands.some(row => row.command.includes('C3_PORTAL_BRIDGE_')), false);
    assert.equal(f.writes.length, 0);
});

test('bootstrap cannot skip missing sibling preservation guards', async t => {
    const f = fresh(t);
    f.links.push(f.baseline);
    await assert.rejects(f.apply({ baselineLinkIds: [BASE], beforeRemoteMutation() { assert.fail('missing sibling sidecar'); } }),
        { code: 'CLASSIC_SCOPED_UNREPRESENTED_BRIDGE_CONFIG' });
    assert.equal(f.commands.some(row => row.command.includes('C3_PORTAL_BRIDGE_BOOTSTRAP')), false);
});

test('removal signals staging/apply but never bootstraps', async t => {
    const f = fresh(t);
    await f.apply();
    const phases = [];
    await f.cascade.removeScopedClassicLink({ ...args, baselineLinkIds: [], beforeRemoteMutation: info => phases.push(info.phase) });
    assert.deepEqual(phases, ['stage', 'stage', 'apply', 'apply']);
});

for (const drift of ['bookkeeping-only', 'outer-pid', 'outer-start', 'loaded-argv', 'exit-status']) {
    test(`bootstrap target MAIN readback: ${drift}`, async t => {
        let reloaded = false;
        const f = fresh(t, ({ id, command }) => {
            if (command.includes('C3_PORTAL_BRIDGE_BOOTSTRAP')) reloaded = true;
            if (id !== BRIDGE || !command.includes('systemctl show xray --')) return;
            const pid = reloaded && drift === 'outer-pid' ? 732 : 731;
            const start = reloaded && drift === 'outer-start' ? 992 : 991;
            const argv = `/usr/local/bin/xray run -config ${MAIN}${reloaded && drift === 'loaded-argv' ? ' --foreign' : ''}`;
            return complete(command, `ActiveState=active\nMainPID=${pid}\nExecMainStartTimestampMonotonic=${start}\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=${argv} ; start_time=[${reloaded ? 'n/a' : 'old'}] ; stop_time=[n/a] ; pid=${reloaded ? 0 : 731} ; code=(null) ; status=${reloaded && drift === 'exit-status' ? '1/0' : '0/0'} }\n`);
        });
        f.files.set(`${BRIDGE}:${MAIN}`, JSON.stringify(f.main));
        if (drift === 'bookkeeping-only') {
            assert.equal((await f.apply()).success, true);
            assert.equal(f.commands.some(row => row.id === BRIDGE && row.command.includes('systemctl restart xray ')), false);
            assert.equal(f.files.get(`${BRIDGE}:${MAIN}`), JSON.stringify(f.main));
        } else {
            await assert.rejects(f.apply({ beforeRemoteMutation() {} }), error => error.code === 'CLASSIC_SCOPED_PRESERVED_PROFILE_DRIFT'
                && !isClassicPortalBridgePreflightError(error));
            assert.equal(f.writes.length, 0);
            assert.equal(f.locks.size, 2);
        }
    });
}

for (let stop = 1; stop <= 7; stop++) test(`callback veto at mutation ordinal ${stop} prevents exact dispatch`, async t => {
    const f = fresh(t);
    let calls = 0;
    await assert.rejects(f.apply({ beforeRemoteMutation() { if (++calls === stop) throw new Error('veto'); } }),
        error => isClassicPortalBridgePreflightError(error) === (stop === 1));
    assert.equal(calls, stop);
    const dispatched = f.commands.filter(row => row.command.includes('C3_PORTAL_BRIDGE_BOOTSTRAP')
        || row.options.stdin !== undefined || row.command.includes('C3_PORTAL_BRIDGE_STAGE_TEST')
        || row.command.includes('ufw allow') || row.command.includes('mv --'));
    assert.equal(dispatched.length, stop - 1);
});

test('reused branded error loses no-write provenance after any later mutation', async () => {
    const { createClassicPortalBridgePhase } = require('../src/services/classicPortalBridgePhase');
    const error = new Error('reused adapter error');
    const first = createClassicPortalBridgePhase({ beforeRemoteMutation() {} });
    first.failure(error);
    assert.equal(isClassicPortalBridgePreflightError(error), true);
    const later = createClassicPortalBridgePhase({ beforeRemoteMutation() {} });
    await later.beforeDispatch(SOURCE, 'stage');
    later.failure(error);
    assert.equal(isClassicPortalBridgePreflightError(error), false);
});

test('daemon-reload exception permits nested bookkeeping only with exact outer identity/argv', () => {
    const before = { bytes: '{}', unit: 'ActiveState=active\nLoadedExecStart=/usr/local/bin/xray|/usr/local/bin/xray run -config fixed\n',
        loaded: ['/usr/local/bin/xray', '/usr/local/bin/xray run -config fixed'],
        runtime: ['MainPID=731', 'ExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config fixed ; start_time=[old] ; stop_time=[n/a] ; pid=731 ; code=(null) ; status=0/0 }', 'ExecMainStartTimestampMonotonic=991'] };
    const after = structuredClone(before);
    after.runtime[1] = after.runtime[1].replace('start_time=[old]', 'start_time=[n/a]').replace('pid=731', 'pid=0');
    assert.equal(bootstrapper.sameProfileAcrossBootstrapReload(before, after), true);
    for (const mutate of [p => p.runtime[0] = 'MainPID=732', p => p.runtime[2] = 'ExecMainStartTimestampMonotonic=992',
        p => p.loaded[1] += ' --foreign', p => p.runtime[1] = p.runtime[1].replace('status=0/0', 'status=1/0'),
        p => p.runtime[1] = p.runtime[1].replace('pid=0', 'pid=999'),
        p => p.runtime[1] = p.runtime[1].replace('start_time=[n/a]', 'start_time=[foreign]'),
        p => p.unit += 'DropInPaths=foreign\n', p => p.bytes += ' ', p => p.runtime[2] = null]) {
        const changed = structuredClone(after); mutate(changed);
        assert.equal(bootstrapper.sameProfileAcrossBootstrapReload(before, changed), false);
    }
});
