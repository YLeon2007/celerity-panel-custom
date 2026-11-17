'use strict';
// Private diagnostics-only test; no runtime/DB/SSH authority is supplied.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
function fixture(enabled) {
    const writes = [];
    const source = fs.readFileSync(path.join(__dirname, '../../../routes/topologyTestDiagnostics.js'), 'utf8');
    const module = { exports: {} };
    const fakeFs = { existsSync: p => p.endsWith('.test-topology-diagnostics-enabled'),
        appendFileSync: (p, data, options) => writes.push({ p, row: JSON.parse(data), options }) };
    vm.runInNewContext('(function(require,module,exports,process){' + source + '\n})', { Date, Object, Number, Array, JSON })(
        name => name === 'node:fs' ? fakeFs : require(name), module, module.exports,
        { env: { TOPOLOGY_TEST_EXECUTION_ENABLED: enabled ? 'true' : 'false' } });
    return { writes, ...module.exports };
}
for (const enabled of [false, true]) test(`private nested connection primary logging is bounded and remains TEST-switch-only (${enabled})`, () => {
    const f = fixture(enabled);
    const error = Object.assign(new Error('PRIVATE_OUTER_MESSAGE'), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    let parent = error;
    for (let i = 0; i < 6; i++) parent = parent.cause = Object.assign(new Error('PRIVATE_INNER_' + i), { code: 112 });
    f.logTopologyTestFailure({ phase: 'worker.v2-terminal', action: 'topology.worker', operationId: '1'.repeat(24), error });
    assert.equal(f.writes.length, enabled ? 2 : 0);
    if (!enabled) return;
    assert.equal(JSON.stringify(f.writes[0].row).includes('PRIVATE_'), false, 'public safe log must not gain private cause data');
    const entry = f.writes[1];
    assert.ok(entry.p.endsWith('topology-test-primary.private.log'));
    assert.equal(entry.options.mode, 0o600);
    assert.equal(entry.row.causes.length, 4);
    assert.equal(entry.row.causes[0].message, 'PRIVATE_INNER_0');
    assert.equal(entry.row.causes[0].code, 112);
    assert.equal(entry.row.causes[3].message, 'PRIVATE_INNER_3');
});
