'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { formatTopologyDiagnostic } = require('../topologyTestDiagnostics');

test('temporary diagnostic includes time, action and structured cause without secrets', () => {
    const error = new Error('secret-password-NOT-FOR-LOG');
    error.code = 'INVALID_TOPOLOGY_DEPLOYMENT';
    error.causeCode = 'INVALID_TOPOLOGY_ROLES';
    error.errors = [{ code: 'UNKNOWN_LINK', linkId: 'a'.repeat(24), pathKey: 'secret-key-NOT-FOR-LOG', privateKey: 'secret' }];
    error.stack = 'secret-stack-NOT-FOR-LOG';
    const entry = formatTopologyDiagnostic({ action: 'link.create', phase: 'auto-deploy.queue',
        revision: 160, linkId: 'b'.repeat(24), operationId: 'c'.repeat(24),
        nodeId: 'd'.repeat(24), groupId: 'e'.repeat(24), error, now: new Date('2026-10-14T07:30:00Z') });
    assert.equal(entry.time, '2026-10-14T07:30:00.000Z');
    assert.equal(entry.action, 'link.create');
    assert.equal(entry.phase, 'auto-deploy.queue');
    assert.equal(entry.revision, 160);
    assert.equal(entry.linkId, 'b'.repeat(24));
    assert.equal(entry.operationId, 'c'.repeat(24));
    assert.equal(entry.nodeId, 'd'.repeat(24));
    assert.equal(entry.groupId, 'e'.repeat(24));
    assert.equal(entry.code, 'INVALID_TOPOLOGY_DEPLOYMENT');
    assert.equal(entry.causeCode, 'INVALID_TOPOLOGY_ROLES');
    assert.deepEqual(entry.validation, [{ code: 'UNKNOWN_LINK', linkId: 'a'.repeat(24) }]);
    assert.doesNotMatch(JSON.stringify(entry), /secret|password|stack|privateKey|pathKey/);
});

test('unexpected fields and unsafe identifiers never reach the file entry', () => {
    const entry = formatTopologyDiagnostic({ action: 'unknown\nSECRET', phase: 'request',
        revision: '160', linkId: 'danger', error: { code: 'BAD SECRET', causeCode: 'PASSWORD',
            message: 'token', errors: [{ code: 'BAD SECRET', nodeId: 'not-id' }] },
        now: new Date('2026-10-14T07:30:01Z') });
    assert.deepEqual(entry, { time: '2026-10-14T07:30:01.000Z', action: 'unknown',
        phase: 'request', code: 'UNKNOWN' });
});
