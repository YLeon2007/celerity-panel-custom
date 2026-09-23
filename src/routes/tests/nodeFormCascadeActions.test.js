'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPTS_SOURCE = fs.readFileSync(
    path.resolve(__dirname, '../../../views/partials/node-form/scripts.ejs'),
    'utf8',
);

function extractCascadeAction() {
    const start = SCRIPTS_SOURCE.indexOf('async function cascadeAction(');
    assert.notStrictEqual(start, -1, 'cascadeAction must exist');
    const end = SCRIPTS_SOURCE.indexOf('\nasync function ', start + 1);
    return SCRIPTS_SOURCE.slice(start, end === -1 ? undefined : end);
}

test('node-form deploy action uses the revision-safe topology deploy endpoint', () => {
    const action = extractCascadeAction();
    assert.match(action, /fetch\('\/api\/cascade\/links'\)/,
        'deploy must read the current topology revision from the links snapshot');
    assert.match(action, /\/api\/cascade\/topology\/deploy/,
        'deploy must call the revision-safe topology deploy endpoint');
    assert.match(action, /expectedTopologyRevision/,
        'deploy must send the tracked topology revision');
    assert.match(action, /['"]x-csrf-token['"]: csrfToken/,
        'deploy must send the panel CSRF token for session requests');
    assert.doesNotMatch(action, /\/api\/cascade\/links\/' \+ linkId \+ '\/deploy/,
        'deploy must not call the retired per-link endpoint');
});

test('node-form cascade actions surface typed error messages instead of stringified objects', () => {
    const action = extractCascadeAction();
    assert.match(action, /typeof errorValue === 'string'[\s\S]*?errorValue\?\.message \|\| errorValue\?\.code/,
        'error rendering must extract message/code from typed error payloads');
    assert.doesNotMatch(action, /\+ \(data\.error \|\|/,
        'error rendering must not stringify bare error objects');
});

test('node-form exposes the panel CSRF token to cascade actions', () => {
    assert.match(SCRIPTS_SOURCE, /const csrfToken = <%- JSON\.stringify\(csrfToken \|\| ''\) %>;/);
});
