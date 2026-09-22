'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const templatePath = path.resolve(__dirname, '../../../../views/l2tp.ejs');

test('L2TP panel template exposes only typed operations and a CSRF token', () => {
    const template = fs.readFileSync(templatePath, 'utf8');

    assert.match(template, /name="clientCidr"/);
    assert.match(template, /name="dnsServers"/);
    assert.match(template, /name="routeGroupId"/);
    assert.match(template, /name="expectedTopologyRevision"/);
    assert.match(template, /csrfToken/);
    assert.match(template, /\/nodes\/\$\{encodeURIComponent\(nodeId\)\}\/l2tp\//);
    assert.doesNotMatch(template, /\b(?:command|argv|shell|psk|password|privateKey|encrypted|ssh)\b/i);
});
