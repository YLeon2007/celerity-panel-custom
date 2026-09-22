'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const templatePath = path.resolve(__dirname, '../../../../views/l2tp.ejs');

test('L2TP panel template exposes typed controls while keeping passwords input-only', () => {
    const template = fs.readFileSync(templatePath, 'utf8');
    const configureFields = [
        'clientCidr',
        'localAddress',
        'poolStart',
        'poolEnd',
        'dnsServers',
        'tproxyPort',
        'fwmark',
        'routeTable',
        'routeGroupId',
    ];

    for (const field of configureFields) {
        assert.match(template, new RegExp(`name="${field}"`), field);
    }
    for (const field of ['tproxyPort', 'fwmark', 'routeTable']) {
        assert.match(
            template,
            new RegExp(`<input[^>]+type="number"[^>]+name="${field}"`),
            field,
        );
    }
    assert.match(template, /name="expectedTopologyRevision"/);
    assert.match(template, /data-l2tp-action="configure"/);
    assert.match(template, /generatePsk:\s*true/);
    assert.match(template, /csrfToken/);
    assert.match(template, /\/nodes\/\$\{encodeURIComponent\(nodeId\)\}\/l2tp\//);
    assert.match(template, /data-l2tp-user-form/);
    assert.match(template, /data-l2tp-user-list/);
    assert.match(template, /data-l2tp-user-action="create"/);
    assert.match(template, /data-l2tp-user-action="toggle"/);

    const passwordInputs = template.match(/<input\b[^>]*\bname="password"[^>]*>/gi) || [];
    assert.equal(passwordInputs.length, 1, 'one password input is exposed');
    assert.match(passwordInputs[0], /\btype="password"/i);
    assert.match(passwordInputs[0], /\bautocomplete="new-password"/i);
    assert.doesNotMatch(passwordInputs[0], /\bvalue\s*=/i, 'password is never pre-filled');
    assert.doesNotMatch(passwordInputs[0], /<%/, 'password is never server-rendered');

    const configurePayload = template.match(
        /function buildConfigurePayload\(values\) \{[\s\S]*?return \{([\s\S]*?)^\s*\};/m,
    );
    assert.ok(configurePayload, 'configure payload builder must be explicit');
    const payloadFields = [...configurePayload[1].matchAll(/^\s+(\w+):/gm)]
        .map(match => match[1]);
    assert.deepEqual(payloadFields, [...configureFields, 'generatePsk']);

    const userPayload = template.match(
        /function buildL2tpUserPayload\(values\) \{[\s\S]*?return \{([\s\S]*?)^\s*\};/m,
    );
    assert.ok(userPayload, 'user payload builder must be explicit');
    assert.deepEqual(
        [...userPayload[1].matchAll(/^\s+(\w+):/gm)].map(match => match[1]),
        ['login', 'ip', 'password', 'enabled'],
    );
    assert.doesNotMatch(template, /\buser\.password(?:Encrypted)?\b/);
    assert.doesNotMatch(template, /<%[-=](?:(?!%>).)*password(?:(?!%>).)*%>/is);
    assert.doesNotMatch(template, /\binnerHTML\b/);
    assert.doesNotMatch(
        template,
        /\b(?:command|argv|shell|psk|privateKey|encrypted|ssh|reveal)\b/i,
    );
});
