'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const templatePath = path.resolve(__dirname, '../../../../views/l2tp.ejs');

test('L2TP panel template exposes typed desired-state controls and no secret surface', () => {
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

    const configurePayload = template.match(
        /function buildConfigurePayload\(values\) \{[\s\S]*?return \{([\s\S]*?)^\s*\};/m,
    );
    assert.ok(configurePayload, 'configure payload builder must be explicit');
    const payloadFields = [...configurePayload[1].matchAll(/^\s+(\w+):/gm)]
        .map(match => match[1]);
    assert.deepEqual(payloadFields, [...configureFields, 'generatePsk']);
    assert.doesNotMatch(
        template,
        /\b(?:command|argv|shell|psk|password|privateKey|encrypted|ssh|reveal)\b/i,
    );
});
