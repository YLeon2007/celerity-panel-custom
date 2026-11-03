'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const network = require('../../../public/js/network');
const shipped = require('../../../public/js/network.min');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
test('shipped messages and both page cache identities match the generated asset', () => {
    const asset = fs.readFileSync(path.resolve(__dirname, '../../../public/js/network.min.js'));
    const version = createHash('sha256').update(asset).digest('hex').slice(0, 16);
    for (const view of ['network', 'nodes']) {
        const text = fs.readFileSync(path.resolve(__dirname, `../../../views/${view}.ejs`), 'utf8');
        assert.ok(text.includes(`/js/network.min.js?v=${version}`), view);
    }
    for (const code of ['CLASSIC_DEPLOY_NODE_BUSY', 'CLASSIC_DEPLOY_PREFLIGHT_FAILED']) {
        assert.equal(shipped.TOPOLOGY_CAUSE_TEXT_RU[code], network.TOPOLOGY_CAUSE_TEXT_RU[code]);
    }
});
for (const [code, pattern] of [
    ['CLASSIC_DEPLOY_NODE_BUSY', /уз(?:ел|лы|лов).*занят/i],
    ['CLASSIC_DEPLOY_PREFLIGHT_FAILED', /предварительн.*проверк/i],
]) {
    test(`${code} has a localized scoped message without topology recovery or leaked backend text`, () => {
        const text = network.describeTopologyError({ error: { code, message: 'password=secret <img src=x onerror=alert(1)>' } }, 'fallback');
        assert.match(text, pattern);
        assert.doesNotMatch(text, /password|secret|<img|alert|не инициализирована|восстановлен.*топологи/i);
        if (code === 'CLASSIC_DEPLOY_PREFLIGHT_FAILED') assert.match(text, /повторн.*деплой.*доступен/i);
    });
}
