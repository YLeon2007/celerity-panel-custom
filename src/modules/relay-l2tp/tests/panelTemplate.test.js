'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const ejs = require('ejs');
const { Script } = require('node:vm');

const templatePath = path.resolve(__dirname, '../../../../views/l2tp.ejs');

// The template shell is localized through t(); tests render it with the
// English locale so structural assertions stay human-readable.
const TEST_RENDER_CONTEXT = Object.freeze({
    csrfToken: 'test-csrf',
    t: key => key,
});

function renderTemplate() {
    const template = fs.readFileSync(templatePath, 'utf8');
    return ejs.render(template, { ...TEST_RENDER_CONTEXT });
}

test('L2TP simple page renders relay and account sections with a safe shell', () => {
    const html = renderTemplate();

    for (const marker of [
        'id="relayList"',
        'id="relayStatus"',
        'id="accountForm"',
        'id="accountLogin"',
        'id="accountPassword"',
        'id="accountList"',
        'l2tp.relays',
        'l2tp.accounts',
        'l2tp.createAccount',
    ]) {
        assert.ok(html.includes(marker), `missing ${marker}`);
    }

    // Passwords and PSKs must never be rendered by the server: the page
    // only fetches them through the JSON API after load.
    assert.ok(!html.includes('user-password'), 'server-rendered password leaked');
    assert.ok(!html.includes('pskEncrypted'), 'encrypted PSK leaked');
});

test('L2TP simple page inline script drives the simplified API surface', () => {
    const html = renderTemplate();

    for (const marker of [
        '/panel/l2tp/simple/overview',
        '/panel/l2tp/simple/relays/',
        '/install',
        '/uninstall',
        '/panel/l2tp/simple/accounts',
        '/delete',
        'navigator.clipboard.writeText',
        '/panel/l2tp/operations/',
        'x-csrf-token',
    ]) {
        assert.ok(html.includes(marker), `missing ${marker}`);
    }
});

test('rendered L2TP inline script has valid JavaScript syntax', () => {
    const html = renderTemplate();
    const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
    assert.ok(scriptMatch, 'inline script tag is missing');
    new Script(scriptMatch[1]);
});
