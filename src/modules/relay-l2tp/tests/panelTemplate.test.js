'use strict';

const assert = require('node:assert/strict');
const ejs = require('ejs');
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

test('L2TP panel renders a minimal typed route-group editor when no groups exist', () => {
    const template = fs.readFileSync(templatePath, 'utf8');
    const html = ejs.render(template, {
        csrfToken: 'test-csrf-token',
        operations: [],
        relays: [],
        routeGroups: [],
        topologyRevision: 7,
    });

    assert.match(html, /data-l2tp-route-groups/);
    assert.match(html, /data-route-group-form/);
    assert.match(html, /data-route-group-list/);
    assert.match(html, /data-route-group-empty/);
    assert.match(html, /data-route-group-paths/);
    assert.match(html, /data-route-group-path-row/);
    assert.match(html, /data-route-group-action="add-path"/);
    assert.match(html, /data-route-group-action="save"/);
    assert.match(html, /name="routeGroupId"/);
    assert.match(html, /name="name"[^>]+maxlength="128"[^>]+required/);
    assert.match(html, /<select[^>]+name="mode"[^>]+required/);
    assert.match(html, /<option value="reverse">Reverse<\/option>/);
    assert.match(html, /<option value="forward">Forward<\/option>/);
    assert.match(html, /name="pathKey"[^>]+maxlength="64"[^>]+required/);
    assert.match(html, /name="linkIds"[^>]+required/);
    assert.match(html, /type="number"[^>]+name="priority"[^>]+step="any"[^>]+required/);
    assert.doesNotMatch(html, /data-route-group-path-row[\s\S]*?name="enabled"/);
    assert.match(html, /priority-failover/);
    assert.match(html, /No route groups\./);
    assert.doesNotMatch(html, /data-route-group-action="deploy"/);
    assert.doesNotMatch(html, /data-route-group-action="import"/);
});

test('route-group editor sends only typed protected CRUD requests and refreshes relay selectors', () => {
    const template = fs.readFileSync(templatePath, 'utf8');

    assert.match(template, /const ROUTE_GROUPS_URL = '\/api\/cascade\/route-groups';/);
    assert.match(template, /const ROUTE_GROUP_STRATEGY = 'priority-failover';/);
    assert.match(template, /function buildRouteGroupPayload\(form\)/);
    assert.match(template, /return \{\s*name,\s*mode,\s*strategy: ROUTE_GROUP_STRATEGY,\s*paths,\s*\};/s);
    assert.match(template, /return \{\s*pathKey,\s*linkIds,\s*priority,\s*\};/s);
    assert.match(template, /function routeGroupUrl\(routeGroupId\)/);
    assert.match(template, /`\$\{ROUTE_GROUPS_URL\}\/\$\{encodeURIComponent\(routeGroupId\)\}`/);
    assert.match(template, /method: routeGroupId \? 'PUT' : 'POST'/);
    assert.match(template, /method: 'DELETE'/);
    assert.match(template, /credentials: 'same-origin'/);
    assert.match(template, /'x-csrf-token': csrfToken/);
    assert.match(template, /response\.status === 429/);
    assert.match(template, /function refreshRouteGroupSelectors\(groups\)/);
    assert.match(template, /select\[name="routeGroupId"\]/);
    assert.match(template, /selector\.replaceChildren\(placeholder\)/);
    assert.match(template, /await loadRouteGroups\(\)/);
    assert.match(template, /\^\[a-fA-F0-9\]\{24\}\$/);
    assert.match(template, /new Set\(paths\.map\(path => path\.pathKey\)\)/);
    assert.match(template, /new Set\(paths\.map\(path => path\.priority\)\)/);
    assert.doesNotMatch(template, /\/panel\/[^'"`\s]*route-groups/);
});

test('route-group payload builder allowlists and validates typed priority-failover fields', () => {
    const template = fs.readFileSync(templatePath, 'utf8');
    const helpers = template.match(
        /function routeGroupError\(code\) \{[\s\S]*?(?=^\s*function routeGroupUrl)/m,
    );
    assert.ok(helpers, 'route-group payload helpers must be extractable');
    const buildRouteGroupPayload = Function(`
        const ROUTE_GROUP_STRATEGY = 'priority-failover';
        ${helpers[0]}
        return buildRouteGroupPayload;
    `)();
    const pathRow = ({ pathKey, linkIds, priority }) => {
        const controls = {
            '[name="pathKey"]': { value: pathKey },
            '[name="linkIds"]': { value: linkIds },
            '[name="priority"]': { value: priority },
        };
        return {
            querySelector(selector) { return controls[selector]; },
        };
    };
    const rows = [
        pathRow({
            pathKey: 'primary',
            linkIds: '507f1f77bcf86cd799439021, 507f1f77bcf86cd799439022',
            priority: '0.5',
        }),
        pathRow({
            pathKey: 'standby',
            linkIds: '507f1f77bcf86cd799439023',
            priority: '20',
        }),
    ];
    const form = {
        elements: {
            name: { value: '  Relay exits  ' },
            mode: { value: 'reverse' },
            ignored: { value: 'must-not-be-sent' },
        },
        querySelectorAll() { return rows; },
    };

    assert.deepEqual(buildRouteGroupPayload(form), {
        name: 'Relay exits',
        mode: 'reverse',
        strategy: 'priority-failover',
        paths: [
            {
                pathKey: 'primary',
                linkIds: ['507f1f77bcf86cd799439021', '507f1f77bcf86cd799439022'],
                priority: 0.5,
            },
            {
                pathKey: 'standby',
                linkIds: ['507f1f77bcf86cd799439023'],
                priority: 20,
            },
        ],
    });

    rows[1].querySelector('[name="priority"]').value = '0.5';
    assert.throws(
        () => buildRouteGroupPayload(form),
        error => error.code === 'DUPLICATE_ROUTE_GROUP_PRIORITY',
    );
    rows[1].querySelector('[name="priority"]').value = '20';
    rows[0].querySelector('[name="priority"]').value = '0';
    assert.throws(
        () => buildRouteGroupPayload(form),
        error => error.code === 'INVALID_ROUTE_GROUP_PRIORITY',
    );
    rows[0].querySelector('[name="priority"]').value = '0.5';
    rows[1].querySelector('[name="linkIds"]').value = '../../not-an-object-id';
    assert.throws(
        () => buildRouteGroupPayload(form),
        error => error.code === 'INVALID_ROUTE_GROUP_LINK_IDS',
    );
});

test('route-group response normalization accepts the persisted API shape and drops extras', () => {
    const template = fs.readFileSync(templatePath, 'utf8');
    const helper = template.match(
        /function normalizeRouteGroup\(value\) \{[\s\S]*?(?=^\s*function createRouteGroupPathRow)/m,
    );
    assert.ok(helper, 'route-group response normalizer must be extractable');
    const normalizeRouteGroup = Function(`
        const ROUTE_GROUP_STRATEGY = 'priority-failover';
        ${helper[0]}
        return normalizeRouteGroup;
    `)();

    assert.deepEqual(normalizeRouteGroup({
        _id: '507f1f77bcf86cd799439011',
        name: '  Relay exits  ',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{
            pathKey: 'primary',
            linkIds: ['507f1f77bcf86cd799439021'],
            priority: 0.5,
            enabled: false,
            ignored: 'must-not-be-used',
        }],
        ignored: 'must-not-be-used',
    }), {
        id: '507f1f77bcf86cd799439011',
        name: 'Relay exits',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{
            pathKey: 'primary',
            linkIds: ['507f1f77bcf86cd799439021'],
            priority: 0.5,
        }],
    });

    assert.equal(normalizeRouteGroup({
        _id: '507f1f77bcf86cd799439011',
        name: 'Relay exits',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{
            pathKey: 'primary',
            linkIds: ['not-an-object-id'],
            priority: 1,
        }],
    }), null);
});

test('rendered L2TP inline script has valid JavaScript syntax', () => {
    const template = fs.readFileSync(templatePath, 'utf8');
    const html = ejs.render(template, {
        csrfToken: 'test-csrf-token',
        operations: [],
        relays: [],
        routeGroups: [],
        topologyRevision: 7,
    });
    const inlineScript = html.match(/<script>([\s\S]*?)<\/script>/);
    assert.ok(inlineScript);
    assert.doesNotThrow(() => Function(inlineScript[1]));
});
