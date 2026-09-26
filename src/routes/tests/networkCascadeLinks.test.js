'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const NETWORK_SOURCE = fs.readFileSync(
    path.resolve(__dirname, '../../../public/js/network.js'),
    'utf8',
);
const NODES_VIEW_SOURCE = fs.readFileSync(
    path.resolve(__dirname, '../../../views/nodes.ejs'),
    'utf8',
);
test('network UI consumes and tracks the versioned cascade-link snapshot', () => {
    assert.match(NETWORK_SOURCE, /let topologyRevision = null;/);
    assert.match(NETWORK_SOURCE, /let deployedRevision = null;/);
    assert.match(NETWORK_SOURCE, /function applyLinkSnapshot\(snapshot\)/);
    assert.match(NETWORK_SOURCE, /topologyRevision = snapshot\.topologyRevision;/);
    assert.match(NETWORK_SOURCE, /deployedRevision = snapshot\.deployedRevision;/);
    assert.match(NETWORK_SOURCE, /_allLinks = snapshot\.links;/);
    assert.match(NETWORK_SOURCE, /applyLinkSnapshot\(await linksRes\.json\(\)\)/);
});

test('network UI sends the tracked topology revision with create, update, and delete', () => {
    assert.match(NETWORK_SOURCE, /data\.expectedTopologyRevision = topologyRevision;/);
    assert.match(
        NETWORK_SOURCE,
        /fetch\('\/api\/cascade\/links\/' \+ linkId, \{[\s\S]*?method: 'DELETE',[\s\S]*?body: JSON\.stringify\(\{ expectedTopologyRevision: topologyRevision \}\)/,
    );
    assert.ok(
        (NETWORK_SOURCE.match(/data\.expectedTopologyRevision = topologyRevision;/g) || []).length >= 2,
        'both the full form and quick-create flow must send expectedTopologyRevision',
    );
});

test('network UI refreshes a stale snapshot on 409 without replaying the mutation', () => {
    assert.match(NETWORK_SOURCE, /async function handleDraftMutationResponse\(response\)/);
    const handlerStart = NETWORK_SOURCE.indexOf('async function handleDraftMutationResponse(response)');
    const handlerEnd = NETWORK_SOURCE.indexOf('\n    async function', handlerStart + 1);
    const handlerSource = NETWORK_SOURCE.slice(handlerStart, handlerEnd);
    assert.match(handlerSource, /if \(response\.status === 409\) \{[\s\S]*?await loadTopology\(\);[\s\S]*?return null;/);
    assert.doesNotMatch(handlerSource, /method: (?:'POST'|'PUT'|'DELETE')/);
    assert.doesNotMatch(NETWORK_SOURCE, /\/api\/cascade\/links\/[^'\n]+\/reconnect/);
});

function extractHandler(name) {
    const start = NETWORK_SOURCE.indexOf(`window.${name} = async function`);
    assert.notStrictEqual(start, -1, `${name} handler must exist`);
    const end = NETWORK_SOURCE.indexOf('\n    window.', start + 1);
    return NETWORK_SOURCE.slice(start, end === -1 ? undefined : end);
}

function extractDeployPath(name) {
    // Deploy handlers delegate the network call to the shared deployTopology helper.
    const helperStart = NETWORK_SOURCE.indexOf('async function deployTopology(linkId)');
    assert.notStrictEqual(helperStart, -1, 'deployTopology helper must exist');
    const helperEnd = NETWORK_SOURCE.indexOf('\n    window.', helperStart);
    assert.notStrictEqual(helperEnd, -1, 'deployTopology helper must precede the handlers');
    return NETWORK_SOURCE.slice(helperStart, helperEnd) + extractHandler(name);
}

test('network UI deploy and chain sync use the revision-safe topology deploy endpoint', () => {
    for (const name of ['_cascadeDeploy', '_cascadeDeployChain']) {
        const handler = extractDeployPath(name);
        assert.match(
            handler,
            /fetch\('\/api\/cascade\/topology\/deploy', \{[\s\S]*?method: 'POST',[\s\S]*?body: JSON\.stringify\([\s\S]*?expectedTopologyRevision: topologyRevision/,
            `${name} must POST to the revision-safe topology deploy endpoint`,
        );
        assert.match(
            handler,
            /expectedTopologyRevision: topologyRevision, domainKey/,
            `${name} must send the domain key for domain-scoped deploys`,
        );
        assert.doesNotMatch(
            handler,
            /\/api\/cascade\/links\/' \+ linkId \+ '\/deploy|\/api\/cascade\/chain\/deploy/,
            `${name} must not call retired unversioned deploy endpoints`,
        );
    }
});

test('network UI deploy surfaces typed error messages instead of stringified objects', () => {
    for (const name of ['_cascadeDeploy', '_cascadeDeployChain']) {
        const handler = extractDeployPath(name);
        assert.match(
            handler,
            /typeof errorValue === 'string'[\s\S]*?errorValue\?\.message/,
            `${name} must surface typed error.message payloads`,
        );
        assert.doesNotMatch(
            handler,
            /throw new Error\(data\?\.error\)/,
            `${name} must not stringify a bare error object`,
        );
    }
});

test('network UI deploy refreshes the topology snapshot on revision conflict', () => {
    for (const name of ['_cascadeDeploy', '_cascadeDeployChain']) {
        const handler = extractDeployPath(name);
        assert.match(
            handler,
            /res\.status === 409[\s\S]*?loadTopology\(\)/,
            `${name} must reload the topology snapshot on 409`,
        );
    }
});

test('network UI deploy sends the panel CSRF token on session requests', () => {
    // POST /api/cascade/topology/deploy enforces requirePanelCsrf for session auth.
    const helper = extractDeployPath('_cascadeDeploy');
    assert.match(helper, /['"]x-csrf-token['"]: csrfToken/, 'deployTopology must send the x-csrf-token header');
    assert.match(NETWORK_SOURCE, /window\._networkCsrfToken/, 'network.js must read the page-exposed CSRF token');
});

test('network UI deploy never stringifies a bare error object', () => {
    const helper = extractDeployPath('_cascadeDeploy');
    assert.match(
        helper,
        /typeof errorValue === 'string'[\s\S]*?errorValue\?\.message \|\| errorValue\?\.code/,
        'deployTopology must fall back to error.code for object errors without message',
    );
});

test('nodes view exposes the CSRF token for network module requests', () => {
    assert.match(NODES_VIEW_SOURCE, /window\._networkCsrfToken = <%- JSON\.stringify\(csrfToken \|\| ''\) %>;/);
});

test('network UI deploy maps coordinator statuses to distinct user messages', () => {
    const helper = extractDeployPath('_cascadeDeploy');
    assert.match(helper, /result\.status === 'succeeded'[\s\S]*?deployAlreadyDeployed/);
    assert.match(helper, /deploymentEndedWithStatus/);
    assert.match(NODES_VIEW_SOURCE, /deployAlreadyDeployed: <%- JSON\.stringify\(t\('network\.deployAlreadyDeployed'\)\) %>/);
    assert.match(NODES_VIEW_SOURCE, /deploymentEndedWithStatus: <%- JSON\.stringify\(t\('network\.deploymentEndedWithStatus'\)\) %>/);
});
