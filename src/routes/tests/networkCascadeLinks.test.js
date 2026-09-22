'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const NETWORK_SOURCE = fs.readFileSync(
    path.resolve(__dirname, '../../../public/js/network.js'),
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
