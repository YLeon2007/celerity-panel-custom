'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.resolve(__dirname, '../../../public/js/network.js'), 'utf8');
const network = require('../../../public/js/network');

test('deployment outcomes never claim client readiness from queue or apply success alone', () => {
    assert.match(network.deployResultMessage({ status: 'queued' }), /готовность клиента не подтверждена/i);
    assert.match(network.deployResultMessage({ status: 'succeeded' }), /готовность клиента не подтверждена/i);
    assert.match(source, /state\.kind === 'link\.apply'[\s\S]*?готовность клиента не подтверждена/);
    assert.match(source, /i18n\.operationApplied[\s\S]*?готовность клиента не подтверждена/);
});

test('edge readiness fails closed without current explicit client proof', () => {
    const label = network.clientReadinessMessage;
    assert.match(label(null, 7, 7), /не подтверждена/i);
    assert.match(label({ status: 'succeeded', topologyRevision: 7 }, 7, 7), /не подтверждена/i);
    assert.match(label({ status: 'ready', clientProbe: 'passed', topologyRevision: 6 }, 7, 7), /не подтверждена/i);
    assert.match(label({ status: 'ready', clientProbe: 'passed', topologyRevision: 7 }, 7, 6), /не подтверждена/i);
    assert.match(label({ status: 'ready', clientProbe: 'passed', topologyRevision: 7 }, 7, 7), /подтверждена проверкой клиента/i);
    assert.doesNotMatch(label({ status: 'failed', message: '<img src=x onerror=alert(1)>' }, 7, 7), /<img|alert/);
    assert.match(source, /clientReadinessMessage\(d\.clientReadiness, topologyRevision, deployedRevision\)/);
    assert.match(source, /ele\.data\('clientReadiness', e\.data\.clientReadiness\)/);
});
