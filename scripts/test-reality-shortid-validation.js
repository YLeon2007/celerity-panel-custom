'use strict';

const assert = require('assert');
const configGenerator = require('../src/services/configGenerator');

function expectInvalid(build) {
    assert.throws(
        build,
        (error) => error && error.code === 'INVALID_REALITY_SHORT_ID',
    );
}

expectInvalid(() => configGenerator.buildXrayStreamSettings({
    transport: 'tcp',
    security: 'reality',
    realitySni: ['www.google.com'],
    realityPrivateKey: 'test-private-key',
    realityShortIds: ['0568gtr17ygce'],
}));

expectInvalid(() => configGenerator.buildCascadeTunnelStreamSettings({
    tunnelTransport: 'tcp',
    tunnelSecurity: 'reality',
    realitySni: ['www.google.com'],
    realityPrivateKey: 'test-private-key',
    realityShortIds: ['not-hex'],
}, { server: true }));

const valid = configGenerator.buildXrayStreamSettings({
    transport: 'tcp',
    security: 'reality',
    realitySni: ['www.google.com'],
    realityPrivateKey: 'test-private-key',
    realityShortIds: ['0123abcd'],
});
assert.deepStrictEqual(valid.realitySettings.shortIds, ['0123abcd']);

console.log('reality short-id validation tests passed');
