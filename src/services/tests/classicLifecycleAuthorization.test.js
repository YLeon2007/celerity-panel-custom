'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { issueClassicLifecycleGrant, hasClassicLifecycleGrant } = require('../classicLifecycleAuthorization');
const env = { CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'true', CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: '12'.repeat(32) };
const link = () => ({ _id: '507f1f77bcf86cd799439041', portalNode: '507f1f77bcf86cd799439031', bridgeNode: '507f1f77bcf86cd799439032', mode: 'reverse' });
test('server-issued grant authorizes this newly created reverse after restart, not arbitrary pending links', () => {
    const original = link();
    assert.equal(hasClassicLifecycleGrant(original, env), false);
    original.classicLifecycleGrant = issueClassicLifecycleGrant(original, env);
    assert.match(original.classicLifecycleGrant, /^[a-f0-9]{64}$/);
    assert.equal(hasClassicLifecycleGrant(JSON.parse(JSON.stringify(original)), { ...env }), true);
    for (const changes of [{ _id: '507f1f77bcf86cd799439042' }, { portalNode: '507f1f77bcf86cd799439033' }, { bridgeNode: '507f1f77bcf86cd799439033' }, { mode: 'forward' }, { classicLifecycleGrant: '00'.repeat(32) }, { classicLifecycleGrant: 'f' }]) {
        assert.equal(hasClassicLifecycleGrant({ ...original, ...changes }, env), false);
    }
    assert.equal(hasClassicLifecycleGrant(original, { ...env, CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: '34'.repeat(32) }), false);
    assert.equal(hasClassicLifecycleGrant(original, { ...env, CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'false' }), false);
});
test('grant issuance is explicit opt-in, requires a strong dedicated key and canonical distinct IDs', () => {
    assert.equal(issueClassicLifecycleGrant(link(), {}), undefined);
    for (const key of ['', 'a', 'g'.repeat(64), undefined]) {
        assert.throws(() => issueClassicLifecycleGrant(link(), { ...env, CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: key }), { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
    }
    for (const changes of [{ mode: 'forward' }, { bridgeNode: link().portalNode }, { _id: 'not-an-id' }]) {
        assert.throws(() => issueClassicLifecycleGrant({ ...link(), ...changes }, env), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    }
});
test('populated node references retain the exact grant binding and metadata is not authority', () => {
    const original = link(); original.classicLifecycleGrant = issueClassicLifecycleGrant(original, env);
    assert.equal(hasClassicLifecycleGrant({ ...original, portalNode: { _id: original.portalNode }, bridgeNode: { _id: original.bridgeNode }, name: 'changed', status: 'online', autoDeploy: false }, env), true);
});
