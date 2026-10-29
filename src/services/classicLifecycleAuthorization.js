'use strict';

const { createHmac, timingSafeEqual } = require('node:crypto');
const ID = /^[a-f0-9]{24}$/;
const HEX_KEY = /^[a-f0-9]{64}$/;
const id = value => String(value?._id ?? value ?? '');
const failure = code => Object.assign(new Error(code), { code });

function keyFor(env) {
    if (env.CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED !== 'true') return null;
    const key = env.CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY;
    if (typeof key !== 'string' || !HEX_KEY.test(key)) throw failure('TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
    return Buffer.from(key, 'hex');
}
function binding(link) {
    const ids = [id(link?._id), id(link?.portalNode), id(link?.bridgeNode)];
    if (link?.mode !== 'reverse' || !ids.every(value => ID.test(value)) || ids[1] === ids[2]) return null;
    return JSON.stringify(['classic-link-lifecycle-v1', ...ids, 'reverse']);
}
// Issue only on the trusted HTTP create path, before its atomic draft insert.
// The request payload and update field allowlists never accept this field.
// This is a durable per-link allowlist entry, not a blanket deployment opt-in.
function issueClassicLifecycleGrant(link, env) {
    const key = keyFor(env);
    if (!key) return undefined;
    const payload = binding(link);
    if (!payload) throw failure('CLASSIC_DEPLOY_UNSUPPORTED');
    return createHmac('sha256', key).update(payload).digest('hex');
}
function hasClassicLifecycleGrant(link, env) {
    try {
        const key = keyFor(env), payload = binding(link), actual = link?.classicLifecycleGrant;
        if (!key || !payload || typeof actual !== 'string' || !HEX_KEY.test(actual)) return false;
        const expected = createHmac('sha256', key).update(payload).digest();
        return timingSafeEqual(Buffer.from(actual, 'hex'), expected);
    } catch { return false; }
}
module.exports = { issueClassicLifecycleGrant, hasClassicLifecycleGrant };
