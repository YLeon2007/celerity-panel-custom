const assert = require('assert');

const {
    buildSessionCookieOptions,
} = require('../src/utils/sessionCookie');

assert.strictEqual(
    buildSessionCookieOptions({ SESSION_COOKIE_SECURE: 'false' }).secure,
    false,
    'SESSION_COOKIE_SECURE=false must disable secure cookies for local HTTP'
);

assert.strictEqual(
    buildSessionCookieOptions({ SESSION_COOKIE_SECURE: 'true' }).secure,
    true,
    'SESSION_COOKIE_SECURE=true must keep secure cookies enabled'
);

assert.strictEqual(
    buildSessionCookieOptions({}).secure,
    true,
    'secure cookies must remain enabled by default'
);

assert.throws(
    () => buildSessionCookieOptions({ SESSION_COOKIE_SECURE: 'maybe' }),
    /SESSION_COOKIE_SECURE/,
    'invalid SESSION_COOKIE_SECURE values should fail clearly'
);

console.log('session cookie config tests passed');
