'use strict';

const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');

const header = 'x-rebuild-l2tp-observation';
const outcomes = new Set(['installed', 'removed', 'can_install_again', 'granted', 'revoked',
    'created', 'disabled', 'deleted', 'canceled', 'settled']);
const observations = new Map();
const limit = 512;
let scriptVersion;

function rebuildL2tpScriptVersion() {
    return scriptVersion ??= createHash('sha256')
        .update(readFileSync(resolve(__dirname, '../../../public/js/rebuild-l2tp.js'))).digest('hex').slice(0, 16);
}

function scope(req) {
    const token = req.headers?.[header];
    if (req.session?.authenticated !== true || !req.sessionID || typeof req.sessionID !== 'string'
        || typeof token !== 'string' || token.length !== 32 || !/^[a-f0-9]+$/.test(token)
        || (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin')) return null;
    return JSON.stringify([req.sessionID, token]);
}

// Called only inside the existing guarded handlers. The browser uses one nonce
// per dispatch; it is neither write authority nor an idempotency key. Keep no
// payload, target identifiers, challenges, credentials or diagnostic details.
// Loss/expiry/eviction of this optional witness must leave the outcome unknown.
function observe(req) {
    const key = scope(req);
    if (!key) return () => {};
    const now = performance.now();
    for (const [key, entry] of observations) if (entry.expires <= now) observations.delete(key);
    if (observations.has(key)) return () => {};
    while (observations.size >= limit) observations.delete(observations.keys().next().value);
    const entry = { expires: now + 30 * 60_000 };
    observations.set(key, entry);
    return outcome => {
        if (!outcomes.has(outcome) || entry.outcome || observations.get(key) !== entry || performance.now() >= entry.expires) return;
        entry.outcome = outcome;
        entry.expires = performance.now() + 5 * 60_000;
    };
}

function readObservation(req) {
    const key = scope(req);
    const entry = key && observations.get(key);
    return entry && performance.now() < entry.expires ? entry.outcome : undefined;
}

module.exports = { observe, readObservation, header, rebuildL2tpScriptVersion };
