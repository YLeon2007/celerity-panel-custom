'use strict';

const allowed = ['chrome', 'firefox', 'safari'];
const publicFingerprints = new Set([...allowed, 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized']);

function realityDialerId(link) {
    // Missing mode is reverse in the native rebuild compiler. A reverse
    // target can be a relay as well as a terminal bridge.
    const ref = link.mode === 'forward' ? link.portalNode : link.bridgeNode;
    return String(ref?._id ?? ref);
}

/** Validate a desired REALITY link against its dialer's probed numeric triplet. */
function assertRealityFingerprint(link, version) {
    const triplet = typeof version === 'string' && /^(\d{1,4})\.(\d{1,4})\.\d{1,4}(?![\s\S])/.exec(version);
    if (!triplet) throw Object.assign(new Error('REBUILD_XRAY_VERSION_UNKNOWN'), { code: 'REBUILD_XRAY_VERSION_UNKNOWN' });

    const configured = link.realityFingerprint;
    const fingerprint = configured == null || typeof configured === 'string' && !configured.trim() ? 'chrome' : configured;
    if (Number(triplet[1]) === 26 && Number(triplet[2]) === 11 && !allowed.includes(fingerprint)) {
        const code = 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED';
        const dialerId = realityDialerId(link);
        throw Object.assign(new Error(code), { code, fingerprintIssue: {
            dialerId: /^[A-Za-z0-9_-]{1,128}(?![\s\S])/.test(dialerId) ? dialerId : '',
            version, fingerprint: publicFingerprints.has(fingerprint) ? fingerprint : 'unknown', allowed: [...allowed],
        } });
    }
    return fingerprint;
}

module.exports = { assertRealityFingerprint, realityDialerId };