'use strict';

const interrelayFingerprints = ['chrome', 'firefox'];
const generalFingerprints = [...interrelayFingerprints, 'safari'];
const publicFingerprints = new Set([...generalFingerprints, 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized']);

const nodeId = ref => String(ref?._id ?? ref);
function realityEndpoints(link) {
    // Missing mode is reverse in the native rebuild compiler. A reverse
    // target can be a relay as well as a terminal bridge.
    const source = nodeId(link.portalNode), target = nodeId(link.bridgeNode);
    return link.mode === 'forward' ? { dialer: source, listener: target } : { dialer: target, listener: source };
}

function isRestrictedVersion(version) {
    const triplet = typeof version === 'string' && /^(\d{1,4})\.(\d{1,4})\.\d{1,4}(?![\s\S])/.exec(version);
    if (!triplet) throw Object.assign(new Error('REBUILD_XRAY_VERSION_UNKNOWN'), { code: 'REBUILD_XRAY_VERSION_UNKNOWN' });
    const major = Number(triplet[1]), minor = Number(triplet[2]);
    return major > 26 || (major === 26 && minor >= 11);
}

/** Validate a desired REALITY link against both endpoints' probed numeric triplets. */
function assertRealityFingerprint(link, versions, roles) {
    const { dialer, listener } = realityEndpoints(link);
    const dialerRestricted = isRestrictedVersion(versions?.get(dialer));
    const listenerRestricted = isRestrictedVersion(versions?.get(listener));
    const allowed = roles?.get(dialer) === 'relay' && roles?.get(listener) === 'relay'
        ? interrelayFingerprints : generalFingerprints;

    const configured = link.realityFingerprint;
    const fingerprint = configured == null || typeof configured === 'string' && !configured.trim() ? 'chrome' : configured;
    if ((dialerRestricted || listenerRestricted) && !allowed.includes(fingerprint)) {
        const code = 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED';
        const endpointRole = dialerRestricted ? 'dialer' : 'listener';
        const id = dialerRestricted ? dialer : listener;
        throw Object.assign(new Error(code), { code, fingerprintIssue: {
            endpointRole, endpointId: /^[A-Za-z0-9_-]{1,128}(?![\s\S])/.test(id) ? id : '',
            version: versions.get(id), fingerprint: publicFingerprints.has(fingerprint) ? fingerprint : 'unknown', allowed: [...allowed],
        } });
    }
    return fingerprint;
}

module.exports = { assertRealityFingerprint, realityEndpoints };