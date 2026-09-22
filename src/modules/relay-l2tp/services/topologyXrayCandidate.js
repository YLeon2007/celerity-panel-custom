'use strict';

const { createHash } = require('node:crypto');

const CANDIDATE_MEDIA_TYPE = 'application/vnd.celerity.xray-topology-node+json;version=1';
const CANDIDATE_KEYS = Object.freeze(['bytes', 'mediaType', 'sha256']);
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const MAX_CANDIDATE_BYTES = 4 * 1024 * 1024;

function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, expectedKeys) {
    return isPlainObject(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!isPlainObject(value)) return value;
    return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonicalize(value[key])]),
    );
}

function invalidCandidate() {
    return new TypeError('Invalid canonical Xray topology candidate');
}

function projectCanonicalXrayCandidate(candidate, candidateHash) {
    if (!hasExactKeys(candidate, CANDIDATE_KEYS)
        || candidate.mediaType !== CANDIDATE_MEDIA_TYPE
        || !Array.isArray(candidate.bytes)
        || candidate.bytes.length === 0
        || candidate.bytes.length > MAX_CANDIDATE_BYTES
        || candidate.bytes.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)
        || typeof candidate.sha256 !== 'string'
        || !DIGEST_PATTERN.test(candidate.sha256)
        || candidateHash !== candidate.sha256) {
        throw invalidCandidate();
    }

    const bytes = Buffer.from(candidate.bytes);
    const content = bytes.toString('utf8');
    if (!Buffer.from(content, 'utf8').equals(bytes)
        || createHash('sha256').update(bytes).digest('hex') !== candidate.sha256) {
        throw invalidCandidate();
    }

    let document;
    try {
        document = JSON.parse(content);
    } catch {
        throw invalidCandidate();
    }
    if (!isPlainObject(document)
        || !Array.isArray(document.inbounds)
        || document.inbounds.some(inbound => !isPlainObject(inbound))
        || !Array.isArray(document.outbounds)
        || document.outbounds.some(outbound => !isPlainObject(outbound))
        || !isPlainObject(document.routing)
        || !Array.isArray(document.routing.rules)
        || document.routing.rules.some(rule => !isPlainObject(rule))
        || content !== `${JSON.stringify(canonicalize(document))}\n`) {
        throw invalidCandidate();
    }

    return {
        candidate: {
            mediaType: candidate.mediaType,
            bytes: [...candidate.bytes],
            sha256: candidate.sha256,
        },
        content,
    };
}

module.exports = {
    CANDIDATE_MEDIA_TYPE,
    DIGEST_PATTERN,
    projectCanonicalXrayCandidate,
};
