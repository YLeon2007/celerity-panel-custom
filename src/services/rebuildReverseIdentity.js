'use strict';

const { createHash } = require('node:crypto');

function reverseObservationEmail(linkId, uuid) {
    if (typeof linkId !== 'string' || !/^[a-f0-9]{24}$/.test(linkId)
        || typeof uuid !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(uuid)) return null;
    const identity = createHash('sha256').update(uuid.toLowerCase()).digest('hex');
    return `rproof-${linkId}-${identity}@rebuild.invalid`;
}

function hasReverseObservationEmail(inbound, suffix, account) {
    const linkId = /^rproof-([a-f0-9]{24})-[a-f0-9]{64}@rebuild\.invalid$/.exec(account.email)?.[1];
    return linkId?.slice(-8) === suffix && account.email === reverseObservationEmail(linkId, account.id)
        && inbound.settings.decryption === 'none' && inbound.streamSettings?.network === 'tcp'
        && inbound.streamSettings.security === 'reality';
}

module.exports = { reverseObservationEmail, hasReverseObservationEmail };