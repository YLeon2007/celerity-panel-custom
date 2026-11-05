'use strict';
const mongoose = require('mongoose');

// No defaults or lifetime immutability here: the owner row may enter a new
// ownership epoch. Enrollment/binding attach this schema as immutable instead.
function scalar(type, options) {
    return { type, required: true, ...options, set(value) {
        if (typeof value !== (type === Number ? 'number' : 'string')) {
            throw Object.assign(new Error('TOPOLOGY_PROFILE_TARGET_INVALID'), { code: 'TOPOLOGY_PROFILE_TARGET_INVALID' });
        }
        return value;
    } };
}
function createProfileTargetPinSchema() {
    return new mongoose.Schema({
        version: scalar(Number, { enum: [1] }),
        layout: scalar(String, { enum: ['legacy-forward-main'] }),
        nodeId: scalar(String, { match: /^[a-f0-9]{24}$/ }),
        role: scalar(String, { enum: ['portal', 'bridge'] }),
        targetProfile: scalar(String, { enum: ['xray-main'] }),
        ownerGeneration: scalar(String, { match: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/ }),
        descriptorSha256: scalar(String, { match: /^[a-f0-9]{64}$/ }),
        ownerEvidenceSha256: scalar(String, { match: /^[a-f0-9]{64}$/ }),
    }, { _id: false, versionKey: false, strict: 'throw' });
}
module.exports = { createProfileTargetPinSchema };
