'use strict';
const mongoose = require('mongoose');
const { topologyExecutionContext } = require('../domain/topologyExecutionContext');
// No defaults: old/unbound persisted work must not inherit the reader's identity.
const schema = new mongoose.Schema({
    target: { type: String, required: true, immutable: true, enum: ['test', 'production'] },
    hostIdentity: { type: String, required: true, immutable: true },
}, { _id: false, versionKey: false, strict: 'throw' });
module.exports = function executionContextField(required = false) {
    return { type: schema, required, immutable: true, default: undefined,
        validate: value => Boolean(topologyExecutionContext(value?.target, value?.hostIdentity)) };
};
