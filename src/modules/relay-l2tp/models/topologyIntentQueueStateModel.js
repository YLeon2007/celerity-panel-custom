'use strict';
const mongoose = require('mongoose');
const schema = new mongoose.Schema({
    // Keep the existing identity: v1/v2 share capacity and acceptance order.
    _id: { type: String, enum: ['create-v1'] },
    outstanding: { type: Number, required: true, min: 0, validate: Number.isSafeInteger },
    ordinal: { type: Number, required: true, min: 0, validate: Number.isSafeInteger },
}, { timestamps: true });
module.exports = mongoose.model('TopologyIntentQueueState', schema);
