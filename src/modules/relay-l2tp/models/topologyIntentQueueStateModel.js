'use strict';
const mongoose = require('mongoose');
const schema = new mongoose.Schema({
    _id: { type: String, enum: ['create-v1'] },
    outstanding: { type: Number, required: true, min: 0 },
    ordinal: { type: Number, required: true, min: 0 },
}, { timestamps: true });
module.exports = mongoose.model('TopologyIntentQueueState', schema);
