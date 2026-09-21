'use strict';

const mongoose = require('mongoose');

const routePathSchema = new mongoose.Schema({
    pathKey: { type: String, required: true, trim: true },
    linkIds: {
        type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'CascadeLink' }],
        required: true,
        default: undefined,
        validate: {
            validator(linkIds) {
                return linkIds.length > 0;
            },
            message: 'linkIds must contain at least one cascade link',
        },
    },
    priority: {
        type: Number,
        required: true,
        validate: {
            validator(priority) {
                return Number.isFinite(priority) && priority > 0;
            },
            message: 'priority must be a positive finite number',
        },
    },
}, { _id: false });

const cascadeRouteGroupSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    mode: {
        type: String,
        enum: ['reverse', 'forward'],
        required: true,
    },
    strategy: {
        type: String,
        enum: ['priority-failover'],
        required: true,
    },
    paths: {
        type: [routePathSchema],
        default: [],
        validate: {
            validator(paths) {
                const pathKeys = paths.map((path) => path.pathKey);
                return pathKeys.length === new Set(pathKeys).size;
            },
            message: 'pathKey values must be unique within a route group',
        },
    },
}, { timestamps: true });

module.exports = mongoose.model('CascadeRouteGroup', cascadeRouteGroupSchema);
