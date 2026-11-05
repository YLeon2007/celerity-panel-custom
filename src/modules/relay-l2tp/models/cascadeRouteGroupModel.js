'use strict';

const mongoose = require('mongoose');

const routePathSchema = new mongoose.Schema({
    pathKey: { type: String, required: true, trim: true },
    linkIds: {
        type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'CascadeLink' }],
        // Installed publication retains the owner's path when no exit remains.
        // Public route-group CRUD separately requires a nonempty ordered path.
        required: true,
        default: undefined,
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
    enabled: { type: Boolean, default: true },
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
