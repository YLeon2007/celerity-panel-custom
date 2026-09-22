'use strict';

const { isDeepStrictEqual } = require('node:util');
const mongoose = require('mongoose');

const {
    IMPORT_DRAFT_KIND,
    TRANSFER_KIND,
    canonicalizeTopologyTransfer,
} = require('../domain/topologyTransfer');

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COLLECTION_NAME = 'relayL2tpTopologyTransferDrafts';
const MODEL_NAME = 'RelayL2tpTopologyTransferDraft';

const topologyCountsSchema = new mongoose.Schema({
    nodes: { type: Number, required: true, min: 0 },
    links: { type: Number, required: true, min: 0 },
    routeGroups: { type: Number, required: true, min: 0 },
    relayStates: { type: Number, required: true, min: 0 },
}, { _id: false, strict: 'throw' });

function expectedKind(source) {
    return source === 'export' ? TRANSFER_KIND : IMPORT_DRAFT_KIND;
}

function isCanonicalDocument(document) {
    try {
        const canonical = canonicalizeTopologyTransfer(document, {
            kind: expectedKind(this.source),
        });
        return isDeepStrictEqual(document, canonical);
    } catch {
        return false;
    }
}

function countsMatchDocument(counts) {
    const topology = this.document?.topology;
    if (!topology) return false;
    return counts?.nodes === topology.nodes?.length
        && counts?.links === topology.links?.length
        && counts?.routeGroups === topology.routeGroups?.length
        && counts?.relayStates === topology.relayStates?.length;
}

const relayL2tpTopologyTransferDraftSchema = new mongoose.Schema({
    draftId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        match: UUID_PATTERN,
        immutable: true,
    },
    status: {
        type: String,
        enum: ['DRAFT'],
        default: 'DRAFT',
        required: true,
        immutable: true,
    },
    source: {
        type: String,
        enum: ['export', 'import'],
        required: true,
        immutable: true,
    },
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: 1,
        maxlength: 120,
        immutable: true,
    },
    document: {
        type: mongoose.Schema.Types.Mixed,
        required: true,
        immutable: true,
        validate: {
            validator: isCanonicalDocument,
            message: 'document must be a canonical secret-free relay-l2tp topology transfer',
        },
    },
    counts: {
        type: topologyCountsSchema,
        required: true,
        immutable: true,
        validate: {
            validator: countsMatchDocument,
            message: 'counts must match the canonical topology transfer document',
        },
    },
}, {
    collection: COLLECTION_NAME,
    strict: 'throw',
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
});

relayL2tpTopologyTransferDraftSchema.index({ status: 1, createdAt: -1, draftId: 1 });

module.exports = mongoose.models[MODEL_NAME]
    || mongoose.model(MODEL_NAME, relayL2tpTopologyTransferDraftSchema, COLLECTION_NAME);
