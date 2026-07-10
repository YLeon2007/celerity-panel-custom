/**
 * Hourly access-log rollups stored in MongoDB.
 *
 * These are tiny aggregate documents (NOT raw events) that power the dashboard
 * summary instantly and keep it working even when DuckDB is unavailable or busy.
 * One document per (nodeId, hourBucket). Raw event search still goes to Parquet
 * via DuckDB; this is only for cheap totals and time series.
 */

const mongoose = require('mongoose');

const accessLogRollupSchema = new mongoose.Schema({
    // UTC hour bucket (truncated to the hour) this rollup covers.
    hourBucket: { type: Date, required: true },
    nodeId: { type: String, required: true, default: '' },

    total: { type: Number, default: 0 },
    accepted: { type: Number, default: 0 },
    rejected: { type: Number, default: 0 },
    blocked: { type: Number, default: 0 },
    tcp: { type: Number, default: 0 },
    udp: { type: Number, default: 0 },

    // Small top-K maps kept bounded (host -> hits, email -> hits). Stored as
    // plain objects; the writer trims them to a fixed size.
    topDestinations: { type: Map, of: Number, default: {} },
    topUsers: { type: Map, of: Number, default: {} },

    updatedAt: { type: Date, default: Date.now },
}, { versionKey: false });

// One rollup per node per hour; also the natural query index for time-range
// dashboards.
accessLogRollupSchema.index({ hourBucket: 1, nodeId: 1 }, { unique: true });
// TTL-friendly secondary index for range scans by node.
accessLogRollupSchema.index({ nodeId: 1, hourBucket: 1 });

module.exports = mongoose.model('AccessLogRollup', accessLogRollupSchema);
