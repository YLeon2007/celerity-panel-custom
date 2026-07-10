/**
 * Filesystem layout for the access-logs pipeline.
 *
 * Everything lives under a single data root so a dedicated Docker volume can be
 * mounted at that path. Layout:
 *
 *   <root>/
 *     incoming/            durable spool of received batches (immutable once sealed)
 *       tmp/               in-flight uploads (fsync + atomic rename into incoming/)
 *     parquet/             immutable Hive-partitioned Parquet
 *       date=YYYY-MM-DD/node_id=<id>/hour=HH/part-<hash>.parquet
 *     quarantine/          malformed batches / out-of-window events
 */

const path = require('path');

// Default matches the Docker volume mount in the compose files. Overridable via
// env for local development.
const DATA_ROOT = process.env.ACCESS_LOGS_DIR
    || path.join(process.cwd(), 'data', 'access-logs');

const INCOMING_DIR = path.join(DATA_ROOT, 'incoming');
const INCOMING_TMP_DIR = path.join(INCOMING_DIR, 'tmp');
const PARQUET_DIR = path.join(DATA_ROOT, 'parquet');
const QUARANTINE_DIR = path.join(DATA_ROOT, 'quarantine');

// Build a Hive-partitioned parquet path from an event date (UTC) and node id.
function parquetPartitionDir(dateStr, nodeId, hour) {
    const safeNode = String(nodeId || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_');
    const hh = String(hour).padStart(2, '0');
    return path.join(PARQUET_DIR, `date=${dateStr}`, `node_id=${safeNode}`, `hour=${hh}`);
}

module.exports = {
    DATA_ROOT,
    INCOMING_DIR,
    INCOMING_TMP_DIR,
    PARQUET_DIR,
    QUARANTINE_DIR,
    parquetPartitionDir,
};
