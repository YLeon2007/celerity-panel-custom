/**
 * Filesystem layout for the access-logs pipeline (panel side).
 *
 * Only the durable ingest spool lives on disk now; storage and analytics live
 * in ClickHouse. Layout:
 *
 *   <root>/
 *     incoming/            durable spool of received batches (immutable once sealed)
 *       tmp/               in-flight uploads (fsync + atomic rename into incoming/)
 *       processed/         zero-byte dedup markers for already-ingested batches
 */

const path = require('path');

// Default matches the Docker volume mount in the compose files. Overridable via
// env for local development.
const DATA_ROOT = process.env.ACCESS_LOGS_DIR
    || path.join(process.cwd(), 'data', 'access-logs');

const INCOMING_DIR = path.join(DATA_ROOT, 'incoming');
const INCOMING_TMP_DIR = path.join(INCOMING_DIR, 'tmp');

module.exports = {
    DATA_ROOT,
    INCOMING_DIR,
    INCOMING_TMP_DIR,
};
