/**
 * Search & analytics over the Parquet access-log store (read side).
 *
 * Builds parameterized DuckDB SQL against the Hive-partitioned Parquet glob and
 * runs it through the isolated duckdbService worker. All user input is bound as
 * parameters — never interpolated — and partition pruning is pushed down via the
 * date/hour columns so DuckDB only touches relevant files.
 *
 * When DuckDB is unavailable the service returns { degraded: true } so callers
 * can fall back to Mongo rollups without throwing.
 */

const path = require('path');
const paths = require('./paths');
const duckdb = require('./duckdbService');
const logger = require('../../utils/logger');

// Glob covering every part file. DuckDB reads hive_partitioning so date=/node_id=
// /hour= become queryable columns, enabling partition pruning.
const PARQUET_GLOB = path.join(paths.PARQUET_DIR, '**', '*.parquet').replace(/\\/g, '/');

const MAX_ROW_LIMIT = 5000;
const DEFAULT_ROW_LIMIT = 200;

// Whitelisted sortable columns to avoid any injection via ORDER BY.
const SORTABLE = new Set(['ts', 'email', 'source_ip', 'dest_host', 'dest_ip', 'action', 'network']);

// Build a FROM clause with hive partitioning + union_by_name so schema drift
// across part files never breaks a query.
function fromClause() {
    return `read_parquet('${PARQUET_GLOB.replace(/'/g, "''")}', hive_partitioning = true, union_by_name = true)`;
}

// Translate high-level filters into a parameterized WHERE + params array.
// Time filters are duplicated onto the hive partition column (`date`, a
// YYYY-MM-DD string; lexicographic order == chronological) so DuckDB prunes
// whole partitions instead of opening every part file's footer.
function buildWhere(filters = {}) {
    const clauses = [];
    const params = [];

    if (filters.from instanceof Date) {
        clauses.push('date >= ?'); params.push(filters.from.toISOString().slice(0, 10));
        clauses.push('ts >= ?'); params.push(filters.from.toISOString());
    }
    if (filters.to instanceof Date) {
        clauses.push('date <= ?'); params.push(filters.to.toISOString().slice(0, 10));
        clauses.push('ts <= ?'); params.push(filters.to.toISOString());
    }
    if (filters.nodeId) { clauses.push('node_id = ?'); params.push(String(filters.nodeId)); }
    if (filters.email) { clauses.push('email = ?'); params.push(String(filters.email)); }
    if (filters.sourceIp) { clauses.push('source_ip = ?'); params.push(String(filters.sourceIp)); }
    if (filters.action) { clauses.push('action = ?'); params.push(String(filters.action)); }
    if (filters.network) { clauses.push('network = ?'); params.push(String(filters.network)); }

    // Destination is matched against host OR ip with a prefix/substring contains
    // (ILIKE) for usability. Bound as a parameter.
    if (filters.destination) {
        clauses.push('(dest_host ILIKE ? OR dest_ip ILIKE ?)');
        const like = `%${String(filters.destination)}%`;
        params.push(like, like);
    }

    // Free-text search across the raw line (bounded, parameterized).
    if (filters.q) {
        clauses.push('raw ILIKE ?');
        params.push(`%${String(filters.q)}%`);
    }

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    return { where, params };
}

/**
 * Paged search returning individual events, newest first by default.
 * @returns {Promise<{degraded?:boolean, rows?:Array, error?:string}>}
 */
async function search(filters = {}, opts = {}) {
    if (!(await duckdb.isAvailable())) {
        return { degraded: true, rows: [] };
    }

    const { where, params } = buildWhere(filters);

    const sortCol = SORTABLE.has(opts.sort) ? opts.sort : 'ts';
    const sortDir = opts.dir === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.max(1, Math.min(MAX_ROW_LIMIT, Number(opts.limit) || DEFAULT_ROW_LIMIT));
    const offset = Math.max(0, Number(opts.offset) || 0);

    const sql = `
        SELECT event_id, ts, node_id, email, source_ip, source_port,
               dest_host, dest_ip, dest_port, network, inbound_tag, outbound_tag,
               action, raw, parse_ok
        FROM ${fromClause()}
        ${where}
        ORDER BY ${sortCol} ${sortDir}
        LIMIT ${limit} OFFSET ${offset}
    `;

    const res = await duckdb.query(sql, params, { rowLimit: limit, timeoutMs: opts.timeoutMs || 30000 });
    if (!res.ok) {
        if (res.error === 'duckdb_unavailable') return { degraded: true, rows: [] };
        logger.warn(`[AccessLogs] search failed: ${res.error}`);
        return { error: res.error, rows: [] };
    }
    return { rows: res.rows };
}

/**
 * Summary aggregates for a dashboard: totals, top destinations, top users, and a
 * per-hour time series. Single query set kept small for weak hardware.
 */
async function summary(filters = {}, opts = {}) {
    if (!(await duckdb.isAvailable())) {
        return { degraded: true };
    }
    const { where, params } = buildWhere(filters);
    const topN = Math.max(1, Math.min(50, Number(opts.topN) || 10));

    const from = fromClause();

    const totalsSql = `SELECT count(*) AS total,
                              count(DISTINCT email) AS users,
                              count(DISTINCT source_ip) AS ips
                       FROM ${from} ${where}`;
    const topDestSql = `SELECT coalesce(nullif(dest_host,''), dest_ip) AS dest, count(*) AS hits
                        FROM ${from} ${where}
                        GROUP BY dest ORDER BY hits DESC LIMIT ${topN}`;
    const topUserSql = `SELECT email, count(*) AS hits
                        FROM ${from} ${where} ${where ? 'AND' : 'WHERE'} email <> ''
                        GROUP BY email ORDER BY hits DESC LIMIT ${topN}`;
    const seriesSql = `SELECT date_trunc('hour', ts) AS bucket, count(*) AS hits
                       FROM ${from} ${where}
                       GROUP BY bucket ORDER BY bucket`;

    // Run sequentially, not in parallel: the DuckDB service intentionally allows
    // only one heavy query at a time (weak-hardware constraint), so concurrent
    // calls would be rejected as "busy".
    const totals = await duckdb.query(totalsSql, params, { rowLimit: 1 });
    const topDest = await duckdb.query(topDestSql, params, { rowLimit: topN });
    const topUser = await duckdb.query(topUserSql, params, { rowLimit: topN });
    const series = await duckdb.query(seriesSql, params, { rowLimit: 24 * 62 });

    if (!totals.ok && totals.error === 'duckdb_unavailable') return { degraded: true };

    return {
        totals: (totals.ok && totals.rows[0]) || { total: 0, users: 0, ips: 0 },
        topDestinations: (topDest.ok && topDest.rows) || [],
        topUsers: (topUser.ok && topUser.rows) || [],
        series: (series.ok && series.rows) || [],
    };
}

module.exports = {
    PARQUET_GLOB,
    buildWhere,
    search,
    summary,
};
