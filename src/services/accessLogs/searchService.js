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

/**
 * Combined dashboard overview computed in a SINGLE DuckDB worker spawn:
 * totals + action/protocol split, an hourly time series (with per-action
 * breakdown), top destinations/ports/blocked, and a per-user aggregate used by
 * both the "users by IP count" (sharing lens) and "users by fan-out" (abuse
 * lens) tables. All filters are bound as parameters; the per-user distinct
 * counts (source IPs, /24 subnets, destinations) are DuckDB-only and therefore
 * absent in degraded mode.
 *
 * @returns {Promise<{degraded?:boolean, error?:string, totals?:Object,
 *   series?:Array, topDestinations?:Array, topPorts?:Array, topBlocked?:Array,
 *   users?:Array}>}
 */
async function overview(filters = {}, opts = {}) {
    if (!(await duckdb.isAvailable())) {
        return { degraded: true };
    }

    const { where, params } = buildWhere(filters);
    const from = fromClause();
    const andWhere = where ? 'AND' : 'WHERE';
    const topN = Math.max(1, Math.min(50, Number(opts.topN) || 10));
    const userN = Math.max(1, Math.min(200, Number(opts.userLimit) || 25));

    // "dest" = human destination: host when present, else IP.
    const DEST = "coalesce(nullif(dest_host,''), dest_ip)";
    // "/24" style subnet for IPv4 (strip last octet); IPv6 left intact.
    const SUBNET = "regexp_replace(source_ip, '\\.[0-9]+$', '')";

    // Every query shares the same WHERE (and therefore the same params array);
    // the extra per-query predicates below add no new bind parameters.
    const queries = [
        {
            key: 'totals', rowLimit: 1, params,
            sql: `SELECT
                    count(*) AS total,
                    count(DISTINCT email) AS users,
                    count(DISTINCT source_ip) AS ips,
                    count(DISTINCT ${DEST}) AS dests,
                    count(*) FILTER (WHERE action='accepted') AS accepted,
                    count(*) FILTER (WHERE action='rejected') AS rejected,
                    count(*) FILTER (WHERE action='blocked')  AS blocked,
                    count(*) FILTER (WHERE network='tcp') AS tcp,
                    count(*) FILTER (WHERE network='udp') AS udp
                  FROM ${from} ${where}`,
        },
        {
            key: 'series', rowLimit: 24 * 62, params,
            sql: `SELECT date_trunc('hour', ts) AS bucket,
                         count(*) AS hits,
                         count(*) FILTER (WHERE action='accepted') AS accepted,
                         count(*) FILTER (WHERE action='rejected') AS rejected,
                         count(*) FILTER (WHERE action='blocked')  AS blocked
                  FROM ${from} ${where}
                  GROUP BY bucket ORDER BY bucket`,
        },
        {
            key: 'topDest', rowLimit: topN, params,
            sql: `SELECT ${DEST} AS dest, count(*) AS hits
                  FROM ${from} ${where}
                  GROUP BY dest ORDER BY hits DESC LIMIT ${topN}`,
        },
        {
            key: 'topPorts', rowLimit: topN, params,
            sql: `SELECT dest_port AS port, count(*) AS hits
                  FROM ${from} ${where} ${andWhere} dest_port IS NOT NULL
                  GROUP BY dest_port ORDER BY hits DESC LIMIT ${topN}`,
        },
        {
            key: 'topBlocked', rowLimit: topN, params,
            sql: `SELECT ${DEST} AS dest, count(*) AS hits
                  FROM ${from} ${where} ${andWhere} action IN ('blocked','rejected')
                  GROUP BY dest ORDER BY hits DESC LIMIT ${topN}`,
        },
        {
            key: 'users', rowLimit: userN, params,
            sql: `SELECT email,
                         count(DISTINCT source_ip) AS ips,
                         count(DISTINCT ${SUBNET}) AS subnets,
                         count(DISTINCT ${DEST}) AS dests,
                         count(*) AS events,
                         (count(*) FILTER (WHERE network='udp'))*1.0 / nullif(count(*),0) AS udp_share,
                         max(ts) AS last_seen
                  FROM ${from} ${where} ${andWhere} email <> ''
                  GROUP BY email ORDER BY ips DESC LIMIT ${userN}`,
        },
    ];

    const res = await duckdb.queryBatch(queries, { timeoutMs: opts.timeoutMs || 45000 });
    if (!res.ok) {
        if (res.error === 'duckdb_unavailable') return { degraded: true };
        logger.warn(`[AccessLogs] overview failed: ${res.error}`);
        return { error: res.error };
    }

    const r = res.results || {};
    return {
        totals: (r.totals && r.totals[0]) || { total: 0, users: 0, ips: 0, dests: 0 },
        series: r.series || [],
        topDestinations: r.topDest || [],
        topPorts: r.topPorts || [],
        topBlocked: r.topBlocked || [],
        users: r.users || [],
    };
}

module.exports = {
    PARQUET_GLOB,
    buildWhere,
    search,
    summary,
    overview,
};
