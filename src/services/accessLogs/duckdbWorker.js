/**
 * DuckDB query worker (child process).
 *
 * Runs a single read-only query against the Parquet dataset and returns the
 * result as JSON on stdout, then exits. Running in a child process keeps the
 * main event loop free, enforces a hard timeout via process kill, and isolates
 * native DuckDB crashes from the panel.
 *
 * Protocol: the parent passes a base64-encoded JSON job as argv[2]:
 *   { sql: string, params: any[], rowLimit: number, threads: number,
 *     memoryLimitMb: number }
 * Output on stdout: { ok: true, rows: [...] } or { ok: false, error: "..." }.
 *
 * The worker never interpolates user input into SQL: only parameter binding is
 * used. The parent is responsible for building parameterized SQL.
 */

// Recursively coerce a DuckDB value into something JSON-serializable.
function normalizeValue(v) {
    if (v === null || v === undefined) return v;
    const t = typeof v;
    if (t === 'bigint') return Number(v);
    if (t === 'number' || t === 'string' || t === 'boolean') return v;
    if (v instanceof Date) return v.toISOString();
    // DuckDB node-api wrapper objects (timestamp/date/time/decimal/etc) commonly
    // expose a toString(). Fall back to that, else JSON of own enumerable props.
    if (t === 'object') {
        if (typeof v.toString === 'function' && v.toString !== Object.prototype.toString) {
            return v.toString();
        }
        try { return JSON.parse(JSON.stringify(v, (_k, val) => (typeof val === 'bigint' ? Number(val) : val))); }
        catch (_) { return String(v); }
    }
    return String(v);
}

async function main() {
    let job;
    try {
        job = JSON.parse(Buffer.from(process.argv[2] || '', 'base64').toString('utf8'));
    } catch (err) {
        process.stdout.write(JSON.stringify({ ok: false, error: 'bad job payload' }));
        process.exit(0);
        return;
    }

    let duckdb;
    try {
        // Lazy require so a missing/incompatible native binding fails only here
        // and is reported gracefully to the parent, rather than crashing the app.
        duckdb = require('@duckdb/node-api');
    } catch (err) {
        process.stdout.write(JSON.stringify({ ok: false, error: 'duckdb_unavailable', detail: String(err && err.message || err) }));
        process.exit(0);
        return;
    }

    try {
        const instance = await duckdb.DuckDBInstance.create(':memory:');
        const conn = await instance.connect();

        const threads = Math.max(1, Math.min(4, Number(job.threads) || 1));
        const memMb = Math.max(64, Math.min(1024, Number(job.memoryLimitMb) || 256));
        await conn.run(`SET threads=${threads}`);
        await conn.run(`SET memory_limit='${memMb}MB'`);

        // Read one query's rows, normalized + row-capped.
        async function runOne(sql, params, rowLimit) {
            const reader = await conn.runAndReadAll(sql, Array.isArray(params) ? params : []);
            let rows = reader.getRowObjects();
            const limit = Number(rowLimit) || 1000;
            if (rows.length > limit) rows = rows.slice(0, limit);
            // Normalize so JSON.stringify never throws: BIGINT -> Number, and
            // DuckDB temporal/complex wrapper objects -> string (node-api returns
            // TIMESTAMP as objects carrying BigInt micros).
            return rows.map((row) => {
                const out = {};
                for (const k of Object.keys(row)) out[k] = normalizeValue(row[k]);
                return out;
            });
        }

        // Batch mode: run several labelled queries on one connection in a single
        // child-process spawn, so a whole dashboard costs one worker instead of N.
        if (Array.isArray(job.queries)) {
            const results = {};
            for (const q of job.queries) {
                results[q.key] = await runOne(q.sql, q.params, q.rowLimit);
            }
            process.stdout.write(JSON.stringify({ ok: true, results }));
            process.exit(0);
            return;
        }

        const safe = await runOne(job.sql, job.params, job.rowLimit);
        process.stdout.write(JSON.stringify({ ok: true, rows: safe }));
        process.exit(0);
    } catch (err) {
        process.stdout.write(JSON.stringify({ ok: false, error: String(err && err.message || err) }));
        process.exit(0);
    }
}

main();
