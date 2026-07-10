/**
 * DuckDB Parquet write worker (child process).
 *
 * Writes one batch of canonical access events to a single ZSTD-compressed
 * Parquet part file. Running in a child process isolates the native binding and
 * bounds memory. The events are passed as a temp JSON file path (not argv) so
 * large batches do not hit argv size limits.
 *
 * Protocol: argv[2] = base64 JSON job:
 *   { eventsFile: string, outFile: string, threads, memoryLimitMb }
 * Output on stdout: { ok: true, rows: N } | { ok: false, error }.
 *
 * The Parquet schema is fixed and matches eventContract.EVENT_COLUMNS so the
 * read side can rely on a stable set of columns.
 */

const fs = require('fs');

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
        duckdb = require('@duckdb/node-api');
    } catch (err) {
        process.stdout.write(JSON.stringify({ ok: false, error: 'duckdb_unavailable', detail: String(err && err.message || err) }));
        process.exit(0);
        return;
    }

    try {
        const instance = await duckdb.DuckDBInstance.create(':memory:');
        const conn = await instance.connect();

        const threads = Math.max(1, Math.min(2, Number(job.threads) || 1));
        const memMb = Math.max(64, Math.min(512, Number(job.memoryLimitMb) || 256));
        await conn.run(`SET threads=${threads}`);
        await conn.run(`SET memory_limit='${memMb}MB'`);

        // Read events from the temp JSON file with an explicit schema so column
        // types are stable regardless of the sampled values. read_json_auto with
        // a columns override keeps this robust.
        const eventsFileSql = job.eventsFile.replace(/'/g, "''");
        const outFileSql = job.outFile.replace(/'/g, "''");

        // COPY the typed selection to Parquet with ZSTD. Column list is explicit
        // and ordered to match the canonical contract.
        const sql = `
            COPY (
                SELECT
                    CAST(eventId AS VARCHAR)          AS event_id,
                    CAST(timestamp AS TIMESTAMP)      AS ts,
                    CAST(nodeId AS VARCHAR)           AS node_id,
                    CAST(email AS VARCHAR)            AS email,
                    CAST(sourceIp AS VARCHAR)         AS source_ip,
                    CAST(sourcePort AS INTEGER)       AS source_port,
                    CAST(destinationHost AS VARCHAR)  AS dest_host,
                    CAST(destinationIp AS VARCHAR)    AS dest_ip,
                    CAST(destinationPort AS INTEGER)  AS dest_port,
                    CAST(network AS VARCHAR)          AS network,
                    CAST(inboundTag AS VARCHAR)       AS inbound_tag,
                    CAST(outboundTag AS VARCHAR)      AS outbound_tag,
                    CAST(action AS VARCHAR)           AS action,
                    CAST(raw AS VARCHAR)              AS raw,
                    CAST(parseOk AS BOOLEAN)          AS parse_ok,
                    CAST(parserVersion AS INTEGER)    AS parser_version
                FROM read_json('${eventsFileSql}',
                    format = 'array',
                    records = true,
                    timestampformat = '%Y-%m-%dT%H:%M:%S.%fZ'
                )
            ) TO '${outFileSql}' (FORMAT PARQUET, COMPRESSION ZSTD);
        `;

        await conn.run(sql);

        // Count rows written for reporting.
        let rows = 0;
        try {
            const rc = fs.existsSync(job.eventsFile)
                ? JSON.parse(fs.readFileSync(job.eventsFile, 'utf8')).length
                : 0;
            rows = rc;
        } catch (_) { /* best-effort */ }

        process.stdout.write(JSON.stringify({ ok: true, rows }));
        process.exit(0);
    } catch (err) {
        process.stdout.write(JSON.stringify({ ok: false, error: String(err && err.message || err) }));
        process.exit(0);
    }
}

main();
